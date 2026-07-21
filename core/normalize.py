"""Load the merged AIT-ADS alert file into one normalized alert table.

Public API:
    normalize(alerts_path, labels_path, scenario="russellmitchell") -> pd.DataFrame
    normalize_scenario(raw_dir, labels_path, scenario) -> pd.DataFrame
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

COLUMNS = ["detector_source", "timestamp", "name", "host", "severity", "attack_window",
           "native_technique_ids", "rule_id"]


@dataclass
class ExtractedFields:
    """Fields that every detector must provide after normalization."""
    name: str
    host: str
    severity: float
    native_technique_ids: str = ""   # ";"-joined ATT&CK IDs, wazuh only
    rule_id: str = ""                # stable detector rule identity, for mapping config

def load_attack_windows(labels_path: Path, scenario: str) -> list[tuple[float, float, str]]:
    windows = []
    with labels_path.open(encoding="utf-8") as fh:
        c = csv.DictReader(fh)
        for row in c:
            if row["scenario"] == scenario:
                windows.append((float(row["start"]), float(row["end"]), row["attack"]))
    return windows


def find_attack_window(timestamp: float, windows: list[tuple[float, float, str]]) -> str:
    for start, end, phase in windows:
        if start <= timestamp <= end:
            return phase
    
    return ""


def get_timestamp(record: dict, detector: str) -> float:
    # AMiner already stores the timestamp;
    # wazuh/suricata store an ISO-8601 string ending in "Z" for UTC
    if detector == "aminer":
        return float(record["LogData"]["Timestamps"][0])
    return datetime.fromisoformat(record["@timestamp"]).timestamp()


def extract_wazuh_fields(record: dict) -> ExtractedFields:
    rule = record["rule"]
    host = record.get("predecoder", {}).get("hostname") or record["agent"]["name"]
    mitre = rule.get("mitre") or {}
    return ExtractedFields(
        name=rule["description"],
        host=host,
        severity=float(rule["level"]),
        # mitre IDs fields have multiple values so we join them
        native_technique_ids=";".join(mitre.get("id") or []),
        rule_id=str(rule.get("id", "")),
    )
    

def extract_suricata_fields(record: dict) -> ExtractedFields:
    alert = record["data"]["alert"]
    return ExtractedFields(
        name=alert["signature"],
        host=record["agent"]["name"],
        severity=float(alert["severity"]),
        rule_id=str(alert.get("signature_id", "")),
    )
    


def aminer_host_candidates(record: dict) -> set[str]:
    """Collect every hostname claimed by an AMiner record's original logs"""
    candidates = set()
    raw_lines = record["LogData"]["RawLogData"]
    for raw_line in raw_lines:
        raw = str(raw_line).strip()

        if raw.startswith("{"):
            embedded = json.loads(raw)
            candidates.add(str(embedded["host"]["name"]))

        match = re.match(
            r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
            r"([A-Za-z0-9._-]+)\s+",
            raw,
        )
        if match:
            candidates.add(match.group(1))

    return candidates


def discover_aminer_hosts(alerts_path: Path) -> dict[str, str]:
    """Build aliases only where the input provides one unambiguous hostname."""
    candidates: dict[str, set[str]] = defaultdict(set)
    with alerts_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            if "AMiner" not in record:
                continue
            ip = str(record["AMiner"]["ID"])
            candidates[ip].update(aminer_host_candidates(record))

    hosts = {}
    for ip, names in candidates.items():
        if len(names) == 1:
            hosts[ip] = next(iter(names))
    return hosts


def extract_aminer_fields(
    record: dict,
    host_by_ip: dict[str, str],
) -> ExtractedFields:
    ip = str(record["AMiner"]["ID"])
    component = record["AnalysisComponent"]["AnalysisComponentName"]
    return ExtractedFields(
        name=component,
        host=host_by_ip.get(ip, ip),
        severity=float("nan"),
        # aminer has no numeric rule ids; the analysis component IS its stable identity
        rule_id=str(component),
    )


def classify_wazuh_record(record: dict) -> str:
    if record.get("decoder", {}).get("name") == "snort":
        return ""
    if "alert" in record.get("data", {}):
        return "suricata"
    return "wazuh"


def normalize_record(
    record: dict,
    detector: str,
    windows: list[tuple[float, float, str]],
    host_by_ip: dict[str, str],
) -> dict:
    if detector == "wazuh":
        fields = extract_wazuh_fields(record)
    elif detector == "suricata":
        fields = extract_suricata_fields(record)
    else:
        fields = extract_aminer_fields(record, host_by_ip)

    timestamp = get_timestamp(record, detector)
    return {
        "detector_source": detector,
        "timestamp": timestamp,
        "name": fields.name,
        "host": fields.host,
        "severity": fields.severity,
        "attack_window": find_attack_window(timestamp, windows),
        "native_technique_ids": fields.native_technique_ids,
        "rule_id": fields.rule_id,
    }


def normalize(
    alerts_path: Path,
    labels_path: Path,
    scenario: str = "russellmitchell",
) -> pd.DataFrame:
    windows = load_attack_windows(labels_path, scenario)
    aminer_hosts = discover_aminer_hosts(alerts_path)
    rows = []

    with alerts_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            rows.append(normalize_record(
                record,
                record["detector_source"],
                windows,
                aminer_hosts,
            ))

    df = pd.DataFrame(rows, columns=COLUMNS)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def normalize_scenario(
    raw_dir: Path,
    labels_path: Path,
    scenario: str,
    event_csv_dir: Path | None = None,
) -> pd.DataFrame:
    aminer_path = raw_dir / f"{scenario}_aminer.json"
    wazuh_path = raw_dir / f"{scenario}_wazuh.json"
    windows = load_attack_windows(labels_path, scenario)
    aminer_hosts = discover_aminer_hosts(aminer_path)
    rows = []

    # The official label CSV follows raw file order: Wazuh, then AMiner.
    event_labels: list[str] | None = None
    aminer_offset = 0
    if event_csv_dir is not None:
        from core.event_labels import load_scenario_labels
        _, _, _, event_labels = load_scenario_labels(event_csv_dir, scenario)
        with wazuh_path.open(encoding="utf-8") as fh:
            aminer_offset = sum(1 for _ in fh)

    with aminer_path.open(encoding="utf-8") as fh:
        for position, line in enumerate(fh):
            row = normalize_record(
                json.loads(line),
                "aminer",
                windows,
                aminer_hosts,
            )
            if event_labels is not None:
                row["event_label"] = event_labels[aminer_offset + position]
            rows.append(row)

    with wazuh_path.open(encoding="utf-8") as fh:
        for position, line in enumerate(fh):
            record = json.loads(line)
            detector = classify_wazuh_record(record)
            if detector:
                row = normalize_record(
                    record,
                    detector,
                    windows,
                    aminer_hosts,
                )
                if event_labels is not None:
                    row["event_label"] = event_labels[position]
                rows.append(row)

    columns = COLUMNS + ["event_label"] if event_labels is not None else COLUMNS
    df = pd.DataFrame(rows, columns=columns)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)





if __name__ == "__main__":
    df = normalize(Path("data/ait_alerts.json"), Path("data/labels.csv"))
    print(f"{len(df)} alerts")
    print(df.groupby("detector_source").size())
