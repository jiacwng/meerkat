"""Load the merged AIT-ADS alert file into one normalized alert table.

Public API:
    normalize(alerts_path, labels_path, scenario="russellmitchell") -> pd.DataFrame
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

""" We use those columns that will be processed and used as features for the model, only attack_window won't
be used as our ground truth for grading """

COLUMNS = ["detector_source", "timestamp", "name", "host", "severity", "attack_window",
           "native_technique_ids", "rule_id"]


@dataclass
class ExtractedFields:
    """Simple structure to simplify what the 3 detectors are supposed to produce"""
    name: str
    host: str
    severity: float
    native_technique_ids: str = ""   # ";"-joined ATT&CK IDs, wazuh only
    rule_id: str = ""                # stable detector rule identity, for mapping config


"""context : a label.csv file contains the attack windows of the simulation,
    we need it for the ground truth"""

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
    # Aminer already stores the timestamp, 
    # wazuh/suricata store an ISO-8601 string ending in "Z" for UTC
    if detector == "aminer":
        return float(record["LogData"]["Timestamps"][0])
    return datetime.fromisoformat(record["@timestamp"]).timestamp()
    

""" Both Wazuh and Suricata have completely different conventions"""

def extract_wazuh_fields(record: dict) -> ExtractedFields:
    rule = record["rule"]
    host = record.get("predecoder", {}).get("hostname") or record["agent"]["name"]
    mitre = rule.get("mitre") or {}
    return ExtractedFields(
        name = rule["description"],
        host = host,
        severity = float(rule["level"]),
        # mitre IDs fields have multiple values so we join them
        native_technique_ids=";".join(mitre.get("id") or []),
        rule_id = str(rule.get("id", "")),
    )
    

def extract_suricata_fields(record: dict) -> ExtractedFields:
    alert = record["data"]["alert"]
    return ExtractedFields(
        name = alert["signature"],
        host = record["agent"]["name"],
        severity = float(alert["severity"]),
        rule_id = str(alert.get("signature_id", "")),
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
            if record["detector_source"] != "aminer":
                continue
            ip = str(record["AMiner"]["ID"])
            candidates[ip].update(aminer_host_candidates(record))

    return {
        ip: next(iter(names))
        for ip, names in candidates.items()
        if len(names) == 1
    }


def extract_aminer_fields(
    record: dict,
    host_by_ip: dict[str, str],
) -> ExtractedFields:
    ip = str(record["AMiner"]["ID"])
    component = record["AnalysisComponent"]["AnalysisComponentName"]
    return ExtractedFields(
        name = component,
        host = host_by_ip[ip],
        severity = float("nan"),
        # aminer has no numeric rule ids; the analysis component IS its stable identity
        rule_id = str(component),
    )
    


def normalize(alerts_path: Path, labels_path: Path, scenario: str = "russellmitchell") -> pd.DataFrame:
    windows = load_attack_windows(labels_path,scenario)
    aminer_hosts = discover_aminer_hosts(alerts_path)
    rows = []

    with alerts_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            detector = record["detector_source"]

            if detector == "wazuh":
                fields = extract_wazuh_fields(record)
            elif detector == "suricata":
                fields = extract_suricata_fields(record)
            elif detector == "aminer":
                fields = extract_aminer_fields(record, aminer_hosts)

            timestamp = get_timestamp(record, detector)
            window = find_attack_window(timestamp, windows)

            rows.append({
            "detector_source": detector,
            "timestamp": timestamp,
            "name": fields.name,
            "host": fields.host,
            "severity": fields.severity,
            "attack_window": window,
            "native_technique_ids": fields.native_technique_ids,
            "rule_id": fields.rule_id,
            })
    
    df = pd.DataFrame(rows,columns=COLUMNS)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)





if __name__ == "__main__":
    df = normalize(Path("data/ait_alerts.json"), Path("data/labels.csv"))
    print(f"{len(df)} alerts")
    print(df.groupby("detector_source").size())
