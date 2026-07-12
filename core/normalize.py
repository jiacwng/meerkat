"""Load the merged AIT-ADS alert file into one normalized alert table.

Public API:
    normalize(alerts_path, labels_path, scenario="russellmitchell") -> pd.DataFrame
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

""" We use those columns that will be processed and used as features for the model, only attack_window won't
be used as our ground truth for grading """

COLUMNS = ["detector_source", "timestamp", "name", "host", "severity", "attack_window"]


AMINER_HOST_BY_IP = {
    "172.19.130.4":    "mail",
    "10.143.2.4":      "intranet-server",
    "172.19.130.106":  "cloud-share",
    "192.168.231.254": "inet-dns",
    "172.19.128.1":    "inet-firewall",
    "192.168.231.164": "morris-mail",
    "192.168.231.56":  "davey-mail",
    "172.19.130.68":   "webserver",
    "10.143.0.103":    "internal-share",
    "172.19.131.174":  "vpn",
}


@dataclass
class ExtractedFields:
    """Simple structure to simplify what the 3 detectors are supposed to produce"""
    name: str
    host: str
    severity: float

"""context : a label.csv file contains the attack windows produced by the simulation,
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
    host = record.get("predecoder", {}).get("hostname") or record["agent"].get("name") or "unknown"
    return ExtractedFields(
        name = rule["description"],
        host = host,
        severity = float(rule["level"]),
    )
    

def extract_suricata_fields(record: dict) -> ExtractedFields:
    alert = record["data"]["alert"]
    return ExtractedFields(
        name = alert["signature"],
        host = record["agent"]["name"],
        severity = float(alert["severity"]),
    )
    


def extract_aminer_fields(record: dict) -> ExtractedFields:
    ip = record.get("AMiner", {}).get("ID")
    return ExtractedFields(
        name = record["AnalysisComponent"]["AnalysisComponentName"],
        host = AMINER_HOST_BY_IP.get(ip,ip) if ip else "unknown",
        severity = float("nan"),
    )
    


def normalize(alerts_path: Path, labels_path: Path, scenario: str = "russellmitchell") -> pd.DataFrame:
    windows = load_attack_windows(labels_path,scenario)
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
                fields = extract_aminer_fields(record)
            else:
                raise ValueError(f"unrecognized detector_source: {detector!r}")

            timestamp = get_timestamp(record, detector)
            window = find_attack_window(timestamp, windows)

            rows.append({
            "detector_source": detector,
            "timestamp": timestamp,
            "name": fields.name,
            "host": fields.host,
            "severity": fields.severity,
            "attack_window": window,
            })
    
    df = pd.DataFrame(rows,columns=COLUMNS)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)





if __name__ == "__main__":
    df = normalize(Path("data/ait_alerts.json"), Path("data/labels.csv"))
    print(f"{len(df)} alerts")
    print(df.groupby("detector_source").size())