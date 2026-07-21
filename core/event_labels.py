"""Load and verify the official AIT-ADS per-alert labels.

The official CSV lists every raw alert in file order: all wazuh-file rows
first, then all aminer rows. Labels are attached to raw records by position,
so the audit verifies that ordering before the labels are used.

Public API:
    load_scenario_labels(csv_dir, scenario) -> timestamps/names/time/event labels
    audit_scenario(raw_dir, csv_dir, labels_path, scenario) -> dict
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from core.normalize import (
    find_attack_window,
    get_timestamp,
    load_attack_windows,
)


def load_scenario_labels(
    csv_dir: Path,
    scenario: str,
) -> tuple[list[float], list[str], list[str], list[str]]:
    timestamps: list[float] = []
    names: list[str] = []
    time_labels: list[str] = []
    event_labels: list[str] = []
    with (csv_dir / f"{scenario}_alerts.txt").open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        next(reader)  # header
        for row in reader:
            timestamps.append(float(row[0]))
            names.append(row[1])
            time_labels.append("" if row[5] == "false_positive" else row[5])
            event_labels.append("" if row[6] == "-" else row[6])
    return timestamps, names, time_labels, event_labels


def _csv_name_matches(csv_name: str, record: dict, detector: str) -> bool:
    if detector == "aminer":
        raw = record["AnalysisComponent"]["AnalysisComponentName"]
        return csv_name == raw
    # wazuh-file rows: suricata descriptions already carry their own prefix,
    # everything else is prefixed "Wazuh: " in the official CSV
    description = record["rule"]["description"]
    if description.startswith("Suricata:"):
        return csv_name == description
    return csv_name == f"Wazuh: {description}"


def audit_scenario(
    raw_dir: Path,
    csv_dir: Path,
    labels_path: Path,
    scenario: str,
) -> dict:
    """Assert the positional join is safe; return the label counts."""
    csv_times, names, time_labels, event_labels = load_scenario_labels(
        csv_dir, scenario
    )
    windows = load_attack_windows(labels_path, scenario)

    wazuh_path = raw_dir / f"{scenario}_wazuh.json"
    aminer_path = raw_dir / f"{scenario}_aminer.json"

    counts = {
        "scenario": scenario,
        "csv_rows": len(names),
        "raw_rows": 0,
        "retained": 0,
        "dropped_snort": 0,
        "dropped_snort_event_positive": 0,
        "event_positive_retained": 0,
        "time_label_mismatches": 0,
        "unexplained_time_label_mismatches": 0,
        "name_mismatches": 0,
        "position_mismatches": 0,
    }

    position = 0
    with wazuh_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            if not _csv_name_matches(names[position], record, "wazuh"):
                counts["name_mismatches"] += 1
            detector = (
                "suricata" if "alert" in record.get("data", {}) else "wazuh"
            )
            stamp = get_timestamp(record, detector)
            if int(stamp) != int(csv_times[position]):
                counts["position_mismatches"] += 1
            dropped = (record.get("decoder") or {}).get("name") == "snort"
            if dropped:
                counts["dropped_snort"] += 1
                if event_labels[position]:
                    counts["dropped_snort_event_positive"] += 1
            else:
                counts["retained"] += 1
                if event_labels[position]:
                    counts["event_positive_retained"] += 1
                # official time label must equal our interval-derived window
                if find_attack_window(stamp, windows) != time_labels[position]:
                    counts["time_label_mismatches"] += 1
                    if not any(
                        abs(stamp - start) <= 1 or abs(stamp - end) <= 1
                        for start, end, _ in windows
                    ):
                        counts["unexplained_time_label_mismatches"] += 1
            position += 1

    with aminer_path.open(encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line)
            if not _csv_name_matches(names[position], record, "aminer"):
                counts["name_mismatches"] += 1
            stamp = get_timestamp(record, "aminer")
            if int(stamp) != int(csv_times[position]):
                counts["position_mismatches"] += 1
            counts["retained"] += 1
            if event_labels[position]:
                counts["event_positive_retained"] += 1
            if find_attack_window(stamp, windows) != time_labels[position]:
                counts["time_label_mismatches"] += 1
                if not any(
                    abs(stamp - start) <= 1 or abs(stamp - end) <= 1
                    for start, end, _ in windows
                ):
                    counts["unexplained_time_label_mismatches"] += 1
            position += 1

    counts["raw_rows"] = position
    if counts["csv_rows"] != counts["raw_rows"]:
        raise AssertionError(f"{scenario}: csv/raw row count mismatch {counts}")
    if counts["name_mismatches"]:
        raise AssertionError(f"{scenario}: positional names disagree {counts}")
    if counts["position_mismatches"]:
        raise AssertionError(f"{scenario}: positional fields disagree {counts}")
    if counts["unexplained_time_label_mismatches"]:
        raise AssertionError(f"{scenario}: unexplained time labels {counts}")
    if counts["dropped_snort_event_positive"]:
        raise AssertionError(f"{scenario}: dedup would drop event positives {counts}")
    return counts


if __name__ == "__main__":
    raw_dir = Path("data/raw")
    csv_dir = Path("data/raw/alerts_csv")
    labels = Path("data/labels.csv")
    total_positive = 0
    total_retained = 0
    for scenario in ("fox", "harrison", "russellmitchell", "santos",
                     "shaw", "wardbeck", "wheeler", "wilson"):
        result = audit_scenario(raw_dir, csv_dir, labels, scenario)
        total_positive += result["event_positive_retained"]
        total_retained += result["retained"]
        print(result)
    print(f"retained {total_retained}, event-positive {total_positive}")
