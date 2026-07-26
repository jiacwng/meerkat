"""Map detector alerts to MITRE ATT&CK and build analyst context.

Public API:
    map_alert(detector, rule_id, native_ids) -> AlertMapping
    attack_story(df)                        -> per-host tactic timeline
    alert_context(df, host, timestamp)      -> one alert's known tactic history
    tactic_coverage(tactics)                -> counts across all tactics
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

import pandas as pd


@dataclass
class AlertMapping:
    technique_ids: str        # ATT&CK IDs separated by semicolons
    tactics: tuple[str, ...]  # all tactics linked to all techniques in 1 alert
    source: str               # mapping source: rule, suppressed, native, or none


def load_attack_lookup(path: Traversable | Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# the json lives inside the package so pip installs it; resources.files finds it
# in a wheel, an editable install and a zip alike, where a path walked up from
# __file__ points at a repo directory that was never shipped
DATA_DIR = resources.files("core") / "data"
ATTACK_LOOKUP = load_attack_lookup(DATA_DIR / "attack_lookup.json")
TACTIC_ORDER = ATTACK_LOOKUP["tactic_order"]
# the technique names and the tactic order both come from this release. The lookup
# file holds tactic_order and techniques and nothing else, so the release is only
# recorded here and has to be changed by hand when the lookup is rebuilt.
ATTACK_RELEASE = "19.1"          # Enterprise ATT&CK, STIX distribution
ATTACK_VERSION = ATTACK_RELEASE.split(".")[0]   # navigator layers take the major


def load_detection_mappings(path: Traversable | Path) -> dict[str, dict[str, list[str]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    mappings = {k: v for k, v in raw.items() if not k.startswith("_")}

    known = ATTACK_LOOKUP["techniques"]
    unknown = set()
    for detector_rules in mappings.values():
        for technique_ids in detector_rules.values():
            for technique_id in technique_ids:
                if technique_id not in known:
                    unknown.add(technique_id)

    # configured IDs must exist, detector IDs may be newer than our lookup
    if unknown:
        raise ValueError(
            f"unknown configured ATT&CK techniques: {sorted(unknown)}"
        )
    return mappings


DETECTION_MAPPINGS = load_detection_mappings(DATA_DIR / "detection_mappings.json")


def technique_name(technique_id: str) -> str:
    entry = ATTACK_LOOKUP["techniques"].get(technique_id)
    if entry is None:
        return technique_id
    return str(entry["name"])


def tactics_for_techniques(technique_ids: str) -> tuple[str, ...]:
    found: set[str] = set()

    for technique_id in technique_ids.split(";"):
        technique_id = technique_id.strip()
        if not technique_id:
            continue

        entry = ATTACK_LOOKUP["techniques"].get(technique_id)
        if entry is None:
            continue

        for tactic in entry.get("tactics", []):
            found.add(tactic)

    ordered = []
    for tactic in TACTIC_ORDER:
        if tactic in found:
            ordered.append(tactic)

    return tuple(ordered)


def map_alert(detector_source: str, rule_id: str, native_technique_ids: str) -> AlertMapping:
    configured = DETECTION_MAPPINGS.get(detector_source, {}).get(rule_id)

    if configured is not None:
        if configured:
            joined = ";".join(configured)
            return AlertMapping(joined, tactics_for_techniques(joined), "rule")
        # an empty mapping means the rule was reviewed and maps to nothing
        return AlertMapping("", (), "suppressed")

    if native_technique_ids:
        tactics = tactics_for_techniques(native_technique_ids)
        return AlertMapping(native_technique_ids, tactics, "native")

    return AlertMapping("", (), "")


def attack_story(df: pd.DataFrame) -> dict[str, list[tuple[float, str]]]:
    story: dict[str, list[tuple[float, str]]] = {}

    for host, host_alerts in df.groupby("host", sort=False):
        rows_with_tactics = host_alerts[host_alerts["tactics"].map(bool)]
        expanded = rows_with_tactics.explode("tactics")
        first_seen = expanded.groupby("tactics")["timestamp"].min()

        timeline = []
        for tactic, timestamp in first_seen.items():
            timeline.append((float(timestamp), str(tactic)))

        # two tactics can land on the same instant, and matrix order gives that
        # tie one answer instead of whatever order the groupby happened to emit
        timeline.sort(key=lambda step: (step[0], TACTIC_ORDER.index(step[1])))
        story[host] = timeline

    return story


def alert_context(
    df: pd.DataFrame,
    host: str,
    timestamp: float,
) -> list[tuple[float, str]]:
    # only alerts up to this timestamp, a live analyst cannot see later ones
    known_rows = df[(df["host"] == host) & (df["timestamp"] <= timestamp)]
    return attack_story(known_rows).get(host, [])

def tactic_coverage(tactics: pd.Series) -> dict[str, int]:
    # empty tuples become NaN when exploded, hence the dropna
    expanded = tactics.explode().dropna()
    counts = expanded.value_counts()
    return {tactic: int(counts.get(tactic, 0)) for tactic in TACTIC_ORDER}


def export_navigator_layer(technique_ids, path: Path,
                           name: str = "Meerkat observed techniques") -> int:
    counts: dict[str, int] = {}
    for joined in technique_ids:
        if not joined:
            continue
        for technique_id in joined.split(";"):
            counts[technique_id] = counts.get(technique_id, 0) + 1

    layer = {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Alert counts per observed ATT&CK technique (Meerkat)",
        "techniques": [
            {"techniqueID": tid, "score": n, "comment": f"{n} alerts"}
            for tid, n in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ffe766", "#ff6666"],
                     "minValue": 0, "maxValue": max(counts.values(), default=1)},
    }
    path.write_text(json.dumps(layer, indent=1), encoding="utf-8")
    return len(counts)
