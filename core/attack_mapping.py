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
from pathlib import Path

import pandas as pd


@dataclass
class AlertMapping:
    technique_ids: str        # ATT&CK IDs separated by semicolons
    tactics: tuple[str, ...]  # all tactics linked to all techniques in 1 alert
    source: str               # mapping source: rule, suppressed, native, or none


def build_attack_lookup(stix_path: Path, out_path: Path) -> dict:
    bundle = json.load(stix_path.open(encoding="utf-8"))
    objects = bundle["objects"]

    tactic_names = {}
    tactic_by_ref = {}

    # we directly use the tactic shortname as the display name
    for obj in objects:
        if obj["type"] == "x-mitre-tactic":
            tactic_names[obj["x_mitre_shortname"]] = obj["name"]
            tactic_by_ref[obj["id"]] = obj["name"]

    matrix = next(obj for obj in objects if obj["type"] == "x-mitre-matrix")

    tactic_order = [
        tactic_by_ref[ref]
        for ref in matrix["tactic_refs"]
        if ref in tactic_by_ref
    ]

    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break
        if not tid:
            continue
        tactics = [tactic_names.get(phase["phase_name"], phase["phase_name"])
                   for phase in obj.get("kill_chain_phases", [])]
        techniques[tid] = {
            "name": obj["name"],
            "tactics": tactics,
            "deprecated": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
        }

    lookup = {"tactic_order": tactic_order, "techniques": techniques}
    out_path.write_text(json.dumps(lookup, indent=1), encoding="utf-8")
    return lookup


def load_attack_lookup(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATTACK_LOOKUP = load_attack_lookup(PROJECT_ROOT / "data" / "attack_lookup.json")
TACTIC_ORDER = ATTACK_LOOKUP["tactic_order"]


def load_detection_mappings(path: Path) -> dict[str, dict[str, list[str]]]:
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


DETECTION_MAPPINGS = load_detection_mappings(
    PROJECT_ROOT / "data" / "detection_mappings.json"
)


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

    # keep tactics in ATT&CK matrix order
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
        # split multi-tactic alerts into one row per tactic
        expanded = rows_with_tactics.explode("tactics")
        first_seen = expanded.groupby("tactics")["timestamp"].min()

        timeline = []
        for tactic, timestamp in first_seen.items():
            timeline.append((float(timestamp), str(tactic)))

        # break timestamp ties using ATT&CK matrix order
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
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Alert counts per observed ATT&CK technique (Meerkat)",
        "techniques": [
            {"techniqueID": tid, "score": n, "comment": f"{n} alerts"}
            for tid, n in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ffe766", "#ff6666"],
                     "minValue": 0, "maxValue": max(counts.values())},
    }
    path.write_text(json.dumps(layer, indent=1), encoding="utf-8")
    return len(counts)


if __name__ == "__main__":
    from datetime import datetime, timezone

    from core.normalize import normalize

    df = normalize(
        Path("data/ait_alerts.json"),
        Path("data/labels.csv"),
        Path("data/raw/inventory/russellmitchell.json"),
    )
    mapped = [
        map_alert(detector, rule_id, technique_ids)
        for detector, rule_id, technique_ids in zip(
            df["detector_source"], df["rule_id"], df["native_technique_ids"]
        )
    ]
    df["technique_ids"] = [m.technique_ids for m in mapped]
    df["tactics"] = [m.tactics for m in mapped]
    df["map_source"] = [m.source for m in mapped]

    in_window = df["attack_window"] != ""
    has_technique = df["technique_ids"] != ""
    has_tactic = df["tactics"].map(bool)
    print(f"technique coverage: {has_technique.mean():.1%} ({int(has_technique.sum())})")
    print(f"tactic coverage: {has_tactic.mean():.1%} overall | "
          f"{has_tactic[in_window].mean():.1%} in-window | "
          f"{has_tactic[~in_window].mean():.1%} outside")
    print("source counts:", df["map_source"].value_counts().to_dict())
    print("tactic counts:", {k: v for k, v in tactic_coverage(df["tactics"]).items() if v})

    print("\nattack story (in-window alerts):")
    for host, steps in attack_story(df[in_window]).items():
        chain = " -> ".join(
            f"{tactic}({datetime.fromtimestamp(ts, tz=timezone.utc):%H:%M})"
            for ts, tactic in steps
        ) or "no mapped ATT&CK tactic"
        print(f"  {host}: {chain}")

    n = export_navigator_layer(df["technique_ids"], Path("docs/navigator_layer.json"))
    print(f"\nnavigator layer: {n} distinct techniques exported to docs/")
