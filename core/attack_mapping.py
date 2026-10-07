# Maps detector alerts to MITRE ATT&CK techniques and tactics, orders one host's
# tactics into an attack chain, and writes an ATT&CK Navigator layer.

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path


@dataclass
class AlertMapping:
    technique_ids: str        # ATT&CK IDs separated by semicolons
    tactics: tuple[str, ...]  # all tactics linked to all techniques in 1 alert
    source: str               # mapping source: rule, suppressed, native, or none


# resources.files finds the json in a wheel, an editable install and a zip alike
DATA_DIR = resources.files("core") / "data"
ATTACK_LOOKUP = json.loads((DATA_DIR / "attack_lookup.json").read_text(encoding="utf-8"))
TACTIC_ORDER = ATTACK_LOOKUP["tactic_order"]
# the technique names and the tactic order both come from this release; the lookup
# file does not record it, so change it by hand when the lookup is rebuilt
ATTACK_RELEASE = "19.1"          # Enterprise ATT&CK, STIX distribution
ATTACK_VERSION = ATTACK_RELEASE.split(".")[0]   # navigator layers take the major


def load_detection_mappings(path: Traversable | Path) -> dict[str, dict[str, list[str]]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.name} is not valid JSON: {error.msg}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name} must map a detector to its rules")
    mappings = {k: v for k, v in raw.items() if not str(k).startswith("_")}
    for detector, rules in mappings.items():
        if not isinstance(rules, dict) or not all(
            isinstance(ids, list) and all(isinstance(i, str) for i in ids)
            for ids in rules.values()
        ):
            raise ValueError(
                f"{path.name}: {detector} must map each rule id to a list of "
                "technique ids"
            )

    known = ATTACK_LOOKUP["techniques"]
    unknown = {
        technique_id
        for rules in mappings.values()
        for ids in rules.values()
        for technique_id in ids
        if technique_id not in known
    }
    if unknown:
        raise ValueError(
            f"{path.name}: unknown ATT&CK techniques {sorted(unknown)}"
        )
    return mappings


DETECTION_MAPPINGS = load_detection_mappings(DATA_DIR / "detection_mappings.json")


def with_local_mappings(path: Path | None) -> dict[str, dict[str, list[str]]]:
    if path is None:
        return DETECTION_MAPPINGS
    merged = {detector: dict(rules) for detector, rules in DETECTION_MAPPINGS.items()}
    for detector, rules in load_detection_mappings(path).items():
        merged.setdefault(detector, {}).update(rules)
    return merged


def technique_name(technique_id: str) -> str:
    entry = ATTACK_LOOKUP["techniques"].get(technique_id)
    return technique_id if entry is None else str(entry["name"])


def tactics_for_techniques(technique_ids: str) -> tuple[str, ...]:
    found: set[str] = set()
    for technique_id in technique_ids.split(";"):
        entry = ATTACK_LOOKUP["techniques"].get(technique_id.strip())
        if entry is not None:
            found.update(entry.get("tactics", []))
    return tuple(tactic for tactic in TACTIC_ORDER if tactic in found)


def map_alert(
    detector_source: str,
    rule_id: str,
    native_technique_ids: str,
    mappings: dict[str, dict[str, list[str]]] = DETECTION_MAPPINGS,
) -> AlertMapping:
    configured = mappings.get(detector_source, {}).get(rule_id)
    if configured is not None:
        if configured:
            joined = ";".join(configured)
            return AlertMapping(joined, tactics_for_techniques(joined), "rule")
        return AlertMapping("", (), "suppressed")
    if native_technique_ids:
        tactics = tactics_for_techniques(native_technique_ids)
        return AlertMapping(native_technique_ids, tactics, "native")
    return AlertMapping("", (), "")


@dataclass
class HostChain:
    steps: list[tuple[str, float]]   # tactic and the time the chain first reached it
    off_chain: tuple[str, ...]       # tactics seen that day but not on the chain

    @property
    def length(self) -> int:
        return len(self.steps)


# After RapSheet (Hassan et al., IEEE S&P 2020): the longest time-ordered run of
# alerts whose tactics never go back in matrix order. One alert gives at most one
# tactic, and the length counts distinct tactics, so it is a longest increasing
# subsequence over tactic positions, at most 15 states per alert.
def host_chain(timestamps, tactics) -> HostChain:
    position = {tactic: index for index, tactic in enumerate(TACTIC_ORDER)}
    best: list[list[tuple[str, float]]] = [[] for _ in TACTIC_ORDER]
    seen: set[str] = set()
    for timestamp, alert_tactics in sorted(
        zip(timestamps, tactics), key=lambda pair: pair[0]
    ):
        known = [tactic for tactic in alert_tactics if tactic in position]
        seen.update(known)
        before = [list(chain) for chain in best]
        for tactic in known:
            index = position[tactic]
            longest = max(before[:index], key=len, default=[])
            if len(longest) + 1 > len(best[index]):
                best[index] = longest + [(tactic, float(timestamp))]
    chain = max(best, key=len)
    on_chain = {tactic for tactic, _ in chain}
    off_chain = tuple(
        tactic for tactic in TACTIC_ORDER if tactic in seen and tactic not in on_chain
    )
    return HostChain(chain, off_chain)


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
