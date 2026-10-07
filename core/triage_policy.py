# The queue order and the ATT&CK mapping of alerts. queue_order is the one place
# that decides which family comes first, so every consumer goes through it.

from __future__ import annotations

import pandas as pd

from core.attack_mapping import DETECTION_MAPPINGS, map_alert


def queue_order(families: pd.DataFrame) -> pd.DataFrame:
    # raw ranking score, never the calibrated probability, so display changes
    # cannot reorder an analyst's day; ties break on start and id
    return families.sort_values(
        ["scenario", "day", "ranking_score", "start", "representative_session_id"],
        ascending=[True, True, False, True, True],
        kind="stable",
    )


def enrich_alerts(
    frame: pd.DataFrame,
    mappings: dict[str, dict[str, list[str]]] = DETECTION_MAPPINGS,
) -> pd.DataFrame:
    keys = list(zip(
        frame["detector_source"], frame["rule_id"], frame["native_technique_ids"]
    ))
    mapped = {key: map_alert(*key, mappings) for key in set(keys)}
    enriched = frame.copy()
    enriched["technique_ids"] = [mapped[key].technique_ids for key in keys]
    enriched["tactics"] = [mapped[key].tactics for key in keys]
    enriched["mapping_source"] = [mapped[key].source for key in keys]
    return enriched
