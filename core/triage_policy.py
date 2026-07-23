"""Select a bounded daily queue of scored review families.

Public API:
    daily_queue(families, k) -> the k families an analyst reviews that day
    enrich_alerts(frame)     -> alerts with ATT&CK mapping columns
"""

from __future__ import annotations

import pandas as pd

from core.attack_mapping import map_alert


def daily_queue(families: pd.DataFrame, k: int = 25) -> pd.DataFrame:
    # the queue is ordered by the raw ranking score, never by the calibrated
    # probability, so display changes cannot reorder an analyst's day
    group_columns = ["day"]
    if "scenario" in families.columns:
        group_columns.insert(0, "scenario")

    ordered = families.sort_values(
        group_columns + ["ranking_score", "start", "representative_session_id"],
        ascending=[True] * len(group_columns) + [False, True, True],
        kind="stable",
    )
    return (
        ordered.groupby(group_columns, sort=False, observed=True)
        .head(k)
        .reset_index(drop=True)
    )


def enrich_alerts(frame: pd.DataFrame) -> pd.DataFrame:
    mappings = [
        map_alert(row.detector_source, row.rule_id, row.native_technique_ids)
        for row in frame.itertuples(index=False)
    ]
    enriched = frame.copy()
    enriched["technique_ids"] = [mapping.technique_ids for mapping in mappings]
    enriched["tactics"] = [mapping.tactics for mapping in mappings]
    enriched["mapping_source"] = [mapping.source for mapping in mappings]
    return enriched
