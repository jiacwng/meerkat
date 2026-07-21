"""Combine model and detector evidence into a daily analyst queue.

Event evidence can raise an alert's priority, but never lower it.

Public API:
    combined_evidence(context_risk, event_score) -> np.ndarray
    assign_bands(context_risk, event_score, urgency_tier) -> np.ndarray
    daily_queue(frame, k, representative_first) -> selected alerts
    enrich_alerts(frame) -> alerts with ATT&CK mapping columns
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from core.attack_mapping import map_alert
from core.classifier import DEFAULT_THRESHOLDS

BAND_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
SECONDS_PER_DAY = 86400.0


def combined_evidence(context_risk: np.ndarray, event_score: np.ndarray) -> np.ndarray:
    # Taking the maximum prevents one model from lowering the other's score.
    return np.maximum(np.asarray(context_risk, float), np.asarray(event_score, float))


def assign_bands(
    context_risk: np.ndarray,
    event_score: np.ndarray,
    urgency_tier: np.ndarray,
) -> np.ndarray:
    thresholds = DEFAULT_THRESHOLDS
    evidence = combined_evidence(context_risk, event_score)
    urgency = np.asarray(urgency_tier, float)

    bands = np.full(len(evidence), "LOW", dtype=object)
    bands[evidence >= thresholds.medium] = "MEDIUM"
    bands[evidence >= thresholds.high] = "HIGH"
    # High-urgency detector findings must remain at least HIGH.
    bands[urgency >= 2] = np.where(
        evidence[urgency >= 2] >= thresholds.critical, "CRITICAL", "HIGH"
    )
    return bands


def daily_queue(
    frame: pd.DataFrame,
    k: int = 50,
    representative_first: bool = True,
) -> pd.DataFrame:
    """Representative-first, band-major selection of k alerts per UTC day.

    frame needs: timestamp, band, evidence, host, detector_source, rule_id.
    """
    selected = []
    frame = frame.copy()
    frame["day"] = (frame["timestamp"] // SECONDS_PER_DAY).astype(int)
    frame["band_rank"] = frame["band"].map(BAND_ORDER)

    for _, day_rows in frame.groupby("day", sort=True):
        day_rows = day_rows.sort_values(
            ["band_rank", "evidence"], ascending=[False, False], kind="stable"
        )
        picked_index: list = []
        for _, band_rows in day_rows.groupby("band_rank", sort=False):
            if len(picked_index) >= k:
                break
            ordered_index = list(band_rows.index)
            if representative_first:
                groups = band_rows.groupby(
                    ["host", "detector_source", "rule_id"], sort=False
                )
                representatives = band_rows.loc[
                    groups["evidence"].idxmax().to_numpy()
                ].sort_values("evidence", ascending=False, kind="stable")
                remaining = band_rows.drop(representatives.index).sort_values(
                    "evidence", ascending=False, kind="stable"
                )
                ordered_index = list(representatives.index) + list(remaining.index)
            for index in ordered_index:
                if len(picked_index) >= k:
                    break
                picked_index.append(index)
        selected.append(frame.loc[picked_index])

    return pd.concat(selected) if selected else frame.iloc[0:0]


def enrich_alerts(frame: pd.DataFrame) -> pd.DataFrame:
    """Attach reviewed/native ATT&CK mappings to a batch of alerts."""
    mappings = [
        map_alert(row.detector_source, row.rule_id, row.native_technique_ids)
        for row in frame.itertuples(index=False)
    ]
    enriched = frame.copy()
    enriched["technique_ids"] = [mapping.technique_ids for mapping in mappings]
    enriched["tactics"] = [mapping.tactics for mapping in mappings]
    enriched["mapping_source"] = [mapping.source for mapping in mappings]
    return enriched
