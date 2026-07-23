"""Group normalized alerts into sessions and daily review families.

A session holds alerts from one entity, detector and rule until that stream goes
quiet for more than ten minutes. A family joins same-day sessions sharing that
identity and carries the aggregates used by the family re-ranker.

Public API:
    assign_sessions(alerts, gap_s)              -> session number per alert
    build_sessions(alerts, scenario, inventory) -> one row per session
    build_families(scored_sessions)             -> one row per review family
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from core.features import standardize_severity
from core.inventory import Inventory


SECONDS_PER_DAY = 86400.0
SESSION_GAP_S = 600.0
SESSION_KEY = ("entity_id", "detector_source", "rule_id")
FAMILY_KEY = ("day", "entity_id", "detector_source", "rule_id")


def assign_sessions(alerts: pd.DataFrame, gap_s: float = SESSION_GAP_S) -> pd.Series:
    # alerts must already be sorted by key then timestamp, so one forward scan
    # is enough to close a session on the first long silence
    key_changed = alerts[list(SESSION_KEY)].ne(
        alerts[list(SESSION_KEY)].shift()
    ).any(axis=1)
    quiet = alerts["timestamp"].diff().gt(gap_s)
    return (key_changed | quiet).cumsum() - 1


def _nonempty(values: pd.Series) -> frozenset[str]:
    return frozenset(value for value in values.astype(str) if value)


def _window_ids(values: pd.Series) -> frozenset[int]:
    return frozenset(int(value) for value in values if value >= 0)


def _split_values(values: pd.Series) -> frozenset[str]:
    found = set()
    for value in values.fillna("").astype(str):
        found.update(part for part in value.split(";") if part)
    return frozenset(found)


def _asset_roles(entity_id: str, inventory: Inventory) -> tuple[str, ...]:
    asset = inventory.assets_by_ip.get(entity_id)
    return asset.groups if asset else ()


def _nearby_detector_count(
    sessions: pd.DataFrame,
    gap_s: float = SESSION_GAP_S,
) -> pd.Series:
    counts = np.ones(len(sessions), dtype=float)
    for positions in sessions.groupby(
        "entity_id", sort=False, observed=True
    ).indices.values():
        positions = np.asarray(positions)
        entity_sessions = sessions.iloc[positions]
        starts = entity_sessions["start"].to_numpy(dtype=float)
        ends = entity_sessions["end"].to_numpy(dtype=float)
        detectors = entity_sessions["detector_source"].astype(str).to_numpy()

        for local_position, session_position in enumerate(positions):
            nearby = (
                (starts <= ends[local_position] + gap_s)
                & (ends >= starts[local_position] - gap_s)
            )
            counts[session_position] = len(set(detectors[nearby]))
    return pd.Series(counts, index=sessions.index, dtype=float)


def build_sessions(
    alerts: pd.DataFrame,
    scenario: str,
    inventory: Inventory,
    gap_s: float = SESSION_GAP_S,
) -> pd.DataFrame:
    work = alerts.copy()
    work["scenario"] = scenario
    work["_alert_row"] = np.arange(len(work))
    if "event_label" not in work:
        work["event_label"] = ""
    work["event_label"] = work["event_label"].fillna("").astype(str)
    work["_is_event"] = work["event_label"].ne("")
    if "window_id" not in work:
        work["window_id"] = -1
    work["_labelled_window"] = work["window_id"].where(work["_is_event"], -1)
    work["_severity"] = standardize_severity(
        work["detector_source"], work["severity"]
    )
    work["_has_technique"] = (
        work["native_technique_ids"].fillna("").astype(str).ne("")
    )
    work["_asset_roles"] = [
        _asset_roles(str(entity), inventory)
        for entity in work["entity_id"]
    ]
    work = work.sort_values(
        list(SESSION_KEY) + ["timestamp"], kind="stable"
    ).reset_index(drop=True)
    work["unit"] = assign_sessions(work, gap_s)

    sessions = work.groupby("unit", observed=True, sort=False).agg(
        scenario=("scenario", "first"),
        entity_id=("entity_id", "first"),
        detector_source=("detector_source", "first"),
        rule_id=("rule_id", "first"),
        start=("timestamp", "min"),
        end=("timestamp", "max"),
        size=("timestamp", "size"),
        severity_max=("_severity", "max"),
        severity_mean=("_severity", "mean"),
        has_technique=("_has_technique", "max"),
        in_inventory=("entity_in_inventory", "max"),
        positive=("_is_event", "any"),
        labelled_alert_count=("_is_event", "sum"),
        labelled_windows=("_labelled_window", _window_ids),
        temporal_overlap_windows=("window_id", _window_ids),
        event_categories=("event_label", _nonempty),
        alert_category_set=("alert_category", _split_values),
        technique_id_set=("native_technique_ids", _split_values),
        rule_group_set=("rule_groups", _split_values),
        asset_roles=("_asset_roles", "first"),
        alert_rows=("_alert_row", list),
    ).reset_index()

    sessions["session_id"] = scenario + "#" + sessions["unit"].astype(str)
    # take roles from the whole inventory, not only the ones seen in this batch,
    # otherwise the feature columns change between batches
    configured_roles = tuple(sorted({
        role
        for asset in inventory.assets_by_ip.values()
        for role in asset.groups
    }))
    sessions["configured_roles"] = [configured_roles] * len(sessions)
    sessions["day"] = (sessions["start"] // SECONDS_PER_DAY).astype(int)
    sessions["duration_s"] = sessions["end"] - sessions["start"]
    sessions["alerts_per_min"] = (
        sessions["size"] / (sessions["duration_s"] / 60.0 + 1.0)
    )
    sessions["log_size"] = np.log1p(sessions["size"])

    entity_day = sessions.groupby(
        ["day", "entity_id"], observed=True, sort=False
    ).agg(
        detectors_on_entity=("detector_source", "nunique"),
        alerts_on_entity=("size", "sum"),
        groups_on_entity=("unit", "size"),
    ).reset_index()
    sessions = sessions.merge(entity_day, on=["day", "entity_id"], how="left")
    sessions["log_alerts_on_entity"] = np.log1p(sessions["alerts_on_entity"])
    sessions["detectors_nearby_10m"] = _nearby_detector_count(sessions)
    sessions["order"] = np.arange(len(sessions))
    return sessions


def _union(values: pd.Series) -> frozenset:
    return frozenset().union(*values)


def _flatten(values: pd.Series) -> list:
    return [item for items in values for item in items]


def _population_std(values: pd.Series) -> float:
    return float(np.std(values.to_numpy(dtype=float)))


def build_families(scored_sessions: pd.DataFrame) -> pd.DataFrame:
    ordered = scored_sessions.sort_values(
        ["ranking_score", "start", "order"],
        ascending=[False, True, True],
        kind="stable",
    )
    grouped = ordered.groupby(list(FAMILY_KEY), observed=True, sort=False)
    # after that sort the first child is the best scoring one, earliest on ties
    representatives = grouped.head(1).set_index(list(FAMILY_KEY))
    families = grouped.agg(
        scenario=("scenario", "first"),
        ranking_score=("ranking_score", "max"),
        child_score_mean=("ranking_score", "mean"),
        child_score_std=("ranking_score", _population_std),
        family_positive=("positive", "any"),
        labelled_windows=("labelled_windows", _union),
        temporal_overlap_windows=("temporal_overlap_windows", _union),
        event_categories=("event_categories", _union),
        start=("start", "min"),
        end=("end", "max"),
        child_session_ids=("session_id", list),
        n_child_sessions=("session_id", "size"),
        alert_count=("size", "sum"),
        labelled_alert_count=("labelled_alert_count", "sum"),
        alert_rows=("alert_rows", _flatten),
        asset_roles=("asset_roles", "first"),
        detectors_on_entity=("detectors_on_entity", "first"),
        groups_on_entity=("groups_on_entity", "first"),
        log_alerts_on_entity=("log_alerts_on_entity", "first"),
        detectors_nearby_10m=("detectors_nearby_10m", "max"),
        alert_category_set=("alert_category_set", _union),
        technique_id_set=("technique_id_set", _union),
        rule_group_set=("rule_group_set", _union),
    )
    families["representative_session_id"] = representatives["session_id"]
    families["representative_score"] = representatives["ranking_score"]
    families["representative_order"] = representatives["order"]
    families = families.reset_index()
    families["child_score_max"] = families["ranking_score"]
    families["family_span_s"] = families["end"] - families["start"]
    families["alert_category_count"] = families["alert_category_set"].map(len)
    families["technique_count"] = families["technique_id_set"].map(len)
    families["rule_group_count"] = families["rule_group_set"].map(len)
    families["family_id"] = (
        families["scenario"].astype(str)
        + "#"
        + families["day"].astype(str)
        + "#"
        + families["entity_id"].astype(str)
        + "#"
        + families["detector_source"].astype(str)
        + "#"
        + families["rule_id"].astype(str)
    )
    return families
