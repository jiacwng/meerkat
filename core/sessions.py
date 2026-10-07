# Groups normalized alerts into sessions (one entity, detector and rule, until the
# stream is quiet for ten minutes) and sessions into daily review families, which
# carry the aggregates the family re-ranker reads.

from __future__ import annotations

import numpy as np
import pandas as pd

from core.features import standardize_severity
from core.inventory import UNSET, Inventory

SECONDS_PER_DAY = 86400.0
SESSION_GAP_S = 600.0
SESSION_KEY = ("entity_id", "detector_source", "rule_id")
FAMILY_KEY = ("day",) + SESSION_KEY


def assign_sessions(alerts: pd.DataFrame) -> pd.Series:
    # alerts are sorted by key then timestamp, so one forward scan closes a
    # session on the first long silence
    key_changed = alerts[list(SESSION_KEY)].ne(
        alerts[list(SESSION_KEY)].shift()
    ).any(axis=1)
    quiet = alerts["timestamp"].diff().gt(SESSION_GAP_S)
    return (key_changed | quiet).cumsum() - 1


def _union(values: pd.Series) -> frozenset:
    return frozenset().union(*values)


def _pair_counts(values: pd.Series) -> tuple[tuple[tuple[str, str], int], ...]:
    return tuple(values.value_counts().items())


def _part_sets(column: pd.Series) -> pd.Series:
    text = column.astype(str)
    parts = {
        value: frozenset(part for part in value.split(";") if part)
        for value in text.unique()
    }
    return text.map(parts)


def _asset_roles(entity_id: str, inventory: Inventory) -> tuple[str, ...]:
    asset = inventory.assets_by_ip.get(entity_id)
    return asset.groups if asset else ()


def _asset_criticality(entity_id: str, inventory: Inventory) -> str:
    asset = inventory.assets_by_ip.get(entity_id)
    return asset.criticality if asset else UNSET


def session_detectors(pair_counts: pd.Series) -> pd.Series:
    return pair_counts.map(
        lambda pairs: frozenset(detector for (detector, _), _ in pairs)
    )


def _nearby_detector_count(sessions: pd.DataFrame) -> pd.Series:
    counts = np.ones(len(sessions), dtype=float)
    detector_sets = session_detectors(sessions["pair_counts"]).to_numpy()
    for positions in sessions.groupby(
        "entity_id", sort=False, observed=True
    ).indices.values():
        positions = np.asarray(positions)
        entity_sessions = sessions.iloc[positions]
        starts = entity_sessions["start"].to_numpy(dtype=float)
        ends = entity_sessions["end"].to_numpy(dtype=float)
        detectors = detector_sets[positions]

        for local_position, session_position in enumerate(positions):
            nearby = (
                (starts <= ends[local_position] + SESSION_GAP_S)
                & (ends >= starts[local_position] - SESSION_GAP_S)
            )
            counts[session_position] = len(frozenset().union(*detectors[nearby]))
    return pd.Series(counts, index=sessions.index, dtype=float)


def build_sessions(
    alerts: pd.DataFrame,
    scenario: str,
    inventory: Inventory,
) -> pd.DataFrame:
    work = alerts.copy()
    work["scenario"] = scenario
    work["_alert_row"] = np.arange(len(work))
    work["_is_event"] = (
        work["event_label"].fillna("").astype(str).ne("")
        if "event_label" in work else False
    )
    work["_severity"] = standardize_severity(
        work["detector_source"], work["severity"]
    )
    work["_has_technique"] = (
        work["native_technique_ids"].astype(str).fillna("").ne("")
    )
    work["_asset_roles"] = [
        _asset_roles(str(entity), inventory)
        for entity in work["entity_id"]
    ]
    work["_asset_criticality"] = [
        _asset_criticality(str(entity), inventory)
        for entity in work["entity_id"]
    ]
    work["_alert_category_set"] = _part_sets(work["alert_category"])
    work["_technique_id_set"] = _part_sets(work["native_technique_ids"])
    work["_rule_group_set"] = _part_sets(work["rule_groups"])
    work["_pair"] = list(zip(
        work["detector_source"].astype(str), work["rule_id"].astype(str)
    ))
    work = work.sort_values(
        list(SESSION_KEY) + ["timestamp"], kind="stable"
    ).reset_index(drop=True)
    work["unit"] = assign_sessions(work)

    sessions = work.groupby("unit", observed=True, sort=False).agg(
        scenario=("scenario", "first"),
        **{name: (name, "first") for name in SESSION_KEY},
        start=("timestamp", "min"),
        end=("timestamp", "max"),
        size=("timestamp", "size"),
        severity_max=("_severity", "max"),
        severity_mean=("_severity", "mean"),
        has_technique=("_has_technique", "max"),
        in_inventory=("entity_in_inventory", "max"),
        positive=("_is_event", "any"),
        alert_category_set=("_alert_category_set", _union),
        technique_id_set=("_technique_id_set", _union),
        rule_group_set=("_rule_group_set", _union),
        asset_roles=("_asset_roles", "first"),
        criticality=("_asset_criticality", "first"),
        alert_rows=("_alert_row", list),
        pair_counts=("_pair", _pair_counts),
    ).reset_index()

    sessions["session_id"] = scenario + "#" + sessions["unit"].astype(str)
    # roles come from the whole inventory, not the ones seen in this batch, so the
    # feature columns do not change between batches
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

    sessions["_detectors"] = session_detectors(sessions["pair_counts"])
    entity_day = sessions.groupby(
        ["day", "entity_id"], observed=True, sort=False
    ).agg(
        detectors_on_entity=("_detectors", lambda sets: len(_union(sets))),
        alerts_on_entity=("size", "sum"),
        groups_on_entity=("unit", "size"),
    ).reset_index()
    sessions = sessions.drop(columns="_detectors").merge(
        entity_day, on=["day", "entity_id"], how="left"
    )
    sessions["log_alerts_on_entity"] = np.log1p(sessions["alerts_on_entity"])
    sessions["detectors_nearby_10m"] = _nearby_detector_count(sessions)
    sessions["order"] = np.arange(len(sessions))
    return sessions


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
        start=("start", "min"),
        end=("end", "max"),
        child_session_ids=("session_id", list),
        n_child_sessions=("session_id", "size"),
        alert_count=("size", "sum"),
        alert_rows=("alert_rows", _flatten),
        asset_roles=("asset_roles", "first"),
        criticality=("criticality", "first"),
        detectors_on_entity=("detectors_on_entity", "first"),
        groups_on_entity=("groups_on_entity", "first"),
        log_alerts_on_entity=("log_alerts_on_entity", "first"),
        detectors_nearby_10m=("detectors_nearby_10m", "max"),
        alert_category_set=("alert_category_set", _union),
        technique_id_set=("technique_id_set", _union),
        rule_group_set=("rule_group_set", _union),
    )
    families["representative_session_id"] = representatives["session_id"]
    families = families.reset_index()
    families["child_score_max"] = families["ranking_score"]
    families["family_span_s"] = families["end"] - families["start"]
    families["alert_category_count"] = families["alert_category_set"].map(len)
    families["technique_count"] = families["technique_id_set"].map(len)
    families["rule_group_count"] = families["rule_group_set"].map(len)
    family_id = families["scenario"].astype(str)
    for part in FAMILY_KEY:
        family_id = family_id + "#" + families[part].astype(str)
    families["family_id"] = family_id
    return families
