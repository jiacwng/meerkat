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
# a family is one day of one session key, so the two must stay in step: a column
# that stops being a session key stops being a family key with it
FAMILY_KEY = ("day",) + SESSION_KEY


def assign_sessions(
    alerts: pd.DataFrame,
    gap_s: float = SESSION_GAP_S,
) -> pd.Series:
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


def _pair_counts(values: pd.Series) -> tuple[tuple[tuple[str, str], int], ...]:
    # what the session is actually made of. Under a key that carries
    # detector_source and rule_id this is always one pair, but the feature builder
    # must not assume that or the aggregation grid measures the key's side effects
    # instead of the key.
    return tuple(values.value_counts().items())


def _count_union(values: pd.Series) -> int:
    return len(frozenset().union(*values))


def _split_values(values: pd.Series) -> frozenset[str]:
    # cast before filling. These columns are categorical, and pandas refuses to
    # fill a category that does not already exist, so a client running one
    # detector crashed here: the AIT corpus only worked because its miner rows
    # happened to contribute the empty string as a category.
    found = set()
    for value in values.astype(str).fillna(""):
        found.update(part for part in value.split(";") if part)
    return frozenset(found)


def _asset_roles(entity_id: str, inventory: Inventory) -> tuple[str, ...]:
    asset = inventory.assets_by_ip.get(entity_id)
    return asset.groups if asset else ()


def session_detectors(pair_counts: pd.Series) -> pd.Series:
    return pair_counts.map(
        lambda pairs: frozenset(detector for (detector, _), _ in pairs)
    )


def _nearby_detector_count(
    sessions: pd.DataFrame,
    gap_s: float = SESSION_GAP_S,
) -> pd.Series:
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
                (starts <= ends[local_position] + gap_s)
                & (ends >= starts[local_position] - gap_s)
            )
            counts[session_position] = len(frozenset().union(*detectors[nearby]))
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
        work["native_technique_ids"].astype(str).fillna("").ne("")
    )
    work["_asset_roles"] = [
        _asset_roles(str(entity), inventory)
        for entity in work["entity_id"]
    ]
    work["_pair"] = list(zip(
        work["detector_source"].astype(str), work["rule_id"].astype(str)
    ))
    work = work.sort_values(
        list(SESSION_KEY) + ["timestamp"], kind="stable"
    ).reset_index(drop=True)
    work["unit"] = assign_sessions(work, gap_s)

    sessions = work.groupby("unit", observed=True, sort=False).agg(
        scenario=("scenario", "first"),
        # the key columns are grouped away, and the features and the CLI both
        # read them back to describe a unit, so carry them onto the row
        **{name: (name, "first") for name in SESSION_KEY},
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
        pair_counts=("_pair", _pair_counts),
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

    sessions["_detectors"] = session_detectors(sessions["pair_counts"])
    entity_day = sessions.groupby(
        ["day", "entity_id"], observed=True, sort=False
    ).agg(
        detectors_on_entity=("_detectors", _count_union),
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
