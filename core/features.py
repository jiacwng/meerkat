"""Turn alert sessions into numbers a classifier can learn from.

Entity, rule and alert-name identity never become features, so a model trained
on one company cannot recognise another by name.

Public API:
    standardize_severity(detector_source, severity) -> shared 0-1 scale
    fit_session_feature_schema(sessions)            -> schema from training data
    build_session_feature_matrix(sessions, schema)  -> numeric matrix
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

SESSION_NUMERIC_FEATURES = (
    "log_size",
    "duration_s",
    "alerts_per_min",
    "severity_max",
    "severity_mean",
    "has_technique",
    "in_inventory",
    "detectors_on_entity",
    "groups_on_entity",
    "log_alerts_on_entity",
)
SUPPORTED_DETECTOR_ORDER = ("wazuh", "suricata", "aminer")
SCHEMA_INDEX_NAMES = ("detector_source", "rule_id")


@dataclass(frozen=True)
class SessionFeatureSchema:
    rule_counts: pd.Series          # alerts per rule, counted on training data
    detectors: tuple[str, ...]      # one column each, in a fixed order
    roles: tuple[str, ...]          # asset roles from the customer inventory

    @property
    def feature_names(self) -> tuple[str, ...]:
        detector_columns = tuple(f"detector_{name}" for name in self.detectors)
        role_columns = tuple(f"role_{name}" for name in self.roles)
        return (
            SESSION_NUMERIC_FEATURES
            + detector_columns
            + ("log_rarity", "is_unseen_rule")
            + role_columns
        )


def standardize_severity(
    detector_source: pd.Series,
    severity: pd.Series,
) -> pd.Series:
    # wazuh rises 0-15, suricata falls 1-3, aminer has no severity at all and
    # takes the midpoint, since scoring it zero would rank a whole detector last
    standardized = pd.Series(0.5, index=severity.index, dtype=float)
    wazuh = detector_source.eq("wazuh")
    suricata = detector_source.eq("suricata")
    standardized[wazuh] = (severity[wazuh] / 15.0).clip(0, 1)
    standardized[suricata] = ((4.0 - severity[suricata]) / 3.0).clip(0, 1)
    return standardized


def fit_session_feature_schema(sessions: pd.DataFrame) -> SessionFeatureSchema:
    # counted over a session's actual alerts rather than its carried key, so the
    # schema is the same whether or not the key happens to separate detectors
    counts: dict[tuple[str, str], int] = {}
    for pairs in sessions["pair_counts"]:
        for pair, count in pairs:
            counts[pair] = counts.get(pair, 0) + count
    index = (
        pd.MultiIndex.from_tuples(list(counts), names=SCHEMA_INDEX_NAMES) if counts
        else pd.MultiIndex.from_arrays([[], []], names=SCHEMA_INDEX_NAMES)
    )
    rule_counts = pd.Series(list(counts.values()), index=index, dtype="int64")
    seen_detectors = {detector for detector, _ in counts}
    detectors = tuple(
        detector
        for detector in SUPPORTED_DETECTOR_ORDER
        if detector in seen_detectors
    ) + tuple(sorted(seen_detectors - set(SUPPORTED_DETECTOR_ORDER)))
    roles = tuple(sorted({
        role
        for configured_roles in sessions["configured_roles"]
        for role in configured_roles
    }))
    return SessionFeatureSchema(rule_counts, detectors, roles)


def build_session_feature_matrix(
    sessions: pd.DataFrame,
    schema: SessionFeatureSchema,
) -> pd.DataFrame:
    X = sessions[list(SESSION_NUMERIC_FEATURES)].astype(float).copy()

    # every alert votes with its own share of the session. A key that separates
    # detectors gives one pair per session, so each of these collapses to the
    # one-hot and the single lookup it replaces.
    known = schema.rule_counts.to_dict()
    shares = {detector: np.zeros(len(sessions)) for detector in schema.detectors}
    rarity = np.zeros(len(sessions))
    unseen = np.zeros(len(sessions))
    for row, pairs in enumerate(sessions["pair_counts"]):
        total = float(sum(count for _, count in pairs)) or 1.0
        for pair, count in pairs:
            weight = count / total
            if pair[0] in shares:
                shares[pair[0]][row] += weight
            # a rule missing from training is unseen, not merely quiet, so it gets
            # its own flag rather than a count of zero
            if pair in known:
                rarity[row] -= weight * np.log1p(float(known[pair]))
            else:
                unseen[row] += weight

    for detector in schema.detectors:
        X[f"detector_{detector}"] = shares[detector]
    X["log_rarity"] = rarity
    X["is_unseen_rule"] = unseen

    for role in schema.roles:
        X[f"role_{role}"] = sessions["asset_roles"].map(
            lambda asset_roles: float(role in asset_roles)
        )

    return X.loc[:, list(schema.feature_names)]
