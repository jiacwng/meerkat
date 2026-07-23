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
    rule_counts = sessions.groupby(
        ["detector_source", "rule_id"], observed=True
    )["size"].sum()
    seen_detectors = set(sessions["detector_source"].astype(str).unique())
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

    for detector in schema.detectors:
        X[f"detector_{detector}"] = (
            sessions["detector_source"].eq(detector).astype(float)
        )

    rule_index = pd.MultiIndex.from_frame(
        sessions[["detector_source", "rule_id"]].astype(object)
    )
    seen = schema.rule_counts.reindex(rule_index).to_numpy(dtype=float)
    # a rule missing from training is unseen, not merely quiet, so it gets its
    # own flag rather than a count of zero
    X["log_rarity"] = -np.log1p(np.nan_to_num(seen, nan=0.0))
    X["is_unseen_rule"] = np.isnan(seen).astype(float)

    for role in schema.roles:
        X[f"role_{role}"] = sessions["asset_roles"].map(
            lambda asset_roles: float(role in asset_roles)
        )

    return X.loc[:, list(schema.feature_names)]
