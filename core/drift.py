# Compares a client's alerts against the training profile stored in the bundle.
# Only covariate shift (the inputs moved) is visible without labels, so a report is
# an alarm that the input moved and never a verdict that the queue got worse.

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

# the 0.10 and 0.25 bands are Siddiqi's, Credit Risk Scorecards, 2006, not tuned here
PSI_STABLE = 0.10
PSI_MAJOR = 0.25
DECILES = tuple(round(0.1 * i, 2) for i in range(1, 10))

UNSEEN_RULE_WARN = 0.20

# every session on a host repeats the host's value, so a day holds about as many
# observations as hosts, too few for PSI
HOST_FEATURES = frozenset({"detectors_on_entity", "groups_on_entity", "log_alerts_on_entity"})


def _compared(name: str) -> bool:
    return not name.startswith("role_") and name not in HOST_FEATURES


@dataclass
class TrainingProfile:
    feature_bins: dict[str, tuple[tuple[float, ...], tuple[float, ...]]] = field(
        default_factory=dict
    )
    feature_medians: dict[str, float] = field(default_factory=dict)
    session_score_bins: tuple[tuple[float, ...], tuple[float, ...]] = ((), ())
    family_score_bins: tuple[tuple[float, ...], tuple[float, ...]] = ((), ())
    detector_mix: dict[str, float] = field(default_factory=dict)
    inventory_coverage: float = 0.0
    n_sessions: int = 0
    n_families: int = 0


@dataclass
class FeatureDrift:
    name: str
    psi: float
    verdict: str
    training_median: float
    current_median: float


def _bin_shares(edges: np.ndarray, values: np.ndarray) -> np.ndarray:
    index = np.searchsorted(edges, values, side="left")
    return np.bincount(index, minlength=len(edges) + 1) / len(values)


def _reference(values: np.ndarray) -> tuple[tuple[float, ...], tuple[float, ...]]:
    clean = np.asarray(values, dtype=float)
    clean = clean[np.isfinite(clean)]
    if not len(clean):
        return (), ()
    cuts = np.unique(np.quantile(clean, DECILES))
    shares = _bin_shares(cuts, clean)
    return tuple(float(c) for c in cuts), tuple(float(s) for s in shares)


def build_profile(
    X: pd.DataFrame,
    session_scores: np.ndarray,
    families: pd.DataFrame | None = None,
    family_scores: np.ndarray | None = None,
) -> TrainingProfile:
    detector_columns = [c for c in X.columns if c.startswith("detector_")]
    total = float(len(X)) or 1.0
    compared = [name for name in X.columns if _compared(name)]
    return TrainingProfile(
        feature_bins={name: _reference(X[name].to_numpy()) for name in compared},
        feature_medians={
            name: float(np.nanmedian(X[name].to_numpy(dtype=float)))
            for name in compared
            if len(X)
        },
        session_score_bins=_reference(np.asarray(session_scores)),
        family_score_bins=(
            _reference(np.asarray(family_scores))
            if family_scores is not None else ((), ())
        ),
        detector_mix={
            c.removeprefix("detector_"): float(X[c].sum() / total)
            for c in detector_columns
        },
        inventory_coverage=(
            float(X["in_inventory"].mean()) if "in_inventory" in X else 0.0
        ),
        n_sessions=int(len(X)),
        n_families=int(len(families)) if families is not None else 0,
    )


def population_stability_index(
    edges: tuple[float, ...],
    expected: tuple[float, ...],
    current: np.ndarray,
) -> float:
    values = np.asarray(current, dtype=float)
    values = values[np.isfinite(values)]
    if not len(edges) or not len(expected) or not len(values):
        return 0.0
    actual = _bin_shares(np.asarray(edges, dtype=float), values)
    if len(actual) != len(expected):
        return 0.0
    # an empty bin on either side makes the log term infinite, so floor both at a
    # tenth of one observation rather than dropping the bin
    floor = 1.0 / (10.0 * len(values))
    a = np.clip(actual, floor, None)
    e = np.clip(np.asarray(expected, dtype=float), floor, None)
    return float(np.sum((a - e) * np.log(a / e)))


def verdict_for(psi: float) -> str:
    if psi < PSI_STABLE:
        return "stable"
    if psi < PSI_MAJOR:
        return "moderate"
    return "major"


def compare_profile(
    profile: TrainingProfile,
    X: pd.DataFrame,
) -> list[FeatureDrift]:
    drifts = []
    for name, (edges, expected) in profile.feature_bins.items():
        if name not in X or not _compared(name):
            continue
        current = X[name].to_numpy(dtype=float)
        psi = population_stability_index(edges, expected, current)
        drifts.append(FeatureDrift(
            name=name,
            psi=psi,
            verdict=verdict_for(psi),
            training_median=profile.feature_medians.get(name, float("nan")),
            current_median=(
                float(np.nanmedian(current)) if len(current) else float("nan")
            ),
        ))
    return sorted(drifts, key=lambda d: -d.psi)


def unseen_rule_share(schema, pair_counts: pd.Series) -> float:
    known = set(schema.rule_counts.index)
    seen = unseen = 0
    for pairs in pair_counts:
        for pair, count in pairs:
            if pair in known:
                seen += count
            else:
                unseen += count
    total = seen + unseen
    return (unseen / total) if total else 0.0
