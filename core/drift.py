"""Compare a client's current alerts against what the model was trained on.

Drift detection here answers one question and refuses the other two. Of the three
kinds of drift in the usual taxonomy, only the first is visible without labels:

    covariate shift   P(X) moved. new rules, new hosts, a detector upgrade.
                      DETECTABLE, and it is what this module reports.
    concept drift     P(y|X) moved. what an attack looks like changed.
                      NEEDS LABELS. not detectable here.
    prior shift       P(y) moved. the attack rate changed.
                      NEEDS LABELS. not detectable here.

So a drift report is an alarm and never a verdict. It says the input moved. It
cannot say the queue got worse, and nothing in here should be read that way.

Public API:
    TrainingProfile                       what a bundle records about its training set
    build_profile(X, scores, families)    compute one at training time
    compare_profile(profile, X)           one FeatureDrift per feature
    population_stability_index(...)       PSI against a stored reference histogram
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

# The credit-risk convention, which is where PSI comes from and where the whole
# reject-inference framing in this project comes from too. These thresholds are the
# published ones rather than anything tuned here.
PSI_STABLE = 0.10
PSI_MAJOR = 0.25
DECILES = tuple(round(0.1 * i, 2) for i in range(1, 10))

# a rule the model never saw contributes no rarity signal, so this is the drift
# that matters most for a ranking built on rule identity
UNSEEN_RULE_WARN = 0.20


@dataclass
class TrainingProfile:
    # edges AND the reference share per bin. Storing edges alone and assuming an
    # even 10% per bin is wrong the moment deciles collapse: a binary feature gives
    # 9 edges that reduce to 2 cuts, and the training data was never spread evenly
    # across the 3 bins those imply. Measured on AIT, that mistake reported
    # PSI 3.583 for has_technique when nothing about it had moved.
    feature_bins: dict[str, tuple[tuple[float, ...], tuple[float, ...]]] = field(
        default_factory=dict
    )
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
    # searchsorted with side="left" makes each bin right-closed, so a value sitting
    # exactly ON a quantile edge falls with the group below it. np.histogram is
    # left-closed instead, which put every zero of a binary feature into the upper
    # bin and made both distributions collapse into one: an unmoved feature and a
    # real fifty-fifty shift both scored PSI 0.
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
    return TrainingProfile(
        # roles are excluded: they describe the client's inventory rather than the
        # alert stream, and `meerkat check` already reports role coverage directly
        feature_bins={
            name: _reference(X[name].to_numpy())
            for name in X.columns
            if not name.startswith("role_")
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
        if name not in X:
            continue
        current = X[name].to_numpy(dtype=float)
        psi = population_stability_index(edges, expected, current)
        drifts.append(FeatureDrift(
            name=name,
            psi=psi,
            verdict=verdict_for(psi),
            training_median=float(edges[len(edges) // 2]) if edges else float("nan"),
            current_median=(
                float(np.nanmedian(current)) if len(current) else float("nan")
            ),
        ))
    return sorted(drifts, key=lambda d: -d.psi)


def unseen_rule_share(schema, pair_counts: pd.Series) -> float:
    # free: the schema already holds every (detector, rule) pair the forest saw, so
    # the most likely real drift needs no new stored statistic at all
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
