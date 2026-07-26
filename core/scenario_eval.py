"""Score sessions with a trained bundle, and refit one on a client's own data.

The evaluation harness that used to live here is in bench/, which the product
cannot import. This file keeps its name because TriageBundle's import path is
recorded inside every saved model bundle and in classifier.TRUSTED_TYPES, so
moving the class would refuse every bundle already written.

Public API:
    add_window_ids(frame, windows)          -> frame with a window_id column
    score_sessions(bundle, sessions)        -> scored sessions and families
    refit_forest(bundle, sessions, prior)   -> a bundle with a client forest
    rescale_bundle(bundle, sessions)        -> the same forest, rescaled re-ranker
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pandas as pd

from core.classifier import (
    fit_soft_labels,
    predict_scores,
    rescale_reranker,
)
from core.drift import TrainingProfile, build_profile
from core.features import (
    SessionFeatureSchema,
    build_session_feature_matrix,
    fit_session_feature_schema,
)
from core.sessions import build_families


def add_window_ids(
    frame: pd.DataFrame,
    windows: list[tuple[float, float, str]],
) -> pd.DataFrame:
    marked = frame.copy()
    marked["window_id"] = -1
    for window_id, (start, end, attack) in enumerate(windows):
        inside = marked["timestamp"].between(start, end)
        marked.loc[
            inside & marked["attack_window"].eq(attack),
            "window_id",
        ] = window_id
    return marked

@dataclass
class TriageBundle:
    forest: object
    schema: SessionFeatureSchema
    reranker: object
    calibrator: object
    training_scenarios: tuple[str, ...]
    n_estimators: int
    seed: int
    # optional so a bundle written before drift existed still loads. Read it with
    # getattr, because skops restores a missing field as absent rather than None.
    profile: TrainingProfile | None = None


# A client has one environment, so the reranker and calibrator cannot be refitted:
# both are defined out-of-fold ACROSS environments. Only the forest and its feature
# schema are replaced, and the rest of the shipped bundle travels unchanged.

def score_sessions(
    bundle: TriageBundle,
    session_table: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    scored = session_table.copy()
    scored["ranking_score"] = predict_scores(
        bundle.forest,
        build_session_feature_matrix(scored, bundle.schema),
    )
    families = build_families(scored)
    families["ranking_score"] = bundle.reranker.predict(families)
    families["evidence_probability"] = bundle.calibrator.predict(
        families["ranking_score"].to_numpy()
    )
    return scored, families

def refit_forest(
    bundle: TriageBundle,
    sessions: pd.DataFrame,
    prior: pd.Series,
    n_estimators: int = 300,
    seed: int = 0,
    min_positives: int = 10,
) -> TriageBundle:
    in_bag = prior > 0
    if int(in_bag.sum()) < min_positives:
        raise ValueError(
            f"only {int(in_bag.sum())} sessions fall inside an incident; "
            f"at least {min_positives} are needed to retrain"
        )
    schema = fit_session_feature_schema(sessions)
    X = build_session_feature_matrix(sessions, schema)
    reviewed = (
        sessions["reviewed"].to_numpy() if "reviewed" in sessions else None
    )
    forest = fit_soft_labels(X, prior.to_numpy(), reviewed, n_estimators, seed)

    # the new forest scores on a different scale, so the re-ranker's scaler is
    # refitted on families built from it. Its coefficients stay as shipped.
    scored = sessions.copy()
    scored["ranking_score"] = predict_scores(forest, X)
    families = build_families(scored)
    reranker = rescale_reranker(bundle.reranker, families)
    return TriageBundle(
        forest=forest,
        schema=schema,
        reranker=reranker,
        calibrator=bundle.calibrator,
        training_scenarios=bundle.training_scenarios,
        n_estimators=n_estimators,
        seed=seed,
        profile=build_profile(
            X, scored["ranking_score"].to_numpy(), families,
            reranker.predict(families),
        ),
    )

def rescale_bundle(bundle: TriageBundle, sessions: pd.DataFrame) -> TriageBundle:
    # the shipped re-ranker's scaler was fitted on AIT families. Moving it onto the
    # client's families costs no labels, so it is the fair floor a retrain has to
    # clear rather than the untouched bundle.
    scored = sessions.copy()
    scored["ranking_score"] = predict_scores(
        bundle.forest, build_session_feature_matrix(scored, bundle.schema)
    )
    return replace(
        bundle, reranker=rescale_reranker(bundle.reranker, build_families(scored))
    )
