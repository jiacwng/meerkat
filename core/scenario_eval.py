# Scores sessions with a trained bundle, and refits one on a client's own data.
# A client has one environment, so only the forest and its feature schema are
# refitted; the re-ranker is rescaled and the calibrator travels unchanged.

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
    CONTRIBUTION_PREFIX,
    SessionFeatureSchema,
    build_session_feature_matrix,
    fit_session_feature_schema,
)
from core.sessions import build_families


@dataclass
class TriageBundle:
    forest: object
    schema: SessionFeatureSchema
    reranker: object
    calibrator: object
    training_scenarios: tuple[str, ...]
    n_estimators: int
    seed: int
    profile: TrainingProfile


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
    pushes, _ = bundle.reranker.contributions(families)
    families = families.join(pushes.add_prefix(CONTRIBUTION_PREFIX))
    families["evidence_probability"] = bundle.calibrator.predict(
        families["ranking_score"].to_numpy()
    )
    return scored, families


def refit_forest(
    bundle: TriageBundle,
    sessions: pd.DataFrame,
    prior: pd.Series,
    n_estimators: int,
    seed: int = 0,
) -> TriageBundle:
    schema = fit_session_feature_schema(sessions)
    X = build_session_feature_matrix(sessions, schema)
    forest = fit_soft_labels(X, prior.to_numpy(), n_estimators, seed)

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
        profile=build_profile(X, reranker.predict(families)),
    )


def rescale_bundle(bundle: TriageBundle, sessions: pd.DataFrame) -> TriageBundle:
    scored = sessions.copy()
    scored["ranking_score"] = predict_scores(
        bundle.forest, build_session_feature_matrix(scored, bundle.schema)
    )
    return replace(
        bundle, reranker=rescale_reranker(bundle.reranker, build_families(scored))
    )
