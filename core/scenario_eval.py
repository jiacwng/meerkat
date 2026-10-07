# Scores sessions with a trained bundle, and refits one on a client's own data.
# A client has one environment, so only the forest and its feature schema are
# refitted; the re-ranker is rescaled and the calibrator travels unchanged.

from __future__ import annotations

from dataclasses import dataclass, replace

import pandas as pd

from core.classifier import (
    fit_family_reranker,
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

LOCAL_RERANKER_FOLDS = 3


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
    ranking_weights: str = "shipped"   # who fitted the family weights: shipped or local


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
    n_estimators: int = 200,
    seed: int = 0,
) -> TriageBundle:
    schema = fit_session_feature_schema(sessions)
    X = build_session_feature_matrix(sessions, schema)
    reviewed = (
        sessions["reviewed"].to_numpy() if "reviewed" in sessions else None
    )
    forest = fit_soft_labels(X, prior.to_numpy(), reviewed, n_estimators, seed)

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


def fit_local_reranker(
    sessions: pd.DataFrame,
    prior: pd.Series,
    n_estimators: int = 200,
    seed: int = 0,
) -> tuple[object | None, int]:
    # day-blocked folds keep every score out of fold on a single environment
    train = sessions.copy()
    train["positive"] = (prior > 0).to_numpy()
    days = sorted(train["day"].unique())
    parts = []
    for offset in range(LOCAL_RERANKER_FOLDS):
        block = days[offset::LOCAL_RERANKER_FOLDS]
        rest = train[~train["day"].isin(block)]
        part = train[train["day"].isin(block)]
        if not len(part) or not rest["positive"].any():
            continue
        schema = fit_session_feature_schema(rest)
        forest = fit_soft_labels(
            build_session_feature_matrix(rest, schema),
            prior.loc[rest.index].to_numpy(),
            None,
            n_estimators,
            seed,
        )
        scored = part.copy()
        scored["ranking_score"] = predict_scores(
            forest, build_session_feature_matrix(part, schema)
        )
        parts.append(scored)
    if not parts:
        return None, 0
    families = build_families(pd.concat(parts, ignore_index=True))
    positives = int(families["family_positive"].sum())
    if positives == 0 or positives == len(families):
        return None, positives
    return fit_family_reranker(families), positives


def rescale_bundle(bundle: TriageBundle, sessions: pd.DataFrame) -> TriageBundle:
    scored = sessions.copy()
    scored["ranking_score"] = predict_scores(
        bundle.forest, build_session_feature_matrix(scored, bundle.schema)
    )
    return replace(
        bundle, reranker=rescale_reranker(bundle.reranker, build_families(scored))
    )
