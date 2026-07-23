"""Train the session ranker and calibrate family evidence scores.

The forest scores sessions. A family takes the highest score among its children,
and the calibrator turns that raw score into a probability for display only.

Public API:
    fit_model(X, session_positive)            -> fitted forest
    predict_scores(model, X)                  -> raw ranking score per session
    fit_calibrator(family_scores, positive)   -> EvidenceCalibrator
    explain_session(model, feature_row)       -> active important features
    save_model(model, path) / load_model(path)
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


@dataclass
class EvidenceCalibrator:
    model: LogisticRegression   # Platt scaling, one variable

    def predict(self, ranking_scores: np.ndarray) -> np.ndarray:
        scores = np.asarray(ranking_scores, dtype=float).reshape(-1, 1)
        return self.model.predict_proba(scores)[:, 1]


def fit_model(
    X: pd.DataFrame,
    session_positive: pd.Series,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        # roughly one session in nine is positive, so the classes need balancing
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, session_positive)
    return model


def predict_scores(
    model: RandomForestClassifier,
    X: pd.DataFrame,
) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


def fit_calibrator(
    family_scores: np.ndarray,
    family_positive: np.ndarray,
) -> EvidenceCalibrator:
    # the scores must come from folds the forest never trained on, otherwise the
    # calibrator learns an overconfident mapping
    scores = np.asarray(family_scores, dtype=float).reshape(-1, 1)
    target = np.asarray(family_positive, dtype=int)
    model = LogisticRegression(max_iter=1000).fit(scores, target)
    return EvidenceCalibrator(model)


def explain_session(
    model: RandomForestClassifier,
    feature_row: pd.Series,
    top: int = 3,
) -> list[tuple[str, float, float]]:
    # these are model-wide importances, not a reason for this one session
    active = []
    for position, name in enumerate(model.feature_names_in_):
        value = feature_row[name]
        if value != 0:
            active.append(
                (name, float(value), float(model.feature_importances_[position]))
            )
    active.sort(key=lambda item: item[2], reverse=True)
    return active[:top]


def save_model(model: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as file:
        pickle.dump(model, file)


def load_model(path: Path) -> object:
    with path.open("rb") as file:
        return pickle.load(file)
