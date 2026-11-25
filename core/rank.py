# Scores each incident with a logistic regression fitted on GUIDE and shipped with the package.

import json
from pathlib import Path

import numpy as np
import pandas as pd

from core import features

WEIGHTS = Path(__file__).parent / "data" / "weights.json"


def load_weights() -> dict:
    return json.loads(WEIGHTS.read_text())


def score(incidents: pd.DataFrame) -> pd.DataFrame:
    weights = load_weights()
    found = features.compute(incidents, weights["prior"])
    standard = ((found[list(features.INPUTS)].to_numpy() - np.array(weights["mean"]))
                / np.array(weights["scale"]))
    logit = standard @ np.array(weights["coefficients"]) + weights["intercept"]

    scored = incidents.copy()
    for column in (*features.SIMILAR, *features.RULE):
        scored[column] = found[column].to_numpy()
    scored["score"] = _logistic(logit)
    return scored.sort_values(
        ["score", "Timestamp", "IncidentId"], ascending=[False, False, True],
        kind="stable").reset_index(drop=True)


def _logistic(logit: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-logit))
