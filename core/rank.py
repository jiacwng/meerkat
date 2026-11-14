# Scores each incident with a logistic regression fitted on GUIDE and shipped with the package.

import json
from pathlib import Path

import numpy as np
import pandas as pd

from core import features

WEIGHTS = Path(__file__).parent / "data" / "weights.json"


def load_weights() -> dict:
    weights = json.loads(WEIGHTS.read_text())
    if weights["inputs"] != list(features.INPUTS):
        raise ValueError(f"{WEIGHTS}: inputs do not match core.features.INPUTS")
    return weights


def score(incidents: pd.DataFrame) -> pd.DataFrame:
    weights = load_weights()
    found = features.compute(incidents, weights["prior"])
    standard = ((found[list(features.INPUTS)].to_numpy() - np.array(weights["mean"]))
                / np.array(weights["scale"]))
    logit = standard @ np.array(weights["coefficients"]) + weights["intercept"]

    graded = incidents[incidents["IncidentGrade"] != ""]
    true_positive = graded["IncidentGrade"] == "TruePositive"
    by_rule = true_positive.groupby(graded["DetectorId"]).agg(["size", "sum"])

    scored = incidents.copy()
    rule = scored["DetectorId"]
    scored["rule_graded"] = rule.map(by_rule["size"]).fillna(0).astype(int)
    scored["rule_true_positives"] = rule.map(by_rule["sum"]).fillna(0).astype(int)
    for column in features.LINKED:
        scored[column] = found[column].to_numpy()
    scored["score"] = 1 / (1 + np.exp(-logit))
    return scored.sort_values(
        ["score", "Timestamp", "IncidentId"], ascending=[False, False, True],
        kind="stable").reset_index(drop=True)
