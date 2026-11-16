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

    unseen = features.smooth(0, 0, weights["prior"])
    links = _shift(found, weights, {
        "log_linked": 0.0, "log_linked_true_positive": 0.0,
        "log_linked_benign_positive": 0.0, "log_linked_false_positive": 0.0,
        "linked_true_positive_rate": unseen})
    rule = _shift(found, weights, {"rule_true_positive_rate": unseen, "log_rule_graded": 0.0})

    graded = incidents[incidents["IncidentGrade"] != ""]
    true_positive = graded["IncidentGrade"] == "TruePositive"
    by_rule = true_positive.groupby(graded["DetectorId"]).agg(["size", "sum"])

    scored = incidents.copy()
    detector = scored["DetectorId"]
    scored["rule_graded"] = detector.map(by_rule["size"]).fillna(0).astype(int)
    scored["rule_true_positives"] = detector.map(by_rule["sum"]).fillna(0).astype(int)
    for column in features.LINKED:
        scored[column] = found[column].to_numpy()
    scored["score"] = _logistic(logit)
    scored["score_without_links"] = _logistic(logit - links)
    scored["score_as_new_rule"] = _logistic(logit - rule)
    scored["reason"] = [_reason(a, b) for a, b in zip(links, rule, strict=True)]
    return scored.sort_values(
        ["score", "Timestamp", "IncidentId"], ascending=[False, False, True],
        kind="stable").reset_index(drop=True)


def _logistic(logit: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-logit))


def _shift(found: pd.DataFrame, weights: dict, neutral: dict[str, float]) -> np.ndarray:
    at = [features.INPUTS.index(name) for name in neutral]
    standard = ((found[list(neutral)].to_numpy() - np.array(list(neutral.values())))
                / np.array(weights["scale"])[at])
    return standard @ np.array(weights["coefficients"])[at]


def _reason(links: float, rule: float) -> str:
    if links == 0.0 and rule == 0.0:
        return "no history"
    if abs(links) >= abs(rule):
        return "linked incidents " + ("raise" if links > 0 else "lower") + " it"
    return "rule history " + ("raises" if rule > 0 else "lowers") + " it"
