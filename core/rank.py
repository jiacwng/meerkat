# Scores each incident by how often its rule was graded true positive before.

import pandas as pd

SMOOTH = 5.0
EMPTY_BASE = 0.5


def score(incidents: pd.DataFrame) -> pd.DataFrame:
    # SMOOTH imaginary reviews at the overall rate keep a rule graded once off 0 and 1
    graded = incidents[incidents["IncidentGrade"] != ""]
    true_positive = graded["IncidentGrade"] == "TruePositive"
    base = true_positive.mean() if len(graded) else EMPTY_BASE
    by_rule = true_positive.groupby(graded["DetectorId"]).agg(["size", "sum"])

    scored = incidents.copy()
    rule = scored["DetectorId"]
    scored["rule_graded"] = rule.map(by_rule["size"]).fillna(0).astype(int)
    scored["rule_true_positives"] = rule.map(by_rule["sum"]).fillna(0).astype(int)
    scored["score"] = (
        (scored["rule_true_positives"] + SMOOTH * base)
        / (scored["rule_graded"] + SMOOTH))
    return scored.sort_values(
        ["score", "Timestamp", "IncidentId"], ascending=[False, False, True],
        kind="stable").reset_index(drop=True)
