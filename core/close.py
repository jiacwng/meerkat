# Decides which open incidents are safe to close and which closed ones are audited.

import hashlib
import math

import pandas as pd

from core.rank import EMPTY_BASE, SMOOTH

MISS_RATE = 0.05
AUDIT_SHARE = 0.10
PILES = ("queue", "audit", "closed")

def needed() -> int:
    return math.ceil(1 / MISS_RATE - 1)

def calibration(scored: pd.DataFrame, reviews: pd.DataFrame) -> pd.DataFrame:
    latest = reviews.drop_duplicates("IncidentId", keep="last")
    kept = latest[(latest["grade"] == "TruePositive")
                  & latest["pile"].isin(("queue", "audit"))]
    # an audited incident stands for 1 / AUDIT_SHARE incidents that were not sampled
    weight = kept["pile"].map({"queue": 1.0, "audit": 1 / AUDIT_SHARE}).astype(float)
    reviewed = pd.DataFrame({"score": kept["score"], "weight": weight})
    left_out = _leave_one_out(scored, latest["IncidentId"])
    imported = pd.DataFrame({"score": left_out, "weight": 1.0})
    return pd.concat([reviewed, imported], ignore_index=True)

def close_level(entries: pd.DataFrame) -> float | None:
    budget = MISS_RATE * (entries["weight"].sum() + 1)
    cumulative = entries.groupby("score")["weight"].sum().cumsum()
    within = cumulative[cumulative <= budget]
    return float(within.index.max()) if len(within) else None

def pile_of(incident_id: str, score: float, level: float | None) -> str:
    if level is None or score >= level:
        return "queue"
    return "audit" if _sampled(incident_id) else "closed"

def place(scored: pd.DataFrame, reviews: pd.DataFrame, level: float | None) -> pd.DataFrame:
    latest = reviews.drop_duplicates("IncidentId", keep="last")
    recorded = latest.set_index("IncidentId")["pile"]
    piles = []
    for row in scored[["IncidentId", "IncidentGrade", "score"]].itertuples(index=False):
        if row.IncidentGrade == "":
            piles.append(pile_of(row.IncidentId, row.score, level))
        else:
            piles.append(recorded.get(row.IncidentId, ""))
    return scored.assign(pile=piles)

def _leave_one_out(scored: pd.DataFrame, reviewed_ids: pd.Series) -> pd.Series:
    # the score an incident graded true positive in the file would get if its grade were unknown
    graded = (scored["IncidentGrade"] != "").sum()
    true_positives = (scored["IncidentGrade"] == "TruePositive").sum()
    base = (true_positives - 1) / (graded - 1) if graded > 1 else EMPTY_BASE
    own = scored[(scored["IncidentGrade"] == "TruePositive")
                 & ~scored["IncidentId"].isin(reviewed_ids)]
    return ((own["rule_true_positives"] - 1 + SMOOTH * base)
            / (own["rule_graded"] - 1 + SMOOTH))

def _sampled(incident_id: str) -> bool:
    digest = hashlib.sha256(incident_id.encode()).hexdigest()
    return int(digest[:8], 16) / 2**32 < AUDIT_SHARE
