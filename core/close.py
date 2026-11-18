# Decides which open incidents are safe to close and which closed ones are audited.

import hashlib
import math

import pandas as pd

DEFAULT_MISS_RATE = 0.05
DEFAULT_KEEP_LINKED = True
AUDIT_SHARE = 0.10
PILES = ("queue", "audit", "closed")


def needed(miss_rate: float) -> int:
    return math.ceil(1 / miss_rate - 1)


def calibration(scored: pd.DataFrame, reviews: pd.DataFrame) -> pd.DataFrame:
    latest = reviews.drop_duplicates("IncidentId", keep="last")
    kept = latest[(latest["grade"] == "TruePositive")
                  & latest["pile"].isin(("queue", "audit"))]
    # an audited incident stands for 1 / AUDIT_SHARE incidents that were not sampled
    weight = kept["pile"].map({"queue": 1.0, "audit": 1 / AUDIT_SHARE}).astype(float)
    reviewed = pd.DataFrame({"score": kept["score"], "weight": weight})
    own = scored[(scored["IncidentGrade"] == "TruePositive")
                 & ~scored["IncidentId"].isin(latest["IncidentId"])]
    imported = pd.DataFrame({"score": own["score"], "weight": 1.0})
    return pd.concat([reviewed, imported], ignore_index=True)


def close_level(entries: pd.DataFrame, miss_rate: float) -> float | None:
    budget = miss_rate * (entries["weight"].sum() + 1)
    cumulative = entries.groupby("score")["weight"].sum().cumsum()
    within = cumulative[cumulative <= budget]
    return float(within.index.max()) if len(within) else None


def pile_of(incident_id: str, score: float, level: float | None,
            linked_true_positive: int, keep_linked: bool, rule_graded: int) -> str:
    if level is None or score >= level:
        return "queue"
    if keep_linked and linked_true_positive >= 1:
        return "queue"
    if rule_graded == 0:
        return "queue"
    return "audit" if _sampled(incident_id) else "closed"


def place(scored: pd.DataFrame, reviews: pd.DataFrame, level: float | None,
          keep_linked: bool) -> pd.DataFrame:
    latest = reviews.drop_duplicates("IncidentId", keep="last")
    recorded = latest.set_index("IncidentId")["pile"]
    piles = []
    columns = ["IncidentId", "IncidentGrade", "score", "linked_true_positive", "rule_graded"]
    for row in scored[columns].itertuples(index=False):
        if row.IncidentGrade == "":
            piles.append(pile_of(row.IncidentId, row.score, level,
                                 row.linked_true_positive, keep_linked, row.rule_graded))
        else:
            piles.append(recorded.get(row.IncidentId, ""))
    return scored.assign(pile=piles)


def _sampled(incident_id: str) -> bool:
    digest = hashlib.sha256(incident_id.encode()).hexdigest()
    return int(digest[:8], 16) / 2**32 < AUDIT_SHARE
