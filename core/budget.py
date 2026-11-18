# Splits the open incidents at the reading budget, draws the sample below it and estimates the unread true positives.

import math
import random

import pandas as pd

from core.incidents import GRADES

DEFAULT_SAMPLE_SHARE = 0.10
STATUSES = ("ranked", "sample", "below")
TRUE_POSITIVE = GRADES[0]
Z = 1.959964


def slots(budget: int, share: float) -> int:
    if budget < 2 or share == 0:
        return 0
    return min(budget - 1, max(1, round(share * budget)))


def split(opened: list[str], budget: int | None, drawn: set[str],
          reserved: int = 0) -> dict[str, str]:
    held = sum(incident in drawn for incident in opened)
    room = len(opened) if budget is None else max(0, budget - held - reserved)
    status = {}
    for incident in opened:
        if incident in drawn:
            status[incident] = "sample"
        elif room > 0:
            status[incident] = "ranked"
            room -= 1
        else:
            status[incident] = "below"
    return status


def draw(opened: list[str], budget: int, share: float, samples: list[dict]) -> dict:
    # an incident enters one pool only, at the first draw that finds it below the budget
    drawn = {incident for sample in samples for incident in sample["drawn"]}
    pooled = {incident for sample in samples for incident in sample["pool"]}
    held = sum(incident in drawn for incident in opened)
    count = max(0, slots(budget, share) - held)
    if count == 0:
        return {"pool": [], "drawn": []}
    status = split(opened, budget, drawn, count)
    pool = [incident for incident in opened
            if status[incident] == "below" and incident not in pooled]
    # seeded by the pool itself, so the same files give the same sample
    picked = random.Random(",".join(pool)).sample(pool, min(count, len(pool)))
    return {"pool": pool, "drawn": sorted(picked)}


def place(scored: pd.DataFrame, reviews: pd.DataFrame, budget: int | None,
          samples: list[dict]) -> pd.DataFrame:
    drawn = {incident for sample in samples for incident in sample["drawn"]}
    opened = scored.loc[scored["IncidentGrade"] == "", "IncidentId"].tolist()
    status = split(opened, budget, drawn)
    first = reviews.drop_duplicates("IncidentId").set_index("IncidentId")["status"]
    recorded = scored["IncidentId"].map(first).fillna("")
    return scored.assign(status=scored["IncidentId"].map(status).fillna(recorded))


def not_sampled(placed: pd.DataFrame, samples: list[dict]) -> int:
    pooled = {incident for sample in samples for incident in sample["pool"]}
    below = placed.loc[(placed["IncidentGrade"] == "") & (placed["status"] == "below"),
                       "IncidentId"]
    return int((~below.isin(pooled)).sum())


def estimate(samples: list[dict], grades: dict[str, str]) -> dict:
    total = known = unread = drawn = graded = positives = 0
    weights = squares = hits = 0.0
    for sample in samples:
        pool = sample["pool"]
        total += len(pool)
        known += sum(grades.get(incident) == TRUE_POSITIVE for incident in pool)
        unread += sum(grades.get(incident, "") == "" for incident in pool)
        drawn += len(sample["drawn"])
        marked = [incident for incident in sample["drawn"] if grades.get(incident, "") != ""]
        if marked:
            # a graded sample row stands for this many incidents of its pool
            weight = len(pool) / len(marked)
            found = sum(grades[incident] == TRUE_POSITIVE for incident in marked)
            graded += len(marked)
            positives += found
            weights += weight * len(marked)
            squares += weight * weight * len(marked)
            hits += weight * found
    result = {"drawn": drawn, "graded": graded, "true_positive": positives,
              "unread_true_positives": None}
    if graded:
        rate = hits / weights
        low, high = _wilson(rate, weights * weights / squares)
        result["unread_true_positives"] = {
            "estimate": round(_bounded(rate * total - known, unread)),
            "low": math.floor(_bounded(low * total - known, unread)),
            "high": math.ceil(_bounded(high * total - known, unread)),
        }
    return result


def _bounded(value: float, unread: int) -> float:
    return min(float(unread), max(0.0, value))


def _wilson(rate: float, size: float) -> tuple[float, float]:
    centre = (rate + Z * Z / (2 * size)) / (1 + Z * Z / size)
    half = Z * math.sqrt(rate * (1 - rate) / size + Z * Z / (4 * size * size)) / (1 + Z * Z / size)
    return max(0.0, centre - half), min(1.0, centre + half)
