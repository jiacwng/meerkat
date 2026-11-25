# Splits the open incidents at the reading budget, draws the sample below it and estimates the unread true positives.

import math
import random

import pandas as pd

from core.incidents import CLASSIFICATIONS

DEFAULT_SAMPLE_SHARE = 0.10
PLACEMENTS = ("to read", "sample", "below budget")
TRUE_POSITIVE = CLASSIFICATIONS[0]
Z = 1.959964


def slots(budget: int, share: float) -> int:
    if budget < 2 or share == 0:
        return 0
    return min(budget - 1, max(1, round(share * budget)))


def drawn_ids(samples: list[dict]) -> set[str]:
    return {incident for sample in samples for incident in sample["drawn"]}


def split(opened: list[str], budget: int | None, drawn: set[str], lead: dict[str, str],
          reserved: int = 0) -> dict[str, str]:
    # a group takes one place in the budget: its other incidents follow the one that leads it
    held = sum(incident in drawn for incident in opened)
    room = len(opened) if budget is None else max(0, budget - held - reserved)
    placement = {}
    for incident in opened:
        if incident in drawn:
            placement[incident] = "sample"
        elif lead[incident] != incident:
            placement[incident] = placement[lead[incident]]
        elif room > 0:
            placement[incident] = "to read"
            room -= 1
        else:
            placement[incident] = "below budget"
    return placement


def draw(opened: list[str], budget: int, share: float, samples: list[dict],
         lead: dict[str, str]) -> dict:
    # an incident enters one pool only, at the first draw that finds it below the budget
    drawn = drawn_ids(samples)
    pooled = {incident for sample in samples for incident in sample["pool"]}
    held = sum(incident in drawn for incident in opened)
    count = max(0, slots(budget, share) - held)
    if count == 0:
        return {"pool": [], "drawn": []}
    placement = split(opened, budget, drawn, lead, count)
    pool = [incident for incident in opened
            if placement[incident] == "below budget" and incident not in pooled]
    # seeded by the pool itself, so the same files give the same sample
    picked = random.Random(",".join(pool)).sample(pool, min(count, len(pool)))
    return {"pool": pool, "drawn": sorted(picked)}


def place(scored: pd.DataFrame, classifications: pd.DataFrame, budget: int | None,
          samples: list[dict], lead: dict[str, str]) -> pd.DataFrame:
    opened = scored.loc[scored["IncidentGrade"] == "", "IncidentId"].tolist()
    placement = split(opened, budget, drawn_ids(samples), lead)
    first = classifications.drop_duplicates("IncidentId").set_index("IncidentId")["placement"]
    recorded = scored["IncidentId"].map(first).fillna("")
    return scored.assign(placement=scored["IncidentId"].map(placement).fillna(recorded),
                         group_lead=scored["IncidentId"].map(lead).fillna(""))


def not_sampled(placed: pd.DataFrame, samples: list[dict]) -> int:
    pooled = {incident for sample in samples for incident in sample["pool"]}
    below = placed.loc[(placed["IncidentGrade"] == "") & (placed["placement"] == "below budget"),
                       "IncidentId"]
    return int((~below.isin(pooled)).sum())


def estimate(samples: list[dict], classifications: dict[str, str], below: set[str]) -> dict:
    total = known = unread = drawn = classified = positives = 0
    weights = squares = hits = 0.0
    for sample in samples:
        pool = sample["pool"]
        total += len(pool)
        known += sum(classifications.get(incident) == TRUE_POSITIVE for incident in pool)
        unread += sum(incident in below for incident in pool)
        drawn += len(sample["drawn"])
        marked = [incident for incident in sample["drawn"]
                  if classifications.get(incident, "") != ""]
        if marked:
            # a classified sample row stands for this many incidents of its pool
            weight = len(pool) / len(marked)
            found = sum(classifications[incident] == TRUE_POSITIVE for incident in marked)
            classified += len(marked)
            positives += found
            weights += weight * len(marked)
            squares += weight * weight * len(marked)
            hits += weight * found
    result = {"drawn": drawn, "classified": classified, "true_positive": positives,
              "tp_below_budget": None}
    if classified:
        rate = hits / weights
        low, high = _wilson(rate, weights * weights / squares)
        result["tp_below_budget"] = {
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
