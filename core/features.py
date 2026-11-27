# The seven inputs of the score, each taken from incidents strictly earlier in time.

import numpy as np
import pandas as pd

from core.incidents import CLASSIFICATIONS, LINKS, SEPARATOR

INPUTS = (
    "org_true_positive_rate", "rule_true_positive_rate", "log_org_classified",
    "log_rule_classified", "log_similar", "similar_true_positive_log_odds",
    "has_similar_true_positive",
)
SIMILAR = ("similar", "similar_true_positive", "similar_benign_positive",
           "similar_false_positive")
RULE = ("rule_classified", "rule_true_positives", "rule_benign_positives")
SMOOTH = 5.0
LINK_SMOOTH = 1.0
CAP = 50


def compute(incidents: pd.DataFrame, prior: float) -> pd.DataFrame:
    rank = _time_rank(incidents)
    classification = incidents["IncidentGrade"].map(
        {name: code for code, name in enumerate(CLASSIFICATIONS)}).fillna(-1).to_numpy(np.int64)
    classified = classification >= 0
    true_positive = classification == 0

    whole = np.zeros(len(incidents), np.int64)
    org_classified, org_tp = _earlier_totals(whole, rank, classified, true_positive)
    rule = pd.factorize(incidents["DetectorId"])[0]
    rule_classified, rule_tp = _earlier_totals(rule, rank, classified, true_positive)
    _, rule_bp = _earlier_totals(rule, rank, classified, classification == 1)
    by_classification = _links(incidents, rank, classification)
    similar = by_classification.sum(axis=0)

    columns = {
        "org_true_positive_rate": smooth(org_tp, org_classified, prior, SMOOTH),
        "rule_true_positive_rate": smooth(rule_tp, rule_classified, prior, SMOOTH),
        "log_org_classified": np.log1p(org_classified),
        "log_rule_classified": np.log1p(rule_classified),
        **similar_inputs(by_classification[0], similar, prior),
        "similar": similar,
        "similar_true_positive": by_classification[0],
        "similar_benign_positive": by_classification[1],
        "similar_false_positive": by_classification[2],
        "rule_classified": rule_classified,
        "rule_true_positives": rule_tp,
        "rule_benign_positives": rule_bp,
    }
    return pd.DataFrame(columns, index=incidents.index)


def similar_to(incidents: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    incidents = incidents.reset_index(drop=True)
    incident, other = _pairs(incidents, _time_rank(incidents))
    position = incidents.index[incidents["IncidentId"] == incident_id][0]
    found = incidents.iloc[other[incident == position]]
    found = found[found["IncidentGrade"] != ""]
    return found.sort_values(["Timestamp", "IncidentId"], ascending=[False, True])


def similar_inputs(true_positives: np.ndarray, similar: np.ndarray, prior: float) -> dict:
    rate = smooth(true_positives, similar, prior, LINK_SMOOTH)
    return {
        "log_similar": np.log1p(similar),
        "similar_true_positive_log_odds": np.log(rate / (1 - rate)),
        "has_similar_true_positive": (true_positives > 0).astype(np.float64),
    }


def smooth(positives: np.ndarray, total: np.ndarray, prior: float,
           strength: float) -> np.ndarray:
    return (positives + strength * prior) / (total + strength)


def _earlier_totals(key: np.ndarray, rank: np.ndarray, classified: np.ndarray,
                    true_positive: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.DataFrame({"key": key, "rank": rank, "classified": classified.astype(np.int64),
                          "tp": true_positive.astype(np.int64)})
    at = frame.groupby(["key", "rank"]).sum()
    before = at.groupby(level="key").cumsum() - at
    found = before.reindex(pd.MultiIndex.from_arrays([key, rank]))
    return found["classified"].to_numpy(), found["tp"].to_numpy()


def _time_rank(incidents: pd.DataFrame) -> np.ndarray:
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    return pd.factorize(times, sort=True)[0].astype(np.int64)


def _links(incidents: pd.DataFrame, rank: np.ndarray,
           classification: np.ndarray) -> np.ndarray:
    count = len(incidents)
    incident, other = _pairs(incidents, rank)
    by_classification = np.zeros((len(CLASSIFICATIONS), count), np.int64)
    for code in range(len(CLASSIFICATIONS)):
        by_classification[code] = np.bincount(incident[classification[other] == code],
                                              minlength=count)
    return by_classification


def _pairs(incidents: pd.DataFrame,
           rank: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    count = len(incidents)
    entries = _entries(incidents, rank)
    entries = entries.sort_values(["value", "rank"], kind="stable", ignore_index=True)
    owner = entries["owner"].to_numpy()
    row = entries.index.to_numpy()
    value_start = row - entries.groupby("value").cumcount().to_numpy()
    time_start = row - entries.groupby(["value", "rank"]).cumcount().to_numpy()

    # the entry `back` rows before the first row of its own time is one of its CAP predecessors
    pairs = []
    for back in range(1, CAP + 1):
        before = time_start - back
        inside = before >= value_start
        pairs.append(owner[inside] * count + owner[before[inside]])
    pairs = np.unique(np.concatenate(pairs))
    return pairs // count, pairs % count


def _entries(incidents: pd.DataFrame, rank: np.ndarray) -> pd.DataFrame:
    parts, offset = [], 0
    for column in LINKS:
        cells = incidents[column].reset_index(drop=True)
        split = cells[cells != ""].str.split(SEPARATOR).explode()
        codes, distinct = pd.factorize(split)
        parts.append(pd.DataFrame({"owner": split.index.to_numpy(np.int64),
                                   "value": codes.astype(np.int64) + offset}))
        offset += len(distinct)
    entries = pd.concat(parts, ignore_index=True)
    entries["rank"] = rank[entries["owner"].to_numpy()]
    return entries
