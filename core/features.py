# The ten inputs of the score, each taken from incidents strictly earlier in time.

import numpy as np
import pandas as pd

from core.incidents import GRADES, LINKS, SEPARATOR

INPUTS = (
    "org_true_positive_rate", "rule_true_positive_rate", "log_org_graded",
    "log_rule_graded", "log_linked", "log_linked_true_positive",
    "log_linked_benign_positive", "log_linked_false_positive",
    "linked_true_positive_rate", "has_link",
)
LINKED = ("linked", "linked_true_positive", "linked_benign_positive",
          "linked_false_positive")
SMOOTH = 5.0
PLACEHOLDER_SHARE = 0.5
CAP = 50


def compute(incidents: pd.DataFrame, prior: float) -> pd.DataFrame:
    rank = _time_rank(incidents)
    grade = incidents["IncidentGrade"].map(
        {name: code for code, name in enumerate(GRADES)}).fillna(-1).to_numpy(np.int64)
    graded = grade >= 0
    true_positive = grade == 0

    whole = np.zeros(len(incidents), np.int64)
    org_graded, org_tp = _earlier_totals(whole, rank, graded, true_positive)
    rule = pd.factorize(incidents["DetectorId"])[0]
    rule_graded, rule_tp = _earlier_totals(rule, rank, graded, true_positive)
    by_grade, has_link = _links(incidents, rank, grade)
    linked = by_grade.sum(axis=0)

    columns = {
        "org_true_positive_rate": smooth(org_tp, org_graded, prior),
        "rule_true_positive_rate": smooth(rule_tp, rule_graded, prior),
        "log_org_graded": np.log1p(org_graded),
        "log_rule_graded": np.log1p(rule_graded),
        "log_linked": np.log1p(linked),
        "log_linked_true_positive": np.log1p(by_grade[0]),
        "log_linked_benign_positive": np.log1p(by_grade[1]),
        "log_linked_false_positive": np.log1p(by_grade[2]),
        "linked_true_positive_rate": smooth(by_grade[0], linked, prior),
        "has_link": has_link.astype(np.float64),
        "linked": linked,
        "linked_true_positive": by_grade[0],
        "linked_benign_positive": by_grade[1],
        "linked_false_positive": by_grade[2],
    }
    return pd.DataFrame(columns, index=incidents.index)


def linked_to(incidents: pd.DataFrame, incident_id: str) -> pd.DataFrame:
    incidents = incidents.reset_index(drop=True)
    incident, other, _ = _pairs(incidents, _time_rank(incidents))
    position = incidents.index[incidents["IncidentId"] == incident_id][0]
    found = incidents.iloc[other[incident == position]]
    found = found[found["IncidentGrade"] != ""]
    return found.sort_values(["Timestamp", "IncidentId"], ascending=[False, True])


def smooth(positives: np.ndarray, total: np.ndarray, prior: float) -> np.ndarray:
    return (positives + SMOOTH * prior) / (total + SMOOTH)


def _earlier_totals(key: np.ndarray, rank: np.ndarray, graded: np.ndarray,
                    true_positive: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.DataFrame({"key": key, "rank": rank, "graded": graded.astype(np.int64),
                          "tp": true_positive.astype(np.int64)})
    at = frame.groupby(["key", "rank"]).sum()
    before = at.groupby(level="key").cumsum() - at
    found = before.reindex(pd.MultiIndex.from_arrays([key, rank]))
    return found["graded"].to_numpy(), found["tp"].to_numpy()


def _time_rank(incidents: pd.DataFrame) -> np.ndarray:
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    return pd.factorize(times, sort=True)[0].astype(np.int64)


def _links(incidents: pd.DataFrame, rank: np.ndarray,
           grade: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    count = len(incidents)
    incident, other, has_link = _pairs(incidents, rank)
    by_grade = np.zeros((len(GRADES), count), np.int64)
    for code in range(len(GRADES)):
        by_grade[code] = np.bincount(incident[grade[other] == code], minlength=count)
    return by_grade, has_link


def _pairs(incidents: pd.DataFrame,
           rank: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    count = len(incidents)
    entries = _entries(incidents, rank)
    share = entries.groupby("value")["owner"].transform("size") / count
    entries = entries[share <= PLACEHOLDER_SHARE]
    has_link = np.zeros(count, bool)
    has_link[entries["owner"]] = True

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
    return pairs // count, pairs % count, has_link


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
