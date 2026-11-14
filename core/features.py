# The ten inputs of the score, each taken from incidents strictly earlier in the file.

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
# link entries expanded per pass; at most CAP pairs each, so this bounds memory
CHUNK = 200_000


def compute(incidents: pd.DataFrame, prior: float) -> pd.DataFrame:
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    rank = pd.factorize(times, sort=True)[0].astype(np.int64)
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
        "org_true_positive_rate": _smooth(org_tp, org_graded, prior),
        "rule_true_positive_rate": _smooth(rule_tp, rule_graded, prior),
        "log_org_graded": np.log1p(org_graded),
        "log_rule_graded": np.log1p(rule_graded),
        "log_linked": np.log1p(linked),
        "log_linked_true_positive": np.log1p(by_grade[0]),
        "log_linked_benign_positive": np.log1p(by_grade[1]),
        "log_linked_false_positive": np.log1p(by_grade[2]),
        "linked_true_positive_rate": _smooth(by_grade[0], linked, prior),
        "has_link": has_link.astype(np.float64),
        "linked": linked,
        "linked_true_positive": by_grade[0],
        "linked_benign_positive": by_grade[1],
        "linked_false_positive": by_grade[2],
    }
    return pd.DataFrame(columns, index=incidents.index)


def _smooth(positives: np.ndarray, total: np.ndarray, prior: float) -> np.ndarray:
    return (positives + SMOOTH * prior) / (total + SMOOTH)


def _earlier_totals(key: np.ndarray, rank: np.ndarray, graded: np.ndarray,
                    true_positive: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.DataFrame({"key": key, "rank": rank, "graded": graded.astype(np.int64),
                          "tp": true_positive.astype(np.int64)})
    at = frame.groupby(["key", "rank"]).sum()
    before = at.groupby(level="key").cumsum() - at
    found = before.reindex(pd.MultiIndex.from_arrays([key, rank]))
    return found["graded"].to_numpy(), found["tp"].to_numpy()


def _links(incidents: pd.DataFrame, rank: np.ndarray,
           grade: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    count = len(incidents)
    owner, value = _entries(incidents)
    common = np.bincount(value)[value] / count > PLACEHOLDER_SHARE
    owner, value = owner[~common], value[~common]
    has_link = np.bincount(owner, minlength=count) > 0

    # each value's entries in time order; an entry links to the CAP entries before its time
    times = int(rank.max()) + 1 if count else 1
    key = value * times + rank[owner]
    order = np.argsort(key, kind="stable")
    key, owner, value = key[order], owner[order], value[order]
    group_start = np.searchsorted(key, value * times)
    time_start = np.searchsorted(key, key)
    window_start = np.maximum(group_start, time_start - CAP)

    by_owner = np.argsort(owner, kind="stable")
    pointer = np.searchsorted(owner[by_owner], np.arange(count + 1))
    bounds = np.unique(np.append(np.searchsorted(pointer, np.arange(0, len(owner), CHUNK)),
                                 count))
    by_grade = np.zeros((len(GRADES), count), np.int64)
    for first, last in zip(bounds[:-1], bounds[1:], strict=True):
        mine = by_owner[pointer[first]:pointer[last]]
        row, earlier = _expand(window_start[mine], time_start[mine])
        pairs = np.unique(owner[mine][row] * count + owner[earlier])
        incident, other = pairs // count, pairs % count
        for code in range(len(GRADES)):
            by_grade[code] += np.bincount(incident[grade[other] == code], minlength=count)
    return by_grade, has_link


def _entries(incidents: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    owners, values, offset = [], [], 0
    for column in LINKS:
        cells = incidents[column].reset_index(drop=True)
        split = cells[cells != ""].str.split(SEPARATOR).explode()
        codes, distinct = pd.factorize(split)
        owners.append(split.index.to_numpy(np.int64))
        values.append(codes.astype(np.int64) + offset)
        offset += len(distinct)
    return np.concatenate(owners), np.concatenate(values)


def _expand(start: np.ndarray, stop: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    lengths = stop - start
    row = np.repeat(np.arange(len(start)), lengths)
    offset = np.cumsum(lengths) - lengths
    return row, np.arange(int(lengths.sum())) - offset[row] + start[row]
