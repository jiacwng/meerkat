# Scores the later 40% of GUIDE when an earlier incident's grade is only known some time after it starts.

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from bench.train import HISTORY, TRAIN_SHARE, _blank_markers, _per_org, read_guide
from core import features, rank
from core.incidents import CLASSIFICATIONS

DELAYS = {"0": 0, "1 hour": 3600, "1 day": 86400, "7 days": 7 * 86400}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("guide", type=Path, help="path to GUIDE_Train.csv")
    args = parser.parse_args()

    incidents = read_guide(args.guide)
    _blank_markers(incidents)
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    nanos = times.dt.as_unit("ns").astype("int64").to_numpy()
    cut = int(np.quantile(nanos, TRAIN_SHARE))
    train, test = nanos < cut, nanos >= cut
    label = (incidents["IncidentGrade"] == "TruePositive").to_numpy(np.int64)
    prior = float(label[train].mean())
    org = incidents["OrgId"].to_numpy()
    weights = rank.load_weights()

    for name, delay in DELAYS.items():
        inputs = pd.concat(delayed(frame, prior, delay)
                           for _, frame in incidents.groupby("OrgId", sort=False))
        inputs = inputs.loc[incidents.index]
        shipped = inputs[list(features.INPUTS)].to_numpy()
        logit = ((shipped - weights["mean"]) / weights["scale"]) @ weights["coefficients"]
        print(f"delay {name}")
        scored = _report("shipped weights", label[test], logit[test], org[test])
        model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
        model.fit(inputs.loc[train, list(HISTORY)].to_numpy(), label[train])
        history = model.predict_proba(inputs.loc[test, list(HISTORY)].to_numpy())[:, 1]
        alone = _report("history only", label[test], history, org[test])
        gain = [scored[organisation] - alone[organisation] for organisation in scored]
        print(f"  gain per organisation: mean {np.mean(gain):.4f}, median {np.median(gain):.4f}")
        _report("rule rate alone", label[test],
                inputs.loc[test, "rule_true_positive_rate"].to_numpy(), org[test])


def delayed(incidents: pd.DataFrame, prior: float, delay: int) -> pd.DataFrame:
    # an earlier incident still counts as similar inside the delay, only without its grade
    seconds = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    seconds = seconds.dt.as_unit("s").astype("int64").to_numpy()
    code = incidents["IncidentGrade"].map(
        {name: code for code, name in enumerate(CLASSIFICATIONS)}).fillna(-1).to_numpy(np.int64)
    whole = np.zeros(len(incidents), np.int64)
    rule = pd.factorize(incidents["DetectorId"])[0]
    org_classified = _known_before(seconds, whole, code >= 0, delay)
    org_tp = _known_before(seconds, whole, code == 0, delay)
    rule_classified = _known_before(seconds, rule, code >= 0, delay)
    rule_tp = _known_before(seconds, rule, code == 0, delay)

    incident, other = features._pairs(incidents.reset_index(drop=True),
                                      features._time_rank(incidents))
    known = seconds[incident] - seconds[other] > delay
    incident, other = incident[known], other[known]
    by_classification = np.array([np.bincount(incident[code[other] == number],
                                              minlength=len(incidents))
                                  for number in range(len(CLASSIFICATIONS))])
    return pd.DataFrame({
        "org_true_positive_rate": features.smooth(org_tp, org_classified, prior,
                                                  features.SMOOTH),
        "rule_true_positive_rate": features.smooth(rule_tp, rule_classified, prior,
                                                   features.SMOOTH),
        "log_org_classified": np.log1p(org_classified),
        "log_rule_classified": np.log1p(rule_classified),
        **features.similar_inputs(by_classification[0], by_classification.sum(axis=0), prior),
    }, index=incidents.index)


def _known_before(seconds: np.ndarray, key: np.ndarray, counted: np.ndarray,
                  delay: int) -> np.ndarray:
    found = np.zeros(len(seconds), np.int64)
    for rows in pd.Series(key).groupby(key).indices.values():
        order = np.argsort(seconds[rows], kind="stable")
        running = np.concatenate([[0], np.cumsum(counted[rows][order])])
        found[rows] = running[np.searchsorted(seconds[rows][order], seconds[rows] - delay)]
    return found


def _report(name: str, label: np.ndarray, score: np.ndarray, org: np.ndarray) -> dict:
    per_org = _per_org(label, score, org)
    print(f"  {name:<16} pooled AP {average_precision_score(label, score):.4f}, mean per "
          f"organisation AP {np.mean(list(per_org.values())):.4f} over {len(per_org)}")
    return per_org


if __name__ == "__main__":
    main()
