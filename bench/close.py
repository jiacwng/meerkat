# Replays closing on GUIDE_Train.csv: each organisation's close level is fixed on its train period, then applied to its test period.

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from train import MIN_TEST, TRAIN_SHARE, _blank_markers, read_guide

from core import close, features, rank

MIN_TEST_TRUE_POSITIVES = 5


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("guide", type=Path, help="path to GUIDE_Train.csv")
    args = parser.parse_args()

    incidents = read_guide(args.guide)
    print(f"{_blank_markers(incidents)} placeholder values blanked")
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    nanos = times.dt.as_unit("ns").astype("int64").to_numpy()
    cut = int(np.quantile(nanos, TRAIN_SHARE))
    train, test = nanos < cut, nanos >= cut
    label = (incidents["IncidentGrade"] == "TruePositive").to_numpy()

    weights = rank.load_weights()
    organisations = incidents_total = set_aside = positives = missed = 0
    for _, rows in incidents.groupby("OrgId", sort=False):
        at = rows.index.to_numpy()
        in_train, in_test, positive = train[at], test[at], label[at]
        if (in_test.sum() < MIN_TEST
                or (in_test & positive).sum() < MIN_TEST_TRUE_POSITIVES):
            continue

        found = features.compute(rows, weights["prior"])
        standard = ((found[list(features.INPUTS)].to_numpy() - np.array(weights["mean"]))
                    / np.array(weights["scale"]))
        logit = standard @ np.array(weights["coefficients"]) + weights["intercept"]
        score = 1 / (1 + np.exp(-logit))

        entries = pd.DataFrame({"score": score[in_train & positive], "weight": 1.0})
        level = close.close_level(entries, close.DEFAULT_MISS_RATE)
        closed = np.zeros(len(rows), bool)
        if level is not None:
            closed = in_test & (score < level)
            if close.DEFAULT_KEEP_SIMILAR:
                closed = closed & (found["similar_true_positive"].to_numpy() < 1)
            closed = closed & (found["rule_classified"].to_numpy() > 0)

        organisations += 1
        incidents_total += in_test.sum()
        set_aside += closed.sum()
        positives += (in_test & positive).sum()
        missed += (closed & positive).sum()

    print(f"{organisations} organisations, {incidents_total} test incidents")
    print(f"set aside {set_aside} test incidents ({set_aside / incidents_total:.4f})")
    print(f"{positives} test true positives, set aside {missed} ({missed / positives:.4f})")


if __name__ == "__main__":
    main()
