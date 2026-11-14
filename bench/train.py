# Fits the score's weights on GUIDE_Train.csv and writes them to core/data/weights.json.

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from core import features, rank
from core.incidents import LINKS, SEPARATOR

KEY = ["OrgId", "IncidentId"]
TRAIN_SHARE = 0.6
MIN_TEST = 20
HISTORY = features.INPUTS[:4]


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
    label = (incidents["IncidentGrade"] == "TruePositive").to_numpy(np.int64)
    prior = float(label[train].mean())

    inputs = pd.concat(features.compute(org, prior)
                       for _, org in incidents.groupby("OrgId", sort=False))
    inputs = inputs.loc[incidents.index]
    org = incidents["OrgId"].to_numpy()
    print(f"{len(incidents)} incidents, {incidents['OrgId'].nunique()} organisations, "
          f"cut {pd.Timestamp(cut, tz='UTC')}, {train.sum()} train, {test.sum()} test")

    results = {}
    for name, columns in (("history", HISTORY), ("all", features.INPUTS)):
        model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
        model.fit(inputs.loc[train, list(columns)].to_numpy(), label[train])
        predicted = model.predict_proba(inputs.loc[test, list(columns)].to_numpy())[:, 1]
        per_org = _per_org(label[test], predicted, org[test])
        results[name] = (model, per_org)
        print(f"{name:<8} {len(columns):>2} inputs: pooled AP "
              f"{average_precision_score(label[test], predicted):.4f}, mean per organisation AP "
              f"{np.mean(list(per_org.values())):.4f} over {len(per_org)} organisations")
    history, every = results["history"][1], results["all"][1]
    gain = [every[org_id] - history[org_id] for org_id in every]
    print(f"mean per organisation gain {np.mean(gain):.4f}, median {np.median(gain):.4f}")

    scaler, regression = results["all"][0].named_steps.values()
    weights = {
        "inputs": list(features.INPUTS),
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "coefficients": regression.coef_[0].tolist(),
        "intercept": float(regression.intercept_[0]),
        "prior": prior,
        "provenance": {
            "dataset": "Microsoft GUIDE, GUIDE_Train.csv, graded incidents",
            "incidents": int(train.sum()),
            "organisations": int(incidents.loc[train, "OrgId"].nunique()),
            "time_cut": pd.Timestamp(cut, tz="UTC").strftime("%Y-%m-%dT%H:%M:%SZ"),
            "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        },
    }
    rank.WEIGHTS.parent.mkdir(exist_ok=True)
    rank.WEIGHTS.write_text(json.dumps(weights, indent=2) + "\n")
    print(f"wrote {rank.WEIGHTS}")


def read_guide(path: Path) -> pd.DataFrame:
    # an incident takes its time and rule from its earliest row, as core.incidents does
    firsts, grades, values = [], [], []
    wanted = [*KEY, "Timestamp", "DetectorId", "IncidentGrade", *LINKS]
    for rows in pd.read_csv(path, usecols=wanted, dtype=str, keep_default_na=False,
                            chunksize=1_000_000):
        rows = rows.sort_values("Timestamp", kind="stable")
        firsts.append(rows.groupby(KEY, sort=False)[["Timestamp", "DetectorId"]].first())
        graded = rows[rows["IncidentGrade"] != ""]
        grades.append(graded.groupby(KEY, sort=False)["IncidentGrade"].first())
        for column in LINKS:
            found = rows.loc[rows[column] != "", [*KEY, column]].drop_duplicates()
            values.append(found.rename(columns={column: "value"}).assign(column=column))

    first = pd.concat(firsts).sort_values("Timestamp", kind="stable")
    incidents = first[~first.index.duplicated()].copy()
    grade = pd.concat(grades)
    incidents["IncidentGrade"] = grade[~grade.index.duplicated()]
    incidents = incidents[incidents["IncidentGrade"].notna()]

    links = pd.concat(values).drop_duplicates().sort_values("value")
    joined = links.groupby([*KEY, "column"])["value"].agg(SEPARATOR.join)
    joined = joined.unstack("column").reindex(columns=list(LINKS))
    incidents = incidents.join(joined).fillna("")
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601")
    incidents["Timestamp"] = times.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return incidents.reset_index()


def _blank_markers(incidents: pd.DataFrame) -> int:
    # GUIDE writes a missing value as a fixed id; a real file leaves the cell blank
    blanked = 0
    for column in LINKS:
        values = incidents[column].str.split(SEPARATOR).explode()
        values = values[values != ""]
        share = values.value_counts() / len(incidents)
        markers = share[share > features.PLACEHOLDER_SHARE].index
        blanked += len(markers)
        kept = values[~values.isin(markers)]
        incidents[column] = (kept.groupby(level=0).agg(SEPARATOR.join)
                             .reindex(incidents.index).fillna(""))
    return blanked


def _per_org(label: np.ndarray, predicted: np.ndarray, org: np.ndarray) -> dict:
    frame = pd.DataFrame({"org": org, "label": label, "predicted": predicted})
    scores = {}
    for name, group in frame.groupby("org"):
        if len(group) >= MIN_TEST and 0 < group["label"].sum() < len(group):
            scores[name] = average_precision_score(group["label"], group["predicted"])
    return scores


if __name__ == "__main__":
    main()
