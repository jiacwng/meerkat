"""Turn a normalized alert table into numbers a classifier can learn from.

Public API:
    build_feature_matrix(df) -> FeatureMatrix
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

import numpy as np
import pandas as pd

PRIORITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
WINDOW_S = 60.0


@dataclass
class FeatureMatrix:
    X: pd.DataFrame
    y: pd.Series
    attack_window: pd.Series
    feature_names: list[str]


def compute_urgency_tier(df: pd.DataFrame) -> pd.Series:

    detector, severity = df["detector_source"], df["severity"]
    tier = pd.Series(0, index=df.index, name="urgency_tier")

    tier[(detector == "wazuh") & (severity >= 5)] = 1
    tier[(detector == "wazuh") & (severity >= 10)] = 2
    tier[(detector == "suricata") & (severity <= 2)] = 1
    tier[(detector == "suricata") & (severity <= 1)] = 2
    tier[detector == "aminer"] = 1
    
    return tier


def derive_priority(attack_window: pd.Series, urgency_tier: pd.Series) -> pd.Series:
    labels = []
    for window, tier in zip(attack_window, urgency_tier):
        if window != "" and tier == 2:
            labels.append("CRITICAL")
        elif window != "":
            labels.append("HIGH")
        elif tier >= 1:
            labels.append("MEDIUM")
        else:
            labels.append("LOW")
    return pd.Series(labels, index=attack_window.index, name="priority")


def add_context_features(df: pd.DataFrame) -> pd.DataFrame:
    assert df["timestamp"].is_monotonic_increasing, "normalize() must sort by time"

    burst = np.zeros(len(df))
    uniq_names = np.zeros(len(df))
    uniq_dets = np.zeros(len(df))

    for _, group in df.groupby("host", sort=False):
        timestamp = group["timestamp"].to_numpy()
        names = group["name"].to_numpy()
        dets = group["detector_source"].to_numpy()
        rows = group.index.to_numpy()
        window: deque = deque()
        name_counts: Counter = Counter()
        det_counts: Counter = Counter()

        for i in range(len(group)):
            # While there are old alert indexes in our window, and the oldest alert is more than 60s before the current, remove
            while window and timestamp[window[0]] + WINDOW_S < timestamp[i]:
                j = window.popleft()
                name_counts[names[j]] -= 1
                if name_counts[names[j]] == 0:
                    del name_counts[names[j]]
                det_counts[dets[j]] -= 1
                if det_counts[dets[j]] == 0:
                    del det_counts[dets[j]]


            burst[rows[i]] = len(window)
            uniq_names[rows[i]] = len(name_counts)
            uniq_dets[rows[i]] = len(det_counts)

            # add alert to the window
            window.append(i)
            name_counts[names[i]] += 1
            det_counts[dets[i]] += 1

    # Create a copy so our original df is not modified directly
    out = df.copy()
    out["alerts_last_60s"] = burst
    out["distinct_names_last_60s"] = uniq_names
    out["distinct_detectors_last_60s"] = uniq_dets
    out["seconds_since_last_alert"] = df.groupby("host")["timestamp"].diff().fillna(-1.0) # if no previous alert, defaults time to -1
    out["times_name_seen_before"] = df.groupby("name").cumcount().astype(float) # The feature matrix will expect floats
    return out



def build_feature_matrix(df: pd.DataFrame) -> FeatureMatrix:
    tier = compute_urgency_tier(df)
    context = add_context_features(df)

    # one hot encoding for dummy variables
    X = pd.get_dummies(
        df[["detector_source", "name", "host"]],
        prefix=["detector", "name", "host"],
        dtype=float,
    )
    # adding context features
    X["urgency_tier"] = tier.astype(float)
    for col in ("alerts_last_60s", "distinct_names_last_60s", "distinct_detectors_last_60s",
                "seconds_since_last_alert", "times_name_seen_before"):
        X[col] = context[col]

    # check if our model features do not accidentally include label information
    leaked = []

    for column in X.columns:
        if "attack_window" in column:
            leaked.append(column)

    if len(leaked) > 0:
        raise AssertionError(f"label source leaked into features: {leaked}")
    

    return FeatureMatrix(
        X=X,
        y=derive_priority(df["attack_window"], tier),
        attack_window=df["attack_window"].copy(),
        feature_names=list(X.columns),
    )




if __name__ == "__main__":
    from pathlib import Path

    from core.normalize import normalize

    fm = build_feature_matrix(normalize(Path("data/ait_alerts.json"), Path("data/labels.csv")))
    print(f"X: {fm.X.shape[0]} alerts x {fm.X.shape[1]} features")
    print(fm.y.value_counts())
    for c in ("alerts_last_60s", "distinct_names_last_60s", "distinct_detectors_last_60s",
              "seconds_since_last_alert", "times_name_seen_before"):
        print(f"{c}: min {fm.X[c].min():.0f}  max {fm.X[c].max():.0f}")
