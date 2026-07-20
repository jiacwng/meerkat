"""Turn a normalized alert table into numbers a classifier can learn from.

Public API:
    build_feature_matrix(df) -> FeatureMatrix
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

import numpy as np
import pandas as pd

WINDOWS_S = (60.0, 600.0, 3600.0)   
MIN_NAME_COUNT = 50                  # threshold for the rare names bucket, depends on the size and diversity of our data
RARE_NAME = "other"


@dataclass
class FeatureMatrix:
    X: pd.DataFrame
    attack_window: pd.Series
    feature_names: list[str]
    kept_names: frozenset[str]   # fit-time artifact: names that keep their own one-hot column


def compute_urgency_tier(df: pd.DataFrame) -> pd.Series:

    detector, severity = df["detector_source"], df["severity"]
    tier = pd.Series(0, index=df.index, name="urgency_tier")

    tier[(detector == "wazuh") & (severity >= 5)] = 1
    tier[(detector == "wazuh") & (severity >= 10)] = 2
    tier[(detector == "suricata") & (severity <= 2)] = 1
    tier[(detector == "suricata") & (severity <= 1)] = 2
    tier[detector == "aminer"] = 1
    
    return tier


def bucket_rare_names(names: pd.Series, kept_names: frozenset[str] | None = None) -> tuple[pd.Series, frozenset[str]]:
    if kept_names is None:
        counts = names.value_counts()
        kept_names = frozenset(counts[counts >= MIN_NAME_COUNT].index)
    bucketed = names.where(names.isin(kept_names), RARE_NAME)
    return bucketed, kept_names


def _counts_in_window(timestamps: np.ndarray, window: float) -> np.ndarray:
    starts = np.searchsorted(timestamps, timestamps - window, side="left")
    return np.arange(len(timestamps)) - starts

def add_context_features(df: pd.DataFrame) -> pd.DataFrame:
    # fail check on new data
    assert df["timestamp"].is_monotonic_increasing, "normalize() must sort by time"

    # Create a copy so our original df is not modified directly
    out = df.copy()

    for window_s in WINDOWS_S:
        tag = f"{int(window_s)}s"
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
                # evict alerts older than the window before counting
                while window and timestamp[window[0]] + window_s < timestamp[i]:
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

        out[f"host_alerts_last_{tag}"] = burst
        out[f"host_distinct_names_last_{tag}"] = uniq_names
        out[f"host_distinct_detectors_last_{tag}"] = uniq_dets

    # global + per-detector streams
    all_timestamps = df["timestamp"].to_numpy()
    for window_s in WINDOWS_S:
        tag = f"{int(window_s)}s"
        out[f"global_alerts_last_{tag}"] = _counts_in_window(all_timestamps, window_s).astype(float)
        per_detector = np.zeros(len(df))
        for _, group in df.groupby("detector_source", sort=False):
            counts = _counts_in_window(group["timestamp"].to_numpy(), window_s)
            per_detector[group.index.to_numpy()] = counts
        out[f"detector_alerts_last_{tag}"] = per_detector

    out["seconds_since_last_alert"] = df.groupby("host")["timestamp"].diff().fillna(-1.0) # if no previous alert, defaults time to -1
    out["times_name_seen_before"] = df.groupby("name").cumcount().astype(float) # The feature matrix will expect floats
    out["first_time_on_host"] = (df.groupby(["host", "name"]).cumcount() == 0).astype(float)
    return out



def build_feature_matrix(df: pd.DataFrame,
                         kept_names: frozenset[str] | None = None) -> FeatureMatrix:
    tier = compute_urgency_tier(df)
    context = add_context_features(df)
    # kept_names is computed here at training time, and passed
    # back in at prediction time so new data one-hot-encodes identically
    bucketed_names, kept_names = bucket_rare_names(df["name"], kept_names)

    # one hot encoding for dummy variables (bucketed names, not raw)
    onehot_input = pd.DataFrame({
        "detector_source": df["detector_source"],
        "name": bucketed_names,
        "host": df["host"],
    })
    X = pd.get_dummies(onehot_input, prefix=["detector", "name", "host"], dtype=float)

    X["urgency_tier"] = tier.astype(float)
    # every column add_context_features created 
    for col in context.columns:
        if col not in df.columns:
            X[col] = context[col]

    # the ground-truth column must never become a feature
    leaked = [col for col in X.columns if "attack_window" in col]
    if leaked:
        raise AssertionError(f"label source leaked into features: {leaked}")

    return FeatureMatrix(
        X=X,
        attack_window=df["attack_window"].copy(),
        feature_names=list(X.columns),
        kept_names=kept_names,
    )




if __name__ == "__main__":
    from pathlib import Path

    from core.normalize import normalize

    fm = build_feature_matrix(normalize(Path("data/ait_alerts.json"), Path("data/labels.csv")))
    print(f"X: {fm.X.shape[0]} alerts x {fm.X.shape[1]} features")
    print(f"kept names: {len(fm.kept_names)}")
    for c in ("host_alerts_last_60s", "host_alerts_last_3600s", "global_alerts_last_600s",
              "detector_alerts_last_600s", "seconds_since_last_alert", "first_time_on_host"):
        print(f"{c}: min {fm.X[c].min():.0f}  max {fm.X[c].max():.0f}")
