"""Random Forest priority classifier with SOC-oriented evaluation.

Public API:
    train(X, y, attack_window)   -> (model, Holdout)
    evaluate(model, holdout)     -> EvalReport
    predict(model, X)            -> (labels, attack risks)
    explain_prediction(model, x_row, feature_names) -> top feature drivers
    save_model(model, path) / load_model(path)
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

ESCALATE = ("CRITICAL", "HIGH")


@dataclass(frozen=True)
class RiskThresholds:
    medium: float = 0.20
    high: float = 0.50
    critical: float = 0.80


DEFAULT_THRESHOLDS = RiskThresholds()


@dataclass
class Holdout:
    # For rows to stay aligned
    X_test: pd.DataFrame
    y_test: pd.Series
    attack_window_test: pd.Series


@dataclass
class EvalReport:
    accuracy: float
    macro_f1: float
    per_class: dict[str, dict[str, float]]
    confusion: np.ndarray
    labels: list[str]
    attack_recall: float
    false_alarm_rate: float


def train(
    X: pd.DataFrame,
    y: pd.Series,
    attack_window: pd.Series,
    # 80/20 split with 300 trees for now
    test_size: float = 0.2,
    n_estimators: int = 300,
    seed: int = 0,
) -> tuple[RandomForestClassifier, Holdout]:
    split_at = int(len(X) * (1 - test_size))

    # normalize() sorts by time, so the final rows form a future holdout.
    X_train, X_test = X.iloc[:split_at], X.iloc[split_at:]
    y_test = y.iloc[split_at:]
    window_train = attack_window.iloc[:split_at]
    window_test = attack_window.iloc[split_at:]

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train, window_train.ne(""))
    return model, Holdout(X_test, y_test, window_test)



def evaluate(
    model: RandomForestClassifier,
    holdout: Holdout,
    thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
) -> EvalReport:
    predicted, _ = predict(model, holdout.X_test, thresholds)
    labels = sorted(set(holdout.y_test))
    report = classification_report(
        holdout.y_test, predicted, labels=labels, output_dict=True, zero_division=0
    )
    per_class = {}
    for label in labels:
        per_class[label] = {
            "precision": report[label]["precision"],
            "recall": report[label]["recall"],
            "f1": report[label]["f1-score"],
            "support": report[label]["support"],
        }

    """2 additional metrics, we label the critical/high labeled predictions
    as escalated, then measure 2 additional metrics :
    attack_recall: recall inside a real attack window
    false_alarm_rate: escalated predictions that are outside a real attack window"""
    escalated = pd.Series(predicted).isin(ESCALATE).to_numpy()
    in_window = holdout.attack_window_test.ne("").to_numpy()
    attack_recall = escalated[in_window].mean()
    false_alarm_rate = escalated[~in_window].mean()

    return EvalReport(
            accuracy=report["accuracy"],
            macro_f1=report["macro avg"]["f1-score"],
            per_class=per_class,
            confusion=confusion_matrix(holdout.y_test, predicted, labels=labels),
            labels=labels,
            attack_recall=attack_recall,
            false_alarm_rate=false_alarm_rate,
        )

def priority_from_risk(
    risk: np.ndarray,
    urgency_tier: pd.Series,
    thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
) -> np.ndarray:
    """Translate attack risk and native urgency into analyst action bands."""
    risk = np.asarray(risk, dtype=float)
    urgency = np.asarray(urgency_tier, dtype=float)

    labels = np.full(len(risk), "LOW", dtype=object)
    labels[(risk >= thresholds.medium) | (urgency >= 1)] = "MEDIUM"
    labels[risk >= thresholds.high] = "HIGH"
    labels[(risk >= thresholds.critical) & (urgency >= 2)] = "CRITICAL"
    return labels


def predict(
    model: RandomForestClassifier,
    X: pd.DataFrame,
    thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
) -> tuple[np.ndarray, np.ndarray]:
    risk = model.predict_proba(X)[:, 1]
    labels = priority_from_risk(risk, X["urgency_tier"], thresholds)
    return labels, risk


def explain_prediction(
    model: RandomForestClassifier,
    x_row: pd.Series,
    feature_names: list[str],
    top: int = 3,
) -> list[tuple[str, float, float]]:
    """Return the top active features for this alert, sorted by model importance
    we assume a prediction has already been made"""
    importances = model.feature_importances_
    active = []
    for position, name in enumerate(feature_names):
        value = x_row[name]

        if value != 0:
            active.append((name, float(value), float(importances[position])))

    active.sort(key=lambda entry: entry[2], reverse=True)

    return active[:top]


def save_model(model: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(model, fh)


def load_model(path: Path) -> object:
    with path.open("rb") as fh:
        return pickle.load(fh)


if __name__ == "__main__":
    from core.features import build_feature_matrix
    from core.normalize import normalize

    fm = build_feature_matrix(normalize(Path("data/ait_alerts.json"), Path("data/labels.csv")))
    model, holdout = train(fm.X, fm.y, fm.attack_window)
    report = evaluate(model, holdout)

    print(f"accuracy {report.accuracy:.1%}   macro-F1 {report.macro_f1:.3f}")
    print(f"attack-window recall {report.attack_recall:.1%}   "
          f"false alarm rate {report.false_alarm_rate:.2%}")
    for label in report.labels:
        m = report.per_class[label]
        print(f"  {label:9s} precision {m['precision']:.3f}  recall {m['recall']:.3f}"
              f"  f1 {m['f1']:.3f}  n={m['support']:.0f}")

    labels, risks = predict(model, holdout.X_test)
    first_critical = int(np.flatnonzero(labels == "CRITICAL")[0])
    drivers = explain_prediction(model, holdout.X_test.iloc[first_critical], fm.feature_names)
    pretty = ", ".join(f"{name}={value:g}" for name, value, _ in drivers)
    print(f"sample CRITICAL ({risks[first_critical]:.0%} attack risk): {pretty}")
