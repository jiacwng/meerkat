"""Random Forest attack-window risk model with SOC-oriented evaluation.

Public API:
    fit_model(X, attack_window)  -> fitted model
    train(X, attack_window)      -> (model, Holdout)
    evaluate(model, holdout)     -> EvalReport
    evaluate_risk(validation_risk, test_risk, holdout) -> EvalReport
    threshold_curve(risk, attack_window) -> threshold operating points
    select_threshold(curve)      -> validation-selected threshold
    analyst_budget_curve(risk, attack_window) -> Recall@K table
    phase_recall(risk, attack_window, threshold) -> per-phase table
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


@dataclass(frozen=True)
class RiskThresholds:
    medium: float = 0.20
    high: float = 0.50
    critical: float = 0.80


DEFAULT_THRESHOLDS = RiskThresholds()

# evaluation policy
ANALYST_BUDGETS = (10, 50, 100, 250, 500, 1000)
THRESHOLD_GRID = tuple(i / 20 for i in range(21))
MINIMUM_WINDOW_RECALL = 0.95


@dataclass
class Holdout:
    # Keep each partition's rows and labels aligned.
    X_validation: pd.DataFrame
    attack_window_validation: pd.Series
    X_test: pd.DataFrame
    attack_window_test: pd.Series


@dataclass
class EvalReport:
    selected_threshold: float
    reviewed_alerts: int
    window_recall: float
    window_precision: float
    outside_window_review_rate: float
    workload_reduction: float
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    validation_curve: pd.DataFrame
    budget_curve: pd.DataFrame
    phase_recall: pd.DataFrame
    test_risk: np.ndarray


def fit_model(
    X: pd.DataFrame,
    attack_window: pd.Series,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, attack_window.ne(""))
    return model


def category_weights(event_label: pd.Series) -> dict[str, float]:
    """Give rare event categories more influence without extreme weights."""
    counts = event_label[event_label.ne("")].value_counts().astype(float)
    raw = (counts.max() / counts).pow(0.5).clip(upper=10.0)
    scale = float((raw * counts).sum() / counts.sum())
    return {category: float(weight / scale) for category, weight in raw.items()}


def fit_event_model(
    X: pd.DataFrame,
    event_label: pd.Series,
    weights: dict[str, float] | None = None,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    """Train a forest to rank event-labeled alerts above unlabeled alerts."""
    sample_weight = None
    if weights is not None:
        sample_weight = event_label.map(weights).fillna(1.0).to_numpy()
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, event_label.ne(""), sample_weight=sample_weight)
    return model


def train(
    X: pd.DataFrame,
    attack_window: pd.Series,
    validation_size: float = 0.2,
    test_size: float = 0.2,
    n_estimators: int = 300,
    seed: int = 0,
) -> tuple[RandomForestClassifier, Holdout]:
    validation_at = int(len(X) * (1 - test_size - validation_size))
    test_at = int(len(X) * (1 - test_size))

    # normalize() sorts by time, so validation and test contain later alerts.
    X_train = X.iloc[:validation_at]
    window_train = attack_window.iloc[:validation_at]

    model = fit_model(X_train, window_train, n_estimators, seed)
    return model, Holdout(
        X_validation=X.iloc[validation_at:test_at],
        attack_window_validation=attack_window.iloc[validation_at:test_at],
        X_test=X.iloc[test_at:],
        attack_window_test=attack_window.iloc[test_at:],
    )


def threshold_curve(
    risk: np.ndarray,
    attack_window: pd.Series,
    thresholds: tuple[float, ...] = THRESHOLD_GRID,
) -> pd.DataFrame:
    risk = np.asarray(risk, dtype=float)
    in_window = attack_window.ne("").to_numpy()
    rows = []

    for threshold in thresholds:
        reviewed = risk >= threshold
        true_positive = int((reviewed & in_window).sum())
        false_positive = int((reviewed & ~in_window).sum())
        true_negative = int((~reviewed & ~in_window).sum())
        false_negative = int((~reviewed & in_window).sum())
        window_recall = (
            float(reviewed[in_window].mean())
            if in_window.any()
            else float("nan")
        )
        window_precision = (
            true_positive / int(reviewed.sum())
            if reviewed.any()
            else float("nan")
        )
        outside_window_review_rate = (
            float(reviewed[~in_window].mean())
            if (~in_window).any()
            else float("nan")
        )
        rows.append({
            "threshold": float(threshold),
            "reviewed": int(reviewed.sum()),
            "window_recall": window_recall,
            "window_precision": window_precision,
            "outside_window_review_rate": outside_window_review_rate,
            "workload_reduction": float(1 - reviewed.mean()),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        })

    return pd.DataFrame(rows)


def select_threshold(
    curve: pd.DataFrame,
    minimum_window_recall: float = MINIMUM_WINDOW_RECALL,
) -> float:
    eligible = curve[curve["window_recall"] >= minimum_window_recall]
    return float(eligible.iloc[-1]["threshold"])


def analyst_budget_curve(
    risk: np.ndarray,
    attack_window: pd.Series,
    budgets: tuple[int, ...] = ANALYST_BUDGETS,
) -> pd.DataFrame:
    risk = np.asarray(risk, dtype=float)
    in_window = attack_window.ne("").to_numpy()
    order = np.argsort(-risk, kind="stable")
    window_total = int(in_window.sum())
    rows = []

    for budget in budgets:
        reviewed = min(budget, len(risk))
        chosen = order[:reviewed]
        found = int(in_window[chosen].sum())
        rows.append({
            "budget": budget,
            "reviewed": reviewed,
            "window_alerts_found": found,
            "window_alerts_total": window_total,
            "recall_at_k": found / window_total if window_total else float("nan"),
            "workload_reduction": 1 - reviewed / len(risk),
        })

    return pd.DataFrame(rows)


def phase_recall(
    risk: np.ndarray,
    attack_window: pd.Series,
    threshold: float,
) -> pd.DataFrame:
    risk = np.asarray(risk, dtype=float)
    windows = attack_window.reset_index(drop=True)
    reviewed = risk >= threshold
    phases = windows[windows.ne("")].drop_duplicates()
    rows = []

    for phase in phases:
        phase_rows = windows.eq(phase).to_numpy()
        rows.append({
            "phase": phase,
            "support": int(phase_rows.sum()),
            "reviewed": int(reviewed[phase_rows].sum()),
            "recall": float(reviewed[phase_rows].mean()),
        })

    return pd.DataFrame(rows, columns=["phase", "support", "reviewed", "recall"])


def evaluate_risk(
    validation_risk: np.ndarray,
    test_risk: np.ndarray,
    holdout: Holdout,
    budgets: tuple[int, ...] = ANALYST_BUDGETS,
    thresholds: tuple[float, ...] = THRESHOLD_GRID,
    minimum_window_recall: float = MINIMUM_WINDOW_RECALL,
) -> EvalReport:
    validation_risk = np.asarray(validation_risk, dtype=float)
    test_risk = np.asarray(test_risk, dtype=float)
    validation_curve = threshold_curve(
        validation_risk,
        holdout.attack_window_validation,
        thresholds,
    )
    selected_threshold = select_threshold(
        validation_curve,
        minimum_window_recall,
    )

    operating_point = threshold_curve(
        test_risk,
        holdout.attack_window_test,
        (selected_threshold,),
    ).iloc[0]

    return EvalReport(
        selected_threshold=selected_threshold,
        reviewed_alerts=int(operating_point["reviewed"]),
        window_recall=float(operating_point["window_recall"]),
        window_precision=float(operating_point["window_precision"]),
        outside_window_review_rate=float(
            operating_point["outside_window_review_rate"]
        ),
        workload_reduction=float(operating_point["workload_reduction"]),
        true_positive=int(operating_point["true_positive"]),
        false_positive=int(operating_point["false_positive"]),
        true_negative=int(operating_point["true_negative"]),
        false_negative=int(operating_point["false_negative"]),
        validation_curve=validation_curve,
        budget_curve=analyst_budget_curve(
            test_risk,
            holdout.attack_window_test,
            budgets,
        ),
        phase_recall=phase_recall(
            test_risk,
            holdout.attack_window_test,
            selected_threshold,
        ),
        test_risk=test_risk,
    )


def evaluate(
    model: RandomForestClassifier,
    holdout: Holdout,
    budgets: tuple[int, ...] = ANALYST_BUDGETS,
    thresholds: tuple[float, ...] = THRESHOLD_GRID,
    minimum_window_recall: float = MINIMUM_WINDOW_RECALL,
) -> EvalReport:
    validation_risk = model.predict_proba(holdout.X_validation)[:, 1]
    test_risk = model.predict_proba(holdout.X_test)[:, 1]
    return evaluate_risk(
        validation_risk,
        test_risk,
        holdout,
        budgets,
        thresholds,
        minimum_window_recall,
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
    """Return this alert's top non-zero features by model importance."""
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

    fm = build_feature_matrix(
        normalize(Path("data/ait_alerts.json"), Path("data/labels.csv"))
    )
    model, holdout = train(fm.X, fm.attack_window)
    report = evaluate(model, holdout)

    print(f"selected threshold: {report.selected_threshold:.2f}")
    print(f"reviewed alerts: {report.reviewed_alerts}")
    print(f"window recall: {report.window_recall:.1%}")
    print(f"outside-window review rate: {report.outside_window_review_rate:.2%}")
    print(f"workload reduction: {report.workload_reduction:.1%}")
    print("\nAnalyst budgets")
    print(report.budget_curve.to_string(index=False))
    print("\nPer-phase recall")
    print(report.phase_recall.to_string(index=False))

    labels, risks = predict(model, holdout.X_test)
    first_critical = int(np.flatnonzero(labels == "CRITICAL")[0])
    drivers = explain_prediction(
        model,
        holdout.X_test.iloc[first_critical],
        fm.feature_names,
    )
    pretty = ", ".join(f"{name}={value:g}" for name, value, _ in drivers)
    print(f"sample CRITICAL ({risks[first_critical]:.0%} attack risk): {pretty}")
