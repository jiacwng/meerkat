"""Evaluate Meerkat on complete alert scenarios it did not train on.

Public API:
    load_scenarios(raw_dir, labels_path) -> normalized scenario tables
    prepare_fold(frames, test_scenario)  -> leakage-safe model partitions
    evaluate_scenarios(frames)           -> per-scenario evaluation tables
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from core.classifier import Holdout, evaluate, fit_model
from core.features import bucket_rare_names, build_feature_matrix
from core.normalize import normalize_scenario


SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)


@dataclass
class PreparedFold:
    X_train: pd.DataFrame
    attack_window_train: pd.Series
    holdout: Holdout
    feature_names: list[str]
    event_feature_names: list[str]
    kept_names: frozenset[str]
    event_train: pd.Series | None = None
    event_validation: pd.Series | None = None
    event_test: pd.Series | None = None
    validation_scenarios: pd.Series | None = None
    test_meta: pd.DataFrame | None = None


@dataclass
class CrossScenarioReport:
    summary: pd.DataFrame
    budget_curve: pd.DataFrame
    phase_recall: pd.DataFrame


def load_scenarios(
    raw_dir: Path,
    labels_path: Path,
    scenarios: tuple[str, ...] = SCENARIOS,
    event_csv_dir: Path | None = None,
) -> dict[str, pd.DataFrame]:
    return {
        scenario: normalize_scenario(raw_dir, labels_path, scenario, event_csv_dir)
        for scenario in scenarios
    }


def prepare_fold(
    frames: dict[str, pd.DataFrame],
    test_scenario: str,
    validation_size: float = 0.2,
) -> PreparedFold:
    # Learn alert-name categories and feature columns from training data only,
    # so the test scenario remains completely unseen.
    training_frames = {
        name: frame for name, frame in frames.items() if name != test_scenario
    }
    split_at = {
        name: int(len(frame) * (1 - validation_size))
        for name, frame in training_frames.items()
    }

    training_names = pd.concat([
        frame.iloc[:split_at[name]]["name"]
        for name, frame in training_frames.items()
    ], ignore_index=True)
    _, kept_names = bucket_rare_names(training_names)

    has_events = all("event_label" in f.columns for f in frames.values())

    # Build each scenario separately so rolling context resets at its boundary.
    train_parts = []
    validation_parts = []
    validation_windows = []
    training_windows = []
    event_train_parts = []
    event_validation_parts = []
    validation_scenario_parts = []
    for name, frame in training_frames.items():
        matrix = build_feature_matrix(
            frame,
            kept_names=kept_names,
            include_host_identity=False,
        )
        position = split_at[name]
        train_parts.append(matrix.X.iloc[:position])
        training_windows.append(matrix.attack_window.iloc[:position])
        validation_parts.append(matrix.X.iloc[position:])
        validation_windows.append(matrix.attack_window.iloc[position:])
        if has_events:
            event_train_parts.append(frame["event_label"].iloc[:position])
            event_validation_parts.append(frame["event_label"].iloc[position:])
            validation_scenario_parts.append(
                pd.Series(name, index=range(len(frame) - position))
            )

    X_train = pd.concat(train_parts, ignore_index=True, sort=False).fillna(0.0)
    feature_names = list(X_train.columns)
    event_feature_names = [
        name for name in feature_names
        if name == "urgency_tier"
        or (
            name.startswith("detector_")
            and not name.startswith("detector_alerts_last_")
        )
        or name.startswith("name_")
    ]
    # Validation and test data must use exactly the training columns.
    X_validation = pd.concat(
        validation_parts,
        ignore_index=True,
        sort=False,
    ).reindex(columns=feature_names, fill_value=0.0)

    test_matrix = build_feature_matrix(
        frames[test_scenario],
        kept_names=kept_names,
        include_host_identity=False,
    )
    X_test = test_matrix.X.reindex(columns=feature_names, fill_value=0.0)

    test_frame = frames[test_scenario]
    return PreparedFold(
        X_train=X_train,
        attack_window_train=pd.concat(training_windows, ignore_index=True),
        holdout=Holdout(
            X_validation=X_validation,
            attack_window_validation=pd.concat(
                validation_windows,
                ignore_index=True,
            ),
            X_test=X_test,
            attack_window_test=test_matrix.attack_window.reset_index(drop=True),
        ),
        feature_names=feature_names,
        event_feature_names=event_feature_names,
        kept_names=kept_names,
        event_train=(
            pd.concat(event_train_parts, ignore_index=True) if has_events else None
        ),
        event_validation=(
            pd.concat(event_validation_parts, ignore_index=True)
            if has_events else None
        ),
        event_test=(
            test_frame["event_label"].reset_index(drop=True) if has_events else None
        ),
        validation_scenarios=(
            pd.concat(validation_scenario_parts, ignore_index=True)
            if has_events else None
        ),
        test_meta=test_frame[
            [
                "timestamp",
                "host",
                "detector_source",
                "rule_id",
                "native_technique_ids",
            ]
        ].reset_index(drop=True),
    )


def evaluate_scenarios(
    frames: dict[str, pd.DataFrame],
    n_estimators: int = 300,
    seed: int = 0,
) -> CrossScenarioReport:
    summaries = []
    budgets = []
    phases = []

    for scenario in frames:
        fold = prepare_fold(frames, scenario)
        model = fit_model(
            fold.X_train,
            fold.attack_window_train,
            n_estimators=n_estimators,
            seed=seed,
        )
        report = evaluate(model, fold.holdout)
        summaries.append({
            "scenario": scenario,
            "test_alerts": len(fold.holdout.X_test),
            "selected_threshold": report.selected_threshold,
            "reviewed_alerts": report.reviewed_alerts,
            "window_recall": report.window_recall,
            "outside_window_review_rate": report.outside_window_review_rate,
            "workload_reduction": report.workload_reduction,
        })

        budget = report.budget_curve.copy()
        budget.insert(0, "scenario", scenario)
        budgets.append(budget)

        phase = report.phase_recall.copy()
        phase.insert(0, "scenario", scenario)
        phases.append(phase)

    return CrossScenarioReport(
        summary=pd.DataFrame(summaries),
        budget_curve=pd.concat(budgets, ignore_index=True),
        phase_recall=pd.concat(phases, ignore_index=True),
    )
