"""Evaluate the session-to-family queue on unseen alert scenarios.

Seven companies train the forest, the eighth is held out, and the calibrator is
fitted inside the training seven so the held-out company stays untouched.

Public API:
    load_scenarios(raw_dir, labels, inventory_dir) -> normalized alert tables
    prepare_sessions(frames, inventories, windows) -> session tables
    evaluate_scenarios(frames, inventories, windows) -> CrossScenarioReport
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from core.classifier import fit_calibrator, fit_model, predict_scores
from core.features import (
    SessionFeatureSchema,
    build_session_feature_matrix,
    fit_session_feature_schema,
)
from core.inventory import Inventory, load_inventory
from core.normalize import load_attack_windows, normalize_scenario
from core.sessions import SESSION_GAP_S, build_families, build_sessions
from core.triage_policy import daily_queue


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
DEFAULT_BUDGETS = (5, 10, 25)


@dataclass
class PreparedFold:
    train: pd.DataFrame
    test: pd.DataFrame
    training_scenarios: tuple[str, ...]
    test_scenario: str


@dataclass
class CrossScenarioReport:
    summary: pd.DataFrame
    per_fold: pd.DataFrame
    calibration: pd.DataFrame
    calibration_summary: pd.DataFrame


def load_scenarios(
    raw_dir: Path,
    labels_path: Path,
    inventory_dir: Path,
    scenarios: tuple[str, ...] = SCENARIOS,
    event_csv_dir: Path | None = None,
) -> dict[str, pd.DataFrame]:
    return {
        scenario: normalize_scenario(
            raw_dir,
            labels_path,
            scenario,
            inventory_dir / f"{scenario}.json",
            event_csv_dir,
        )
        for scenario in scenarios
    }


def load_inventories(
    inventory_dir: Path,
    scenarios: tuple[str, ...] = SCENARIOS,
) -> dict[str, Inventory]:
    return {
        scenario: load_inventory(inventory_dir / f"{scenario}.json")
        for scenario in scenarios
    }


def _add_window_ids(
    frame: pd.DataFrame,
    windows: list[tuple[float, float, str]],
) -> pd.DataFrame:
    marked = frame.copy()
    marked["window_id"] = -1
    for window_id, (start, end, attack) in enumerate(windows):
        inside = marked["timestamp"].between(start, end)
        marked.loc[inside & marked["attack_window"].eq(attack), "window_id"] = (
            window_id
        )
    return marked


def prepare_sessions(
    frames: dict[str, pd.DataFrame],
    inventories: dict[str, Inventory],
    windows_by_scenario: dict[str, list[tuple[float, float, str]]],
    gap_s: float = SESSION_GAP_S,
) -> dict[str, pd.DataFrame]:
    # built once and reused, so every fold ranks the same review objects
    return {
        scenario: build_sessions(
            _add_window_ids(frame, windows_by_scenario[scenario]),
            scenario,
            inventories[scenario],
            gap_s,
        )
        for scenario, frame in frames.items()
    }


def prepare_fold(
    session_tables: dict[str, pd.DataFrame],
    test_scenario: str,
) -> PreparedFold:
    training_scenarios = tuple(
        scenario for scenario in session_tables if scenario != test_scenario
    )
    train = pd.concat(
        [session_tables[scenario] for scenario in training_scenarios],
        ignore_index=True,
    )
    return PreparedFold(
        train=train,
        test=session_tables[test_scenario].copy(),
        training_scenarios=training_scenarios,
        test_scenario=test_scenario,
    )


def score_fold(
    fold: PreparedFold,
    n_estimators: int,
    seed: int,
) -> tuple[pd.DataFrame, object, SessionFeatureSchema]:
    # the schema is fitted on training scenarios only, then applied unchanged to
    # the test one, so a rule seen for the first time there stays unseen
    schema = fit_session_feature_schema(fold.train)
    X_train = build_session_feature_matrix(fold.train, schema)
    X_test = build_session_feature_matrix(fold.test, schema)
    model = fit_model(
        X_train,
        fold.train["positive"],
        n_estimators=n_estimators,
        seed=seed,
    )
    scored = fold.test.copy()
    scored["ranking_score"] = predict_scores(model, X_test)
    return scored, model, schema


def _out_of_fold_families(
    session_tables: dict[str, pd.DataFrame],
    training_scenarios: tuple[str, ...],
    n_estimators: int,
    seed: int,
) -> pd.DataFrame:
    parts = []
    training_tables = {
        scenario: session_tables[scenario]
        for scenario in training_scenarios
    }
    for calibration_scenario in training_scenarios:
        fold = prepare_fold(training_tables, calibration_scenario)
        scored, _, _ = score_fold(fold, n_estimators, seed)
        parts.append(build_families(scored))
    return pd.concat(parts, ignore_index=True)


def _ndcg(queue: pd.DataFrame, families: pd.DataFrame, k: int) -> float:
    scores = []
    for day, day_queue in queue.groupby("day", sort=False, observed=True):
        relevance = day_queue["family_positive"].to_numpy(dtype=float)
        discount = np.log2(np.arange(2, len(relevance) + 2))
        dcg = float((relevance / discount).sum())
        available = int(families.loc[
            families["day"].eq(day), "family_positive"
        ].sum())
        ideal = np.ones(min(k, available))
        ideal_dcg = float(
            (ideal / np.log2(np.arange(2, len(ideal) + 2))).sum()
        )
        if ideal_dcg:
            scores.append(dcg / ideal_dcg)
    return float(np.mean(scores)) if scores else float("nan")


def _queue_metrics(
    queue: pd.DataFrame,
    families: pd.DataFrame,
    total_labelled_alerts: int,
    budget: int,
) -> dict[str, float | int]:
    windows = (
        frozenset().union(*queue["labelled_windows"])
        if len(queue)
        else frozenset()
    )
    categories = (
        frozenset().union(*queue["event_categories"])
        if len(queue)
        else frozenset()
    )
    duplicate_rates = []
    distinct_entities = []
    for _, day_queue in queue.groupby("day", sort=False, observed=True):
        unique = day_queue[
            ["entity_id", "detector_source", "rule_id"]
        ].drop_duplicates()
        duplicate_rates.append(1.0 - len(unique) / len(day_queue))
        distinct_entities.append(day_queue["entity_id"].nunique())

    return {
        "budget": budget,
        "queued": len(queue),
        "exact_windows": len(windows),
        "precision": float(queue["family_positive"].mean()),
        "labelled_alert_coverage": float(
            queue["labelled_alert_count"].sum() / total_labelled_alerts
        ),
        "distinct_categories": len(categories),
        "ndcg": _ndcg(queue, families, budget),
        "daily_duplicate_concentration": float(np.mean(duplicate_rates)),
        "daily_distinct_entities": float(np.mean(distinct_entities)),
        "median_family_alerts": float(queue["alert_count"].median()),
        "p90_family_alerts": float(queue["alert_count"].quantile(0.9)),
        "median_child_sessions": float(queue["n_child_sessions"].median()),
        "p90_child_sessions": float(queue["n_child_sessions"].quantile(0.9)),
    }


def _brier(probability: np.ndarray, target: pd.Series) -> float:
    return float(np.mean((probability - target.astype(float).to_numpy()) ** 2))


def _summarize(per_fold: pd.DataFrame) -> pd.DataFrame:
    averages = per_fold.groupby("budget", as_index=False).agg(
        precision=("precision", "mean"),
        labelled_alert_coverage=("labelled_alert_coverage", "mean"),
        distinct_categories=("distinct_categories", "mean"),
        ndcg=("ndcg", "mean"),
        daily_duplicate_concentration=(
            "daily_duplicate_concentration", "mean"
        ),
        daily_distinct_entities=("daily_distinct_entities", "mean"),
        median_family_alerts=("median_family_alerts", "median"),
        p90_family_alerts=("p90_family_alerts", "median"),
        median_child_sessions=("median_child_sessions", "median"),
        p90_child_sessions=("p90_child_sessions", "median"),
    )
    totals = per_fold.groupby(["seed", "budget"], as_index=False)[
        "exact_windows"
    ].sum()
    window_summary = totals.groupby("budget", as_index=False).agg(
        windows_mean=("exact_windows", "mean"),
        windows_min=("exact_windows", "min"),
        windows_max=("exact_windows", "max"),
    )
    return window_summary.merge(averages, on="budget")


def _summarize_calibration(calibration: pd.DataFrame) -> pd.DataFrame:
    total_families = calibration["families"].sum()
    raw = float(
        (calibration["raw_brier"] * calibration["families"]).sum()
        / total_families
    )
    calibrated = float(
        (calibration["calibrated_brier"] * calibration["families"]).sum()
        / total_families
    )
    improved = calibration["calibrated_brier"] < calibration["raw_brier"]
    worsened = calibration["calibrated_brier"] > calibration["raw_brier"]
    return pd.DataFrame([{
        "pooled_raw_brier": raw,
        "pooled_calibrated_brier": calibrated,
        "wins": int(improved.sum()),
        "ties": int((~improved & ~worsened).sum()),
        "losses": int(worsened.sum()),
    }])


def evaluate_scenarios(
    frames: dict[str, pd.DataFrame],
    inventories: dict[str, Inventory],
    windows_by_scenario: dict[str, list[tuple[float, float, str]]],
    budgets: tuple[int, ...] = DEFAULT_BUDGETS,
    n_estimators: int = 300,
    seeds: tuple[int, ...] = (0,),
    gap_s: float = SESSION_GAP_S,
) -> CrossScenarioReport:
    sessions = prepare_sessions(
        frames, inventories, windows_by_scenario, gap_s
    )
    total_labelled = {
        scenario: int(frame["event_label"].fillna("").astype(str).ne("").sum())
        for scenario, frame in frames.items()
    }
    metric_rows = []
    calibration_rows = []

    for seed in seeds:
        for test_scenario in sessions:
            fold = prepare_fold(sessions, test_scenario)
            calibration_families = _out_of_fold_families(
                sessions,
                fold.training_scenarios,
                n_estimators,
                seed,
            )
            calibrator = fit_calibrator(
                calibration_families["ranking_score"].to_numpy(),
                calibration_families["family_positive"].to_numpy(),
            )

            scored, _, _ = score_fold(fold, n_estimators, seed)
            families = build_families(scored)
            families["evidence_probability"] = calibrator.predict(
                families["ranking_score"].to_numpy()
            )
            calibration_rows.append({
                "seed": seed,
                "scenario": test_scenario,
                "families": len(families),
                "raw_brier": _brier(
                    families["ranking_score"].to_numpy(),
                    families["family_positive"],
                ),
                "calibrated_brier": _brier(
                    families["evidence_probability"].to_numpy(),
                    families["family_positive"],
                ),
            })

            for budget in budgets:
                queue = daily_queue(families, budget)
                metric_rows.append({
                    "seed": seed,
                    "scenario": test_scenario,
                    **_queue_metrics(
                        queue,
                        families,
                        total_labelled[test_scenario],
                        budget,
                    ),
                })

    per_fold = pd.DataFrame(metric_rows)
    calibration = pd.DataFrame(calibration_rows)
    return CrossScenarioReport(
        summary=_summarize(per_fold),
        per_fold=per_fold,
        calibration=calibration,
        calibration_summary=_summarize_calibration(calibration),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Meerkat's session-to-family queue"
    )
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    parser.add_argument(
        "--inventory-dir", type=Path, default=Path("data/raw/inventory")
    )
    parser.add_argument(
        "--event-csv-dir", type=Path, default=Path("data/raw/alerts_csv")
    )
    parser.add_argument("--trees", type=int, default=50)
    parser.add_argument("--seeds", default="0")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    seeds = tuple(int(value) for value in args.seeds.split(","))
    frames = load_scenarios(
        args.raw_dir,
        args.labels,
        args.inventory_dir,
        event_csv_dir=args.event_csv_dir,
    )
    inventories = load_inventories(args.inventory_dir)
    windows = {
        scenario: load_attack_windows(args.labels, scenario)
        for scenario in SCENARIOS
    }
    report = evaluate_scenarios(
        frames,
        inventories,
        windows,
        n_estimators=args.trees,
        seeds=seeds,
    )
    print(report.summary.to_string(index=False))
    print("\nCalibration")
    print(report.calibration_summary.to_string(index=False))

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        report.summary.to_csv(args.output_dir / "summary.csv", index=False)
        report.per_fold.to_csv(args.output_dir / "per_fold.csv", index=False)
        report.calibration.to_csv(args.output_dir / "calibration.csv", index=False)
        report.calibration_summary.to_csv(
            args.output_dir / "calibration_summary.csv", index=False
        )


if __name__ == "__main__":
    main()
