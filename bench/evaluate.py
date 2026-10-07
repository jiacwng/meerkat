# Leave-one-environment-out evaluation over the AIT-ADS benchmark, and the fit of
# the shipped model bundle. It needs the dataset described in bench/README.md and
# nothing under meerkat/ may import it.

from __future__ import annotations

import argparse
from dataclasses import dataclass
from math import comb
from pathlib import Path

import numpy as np
import pandas as pd

from core.classifier import (
    fit_calibrator,
    fit_family_reranker,
    fit_model,
    predict_scores,
)
from core.drift import build_profile
from core.features import (
    SessionFeatureSchema,
    build_session_feature_matrix,
    fit_session_feature_schema,
)
from core.inventory import Inventory, load_inventory
from core.normalize import load_attack_windows, normalize_scenario
from core.scenario_eval import TriageBundle
from core.sessions import FAMILY_KEY, build_families, build_sessions
from core.triage_policy import queue_order

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
    sign_tests: pd.DataFrame

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


def add_window_ids(
    frame: pd.DataFrame,
    windows: list[tuple[float, float, str]],
) -> pd.DataFrame:
    marked = frame.copy()
    marked["window_id"] = -1
    for window_id, (start, end, attack) in enumerate(windows):
        inside = marked["timestamp"].between(start, end)
        marked.loc[
            inside & marked["attack_window"].eq(attack),
            "window_id",
        ] = window_id
    return marked


def _window_set(window_ids: np.ndarray) -> frozenset[int]:
    return frozenset(int(window_id) for window_id in window_ids if window_id >= 0)


def _with_ground_truth(families: pd.DataFrame, marked: pd.DataFrame) -> pd.DataFrame:
    label = marked["event_label"].fillna("").astype(str).to_numpy()
    window = marked["window_id"].to_numpy()
    is_event = label != ""
    in_event = np.where(is_event, window, -1)
    rows = [np.asarray(indices) for indices in families["alert_rows"]]
    return families.assign(
        labelled_alert_count=[int(is_event[r].sum()) for r in rows],
        labelled_windows=[_window_set(in_event[r]) for r in rows],
        temporal_overlap_windows=[_window_set(window[r]) for r in rows],
        event_categories=[frozenset(label[r][is_event[r]]) for r in rows],
    )


def daily_queue(families: pd.DataFrame, k: int) -> pd.DataFrame:
    return (
        queue_order(families)
        .groupby(["scenario", "day"], sort=False, observed=True)
        .head(k)
        .reset_index(drop=True)
    )


def prepare_sessions(
    frames: dict[str, pd.DataFrame],
    inventories: dict[str, Inventory],
) -> dict[str, pd.DataFrame]:
    return {
        scenario: build_sessions(frame, scenario, inventories[scenario])
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


def _out_of_fold_reranker_scores(
    families: pd.DataFrame,
) -> pd.DataFrame:
    parts = []
    for scenario in families["scenario"].drop_duplicates():
        train = families[~families["scenario"].eq(scenario)]
        test = families[families["scenario"].eq(scenario)].copy()
        reranker = fit_family_reranker(train)
        test["ranking_score"] = reranker.predict(test)
        parts.append(test)
    return pd.concat(parts, ignore_index=True)


# Averaged only over days that hold a positive family, since a day with none has
# no ideal ranking to divide by. That makes the result valid for comparing rankers
# on the same data and invalid across configurations, which cover different days.
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
    strict_windows = (
        frozenset().union(*queue["labelled_windows"])
        if len(queue)
        else frozenset()
    )
    temporal_overlap_windows = (
        frozenset().union(*queue["temporal_overlap_windows"])
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

    day_volume = families.groupby("day", observed=True)["alert_count"].sum()
    day_shares = [
        queued_alerts / day_volume[day]
        for day, queued_alerts
        in queue.groupby("day", observed=True)["alert_count"].sum().items()
    ]

    return {
        "budget": budget,
        "queued": len(queue),
        "strict_windows": len(strict_windows),
        "temporal_overlap_windows": len(temporal_overlap_windows),
        "alerts_in_queue": int(queue["alert_count"].sum()),
        "share_of_day_alerts": float(np.mean(day_shares)) if day_shares else 0.0,
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


def _ranker_signals(families, learned, severity, rng):
    return {
        "family re-ranker": learned,
        "best child session": families["child_score_max"],
        "family size": families["alert_count"],
        "native severity": severity,
        "random": pd.Series(rng.random(len(families)), index=families.index),
    }


def _family_severity(scored, families):
    per_family = scored.groupby(list(FAMILY_KEY), observed=True)["severity_max"].max()
    keys = pd.MultiIndex.from_frame(families[list(FAMILY_KEY)])
    return pd.Series(per_family.reindex(keys).to_numpy(), index=families.index)


# one item per day covers every window present at the cost of the whole day.
# Any grouping or ranking has to beat this row to have bought anything.
def _floor_metrics(
    families: pd.DataFrame,
    total_labelled_alerts: int,
    budget: int,
) -> dict[str, float | int]:
    strict = frozenset().union(*families["labelled_windows"])
    temporal = frozenset().union(*families["temporal_overlap_windows"])
    labelled = int(families["labelled_alert_count"].sum())
    return {
        "budget": budget,
        "queued": int(families["day"].nunique()),
        "strict_windows": len(strict),
        "temporal_overlap_windows": len(temporal),
        "alerts_in_queue": int(families["alert_count"].sum()),
        "share_of_day_alerts": 1.0,
        "precision": float("nan"),
        "labelled_alert_coverage": (
            labelled / total_labelled_alerts if total_labelled_alerts else 0.0
        ),
        "distinct_categories": len(
            frozenset().union(*families["event_categories"])
        ),
        "ndcg": float("nan"),
        "daily_duplicate_concentration": float("nan"),
        "daily_distinct_entities": float("nan"),
        "median_family_alerts": float("nan"),
        "p90_family_alerts": float("nan"),
        "median_child_sessions": float("nan"),
        "p90_child_sessions": float("nan"),
    }


def _exact_sign_p(deltas: list[int]) -> tuple[float, int]:
    nonzero = [delta for delta in deltas if delta != 0]
    n_eff = len(nonzero)
    if n_eff == 0:
        return float("nan"), 0
    positive = sum(1 for delta in nonzero if delta > 0)
    tail = sum(comb(n_eff, i) for i in range(min(positive, n_eff - positive) + 1))
    return min(1.0, 2 * tail / 2 ** n_eff), n_eff


def sign_tests(per_fold: pd.DataFrame, metric: str) -> pd.DataFrame:
    reference = "family re-ranker"
    rows = []
    rankers = [
        ranker for ranker in per_fold["ranker"].unique()
        if ranker != reference and not ranker.startswith("floor")
    ]
    for budget in sorted(per_fold["budget"].unique()):
        for ranker in rankers:
            for seed in sorted(per_fold["seed"].unique()):
                slice_ = per_fold[
                    per_fold["budget"].eq(budget) & per_fold["seed"].eq(seed)
                ]
                paired = slice_.pivot_table(
                    index="scenario", columns="ranker", values=metric
                )
                deltas = (paired[reference] - paired[ranker]).round().astype(int)
                p_value, n_eff = _exact_sign_p(list(deltas))
                rows.append({
                    "metric": metric,
                    "budget": budget,
                    "against": ranker,
                    "seed": seed,
                    "deltas": " ".join(str(delta) for delta in deltas),
                    "n_eff": n_eff,
                    # at five informative folds the smallest two-sided p is
                    # 0.0625, so a p is only worth printing from six up
                    "p": p_value if n_eff >= 6 else float("nan"),
                    "verdict": (
                        f"p={p_value:.3f}" if n_eff >= 6
                        else f"not separable (n_eff={n_eff})"
                    ),
                })
    return pd.DataFrame(rows)


def _summarize(per_fold: pd.DataFrame) -> pd.DataFrame:
    averages = per_fold.groupby(["ranker", "budget"], as_index=False).agg(
        alerts_in_queue=("alerts_in_queue", "mean"),
        share_of_day_alerts=("share_of_day_alerts", "mean"),
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
    totals = per_fold.groupby(["ranker", "seed", "budget"], as_index=False).agg(
        strict_windows=("strict_windows", "sum"),
        temporal_overlap_windows=("temporal_overlap_windows", "sum"),
    )
    window_summary = totals.groupby(["ranker", "budget"], as_index=False).agg(
        strict_windows_mean=("strict_windows", "mean"),
        strict_windows_min=("strict_windows", "min"),
        strict_windows_max=("strict_windows", "max"),
        temporal_overlap_windows_mean=("temporal_overlap_windows", "mean"),
        temporal_overlap_windows_min=("temporal_overlap_windows", "min"),
        temporal_overlap_windows_max=("temporal_overlap_windows", "max"),
    )
    return window_summary.merge(averages, on=["ranker", "budget"])


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
    n_estimators: int = 200,
    seeds: tuple[int, ...] = (0,),
) -> CrossScenarioReport:
    sessions = prepare_sessions(frames, inventories)
    marked = {
        scenario: add_window_ids(frame, windows_by_scenario[scenario])
        for scenario, frame in frames.items()
    }
    total_labelled = {
        scenario: int(frame["event_label"].fillna("").astype(str).ne("").sum())
        for scenario, frame in frames.items()
    }
    metric_rows = []
    calibration_rows = []

    for seed in seeds:
        for test_scenario in sessions:
            fold = prepare_fold(sessions, test_scenario)
            training_families = _out_of_fold_families(
                sessions,
                fold.training_scenarios,
                n_estimators,
                seed,
            )
            calibration_families = _out_of_fold_reranker_scores(
                training_families
            )
            calibrator = fit_calibrator(
                calibration_families["ranking_score"].to_numpy(),
                calibration_families["family_positive"].to_numpy(),
            )
            reranker = fit_family_reranker(training_families)

            scored, _, _ = score_fold(fold, n_estimators, seed)
            families = _with_ground_truth(
                build_families(scored), marked[test_scenario]
            )
            families["ranking_score"] = reranker.predict(families)
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

            rng = np.random.default_rng(seed)
            learned = families["ranking_score"].copy()
            severity = _family_severity(scored, families)
            signals = _ranker_signals(families, learned, severity, rng)
            for ranker, signal in signals.items():
                families["ranking_score"] = signal
                for budget in budgets:
                    queue = daily_queue(families, budget)
                    metric_rows.append({
                        "seed": seed,
                        "scenario": test_scenario,
                        "ranker": ranker,
                        **_queue_metrics(
                            queue,
                            families,
                            total_labelled[test_scenario],
                            budget,
                        ),
                    })
            for budget in budgets:
                metric_rows.append({
                    "seed": seed,
                    "scenario": test_scenario,
                    "ranker": "floor: one item per day",
                    **_floor_metrics(
                        families, total_labelled[test_scenario], budget
                    ),
                })
            families["ranking_score"] = learned

    per_fold = pd.DataFrame(metric_rows)
    calibration = pd.DataFrame(calibration_rows)
    return CrossScenarioReport(
        summary=_summarize(per_fold),
        per_fold=per_fold,
        calibration=calibration,
        calibration_summary=_summarize_calibration(calibration),
        sign_tests=pd.concat(
            [
                sign_tests(per_fold, metric="strict_windows"),
                sign_tests(per_fold, metric="alerts_in_queue"),
            ],
            ignore_index=True,
        ),
    )

def build_bundle(
    session_tables: dict[str, pd.DataFrame],
    n_estimators: int = 200,
    seed: int = 0,
) -> TriageBundle:
    training_scenarios = tuple(session_tables)
    train = pd.concat(
        [session_tables[scenario] for scenario in training_scenarios],
        ignore_index=True,
    )
    schema = fit_session_feature_schema(train)
    X = build_session_feature_matrix(train, schema)
    forest = fit_model(X, train["positive"], n_estimators=n_estimators, seed=seed)
    # the reranker sees the same kind of child scores it will see at inference,
    # so the out-of-fold folds train the same way the shipped forest did
    training_families = _out_of_fold_families(
        session_tables, training_scenarios, n_estimators, seed
    )
    calibration_families = _out_of_fold_reranker_scores(training_families)
    calibrator = fit_calibrator(
        calibration_families["ranking_score"].to_numpy(),
        calibration_families["family_positive"].to_numpy(),
    )
    reranker = fit_family_reranker(training_families)
    return TriageBundle(
        forest=forest,
        schema=schema,
        reranker=reranker,
        calibrator=calibrator,
        training_scenarios=training_scenarios,
        n_estimators=n_estimators,
        seed=seed,
        profile=build_profile(
            X, predict_scores(forest, X), training_families,
            reranker.predict(training_families),
        ),
    )

def parse_budgets(text: str) -> tuple[int, ...]:
    budgets: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-", 1)
            budgets.extend(range(int(low), int(high) + 1))
        else:
            budgets.append(int(part))
    if not budgets or any(budget < 1 for budget in budgets):
        raise ValueError(f"budgets must be positive: {text!r}")
    return tuple(dict.fromkeys(budgets))


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
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--seeds", default="0")
    parser.add_argument(
        "--budgets", default="5,10,25",
        help="comma list or a range like 1-25",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    seeds = tuple(int(value) for value in args.seeds.split(","))
    budgets = parse_budgets(args.budgets)
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
        budgets=budgets,
        n_estimators=args.trees,
        seeds=seeds,
    )
    print(report.summary.to_string(index=False))
    print("\nSign tests against the re-ranker, per seed")
    print(report.sign_tests.to_string(index=False))
    print("\nCalibration")
    print(report.calibration_summary.to_string(index=False))

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        report.summary.to_csv(args.output_dir / "summary.csv", index=False)
        report.per_fold.to_csv(args.output_dir / "per_fold.csv", index=False)
        report.sign_tests.to_csv(args.output_dir / "sign_tests.csv", index=False)
        report.calibration.to_csv(args.output_dir / "calibration.csv", index=False)
        report.calibration_summary.to_csv(
            args.output_dir / "calibration_summary.csv", index=False
        )


if __name__ == "__main__":
    main()
