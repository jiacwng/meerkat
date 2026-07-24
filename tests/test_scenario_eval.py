import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from core import scenario_eval
from core.classifier import FAMILY_NUMERIC_FEATURES
from core.inventory import Asset, Inventory
from core.scenario_eval import (
    _out_of_fold_families,
    _out_of_fold_reranker_scores,
    _queue_metrics,
    add_window_ids,
    evaluate_scenarios,
    prepare_sessions,
)


def scenario_data(name: str, day: int):
    start = day * 86400.0
    entity = f"10.0.{day}.1"
    frame = pd.DataFrame({
        "timestamp": [start + 1, start + 2, start + 3, start + 4],
        "entity_id": [entity] * 4,
        "detector_source": ["wazuh"] * 4,
        "rule_id": ["positive", "quiet-a", "quiet-b", "quiet-c"],
        "severity": [12.0, 2.0, 2.0, 2.0],
        "native_technique_ids": ["T1110", "", "", ""],
        "alert_category": ["authentication", "", "", ""],
        "rule_groups": ["auth", "", "", ""],
        "entity_in_inventory": [True] * 4,
        "event_label": ["attack", "", "", ""],
        "attack_window": ["phase", "phase", "", ""],
    })
    asset = Asset(f"host-{name}", (entity,), ("servers",))
    inventory = Inventory(name, {entity: asset}, {asset.hostname: entity})
    windows = [(start, start + 2, "phase")]
    return frame, inventory, windows


class ScenarioEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.frames = {}
        self.inventories = {}
        self.windows = {}
        for day, name in enumerate(("alpha", "beta", "gamma"), start=1):
            frame, inventory, windows = scenario_data(name, day)
            self.frames[name] = frame
            self.inventories[name] = inventory
            self.windows[name] = windows

    def test_prepare_sessions_keeps_scenarios_separate(self):
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )

        self.assertEqual(set(sessions), {"alpha", "beta", "gamma"})
        self.assertTrue(
            all(table["session_id"].str.startswith(f"{name}#").all()
                for name, table in sessions.items())
        )

    def test_prepare_sessions_uses_timestamps_for_temporal_overlap(self):
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )
        quiet = sessions["alpha"].loc[
            sessions["alpha"]["rule_id"].eq("quiet-a")
        ].iloc[0]

        self.assertIn("temporal_overlap_windows", sessions["alpha"])
        self.assertEqual(quiet["labelled_windows"], frozenset())
        self.assertEqual(quiet["temporal_overlap_windows"], frozenset({0}))

    def test_window_id_follows_normalized_phase_at_shared_boundary(self):
        frame = pd.DataFrame({
            "timestamp": [10.0],
            "attack_window": ["first"],
        })
        windows = [
            (0.0, 10.0, "first"),
            (10.0, 20.0, "second"),
        ]

        marked = add_window_ids(frame, windows)

        self.assertEqual(int(marked.loc[0, "window_id"]), 0)

    def test_evaluation_uses_unseen_scenarios_and_returns_queue_metrics(self):
        report = evaluate_scenarios(
            self.frames,
            self.inventories,
            self.windows,
            budgets=(1,),
            n_estimators=5,
            seeds=(0,),
        )

        self.assertEqual(set(report.per_fold["scenario"]), set(self.frames))
        self.assertEqual(len(report.per_fold), 3)
        self.assertEqual(list(report.summary["budget"]), [1])
        self.assertEqual(len(report.calibration), 3)
        self.assertEqual(len(report.calibration_summary), 1)
        self.assertIn("pooled_calibrated_brier", report.calibration_summary)
        self.assertTrue((report.per_fold["daily_duplicate_concentration"] == 0).all())
        self.assertIn("strict_windows", report.per_fold)
        self.assertIn("temporal_overlap_windows", report.per_fold)
        self.assertIn("strict_windows_mean", report.summary)
        self.assertIn("temporal_overlap_windows_mean", report.summary)

    def test_family_calibration_scores_each_scenario_out_of_fold(self):
        rows = []
        for scenario in ("alpha", "beta", "gamma"):
            for positive in (False, True):
                row = {
                    feature: float(positive)
                    for feature in FAMILY_NUMERIC_FEATURES
                }
                row["scenario"] = scenario
                row["asset_roles"] = ("servers",)
                row["family_positive"] = positive
                rows.append(row)
        families = pd.DataFrame(rows)
        fitted_on = []

        class FakeReranker:
            def predict(self, test):
                return np.full(len(test), 0.5)

        def fake_fit(train):
            fitted_on.append(set(train["scenario"]))
            return FakeReranker()

        with patch.object(
            scenario_eval,
            "fit_family_reranker",
            side_effect=fake_fit,
        ):
            scored = _out_of_fold_reranker_scores(families)

        self.assertEqual(len(scored), len(families))
        for scenario, training_scenarios in zip(
            ("alpha", "beta", "gamma"),
            fitted_on,
        ):
            self.assertNotIn(scenario, training_scenarios)

    def test_reranker_child_scores_are_out_of_fold(self):
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )
        fitted_on = []

        def fake_score(fold, n_estimators, seed):
            fitted_on.append(
                (fold.test_scenario, set(fold.training_scenarios))
            )
            scored = fold.test.copy()
            scored["ranking_score"] = 0.5
            return scored, None, None

        with patch.object(
            scenario_eval,
            "score_fold",
            side_effect=fake_score,
        ):
            families = _out_of_fold_families(
                sessions,
                tuple(sessions),
                n_estimators=5,
                seed=0,
            )

        self.assertGreater(len(families), 0)
        for test_scenario, training_scenarios in fitted_on:
            self.assertNotIn(test_scenario, training_scenarios)

    def test_evaluation_queues_family_reranker_scores(self):
        queued_scores = []
        real_daily_queue = scenario_eval.daily_queue

        class FakeReranker:
            def predict(self, families):
                return np.full(len(families), 0.123)

        def capture_queue(families, budget):
            queued_scores.append(families["ranking_score"].copy())
            return real_daily_queue(families, budget)

        with (
            patch.object(
                scenario_eval,
                "fit_family_reranker",
                return_value=FakeReranker(),
            ),
            patch.object(
                scenario_eval,
                "daily_queue",
                side_effect=capture_queue,
            ),
        ):
            evaluate_scenarios(
                self.frames,
                self.inventories,
                self.windows,
                budgets=(1,),
                n_estimators=5,
                seeds=(0,),
            )

        self.assertEqual(len(queued_scores), len(self.frames))
        self.assertTrue(
            all(scores.eq(0.123).all() for scores in queued_scores)
        )

    def test_queue_reports_strict_and_temporal_window_coverage_together(self):
        families = pd.DataFrame([{
            "labelled_windows": frozenset({0}),
            "temporal_overlap_windows": frozenset({0, 1}),
            "event_categories": frozenset({"attack"}),
            "day": 0,
            "entity_id": "10.0.0.1",
            "detector_source": "wazuh",
            "rule_id": "100",
            "family_positive": True,
            "labelled_alert_count": 1,
            "alert_count": 2,
            "n_child_sessions": 1,
        }])

        metrics = _queue_metrics(
            families,
            families,
            total_labelled_alerts=1,
            budget=1,
        )

        self.assertIn("strict_windows", metrics)
        self.assertIn("temporal_overlap_windows", metrics)
        self.assertEqual(metrics["strict_windows"], 1)
        self.assertEqual(metrics["temporal_overlap_windows"], 2)


if __name__ == "__main__":
    unittest.main()
