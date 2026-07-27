# the cost columns and floors the results table carries beside every coverage
# number, and the exact test that decides whether a ranker separates at all

from __future__ import annotations

import unittest

import pandas as pd

from bench.evaluate import (
    _exact_sign_p,
    _floor_metrics,
    _queue_metrics,
    sign_tests,
)


def family(day, entity, alerts, positive, windows=(), labelled_alerts=0):
    return {
        "day": day,
        "entity_id": entity,
        "detector_source": "wazuh",
        "rule_id": "r1",
        "alert_count": alerts,
        "family_positive": positive,
        "labelled_alert_count": labelled_alerts,
        "labelled_windows": frozenset(windows),
        "temporal_overlap_windows": frozenset(windows),
        "event_categories": frozenset(),
        "n_child_sessions": 1,
    }


def two_day_families():
    # day 1 holds 100 alerts in two families, day 2 holds 50 in two more
    return pd.DataFrame([
        family(1, "a", 90, True, windows={"scan"}, labelled_alerts=3),
        family(1, "b", 10, False),
        family(2, "c", 30, True, windows={"exfil"}, labelled_alerts=2),
        family(2, "d", 20, False),
    ])


class ExactSignTests(unittest.TestCase):
    def test_three_wins_cannot_reach_significance(self):
        # 2 / 2^3: the smallest p three informative folds can produce
        p, n_eff = _exact_sign_p([1, 1, 1])
        self.assertEqual(n_eff, 3)
        self.assertAlmostEqual(p, 0.25)

    def test_eight_wins_is_the_floor_of_eight_folds(self):
        p, n_eff = _exact_sign_p([1] * 8)
        self.assertEqual(n_eff, 8)
        self.assertAlmostEqual(p, 2 / 256)

    def test_ties_drop_out(self):
        p, n_eff = _exact_sign_p([0, 0, 0])
        self.assertEqual(n_eff, 0)
        self.assertNotEqual(p, p)  # nan

    def test_a_split_verdict_caps_at_one(self):
        p, n_eff = _exact_sign_p([1, -1])
        self.assertEqual(n_eff, 2)
        self.assertEqual(p, 1.0)


class CostColumnTests(unittest.TestCase):
    def test_the_queue_carries_its_alert_cost(self):
        families = two_day_families()
        # the biggest family of each day, which is what a size ranker buys
        queue = families.iloc[[0, 2]]
        metrics = _queue_metrics(queue, families, total_labelled_alerts=5, budget=1)
        self.assertEqual(metrics["alerts_in_queue"], 120)
        # day 1 reads 90 of 100, day 2 reads 30 of 50
        self.assertAlmostEqual(metrics["share_of_day_alerts"], (0.9 + 0.6) / 2)

    def test_the_floor_reads_everything_and_covers_everything(self):
        families = two_day_families()
        floor = _floor_metrics(families, total_labelled_alerts=5, budget=5)
        self.assertEqual(floor["queued"], 2)
        self.assertEqual(floor["strict_windows"], 2)
        self.assertEqual(floor["alerts_in_queue"], 150)
        self.assertEqual(floor["share_of_day_alerts"], 1.0)
        self.assertEqual(floor["labelled_alert_coverage"], 1.0)


class SignTestTableTests(unittest.TestCase):
    def rows(self, ranker, values, seed=51):
        return [
            {"seed": seed, "scenario": f"env{i}", "ranker": ranker,
             "budget": 5, "strict_windows": value}
            for i, value in enumerate(values)
        ]

    def test_a_clean_sweep_is_significant_and_a_near_tie_is_not(self):
        per_fold = pd.DataFrame(
            self.rows("family re-ranker", [5, 5, 5, 5, 5, 5, 5, 5])
            + self.rows("random", [4, 4, 4, 4, 4, 4, 4, 4])
            + self.rows("best child session", [5, 5, 5, 5, 5, 4, 4, 4])
            + self.rows("floor: one item per day", [9] * 8)
        )
        table = sign_tests(per_fold)
        against = dict(zip(table["against"], table["verdict"]))
        self.assertEqual(against["random"], "p=0.008")
        self.assertEqual(against["best child session"], "not separable (n_eff=3)")
        # the floor is a different unit, so it is never tested as a ranker
        self.assertNotIn("floor: one item per day", against)


if __name__ == "__main__":
    unittest.main()
