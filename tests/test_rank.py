# The score: the shipped logistic regression over the inputs of core.features.

import math
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import features
from core.incidents import COLUMNS, read_incidents
from core.rank import load_weights, score
from tests.fixtures import DEFENDER, ROWS, WEIGHTS, use_weights, write_csv


def _open_row(name: str, minute: int, account: str) -> dict:
    return dict.fromkeys(COLUMNS, "") | {
        "IncidentId": name, "Timestamp": f"2024-06-10T00:{minute:02d}:00Z",
        "DetectorId": "7", "AccountName": account}


def _logistic(value: float) -> float:
    return 1 / (1 + math.exp(-value))


class ScoreTests(unittest.TestCase):
    def setUp(self):
        use_weights(self)
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.incidents = read_incidents(write_csv(tmp / "incidents.csv"), DEFENDER)

    def test_score_is_the_logistic_of_the_weighted_inputs(self):
        scored = score(self.incidents).set_index("IncidentId")
        # rule 7 has two earlier true positives, rule 9 two earlier other grades
        self.assertAlmostEqual(scored.loc["201", "score"], _logistic(4 * 4.5 / 7 - 2))
        self.assertAlmostEqual(scored.loc["200", "score"], _logistic(4 * 2.5 / 7 - 2))
        self.assertAlmostEqual(scored.loc["202", "score"], 0.5)

    def test_inputs_are_standardised_before_the_coefficients(self):
        weights = dict(WEIGHTS, mean=[0.5] * 8, scale=[2.0] * 8,
                       coefficients=[1.0, -1.0, 0.5, 0.25, 2.0, 1.0, -0.5, 0.3],
                       intercept=0.1)
        use_weights(self, weights)
        scored = score(self.incidents).set_index("IncidentId")
        inputs = features.compute(self.incidents, 0.5).set_index(self.incidents["IncidentId"])
        for incident in ("100", "201", "202"):
            values = inputs.loc[incident, list(features.INPUTS)]
            logit = sum((value - 0.5) / 2.0 * weight
                        for value, weight in zip(values, weights["coefficients"], strict=True))
            self.assertAlmostEqual(scored.loc[incident, "score"], _logistic(logit + 0.1))

    def test_counts_behind_the_score(self):
        scored = score(self.incidents).set_index("IncidentId")
        self.assertEqual(scored.loc["201", "rule_graded"], 2)
        self.assertEqual(scored.loc["201", "rule_true_positives"], 2)
        self.assertEqual(scored.loc["202", "rule_graded"], 0)
        linked = scored.loc["201", list(features.LINKED)].tolist()
        self.assertEqual(linked, [1, 1, 0, 0])
        self.assertEqual(scored.loc["200", "linked"], 0)

    def test_open_incidents_are_ordered_by_score(self):
        scored = score(self.incidents)
        still_open = scored[scored["IncidentGrade"] == ""]
        self.assertEqual(list(still_open["IncidentId"]), ["201", "202", "200"])

    def test_ties_go_to_the_newest_then_the_lowest_id(self):
        rows = list(ROWS[5:])
        rows.append(("1", "150", "a9", "2024-06-05T14:00:00Z", "8", "", "", "", "", "", ""))
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        scored = score(read_incidents(write_csv(tmp / "open.csv", rows), DEFENDER))
        self.assertEqual(set(scored["score"]), {0.5})
        self.assertEqual(list(scored["IncidentId"]), ["150", "202", "201", "200"])

    def test_no_history_leaves_both_other_scores_at_the_score(self):
        scored = score(self.incidents).set_index("IncidentId").loc["202"]
        self.assertEqual(scored["score_without_links"], scored["score"])
        self.assertEqual(scored["score_as_new_rule"], scored["score"])

    def test_linked_true_positives_raise_the_score(self):
        use_weights(self, dict(WEIGHTS, coefficients=[0, 0, 0, 0, 0, 1, 1, 0],
                               intercept=0.0))
        scored = score(self.incidents).set_index("IncidentId").loc["201"]
        self.assertLess(scored["score_without_links"], scored["score"])
        self.assertEqual(scored["score_as_new_rule"], scored["score"])

    def test_a_poor_rule_history_lowers_the_score(self):
        scored = score(self.incidents).set_index("IncidentId").loc["200"]
        self.assertGreater(scored["score_as_new_rule"], scored["score"])
        self.assertEqual(scored["score_without_links"], scored["score"])

    def test_a_good_rule_history_raises_the_score(self):
        scored = score(self.incidents).set_index("IncidentId").loc["201"]
        self.assertLess(scored["score_as_new_rule"], scored["score"])

    def test_scored_as_a_new_rule_ignores_the_rule_history(self):
        use_weights(self, dict(WEIGHTS, coefficients=[0, 4, 0, 0.5, 0, 1, 1, 0]))
        scored = score(self.incidents).set_index("IncidentId")
        self.assertNotEqual(scored.loc["200", "score"], scored.loc["202", "score"])
        self.assertAlmostEqual(scored.loc["200", "score_as_new_rule"],
                               scored.loc["202", "score_as_new_rule"])

    def test_input_is_left_unchanged(self):
        before = self.incidents.copy()
        score(self.incidents)
        self.assertTrue(before.equals(self.incidents))


class ShippedWeightsTests(unittest.TestCase):
    def test_the_weights_file_has_one_value_per_input(self):
        weights = load_weights()
        self.assertEqual(weights["inputs"], list(features.INPUTS))
        self.assertEqual(len(weights["inputs"]), 8)
        for name in ("mean", "scale", "coefficients"):
            self.assertEqual(len(weights[name]), 8)
        self.assertTrue(0 < weights["prior"] < 1)
        self.assertEqual(set(weights["provenance"]),
                         {"dataset", "incidents", "organisations", "time_cut", "date"})

    def test_shipped_scores_are_probabilities(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        scored = score(read_incidents(write_csv(tmp / "incidents.csv"), DEFENDER))
        self.assertTrue(scored["score"].between(0, 1, inclusive="neither").all())

    def test_links_to_open_incidents_change_nothing(self):
        rows = [_open_row(f"u{i}", i, "x") for i in range(3)]
        rows += [_open_row(f"f{i}", 10 + i, "") for i in range(4)]
        linked = score(pd.DataFrame([*rows, _open_row("new", 20, "x")]))
        unlinked = score(pd.DataFrame([*rows, _open_row("new", 20, "y")]))
        linked, unlinked = (frame.set_index("IncidentId").loc["new"]
                            for frame in (linked, unlinked))
        self.assertEqual(linked["linked"], 0)
        self.assertEqual(linked["score"], unlinked["score"])

    def test_an_incident_with_no_history_is_scored_the_same_three_ways(self):
        found = score(pd.DataFrame([_open_row("only", 0, "")])).iloc[0]
        self.assertEqual(found["score"], found["score_without_links"])
        self.assertEqual(found["score"], found["score_as_new_rule"])

    def test_a_rule_history_without_links_changes_only_the_new_rule_score(self):
        past = _open_row("past", 0, "") | {"IncidentGrade": "TruePositive"}
        found = score(pd.DataFrame([past, _open_row("new", 5, "")])).set_index("IncidentId")
        found = found.loc["new"]
        self.assertEqual(found["score_without_links"], found["score"])
        self.assertNotEqual(found["score_as_new_rule"], found["score"])


if __name__ == "__main__":
    unittest.main()
