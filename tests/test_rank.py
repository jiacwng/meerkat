# The score: a rule's past true positive rate, smoothed toward the overall rate.

import tempfile
import unittest
from pathlib import Path

from core.incidents import read_incidents
from core.rank import EMPTY_BASE, SMOOTH, score
from tests.fixtures import ROWS, write_csv


class ScoreTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.incidents = read_incidents(write_csv(tmp / "incidents.csv"))

    def test_score_is_the_smoothed_rule_rate(self):
        scored = score(self.incidents).set_index("IncidentId")
        base = 2 / 4
        self.assertAlmostEqual(scored.loc["201", "score"], (2 + SMOOTH * base) / (2 + SMOOTH))
        self.assertAlmostEqual(scored.loc["200", "score"], (0 + SMOOTH * base) / (2 + SMOOTH))
        self.assertAlmostEqual(scored.loc["202", "score"], base)

    def test_counts_behind_the_score(self):
        scored = score(self.incidents).set_index("IncidentId")
        self.assertEqual(scored.loc["201", "rule_graded"], 2)
        self.assertEqual(scored.loc["201", "rule_true_positives"], 2)
        self.assertEqual(scored.loc["202", "rule_graded"], 0)

    def test_open_incidents_are_ordered_by_score(self):
        scored = score(self.incidents)
        still_open = scored[scored["IncidentGrade"] == ""]
        self.assertEqual(list(still_open["IncidentId"]), ["201", "202", "200"])

    def test_ties_go_to_the_newest_then_the_lowest_id(self):
        rows = list(ROWS[5:])
        rows.append(("1", "150", "a9", "2024-06-05T14:00:00Z", "8", "", "", "", "", "", ""))
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        scored = score(read_incidents(write_csv(tmp / "open.csv", rows)))
        self.assertEqual(set(scored["score"]), {EMPTY_BASE})
        self.assertEqual(list(scored["IncidentId"]), ["150", "202", "201", "200"])

    def test_input_is_left_unchanged(self):
        before = self.incidents.copy()
        score(self.incidents)
        self.assertTrue(before.equals(self.incidents))


if __name__ == "__main__":
    unittest.main()
