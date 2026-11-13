# The close level, the audit sample and the pile of each incident, on hand computed cases.

import unittest

import pandas as pd

from core import close, rank, store
from core.rank import EMPTY_BASE
from tests.fixtures import HEADER, is_sampled, plain_row, sampled_ids


def _reviews(*rows: tuple) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=store.GRADE_COLUMNS)


def _tp(name: str, score: float, pile: str = "queue") -> tuple:
    return ("t", name, "TruePositive", "", score, pile)


def _history(*graded: tuple[str, str, str]) -> pd.DataFrame:
    rows = [plain_row(name, rule, grade) for name, rule, grade in graded]
    return rank.score(pd.DataFrame(rows, columns=HEADER))


def _level(*rows: tuple) -> float | None:
    return close.close_level(close.calibration(_history(), _reviews(*rows)))


class LevelTests(unittest.TestCase):
    def test_needed_follows_the_miss_rate(self):
        self.assertEqual(close.needed(), 19)

    def test_fewer_entries_than_needed_give_no_level(self):
        self.assertIsNone(_level())
        self.assertIsNone(_level(*(_tp(str(i), i + 1.0) for i in range(18))))

    def test_the_smallest_count_that_reaches_a_level(self):
        # 19 entries: W = 20, budget 1.0, so the lowest score fits and the next does not
        self.assertEqual(_level(*(_tp(str(i), i + 1.0) for i in range(19))), 1.0)
        # 39 entries: W = 40, budget 2.0, so the two lowest fit
        self.assertEqual(_level(*(_tp(str(i), i + 1.0) for i in range(39))), 2.0)

    def test_tied_scores_count_together(self):
        tied_low = [_tp("a", 0.2), _tp("b", 0.2), *(_tp(str(i), 1 + i / 10) for i in range(17))]
        self.assertIsNone(_level(*tied_low))
        tied_high = [_tp("a", 0.2), *(_tp(str(i), 0.5) for i in range(19))]
        self.assertEqual(_level(*tied_high), 0.2)

    def test_an_audit_entry_counts_ten_times(self):
        queue = [_tp(str(i), i + 1.0) for i in range(25)]
        # W = 25 + 10 + 1 = 36, budget 1.8: the score of 1 fits, the score of 2 does not
        self.assertEqual(_level(*queue, _tp("x", 90.0, "audit")), 1.0)
        # an audit entry below every other one weighs 10 against a budget of 1.8
        self.assertIsNone(_level(*queue, _tp("x", 0.0, "audit")))

    def test_only_the_latest_true_positive_grade_in_queue_or_audit_counts(self):
        rows = [_tp(str(i), i + 1.0) for i in range(19)]
        self.assertEqual(_level(*rows), 1.0)
        self.assertEqual(_level(*rows, _tp("closed", 0.1, "closed")), 1.0)
        regraded = [*rows, ("t", "0", "FalsePositive", "", 1.0, "queue")]
        self.assertIsNone(_level(*regraded))
        self.assertEqual(len(close.calibration(_history(), _reviews(*regraded))), 18)


class ImportedGradeTests(unittest.TestCase):
    def test_leave_one_out_score_on_a_hand_computed_history(self):
        # 7 graded, 3 true positive: without its own grade the base is 2 / 6
        history = _history(("a1", "A", "TruePositive"), ("a2", "A", "TruePositive"),
                           ("a3", "A", "FalsePositive"), ("b1", "B", "TruePositive"),
                           ("c1", "C", "FalsePositive"), ("c2", "C", "FalsePositive"),
                           ("c3", "C", "FalsePositive"))
        entries = close.calibration(history, _reviews())
        # rule A keeps 1 of 2 graded: (1 + 5 / 3) / 7; rule B is left with none: (5 / 3) / 5
        self.assertEqual(len(entries), 3)
        self.assertEqual(set(entries["weight"]), {1.0})
        self.assertAlmostEqual(entries["score"].min(), 1 / 3)
        self.assertAlmostEqual(entries["score"].max(), 8 / 21)
        self.assertEqual(entries["score"].round(6).tolist().count(round(8 / 21, 6)), 2)

    def test_the_only_graded_incident_falls_back_to_the_empty_base(self):
        history = _history(("a1", "A", "TruePositive"), ("a2", "A", ""))
        entries = close.calibration(history, _reviews())
        self.assertEqual(entries["score"].tolist(), [EMPTY_BASE])

    def test_an_incident_graded_in_the_file_and_reviewed_counts_once(self):
        history = _history(("a1", "A", "TruePositive"), ("a2", "A", "TruePositive"))
        entries = close.calibration(history, _reviews(_tp("a1", 0.9)))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries["score"].tolist().count(0.9), 1)

    def test_a_true_positive_in_the_file_later_reviewed_as_false_positive_is_left_out(self):
        history = _history(("a1", "A", "FalsePositive"), ("a2", "A", "TruePositive"))
        reviews = _reviews(("t", "a1", "FalsePositive", "", 0.9, "queue"))
        self.assertEqual(len(close.calibration(history, reviews)), 1)
        history = _history(("a1", "A", "FalsePositive"))
        self.assertEqual(len(close.calibration(history, reviews)), 0)


class PileTests(unittest.TestCase):
    def test_pile_of_an_open_incident(self):
        audit_id = sampled_ids(True, 1)[0]
        closed_id = sampled_ids(False, 1)[0]
        self.assertEqual(close.pile_of(closed_id, 0.1, None), "queue")
        self.assertEqual(close.pile_of(closed_id, 0.5, 0.5), "queue")
        self.assertEqual(close.pile_of(closed_id, 0.7, 0.5), "queue")
        self.assertEqual(close.pile_of(closed_id, 0.4, 0.5), "closed")
        self.assertEqual(close.pile_of(audit_id, 0.4, 0.5), "audit")

    def test_the_sample_is_stable_for_an_id_and_near_the_share(self):
        ids = [f"id{i}" for i in range(2000)]
        first = [close.pile_of(i, 0.0, 1.0) for i in ids]
        self.assertEqual(first, [close.pile_of(i, 0.0, 1.0) for i in ids])
        self.assertEqual([pile == "audit" for pile in first], [is_sampled(i) for i in ids])
        self.assertTrue(140 <= first.count("audit") <= 260)

    def test_place_keeps_the_recorded_pile_of_a_graded_incident(self):
        scored = pd.DataFrame({
            "IncidentId": ["a", "b", "c", "d"],
            "IncidentGrade": ["", "TruePositive", "TruePositive", ""],
            "score": [0.9, 0.1, 0.1, 0.1]})
        reviews = _reviews(("t", "b", "TruePositive", "", 0.8, "audit"))
        piles = close.place(scored, reviews, 0.5)["pile"].tolist()
        expected_open = close.pile_of("d", 0.1, 0.5)
        self.assertEqual(piles, ["queue", "audit", "", expected_open])


if __name__ == "__main__":
    unittest.main()
