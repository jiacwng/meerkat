# The ten inputs on hand computed histories: strictly earlier only, placeholders and the cap.

import math
import unittest

import pandas as pd

from core.features import CAP, INPUTS, LINKED, compute
from core.incidents import COLUMNS

PRIOR = 0.2


def _frame(*incidents: dict) -> pd.DataFrame:
    rows = [dict.fromkeys(COLUMNS, "") | {"DetectorId": "7"} | incident
            for incident in incidents]
    return pd.DataFrame(rows, columns=list(COLUMNS))


def _at(minute: int) -> str:
    return f"2024-06-10T{minute // 60:02d}:{minute % 60:02d}:00Z"


def _incident(name: str, minute: int, grade: str = "", **values: str) -> dict:
    return {"IncidentId": name, "Timestamp": _at(minute), "IncidentGrade": grade, **values}


def _smooth(positives: int, total: int) -> float:
    return (positives + 5 * PRIOR) / (total + 5)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.inputs = compute(_frame(
            _incident("open", 0),
            _incident("a", 1, "TruePositive"),
            _incident("b", 2, "FalsePositive"),
            _incident("c", 2),
            _incident("d", 3, "BenignPositive", DetectorId="8"),
            _incident("e", 4),
        ), PRIOR)

    def _row(self, position: int) -> list[float]:
        return self.inputs.iloc[position][list(INPUTS[:4])].tolist()

    def test_the_first_incident_sees_only_the_prior(self):
        self.assertEqual(self._row(0), [PRIOR, PRIOR, 0.0, 0.0])

    def test_an_open_earlier_incident_is_not_counted(self):
        self.assertEqual(self._row(1), [PRIOR, PRIOR, 0.0, 0.0])

    def test_an_incident_at_the_same_time_is_not_counted(self):
        expected = [_smooth(1, 1), _smooth(1, 1), math.log1p(1), math.log1p(1)]
        for position in (2, 3):
            for value, wanted in zip(self._row(position), expected, strict=True):
                self.assertAlmostEqual(value, wanted)

    def test_the_rule_counts_its_own_incidents_and_the_organisation_all(self):
        rule_8 = self._row(4)
        self.assertAlmostEqual(rule_8[0], _smooth(1, 2))
        self.assertAlmostEqual(rule_8[1], PRIOR)
        later = self._row(5)
        self.assertAlmostEqual(later[0], _smooth(1, 3))
        self.assertAlmostEqual(later[1], _smooth(1, 2))
        self.assertAlmostEqual(later[3], math.log1p(2))


class LinkTests(unittest.TestCase):
    def test_links_count_strictly_earlier_incidents_by_grade(self):
        inputs = compute(_frame(
            _incident("a", 0, "TruePositive", AccountName="alice"),
            _incident("b", 1, "FalsePositive", IpAddress="10.0.0.1|10.0.0.2"),
            _incident("c", 2, AccountName="alice"),
            _incident("same", 3, "BenignPositive", DeviceName="pc"),
            _incident("now", 3, AccountName="alice", IpAddress="10.0.0.2", DeviceName="pc"),
            _incident("later", 4, "TruePositive", AccountName="bob"),
            _incident("other", 5, "TruePositive", DeviceName="server"),
        ), PRIOR)
        now = inputs.iloc[4]
        # a and b are earlier and graded; c is open and "same" is not earlier
        self.assertEqual(now[list(LINKED)].tolist(), [2, 1, 0, 1])
        self.assertAlmostEqual(now["log_linked"], math.log1p(2))
        self.assertAlmostEqual(now["log_linked_true_positive"], math.log1p(1))
        self.assertAlmostEqual(now["log_linked_false_positive"], math.log1p(1))
        self.assertAlmostEqual(now["linked_true_positive_rate"], _smooth(1, 2))
        self.assertEqual(inputs["linked"].tolist(), [0, 0, 1, 0, 2, 0, 0])
        self.assertEqual(inputs["has_link"].tolist(), [1.0] * 7)

    def test_a_value_in_more_than_half_the_incidents_is_ignored(self):
        common = [_incident(str(i), i, "TruePositive", Url="x") for i in range(3)]
        inputs = compute(_frame(*common, _incident("3", 3)), PRIOR)
        self.assertEqual(inputs["linked"].tolist(), [0, 0, 0, 0])
        self.assertEqual(inputs["has_link"].tolist(), [0.0] * 4)
        half = [_incident(str(i), i, "TruePositive", Url="x") for i in range(2)]
        inputs = compute(_frame(*half, _incident("2", 2), _incident("3", 3)), PRIOR)
        self.assertEqual(inputs["linked"].tolist(), [0, 1, 0, 0])
        self.assertEqual(inputs["has_link"].tolist(), [1.0, 1.0, 0.0, 0.0])

    def test_each_value_counts_only_the_most_recent_earlier_incidents(self):
        sharing = [_incident(f"s{i}", i, "FalsePositive", Sha256="h", Url="u")
                   for i in range(CAP + 2)]
        sharing[0]["IncidentGrade"] = sharing[1]["IncidentGrade"] = "TruePositive"
        filler = [_incident(f"f{i}", 100 + i) for i in range(CAP + 5)]
        newest = _incident("new", 200, Sha256="h", Url="u")
        inputs = compute(_frame(*sharing, *filler, newest), PRIOR)
        # the two oldest are past the cap on both values, so their grades never count
        self.assertEqual(inputs.iloc[-1][list(LINKED)].tolist(), [CAP, 0, 0, CAP])
        self.assertEqual(inputs.iloc[CAP + 1]["linked"], CAP)

    def test_a_frame_without_link_values(self):
        inputs = compute(_frame(_incident("a", 0, "TruePositive"), _incident("b", 1)), PRIOR)
        self.assertEqual(inputs["linked"].tolist(), [0, 0])
        self.assertEqual(inputs["linked_true_positive_rate"].tolist(), [PRIOR, PRIOR])
        self.assertEqual(inputs["has_link"].tolist(), [0.0, 0.0])

    def test_inputs_keep_the_index_and_order_of_the_frame(self):
        frame = _frame(_incident("late", 5, "TruePositive", AccountName="a"),
                       _incident("early", 1, "TruePositive", AccountName="a"),
                       _incident("x", 2), _incident("y", 3))
        frame.index = [10, 20, 30, 40]
        inputs = compute(frame, PRIOR)
        self.assertEqual(list(inputs.index), [10, 20, 30, 40])
        self.assertEqual(inputs["linked"].tolist(), [1, 0, 0, 0])
        self.assertEqual(list(inputs.columns), [*INPUTS, *LINKED])


if __name__ == "__main__":
    unittest.main()
