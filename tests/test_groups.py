# Groups of open incidents: one rule, identical entity values, led by the highest score.

import unittest

import pandas as pd

from core import groups
from core.incidents import COLUMNS


def _scored(*rows: dict) -> pd.DataFrame:
    filler = [{"IncidentId": f"x{number}", "DetectorId": "1"} for number in range(6)]
    return pd.DataFrame([*rows, *filler], columns=list(COLUMNS)).fillna("")


class GroupTests(unittest.TestCase):
    def test_open_incidents_of_one_rule_with_identical_values_follow_the_first(self):
        scored = _scored(
            {"IncidentId": "a", "DetectorId": "7", "Url": "u1", "DeviceName": "h1"},
            {"IncidentId": "b", "DetectorId": "7", "Url": "u1", "DeviceName": "h1"},
            {"IncidentId": "c", "DetectorId": "9", "Url": "u1", "DeviceName": "h1"},
            {"IncidentId": "g", "DetectorId": "7", "Url": "u1", "DeviceName": "h1",
             "IncidentGrade": "TruePositive"})
        lead = groups.leads(scored, set())
        self.assertEqual({name: lead[name] for name in "abc"}, {"a": "a", "b": "a", "c": "c"})
        self.assertNotIn("g", lead)

    def test_a_shared_value_among_other_values_groups_nothing(self):
        scored = _scored(
            {"IncidentId": "a", "DetectorId": "7", "Url": "u1", "DeviceName": "h1"},
            {"IncidentId": "b", "DetectorId": "7", "Url": "u1", "DeviceName": "h2"},
            {"IncidentId": "c", "DetectorId": "7", "Url": "u1|u2", "DeviceName": "h1"},
            {"IncidentId": "d", "DetectorId": "7", "Url": "u1"})
        lead = groups.leads(scored, set())
        self.assertEqual({name: lead[name] for name in "abcd"},
                         {"a": "a", "b": "b", "c": "c", "d": "d"})

    def test_incidents_with_no_entity_value_stay_alone(self):
        scored = _scored(
            {"IncidentId": "a", "DetectorId": "7"},
            {"IncidentId": "b", "DetectorId": "7"})
        lead = groups.leads(scored, set())
        self.assertEqual((lead["a"], lead["b"]), ("a", "b"))

    def test_a_drawn_incident_stays_on_its_own_row(self):
        scored = _scored(
            {"IncidentId": "a", "DetectorId": "7", "Url": "u1"},
            {"IncidentId": "b", "DetectorId": "7", "Url": "u1"},
            {"IncidentId": "c", "DetectorId": "7", "Url": "u1"})
        lead = groups.leads(scored, {"b"})
        self.assertEqual((lead["a"], lead["b"], lead["c"]), ("a", "b", "a"))

    def test_a_value_on_more_than_half_of_the_incidents_groups_nothing(self):
        rows = [{"IncidentId": f"n{number}", "DetectorId": "7", "Url": "everywhere"}
                for number in range(8)]
        lead = groups.leads(_scored(*rows), set())
        self.assertEqual(lead["n3"], "n3")


if __name__ == "__main__":
    unittest.main()
