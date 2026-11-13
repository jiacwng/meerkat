# Reading an incident CSV: the collapse to one row per incident and every refusal.

import tempfile
import unittest
from pathlib import Path

from core.incidents import COLUMNS, IncidentError, read_incidents
from tests.fixtures import HEADER, ROWS, write_csv


class ReadIncidentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.tmp / "incidents.csv"

    def _row(self, **changes) -> tuple:
        row = dict(zip(HEADER, ROWS[5], strict=True))
        row.update(changes)
        return tuple(row.values())

    def test_one_row_per_incident_with_every_column(self):
        incidents = read_incidents(write_csv(self.path))
        self.assertEqual(list(incidents.columns), list(COLUMNS))
        self.assertEqual(sorted(incidents["IncidentId"]),
                         ["100", "101", "102", "103", "200", "201", "202"])

    def test_incident_takes_rule_and_time_from_its_earliest_row(self):
        rows = (ROWS[1], ROWS[0], *ROWS[2:])
        incidents = read_incidents(write_csv(self.path, rows)).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["DetectorId"], "7")
        self.assertEqual(first["Timestamp"], "2024-06-01T08:00:00Z")
        self.assertEqual(first["AlertTitle"], "Suspicious sign in")

    def test_techniques_and_links_are_distinct_values_over_all_rows(self):
        incidents = read_incidents(write_csv(self.path)).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["MitreTechniques"], "T1078|T1078.004|T1114")
        self.assertEqual(first["IpAddress"], "10.0.0.1|10.0.0.2")
        self.assertEqual(first["AccountName"], "alice")

    def test_absent_optional_columns_read_as_blank(self):
        header = ("IncidentId", "Timestamp", "DetectorId")
        rows = (("5", "2024-06-01T08:00:00Z", "7"),)
        incidents = read_incidents(write_csv(self.path, rows, header))
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "")
        self.assertEqual(incidents.loc[0, "Url"], "")

    def test_grade_comes_from_any_row_of_the_incident(self):
        rows = (self._row(AlertId="x"), self._row(IncidentGrade="FalsePositive"))
        incidents = read_incidents(write_csv(self.path, rows))
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "FalsePositive")

    def test_timestamps_are_normalised_to_utc(self):
        rows = (self._row(Timestamp="2024-06-05T14:00:00+02:00"),)
        incidents = read_incidents(write_csv(self.path, rows))
        self.assertEqual(incidents.loc[0, "Timestamp"], "2024-06-05T12:00:00Z")

    def test_missing_file(self):
        with self.assertRaisesRegex(IncidentError, "no such file"):
            read_incidents(self.tmp / "absent.csv")

    def test_directory_instead_of_file(self):
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_incidents(self.tmp)

    def test_empty_file(self):
        self.path.write_text("")
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_incidents(self.path)

    def test_binary_file(self):
        self.path.write_bytes(bytes(range(256)) * 50)
        with self.assertRaises(IncidentError):
            read_incidents(self.path)

    def test_header_without_rows(self):
        with self.assertRaisesRegex(IncidentError, "no incident rows"):
            read_incidents(write_csv(self.path, rows=()))

    def test_missing_required_column(self):
        header = ("IncidentId", "Timestamp")
        with self.assertRaisesRegex(IncidentError, "missing column DetectorId"):
            read_incidents(write_csv(self.path, (("5", "2024-06-01"),), header))

    def test_two_organisations(self):
        rows = (self._row(), self._row(OrgId="2", IncidentId="300"))
        with self.assertRaisesRegex(IncidentError, "2 organisations"):
            read_incidents(write_csv(self.path, rows))

    def test_blank_required_value(self):
        for name in ("IncidentId", "Timestamp", "DetectorId"):
            with self.subTest(name), self.assertRaisesRegex(
                    IncidentError, f"1 rows have no {name}"):
                read_incidents(write_csv(self.path, (self._row(**{name: " "}),)))

    def test_unknown_grade(self):
        with self.assertRaisesRegex(IncidentError, "IncidentGrade 'Malicious'"):
            read_incidents(write_csv(self.path, (self._row(IncidentGrade="Malicious"),)))

    def test_unparseable_timestamp(self):
        for value in ("yesterday", "99999-01-01T00:00:00Z"):
            with self.subTest(value), self.assertRaisesRegex(
                    IncidentError, "Timestamp is not ISO 8601"):
                read_incidents(write_csv(self.path, (self._row(Timestamp=value),)))

    def test_many_rows(self):
        rows = [self._row(IncidentId=str(n % 20_000), AlertId=str(n),
                          IpAddress=f"10.0.{n % 250}.{n % 199}")
                for n in range(100_000)]
        incidents = read_incidents(write_csv(self.path, rows))
        self.assertEqual(len(incidents), 20_000)


if __name__ == "__main__":
    unittest.main()
