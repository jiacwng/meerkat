# Reading an incident CSV: the collapse to one row per incident and every refusal.

import tempfile
import unittest
from pathlib import Path

from core.incidents import COLUMNS, IncidentError, read_incidents
from core.mapping import load_mapping
from tests.fixtures import DEFENDER, HEADER, ROWS, write_csv


class ReadIncidentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.tmp / "incidents.csv"

    def _row(self, **changes) -> tuple:
        row = dict(zip(HEADER, ROWS[5], strict=True))
        row.update(changes)
        return tuple(row.values())

    def test_one_row_per_incident_with_every_column(self):
        incidents = read_incidents(write_csv(self.path), DEFENDER)
        self.assertEqual(list(incidents.columns), list(COLUMNS))
        self.assertEqual(sorted(incidents["IncidentId"]),
                         ["100", "101", "102", "103", "200", "201", "202"])

    def test_incident_takes_rule_and_time_from_its_earliest_row(self):
        rows = (ROWS[1], ROWS[0], *ROWS[2:])
        incidents = read_incidents(write_csv(self.path, rows), DEFENDER).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["DetectorId"], "7")
        self.assertEqual(first["Timestamp"], "2024-06-01T08:00:00Z")
        self.assertEqual(first["AlertTitle"], "Suspicious sign in")

    def test_techniques_and_links_are_distinct_values_over_all_rows(self):
        incidents = read_incidents(write_csv(self.path), DEFENDER).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["MitreTechniques"], "T1078|T1078.004|T1114")
        self.assertEqual(first["IpAddress"], "10.0.0.1|10.0.0.2")
        self.assertEqual(first["AccountName"], "alice")

    def test_absent_optional_columns_read_as_blank(self):
        header = ("IncidentId", "Timestamp", "DetectorId")
        rows = (("5", "2024-06-01T08:00:00Z", "7"),)
        incidents = read_incidents(write_csv(self.path, rows, header), DEFENDER)
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "")
        self.assertEqual(incidents.loc[0, "Url"], "")

    def test_grade_comes_from_any_row_of_the_incident(self):
        rows = (self._row(AlertId="x"), self._row(IncidentGrade="FalsePositive"))
        incidents = read_incidents(write_csv(self.path, rows), DEFENDER)
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "FalsePositive")

    def test_timestamps_are_normalised_to_utc(self):
        rows = (self._row(Timestamp="2024-06-05T14:00:00+02:00"),)
        incidents = read_incidents(write_csv(self.path, rows), DEFENDER)
        self.assertEqual(incidents.loc[0, "Timestamp"], "2024-06-05T12:00:00Z")

    def test_missing_file(self):
        with self.assertRaisesRegex(IncidentError, "no such file"):
            read_incidents(self.tmp / "absent.csv", DEFENDER)

    def test_directory_instead_of_file(self):
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_incidents(self.tmp, DEFENDER)

    def test_empty_file(self):
        self.path.write_text("")
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_incidents(self.path, DEFENDER)

    def test_binary_file(self):
        self.path.write_bytes(bytes(range(256)) * 50)
        with self.assertRaises(IncidentError):
            read_incidents(self.path, DEFENDER)

    def test_header_without_rows(self):
        with self.assertRaisesRegex(IncidentError, "no incident rows"):
            read_incidents(write_csv(self.path, rows=()), DEFENDER)

    def test_missing_required_column(self):
        header = ("IncidentId", "Timestamp")
        with self.assertRaisesRegex(IncidentError, "missing column DetectorId"):
            read_incidents(write_csv(self.path, (("5", "2024-06-01"),), header), DEFENDER)

    def test_two_organisations(self):
        rows = (self._row(), self._row(OrgId="2", IncidentId="300"))
        with self.assertRaisesRegex(IncidentError, "2 organisations"):
            read_incidents(write_csv(self.path, rows), DEFENDER)

    def test_blank_required_value(self):
        for name in ("IncidentId", "Timestamp", "DetectorId"):
            with self.subTest(name), self.assertRaisesRegex(
                    IncidentError, f"1 rows have no {name}"):
                read_incidents(write_csv(self.path, (self._row(**{name: " "}),)), DEFENDER)

    def test_unknown_grade(self):
        with self.assertRaisesRegex(IncidentError, "IncidentGrade 'Malicious'"):
            read_incidents(write_csv(self.path, (self._row(IncidentGrade="Malicious"),)), DEFENDER)

    def test_unknown_grade_names_the_source_column_and_accepted_words(self):
        header = ("rule_id", "_time", "rule_name", "disposition_label")
        rows = (("1", "2024-06-01T00:00:00Z", "r", "Maybe"),)
        with self.assertRaisesRegex(
                IncidentError, "disposition_label 'Maybe' is not one of True Positive"):
            read_incidents(write_csv(self.path, rows, header), load_mapping("splunk"))

    def test_a_missing_source_column_is_named(self):
        rows = (("1", "2024-06-01T00:00:00Z"),)
        with self.assertRaisesRegex(IncidentError, "missing column rule_name"):
            read_incidents(write_csv(self.path, rows, ("rule_id", "_time")),
                           load_mapping("splunk"))

    def test_splunk_export_reads_like_guide_names(self):
        header = ("rule_id", "_time", "rule_name", "rule_title", "security_domain",
                  "disposition_label", "src", "dest", "user", "Category")
        labels = ("True Positive - Suspicious Activity",
                  "Benign Positive - Suspicious But Expected",
                  "False Positive - Incorrect Analytic Logic",
                  "False Positive - Inaccurate Data", "Undetermined", "Other")
        rows = [(f"n{i}", "2024-06-01T08:00:00Z", "Brute force", "Title", "access",
                 label, "10.0.0.1", "host1", "alice", "ignored")
                for i, label in enumerate(labels)]
        incidents = read_incidents(write_csv(self.path, rows, header),
                                   load_mapping("splunk")).set_index("IncidentId")
        self.assertEqual(list(incidents.reset_index().columns), list(COLUMNS))
        self.assertEqual(list(incidents["IncidentGrade"]),
                         ["TruePositive", "BenignPositive", "FalsePositive",
                          "FalsePositive", "", ""])
        self.assertEqual(incidents.loc["n0", "DetectorId"], "Brute force")
        self.assertEqual(incidents.loc["n0", "Category"], "access")
        self.assertEqual(incidents.loc["n0", "IpAddress"], "10.0.0.1")
        self.assertEqual(incidents.loc["n0", "DeviceName"], "host1")

    def test_sentinel_export_collapses_rows_per_incident(self):
        header = ("IncidentNumber", "CreatedTime", "RelatedAnalyticRuleIds", "Title",
                  "Classification")
        rows = (("7", "2024-06-01T09:00:00Z", "rule-b", "Later", "Undetermined"),
                ("7", "2024-06-01T08:00:00Z", "rule-a", "Earlier", "TruePositive"),
                ("8", "2024-06-02T08:00:00Z", "rule-a", "Other", "Undetermined"))
        incidents = read_incidents(write_csv(self.path, rows, header),
                                   load_mapping("sentinel")).set_index("IncidentId")
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents.loc["7", "DetectorId"], "rule-a")
        self.assertEqual(incidents.loc["7", "AlertTitle"], "Earlier")
        self.assertEqual(incidents.loc["7", "IncidentGrade"], "TruePositive")
        self.assertEqual(incidents.loc["8", "IncidentGrade"], "")

    def test_a_site_file_can_rename_one_column_only(self):
        site = self.tmp / "site.toml"
        site.write_text('[columns]\nDetectorId = "rule"\n')
        header = tuple("rule" if name == "DetectorId" else name for name in HEADER)
        incidents = read_incidents(write_csv(self.path, ROWS, header),
                                   load_mapping(str(site)))
        self.assertEqual(sorted(incidents["IncidentId"]),
                         ["100", "101", "102", "103", "200", "201", "202"])

    def test_unparseable_timestamp(self):
        for value in ("yesterday", "99999-01-01T00:00:00Z"):
            with self.subTest(value), self.assertRaisesRegex(
                    IncidentError, "Timestamp is not ISO 8601"):
                read_incidents(write_csv(self.path, (self._row(Timestamp=value),)), DEFENDER)

    def test_many_rows(self):
        rows = [self._row(IncidentId=str(n % 20_000), AlertId=str(n),
                          IpAddress=f"10.0.{n % 250}.{n % 199}")
                for n in range(100_000)]
        incidents = read_incidents(write_csv(self.path, rows), DEFENDER)
        self.assertEqual(len(incidents), 20_000)


if __name__ == "__main__":
    unittest.main()
