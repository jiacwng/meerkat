# Reading an incident CSV: the collapse to one row per incident and every refusal.

import tempfile
import unittest
from pathlib import Path

from core.features import compute
from core.incidents import COLUMNS, SEPARATOR, IncidentError
from tests.fixtures import HEADER, ROWS, read_file, write_csv


class ReadIncidentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.tmp / "incidents.csv"

    def _row(self, **changes) -> tuple:
        row = dict(zip(HEADER, ROWS[5], strict=True))
        row.update(changes)
        return tuple(row.values())

    def test_one_row_per_incident_with_every_column(self):
        incidents = read_file(write_csv(self.path))
        self.assertEqual(list(incidents.columns), list(COLUMNS))
        self.assertEqual(sorted(incidents["IncidentId"]),
                         ["100", "101", "102", "103", "200", "201", "202"])

    def test_incident_takes_rule_and_time_from_its_earliest_row(self):
        rows = (ROWS[1], ROWS[0], *ROWS[2:])
        incidents = read_file(write_csv(self.path, rows)).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["DetectorId"], "7")
        self.assertEqual(first["Timestamp"], "2024-06-01T08:00:00Z")
        self.assertEqual(first["AlertTitle"], "Suspicious sign in")

    def test_techniques_and_links_are_distinct_values_over_all_rows(self):
        incidents = read_file(write_csv(self.path)).set_index("IncidentId")
        first = incidents.loc["100"]
        self.assertEqual(first["MitreTechniques"], "T1078|T1078.004|T1114")
        self.assertEqual(first["IpAddress"], "10.0.0.1|10.0.0.2")
        self.assertEqual(first["AccountName"], "alice")

    def test_absent_optional_columns_read_as_blank(self):
        header = ("IncidentId", "Timestamp", "DetectorId")
        rows = (("5", "2024-06-01T08:00:00Z", "7"),)
        incidents = read_file(write_csv(self.path, rows, header))
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "")
        self.assertEqual(incidents.loc[0, "Url"], "")

    def test_classification_comes_from_any_row_of_the_incident(self):
        rows = (self._row(AlertId="x"), self._row(IncidentGrade="FalsePositive"))
        incidents = read_file(write_csv(self.path, rows))
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "FalsePositive")

    def test_a_separator_inside_a_link_value_does_not_link_incidents(self):
        header = ("IncidentId", "Timestamp", "DetectorId", "IncidentGrade", "Url")
        rows = (("1", "2024-06-01T08:00:00Z", "7", "TruePositive", "http://a/x|shared"),
                ("2", "2024-06-02T08:00:00Z", "7", "", "http://b/y|shared"))
        incidents = read_file(write_csv(self.path, rows, header))
        urls = [set(value.split(SEPARATOR)) for value in incidents["Url"]]
        self.assertEqual(urls[0] & urls[1], set())
        self.assertEqual(urls[0], {"http://a/x%7Cshared"})
        self.assertEqual(compute(incidents, 0.5)["similar"].tolist(), [0, 0])

    def test_classification_is_the_latest_one_and_a_later_blank_does_not_erase_it(self):
        rows = (self._row(AlertId="x", Timestamp="2024-06-01T00:00:00Z",
                          IncidentGrade="FalsePositive"),
                self._row(AlertId="y", Timestamp="2024-06-02T00:00:00Z",
                          IncidentGrade="TruePositive"),
                self._row(AlertId="z", Timestamp="2024-06-03T00:00:00Z", IncidentGrade=""))
        incidents = read_file(write_csv(self.path, rows))
        self.assertEqual(incidents.loc[0, "IncidentGrade"], "TruePositive")

    def test_timestamps_are_normalised_to_utc(self):
        rows = (self._row(Timestamp="2024-06-05T14:00:00+02:00"),)
        incidents = read_file(write_csv(self.path, rows))
        self.assertEqual(incidents.loc[0, "Timestamp"], "2024-06-05T12:00:00Z")

    def test_missing_file(self):
        with self.assertRaisesRegex(IncidentError, "no such file"):
            read_file(self.tmp / "absent.csv")

    def test_directory_instead_of_file(self):
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_file(self.tmp)

    def test_empty_file(self):
        self.path.write_text("")
        with self.assertRaisesRegex(IncidentError, "not a readable CSV"):
            read_file(self.path)

    def test_binary_file(self):
        self.path.write_bytes(bytes(range(256)) * 50)
        with self.assertRaises(IncidentError):
            read_file(self.path)

    def test_header_without_rows(self):
        with self.assertRaisesRegex(IncidentError, "no incident rows"):
            read_file(write_csv(self.path, rows=()))

    def test_two_organisations(self):
        rows = (self._row(), self._row(OrgId="2", IncidentId="300"))
        with self.assertRaisesRegex(IncidentError, "2 organisations"):
            read_file(write_csv(self.path, rows))

    def test_blank_required_value(self):
        for name in ("IncidentId", "Timestamp", "DetectorId"):
            with self.subTest(name), self.assertRaisesRegex(
                    IncidentError, f"1 rows have no {name}"):
                read_file(write_csv(self.path, (self._row(**{name: " "}),)))

    def test_severity_comes_from_the_earliest_row(self):
        header = ("IncidentId", "Timestamp", "DetectorId", "Severity")
        rows = (("1", "2024-06-02T00:00:00Z", "7", "Low"), ("1", "2024-06-01T00:00:00Z", "7", "High"))
        incidents = read_file(write_csv(self.path, rows, header))
        self.assertEqual(list(incidents["Severity"]), ["High"])

    def _refusal(self) -> str:
        with self.assertRaises(IncidentError) as raised:
            read_file(self.path)
        self.assertNotIn("\n", str(raised.exception))
        return str(raised.exception)

    def test_unparseable_timestamp_names_the_first_value_in_one_line(self):
        for value in ("yesterday", "15/06/2024 10:00"):
            with self.subTest(value):
                rows = (self._row(), self._row(IncidentId="300", Timestamp=value),
                        self._row(IncidentId="301", Timestamp="never"))
                write_csv(self.path, rows)
                self.assertEqual(
                    self._refusal(),
                    f"{self.path}: Timestamp '{value}' is not a time meerkat reads, "
                    "like 2024-06-15T10:00:00Z")

    def test_saved_text_drops_fractions_and_converts_offsets_to_utc(self):
        cases = (("2024-06-15T10:00:00Z", "2024-06-15T10:00:00Z"),
                 ("2024-06-15T10:00:00.987Z", "2024-06-15T10:00:00Z"),
                 ("2024-06-15T10:00:00+02:00", "2024-06-15T08:00:00Z"))
        for value, saved in cases:
            with self.subTest(value):
                write_csv(self.path, (self._row(Timestamp=value),))
                self.assertEqual(read_file(self.path).loc[0, "Timestamp"], saved)

    def test_a_utf16_file_is_named_as_utf16(self):
        text = ",".join(HEADER) + "\n" + ",".join(ROWS[5]) + "\n"
        for name, data in (("utf-16", text.encode("utf-16")),):
            with self.subTest(name):
                self.path.write_bytes(data)
                self.assertEqual(self._refusal(), f"{self.path}: is UTF-16, save it as UTF-8")

    def test_a_file_that_is_not_utf8_is_named(self):
        text = ",".join(HEADER) + "\n" + ",".join(ROWS[5]).replace("Mail", "Caf\xe9") + "\n"
        self.path.write_bytes(text.encode("latin-1"))
        self.assertEqual(self._refusal(), f"{self.path}: is not UTF-8, save it as UTF-8")

    def test_a_utf8_byte_order_mark_is_read(self):
        text = ",".join(HEADER) + "\n" + ",".join(ROWS[5]) + "\n"
        self.path.write_bytes(b"\xef\xbb\xbf" + text.encode())
        self.assertEqual(list(read_file(self.path)["IncidentId"]), ["200"])

    def test_a_semicolon_or_tab_header_names_the_separator(self):
        for separator, shown in ((";", "';'"), ("\t", "'\\t'")):
            with self.subTest(shown):
                lines = (separator.join(HEADER), separator.join(ROWS[5]))
                self.path.write_text("\n".join(lines) + "\n")
                self.assertEqual(self._refusal(),
                                 f"{self.path}: columns are separated by {shown}, expected ','")

    def test_header_missing_a_column_names_it(self):
        self.path.write_text("IncidentId,DetectorId\n1,7\n")
        self.assertEqual(self._refusal(), f"{self.path}: missing column Timestamp")
        self.path.write_text("Incident Id,Status\n1,Active\n")
        self.assertIn("missing column Creation time", self._refusal())

    def test_a_header_of_no_known_layout_names_the_three_layouts(self):
        for text in ("a,b\n1,2\n", "Incident name,Status\nx,Active\n"):
            with self.subTest(text):
                self.path.write_text(text)
                self.assertEqual(self._refusal(),
                                 f"{self.path}: not a Defender queue export, a Splunk search "
                                 "export or a file with meerkat's columns IncidentId, Timestamp "
                                 "and DetectorId")

    def test_a_classification_word_outside_meerkats_three_is_refused(self):
        write_csv(self.path, (self._row(IncidentGrade="truePositive"),))
        self.assertEqual(self._refusal(),
                         f"{self.path}: IncidentGrade 'truePositive' is not one of "
                         "TruePositive, BenignPositive, FalsePositive")

    def test_a_blank_organisation_does_not_count_as_one(self):
        rows = (self._row(), self._row(IncidentId="300", OrgId=""),
                self._row(IncidentId="301", OrgId=" "))
        incidents = read_file(write_csv(self.path, rows))
        self.assertEqual(sorted(incidents["IncidentId"]), ["200", "300", "301"])

    def test_many_rows(self):
        rows = [self._row(IncidentId=str(n % 20_000), AlertId=str(n),
                          IpAddress=f"10.0.{n % 250}.{n % 199}")
                for n in range(100_000)]
        incidents = read_file(write_csv(self.path, rows))
        self.assertEqual(len(incidents), 20_000)


if __name__ == "__main__":
    unittest.main()
