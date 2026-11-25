# Reading the Defender queue export and a Splunk search export, picked by their header.

import tempfile
import unittest
from pathlib import Path

from core.exports import DEFENDER_COLUMNS, read
from core.incidents import COLUMNS, IncidentError
from tests.fixtures import write_csv

# a row of a real Defender queue export, from the public repo abenezerbirri/azure-cybersecurity-lab
DEFENDER_ROW = {
    "Incident name": "Windows Account Lockout", "Incident Id": "61", "Priority score": "12",
    "Tags": "-", "Severity": "medium", "Investigation state": "Unsupported alert type",
    "Categories": "CredentialAccess",
    "Impacted assets": "Devices: DC01.cyberlab.local,Accounts: admin01",
    "Active alerts": "1", "Service sources": "Microsoft Sentinel",
    "Detection sources": "Scheduled detection", "Product names": "Microsoft Sentinel",
    "Last update time": "2026-05-04T22:05:25.720Z", "Last activity": "2026-05-04T21:57:42.709Z",
    "Policy name": "Windows Account Lockout", "Data sensitivity": "-", "Status": "Active",
    "Assigned to": "Unassigned", "Classification": "Not set", "Determination": "Not set",
    "Device groups": "-", "Creation time": "2026-05-04T22:05:25.680Z",
    "Workspaces": "law-cyberlab-sentinel", "Cloud Scopes": "",
}
SPLUNK_HEADER = ("_time", "event_id", "rule_id", "rule_name", "rule_title", "security_domain",
                 "urgency", "status_group", "status_label", "disposition_label", "owner", "src",
                 "dest", "user")


def splunk_row(**changes) -> tuple:
    row = dict.fromkeys(SPLUNK_HEADER, "")
    row.update({"_time": "2026-11-24T09:15:02.000+00:00", "event_id": "n1", "rule_id": "n1",
                "rule_name": "Access - Brute Force - Rule", "rule_title": "Brute Force",
                "security_domain": "access", "disposition_label": "Undetermined"})
    row.update(changes)
    return tuple(row.values())


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.tmp / "export.csv"

    def _defender(self, *changes: dict) -> Path:
        rows = [tuple({**DEFENDER_ROW, "Incident Id": str(61 + n), **change}.values())
                for n, change in enumerate(changes or ({},))]
        return write_csv(self.path, rows, tuple(DEFENDER_ROW))

    def _refusal(self) -> str:
        with self.assertRaises(IncidentError) as raised:
            read(self.path)
        return str(raised.exception)

    def test_the_real_defender_row_reads_as_one_open_incident(self):
        incidents, source = read(self._defender())
        self.assertEqual(source, "defender")
        self.assertEqual(list(incidents.columns), list(COLUMNS))
        row = incidents.iloc[0]
        self.assertEqual((row["IncidentId"], row["Timestamp"], row["DetectorId"]),
                         ("61", "2026-05-04T22:05:25Z", "Windows Account Lockout"))
        self.assertEqual((row["IncidentGrade"], row["Category"], row["Severity"]),
                         ("", "CredentialAccess", "medium"))
        self.assertEqual((row["DeviceName"], row["AccountName"]),
                         ("DC01.cyberlab.local", "admin01"))

    def test_a_byte_order_mark_and_crlf_lines_are_read(self):
        text = self._defender().read_text(encoding="utf-8").replace("\n", "\r\n")
        self.path.write_bytes(b"\xef\xbb\xbf" + text.encode())
        self.assertEqual(read(self.path)[0]["IncidentId"].tolist(), ["61"])

    def test_a_classification_counts_only_once_the_incident_is_resolved(self):
        cases = (("Resolved", "True alert", "TruePositive"),
                 ("Resolved", "Benign Positive", "BenignPositive"),
                 ("Resolved", "False alert", "FalsePositive"),
                 ("Resolved", "Not set", "closed"),
                 ("Active", "True alert", ""),
                 ("In Progress", "False alert", ""),
                 ("Awaiting Customer Action", "Not set", ""))
        incidents, _ = read(self._defender(*({"Status": status, "Classification": given}
                                             for status, given, _ in cases)))
        self.assertEqual(incidents["IncidentGrade"].tolist(), [want for *_, want in cases])

    def test_assets_split_into_devices_and_accounts_and_other_groups_are_left_out(self):
        assets = "Devices: pc-1,pc-2,Accounts: alice,bob,Mailboxes: alice@contoso.com"
        row = read(self._defender({"Impacted assets": assets}))[0].iloc[0]
        self.assertEqual((row["DeviceName"], row["AccountName"]), ("pc-1|pc-2", "alice|bob"))

    def test_a_dash_or_an_escaped_dash_reads_as_empty(self):
        row = read(self._defender({"Impacted assets": "'-", "Categories": "-"}))[0].iloc[0]
        self.assertEqual((row["DeviceName"], row["Category"]), ("", ""))

    def test_the_apostrophe_before_a_formula_is_removed(self):
        row = read(self._defender({"Incident name": "'=cmd", "Policy name": "'+rule"}))[0]
        self.assertEqual((row.loc[0, "AlertTitle"], row.loc[0, "DetectorId"]), ("=cmd", "+rule"))

    def test_an_incident_without_a_policy_name_takes_its_incident_name_as_rule(self):
        row = read(self._defender({"Policy name": "-"}))[0].iloc[0]
        self.assertEqual(row["DetectorId"], "Windows Account Lockout")

    def test_a_column_an_analyst_can_add_is_accepted(self):
        header = (*DEFENDER_ROW, "Tenant name")
        write_csv(self.path, ((*DEFENDER_ROW.values(), "contoso"),), header)
        self.assertEqual(len(read(self.path)[0]), 1)
        self.assertIn("Tenant name", DEFENDER_COLUMNS)

    def test_an_unknown_defender_word_or_column_is_refused_with_its_row(self):
        cases = (({"Status": "Closed"}, "Status 'Closed' in row 2 is not one of Active"),
                 ({"Classification": "True positive"},
                  "Classification 'True positive' in row 2 is not one of Not set, True alert"),
                 ({"Impacted assets": "Appareils: pc-1"},
                  "Impacted assets group 'Appareils' in row 2 is not one of Devices"),
                 ({"Impacted assets": "pc-1"}, "does not start with a group"))
        for change, message in cases:
            with self.subTest(message):
                self._defender({}, change)
                self.assertIn(message, self._refusal())
        write_csv(self.path, ((*DEFENDER_ROW.values(), "x"),), (*DEFENDER_ROW, "Score"))
        self.assertEqual(self._refusal(),
                         f"{self.path}: column 'Score' is not a column of the Defender queue "
                         "export")

    def test_a_defender_export_missing_a_column_meerkat_reads_names_it(self):
        header = tuple(name for name in DEFENDER_ROW if name != "Creation time")
        write_csv(self.path, (tuple(DEFENDER_ROW[name] for name in header),), header)
        self.assertEqual(self._refusal(), f"{self.path}: missing column Creation time")

    def test_a_splunk_export_reads_in_both_time_formats(self):
        write_csv(self.path, (splunk_row(),
                              splunk_row(rule_id="n2", _time="2026-11-24 09:16:02.000 GMT")),
                  SPLUNK_HEADER)
        incidents, source = read(self.path)
        self.assertEqual(source, "splunk")
        self.assertEqual(incidents["Timestamp"].tolist(),
                         ["2026-11-24T09:15:02Z", "2026-11-24T09:16:02Z"])

    def test_every_default_disposition_reads(self):
        labels = ("True Positive - Suspicious Activity",
                  "Benign Positive - Suspicious But Expected",
                  "False Positive - Incorrect Analytic Logic",
                  "False Positive - Inaccurate Data", "Undetermined", "Other", "")
        write_csv(self.path, [splunk_row(rule_id=f"n{n}", disposition_label=label)
                              for n, label in enumerate(labels)], SPLUNK_HEADER)
        self.assertEqual(read(self.path)[0]["IncidentGrade"].tolist(),
                         ["TruePositive", "BenignPositive", "FalsePositive", "FalsePositive",
                          "", "", ""])

    def test_a_multi_value_cell_gives_one_entity_per_line(self):
        write_csv(self.path, (splunk_row(user="alice\nbob", src="10.0.0.5", dest="dc01"),
                              splunk_row(rule_id="n2", user="bob")), SPLUNK_HEADER)
        incidents = read(self.path)[0].set_index("IncidentId")
        self.assertEqual(incidents.loc["n1", "AccountName"], "alice|bob")
        self.assertEqual((incidents.loc["n1", "IpAddress"], incidents.loc["n1", "DeviceName"]),
                         ("10.0.0.5", "dc01"))

    def test_a_splunk_search_needs_only_the_three_columns_meerkat_cannot_do_without(self):
        write_csv(self.path, (("n1", "2026-11-24T09:15:02Z", "r"),),
                  ("rule_id", "_time", "rule_name"))
        self.assertEqual(read(self.path)[0]["DetectorId"].tolist(), ["r"])

    def test_an_unknown_splunk_word_column_or_time_is_refused(self):
        write_csv(self.path, (splunk_row(disposition_label="Maybe"),), SPLUNK_HEADER)
        self.assertIn("disposition_label 'Maybe' in row 1 is not one of Undetermined, Other",
                      self._refusal())
        write_csv(self.path, ((*splunk_row(), "x"),), (*SPLUNK_HEADER, "risk_score"))
        self.assertEqual(self._refusal(),
                         f"{self.path}: column 'risk_score' is not a column of a Splunk "
                         "notable event")
        write_csv(self.path, (splunk_row(_time="2026-11-24 10:15:02.000 CET"),), SPLUNK_HEADER)
        self.assertEqual(self._refusal(),
                         f"{self.path}: _time '2026-11-24 10:15:02.000 CET' is not a time "
                         "meerkat reads, like 2024-06-15T10:00:00Z")

    def test_a_splunk_export_with_a_blank_rule_names_the_splunk_column(self):
        write_csv(self.path, (splunk_row(rule_name=""),), SPLUNK_HEADER)
        self.assertEqual(self._refusal(), f"{self.path}: 1 rows have no rule_name")


if __name__ == "__main__":
    unittest.main()
