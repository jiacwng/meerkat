# Reading Defender incidents from the JSON that Microsoft Graph answers.

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from core import defender, features
from core.incidents import IncidentError
from meerkat.cli import main
from tests.fixtures import graph_alert, graph_incident, use_weights

EXAMPLE = Path(__file__).parent.parent / "examples" / "incidents.csv"
WORDS = {name: word for word, name in defender.CLASSIFICATION.items() if name}
ENTITIES = {
    "DeviceId": ("deviceEvidence", "mdeDeviceId", None),
    "DeviceName": ("deviceEvidence", "deviceDnsName", None),
    "AccountObjectId": ("userEvidence", "userAccount", "azureAdUserId"),
    "AccountSid": ("userEvidence", "userAccount", "userSid"),
    "AccountUpn": ("userEvidence", "userAccount", "userPrincipalName"),
    "AccountName": ("userEvidence", "userAccount", "accountName"),
    "IpAddress": ("ipEvidence", "ipAddress", None),
    "Sha256": ("fileEvidence", "fileDetails", "sha256"),
    "Url": ("urlEvidence", "url", None),
}


def as_graph(path: Path) -> list[dict]:
    found: dict[str, dict] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            incident = found.setdefault(row["IncidentId"], graph_incident(
                row["IncidentId"], alerts=[], severity=None))
            if row["IncidentGrade"]:
                incident["classification"] = WORDS[row["IncidentGrade"]]
                incident["status"] = "resolved"
            evidence = []
            for column, (kind, key, inner) in ENTITIES.items():
                if row[column]:
                    value = row[column] if inner is None else {inner: row[column]}
                    evidence.append({"@odata.type": f"#microsoft.graph.security.{kind}",
                                     key: value})
            incident["alerts"].append(graph_alert(
                row["DetectorId"], row["Timestamp"], title=row["AlertTitle"],
                categories=[row["Category"]] if row["Category"] else [],
                mitreTechniques=[name for name in row["MitreTechniques"].split(";") if name],
                evidence=evidence))
    return list(found.values())


class DefenderTests(unittest.TestCase):
    def setUp(self):
        use_weights(self)
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.file = self.tmp / "incidents.json"

    def _write(self, answer, encoding: str = "utf-8") -> Path:
        self.file.write_text(json.dumps(answer), encoding=encoding)
        return self.file

    def _read(self, *incidents: dict):
        return defender.read_graph(self._write({"value": list(incidents)})).set_index("IncidentId")

    def _refusal(self, answer) -> str:
        with self.assertRaises(IncidentError) as raised:
            defender.read_graph(self._write(answer))
        message = str(raised.exception)
        self.assertNotIn("\n", message)
        return message

    def _run(self, *argv: str, runs_dir: Path | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                main([*argv, "--runs-dir", str(runs_dir or self.runs_dir)])
            except SystemExit as stop:
                code = stop.code
        return code, out.getvalue(), err.getvalue()

    def _ranked(self, runs_dir: Path) -> dict:
        rows = json.loads(self._run("queue", "--json", runs_dir=runs_dir)[1])["queue"]
        return {row["IncidentId"]: (row["score"], row["placement"], row["flag"], row["members"])
                for row in rows}

    def test_a_json_file_ranks_the_example_as_its_csv_does(self):
        found = as_graph(EXAMPLE)
        self._write([{"@odata.context": "https://graph.microsoft.com/v1.0/$metadata"
                                        "#security/incidents(alerts())",
                      "value": found[:150],
                      "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/incidents"
                                         "?$expand=alerts&$skip=150"},
                     {"value": found[150:]}])
        from_csv = self.tmp / "csv"
        for runs_dir in (self.runs_dir, from_csv):
            self._run("config", "budget", "10", runs_dir=runs_dir)
        self._run("queue", str(EXAMPLE), runs_dir=from_csv)
        code, _, err = self._run("queue", str(self.file))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(self._ranked(self.runs_dir)), 46)
        self.assertEqual(self._ranked(self.runs_dir), self._ranked(from_csv))
        record = json.loads(self._run("details", "138267", "--json")[1])
        self.assertEqual(record["IncidentUrl"], "https://security.microsoft.com/incidents/138267")

    def test_each_column_comes_from_its_graph_property(self):
        evidence = [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence",
             "mdeDeviceId": "f3b0", "deviceDnsName": "pc-1.contoso.com"},
            {"@odata.type": "#microsoft.graph.security.userEvidence",
             "userAccount": {"azureAdUserId": "e1", "userSid": "S-1-5-21-1",
                             "userPrincipalName": "Bob@Contoso.com", "accountName": "BOB"}},
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "10.0.0.5"},
            {"@odata.type": "#microsoft.graph.security.fileEvidence",
             "fileDetails": {"sha256": "ab" * 32, "fileName": "a.exe"}},
            {"@odata.type": "#microsoft.graph.security.urlEvidence", "url": "https://x.example/a"},
            {"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "a@b"},
        ]
        first = graph_alert("7", "2024-06-01T08:00:00.9999999Z", title="First",
                            categories=["CredentialAccess", "LateralMovement"],
                            mitreTechniques=["T1110", "T1021"], evidence=evidence)
        later = graph_alert("9", "2024-06-01T09:00:00Z", title="Later",
                            mitreTechniques=["T1110"])
        row = self._read(graph_incident("1", alerts=[later, first], severity="high")).loc["1"]
        self.assertEqual((row["Timestamp"], row["DetectorId"], row["AlertTitle"]),
                         ("2024-06-01T08:00:00Z", "7", "First"))
        self.assertEqual((row["Category"], row["Severity"], row["MitreTechniques"]),
                         ("CredentialAccess, LateralMovement", "high", "T1021|T1110"))
        self.assertEqual(row["IncidentUrl"], "https://security.microsoft.com/incidents/1")
        self.assertEqual(
            {name: row[name] for name in ENTITIES},
            {"DeviceId": "f3b0", "DeviceName": "pc-1", "AccountObjectId": "e1",
             "AccountSid": "S-1-5-21-1", "AccountUpn": "bob@contoso.com",
             "AccountName": "alice|bob", "IpAddress": "10.0.0.5", "Sha256": "ab" * 32,
             "Url": "https://x.example/a"})

    def test_a_host_and_an_account_link_across_case_and_dns_domain(self):
        device = "#microsoft.graph.security.deviceEvidence"
        user = "#microsoft.graph.security.userEvidence"
        pairs = {
            "DeviceName dc01": ({"@odata.type": device, "hostName": "DC01",
                                 "deviceDnsName": "DC01.contoso.local"},
                                {"@odata.type": device, "deviceDnsName": "dc01.contoso.local"}),
            "DeviceId 4a1b": ({"@odata.type": device, "mdeDeviceId": "4a1b"},
                              {"@odata.type": device, "mdeDeviceId": "4a1b", "hostName": "pc-9"}),
            "AccountUpn alice@contoso.com": (
                {"@odata.type": user, "userAccount": {"userPrincipalName": "Alice@Contoso.com"}},
                {"@odata.type": user, "userAccount": {"userPrincipalName": "alice@contoso.com"}}),
            "AccountName alice": ({"@odata.type": user, "userAccount": {"accountName": "ALICE"}},
                                  {"@odata.type": user, "userAccount": {"accountName": "alice"}}),
            "AccountSid S-1-5-21-7": (
                {"@odata.type": user, "userAccount": {"userSid": "S-1-5-21-7"}},
                {"@odata.type": user, "userAccount": {"userSid": "S-1-5-21-7",
                                                      "accountName": "other"}}),
        }
        for shared, (earlier, later) in pairs.items():
            with self.subTest(shared):
                table = self._read(
                    graph_incident("1", "resolved", "truePositive",
                                   alerts=[graph_alert(evidence=[earlier])]),
                    graph_incident("2", alerts=[graph_alert(time="2024-06-02T08:00:00Z",
                                                            evidence=[later])]),
                    *(graph_incident(number, alerts=[graph_alert(evidence=[])])
                      for number in ("3", "4")))
                similar = features.similar_to(table.reset_index(), "2")
                self.assertEqual(similar["IncidentId"].tolist(), ["1"])
                column, value = shared.split(" ")
                self.assertEqual(table.loc["2", column], value)

    def test_an_alert_without_a_detector_id_still_brings_its_evidence(self):
        unnamed = graph_alert(None, "2024-06-01T07:30:00Z", evidence=[
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "10.0.0.9"}])
        row = self._read(graph_incident("1", alerts=[unnamed, graph_alert("7")])).loc["1"]
        self.assertEqual((row["DetectorId"], row["Timestamp"], row["IpAddress"]),
                         ("7", "2024-06-01T07:30:00Z", "10.0.0.9"))

    def test_an_open_incident_without_a_detector_id_is_refused_by_its_id(self):
        for alerts in ([graph_alert(None)], [graph_alert("")], []):
            with self.subTest(alerts):
                self.assertEqual(
                    self._refusal({"value": [graph_incident("1"), graph_incident("2", alerts=alerts)]}),
                    f"{self.file}: incident '2' is open or classified and none of its alerts "
                    "has a detectorId")
        table = self._read(graph_incident("1", "redirected", alerts=[]),
                           graph_incident("2", "resolved", alerts=[graph_alert(None)]))
        self.assertEqual(table["IncidentGrade"].to_dict(), {"1": "closed", "2": "closed"})
        self.assertEqual(table.loc["1", "Timestamp"], "2024-06-01T07:00:00Z")

    def test_a_classification_counts_as_soon_as_it_is_set_whatever_the_status(self):
        cases = (("resolved", "truePositive", "TruePositive"),
                 ("resolved", "informationalExpectedActivity", "BenignPositive"),
                 ("resolved", "falsePositive", "FalsePositive"),
                 ("active", "truePositive", "TruePositive"),
                 ("inProgress", "falsePositive", "FalsePositive"),
                 ("awaitingAction", "informationalExpectedActivity", "BenignPositive"),
                 ("redirected", "truePositive", "TruePositive"),
                 ("resolved", "unknown", "closed"),
                 ("resolved", None, "closed"),
                 ("redirected", "unknown", "closed"),
                 ("active", "unknown", ""),
                 ("inProgress", "unknown", ""),
                 ("awaitingAction", "unknownFutureValue", ""),
                 ("unknownFutureValue", None, ""))
        table = self._read(*(graph_incident(f"i{n}", status, given)
                             for n, (status, given, _) in enumerate(cases)))
        self.assertEqual(table["IncidentGrade"].tolist(), [want for *_, want in cases])

    def test_an_incident_classified_while_still_active_leaves_the_queue_and_counts(self):
        later = graph_incident("2", alerts=[graph_alert(time="2024-06-02T08:00:00Z")])
        self._run("queue", str(self._write({"value": [graph_incident("1"), later]})))
        self._run("queue", str(self._write({"value": [graph_incident("1", "active",
                                                                     "truePositive")]})))
        self.assertEqual(list(self._ranked(self.runs_dir)), ["2"])
        record = json.loads(self._run("details", "2", "--json")[1])
        self.assertEqual((record["rule_true_positives"], record["rule_classified"]), (1, 1))

    def test_a_later_file_brings_the_classification_and_closes_incidents(self):
        monday = [graph_incident(str(number)) for number in range(1, 5)]
        tuesday = [graph_incident("2", "resolved", "truePositive"),
                   graph_incident("3", "resolved", "unknown"),
                   graph_incident("4", "redirected", alerts=[], redirectIncidentId="1")]
        self._run("queue", str(self._write({"value": monday})))
        self.assertEqual(sorted(self._ranked(self.runs_dir)), ["1", "2", "3", "4"])
        self._run("queue", str(self._write({"value": tuesday})))
        self.assertEqual(sorted(self._ranked(self.runs_dir)), ["1"])
        record = json.loads(self._run("details", "2", "--json")[1])
        self.assertEqual((record["IncidentGrade"], record["AccountName"]),
                         ("TruePositive", ["alice"]))
        for gone in ("3", "4"):
            self.assertEqual(self._run("details", gone)[0], 1)

    def test_an_unknown_status_or_classification_word_is_refused_with_the_word(self):
        message = self._refusal({"value": [graph_incident("1", "closed")]})
        self.assertIn("incident '1': status 'closed' is not one of active, resolved", message)
        message = self._refusal({"value": [graph_incident("1", "resolved", "TruePositive")]})
        self.assertIn("incident '1': classification 'TruePositive' is not one of unknown",
                      message)

    def test_an_unsafe_link_is_dropped_and_utf_16_reads(self):
        found = [graph_incident("1", incidentWebUrl="javascript:alert(1)"), graph_incident("2")]
        for encoding in ("utf-8", "utf-8-sig", "utf-16"):
            with self.subTest(encoding):
                table = defender.read_graph(self._write({"value": found}, encoding))
                self.assertEqual(table.set_index("IncidentId")["IncidentUrl"].to_dict(),
                                 {"1": "", "2": "https://security.microsoft.com/incidents/2"})

    def test_a_value_of_the_wrong_type_is_refused(self):
        good = graph_incident("1")
        no_id = {name: value for name, value in good.items() if name != "id"}
        wrong = {
            "the incident is not an object": "incident",
            "no id": no_id,
            "id is not a string": {**good, "id": 7},
            "'1': no status": {**good, "status": None},
            "status is not a string": {**good, "status": ["active"]},
            "alerts is not a list": {**good, "alerts": {"a": 1}},
            "no createdDateTime": {**good, "alerts": [graph_alert(createdDateTime=None)]},
            "categories is not a list": {**good, "alerts": [graph_alert(categories="Exec")]},
            "mitreTechniques is not a list": {**good, "alerts": [graph_alert(mitreTechniques=[1])]},
            "evidence is not a list": {**good, "alerts": [graph_alert(evidence="none")]},
            "has no attribute 'get'": {**good, "alerts": ["alert"]},
            "accountName is not a string": {**good, "alerts": [graph_alert(evidence=[
                {"@odata.type": "#microsoft.graph.security.userEvidence",
                 "userAccount": {"accountName": 5}}])]},
        }
        for needle, incident in wrong.items():
            with self.subTest(needle):
                message = self._refusal({"value": [incident]})
                self.assertIn("is not as Microsoft Graph documents it", message)
                self.assertIn(needle, message)
        self.assertIn("'yesterday' is not a time meerkat reads", self._refusal(
            {"value": [{**good, "alerts": [graph_alert(time="yesterday")]}]}))
        self.assertIn("id is not a string", self._refusal({"value": [{**good, "id": 1e999}]}))

    def test_a_file_that_is_not_a_graph_answer_is_refused(self):
        for answer in ([graph_incident("1")], [], {"incidents": []}, {"value": "none"}, None, 5):
            with self.subTest(answer):
                self.assertIn("under value", self._refusal(answer))
        self.assertEqual(self._refusal({"value": []}), f"{self.file}: no incidents under value")
        for text in ("", "IncidentId,Timestamp", "[" * 100_000, "{\"value\": [" + "9" * 5000 + "]}"):
            with self.subTest(text[:20]):
                self.file.write_text(text)
                with self.assertRaisesRegex(IncidentError, "not a readable JSON file"):
                    defender.read_graph(self.file)
        with self.assertRaisesRegex(IncidentError, "no such file"):
            defender.read_graph(self.tmp / "absent.json")

    def test_a_refused_file_leaves_no_run_behind(self):
        code, out, err = self._run("queue", str(self._write({"value": [graph_incident("1", "x")]})))
        self.assertEqual((code, out, err.count("\n")), (1, "", 1))
        self.assertFalse(self.runs_dir.exists())


if __name__ == "__main__":
    unittest.main()
