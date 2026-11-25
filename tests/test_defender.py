# Reading a file of Defender incidents in the shape Microsoft Graph documents.

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from core.incidents import IncidentError
from meerkat import defender
from meerkat.cli import main
from tests.fixtures import use_weights

EXAMPLE = Path(__file__).parent.parent / "examples" / "incidents.csv"
WORDS = {name: word for word, name in defender.CLASSIFICATION.items()}
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
            incident = found.setdefault(row["IncidentId"], {
                "id": row["IncidentId"], "classification": "unknown", "alerts": [],
                "incidentWebUrl": f"https://security.example/incident2/{row['IncidentId']}"})
            if row["IncidentGrade"]:
                incident["classification"] = WORDS[row["IncidentGrade"]]
            evidence = []
            for column, (kind, key, inner) in ENTITIES.items():
                if row[column]:
                    value = row[column] if inner is None else {inner: row[column]}
                    evidence.append({"@odata.type": f"#microsoft.graph.security.{kind}",
                                     key: value})
            incident["alerts"].append({
                "detectorId": row["DetectorId"], "createdDateTime": row["Timestamp"],
                "title": row["AlertTitle"], "category": row["Category"],
                "mitreTechniques": [name for name in row["MitreTechniques"].split(";") if name],
                "evidence": evidence})
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

    def _incident(self, number: str, classification: str | None, **extra) -> dict:
        return {"id": number, "classification": classification,
                "incidentWebUrl": f"https://security.example/incident2/{number}",
                "alerts": [{"detectorId": "7", "createdDateTime": "2024-06-01T08:00:00.1234567Z",
                            "title": "Suspicious sign in", "category": "InitialAccess",
                            "mitreTechniques": ["T1078"], "evidence": [{
                                "@odata.type": "#microsoft.graph.security.userEvidence",
                                "userAccount": {"accountName": "alice", "userSid": None}}]}],
                **extra}

    def test_a_json_file_ranks_the_example_as_its_csv_does(self):
        self._write({"@odata.context": "incidents(alerts())", "value": as_graph(EXAMPLE)})
        from_csv = self.tmp / "csv"
        for runs_dir in (self.runs_dir, from_csv):
            self._run("config", "budget", "10", runs_dir=runs_dir)
        self._run("queue", str(EXAMPLE), runs_dir=from_csv)
        code, _, err = self._run("queue", str(self.file))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(self._ranked(self.runs_dir)), 46)
        self.assertEqual(self._ranked(self.runs_dir), self._ranked(from_csv))
        record = json.loads(self._run("details", "138267", "--json")[1])
        self.assertEqual(record["IncidentUrl"], "https://security.example/incident2/138267")
        self.assertRegex(self._run("details", "138267")[1],
                         r"\nlink\s+https://security.example/incident2/138267\n")

    def test_a_later_file_brings_the_classification(self):
        self._run("queue", str(self._write({"value": [self._incident("1", "unknown"),
                                                      self._incident("2", "unknown")]})))
        self._run("queue", str(self._write({"value": [self._incident("2", "truePositive")]})))
        self.assertEqual(list(self._ranked(self.runs_dir)), ["1"])
        record = json.loads(self._run("details", "2", "--json")[1])
        self.assertEqual((record["IncidentGrade"], record["Timestamp"], record["AccountName"]),
                         ("TruePositive", "2024-06-01T08:00:00Z", ["alice"]))

    def test_classification_words_an_unsafe_link_and_utf_16(self):
        found = [self._incident("1", "informationalExpectedActivity"),
                 self._incident("2", "falsePositive", incidentWebUrl="javascript:alert(1)"),
                 self._incident("3", None, alerts=[])]
        for encoding in ("utf-8", "utf-8-sig", "utf-16"):
            with self.subTest(encoding):
                table = defender.read_incidents(self._write({"value": found}, encoding))
                table = table.set_index("IncidentId")
                self.assertEqual(table["IncidentGrade"].to_dict(),
                                 {"1": "BenignPositive", "2": "FalsePositive"})
                self.assertEqual(table["IncidentUrl"].to_dict(),
                                 {"1": "https://security.example/incident2/1", "2": ""})

    def test_a_file_that_is_not_in_the_documented_shape_is_refused(self):
        good = self._incident("1", "unknown")
        no_id = {name: value for name, value in good.items() if name != "id"}
        bad_time = {**good, "alerts": [{"detectorId": "7", "createdDateTime": "yesterday"}]}
        for wrong in (no_id, bad_time, {**good, "alerts": "none"}, "incident"):
            with self.subTest(wrong):
                code, out, err = self._run("queue", str(self._write({"value": [wrong]})))
                self.assertEqual((code, out), (1, ""))
                self.assertIn("is not as Microsoft Graph documents it", err)
        for answer in ([good], {"incidents": [good]}, {"value": "none"}, None):
            with self.subTest(answer):
                with self.assertRaisesRegex(IncidentError, "under value"):
                    defender.read_incidents(self._write(answer))
        for text in ("", "IncidentId,Timestamp", "[" * 100_000):
            with self.subTest(text[:20]):
                self.file.write_text(text)
                with self.assertRaisesRegex(IncidentError, "not a readable JSON file"):
                    defender.read_incidents(self.file)
        with self.assertRaisesRegex(IncidentError, "no incident with an alert"):
            defender.read_incidents(self._write({"value": [{**good, "alerts": []}]}))
        with self.assertRaisesRegex(IncidentError, "no such file"):
            defender.read_incidents(self.tmp / "absent.json")
        self.assertFalse(self.runs_dir.exists())


if __name__ == "__main__":
    unittest.main()
