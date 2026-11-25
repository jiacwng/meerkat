# The Defender pull against a local server that answers in the shape Microsoft Graph documents.

import contextlib
import csv
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import unquote

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
                "lastUpdateDateTime": row["Timestamp"],
                "incidentWebUrl": f"https://security.example/incident2/{row['IncidentId']}"})
            if row["IncidentGrade"]:
                incident["classification"] = WORDS[row["IncidentGrade"]]
            incident["lastUpdateDateTime"] = max(incident["lastUpdateDateTime"], row["Timestamp"])
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


class Graph(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        self.server.forms.append(self.rfile.read(length).decode())
        self._send({"token_type": "Bearer", "expires_in": 3599, "access_token": "issued"})

    def do_GET(self):
        self.server.asked.append((unquote(self.path), self.headers["Authorization"]))
        pages = self.server.pages
        number = int(self.path.rsplit("page=", 1)[1]) if "page=" in self.path else 0
        page = {"value": pages[number]}
        if number + 1 < len(pages):
            page["@odata.nextLink"] = self.server.next_link or (
                f"{defender.GRAPH}/security/incidents?page={number + 1}")
        self._send(page)

    def _send(self, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class DefenderTests(unittest.TestCase):
    def setUp(self):
        use_weights(self)
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.server = HTTPServer(("127.0.0.1", 0), Graph)
        self.server.pages, self.server.forms, self.server.asked = [[]], [], []
        self.server.next_link = None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        here = f"http://127.0.0.1:{self.server.server_port}"
        self.enterContext(mock.patch.object(defender, "LOGIN", here))
        self.enterContext(mock.patch.object(defender, "GRAPH", f"{here}/v1.0"))
        self.enterContext(mock.patch.dict(os.environ, {
            "MEERKAT_TENANT_ID": "tenant", "MEERKAT_CLIENT_ID": "client",
            "MEERKAT_CLIENT_SECRET": "secret"}))

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

    def test_a_pull_ranks_the_example_as_its_file_does(self):
        found = as_graph(EXAMPLE)
        self.server.pages = [found[:150], found[150:]]
        from_file = self.tmp / "file"
        for runs_dir in (self.runs_dir, from_file):
            self._run("config", "budget", "10", runs_dir=runs_dir)
        self._run("queue", str(EXAMPLE), runs_dir=from_file)
        code, out, err = self._run("pull", "defender")
        self.assertEqual((code, err), (0, ""))
        self.assertRegex(out, r"^PULLED   incidents 297   open 47   classified 250   run \S+\n$")
        self.assertEqual(self._ranked(self.runs_dir), self._ranked(from_file))
        self.assertEqual(len(self.server.asked), 2)
        self.assertEqual({token for _, token in self.server.asked}, {"Bearer issued"})
        self.assertEqual(self.server.asked[0][0], "/v1.0/security/incidents?$expand=alerts")
        self.assertIn("grant_type=client_credentials", self.server.forms[0])
        record = json.loads(self._run("details", "138267", "--json")[1])
        self.assertEqual(record["IncidentUrl"], "https://security.example/incident2/138267")
        self.assertRegex(self._run("details", "138267")[1],
                         r"\nlink\s+https://security.example/incident2/138267\n")

    def _incident(self, number: str, classification: str, updated: str, **extra) -> dict:
        return {"id": number, "classification": classification, "lastUpdateDateTime": updated,
                "incidentWebUrl": f"https://security.example/incident2/{number}",
                "alerts": [{"detectorId": "7", "createdDateTime": "2024-06-01T08:00:00.1234567Z",
                            "title": "Suspicious sign in", "category": "InitialAccess",
                            "mitreTechniques": ["T1078"], "evidence": [{
                                "@odata.type": "#microsoft.graph.security.userEvidence",
                                "userAccount": {"accountName": "alice", "userSid": None}}]}],
                **extra}

    def test_a_later_pull_asks_for_changes_only_and_takes_the_classification(self):
        self.server.pages = [[self._incident("1", "unknown", "2024-06-01T09:00:00Z"),
                              self._incident("2", "unknown", "2024-06-02T09:00:00.5Z")]]
        self.assertEqual(self._run("pull", "defender")[1].split("   run ")[0],
                         "PULLED   incidents 2   open 2   classified 0")
        self.server.pages = [[self._incident("2", "truePositive", "2024-06-03T10:00:00Z")]]
        self.assertEqual(self._run("pull", "defender")[1].split("   run ")[0],
                         "PULLED   incidents 1   open 0   classified 1")
        self.assertEqual(self.server.asked[-1][0], "/v1.0/security/incidents?$expand=alerts"
                         "&$filter=lastUpdateDateTime ge 2024-06-02T09:00:00.5Z")
        self.assertEqual(list(self._ranked(self.runs_dir)), ["1"])
        record = json.loads(self._run("details", "2", "--json")[1])
        self.assertEqual((record["IncidentGrade"], record["Timestamp"], record["AccountName"]),
                         ("TruePositive", "2024-06-01T08:00:00Z", ["alice"]))

        self.server.pages = [[]]
        self.assertEqual(self._run("pull", "defender")[1], "PULLED   incidents 0\n")
        self.assertIn("ge 2024-06-03T10:00:00Z", self.server.asked[-1][0])

    def test_classification_words_and_an_unsafe_link(self):
        found = [self._incident("1", "informationalExpectedActivity", "2024-06-01T09:00:00Z"),
                 self._incident("2", "falsePositive", "2024-06-01T09:00:00Z",
                                incidentWebUrl="javascript:alert(1)"),
                 self._incident("3", None, "2024-06-01T09:00:00Z", alerts=[])]
        table = defender.incidents(found)[0].set_index("IncidentId")
        self.assertEqual(table["IncidentGrade"].to_dict(),
                         {"1": "BenignPositive", "2": "FalsePositive"})
        self.assertEqual(table["IncidentUrl"].to_dict(),
                         {"1": "https://security.example/incident2/1", "2": ""})

    def test_an_answer_that_is_not_in_the_documented_shape_stops_the_pull(self):
        good = self._incident("1", "unknown", "2024-06-01T09:00:00Z")
        no_id = {name: value for name, value in good.items() if name != "id"}
        undated = {name: value for name, value in good.items() if name != "lastUpdateDateTime"}
        bad_time = {**good, "alerts": [{"detectorId": "7", "createdDateTime": "yesterday"}]}
        for wrong in (no_id, undated, bad_time, {**good, "alerts": "none"}, "incident"):
            with self.subTest(wrong):
                self.server.pages = [[wrong]]
                code, out, err = self._run("pull", "defender")
                self.assertEqual((code, out), (1, ""))
                self.assertIn("is not as Microsoft Graph documents it", err)
        self.assertFalse(self.runs_dir.exists())

    def test_missing_settings_and_a_next_page_elsewhere_stop_the_pull(self):
        with mock.patch.dict(os.environ, {"MEERKAT_CLIENT_SECRET": ""}):
            code, out, err = self._run("pull", "defender")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, "meerkat: error: set the environment variable "
                              "MEERKAT_CLIENT_SECRET\n")
        self.assertEqual(self.server.forms, [])

        self.server.pages = [[self._incident("1", "unknown", "2024-06-01T09:00:00Z")], []]
        self.server.next_link = "http://elsewhere.example/v1.0/security/incidents?page=1"
        code, out, err = self._run("pull", "defender")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("a next page outside", err)
        self.assertEqual(len(self.server.asked), 1)
        self.assertFalse(self.runs_dir.exists())


if __name__ == "__main__":
    unittest.main()
