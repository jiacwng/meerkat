# The web page's server: the page, its five JSON routes and the requests it refuses.

import contextlib
import http.client
import io
import json
import re
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from meerkat import web
from meerkat.cli import main
from tests.fixtures import ROWS, use_weights, write_csv

HOSTILE = "<img src=x onerror=alert(1)>"


class WebTests(unittest.TestCase):
    def setUp(self):
        use_weights(self)
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = tmp / "runs"
        rows = (*ROWS[:-1], (*ROWS[-1][:5], HOSTILE, *ROWS[-1][6:]))
        self.source = write_csv(tmp / "incidents.csv", rows)
        self.empty_dir = tmp / "empty"
        with contextlib.redirect_stdout(io.StringIO()):
            main(["queue", str(self.source), "--runs-dir", str(self.runs_dir)])
        self.server = self._serve(self.runs_dir)

    def _serve(self, runs_dir: Path):
        server = web.make_server(runs_dir, 0, 1)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def _request(self, method: str, path: str, body: dict | str | bytes | None = None,
                 token: bool = True, host: str | None = None,
                 headers: dict | None = None) -> tuple[int, dict, str]:
        port = self.server.server_port
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        self.addCleanup(connection.close)
        headers = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
        if token:
            headers[web.TOKEN_HEADER] = self.server.token
        if isinstance(body, dict):
            body = json.dumps(body)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode()

    def _queue_ids(self) -> list[str]:
        status, _, body = self._request("GET", "/api/queue")
        self.assertEqual(status, 200)
        return [row["IncidentId"] for row in json.loads(body)["queue"]]

    def test_the_page_carries_the_token_and_a_content_security_policy(self):
        status, headers, body = self._request("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(self.server.token, body)
        self.assertNotIn("__TOKEN__", body)
        self.assertNotIn("__NONCE__", body)
        policy = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)
        nonce = re.search(r"script-src 'nonce-([^']+)'", policy).group(1)
        self.assertIn(f'<script nonce="{nonce}">', body)

    def test_the_queue_route_lists_the_open_incidents_by_score(self):
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])

    def test_the_queue_route_sends_the_classifications_links_and_row_columns(self):
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual(record["classifications"], ["TruePositive", "BenignPositive", "FalsePositive"])
        self.assertIn("AccountUpn", record["links"])
        first = record["queue"][0]
        self.assertEqual((first["host"], first["user"], first["flag"]), ("", "alice", ""))

    def test_a_request_without_the_token_is_refused(self):
        self.assertEqual(self._request("GET", "/api/queue", token=False)[0], 403)
        classification = {"incidents": ["201"], "classification": "TruePositive"}
        self.assertEqual(self._request("POST", "/api/classify", classification, token=False)[0], 403)
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])

    def test_a_request_under_another_host_name_is_refused(self):
        for path in ("/", "/api/queue"):
            self.assertEqual(self._request("GET", path, host="evil.example")[0], 403)
        port = self.server.server_port
        self.assertEqual(self._request("GET", "/", host=f"localhost:{port}")[0], 200)

    def test_a_classification_from_the_page_closes_the_incident(self):
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])
        classification = {"incidents": ["201"], "classification": "TruePositive", "comment": "checked with the user"}
        status, _, body = self._request("POST", "/api/classify", classification)
        self.assertEqual((status, json.loads(body)["classification"]), (200, "TruePositive"))
        self.assertEqual(self._queue_ids(), ["202", "200"])
        self.assertIn("checked with the user", (self.runs_dir / "classifications.csv").read_text())
        record = json.loads(self._request("GET", "/api/incident?id=201")[2])
        self.assertEqual(record["IncidentGrade"], "TruePositive")
        similar = record["similar_incidents"]
        self.assertEqual([row["IncidentId"] for row in similar], ["100"])
        self.assertEqual(similar[0]["shared"], ["AccountName alice", "IpAddress 10.0.0.1"])
        self.assertEqual(record["entities"], [
            {"field": "AccountName", "value": "alice", "classified_before": 1,
             "TruePositive": 1, "BenignPositive": 0, "FalsePositive": 0},
            {"field": "IpAddress", "value": "10.0.0.1", "classified_before": 1,
             "TruePositive": 1, "BenignPositive": 0, "FalsePositive": 0}])

    def test_several_incidents_are_classified_in_one_request(self):
        several = {"incidents": ["201", "202", "201"], "classification": "BenignPositive"}
        status, _, body = self._request("POST", "/api/classify", several)
        self.assertEqual((status, json.loads(body)["classified"]), (200, 2))
        self.assertEqual(self._queue_ids(), ["200"])
        for wrong in ([], "201", ["201", 7], ["201", "999"]):
            with self.subTest(wrong):
                body = {"incidents": wrong, "classification": "TruePositive"}
                self.assertIn(self._request("POST", "/api/classify", body)[0], (400, 404))
        self.assertEqual(self._queue_ids(), ["200"])
        many = {"incidents": ["200"] * 5000, "classification": "FalsePositive"}
        self.assertEqual(self._request("POST", "/api/classify", many)[0], 200)
        self.assertEqual(self._queue_ids(), [])

    def test_a_classification_recorded_in_the_terminal_reaches_the_page(self):
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])
        with contextlib.redirect_stdout(io.StringIO()):
            main(["classify", "202", "fp", "--runs-dir", str(self.runs_dir)])
        self.assertEqual(self._queue_ids(), ["201", "200"])

    def test_a_wrong_classification_and_an_unknown_incident_are_refused(self):
        wrong = {"incidents": ["201"], "classification": "Malicious"}
        self.assertEqual(self._request("POST", "/api/classify", wrong)[0], 400)
        wrong = {"incidents": ["201"], "classification": "TruePositive", "group": "yes"}
        self.assertEqual(self._request("POST", "/api/classify", wrong)[0], 400)
        unknown = {"incidents": ["999"], "classification": "TruePositive"}
        self.assertEqual(self._request("POST", "/api/classify", unknown)[0], 404)
        self.assertEqual(self._request("POST", "/api/classify", "not json")[0], 400)
        self.assertEqual(self._request("GET", "/api/incident?id=999")[0], 404)
        self.assertEqual(self._request("GET", "/api/other")[0], 404)
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])

    def test_a_budget_typed_in_the_page_is_saved_and_splits_the_queue(self):
        status, _, body = self._request("POST", "/api/budget", {"budget": 2})
        self.assertEqual((status, json.loads(body)), (200, {"budget": 2}))
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual((record["budget"], record["to_read"], record["below_budget"]), (2, 2, 1))
        self.assertEqual(json.loads((self.runs_dir / "settings.json").read_text()), {"budget": 2})
        self.assertEqual(self._request("POST", "/api/budget", {"budget": None})[0], 200)
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual((record["budget"], record["to_read"]), (None, 3))

    def test_a_wrong_budget_is_refused_and_nothing_is_saved(self):
        for wrong in ({"budget": 0}, {"budget": -3}, {"budget": 2.5}, {"budget": "3"},
                      {"budget": True}, {"size": 3}, "not json"):
            with self.subTest(wrong):
                self.assertEqual(self._request("POST", "/api/budget", wrong)[0], 400)
        self.assertEqual(self._request("POST", "/api/budget", {"budget": 2}, token=False)[0], 403)
        self.assertFalse((self.runs_dir / "settings.json").exists())

    def test_the_queue_route_names_the_file_and_the_sample_behind_the_estimate(self):
        self._request("POST", "/api/budget", {"budget": 2})
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual(record["file"], "incidents.csv")
        self.assertEqual(record["sample"]["drawn"], 1)
        self.assertIsNone(record["tp_below_budget"])
        sampled = next(row["IncidentId"] for row in record["queue"] if row["flag"] == "sample")
        self._request("POST", "/api/classify",
                      {"incidents": [sampled], "classification": "FalsePositive"})
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual(record["sample"]["classified"], 1)

    def test_a_page_with_no_run_loads_a_file_and_lists_its_queue(self):
        self.server = self._serve(self.empty_dir)
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual((record["queue"], record["max_file_bytes"]), (None, 1024 * 1024))
        sent = {web.FILE_HEADER: "C%3A%5Cexports%5Ctoday.csv"}
        status, _, body = self._request("POST", "/api/load", self.source.read_bytes(),
                                        headers=sent)
        self.assertEqual(status, 200, body)
        record = json.loads(self._request("GET", "/api/queue")[2])
        self.assertEqual([row["IncidentId"] for row in record["queue"]], ["201", "202", "200"])
        self.assertEqual(record["file"], "today.csv")
        self.assertEqual(self._request("POST", "/api/load", self.source.read_bytes(),
                                       headers=sent)[0], 200)
        self.assertEqual(len(list(self.empty_dir.glob("*/meta.json"))), 1)

    def test_a_file_that_cannot_be_read_is_refused_under_its_own_name(self):
        self.server = self._serve(self.empty_dir)
        sent = {web.FILE_HEADER: "notes.csv"}
        for body in (b"", b"a,b\n1,2\n", b"\xff\xfe\x00", b'"open quote'):
            with self.subTest(body):
                status, _, answer = self._request("POST", "/api/load", body, headers=sent)
                self.assertEqual(status, 400, answer)
                self.assertIn("notes.csv", json.loads(answer)["error"])
        self.assertEqual(self._request("POST", "/api/load", self.source.read_bytes(),
                                       headers=sent, token=False)[0], 403)
        self.assertFalse(self.empty_dir.exists())

    def test_a_file_above_the_size_limit_is_refused_before_it_is_read(self):
        port = self.server.server_port
        with socket.create_connection(("127.0.0.1", port), timeout=60) as raw:
            raw.sendall((f"POST /api/load HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                         f"{web.TOKEN_HEADER}: {self.server.token}\r\n"
                         f"Content-Length: {1024 * 1024 + 1}\r\n\r\n").encode())
            answer = b"".join(iter(lambda: raw.recv(65536), b"")).decode()
        self.assertIn("413", answer.splitlines()[0])
        self.assertIn("--max-file-mb", answer)

    def test_a_connection_that_sends_nothing_does_not_hold_the_other_requests(self):
        idle = socket.create_connection(("127.0.0.1", self.server.server_port))
        self.addCleanup(idle.close)
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])

    def test_a_damaged_classification_file_is_answered_with_an_error(self):
        (self.runs_dir / "classifications.csv").write_text('"open quote')
        status, _, body = self._request("GET", "/api/queue")
        self.assertEqual(status, 404)
        self.assertIn("classifications.csv", json.loads(body)["error"])

    def test_incident_text_reaches_the_page_as_data_and_is_never_parsed_as_html(self):
        status, headers, body = self._request("GET", "/api/incident?id=202")
        self.assertEqual((status, headers["Content-Type"]), (200, "application/json"))
        self.assertEqual(json.loads(body)["AlertTitle"], HOSTILE)
        page = web.PAGE.read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, page)


if __name__ == "__main__":
    unittest.main()
