# the Wazuh connector: file-mode window reads and the indexer client, with the
# indexer's HTTP layer mocked so the suite needs no live Wazuh

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from core.normalize import AlertFileError
from meerkat import connectors


def wazuh(ts, level=5, rule_id="1000", agent="host-a"):
    return {
        "timestamp": ts,
        "rule": {"level": level, "id": rule_id, "description": "x"},
        "agent": {"id": "001", "name": agent},
        "data": {},
    }


def suricata(ts):
    row = wazuh(ts)
    row["data"] = {"alert": {"signature": "SURICATA test"}}
    return row


def write_lines(path, records):
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


class WindowTests(unittest.TestCase):
    def test_day_window_is_half_open(self):
        window = connectors.day_window("2022-01-21")
        self.assertTrue(window.contains(window.start))
        self.assertFalse(window.contains(window.end))
        self.assertEqual(window.end - window.start, 86400)

    def test_parse_moment_reads_iso_and_epoch(self):
        iso = connectors.parse_moment("2022-01-21T00:00:00Z")
        self.assertEqual(connectors.parse_moment("1642723200"), iso)

    def test_parse_moment_treats_naive_as_utc(self):
        self.assertEqual(
            connectors.parse_moment("2022-01-21T00:00:00"),
            connectors.parse_moment("2022-01-21T00:00:00Z"),
        )


class FileModeTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.window = connectors.day_window("2022-01-21")

    def test_only_records_inside_the_window_are_kept(self):
        source = self.dir / "source.json"
        write_lines(source, [
            wazuh("2022-01-20T23:59:59+0000"),
            wazuh("2022-01-21T00:00:00+0000"),
            wazuh("2022-01-21T12:00:00+0000"),
            wazuh("2022-01-22T00:00:00+0000"),
        ])
        kept = connectors.read_window_file(source, self.window)
        self.assertEqual(len(kept), 2)
        self.assertEqual(
            [row["timestamp"] for row in kept],
            ["2022-01-21T00:00:00+0000", "2022-01-21T12:00:00+0000"],
        )

    def test_blank_lines_are_skipped_and_bad_json_is_fatal(self):
        source = self.dir / "source.json"
        with source.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(wazuh("2022-01-21T01:00:00+0000")) + "\n")
            handle.write("\n")
            handle.write("{not json\n")
        with self.assertRaises(AlertFileError):
            connectors.read_window_file(source, self.window)

    def test_a_record_without_a_timestamp_is_dropped(self):
        source = self.dir / "source.json"
        write_lines(source, [{"rule": {"level": 5}, "agent": {"name": "h"}}])
        self.assertEqual(connectors.read_window_file(source, self.window), [])

    def test_write_records_round_trips(self):
        out = self.dir / "out.json"
        rows = [wazuh("2022-01-21T01:00:00+0000"), suricata("2022-01-21T02:00:00+0000")]
        connectors.write_records(out, rows)
        back = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(back, rows)


def hit(ts, ident, source=None):
    return {"_id": ident, "_source": source or wazuh(ts), "sort": [ts, ident]}


class StubTransport:
    def __init__(self, pages, pit_id="PIT1"):
        self.pages = list(pages)
        self.pit_id = pit_id
        self.calls = []
        self.searches = 0

    def __call__(self, config, method, path, body):
        self.calls.append((method, path, body))
        if "point_in_time" in path:
            if method == "DELETE":
                return {}
            if self.pit_id is None:
                raise connectors.ConnectorError("point in time unsupported")
            return {"pit_id": self.pit_id}
        page = self.pages[self.searches] if self.searches < len(self.pages) else []
        self.searches += 1
        return {"pit_id": self.pit_id, "hits": {"hits": page}}


class IndexerPagingTests(unittest.TestCase):
    def setUp(self):
        self.config = connectors.IndexerConfig(host="idx.example", index="wazuh-alerts-*")
        self.window = connectors.day_window("2022-01-21")

    def test_pit_path_walks_pages_and_unwraps_source(self):
        pages = [
            [hit("2022-01-21T01:00:00Z", "a"), hit("2022-01-21T02:00:00Z", "b")],
            [hit("2022-01-21T03:00:00Z", "c")],
            [],
        ]
        stub = StubTransport(pages)
        with mock.patch.object(connectors, "_send", stub):
            records = connectors.query_window(self.config, self.window)
        self.assertEqual(len(records), 3)
        self.assertTrue(all("rule" in row for row in records))
        searches = [call for call in stub.calls if call[1] == "/_search"]
        self.assertTrue(searches)
        self.assertEqual(searches[1][2]["search_after"], ["2022-01-21T02:00:00Z", "b"])
        self.assertTrue(any(call[0] == "DELETE" for call in stub.calls))

    def test_fallback_without_pit_uses_the_index_path(self):
        pages = [[hit("2022-01-21T01:00:00Z", "a")], []]
        stub = StubTransport(pages, pit_id=None)
        with mock.patch.object(connectors, "_send", stub):
            records = connectors.query_window(self.config, self.window)
        self.assertEqual(len(records), 1)
        self.assertTrue(any(call[1] == "/wazuh-alerts-*/_search" for call in stub.calls))
        self.assertFalse(any(call[0] == "DELETE" for call in stub.calls))

    def test_empty_result_returns_no_records(self):
        stub = StubTransport([[]])
        with mock.patch.object(connectors, "_send", stub):
            self.assertEqual(connectors.query_window(self.config, self.window), [])

    def test_a_hit_without_source_is_a_clean_error(self):
        stub = StubTransport([[{"sort": ["2022-01-21T01:00:00Z", "a"]}]])
        with mock.patch.object(connectors, "_send", stub):
            with self.assertRaises(connectors.ConnectorError) as caught:
                connectors.query_window(self.config, self.window)
        self.assertIn("_source", str(caught.exception))


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.payload


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.config = connectors.IndexerConfig(host="idx.example")

    def test_basic_auth_header_is_set(self):
        captured = {}

        def fake_urlopen(request, context=None, timeout=None):
            captured["auth"] = request.get_header("Authorization")
            return FakeResponse(b'{"ok": true}')

        self.config.user = "admin"
        self.config.password = "secret"
        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            connectors._send(self.config, "GET", "/", None)
        self.assertTrue(captured["auth"].startswith("Basic "))

    def test_token_header_is_used_verbatim(self):
        captured = {}

        def fake_urlopen(request, context=None, timeout=None):
            captured["auth"] = request.get_header("Authorization")
            return FakeResponse(b"{}")

        self.config.token = "Bearer abc"
        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            connectors._send(self.config, "GET", "/", None)
        self.assertEqual(captured["auth"], "Bearer abc")

    def test_401_becomes_a_credentials_error(self):
        def fake_urlopen(request, context=None, timeout=None):
            raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)

        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(connectors.ConnectorError) as caught:
                connectors._send(self.config, "GET", "/", None)
        self.assertIn("credentials", str(caught.exception))

    def test_a_non_json_response_is_reported(self):
        def fake_urlopen(request, context=None, timeout=None):
            return FakeResponse(b"<html>not json</html>")

        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(connectors.ConnectorError) as caught:
                connectors._send(self.config, "GET", "/", None)
        self.assertIn("not JSON", str(caught.exception))

    def test_deeply_nested_response_is_reported(self):
        deep = b"[" * 100000 + b"]" * 100000

        def fake_urlopen(request, context=None, timeout=None):
            return FakeResponse(deep)

        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(connectors.ConnectorError) as caught:
                connectors._send(self.config, "GET", "/", None)
        self.assertIn("nested too deeply", str(caught.exception))

    def test_unreachable_host_becomes_a_reach_error(self):
        def fake_urlopen(request, context=None, timeout=None):
            raise urllib.error.URLError("name or service not known")

        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(connectors.ConnectorError) as caught:
                connectors._send(self.config, "GET", "/", None)
        self.assertIn("cannot reach", str(caught.exception))

    def test_insecure_config_disables_verification(self):
        captured = {}

        def fake_urlopen(request, context=None, timeout=None):
            captured["context"] = context
            return FakeResponse(b"{}")

        self.config.verify_tls = False
        with mock.patch.object(connectors.urllib.request, "urlopen", fake_urlopen):
            connectors._send(self.config, "GET", "/", None)
        self.assertFalse(captured["context"].check_hostname)
        self.assertEqual(captured["context"].verify_mode, connectors.ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()
