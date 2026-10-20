# meerkat pull: file-mode and config failure modes exercised through the CLI,
# so no live indexer is needed

import argparse
import contextlib
import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from meerkat import cli
from tests.fixtures import ROOT, run_cli, wazuh_record


def run_pull(args, env_extra=None):
    return run_cli(["pull", *args], cwd=ROOT, env=env_extra)


def flat(result):
    return " ".join((result.stdout + result.stderr).split())


class PullFileModeTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.out = self.dir / "out"
        self.src = self.dir / "src.json"
        record = wazuh_record(
            "2022-01-21T06:00:00+0000", rule_id="1", level=5, description="x",
            timestamp_key="timestamp",
        )
        self.src.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def base(self, *extra):
        return ["--environment", "acme", "--input", str(self.out), "--source",
                "file", "--alerts-file", str(self.src), *extra]

    def test_empty_window_writes_no_file(self):
        result = run_pull(self.base("--day", "2019-01-01"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no alerts in the window", flat(result))
        self.assertFalse((self.out / "acme_wazuh.json").exists())

    def test_out_of_range_epoch_fails_cleanly(self):
        result = run_pull(self.base("--from", "1642723200000", "--to", "1642809600000"))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback (most recent call last)", flat(result))
        self.assertIn("epoch seconds", flat(result))

    def test_the_last_representable_day_fails_cleanly(self):
        result = run_pull(self.base("--day", "9999-12-31"))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback (most recent call last)", flat(result))
        self.assertIn("--day", flat(result))

    def test_to_before_from_fails(self):
        result = run_pull(self.base("--from", "2022-01-22", "--to", "2022-01-21"))
        self.assertEqual(result.returncode, 1)

    def test_refuse_existing_output(self):
        self.out.mkdir(parents=True)
        (self.out / "acme_wazuh.json").write_text("x", encoding="utf-8")
        result = run_pull(self.base("--day", "2022-01-21"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("already exists", flat(result))

    def test_environment_falls_back_to_the_env_var(self):
        result = run_pull(
            ["--input", str(self.out), "--source", "file",
             "--alerts-file", str(self.src), "--day", "2022-01-21"],
            env_extra={"MEERKAT_ENVIRONMENT": "acme"},
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.out / "acme_wazuh.json").exists())

    def test_a_gzipped_alerts_file_is_pulled(self):
        gz = self.dir / "src.json.gz"
        with gzip.open(gz, "wt", encoding="utf-8") as handle:
            handle.write(self.src.read_text(encoding="utf-8"))
        result = run_pull(
            ["--environment", "acme", "--input", str(self.out), "--source", "file",
             "--alerts-file", str(gz), "--day", "2022-01-21"]
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.out / "acme_wazuh.json").exists())

    def test_stray_eve_file_does_not_block_a_file_pull(self):
        self.out.mkdir(parents=True)
        (self.out / "acme_eve.json").write_text("x", encoding="utf-8")
        result = run_pull(self.base("--day", "2022-01-21"))
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.out / "acme_wazuh.json").exists())


class PullBadRecordTests(unittest.TestCase):
    def pull(self, bad_lines: int):
        directory = Path(tempfile.mkdtemp())
        record = json.dumps(wazuh_record(
            "2022-01-21T06:00:00+0000", rule_id="1", level=5, description="x",
            timestamp_key="timestamp",
        ))
        lines = [record] * (200 - bad_lines) + ["{oops"] * bad_lines
        source = directory / "src.json"
        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out = directory / "out"
        result = run_pull(
            ["--environment", "acme", "--input", str(out), "--source", "file",
             "--alerts-file", str(source), "--day", "2022-01-21"]
        )
        return result, out / "acme_wazuh.json"

    def test_one_bad_line_in_two_hundred_is_skipped_and_reported(self):
        result, written = self.pull(1)
        self.assertEqual(result.returncode, 0)
        self.assertIn("skipped 1 bad records", flat(result))
        self.assertEqual(len(written.read_text(encoding="utf-8").splitlines()), 199)

    def test_five_bad_lines_in_two_hundred_stop_the_pull(self):
        result, written = self.pull(5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("5 bad records in 200 lines", flat(result))
        self.assertFalse(written.exists())


class PullConfigTests(unittest.TestCase):
    def test_non_numeric_port_fails_cleanly(self):
        out = Path(tempfile.mkdtemp()) / "out"
        result = run_pull(
            ["--environment", "acme", "--input", str(out), "--source", "indexer",
             "--day", "2022-01-21"],
            env_extra={"MEERKAT_INDEXER_HOST": "localhost",
                       "MEERKAT_INDEXER_PORT": "notaport"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback (most recent call last)", flat(result))
        self.assertIn("port is not a number", flat(result))

    def _config_with(self, section):
        args = argparse.Namespace(
            host="idx.example", user=None, insecure=False, ca_file=None
        )
        with (
            mock.patch.object(cli, "_load_config", return_value=({"pull": section}, "")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return cli._indexer_config(args)

    def test_verify_tls_takes_a_boolean(self):
        self.assertFalse(self._config_with({"verify_tls": False}).verify_tls)
        self.assertTrue(self._config_with({"verify_tls": True}).verify_tls)

    def test_ca_file_is_read_from_the_config(self):
        ca = Path(tempfile.mkdtemp()) / "ca.pem"
        ca.write_text("x", encoding="utf-8")
        self.assertEqual(self._config_with({"ca_file": str(ca)}).ca_file, str(ca))
        self.assertIsNone(self._config_with({}).ca_file)

    def test_a_ca_file_that_is_not_there_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            self._config_with({"ca_file": "/no/such/ca.pem"})
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)

    def test_verify_tls_as_a_string_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            self._config_with({"verify_tls": "false"})
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
