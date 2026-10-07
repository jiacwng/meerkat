# meerkat pull: file-mode and config failure modes exercised through the CLI,
# so no live indexer is needed

import argparse
import contextlib
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
        self.assertEqual(result.returncode, 0)
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

    def test_stray_eve_file_does_not_block_a_file_pull(self):
        self.out.mkdir(parents=True)
        (self.out / "acme_eve.json").write_text("x", encoding="utf-8")
        result = run_pull(self.base("--day", "2022-01-21"))
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.out / "acme_wazuh.json").exists())


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
        args = argparse.Namespace(host="idx.example", user=None, insecure=False)
        with (
            mock.patch.object(cli, "_load_config", return_value=({"pull": section}, "")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return cli._indexer_config(args)

    def test_verify_tls_takes_a_boolean(self):
        self.assertFalse(self._config_with({"verify_tls": False}).verify_tls)
        self.assertTrue(self._config_with({"verify_tls": True}).verify_tls)

    def test_verify_tls_as_a_string_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            self._config_with({"verify_tls": "false"})
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
