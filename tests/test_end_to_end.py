# one whole run of the shipped tool, command by command, the way a user runs it:
# alerts in a directory, the bundled model, and nothing prepared in advance

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.fixtures import (
    HAS_BUNDLE,
    ROOT,
    SHIPPED_BUNDLE,
    aminer_export_record,
    eve_alert_record,
    run_cli,
    wazuh_record,
    write_company_inventory,
    write_records,
)


@unittest.skipUnless(HAS_BUNDLE, "model bundle not fetched (git lfs pull)")
class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        alerts = root / "alerts"
        alerts.mkdir()
        # a small but three-detector day: wazuh, a native eve.json, and a miner
        write_records(alerts / "acme_wazuh.json", *[wazuh_record()] * 12)
        write_records(alerts / "eve.json", *[eve_alert_record()] * 5)
        write_records(alerts / "acme_aminer.json", *[aminer_export_record()] * 3)
        write_company_inventory(
            root / "inventory.json",
            ("server-a", "10.0.0.1", ("servers",)),
            ("mail", "10.0.0.2", ("mailserver",)),
        )
        cls.root = root
        cls.base = [
            "--input", "alerts",
            "--inventory", "inventory.json",
            "--model", str(SHIPPED_BUNDLE),
        ]
        cls.runs = ["--runs-dir", "runs"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_command(self, arguments):
        return run_cli(arguments, cwd=self.root)

    def test_the_whole_flow_in_order(self):
        # check first, as the README tells the user to
        result = self.run_command(["check", *self.base[:4]])
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_command(["triage", *self.base, *self.runs])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "runs").is_dir())

        # the one real process: the module entry point and the bytes on a pipe,
        # utf-8 pinned on both sides because the queue draws box characters
        environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")
        real = subprocess.run(
            [sys.executable, "-m", "meerkat", "queue", "--json", *self.runs],
            cwd=self.root, capture_output=True, text=True, timeout=600,
            env=environment, encoding="utf-8", errors="replace",
        )
        self.assertEqual(real.returncode, 0, real.stderr)
        queue = json.loads(real.stdout)
        self.assertTrue(queue, "queue is empty")
        handle = queue[0]["handle"]

        result = self.run_command(["inspect", handle, *self.runs])
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_command(["review", handle, "benign", *self.runs])
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_command(["export", "queue", "--format", "csv", *self.runs])
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_command(["runs", "--json", *self.runs])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

        # synthetic alerts sit far from the training data, so drift may exit 4
        # by design; anything else is a failure
        result = self.run_command(["drift", *self.base])
        self.assertIn(result.returncode, (0, 4), result.stderr)


if __name__ == "__main__":
    unittest.main()
