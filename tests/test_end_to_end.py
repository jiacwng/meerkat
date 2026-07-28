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

from tests.test_normalize import (
    aminer_export_record,
    eve_alert_record,
    wazuh_record,
    write_company_inventory,
    write_records,
)

REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "models" / "meerkat_bundle.skops"


def bundle_fetched() -> bool:
    # CI checks out without LFS, so the bundle exists as a pointer file there
    if not BUNDLE.exists():
        return False
    with BUNDLE.open("rb") as fh:
        return not fh.read(24).startswith(b"version https://git-lfs")


def run(args, cwd):
    # cwd is the user's own directory, so the package comes from the checkout.
    # utf-8 pinned on both sides: the queue draws box characters that cp1252
    # cannot decode on windows
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "meerkat", *args],
        cwd=cwd, capture_output=True, text=True, timeout=600, env=env,
        encoding="utf-8", errors="replace",
    )


@unittest.skipUnless(bundle_fetched(), "model bundle not fetched (git lfs pull)")
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
            "--model", str(BUNDLE),
        ]
        cls.runs = ["--runs-dir", "runs"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_whole_flow_in_order(self):
        # check first, as the README tells the user to
        result = run(["check", *self.base[:4]], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(["triage", *self.base, *self.runs], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "runs").is_dir())

        result = run(["queue", "--json", *self.runs], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        queue = json.loads(result.stdout)
        self.assertTrue(queue, "queue is empty")
        handle = queue[0]["handle"]

        result = run(["inspect", handle, *self.runs], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(["review", handle, "benign", *self.runs], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(
            ["export", "queue", "--format", "csv", *self.runs], self.root
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(["runs", "--json", *self.runs], self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

        # synthetic alerts sit far from the training data, so drift may exit 4
        # by design; anything else is a failure
        result = run(["drift", *self.base], self.root)
        self.assertIn(result.returncode, (0, 4), result.stderr)


if __name__ == "__main__":
    unittest.main()
