# ATT&CK mapping coverage: the local mapping file, check's coverage report and
# `meerkat attack`

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

from core.attack_mapping import DETECTION_MAPPINGS, map_alert, with_local_mappings
from meerkat import cli
from tests.test_cli import (
    HAS_BUNDLE,
    SHIPPED_BUNDLE,
    client_directory,
    make_alerts,
    make_families,
    make_sessions,
    squashed,
)


def _mapping_file(content) -> Path:
    path = Path(tempfile.mkdtemp()) / "local_mappings.json"
    text = content if isinstance(content, str) else json.dumps(content)
    path.write_text(text, encoding="utf-8")
    return path


LOCAL = {"wazuh": {"5710": ["T1110"], "31101": []}, "zeek": {"notice": ["T1046"]}}


class LocalMappingTests(unittest.TestCase):
    def test_a_local_rule_wins_and_every_other_rule_stays(self):
        merged = with_local_mappings(_mapping_file(LOCAL))
        self.assertEqual(merged["wazuh"]["5710"], ["T1110"])
        self.assertEqual(merged["wazuh"]["31101"], [])
        self.assertEqual(merged["zeek"]["notice"], ["T1046"])
        self.assertEqual(merged["wazuh"]["31516"], DETECTION_MAPPINGS["wazuh"]["31516"])
        self.assertEqual(merged["aminer"], DETECTION_MAPPINGS["aminer"])
        self.assertEqual(DETECTION_MAPPINGS["wazuh"]["31101"], ["T1595.002"])

    def test_the_merged_mapping_reaches_map_alert(self):
        merged = with_local_mappings(_mapping_file(LOCAL))
        mapping = map_alert("wazuh", "5710", "", merged)
        self.assertEqual(mapping.source, "rule")
        self.assertIn("Credential Access", mapping.tactics)
        self.assertEqual(map_alert("wazuh", "31101", "T1595", merged).source, "suppressed")

    def test_no_local_file_is_the_shipped_mapping(self):
        self.assertIs(with_local_mappings(None), DETECTION_MAPPINGS)

    def test_a_bad_file_is_refused_with_its_name(self):
        for content in (
            {"wazuh": {"5710": ["T9999"]}},
            {"wazuh": {"5710": "T1110"}},
            {"wazuh": ["5710"]},
            ["wazuh"],
            "{not json",
        ):
            with self.subTest(content=content):
                path = _mapping_file(content)
                with self.assertRaises(ValueError) as caught:
                    with_local_mappings(path)
                self.assertIn("local_mappings.json", str(caught.exception))


class CheckCoverageTests(unittest.TestCase):
    def _check(self, *extra_args, mappings=None):
        directory = client_directory()
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            contextlib.suppress(SystemExit),
        ):
            cli.cmd_check(argparse.Namespace(
                company="acme", input=directory,
                inventory=directory / "inventory" / "acme.json",
                sample=100, wazuh_file=None, aminer_file=None,
                attack_mappings=mappings, json="--json" in extra_args,
            ))
        return stdout.getvalue(), stderr.getvalue()

    def test_check_reports_the_mapped_share_and_the_busiest_unmapped_rules(self):
        stdout, _ = self._check("--json")
        report = json.loads(stdout)
        wazuh = next(d for d in report["detectors"] if d["detector"] == "wazuh")
        self.assertEqual(wazuh["attack_mapped"], 18)
        self.assertEqual(
            report["unmapped_rules"],
            [{"detector": "wazuh", "rule_id": "5710", "alerts": 18}],
        )
        self.assertNotIn("unmapped_rules", report["problems"])

    def test_check_prints_the_coverage_as_a_warning(self):
        stdout, _ = self._check()
        printed = squashed(stdout)
        self.assertIn("ATT&CKmapped", printed)
        self.assertIn("50%", printed)
        self.assertIn("busiestruleswithnoATT&CKtactic", printed)
        self.assertIn("5710", printed)

    def test_check_applies_the_local_mapping_and_skips_suppressed_rules(self):
        # LOCAL maps 5710 and suppresses 31101, so nothing is left unmapped
        stdout, _ = self._check("--json", mappings=_mapping_file(LOCAL))
        report = json.loads(stdout)
        self.assertEqual(report["unmapped_rules"], [])
        wazuh = next(d for d in report["detectors"] if d["detector"] == "wazuh")
        self.assertEqual(wazuh["attack_mapped"], 18)

    def test_a_bad_local_mapping_exits_cleanly(self):
        directory = client_directory()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.cmd_check(argparse.Namespace(
                    company="acme", input=directory,
                    inventory=directory / "inventory" / "acme.json",
                    sample=100, wazuh_file=None, aminer_file=None, json=False,
                    attack_mappings=_mapping_file({"wazuh": {"1": ["T9999"]}}),
                ))
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertIn("unknownATT&CKtechniques", squashed(stderr.getvalue()))


def _run():
    alerts = make_alerts().assign(
        mapping_source=["rule", "rule", "rule", ""],
        technique_ids=["T1595.002", "T1595.002", "T1595.002", ""],
    )
    decorated = cli.decorate_families(make_families(), alerts, budget=2)
    runs = Path(tempfile.mkdtemp())
    cli.save_run(runs, "acme-1", {"company": "acme", "budget": 2},
                 decorated, make_sessions(), alerts)
    return runs


class AttackCommandTests(unittest.TestCase):
    def test_rules_list_unmapped_first_with_counts_sources_and_names(self):
        rows = cli.attack_rules(cli.load_run(_run(), "acme-1"))
        self.assertEqual(
            [(row["detector"], row["rule_id"], row["alerts"], row["source"]) for row in rows],
            [("suricata", "2001", 1, "unmapped"), ("wazuh", "31101", 3, "reviewed")],
        )
        self.assertEqual(rows[1]["techniques"][0]["name"], "Vulnerability Scanning")

    def test_json_and_table_output(self):
        runs = _run()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            cli.main(["attack", "--runs-dir", str(runs), "--json"])
        self.assertEqual(json.loads(stdout.getvalue())[0]["source"], "unmapped")
        with cli.console.capture() as capture:
            cli.cmd_attack(argparse.Namespace(runs_dir=runs, run="acme-1", json=False))
        self.assertIn("unmapped", capture.get())


class ConfigTests(unittest.TestCase):
    def test_the_environment_fills_the_mapping_file(self):
        args = cli.build_parser().parse_args(["triage"])
        with mock.patch.dict(os.environ, {"MEERKAT_ATTACK_MAPPINGS": "local.json"}):
            cli._apply_config(args)
        self.assertEqual(args.attack_mappings, Path("local.json"))

    def test_unset_means_the_shipped_mapping(self):
        args = cli.build_parser().parse_args(["check"])
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MEERKAT_ATTACK_MAPPINGS", None)
            with mock.patch.object(cli, "_load_config", return_value=({}, "")):
                cli._apply_config(args)
        self.assertIsNone(args.attack_mappings)


@unittest.skipUnless(
    HAS_BUNDLE, "needs models/meerkat_bundle.skops, which is stored with Git LFS"
)
class TriageWithLocalMappingTests(unittest.TestCase):
    def _triage(self, mappings):
        directory = client_directory()
        runs = Path(tempfile.mkdtemp())
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            cli.cmd_triage(argparse.Namespace(
                model=SHIPPED_BUNDLE, input=directory, company="acme",
                inventory=directory / "inventory" / "acme.json",
                labels=None, event_csv_dir=None, wazuh_file=None, aminer_file=None,
                attack_mappings=mappings, budget=2, runs_dir=runs,
            ))
        return cli.load_run(runs)

    def test_a_local_mapping_changes_the_tactics_and_never_the_ranking(self):
        path = _mapping_file(LOCAL)
        local = self._triage(path)
        shipped = self._triage(None)
        columns = ["family_id", "ranking_score", "queue_rank", "in_queue", "handle"]
        pd.testing.assert_frame_equal(local.families[columns], shipped.families[columns])
        self.assertNotEqual(
            list(local.alerts["mapping_source"]), list(shipped.alerts["mapping_source"])
        )

    def test_run_json_records_the_file_and_its_sha256(self):
        import hashlib

        path = _mapping_file(LOCAL)
        meta = self._triage(path).meta["attack_mappings"]
        self.assertEqual(meta["file"], str(path))
        self.assertEqual(meta["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertIsNone(self._triage(None).meta["attack_mappings"])


if __name__ == "__main__":
    unittest.main()
