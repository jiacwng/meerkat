# asset criticality: read from the inventory, shown and filtered, never scored

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd
from rich.console import Console

from core.classifier import _family_feature_matrix
from core.features import build_session_feature_matrix, fit_session_feature_schema
from core.inventory import load_inventory
from core.normalize import normalize_scenario
from core.sessions import build_families, build_sessions
from meerkat import cli
from tests.fixtures import (
    HAS_BUNDLE,
    client_directory,
    make_families,
    make_run,
    squashed,
    triage_client,
    write_inventory,
)


def _load(assets: list[dict]):
    path = Path(tempfile.mkdtemp()) / "inventory.json"
    path.write_text(json.dumps({"company": "t", "assets": assets}), encoding="utf-8")
    return load_inventory(path)


def _asset(criticality=None, **extra) -> dict:
    asset = {"hostname": "a", "ip_addresses": ["10.0.0.1"], **extra}
    if criticality is not None:
        asset["criticality"] = criticality
    return asset


class LoadCriticalityTests(unittest.TestCase):
    def test_a_tier_is_read_and_lowercased(self):
        inventory = _load([_asset(" High ")])
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].criticality, "high")

    def test_absent_empty_unset_and_null_all_mean_unset(self):
        for value in (None, "", "unset", "UNSET"):
            asset = _asset() if value is None else _asset(value)
            inventory = _load([asset])
            self.assertEqual(inventory.assets_by_ip["10.0.0.1"].criticality, "unset")
            self.assertEqual(inventory.unknown_criticalities, ())
        path = Path(tempfile.mkdtemp()) / "inventory.json"
        path.write_text(
            '{"assets": [{"hostname": "a", "ip_addresses": ["10.0.0.1"], '
            '"criticality": null}]}',
            encoding="utf-8",
        )
        inventory = load_inventory(path)
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].criticality, "unset")
        self.assertEqual(inventory.unknown_criticalities, ())

    def test_a_typo_or_a_non_string_is_reported_and_unset(self):
        inventory = _load([
            _asset("hgih"),
            {"hostname": "b", "ip_addresses": ["10.0.0.2"], "criticality": 3},
        ])
        self.assertEqual(inventory.unknown_criticalities, ("3", "hgih"))
        for ip in ("10.0.0.1", "10.0.0.2"):
            self.assertEqual(inventory.assets_by_ip[ip].criticality, "unset")

    def test_a_1_1_inventory_loads_unchanged(self):
        inventory = _load([_asset(roles=["server"])])
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].groups, ("server",))
        self.assertEqual(inventory.assets_without_criticality(), ("a",))


class CriticalityNeverScoresTests(unittest.TestCase):
    def _frames(self, tiered: bool):
        directory = client_directory()
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"],
              "roles": ["server", "internet_facing"],
              **({"criticality": "critical"} if tiered else {})}],
        )
        alerts = normalize_scenario(directory, None, "acme", inventory)
        sessions = build_sessions(alerts, "acme", load_inventory(inventory))
        return sessions

    def test_the_feature_matrices_are_identical_with_and_without_tiers(self):
        tiered = self._frames(True)
        untiered = self._frames(False)
        self.assertEqual(set(tiered["criticality"]), {"critical"})
        self.assertEqual(set(untiered["criticality"]), {"unset"})
        schema = fit_session_feature_schema(untiered)
        pd.testing.assert_frame_equal(
            build_session_feature_matrix(tiered, schema),
            build_session_feature_matrix(untiered, schema),
        )
        for frame in (tiered, untiered):
            frame["ranking_score"] = frame["size"] / frame["size"].max()
        tiered_families = build_families(tiered)
        untiered_families = build_families(untiered)
        self.assertEqual(set(tiered_families["criticality"]), {"critical"})
        roles = ("internet_facing", "server")
        pd.testing.assert_frame_equal(
            _family_feature_matrix(tiered_families, roles),
            _family_feature_matrix(untiered_families, roles),
        )

    @unittest.skipUnless(
        HAS_BUNDLE, "needs models/meerkat_bundle.skops, which is stored with Git LFS"
    )
    def test_triage_ranks_identically_with_and_without_tiers(self):
        columns = ["family_id", "ranking_score", "queue_rank", "in_queue", "handle"]
        tiered = triage_client("high").run.families
        untiered = triage_client().run.families
        self.assertEqual(set(tiered["criticality"]), {"high"})
        pd.testing.assert_frame_equal(tiered[columns], untiered[columns])


def _run(criticalities):
    runs = make_run(families=make_families().assign(criticality=criticalities))
    return cli.load_run(runs, "acme-1")


class DisplayAndFilterTests(unittest.TestCase):
    def test_the_queue_shows_a_tier_and_leaves_unset_blank(self):
        run = _run(["critical", "unset"])
        with mock.patch.object(cli, "console", Console(width=200)):
            with cli.console.capture() as capture:
                cli.render_queue(run.families, {}, "Review queue")
        text = capture.get()
        self.assertIn("crit", text)
        self.assertIn("critical", text)
        self.assertNotIn("unset", text)

    def test_inspect_shows_the_tier(self):
        run = _run(["high", "unset"])
        with cli.console.capture() as capture:
            cli.render_family(run, run.family_by_handle("F1"), {})
        self.assertIn("criticality   : high", capture.get())

    def test_the_filter_keeps_one_tier_across_the_whole_run(self):
        run = _run(["high", "low"])
        selected = cli._select_families(
            run, False, None, None, None, None, None, "low"
        )
        self.assertEqual(list(selected["criticality"]), ["low"])

    def test_a_run_saved_before_criticality_shows_blank_and_filters_to_nothing(self):
        run = _run(["high", "low"])
        run.families = run.families.drop(columns="criticality")
        with cli.console.capture() as capture:
            cli.render_queue(run.families, {}, "Review queue")
        self.assertNotIn("high", capture.get())
        selected = cli._select_families(
            run, False, None, None, None, None, None, "high"
        )
        self.assertEqual(len(selected), 0)

    def test_queue_json_carries_the_tier(self):
        run = _run(["medium", "unset"])
        records = cli.queue_records(run, run.families)
        self.assertEqual(
            sorted(record["criticality"] for record in records),
            ["medium", "unset"],
        )


class CheckAndScaffoldTests(unittest.TestCase):
    def _check(self, assets: list[dict]) -> tuple[str, dict]:
        directory = client_directory()
        inventory = write_inventory(directory / "inventory" / "acme.json", assets)
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            contextlib.suppress(SystemExit),
        ):
            cli.cmd_check(argparse.Namespace(
                company="acme", input=directory, inventory=inventory,
                sample=100, wazuh_file=None, aminer_file=None, json=True,
            ))
        return squashed(stderr.getvalue()), json.loads(stdout.getvalue())

    def test_a_missing_tier_warns_and_is_not_a_problem(self):
        printed, report = self._check([
            {"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"]},
        ])
        self.assertIn("havenocriticality", printed)
        self.assertEqual(report["assets_without_criticality"], 1)
        self.assertNotIn("unknown_criticality", report["problems"])

    def test_an_unknown_tier_is_a_problem(self):
        printed, report = self._check([
            {"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"],
             "criticality": "urgent"},
        ])
        self.assertIn("unrecognisedcriticality", printed)
        self.assertIn("unknown_criticality", report["problems"])

    def test_the_scaffold_writes_the_field_blank_and_check_accepts_it(self):
        directory = client_directory()
        out = directory / "inventory" / "scaffold.json"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_inventory(argparse.Namespace(
                company="acme", input=directory, out=out, limit=1000,
                list_roles=False,
            ))
        assets = json.loads(out.read_text(encoding="utf-8"))["assets"]
        self.assertTrue(assets)
        self.assertTrue(all(asset["criticality"] == "" for asset in assets))
        self.assertEqual(load_inventory(out).unknown_criticalities, ())


if __name__ == "__main__":
    unittest.main()
