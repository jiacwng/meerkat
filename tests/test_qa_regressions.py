# Regression tests for the QA findings fixed before the first release.
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from core import classifier
from core.drift import build_profile, compare_profile
from core.inventory import load_inventory
from core.normalize import get_timestamp, normalize_scenario
from core.sessions import build_sessions


def one_detector_client(detector_records: list[dict], blank_line: bool = False) -> Path:
    directory = Path(tempfile.mkdtemp())
    (directory / "inventory").mkdir()
    (directory / "inventory" / "acme.json").write_text(
        json.dumps({"company": "acme", "assets": [
            {"hostname": "h1", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}
        ]}), encoding="utf-8")
    body = "\n".join(json.dumps(r) for r in detector_records)
    if blank_line:
        body = body.replace("\n", "\n\n", 1)
    (directory / "acme_wazuh.json").write_text(body + "\n", encoding="utf-8")
    return directory


def wazuh(second: int) -> dict:
    return {
        "@timestamp": f"2022-01-21T00:00:0{second}Z",
        "agent": {"name": "w", "ip": "10.0.0.1"},
        "rule": {"id": "5710", "level": 5, "description": "sshd auth failure",
                 "groups": ["syslog", "sshd"]},
        "predecoder": {"hostname": "h1"},
    }


class TestSingleDetectorClient(unittest.TestCase):
    def sessions_for(self, **kwargs):
        directory = one_detector_client([wazuh(i) for i in range(4)], **kwargs)
        frame = normalize_scenario(
            directory, None, "acme", directory / "inventory" / "acme.json"
        )
        return build_sessions(
            frame, "acme", load_inventory(directory / "inventory" / "acme.json")
        )

    def test_a_client_running_only_wazuh_can_build_sessions(self):
        # every rule_groups value was a category and none of them was "", so
        # fillna("") refused. The benchmark hid it because its miner rows supply
        # the empty string; a client with one detector hit it on the first run.
        self.assertEqual(len(self.sessions_for()), 1)

    def test_a_blank_line_between_concatenated_exports_is_skipped(self):
        # exports joined with cat carry them, and one used to abort the whole run
        self.assertEqual(len(self.sessions_for(blank_line=True)), 1)


class TestTimestampZone(unittest.TestCase):
    def test_a_timestamp_without_a_zone_is_read_as_utc(self):
        # otherwise the same export normalises differently on every machine,
        # moving sessions, day partitions and attack-window labels
        naive = get_timestamp({"@timestamp": "2022-01-21T00:01:00"}, "wazuh")
        marked = get_timestamp({"@timestamp": "2022-01-21T00:01:00Z"}, "wazuh")
        self.assertEqual(naive, marked)
        self.assertEqual(
            naive, datetime(2022, 1, 21, 0, 1, tzinfo=UTC).timestamp()
        )


class TestDriftMedian(unittest.TestCase):
    def test_a_binary_feature_reports_its_real_median(self):
        # the median came off the middle bin EDGE, so an unmoved binary feature
        # showed "training 1.000 against now 0.000" beside "PSI 0.0000 stable"
        rng = np.random.default_rng(0)
        X = pd.DataFrame({"has_technique": (rng.random(3000) < 0.25).astype(float)})
        drift = compare_profile(build_profile(X, np.zeros(3000)), X)[0]
        self.assertEqual(drift.verdict, "stable")
        self.assertEqual(drift.training_median, drift.current_median)
        self.assertEqual(drift.training_median, 0.0)


class TestDegeneratePrior(unittest.TestCase):
    def test_every_session_inside_an_incident_is_refused(self):
        # with no negative the forest scores every session 1.0 and the ranking is
        # meaningless. The mirror case was already refused.
        X = pd.DataFrame({"signal": np.linspace(0, 1, 20), "noise": np.zeros(20)})
        with self.assertRaises(ValueError) as caught:
            classifier.fit_soft_labels(X, np.ones(20), None, n_estimators=5)
        self.assertIn("nothing to", str(caught.exception))

class TestCliRobustness(unittest.TestCase):
    # every one of these reached the user as a Python traceback before release
    def client(self, alerts: str, inventory: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        (directory / "inventory").mkdir()
        name = directory.name
        (directory / f"{name}_wazuh.json").write_text(alerts, encoding="utf-8")
        (directory / "inventory" / f"{name}.json").write_text(
            inventory, encoding="utf-8"
        )
        return directory

    GOOD_INVENTORY = json.dumps({"company": "x", "assets": [
        {"hostname": "h1", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}]})

    def test_a_record_without_rule_or_agent_is_not_claimed_as_wazuh(self):
        from core.normalize import classify_wazuh_record
        self.assertEqual(classify_wazuh_record({}), "")
        self.assertEqual(classify_wazuh_record({"rule": {"id": "1"}}), "")

    def test_a_malformed_line_names_its_file_and_line(self):
        from core.normalize import AlertFileError, read_alert_record
        with self.assertRaises(AlertFileError) as caught:
            read_alert_record('{"broken', Path("acme_wazuh.json"), 41)
        message = str(caught.exception)
        self.assertIn("acme_wazuh.json", message)
        self.assertIn("line 42", message)

    def test_a_blank_line_is_skipped_rather_than_reported(self):
        from core.normalize import read_alert_record
        self.assertIsNone(read_alert_record("\n", Path("a.json"), 0))

    def test_an_inventory_that_is_not_json_says_so(self):
        directory = self.client("", "{oops")
        with self.assertRaises(ValueError) as caught:
            load_inventory(directory / "inventory" / f"{directory.name}.json")
        self.assertIn("not valid JSON", str(caught.exception))

    def test_an_inventory_without_assets_says_so(self):
        directory = self.client("", '{"company": "x"}')
        with self.assertRaises(ValueError) as caught:
            load_inventory(directory / "inventory" / f"{directory.name}.json")
        self.assertIn("assets", str(caught.exception))

    def test_roles_given_as_a_string_is_one_role_not_six_letters(self):
        # "webserver" is iterable, so the asset used to get w, e, b, s, r, v as
        # unrecognised roles and then no roles at all
        directory = self.client("", json.dumps({"company": "x", "assets": [
            {"hostname": "h", "ip_addresses": ["10.0.0.1"], "roles": "server"}]}))
        inventory = load_inventory(directory / "inventory" / f"{directory.name}.json")
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].groups, ("server",))

    def test_a_bundle_without_the_median_field_still_reports_drift(self):
        # skops restores a field a stored profile never had as absent, so a
        # bundle written before feature_medians existed crashed every drift run
        from core.drift import TrainingProfile, compare_profile
        profile = TrainingProfile()
        object.__delattr__ if False else None
        profile.feature_bins = {"log_size": ((1.0,), (0.5, 0.5))}
        del profile.__dict__["feature_medians"]
        drift = compare_profile(profile, pd.DataFrame({"log_size": [1.0, 2.0]}))
        self.assertEqual(len(drift), 1)
        self.assertTrue(np.isnan(drift[0].training_median))

    def test_csv_export_strips_control_characters(self):
        # this file goes to a ticketing system and gets cat'd, and hostnames are
        # written by whoever set the alert off
        from meerkat.cli import _csv_safe
        self.assertEqual(_csv_safe("host\x1b[2Jname"), "host[2Jname")
        self.assertEqual(_csv_safe("a\x00b"), "ab")
        self.assertEqual(_csv_safe("=cmd()"), "'=cmd()")


class TestBoundaryValues(unittest.TestCase):
    # each of these was accepted silently and produced a wrong or unreachable
    # result rather than an error
    def parser(self):
        from meerkat.cli import build_parser
        return build_parser()

    def test_a_budget_of_zero_or_less_is_refused_everywhere(self):
        # queue --budget already refused them while triage saved a run whose
        # entire queue was unreachable
        commands = (
            ["triage"],
            ["retrain", "--incidents", "i.csv", "--inventory", "v.json"],
            ["demo"],
        )
        for command in commands:
            for value in ("0", "-1"):
                with self.subTest(command=command[0], value=value):
                    with self.assertRaises(SystemExit):
                        self.parser().parse_args([*command, "--budget", value])

    def test_prior_k_must_be_finite_and_positive(self):
        # a negative or NaN k left every prior at zero, and the error then
        # blamed the user's incident records for a tuning flag
        base = ["retrain", "--incidents", "i.csv", "--inventory", "v.json"]
        for value in ("-1", "0", "nan", "inf"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.parser().parse_args([*base, "--prior-k", value])
        self.assertEqual(
            self.parser().parse_args([*base, "--prior-k", "2.5"]).prior_k, 2.5
        )

    def test_a_bidi_override_is_stripped_like_any_control_character(self):
        # rich strips neither C1 nor the bidi overrides, and one reorders the
        # line it lands in and knocks the table's columns out of alignment
        from meerkat.cli import safe
        self.assertEqual(safe("host\u202egnp.exe"), "hostgnp.exe")
        self.assertEqual(safe("a\u2066b\u2069c"), "abc")

    def test_two_runs_with_the_same_id_do_not_overwrite(self):
        # second-granularity ids meant two triages in one second interleaved
        # their pickles, the later latest.txt won, and both reported success
        from meerkat.cli import save_run
        runs = Path(tempfile.mkdtemp())
        frame = pd.DataFrame([{"a": 1}])
        first = save_run(runs, "acme-1", {}, frame, frame, frame)
        second = save_run(runs, "acme-1", {}, frame, frame, frame)
        self.assertNotEqual(first, second)
        self.assertEqual(
            (runs / "latest.txt").read_text(encoding="utf-8"), second.name
        )


class TestIncidentValidation(unittest.TestCase):
    def csv(self, body: str) -> Path:
        path = Path(tempfile.mkdtemp()) / "tickets.csv"
        path.write_text(body, encoding="utf-8")
        return path

    def test_a_swapped_start_and_end_is_named(self):
        # it matched nothing, and the user was told every incident was recent
        from core.incidents import load_incidents
        body = "start,end,host,verdict\n900,100,h,true_positive\n"
        with self.assertRaises(ValueError) as caught:
            load_incidents(self.csv(body))
        self.assertIn("after its end", str(caught.exception))

    def test_a_non_finite_time_is_refused(self):
        # NaN failed both sides of the holdout comparison, so the row vanished
        # from training and from scoring and the printed counts did not add up
        from core.incidents import load_incidents
        body = "start,end,host,verdict\nnan,inf,h,true_positive\n"
        with self.assertRaises(ValueError) as caught:
            load_incidents(self.csv(body))
        self.assertIn("finite", str(caught.exception))


class TestTechniqueParsing(unittest.TestCase):
    def test_a_single_technique_given_as_a_string_stays_one_technique(self):
        # "T1059" is iterable, so it used to join to "T;1;0;5;9" and
        # technique_count, a live re-ranker feature, read 5 instead of 1
        from core.inventory import Inventory
        from core.normalize import extract_wazuh_fields
        record = {
            "agent": {"name": "w", "ip": "10.0.0.1"},
            "rule": {"id": "1", "level": 5, "description": "d",
                     "mitre": {"id": "T1059"}},
        }
        fields = extract_wazuh_fields(record, Inventory("x", {}, {}))
        self.assertEqual(fields.native_technique_ids, "T1059")


class TestMissingBundle(unittest.TestCase):
    # triage, retrain and demo each checked for the bundle themselves and drift
    # did not, so the one command a new user runs against an unfetched LFS
    # clone answered with a traceback
    def test_every_command_that_loads_a_model_reports_it_missing(self):
        from meerkat import cli
        absent = Path(tempfile.mkdtemp()) / "meerkat_bundle.skops"
        with self.assertRaises(SystemExit) as caught:
            cli._require_bundle(absent)
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)

    def test_a_missing_input_directory_is_not_reported_as_a_missing_inventory(self):
        # require_directory only rejected a path that existed and was a file, so
        # a first run with nothing in place fell through to the inventory check
        # and blamed the inventory. The inventory is built from the alerts.
        from meerkat import cli
        absent = Path(tempfile.mkdtemp()) / "alerts"
        with self.assertRaises(SystemExit) as caught:
            cli.require_directory(absent)
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)

    def test_drift_goes_through_the_same_guard(self):
        # the guard lives in _load_bundle so a future command cannot forget it
        import inspect

        from meerkat import cli
        self.assertIn("_require_bundle", inspect.getsource(cli._load_bundle))


class TestNoStaleCommandNames(unittest.TestCase):
    def test_nothing_shipped_points_at_the_removed_train_command(self):
        # `meerkat train` moved to bench/ and is not in the installed package,
        # so an error message naming it sends the user to a command that no
        # longer parses
        root = Path(__file__).resolve().parent.parent
        offenders = []
        for package in ("core", "meerkat"):
            for path in (root / package).rglob("*.py"):
                if "meerkat train" in path.read_text(encoding="utf-8"):
                    offenders.append(path.name)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
