# bugs that reached a user, and the dead names removed after them

import argparse
import contextlib
import csv
import io
import json
import re
import tempfile
import unittest
import warnings
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

from core import classifier, features
from core.drift import build_profile, compare_profile
from core.features import standardize_severity
from core.inventory import Asset, Inventory, load_inventory
from core.normalize import get_timestamp, iter_normalized_rows, normalize_scenario
from core.sessions import FAMILY_KEY, SESSION_KEY, build_families, build_sessions

# Regression tests for the QA findings fixed before the first release.


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
        # the guard lives in _load_bundle so a future command cannot forget it,
        # and it has to answer before the export is read rather than after
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        (directory / "inventory").mkdir()
        inventory = directory / "inventory" / f"{directory.name}.json"
        inventory.write_text(
            json.dumps({"company": "x", "assets": [
                {"hostname": "h1", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}
            ]}), encoding="utf-8"
        )
        with (
            mock.patch.object(cli, "normalize_scenario") as read_alerts,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.cmd_drift(argparse.Namespace(
                model=directory / "absent.skops", input=directory, company=None,
                inventory=inventory, wazuh_file=None, aminer_file=None, top=5,
            ))
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertEqual(read_alerts.call_count, 0)


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


def wazuh_line(rule_id: str, description: str, timestamp: str) -> str:
    return json.dumps({
        "rule": {"id": rule_id, "level": 5, "description": description},
        "agent": {"ip": "10.0.0.1", "name": "wazuh-client"},
        "predecoder": {"hostname": "server"},
        "@timestamp": timestamp,
    })


def write_inventory(path: Path) -> Path:
    path.write_text(
        json.dumps({
            "company": "demo",
            "assets": [{
                "hostname": "server",
                "ip_addresses": ["10.0.0.1"],
                "groups": ["servers"],
            }],
        }),
        encoding="utf-8",
    )
    return path


class UndecodableAlertFileTests(unittest.TestCase):
    # a log line is attacker-influenced, so one byte that is not valid UTF-8
    # anywhere in a 45MB export used to abort the whole ingest with a
    # UnicodeDecodeError. sniff_alert_family already survived it, so discovery
    # accepted a file that ingestion then refused to read.

    def test_ingest_survives_an_invalid_byte_in_the_wazuh_export(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir = Path(directory)
            inventory_path = write_inventory(raw_dir / "inventory.json")
            wazuh_path = raw_dir / "demo_wazuh.json"

            clean = wazuh_line("100", "first", "2024-01-01T00:00:00Z")
            # 0x9c is a continuation byte with nothing in front of it, so utf-8
            # cannot decode it. It sits inside a JSON string, which keeps the
            # line parseable once the decoder replaces it.
            broken = wazuh_line("200", "second", "2024-01-01T00:10:00Z").encode()
            broken = broken.replace(b'"second"', b'"sec\x9cond"')
            wazuh_path.write_bytes(
                clean.encode("utf-8") + b"\n" + broken + b"\n"
            )

            rows = list(iter_normalized_rows(
                raw_dir, None, "demo", inventory_path
            ))

        self.assertEqual(len(rows), 2)
        self.assertEqual([row["rule_id"] for row in rows], ["100", "200"])
        # the bad byte becomes the replacement character rather than taking the
        # record with it
        self.assertIn("�", rows[1]["name"])

    def test_source_positions_still_line_up_after_a_replacement(self):
        # the event-label join is by line number, so replacing a byte must not
        # add or drop a line
        with tempfile.TemporaryDirectory() as directory:
            raw_dir = Path(directory)
            inventory_path = write_inventory(raw_dir / "inventory.json")
            wazuh_path = raw_dir / "demo_wazuh.json"
            lines = [
                wazuh_line("100", "first", "2024-01-01T00:00:00Z").encode(),
                wazuh_line("200", "second", "2024-01-01T00:10:00Z")
                .encode()
                .replace(b'"second"', b'"sec\xffond"'),
                wazuh_line("300", "third", "2024-01-01T00:20:00Z").encode(),
            ]
            wazuh_path.write_bytes(b"\n".join(lines) + b"\n")

            rows = list(iter_normalized_rows(
                raw_dir, None, "demo", inventory_path
            ))

        self.assertEqual([row["source_position"] for row in rows], [0, 1, 2])


class UnscaledDetectorTests(unittest.TestCase):
    # every detector that is not wazuh or suricata takes a flat 0.5. That is a
    # decision for aminer, which has no severity at all, and an accident for a
    # client detector nobody mapped: its alerts rank plausibly and say nothing.

    def setUp(self):
        self._warned = set(features._UNSCALED_DETECTORS_WARNED)
        features._UNSCALED_DETECTORS_WARNED.clear()

    def tearDown(self):
        features._UNSCALED_DETECTORS_WARNED.clear()
        features._UNSCALED_DETECTORS_WARNED.update(self._warned)

    def test_unmapped_detector_is_named_once(self):
        detectors = pd.Series(["crowdstrike"] * 3)
        severity = pd.Series([1.0, 2.0, 3.0])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            first = standardize_severity(detectors, severity)
            standardize_severity(detectors, severity)

        self.assertEqual(len(caught), 1)
        self.assertIn("crowdstrike", str(caught[0].message))
        # the value is unchanged; only the silence is
        self.assertEqual(list(first), [0.5, 0.5, 0.5])

    def test_mapped_detectors_stay_quiet(self):
        detectors = pd.Series(["wazuh", "suricata", "aminer"])
        severity = pd.Series([15.0, 1.0, float("nan")])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            standardized = standardize_severity(detectors, severity)

        self.assertEqual(caught, [])
        self.assertEqual(list(standardized), [1.0, 1.0, 0.5])


class SessionKeyTests(unittest.TestCase):
    def test_sessions_and_families_still_carry_the_key_columns(self):
        # the features and the CLI read these back off the row to describe a
        # unit, so grouping them away has to be undone on both frames
        asset = Asset("server", ("10.0.0.1",), ("servers",))
        inventory = Inventory("demo", {"10.0.0.1": asset}, {"server": "10.0.0.1"})
        alerts = pd.DataFrame({
            "timestamp": [0.0, 60.0, 100000.0],
            "entity_id": ["10.0.0.1"] * 3,
            "detector_source": ["wazuh"] * 3,
            "rule_id": ["100", "100", "100"],
            "severity": [5.0, 10.0, 3.0],
            "native_technique_ids": ["", "T1110", ""],
            "alert_category": ["authentication", "policy", ""],
            "rule_groups": ["auth", "auth;policy", ""],
            "entity_in_inventory": [True] * 3,
            "event_label": ["", "brute_force", ""],
            "window_id": [-1, 0, -1],
        })

        sessions = build_sessions(alerts, "demo", inventory)
        for name in SESSION_KEY:
            self.assertIn(name, sessions.columns)

        sessions["ranking_score"] = [0.9, 0.1]
        families = build_families(sessions)
        for name in FAMILY_KEY:
            self.assertIn(name, families.columns)
        # the two days do not merge, and the better child represents its family
        self.assertEqual(len(families), 2)
        self.assertEqual(
            families.sort_values("ranking_score", ascending=False)
            .iloc[0]["representative_session_id"],
            sessions.iloc[0]["session_id"],
        )


class RemovedNamesTests(unittest.TestCase):
    def test_dead_names_are_gone(self):
        # each of these had no caller anywhere in core, meerkat, bench or tests
        from core import classifier, normalize, sessions

        for module, name in (
            (normalize, "normalize"),
            (normalize, "build_normalized_frame"),
            (normalize, "write_day_partitioned"),
            (normalize, "iter_days"),
            (normalize, "SECONDS_PER_DAY"),
            (sessions, "DESCRIPTIVE"),
            (sessions, "SPLIT_SESSIONS_AT_MIDNIGHT"),
            (classifier, "SKOPS_SUFFIX"),
        ):
            with self.subTest(name=f"{module.__name__}.{name}"):
                self.assertFalse(hasattr(module, name))


# --------------------------------------------------------------------------
# hostile input: alert text, incident CSVs, inventories and model bundles are
# all written by someone outside the SOC
# --------------------------------------------------------------------------

# a closing tag with nothing open is a MarkupError, and a link tag is a real
# OSC-8 hyperlink in the text an analyst reads
BREAKS_MARKUP = "Mozilla/5.0 [/b] compatible"
FORGES_A_LINK = "[link=https://evil.example]GET /index.html[/link]"
OSC8 = "\x1b]8;"
_SGR = re.compile(r"\x1b\[[0-9;]*m")


def captured_console(width: int = 200):
    # a real terminal, because that is where a forged hyperlink would be drawn
    from rich.console import Console
    buffer = io.StringIO()
    return buffer, Console(file=buffer, width=width, force_terminal=True)


def plain(text: str) -> str:
    # rich colours a word at a time, so read the text back without the colours
    return _SGR.sub("", text)


def one_family_run():
    # the smallest RunState render_family and render_session will accept, with
    # every alert-written field carrying markup
    from meerkat.cli import RunState
    family = pd.Series({
        "handle": "F001",
        "family_id": f"acme#19013#10.0.0.1#wazuh#{BREAKS_MARKUP}",
        "entity_id": f"10.0.0.1 {BREAKS_MARKUP}",
        "rule_id": FORGES_A_LINK,
        "host_label": BREAKS_MARKUP,
        "title": FORGES_A_LINK,
        "detector_source": "wazuh",
        "asset_roles": ("server",),
        "day": 19013,
        "start": 0.0,
        "end": 60.0,
        "family_span_s": 60.0,
        "ranking_score": 0.9,
        "evidence_probability": 0.5,
        "alert_count": 1,
        "n_child_sessions": 1,
        "child_score_max": 0.9,
        "detectors_nearby_10m": 1,
        "technique_count": 1,
        # technique_name hands an id it does not know straight back
        "technique_id_set": frozenset({f"T1059 {BREAKS_MARKUP}"}),
        "child_session_ids": ("s1",),
        "alert_rows": (0,),
    })
    alerts = pd.DataFrame([{
        "timestamp": 0.0,
        "host": BREAKS_MARKUP,
        "name": FORGES_A_LINK,
        "rule_id": FORGES_A_LINK,
        "detector_source": "wazuh",
        "source_file": "acme_wazuh.json",
        "source_position": 0,
        "tactics": (),
        "technique_ids": "",
    }])
    sessions = pd.DataFrame([{
        "session_id": "s1",
        "detector_source": "wazuh",
        "rule_id": FORGES_A_LINK,
        "start": 0.0,
        "end": 60.0,
        "duration_s": 60.0,
        "size": 1,
        "ranking_score": 0.9,
    }])
    run = RunState(
        run_id="acme-1",
        directory=Path(tempfile.mkdtemp()),
        meta={"company": "acme", "budget": 10},
        families=pd.DataFrame([family]),
        sessions=sessions,
        alerts=alerts,
    )
    return run, family


class MarkupInAlertTextTests(unittest.TestCase):
    # safe() existed and was applied at eight sites. At the six below it was
    # missed, so a rule description of "Mozilla/5.0 [/b] compatible" raised
    # MarkupError and took out the view, and a [link=...] tag drew a live
    # hyperlink into the evidence an analyst is deciding on.

    def test_the_session_drill_down_survives_a_rule_name_with_a_closing_tag(self):
        from meerkat import cli
        run, family = one_family_run()
        session = run.sessions.iloc[0]
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            cli.render_session(family, "S1", session, run.alerts)
        text = buffer.getvalue()
        self.assertIn("[/b]", plain(text))
        self.assertNotIn(OSC8, text)

    def test_the_family_overview_escapes_every_alert_written_field(self):
        from meerkat import cli
        run, family = one_family_run()
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            cli.render_family(run, family, {})
        text = buffer.getvalue()
        # entity, rule, family_id and the unknown technique id all reach the
        # Overview block, and none of them may open a tag
        self.assertNotIn(OSC8, text)
        for fragment in ("10.0.0.1", "T1059", "acme#19013"):
            self.assertIn(fragment, plain(text))

    def test_an_unrecognised_role_from_the_inventory_is_escaped_when_scoring(self):
        # `check` escaped this same value and the triage path did not
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        inventory_path = directory / "acme.json"
        inventory_path.write_text(json.dumps({"company": "acme", "assets": [
            {"hostname": "h1", "ip_addresses": ["10.0.0.1"],
             "roles": [BREAKS_MARKUP]}]}), encoding="utf-8")
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            # no alert files in the directory, so it stops just after the warning
            with self.assertRaises(FileNotFoundError):
                cli._score_company(
                    None, directory, "acme", inventory_path, None, None
                )
        self.assertIn("unrecognised roles", buffer.getvalue())
        self.assertNotIn(OSC8, buffer.getvalue())

    def test_a_host_from_the_incident_csv_is_escaped_before_retrain_prints_it(self):
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        (directory / "alerts").mkdir()
        incidents = directory / "tickets.csv"
        incidents.write_text(
            f"start,end,host,verdict\n0,60,{FORGES_A_LINK},true_positive\n",
            encoding="utf-8",
        )
        inventory_path = directory / "acme.json"
        inventory_path.write_text(json.dumps({"company": "acme", "assets": [
            {"hostname": "h1", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}
        ]}), encoding="utf-8")
        model = directory / "m.skops"
        model.write_bytes(b"not a bundle at all")
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            # the warning prints, then the bundle gate refuses the dummy model.
            # The refusal arrives as an exit, not as a traceback: the message is
            # the control that tells the user what is wrong with the file.
            with self.assertRaises(SystemExit) as caught:
                cli.cmd_retrain(argparse.Namespace(
                    incidents=incidents, inventory=inventory_path, model=model,
                    input=directory / "alerts", company="acme",
                    wazuh_file=None, aminer_file=None,
                ))
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertIn("incident hosts are not in the", buffer.getvalue())
        self.assertNotIn(OSC8, buffer.getvalue())

    def test_a_cell_quoted_back_by_a_loader_is_escaped(self):
        # pandas names the value it could not convert, so an incident CSV with a
        # start of "[/b]" raised MarkupError from inside the handler that exists
        # to keep a bad file from printing a traceback
        from core.incidents import load_incidents
        from meerkat import cli
        path = Path(tempfile.mkdtemp()) / "tickets.csv"
        path.write_text(
            f"start,end,host,verdict\n{BREAKS_MARKUP},60,h,true_positive\n",
            encoding="utf-8",
        )
        buffer, console = captured_console()
        with mock.patch.object(cli, "errors", console):
            with self.assertRaises(SystemExit) as caught:
                cli._load_or_exit(load_incidents, path, "the incident records")
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertIn("could not be read", plain(buffer.getvalue()))

    def test_a_raw_source_line_names_its_file_without_opening_a_tag(self):
        # render_alert_rows escaped source_file and inspect --raw printed it
        # twice unescaped. A link tag needs no slash, so it survives being
        # joined onto a Windows path.
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        alert_slice = pd.DataFrame([
            {"source_file": "[link=x]acme.json", "source_position": 0}
        ])
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            cli._render_raw(alert_slice, directory, 5)
        self.assertIn("[link=x]", plain(buffer.getvalue()))
        self.assertNotIn(OSC8, buffer.getvalue())


class CsvExportTests(unittest.TestCase):
    # _csv_safe was tested on its own and `meerkat export-queue` was run by
    # nothing, so nothing checked that the export applies it to the file
    def export(self, host_label: str, title: str) -> list[dict]:
        from meerkat import cli
        runs = Path(tempfile.mkdtemp())
        run, family = one_family_run()
        family = family.copy()
        family["host_label"] = host_label
        family["title"] = title
        family["queue_rank"] = 0
        family["in_queue"] = True
        cli.save_run(
            runs, "acme-1", {"company": "acme", "budget": 10},
            pd.DataFrame([family]), run.sessions, run.alerts,
        )
        output = runs / "queue.csv"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_export_queue(argparse.Namespace(
                runs_dir=runs, run="acme-1", all=False, format="csv",
                output=output,
            ))
        with output.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_the_export_quotes_every_lead_a_spreadsheet_evaluates(self):
        # Excel evaluates a cell opening with any of these, and host_label is
        # whatever the machine that set the alert off calls itself
        for lead in ("=", "+", "-", "@", "\t"):
            with self.subTest(lead=lead):
                rows = self.export(f"{lead}cmd()", "a finding")
                self.assertEqual(rows[0]["host_label"], f"'{lead}cmd()")

    def test_the_export_strips_control_characters(self):
        rows = self.export("host\x1b[2Jname", "a\x00finding")
        self.assertEqual(rows[0]["host_label"], "host[2Jname")
        self.assertEqual(rows[0]["title"], "afinding")

    def test_an_empty_cell_exports_empty(self):
        # "" is in every string, so `value[:1] in "=+-@\t\r"` was True for a
        # blank cell and every empty field in every export shipped as "'"
        rows = self.export("", "")
        self.assertEqual(rows[0]["host_label"], "")
        self.assertEqual(rows[0]["title"], "")


class CsvBlankCellTests(unittest.TestCase):
    # "" is in every string, so `value[:1] in "=+-@\t\r"` was True for a blank
    # cell and every empty field in every export became a lone apostrophe
    def test_a_blank_cell_stays_blank(self):
        from meerkat.cli import _csv_safe
        self.assertEqual(_csv_safe(""), "")

    def test_a_formula_still_gets_its_apostrophe(self):
        from meerkat.cli import _csv_safe
        for cell in ("=cmd()", "+1", "-1", "@x", "\tx"):
            with self.subTest(cell=cell):
                self.assertEqual(_csv_safe(cell), "'" + cell)

    def test_a_leading_newline_no_longer_hides_the_formula(self):
        # \r never survives _CONTROL, and \n did, so this reached the
        # spreadsheet with = still at the front of the cell
        from meerkat.cli import _csv_safe
        self.assertEqual(
            _csv_safe("\n=HYPERLINK(1)"), "'\n=HYPERLINK(1)"
        )

    def test_the_whole_export_has_no_invented_apostrophes(self):
        from meerkat.cli import _csv_safe
        frame = pd.DataFrame([{"a": "", "b": None, "c": 1}])
        cleaned = frame.map(_csv_safe)
        self.assertEqual(cleaned.iloc[0]["a"], "")
        self.assertIsNone(cleaned.iloc[0]["b"])


def small_bundle(directory: Path) -> Path:
    from sklearn.ensemble import RandomForestClassifier
    X = pd.DataFrame({"a": np.arange(20.0), "b": np.zeros(20)})
    forest = RandomForestClassifier(n_estimators=2, random_state=0).fit(
        X, np.array([0, 1] * 10)
    )
    path = directory / "bundle.skops"
    classifier.save_model(forest, path)
    return path


def rewrite_members(source: Path, target: Path, edit) -> Path:
    with zipfile.ZipFile(source) as reader, zipfile.ZipFile(target, "w") as writer:
        for item in reader.infolist():
            writer.writestr(item.filename, edit(item.filename, reader.read(item.filename)))
    return target


class HostileBundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())

    def test_a_tree_with_a_child_index_past_its_nodes_is_refused(self):
        # skops blocks __reduce__, but Tree.__setstate__ checks dtype and shape
        # and never the values, so these indices used to load cleanly and then
        # read out of bounds inside Tree.apply, which is a segfault
        good = small_bundle(self.directory)

        def corrupt(name: str, raw: bytes) -> bytes:
            if not name.endswith(".npy"):
                return raw
            array = np.load(io.BytesIO(raw), allow_pickle=False)
            if not array.dtype.names or "left_child" not in array.dtype.names:
                return raw
            array = array.copy()
            array["left_child"][0] = 4_000_000
            out = io.BytesIO()
            np.save(out, array)
            return out.getvalue()

        evil = rewrite_members(good, self.directory / "evil.skops", corrupt)
        with self.assertRaises(classifier.UntrustedBundleError) as caught:
            classifier.load_model(evil)
        self.assertIn("malformed", str(caught.exception))

    def test_a_node_count_past_the_end_of_the_arrays_is_refused(self):
        # children_left slices to node_count, so a count past the array is a
        # short slice rather than an error
        class Tree:
            node_count = 4
            children_left = np.array([-1, -1])
            children_right = np.array([-1, -1])
            feature = np.array([-2, -2])
            n_features = 2

        class Estimator:
            tree_ = Tree()

        class Forest:
            estimators_ = [Estimator()]

        with self.assertRaises(classifier.UntrustedBundleError) as caught:
            classifier._refuse_malformed_forest(Path("evil.skops"), Forest())
        self.assertIn("malformed", str(caught.exception))

    def test_the_shipped_bundle_passes_the_structural_check(self):
        path = Path(__file__).resolve().parent.parent / "models/meerkat_bundle.skops"
        if not path.exists():
            self.skipTest("the bundle is not fetched")
        classifier.load_model(path)

    def test_a_zip_bomb_is_refused_before_it_is_unpacked(self):
        # a 204 KB file whose schema.json declares 200 MB drove peak allocation
        # to 459 MB inside get_untrusted_types, before the allowlist ran
        bomb = self.directory / "bomb.skops"
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("schema.json", json.dumps({"a": "b" * 50_000_000}))
        self.assertLess(bomb.stat().st_size, 1_000_000)
        with self.assertRaises(classifier.UntrustedBundleError) as caught:
            classifier.load_model(bomb)
        # the limit an operator would have to argue with is in the message
        self.assertIn(str(classifier.MAX_BUNDLE_RATIO), str(caught.exception))

    def test_the_size_limits_leave_room_for_a_real_bundle(self):
        # the shipped bundle is about 15 MB and skops stores its members
        # uncompressed, so both limits sit far above anything real
        self.assertGreaterEqual(classifier.MAX_BUNDLE_UNPACKED, 128 * 1024 * 1024)
        classifier.load_model(small_bundle(self.directory))

    def test_a_zip_without_schema_json_gets_the_gate_message(self):
        # every zip passed _is_skops, so this reached skops and came back as a
        # KeyError on the missing member
        path = self.directory / "empty.skops"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("nothing.txt", "x")
        with self.assertRaises(classifier.UntrustedBundleError) as caught:
            classifier.load_model(path)
        self.assertIn("not a skops bundle", str(caught.exception))

    def test_a_sidecar_that_is_not_an_object_gets_the_gate_message(self):
        # a bundle from elsewhere brings its own sidecar, and a list reached
        # .get and answered with an AttributeError
        path = self.directory / "bundle.skops"
        path.write_bytes(b"PK\x03\x04")
        for body in ("[]", '"x"', "{oops"):
            classifier.provenance_path(path).write_text(body, encoding="utf-8")
            with self.subTest(body=body):
                with self.assertRaises(classifier.UntrustedBundleError):
                    classifier.read_provenance(path)

    def test_a_written_sidecar_still_reads_back(self):
        path = small_bundle(self.directory)
        record = classifier.read_provenance(path)
        self.assertTrue(record["matches_file"])


class DeepJsonTests(unittest.TestCase):
    # json.loads recurses, so a record nested a few thousand deep raises
    # RecursionError rather than JSONDecodeError and escaped every handler
    # written for a bad line, ending triage, check, drift, retrain and
    # inspect --raw with a traceback
    DEEP = "{" + '"a":{' * 40_000

    def test_a_deeply_nested_raw_log_line_is_skipped(self):
        from core.normalize import aminer_host_candidates
        record = {"LogData": {"RawLogData": [self.DEEP]}}
        self.assertEqual(aminer_host_candidates(record), set())

    def test_a_deeply_nested_raw_log_line_still_yields_a_row(self):
        from core.inventory import Inventory
        from core.normalize import extract_aminer_fields
        record = {
            "AMiner": {"ID": "1"},
            "AnalysisComponent": {"AnalysisComponentName": "c"},
            "LogData": {"RawLogData": [self.DEEP], "LogResources": []},
        }
        fields = extract_aminer_fields(record, Inventory("x", {}, {}))
        self.assertTrue(np.isnan(fields.cpu_total_pct))

    def test_a_deeply_nested_alert_line_names_its_file_and_line(self):
        from core.normalize import AlertFileError, read_alert_record
        with self.assertRaises(AlertFileError) as caught:
            read_alert_record(self.DEEP, Path("acme_wazuh.json"), 41)
        self.assertIn("line 42", str(caught.exception))

    def test_inspect_raw_prints_a_deeply_nested_line_as_text(self):
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        (directory / "acme_wazuh.json").write_text(self.DEEP, encoding="utf-8")
        alert_slice = pd.DataFrame([
            {"source_file": "acme_wazuh.json", "source_position": 0}
        ])
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            cli._render_raw(alert_slice, directory, 5)
        self.assertIn("acme_wazuh.json", plain(buffer.getvalue()[:200]))


class RawSourceEncodingTests(unittest.TestCase):
    def test_inspect_raw_replaces_an_invalid_byte_like_every_ingest_path(self):
        # normalize opens every alert file with errors="replace"; this one path
        # did not, so one bad byte in a 45 MB export was a traceback
        from meerkat import cli
        directory = Path(tempfile.mkdtemp())
        (directory / "acme_wazuh.json").write_bytes(b'{"rule": "sec\x9cond"}\n')
        alert_slice = pd.DataFrame([
            {"source_file": "acme_wazuh.json", "source_position": 0}
        ])
        buffer, console = captured_console()
        with mock.patch.object(cli, "console", console):
            cli._render_raw(alert_slice, directory, 5)
        self.assertIn("acme_wazuh.json", plain(buffer.getvalue()[:200]))


class PandasPinTests(unittest.TestCase):
    def test_the_declared_pandas_is_new_enough_for_dataframe_map(self):
        # the csv export sanitises every cell with DataFrame.map, added in 2.1.
        # It fails closed rather than writing unsanitised output, but it fails.
        root = Path(__file__).resolve().parent.parent
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"pandas>=2.1"', text)
        self.assertTrue(hasattr(pd.DataFrame, "map"))


if __name__ == "__main__":
    unittest.main()
