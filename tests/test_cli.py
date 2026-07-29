# the command line: parsing, the saved run, what it prints and what it refuses

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

from core.classifier import provenance_path, save_model
from core.drift import PSI_MAJOR
from core.normalize import AMINER_FAMILY, WAZUH_FAMILY, resolve_alert_files
from meerkat import cli
from meerkat.cli import (
    EXIT_DECLINED,
    EXIT_ERROR,
    RULE_CARDINALITY_WARN,
    build_parser,
)


def make_alerts() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "timestamp": 100.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "source_file": "acme_wazuh.json", "source_position": 10,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 400.0, "http_method": "GET", "web_request": "/a",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 160.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "source_file": "acme_wazuh.json", "source_position": 11,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 404.0, "http_method": "GET", "web_request": "/b",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 900.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "source_file": "acme_wazuh.json", "source_position": 40,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 400.0, "http_method": "GET", "web_request": "/c",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 500.0, "detector_source": "suricata",
            "name": "ET SCAN probe", "host": "intranet-server",
            "source_file": "acme_suricata.json", "source_position": 3,
            "rule_id": "2001", "severity": 2.0, "alert_category": "recon",
            "http_status": float("nan"), "http_method": "", "web_request": "",
            "technique_ids": "", "tactics": (),
        },
    ])


def make_families() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "day": 0, "entity_id": "10.0.0.5", "detector_source": "wazuh",
            "rule_id": "31101", "ranking_score": 0.9,
            "evidence_probability": 0.8, "start": 100.0, "end": 900.0,
            "family_span_s": 800.0, "representative_session_id": "acme#0",
            "alert_rows": [0, 1, 2], "alert_count": 3, "n_child_sessions": 2,
            "child_session_ids": ["acme#0", "acme#1"], "child_score_max": 0.9,
            "detectors_nearby_10m": 2.0, "technique_count": 1,
            "technique_id_set": frozenset({"T1595"}), "family_positive": True,
            "asset_roles": ("intranet", "servers"),
            "labelled_windows": frozenset({0}),
            "temporal_overlap_windows": frozenset({0}),
            "labelled_alert_count": 2, "family_id": "acme#0#10.0.0.5#wazuh#31101",
        },
        {
            "day": 0, "entity_id": "10.0.0.5", "detector_source": "suricata",
            "rule_id": "2001", "ranking_score": 0.4,
            "evidence_probability": 0.3, "start": 500.0, "end": 500.0,
            "family_span_s": 0.0, "representative_session_id": "acme#2",
            "alert_rows": [3], "alert_count": 1, "n_child_sessions": 1,
            "child_session_ids": ["acme#2"], "child_score_max": 0.4,
            "detectors_nearby_10m": 2.0, "technique_count": 0,
            "technique_id_set": frozenset(), "family_positive": False,
            "asset_roles": (),
            "labelled_windows": frozenset(),
            "temporal_overlap_windows": frozenset(),
            "labelled_alert_count": 0, "family_id": "acme#0#10.0.0.5#suricata#2001",
        },
    ])


def make_sessions() -> pd.DataFrame:
    return pd.DataFrame([
        {"session_id": "acme#0", "start": 100.0, "end": 160.0,
         "duration_s": 60.0, "size": 2, "ranking_score": 0.9,
         "detector_source": "wazuh", "rule_id": "31101", "alert_rows": [0, 1]},
        {"session_id": "acme#1", "start": 900.0, "end": 900.0,
         "duration_s": 0.0, "size": 1, "ranking_score": 0.7,
         "detector_source": "wazuh", "rule_id": "31101", "alert_rows": [2]},
        {"session_id": "acme#2", "start": 500.0, "end": 500.0,
         "duration_s": 0.0, "size": 1, "ranking_score": 0.4,
         "detector_source": "suricata", "rule_id": "2001", "alert_rows": [3]},
    ])


class HandleTests(unittest.TestCase):
    def test_handles_follow_queue_order_and_budget(self):
        # F001 is handed out down the queue order, so the day's top family is
        # always F001 and budget 1 leaves F002 out of in_queue
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=1)
        by_score = decorated.sort_values("ranking_score", ascending=False)
        self.assertEqual(list(by_score["handle"]), ["F1", "F2"])
        top = decorated[decorated["handle"].eq("F1")].iloc[0]
        bottom = decorated[decorated["handle"].eq("F2")].iloc[0]
        self.assertTrue(top["in_queue"])
        self.assertFalse(bottom["in_queue"])

    def test_title_and_host_come_from_alerts(self):
        # a family key holds only entity_id and rule_id, so the readable host
        # and finding are the mode over the alerts the family covers. The odd
        # rows sit first and last and sort either side of the majority, so
        # first, last, min and max each give a different answer from the mode.
        alerts = pd.DataFrame([
            {"name": "aaa scan", "host": "aaa-host"},
            {"name": "mmm probe", "host": "mmm-host"},
            {"name": "mmm probe", "host": "mmm-host"},
            {"name": "zzz flood", "host": "zzz-host"},
        ])
        families = pd.DataFrame([{
            "day": 0, "entity_id": "10.0.0.5", "ranking_score": 0.9,
            "start": 100.0, "representative_session_id": "acme#0",
            "alert_rows": [0, 1, 2, 3],
        }])
        top = cli.decorate_families(families, alerts, budget=2).iloc[0]
        self.assertEqual(top["host_label"], "mmm-host")
        self.assertEqual(top["title"], "mmm probe")

    def test_a_family_whose_alerts_name_no_host_falls_back_to_the_entity(self):
        # entity_id is the address the session keyed on, and it is the only
        # label left when every covered alert has an empty host field
        alerts = pd.DataFrame([{"name": "", "host": ""}])
        families = pd.DataFrame([{
            "day": 0, "entity_id": "10.0.0.5", "ranking_score": 0.9,
            "start": 100.0, "representative_session_id": "acme#0",
            "alert_rows": [0],
        }])
        top = cli.decorate_families(families, alerts, budget=1).iloc[0]
        self.assertEqual(top["host_label"], "10.0.0.5")
        self.assertEqual(top["title"], "")


class RunRoundTripTests(unittest.TestCase):
    def _save(self, runs_dir: Path, run_id: str) -> None:
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=1)
        cli.save_run(
            runs_dir, run_id, {"company": "acme", "budget": 1},
            decorated, make_sessions(), make_alerts(),
        )

    def test_latest_pointer_tracks_newest_good_run(self):
        # latest.txt is written after the pickles, so a run that died halfway
        # is never the one a bare `meerkat queue` reopens
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._save(runs, "acme-1")
            self._save(runs, "acme-2")
            self.assertEqual(cli.latest_run_id(runs), "acme-2")
            run = cli.load_run(runs)
            self.assertEqual(run.run_id, "acme-2")
            self.assertEqual(len(run.families), 2)

    def test_a_run_that_died_before_run_json_is_not_the_latest(self):
        # the pickles land first and run.json last, so a triage killed between
        # the two leaves a directory that must never be what `queue` reopens
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._save(runs, "acme-1")
            half_written = runs / "acme-2"
            half_written.mkdir()
            for name in ("families.pkl", "sessions.pkl", "alerts.pkl"):
                (half_written / name).write_bytes(
                    (runs / "acme-1" / name).read_bytes()
                )
            self.assertEqual(cli.latest_run_id(runs), "acme-1")
            self.assertEqual(cli.load_run(runs).run_id, "acme-1")
            # naming it outright still reports what is missing rather than
            # unpickling three files and failing on the metadata
            with self.assertRaises(FileNotFoundError):
                cli.load_run(runs, "acme-2")

    def test_handles_and_related_resolve_after_reload(self):
        # the read commands reopen the run rather than scoring again, so f001
        # still resolves and S1/S2 keep the order build_families sorted
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._save(runs, "acme-1")
            run = cli.load_run(runs, "acme-1")
            family = run.family_by_handle("f001")
            self.assertEqual(family["rule_id"], "31101")
            self.assertEqual(
                [handle for handle, _ in run.session_handles(family)],
                ["S1", "S2"],
            )
            related = run.related_families(family)
            self.assertEqual(list(related["handle"]), ["F2"])
            self.assertNotEqual(
                related.iloc[0]["detector_source"], family["detector_source"]
            )


class ReviewTests(unittest.TestCase):
    def test_append_only_history_last_entry_wins(self):
        # reviews.jsonl is append only so the audit trail survives, and the
        # family's current state is whichever line was written last
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cli.append_review(
                directory, "acme-1", "fid", "F001", "escalate", "look again"
            )
            cli.append_review(
                directory, "acme-1", "fid", "F001", "benign", "approved scanner"
            )
            history = cli.review_history(directory)
            self.assertEqual(len(history), 2)
            current = cli.current_reviews(directory)
            self.assertEqual(current["fid"]["decision"], "benign")


class DecisionExportTests(unittest.TestCase):
    def test_decisions_propagate_family_wide_unless_a_session_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=2
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 2},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            family = run.family_by_handle("F1")
            cli.append_review(
                run.directory, "acme-1", family["family_id"],
                "F1", "benign", "known scanner",
            )
            cli.append_review(
                run.directory, "acme-1", family["family_id"],
                "F1", "escalate", "this burst is real",
                session_key="k", session_handle="S1",
            )
            rows = cli.decision_rows(run, run.families)
            by_session = {}
            for row in rows:
                if row["family"] == "F1":
                    by_session.setdefault(row["session"], row)
            self.assertEqual(by_session["S1"]["decision"], "escalate")
            self.assertEqual(by_session["S1"]["decided_by"], "session")
            self.assertEqual(by_session["S2"]["decision"], "benign")
            self.assertEqual(by_session["S2"]["decided_by"], "family")

    def test_a_later_family_decision_covers_everything_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=2
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 2},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            family = run.family_by_handle("F1")
            cli.append_review(
                run.directory, "acme-1", family["family_id"],
                "F1", "escalate", "", session_key="k", session_handle="S1",
            )
            cli.append_review(
                run.directory, "acme-1", family["family_id"],
                "F1", "false-positive", "all noise after checking",
            )
            rows = cli.decision_rows(run, run.families)
            decisions = {
                row["session"]: row["decision"]
                for row in rows if row["family"] == "F1"
            }
            self.assertEqual(set(decisions.values()), {"false-positive"})


class HtmlExportTests(unittest.TestCase):
    @staticmethod
    def _text(page):
        # rich wraps every number in a styled span; content assertions
        # read the page the way a browser shows it
        return re.sub(r"<[^>]+>", "", page)

    def _saved_run(self, runs):
        decorated = cli.decorate_families(
            make_families(), make_alerts(), budget=2
        )
        cli.save_run(
            runs, "acme-1", {"company": "acme", "budget": 2},
            decorated, make_sessions(), make_alerts(),
        )

    def test_escalations_carry_evidence_closed_take_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._saved_run(runs)
            run = cli.load_run(runs, "acme-1")
            f1 = run.family_by_handle("F1")
            f2 = run.family_by_handle("F2")
            cli.append_review(
                run.directory, "acme-1", f1["family_id"], "F1",
                "escalate", "this burst is real",
                session_key="k", session_handle="S1", analyst="jwang",
            )
            cli.append_review(
                run.directory, "acme-1", f2["family_id"], "F2",
                "benign", "known scanner", analyst="jwang",
            )
            output = runs / "report.html"
            keep_console = cli.console
            cli.cmd_export_html(argparse.Namespace(
                runs_dir=runs, run="acme-1", handle=None, output=output,
            ))
            self.assertIs(cli.console, keep_console)
            page = output.read_text(encoding="utf-8")
            text = self._text(page)
            self.assertIn("<title>meerkat acme-1</title>", page)
            self.assertIn("escalated 1", text)
            self.assertIn("closed 1", text)
            self.assertIn("unreviewed 0", text)
            # only the escalated family ships its full view
            self.assertEqual(text.count("Overview"), 1)
            self.assertIn("escalate (S1)", text)
            self.assertIn("Closed", text)
            self.assertIn("known scanner", text)
            self.assertIn("jwang", text)
            self.assertNotIn("[bold]", page)

    def test_an_unreviewed_run_says_so_instead_of_dumping_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._saved_run(runs)
            output = runs / "report.html"
            cli.cmd_export_html(argparse.Namespace(
                runs_dir=runs, run="acme-1", handle=None, output=output,
            ))
            text = self._text(output.read_text(encoding="utf-8"))
            run = cli.load_run(runs, "acme-1")
            queued = run.families[run.families["in_queue"]]
            self.assertIn(f"unreviewed {len(queued)}", text)
            self.assertIn(f"Unreviewed ({len(queued)} of {len(queued)})", text)
            self.assertEqual(text.count("Overview"), 0)

    def test_hostile_alert_text_cannot_script_the_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            alerts = make_alerts()
            alerts["name"] = (
                "<script>alert(1)</script> [red]boom[/red] \x07 "
                "[link=javascript:alert(1)]x[/link]"
            )
            decorated = cli.decorate_families(
                make_families(), alerts, budget=2
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 2},
                decorated, make_sessions(), alerts,
            )
            run = cli.load_run(runs, "acme-1")
            f1 = run.family_by_handle("F1")
            cli.append_review(
                run.directory, "acme-1", f1["family_id"], "F1",
                "escalate", "<img src=x onerror=alert(2)>", analyst="jwang",
            )
            output = runs / "report.html"
            cli.cmd_export_html(argparse.Namespace(
                runs_dir=runs, run="acme-1", handle=None, output=output,
            ))
            page = output.read_text(encoding="utf-8")
            self.assertNotIn("<script", page)
            self.assertIn("&lt;script&gt;", page)
            self.assertNotIn("<img", page)
            self.assertNotIn("\x07", page)
            # rich link markup would export as a real anchor; the only
            # anchors allowed are the vetted attack.mitre.org technique links
            self.assertNotIn("javascript:", page)
            for href in re.findall(r'href="([^"]*)"', page):
                self.assertTrue(href.startswith("https://attack.mitre.org/"))

    def test_an_output_path_the_os_refuses_is_an_error_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._saved_run(runs)
            with cli.errors.capture() as captured:
                with self.assertRaises(SystemExit) as caught:
                    cli.main([
                        "export", "html", "--runs-dir", str(runs),
                        "--run", "acme-1", "--output", tmp,
                    ])
            self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
            self.assertIn("Errno", captured.get())

    def test_one_family_page_and_a_wrong_handle(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._saved_run(runs)
            output = runs / "family.html"
            cli.cmd_export_html(argparse.Namespace(
                runs_dir=runs, run="acme-1", handle="F1", output=output,
            ))
            page = output.read_text(encoding="utf-8")
            self.assertIn("<title>meerkat acme-1 F1</title>", page)
            self.assertNotIn("Review queue", page)
            with self.assertRaises(SystemExit) as caught:
                cli.cmd_export_html(argparse.Namespace(
                    runs_dir=runs, run="acme-1", handle="F999", output=None,
                ))
            self.assertEqual(caught.exception.code, cli.EXIT_ERROR)


class FilterTests(unittest.TestCase):
    def test_match_handles_float_and_string_fields(self):
        # an analyst types --where http_status=400 as text against a float
        # column, so 400 and 400.0 have to compare as the same value
        alerts = make_alerts()
        kept = cli._apply_filters(alerts, [("http_status", "400")], [])
        self.assertEqual(len(kept), 2)
        dropped = cli._apply_filters(alerts, [], [("http_status", "404")])
        self.assertNotIn(404.0, dropped["http_status"].tolist())
        by_rule = cli._apply_filters(alerts, [("rule_id", "2001")], [])
        self.assertEqual(len(by_rule), 1)

    def test_match_numeric_series_directly(self):
        # the typed value always arrives as a string, so a float column parses
        # it once and returns a mask over the rows
        series = pd.Series([400.0, 404.0])
        self.assertEqual(cli._match(series, "400").tolist(), [True, False])


class PanelTests(unittest.TestCase):
    def _capture(self, call) -> str:
        # the CLI renders through its module-level rich console, which resolves
        # sys.stdout lazily, so redirecting stdout captures the output
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            call()
        return buffer.getvalue()

    def test_http_panel_shows_process_panel_hidden(self):
        # a panel with nothing in it is skipped outright
        text = self._capture(
            lambda: cli._render_panels(make_alerts().iloc[[0, 1]])
        )
        self.assertIn("Network / HTTP", text)
        self.assertIn("Provenance", text)
        self.assertNotIn("Process / System", text)

    def test_http_outcome_leads_with_the_verdict(self):
        # whether anything got through is the first question on a web attack,
        # so the count of successes leads and the codes follow as detail
        all_404 = pd.DataFrame({"http_status": [404.0] * 6})
        mixed = pd.DataFrame(
            {"http_status": [200.0, 200.0, 302.0, 404.0, 500.0]}
        )

        self.assertEqual(
            cli._http_outcome(all_404), "6 requests, none succeeded (404)"
        )
        self.assertEqual(
            cli._http_outcome(mixed),
            "5 requests, 3 succeeded (200, 302) of 200, 302, 404, 500",
        )

    def test_family_and_session_overviews_show_http_outcome(self):
        # the outcome line is recomputed over whatever alerts are in scope, so
        # the family reads 3 requests and drilling into S1 reads 2
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            alerts = make_alerts()
            alerts.loc[[0, 1, 2], "http_status"] = 404.0
            decorated = cli.decorate_families(
                make_families(), alerts, budget=1
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 1},
                decorated, make_sessions(), alerts,
            )
            run = cli.load_run(runs, "acme-1")
            family = run.family_by_handle("F001")
            family_text = self._capture(
                lambda: cli.render_family(run, family, {})
            )
            handle, session_id = run.session_handles(family)[0]
            session = run.sessions[
                run.sessions["session_id"].eq(session_id)
            ].iloc[0]
            session_text = self._capture(
                lambda: cli.render_session(
                    family, handle, session, run.session_alerts(session)
                )
            )

            # the label column is padded to the widest label, so read both
            # back with the whitespace squashed rather than pinning the width
            self.assertIn(
                "outcome : 3 requests, none succeeded (404)",
                " ".join(family_text.split()),
            )
            self.assertIn(
                "outcome: 2 requests, none succeeded (404)",
                " ".join(session_text.split()),
            )

    def test_family_overview_omits_outcome_without_http_status(self):
        # only HTTP carries success semantics in the normalized schema, so a
        # suricata family prints no outcome line at all
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=2
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 2},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F002"), {})
            )
            self.assertNotIn("outcome", text)

    def test_family_view_renders_without_error(self):
        # the whole family view renders in one pass, so a broken ATT&CK story
        # or related-host block shows up here as a traceback
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=1
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 1},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F001"), {})
            )
            self.assertIn("Related ATT&CK observations", text)
            self.assertIn("Reconnaissance", text)
            self.assertIn("Related families on this host", text)

    def test_family_overview_shows_known_asset_roles(self):
        # asset role is the largest feature block, so the roles behind the
        # score are printed where they can be checked against the inventory
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=1
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 1},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F001"), {})
            )
            self.assertIn("asset : intranet, servers", " ".join(text.split()))

    def test_family_overview_omits_empty_asset_roles(self):
        # a host outside the inventory has no roles, and an empty asset line
        # would read as a fact about the host
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=2
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 2},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F002"), {})
            )
            self.assertNotIn("asset :", " ".join(text.split()))

    def test_family_overview_compares_volume_with_three_rule_peers(self):
        # 40 alerts says nothing on its own, so it is put against the median
        # for the same rule in this run once three peers exist
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=1
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 1},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            current = run.families["handle"].eq("F1")
            run.families.loc[current, "alert_count"] = 40
            family = run.family_by_handle("F001")
            peers = []
            for number, count in enumerate((10, 20, 30), start=3):
                peer = family.copy()
                peer["handle"] = f"F{number}"
                peer["family_id"] = f"peer-{number}"
                peer["entity_id"] = f"10.0.0.{number}"
                peer["alert_count"] = count
                peers.append(peer)
            run.families = pd.concat(
                [run.families, pd.DataFrame(peers)], ignore_index=True
            )

            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F001"), {})
            )
            self.assertIn(
                "40 alerts, 2 sessions, "
                "2x the median for this rule in this run",
                " ".join(text.split()),
            )

    def test_family_overview_omits_volume_comparison_below_three_peers(self):
        # a median over one or two peers is noise, so the comparison is
        # dropped rather than printed with nothing behind it
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            decorated = cli.decorate_families(
                make_families(), make_alerts(), budget=1
            )
            cli.save_run(
                runs, "acme-1", {"company": "acme", "budget": 1},
                decorated, make_sessions(), make_alerts(),
            )
            run = cli.load_run(runs, "acme-1")
            text = self._capture(
                lambda: cli.render_family(run, run.family_by_handle("F001"), {})
            )
            self.assertNotIn("median for this rule", text)


class OutcomeTests(unittest.TestCase):
    def outcome(self, statuses) -> str:
        return cli._http_outcome(pd.DataFrame({"http_status": statuses}))

    def test_nothing_succeeded_is_stated_not_implied(self):
        # a wall of 404s is the common shape, and reading that off the codes
        # alone costs an analyst longer than the sentence does
        self.assertEqual(
            self.outcome([404.0] * 6), "6 requests, none succeeded (404)"
        )
        self.assertEqual(
            self.outcome([403.0, 404.0, 405.0]),
            "3 requests, none succeeded (403, 404, 405)",
        )

    def test_mixed_leads_with_how_many_got_through(self):
        # no family in the demo run mixes success and failure, so this path has
        # no live coverage and is the one that matters most to an analyst
        statuses = [404.0] * 45 + [200.0] * 3
        self.assertEqual(
            self.outcome(statuses),
            "48 requests, 3 succeeded (200) of 200, 404",
        )

    def test_all_succeeded_and_single_request(self):
        # one request would otherwise read as "1 requests", and 304 counts as
        # success because the 200-399 range is what decides it
        self.assertEqual(
            self.outcome([200.0, 304.0]), "2 requests, all succeeded (200, 304)"
        )
        self.assertEqual(self.outcome([200.0]), "1 request, succeeded (200)")
        self.assertEqual(self.outcome([404.0]), "1 request, failed (404)")

    def test_absent_or_empty_http_renders_nothing(self):
        # aminer and most wazuh alerts have no http_status at all, so the
        # outcome line disappears rather than rendering an empty verdict
        self.assertEqual(self.outcome([float("nan")] * 3), "")
        self.assertEqual(cli._http_outcome(pd.DataFrame({"name": ["x"]})), "")


class QueueSelectionTests(unittest.TestCase):
    def _run(self, runs: Path) -> cli.RunState:
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=1)
        cli.save_run(
            runs, "acme-1", {"company": "acme", "budget": 1},
            decorated, make_sessions(), make_alerts(),
        )
        return cli.load_run(runs, "acme-1")

    def test_default_scope_is_top_k_but_a_filter_sees_all(self):
        # "show me everything on this host" has to reach families below the
        # queue line, so any filter widens the scope to the whole run
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            default = cli._select_families(run, False, None, None, None, None)
            self.assertEqual(len(default), 1)  # budget 1, one family in queue
            by_detector = cli._select_families(
                run, False, None, "suricata", None, None
            )
            # F002 is suricata and below the queue line, a filter still finds it
            self.assertEqual(list(by_detector["handle"]), ["F2"])

    def test_day_filter_keeps_the_daily_budget(self):
        # --day picks one day and keeps that day's top-K, so it never widens
        # past the budget the way a host or detector filter does
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            same_day = cli._select_families(
                run, False, None, None, None, None, cli.fmt_date(0)
            )
            # --day narrows to one day without widening past the budget
            self.assertEqual(len(same_day), 1)

    def test_unknown_day_is_rejected(self):
        # a mistyped date would print an empty queue that reads as a quiet
        # day, so it exits and lists the days the run actually covers
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            with self.assertRaises(SystemExit):
                cli._select_families(
                    run, False, None, None, None, None, "1999-01-01"
                )

    def test_review_state_filter_matches_recorded_decision(self):
        # decisions live in reviews.jsonl beside the run, so --review-state
        # finds F002 by family_id after the run was reopened from disk
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            cli.append_review(
                run.directory, run.run_id,
                "acme#0#10.0.0.5#suricata#2001", "F002", "escalate", "",
            )
            escalated = cli._select_families(
                run, False, None, None, None, "escalate"
            )
            self.assertEqual(list(escalated["handle"]), ["F2"])


class LfsTests(unittest.TestCase):
    def test_pointer_file_detected(self):
        # a clone without `git lfs pull` gets a text stub where the alerts
        # should be, and json parsing it would fail much later and worse
        with tempfile.TemporaryDirectory() as tmp:
            pointer = Path(tmp) / "big.json"
            pointer.write_text(
                "version https://git-lfs.github.com/spec/v1\noid sha256:abc\n"
            )
            self.assertTrue(cli._is_lfs_pointer(pointer))
            real = Path(tmp) / "real.json"
            real.write_text('{"detector_source": "wazuh"}\n')
            self.assertFalse(cli._is_lfs_pointer(real))


# The parts of the CLI a script depends on: where alert files are found, which
# stream errors go to, and what the exit codes mean.


def directory(*names: str) -> Path:
    made = Path(tempfile.mkdtemp())
    for name in names:
        (made / name).write_text("{}\n", encoding="utf-8")
    return made


class TestAlertFileDiscovery(unittest.TestCase):
    def test_the_ait_naming_still_works_with_no_flags(self):
        # every AIT company and the demo rely on <company>_wazuh.json, so
        # adding the override flags must not move the default path
        raw = directory("acme_wazuh.json", "acme_aminer.json")
        files = resolve_alert_files(raw, "acme")
        self.assertEqual(
            [(path.name, family) for path, family in files],
            [("acme_aminer.json", AMINER_FAMILY), ("acme_wazuh.json", WAZUH_FAMILY)],
        )

    def test_a_named_file_wins_over_the_convention(self):
        # a SIEM export is called whatever the SIEM called it, so a named file
        # is taken even with the conventional one in the same directory
        raw = directory("acme_wazuh.json")
        chosen = raw / "exported-alerts.json"
        chosen.write_text("{}\n", encoding="utf-8")
        files = resolve_alert_files(raw, "acme", wazuh_path=chosen)
        self.assertEqual([path for path, _ in files], [chosen])

    def test_the_miner_alone_is_enough(self):
        # resolve_alert_files lists only the files that are there, so a company
        # running only the miner still resolves
        raw = directory("acme_aminer.json")
        files = resolve_alert_files(raw, "acme")
        self.assertEqual([(p.name, f) for p, f in files],
                         [("acme_aminer.json", AMINER_FAMILY)])

    def test_a_client_whose_export_is_named_differently_is_told_what_to_do(self):
        # the whole point: a real wazuh export is not called <company>_wazuh.json,
        # and the error has to name the files that ARE there and the flag to use
        raw = directory("alerts-2026-07-26.json", "archive.json")
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(raw, "acme")
        message = str(caught.exception)
        self.assertIn("alerts-2026-07-26.json", message)
        self.assertIn("--wazuh-file", message)

    def test_an_empty_directory_says_so_rather_than_listing_nothing(self):
        # an empty --input is usually the wrong directory, and a file list of
        # nothing would read as the files being there but unreadable
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(directory(), "acme")
        self.assertIn("no json files", str(caught.exception))


class TestExitCodes(unittest.TestCase):
    def test_a_declined_retrain_is_not_the_same_code_as_a_crash(self):
        # a wrapper script has to tell "the gate said no", which is the gate
        # working, apart from "the tool broke"
        self.assertNotEqual(EXIT_DECLINED, EXIT_ERROR)
        self.assertEqual(EXIT_ERROR, 1)
        self.assertEqual(EXIT_DECLINED, 3)


class TestParserContract(unittest.TestCase):
    def test_triage_finds_the_inventory_the_inventory_command_wrote(self):
        # --inventory resolves to None so triage can fill in where `meerkat
        # inventory` wrote it, which needs --input and --environment first
        args = build_parser().parse_args(["triage", "--environment", "acme"])
        cli._apply_config(args)
        self.assertIsNone(args.inventory)

    def test_alert_file_overrides_reach_triage_and_retrain(self):
        # both commands normalize the same alert files, so the overrides are
        # attached to each rather than to triage alone
        parser = build_parser()
        triage = parser.parse_args([
            "triage", "--environment", "acme", "--wazuh-file", "w.json",
        ])
        retrain = parser.parse_args([
            "retrain", "--environment", "acme", "--incidents", "i.csv",
            "--inventory", "inv.json", "--aminer-file", "a.json",
        ])
        self.assertEqual(triage.wazuh_file, Path("w.json"))
        self.assertEqual(retrain.aminer_file, Path("a.json"))

    def test_the_bag_size_discount_defaults_to_one_per_ticket(self):
        # k=1 keeps every ticket's total weight at 1.0 whatever its width, and
        # five fits are what the majority gate counts
        args = build_parser().parse_args([
            "retrain", "--environment", "acme", "--incidents", "i.csv",
            "--inventory", "inv.json",
        ])
        self.assertEqual(args.prior_k, 1.0)
        self.assertEqual(args.fits, 5)

    def test_the_read_commands_can_emit_json(self):
        # a wrapper script reads the queue and the run list, so both take
        # --json, and errors go to stderr to keep the pipe parseable
        parser = build_parser()
        self.assertTrue(parser.parse_args(["queue", "--json"]).json)
        self.assertTrue(parser.parse_args(["runs", "--json"]).json)

    def test_the_queue_can_leave_as_csv_for_a_ticketing_system(self):
        # a ticketing system imports csv more often than json, so csv is what
        # an analyst gets without having to think about the flag
        args = build_parser().parse_args(["export", "queue", "--format", "csv"])
        self.assertEqual(args.format, "csv")


# Each of these reached the user as a traceback, a message naming the wrong
# thing, or a full scoring run spent before an argument was looked at.


WAZUH_ALERT = {
    "@timestamp": "2026-01-01T00:00:00Z",
    "agent": {"name": "collector", "ip": "10.0.0.9"},
    "predecoder": {"hostname": "web01"},
    "rule": {"id": "5501", "level": 5, "description": "User login"},
}

# a line suricata writes to eve.json itself, with no wazuh envelope around it
EVE_ALERT = {
    "timestamp": "2026-01-01T00:05:00.000000+0000",
    "event_type": "alert",
    "src_ip": "10.0.0.9",
    "dest_ip": "10.0.0.9",
    "proto": "TCP",
    "alert": {
        "signature_id": 2009582,
        "signature": "ET SCAN Nmap Scripting Engine",
        "category": "Attempted Information Leak",
        "severity": 2,
    },
}


def temporary_directory() -> Path:
    return Path(tempfile.mkdtemp())


def squashed(text: str) -> str:
    # rich wraps at the console width, so a token can arrive split over two lines
    return re.sub(r"\s+", "", text)


def write_lines(path: Path, records: list[dict], bom: bool = False) -> Path:
    body = "".join(json.dumps(record) + "\n" for record in records)
    path.write_text("﻿" + body if bom else body, encoding="utf-8")
    return path


def write_inventory(path: Path, assets: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"company": "acme", "assets": assets}), encoding="utf-8"
    )
    return path


class FakeInventory:
    unknown_roles: tuple[str, ...] = ()
    assets_by_ip: dict = {}

    def assets_without_roles(self) -> tuple[str, ...]:
        return ()


class EmptyInputTests(unittest.TestCase):
    def test_triage_reports_no_alerts_the_way_check_does(self):
        # the empty feature matrix used to reach the forest, and the answer was
        # sklearn's "Found array with 0 sample(s) (shape=(0, 31))"
        errors = io.StringIO()
        with (
            mock.patch.object(cli, "load_inventory", return_value=FakeInventory()),
            mock.patch.object(cli, "normalize_scenario", return_value=pd.DataFrame()),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as caught,
        ):
            cli._score_company(
                None, temporary_directory(), "acme", Path("inventory.json"),
                None, None,
            )
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertIn("no alerts parsed", errors.getvalue())


class RunsDirectoryMessageTests(unittest.TestCase):
    def test_an_empty_runs_directory_names_the_flag_that_fixes_it(self):
        # triage in one directory and queue in another was told to run triage,
        # which it had. The default runs/ is resolved from the working directory.
        with self.assertRaises(FileNotFoundError) as caught:
            cli.load_run(Path("no_such_runs_directory"))
        message = str(caught.exception)
        self.assertIn("--runs-dir", message)
        self.assertIn("current directory", message)

    def test_an_absolute_runs_directory_is_not_told_it_is_relative(self):
        # the advice only holds for a path the working directory resolves
        with self.assertRaises(FileNotFoundError) as caught:
            cli.load_run(temporary_directory())
        self.assertNotIn("current directory", str(caught.exception))


class CompanyValidationTests(unittest.TestCase):
    def parse(self, arguments: list[str]):
        # argparse prints the usage block to stderr on a refusal, which is the
        # right place for it and only noise in a test run
        with contextlib.redirect_stderr(io.StringIO()):
            return cli.build_parser().parse_args(arguments)

    def test_a_company_with_a_path_in_it_is_refused_before_any_work(self):
        # it was checked in new_run_id, which runs after the whole dataset has
        # been normalized and scored
        for command in (
            ["triage"],
            ["check"],
            ["drift"],
            ["retrain", "--incidents", "i.csv", "--inventory", "v.json"],
        ):
            for value in ("../evil", "a/b", "."):
                with self.subTest(command=command[0], value=value):
                    with self.assertRaises(SystemExit) as caught:
                        self.parse([*command, "--environment", value])
                    self.assertEqual(caught.exception.code, 2)

    def test_the_inventory_positional_takes_the_same_rule(self):
        with self.assertRaises(SystemExit):
            self.parse(["inventory", "../evil"])

    def test_an_ordinary_company_still_parses(self):
        self.assertEqual(self.parse(["triage", "--environment", "acme"]).company, "acme")
        self.assertEqual(
            self.parse(["triage", "--environment", "acme"]).company, "acme"
        )
        unset = self.parse(["triage"])
        cli._apply_config(unset)
        self.assertIsNone(unset.company)

    def test_a_root_input_directory_is_told_to_pass_a_company(self):
        # a drive or filesystem root has no name, and safe_run_id("") raised
        # ValueError with no handler above it
        root = Path(temporary_directory().anchor)
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            cli.resolve_company(argparse.Namespace(company=None, input=root))
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)
        self.assertIn("--environment", errors.getvalue())


class CheckReportsTheTestedValueTests(unittest.TestCase):
    def test_the_unmatched_warning_names_the_entity_not_the_hostname(self):
        # the condition is entity_in_inventory, keyed on the address, so
        # printing host reported web01 as outside an inventory that held it
        directory = temporary_directory()
        write_lines(directory / "acme_wazuh.json", [WAZUH_ALERT])
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}],
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.cmd_check(argparse.Namespace(
                company="acme", input=directory, inventory=inventory,
                sample=100, wazuh_file=None, aminer_file=None, json=False,
            ))
        printed = squashed(output.getvalue())
        self.assertIn("outsidetheinventory", printed)
        self.assertIn("10.0.0.9", printed)
        self.assertNotIn("web01", printed)


class CheckReadsEveryAlertFileTests(unittest.TestCase):
    def test_a_native_eve_file_beside_the_wazuh_export_is_named_and_sampled(self):
        # check is what an analyst runs before triage, so a file triage will read
        # and check never mentions would be the wrong answer twice
        directory = temporary_directory()
        write_lines(directory / "alerts.json", [WAZUH_ALERT])
        write_lines(directory / "eve.json", [EVE_ALERT])
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"]}],
        )
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.suppress(SystemExit),
        ):
            cli.cmd_check(argparse.Namespace(
                company="acme", input=directory, inventory=inventory,
                sample=100, wazuh_file=None, aminer_file=None, json=False,
            ))
        printed = squashed(output.getvalue())
        self.assertIn("alerts.json", printed)
        self.assertIn("eve.json", printed)
        self.assertIn("Suricata", printed)
        self.assertIn("absentloganomaly", printed)


class InventoryScaffoldTests(unittest.TestCase):
    def scaffold(self, records: list[dict], bom: bool = False) -> dict:
        directory = temporary_directory()
        write_lines(directory / "acme_wazuh.json", records, bom=bom)
        out = directory / "inventory" / "acme.json"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_inventory(argparse.Namespace(
                list_roles=False, input=directory, company="acme", out=out,
                limit=500,
            ))
        return json.loads(out.read_text(encoding="utf-8"))

    def test_a_byte_order_mark_no_longer_swallows_the_first_alert(self):
        # the file was opened as plain utf-8, so the BOM made line 1 invalid
        # JSON and the machine it named was silently left out
        written = self.scaffold([
            {"agent": {"ip": "10.0.0.1"}, "predecoder": {"hostname": "web01"}},
            {"agent": {"ip": "10.0.0.2"}, "predecoder": {"hostname": "db01"}},
        ], bom=True)
        self.assertEqual(
            sorted(asset["hostname"] for asset in written["assets"]),
            ["db01", "web01"],
        )

    def test_every_scaffolded_asset_carries_an_address(self):
        # a record without one is skipped, so the "assets have no address"
        # warning that used to follow could never fire
        written = self.scaffold([
            {"agent": {"ip": ""}, "predecoder": {"hostname": "nowhere"}},
            {"agent": {"ip": "10.0.0.2"}, "predecoder": {"hostname": "db01"}},
        ])
        self.assertEqual(len(written["assets"]), 1)
        self.assertTrue(all(asset["ip_addresses"] for asset in written["assets"]))


class TriageMetaTests(unittest.TestCase):
    def run_triage(self) -> dict:
        directory = temporary_directory()
        write_lines(directory / "acme_wazuh.json", [WAZUH_ALERT])
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"]}],
        )
        model = directory / "bundle.skops"
        model.write_text("", encoding="utf-8")
        runs = temporary_directory()
        frame = pd.DataFrame([{"a": 1}])
        bundle = mock.Mock(training_scenarios=("fox",))
        with (
            mock.patch.object(cli, "_load_bundle", return_value=bundle),
            mock.patch.object(
                cli, "_score_company", return_value=(frame, frame, frame)
            ),
            mock.patch.object(
                cli, "decorate_families", side_effect=lambda f, a, budget: f
            ),
            mock.patch.object(cli, "_print_queue"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.cmd_triage(argparse.Namespace(
                model=model, input=directory, company="acme", inventory=inventory,
                labels=None, event_csv_dir=None, wazuh_file=None, aminer_file=None,
                budget=10, runs_dir=runs,
            ))
        latest = (runs / "latest.txt").read_text(encoding="utf-8").strip()
        return json.loads((runs / latest / "run.json").read_text(encoding="utf-8"))

    def test_run_json_drops_the_metrics_nothing_read(self):
        # the four window counters were written on every labelled run and read
        # by nothing: bench/evaluate.py computes its own from the families
        meta = self.run_triage()
        for key in (
            "labelled_alerts", "total_windows", "strict_windows",
            "temporal_overlap_windows",
        ):
            self.assertNotIn(key, meta)

    def test_run_json_keeps_what_the_read_commands_use(self):
        # queue, runs, inspect and export navigator read these back
        meta = self.run_triage()
        for key in ("company", "budget", "families", "input", "saved_at"):
            self.assertIn(key, meta)


# Everything above patches the model away, which is what makes those tests fast
# and what leaves normalize -> sessions -> score -> save untested as a whole.
# These run the real commands against the shipped bundle over a small synthetic
# export, and skip where the bundle is not fetched.

SHIPPED_BUNDLE = Path(__file__).resolve().parents[1] / "models" / "meerkat_bundle.skops"
HAS_BUNDLE = SHIPPED_BUNDLE.exists() and not cli._is_lfs_pointer(SHIPPED_BUNDLE)


def client_directory(days: int = 3, per_day: int = 12) -> Path:
    # one host, two rules, alerts spread far enough apart to close sessions
    directory = temporary_directory()
    write_lines(directory / "acme_wazuh.json", [
        {
            "@timestamp": f"2022-01-{21 + day:02d}T{n // 6:02d}:{(n * 5) % 60:02d}:00Z",
            "agent": {"name": "collector", "ip": "10.0.0.9"},
            "predecoder": {"hostname": "web01"},
            "rule": {
                "id": "5710" if n % 2 else "31101", "level": 5,
                "description": "sshd auth failure", "groups": ["syslog", "sshd"],
            },
        }
        for day in range(days)
        for n in range(per_day)
    ])
    write_inventory(
        directory / "inventory" / "acme.json",
        [{"hostname": "web01", "ip_addresses": ["10.0.0.9"],
          "roles": ["server", "internet_facing"]}],
    )
    return directory


@unittest.skipUnless(
    HAS_BUNDLE,
    "needs models/meerkat_bundle.skops, which is stored with Git LFS",
)
class EndToEndTriageTests(unittest.TestCase):
    # nothing else in the suite takes alerts all the way to a saved run: the
    # meta tests patch _load_bundle, _score_company, decorate_families and
    # _print_queue, which is four of the five things cmd_triage does
    @classmethod
    def setUpClass(cls):
        cls.input = client_directory()
        cls.runs = temporary_directory()
        cls.output = io.StringIO()
        with (
            contextlib.redirect_stdout(cls.output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            cli.cmd_triage(argparse.Namespace(
                model=SHIPPED_BUNDLE, input=cls.input, company="acme",
                inventory=cls.input / "inventory" / "acme.json",
                labels=None, event_csv_dir=None, wazuh_file=None,
                aminer_file=None, budget=2, runs_dir=cls.runs,
            ))
        cls.saved = cli.load_run(cls.runs)

    def test_the_run_holds_every_alert_grouped_into_sessions_and_families(self):
        # 36 alerts on one host, two rules, three days: the alert table is kept
        # whole and the grouping collapses it to two families a day
        self.assertEqual(len(self.saved.alerts), 36)
        self.assertEqual(len(self.saved.sessions), 12)
        self.assertEqual(len(self.saved.families), 6)
        self.assertEqual(self.saved.families["day"].nunique(), 3)

    def test_every_family_is_scored_ranked_and_labelled_from_the_alerts(self):
        families = self.saved.families
        self.assertEqual(list(families["handle"]), [f"F{i}" for i in range(1, 7)])
        self.assertTrue(families["ranking_score"].between(0, 1).all())
        self.assertTrue(families["evidence_probability"].between(0, 1).all())
        self.assertEqual(set(families["host_label"]), {"web01"})
        self.assertEqual(set(families["title"]), {"sshd auth failure"})

    def test_the_budget_cuts_each_day_rather_than_the_run(self):
        # budget 2 over three days keeps six families, not two
        self.assertEqual(int(self.saved.families["in_queue"].sum()), 6)
        self.assertEqual(
            list(self.saved.families.groupby("day")["in_queue"].sum()), [2, 2, 2]
        )

    def test_the_saved_run_reopens_and_the_alert_rows_still_line_up(self):
        # families index the alert table by position, so a reordering anywhere
        # between normalize and save shows up as the wrong alerts here
        family = self.saved.family_by_handle("F001")
        covered = self.saved.family_alerts(family)
        self.assertEqual(len(covered), family["alert_count"])
        self.assertEqual(set(covered["rule_id"]), {family["rule_id"]})
        self.assertEqual(set(covered["host"]), {"web01"})

    def test_triage_reports_the_saved_run_and_prints_the_queue(self):
        printed = self.output.getvalue()
        self.assertIn("saved run", printed)
        self.assertIn("Review queue", printed)
        self.assertIn("F1", printed)


@unittest.skipUnless(
    HAS_BUNDLE,
    "needs models/meerkat_bundle.skops, which is stored with Git LFS",
)
class RealExitCodeTests(unittest.TestCase):
    # EXIT_DECLINED and EXIT_DRIFT were asserted as constants and never observed
    # coming out of a command, which is the only place they mean anything
    def test_a_refused_retrain_exits_declined_and_saves_nothing(self):
        # everything up to the gate runs for real: the bundle loads, the alerts
        # normalize, the bags are assigned and two forests are fitted. Only the
        # verdict is stood in for, so the refusal reaches the exit code.
        directory = client_directory()
        incidents = directory / "incidents.csv"
        start = datetime(2022, 1, 21, tzinfo=UTC).timestamp()
        incidents.write_text(
            f"start,end,host,verdict\n{start},{start + 1800},web01,true_positive\n",
            encoding="utf-8",
        )
        refused = {
            "approved": False,
            "passed": [False, False],
            "reason": "they disagree on 0 incidents",
            "shipped": np.array([True, False]),
            "rescaled": np.array([True, False]),
            "candidates": [np.array([False, False])],
            "median_index": 0,
        }
        written = directory / "retrained.skops"
        reported = io.StringIO()
        with (
            mock.patch.object(cli, "compare_models", return_value=refused),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(reported),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.cmd_retrain(argparse.Namespace(
                model=SHIPPED_BUNDLE, input=directory, company="acme",
                inventory=directory / "inventory" / "acme.json",
                incidents=incidents, wazuh_file=None, aminer_file=None,
                reviewed_periods=None, holdout_days=1, prior_k=1.0, budget=10,
                min_positives=1, trees=5, seed=0, fits=2, out=written,
            ))
        self.assertEqual(caught.exception.code, EXIT_DECLINED)
        self.assertNotEqual(EXIT_DECLINED, EXIT_ERROR)
        self.assertIn("not saved", reported.getvalue())
        # the gate saying no must not leave a bundle behind
        self.assertFalse(written.exists())

    def test_a_major_drift_run_exits_with_its_own_code(self):
        # a client stream this far from the training set is exactly the case
        # drift exists to report, and a wrapper has to tell it from a crash
        directory = client_directory()
        printed = io.StringIO()
        with (
            contextlib.redirect_stdout(printed),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.cmd_drift(argparse.Namespace(
                model=SHIPPED_BUNDLE, input=directory, company="acme",
                inventory=directory / "inventory" / "acme.json",
                wazuh_file=None, aminer_file=None, top=5, json=False, all=False,
            ))
        self.assertEqual(caught.exception.code, cli.EXIT_DRIFT)
        self.assertNotIn(cli.EXIT_DRIFT, (EXIT_ERROR, EXIT_DECLINED))
        report = " ".join(printed.getvalue().split())
        self.assertIn(f"past PSI {PSI_MAJOR}", report)
        # and it never claims the ranking got worse, which needs labels
        self.assertIn("does not measure whether the ranking is still right", report)

    def test_the_drift_report_names_the_rules_the_model_never_saw(self):
        # these two rule ids are not in the shipped schema, so every alert in
        # the fixture is unseen and the rarity feature carries nothing
        directory = client_directory()
        printed = io.StringIO()
        with (
            contextlib.redirect_stdout(printed),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.suppress(SystemExit),
        ):
            cli.cmd_drift(argparse.Namespace(
                model=SHIPPED_BUNDLE, input=directory, company="acme",
                inventory=directory / "inventory" / "acme.json",
                wazuh_file=None, aminer_file=None, top=5, json=False, all=False,
            ))
        report = " ".join(printed.getvalue().split())
        self.assertIn("rules the model never saw", report)
        self.assertIn("the model has no rarity signal for these", report)


class SharedOpeningTests(unittest.TestCase):
    def test_the_inventory_defaults_beside_the_alerts(self):
        # triage, check and drift each spelled these five lines out, and the
        # helper has to keep defaulting the path `meerkat inventory` writes to
        directory = temporary_directory()
        inventory = write_inventory(
            directory / "inventory" / f"{directory.name}.json", []
        )
        args = argparse.Namespace(company=None, input=directory, inventory=None)
        self.assertEqual(cli._open_company(args), directory.name)
        self.assertEqual(args.inventory, inventory)


class DemoBundleCheckTests(unittest.TestCase):
    def test_demo_leaves_the_bundle_check_to_triage(self):
        # demo checked the bundle and then called triage, which checks it again
        directory = temporary_directory()
        for name in ("russellmitchell_wazuh.json", "russellmitchell_aminer.json"):
            (directory / name).write_text("{}\n", encoding="utf-8")
        with (
            mock.patch.object(cli, "_require_bundle") as required,
            mock.patch.object(cli, "cmd_triage") as triage,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.cmd_demo(argparse.Namespace(
                raw_dir=directory, model=Path("models/bundle.skops"),
                budget=10, runs_dir=temporary_directory(),
            ))
        self.assertEqual(required.call_count, 0)
        self.assertEqual(triage.call_count, 1)

    def test_triage_and_retrain_still_check_it_before_reading_alerts(self):
        # both guards are load-bearing: they answer before a large export is
        # read, so the refusal has to arrive with normalize_scenario untouched
        directory = temporary_directory()
        write_lines(directory / "acme_wazuh.json", [WAZUH_ALERT])
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"]}],
        )
        # a loadable incident file, so retrain reaches the guard rather than
        # stopping at the incident records and passing for the wrong reason
        incidents = directory / "incidents.csv"
        incidents.write_text(
            "host,start,end,verdict\nweb01,100,200,true_positive\n", encoding="utf-8"
        )
        absent = directory / "no_such_bundle.skops"
        commands = {
            "triage": argparse.Namespace(
                model=absent, input=directory, company="acme", inventory=inventory,
                labels=None, event_csv_dir=None, wazuh_file=None, aminer_file=None,
                budget=10, runs_dir=temporary_directory(),
            ),
            "retrain": argparse.Namespace(
                model=absent, input=directory, company="acme", inventory=inventory,
                incidents=incidents, wazuh_file=None, aminer_file=None,
                reviewed_periods=None, holdout_days=1, prior_k=1.0, budget=10,
                min_positives=1, trees=10, seed=0, fits=1, out=absent,
            ),
        }
        for name, args in commands.items():
            with self.subTest(command=name):
                with (
                    mock.patch.object(cli, "normalize_scenario") as read_alerts,
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as caught,
                ):
                    getattr(cli, f"cmd_{name}")(args)
                self.assertEqual(caught.exception.code, EXIT_ERROR)
                self.assertEqual(read_alerts.call_count, 0)


def tiny_bundle(path: Path) -> Path:
    # a real skops bundle with a real sidecar, small enough to write per test
    from sklearn.ensemble import RandomForestClassifier
    save_model(
        RandomForestClassifier(n_estimators=2, random_state=0).fit(
            pd.DataFrame({"a": [0.0, 1.0]}), [0, 1]
        ),
        path,
    )
    return path


class BundleGateCliTests(unittest.TestCase):
    # the refusal message is the control that tells a user what is wrong with
    # the file, so it has to arrive as a message on stderr and an exit code.
    # Letting UntrustedBundleError escape printed a traceback instead.
    def load(self, path: Path) -> tuple[int, str, str]:
        printed, reported = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(printed),
            contextlib.redirect_stderr(reported),
            self.assertRaises(SystemExit) as caught,
        ):
            cli._load_bundle(path)
        return caught.exception.code, printed.getvalue(), reported.getvalue()

    def test_a_file_that_is_not_a_bundle_exits_error_without_a_traceback(self):
        path = temporary_directory() / "model.skops"
        path.write_bytes(b"\x80\x05\x95 a pickle, which must never be loaded")
        code, _, reported = self.load(path)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("isnotaskopsbundle", squashed(reported))
        # and it says what to do about it rather than only what is wrong
        self.assertIn("meerkatretrain", squashed(reported))

    def test_an_unfetched_lfs_pointer_exits_error_naming_the_two_commands(self):
        path = temporary_directory() / "meerkat_bundle.skops"
        path.write_bytes(
            b"version https://git-lfs.github.com/spec/v1\noid sha256:0\nsize 1\n"
        )
        code, _, reported = self.load(path)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("gitlfspull", squashed(reported))

    def test_a_missing_model_and_an_untrusted_one_share_an_exit_code(self):
        # both mean "no usable bundle here", and a wrapper reads the message
        absent = temporary_directory() / "absent.skops"
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli._require_bundle(absent)
        self.assertEqual(caught.exception.code, EXIT_ERROR)

    def test_a_bundle_with_no_sidecar_loads_and_says_it_proves_nothing(self):
        # the hash only shows the file is unchanged since it was written, so a
        # bundle arriving without one is used and the gap is stated
        path = tiny_bundle(temporary_directory() / "bundle.skops")
        provenance_path(path).unlink()
        reported = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(reported),
        ):
            self.assertIsNotNone(cli._load_bundle(path))
        self.assertIn("noprovenancesidecar", squashed(reported.getvalue()))

    def test_a_bundle_edited_after_it_was_written_is_reported(self):
        path = tiny_bundle(temporary_directory() / "bundle.skops")
        # a zip tolerates trailing bytes, so this still loads and no longer
        # matches the sha256 the sidecar recorded
        path.write_bytes(path.read_bytes() + b"\x00")
        reported = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(reported),
        ):
            cli._load_bundle(path)
        self.assertIn("changedafteritwaswritten", squashed(reported.getvalue()))


# `meerkat check` reads a sample and reports what triage will see. `queue --budget`
# re-cuts a saved run, which works only because K never reaches the model.


class TestCheckParser(unittest.TestCase):
    def test_check_needs_nothing_but_a_directory(self):
        # a client's first command after unpacking their alerts, so requiring
        # --environment or --inventory here would defeat the point
        args = build_parser().parse_args(["check"])
        cli._apply_config(args)
        self.assertIsNone(args.company)
        self.assertIsNone(args.inventory)
        self.assertEqual(args.input.name, "alerts")

    def test_check_takes_the_same_file_overrides_as_triage(self):
        # whatever names a client's exports have, check has to read the files
        # triage will read, or it validates something else
        args = build_parser().parse_args([
            "check", "--wazuh-file", "w.json", "--aminer-file", "a.json",
        ])
        self.assertEqual(args.wazuh_file.name, "w.json")
        self.assertEqual(args.aminer_file.name, "a.json")

    def test_the_sample_size_is_boundable(self):
        # the demo's wazuh export alone is 45 MB, so check must never be asked to
        # read a whole file to answer a question about its shape
        args = build_parser().parse_args(["check", "--sample", "250"])
        self.assertEqual(args.sample, 250)


class TestRuleCardinality(unittest.TestCase):
    # the ratio is only warned on above 500 alerts, so both fixtures clear that
    def check(self, rule_ids: list[str]) -> str:
        directory = temporary_directory()
        write_lines(directory / "acme_wazuh.json", [
            {
                "@timestamp": f"2026-01-01T00:{minute // 60:02d}:{minute % 60:02d}Z",
                "agent": {"name": "collector", "ip": "10.0.0.9"},
                "predecoder": {"hostname": "web01"},
                "rule": {"id": rule_id, "level": 5, "description": "an event"},
            }
            for minute, rule_id in enumerate(rule_ids)
        ])
        inventory = write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"], "roles": ["server"]}],
        )
        reported = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(reported),
            contextlib.suppress(SystemExit),
        ):
            cli.cmd_check(argparse.Namespace(
                company="acme", input=directory, inventory=inventory,
                sample=len(rule_ids) * 2, wazuh_file=None, aminer_file=None, json=False,
            ))
        return squashed(reported.getvalue())

    def test_the_warning_threshold_catches_one_rule_id_per_alert(self):
        # a detector that numbers each anomaly instead of naming its type makes
        # every session unique, so rarity carries nothing and sessions never group.
        # nothing errors, which is why check has to say it out loud.
        per_occurrence = self.check([str(9000 + n) for n in range(600)])
        self.assertIn("600distinctruleidsacross600alerts", per_occurrence)
        self.assertIn("rulerarity", per_occurrence)

    def test_a_detector_naming_kinds_of_alert_draws_no_warning(self):
        # 12 rule ids over 600 alerts is what a detector naming types looks
        # like, and warning there would train the client to ignore the message
        per_type = self.check([str(5500 + n % 12) for n in range(600)])
        self.assertNotIn("distinctruleids", per_type)

    def test_the_threshold_sits_between_the_two_ratios(self):
        self.assertGreater(1.0, RULE_CARDINALITY_WARN)
        self.assertLess(12 / 600, RULE_CARDINALITY_WARN)


class TestQueueBudget(unittest.TestCase):
    # `queue --budget` re-cuts a saved run without rescoring, which works only
    # because K never reaches the model. These drive the real command.
    def save(self, runs: Path, per_day: int, days: int) -> None:
        families = pd.DataFrame([
            {
                "day": day, "entity_id": "10.0.0.5", "detector_source": "wazuh",
                "rule_id": "31101", "ranking_score": 1.0 - rank / 100,
                "start": float(rank), "representative_session_id": f"acme#{rank}",
                "alert_rows": [0], "family_id": f"acme#{day}#{rank}",
            }
            for day in range(days)
            for rank in range(per_day)
        ])
        decorated = cli.decorate_families(families, make_alerts(), budget=10)
        cli.save_run(
            runs, "acme-1", {"company": "acme", "budget": 10},
            decorated, make_sessions(), make_alerts(),
        )

    def queued(self, runs: Path, budget: int | None) -> int:
        args = argparse.Namespace(
            runs_dir=runs, run=None, budget=budget, json=True, all=False,
            host=None, detector=None, rule=None, review_state=None, day=None,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.cmd_queue(args)
        return len(json.loads(output.getvalue()))

    def test_recutting_uses_the_rank_triage_already_saved(self):
        # every family carries its queue_rank, so a saved run can be cut anywhere
        # without rescoring. This is the whole reason K is free.
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self.save(runs, per_day=30, days=4)
            for budget in (3, 10, 25):
                with self.subTest(budget=budget):
                    self.assertEqual(self.queued(runs, budget), budget * 4)

    def test_a_budget_wider_than_the_day_keeps_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self.save(runs, per_day=7, days=2)
            self.assertEqual(self.queued(runs, 50), 14)

    def test_no_budget_leaves_the_saved_cut_alone(self):
        # the flag defaults to None, and the run keeps the K triage saved it with
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self.save(runs, per_day=30, days=2)
            self.assertEqual(self.queued(runs, None), 20)

    def test_queue_accepts_a_budget_and_defaults_to_leaving_the_run_alone(self):
        parser = build_parser()
        self.assertIsNone(parser.parse_args(["queue"]).budget)
        self.assertEqual(parser.parse_args(["queue", "--budget", "5"]).budget, 5)

class TestInventoryScaffold(unittest.TestCase):
    # the scaffold keys on the agent address, because that is what a session keys
    # on. Grouping by agent.name collapsed every machine behind a manager
    # reporting one name into a single asset sharing one set of roles.
    def records(self) -> list[str]:
        import json
        rows = [
            {"agent": {"name": "wazuh-client", "ip": "10.0.0.1"},
             "predecoder": {"hostname": "mail"}},
            {"agent": {"name": "wazuh-client", "ip": "10.0.0.2"}},
            {"agent": {"name": "wazuh-client", "ip": "10.0.0.1"},
             "predecoder": {"hostname": "mail"}},
        ]
        return [json.dumps(r) for r in rows]

    def scaffold(self):
        import json
        import tempfile
        from pathlib import Path

        from meerkat.cli import build_parser, cmd_inventory

        directory = Path(tempfile.mkdtemp())
        (directory / "acme_wazuh.json").write_text(
            "\n".join(self.records()) + "\n", encoding="utf-8"
        )
        args = build_parser().parse_args(
            ["inventory", "acme", "--input", str(directory)]
        )
        cmd_inventory(args)
        return json.loads(
            (directory / "inventory" / "acme.json").read_text(encoding="utf-8")
        )

    def test_one_asset_per_address_not_per_agent_name(self):
        assets = self.scaffold()["assets"]
        self.assertEqual(len(assets), 2)
        self.assertEqual(
            sorted(a["ip_addresses"][0] for a in assets), ["10.0.0.1", "10.0.0.2"]
        )

    def test_the_machine_s_own_hostname_wins_over_the_collector_name(self):
        assets = {a["ip_addresses"][0]: a["hostname"] for a in self.scaffold()["assets"]}
        self.assertEqual(assets["10.0.0.1"], "mail")

    def test_an_address_with_no_hostname_is_labelled_by_its_address(self):
        # never by the agent name, which would give several machines one label
        assets = {a["ip_addresses"][0]: a["hostname"] for a in self.scaffold()["assets"]}
        self.assertEqual(assets["10.0.0.2"], "10.0.0.2")

    def test_roles_start_empty_so_triage_can_warn(self):
        self.assertTrue(all(a["roles"] == [] for a in self.scaffold()["assets"]))


# Alert text is written by whoever triggered the alert. These pin that a crafted
# rule name, hostname or user agent cannot crash the queue view, draw a live
# hyperlink inside evidence, or repaint the analyst's terminal.


# a closing tag with nothing open is what rich raises MarkupError on
BROKEN_MARKUP = "Mozilla/5.0 [/b] compatible"
SMUGGLED_LINK = "[link=https://evil.example/harvest]GET /index.html[/link]"
CLEAR_SCREEN = "web-01\x1b[2J\x1b[1;1H"


def capture(call) -> str:
    # the CLI renders through its module-level rich console, which resolves
    # sys.stdout lazily, so redirecting stdout captures the output
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        call()
    return buffer.getvalue()


def alerts(**overrides) -> pd.DataFrame:
    row = {
        "timestamp": 100.0, "detector_source": "wazuh",
        "name": "Web server 400 error", "host": "intranet-server",
        "source_file": "acme_wazuh.json", "source_position": 10,
        "rule_id": "31101", "severity": 5.0, "alert_category": "",
        "http_status": 400.0, "http_method": "GET", "web_request": "/a",
        "http_user_agent": "curl/8.0",
        "technique_ids": "T1595", "tactics": ("Reconnaissance",),
    }
    row.update(overrides)
    return pd.DataFrame([row])


class TestSafe(unittest.TestCase):
    def test_a_stray_closing_tag_is_neutralised_with_a_backslash(self):
        # rich raises MarkupError on "[/b]" with nothing open, and there is no
        # try/except up to main(), so one user agent would kill the command
        self.assertIn("\\[/b]", cli.safe(BROKEN_MARKUP))
        self.assertIn("Mozilla/5.0", cli.safe(BROKEN_MARKUP))

    def test_the_escape_byte_is_removed_rather_than_escaped(self):
        # rich strips BEL and CR but leaves ESC alone inside a Table cell, and
        # "\x1b[2J" clears the analyst's screen mid-table. The bracket that
        # follows is left readable because rich never parses "[2J" as a tag.
        cleaned = cli.safe(CLEAR_SCREEN)
        self.assertNotIn("\x1b", cleaned)
        self.assertEqual(cleaned, "web-01[2J[1;1H")

    def test_ordinary_text_is_left_readable(self):
        self.assertEqual(cli.safe("intranet-server"), "intranet-server")
        self.assertEqual(cli.safe(404), "404")


class TestPanelRendering(unittest.TestCase):
    def test_a_crafted_user_agent_does_not_crash_the_evidence_panel(self):
        text = capture(
            lambda: cli._render_panels(alerts(http_user_agent=BROKEN_MARKUP))
        )
        self.assertIn("Mozilla/5.0", text)

    def test_a_url_cannot_smuggle_a_hyperlink_into_the_evidence(self):
        # an OSC-8 sequence would render as clickable text pointing at the
        # attacker while reading as ordinary evidence
        text = capture(
            lambda: cli._render_panels(alerts(web_request=SMUGGLED_LINK))
        )
        self.assertNotIn("\x1b]8;", text)
        self.assertIn("evil.example", text)


class TestQueueRendering(unittest.TestCase):
    def family(self, **overrides) -> pd.DataFrame:
        row = {
            "handle": "F001", "family_id": "acme#1#10.0.0.1#wazuh#31101",
            "day": 19013, "host_label": "web-01", "detector_source": "wazuh",
            "title": "Web server 400 error", "rule_id": "31101",
            "alert_count": 3, "ranking_score": 0.9,
            "evidence_probability": 0.8, "start": 100.0,
        }
        row.update(overrides)
        return pd.DataFrame([row])

    def test_one_crafted_hostname_does_not_blank_the_whole_queue(self):
        # the table renders every family, so an unescaped tag in one row would
        # take out every other row the analyst needed to see
        text = capture(
            lambda: cli.render_queue(
                self.family(host_label=BROKEN_MARKUP), {}, "Review queue"
            )
        )
        self.assertIn("Mozilla", text)

    def test_a_hostname_cannot_repaint_the_terminal_from_a_table_cell(self):
        text = capture(
            lambda: cli.render_queue(
                self.family(host_label=CLEAR_SCREEN), {}, "Review queue"
            )
        )
        self.assertNotIn("\x1b[2J", text)

    def test_a_crafted_rule_name_does_not_crash_the_family_heading(self):
        # the heading is printed as markup, so the tag has to arrive escaped
        heading = cli.family_heading(self.family(title=BROKEN_MARKUP).iloc[0])
        self.assertIn("\\[/b]", heading)
        capture(lambda: cli.console.print(heading))


if __name__ == "__main__":
    unittest.main()
