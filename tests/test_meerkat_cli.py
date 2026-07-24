import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from meerkat import cli


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
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=1)
        by_score = decorated.sort_values("ranking_score", ascending=False)
        self.assertEqual(list(by_score["handle"]), ["F001", "F002"])
        top = decorated[decorated["handle"].eq("F001")].iloc[0]
        bottom = decorated[decorated["handle"].eq("F002")].iloc[0]
        self.assertTrue(top["in_queue"])
        self.assertFalse(bottom["in_queue"])

    def test_title_and_host_come_from_alerts(self):
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=2)
        top = decorated[decorated["handle"].eq("F001")].iloc[0]
        self.assertEqual(top["host_label"], "intranet-server")
        self.assertEqual(top["title"], "Web server 400 error")


class RunRoundTripTests(unittest.TestCase):
    def _save(self, runs_dir: Path, run_id: str) -> None:
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=1)
        cli.save_run(
            runs_dir, run_id, {"company": "acme", "budget": 1},
            decorated, make_sessions(), make_alerts(),
        )

    def test_latest_pointer_tracks_newest_good_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            self._save(runs, "acme-1")
            self._save(runs, "acme-2")
            self.assertEqual(cli.latest_run_id(runs), "acme-2")
            run = cli.load_run(runs)
            self.assertEqual(run.run_id, "acme-2")
            self.assertEqual(len(run.families), 2)

    def test_handles_and_related_resolve_after_reload(self):
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
            self.assertEqual(list(related["handle"]), ["F002"])
            self.assertNotEqual(
                related.iloc[0]["detector_source"], family["detector_source"]
            )


class ReviewTests(unittest.TestCase):
    def test_append_only_history_last_entry_wins(self):
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


class FilterTests(unittest.TestCase):
    def test_match_handles_float_and_string_fields(self):
        alerts = make_alerts()
        kept = cli._apply_filters(alerts, [("http_status", "400")], [])
        self.assertEqual(len(kept), 2)
        dropped = cli._apply_filters(alerts, [], [("http_status", "404")])
        self.assertNotIn(404.0, dropped["http_status"].tolist())
        by_rule = cli._apply_filters(alerts, [("rule_id", "2001")], [])
        self.assertEqual(len(by_rule), 1)

    def test_match_numeric_series_directly(self):
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
        text = self._capture(
            lambda: cli._render_panels(make_alerts().iloc[[0, 1]])
        )
        self.assertIn("Network / HTTP", text)
        self.assertIn("Provenance", text)
        self.assertNotIn("Process / System", text)
        self.assertIn("Available evidence", text)

    def test_http_outcome_leads_with_the_verdict(self):
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

            self.assertIn(
                "outcome       : 3 requests, none succeeded (404)", family_text
            )
            self.assertIn(
                "outcome: 2 requests, none succeeded (404)", session_text
            )

    def test_family_overview_omits_outcome_without_http_status(self):
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
            self.assertIn("asset         : intranet, servers", text)

    def test_family_overview_omits_empty_asset_roles(self):
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
            self.assertNotIn("asset         :", text)

    def test_family_overview_compares_volume_with_three_rule_peers(self):
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
            current = run.families["handle"].eq("F001")
            run.families.loc[current, "alert_count"] = 40
            family = run.family_by_handle("F001")
            peers = []
            for number, count in enumerate((10, 20, 30), start=3):
                peer = family.copy()
                peer["handle"] = f"F{number:03d}"
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
        self.assertEqual(
            self.outcome([200.0, 304.0]), "2 requests, all succeeded (200, 304)"
        )
        self.assertEqual(self.outcome([200.0]), "1 request, succeeded (200)")
        self.assertEqual(self.outcome([404.0]), "1 request, failed (404)")

    def test_absent_or_empty_http_renders_nothing(self):
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
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            default = cli._select_families(run, False, None, None, None, None)
            self.assertEqual(len(default), 1)  # budget 1, one family in queue
            by_detector = cli._select_families(
                run, False, None, "suricata", None, None
            )
            # F002 is suricata and below the queue line, a filter still finds it
            self.assertEqual(list(by_detector["handle"]), ["F002"])

    def test_day_filter_keeps_the_daily_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            same_day = cli._select_families(
                run, False, None, None, None, None, cli.fmt_date(0)
            )
            # --day narrows to one day without widening past the budget
            self.assertEqual(len(same_day), 1)

    def test_unknown_day_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            with self.assertRaises(SystemExit):
                cli._select_families(
                    run, False, None, None, None, None, "1999-01-01"
                )

    def test_review_state_filter_matches_recorded_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self._run(Path(tmp))
            cli.append_review(
                run.directory, run.run_id,
                "acme#0#10.0.0.5#suricata#2001", "F002", "escalate", "",
            )
            escalated = cli._select_families(
                run, False, None, None, None, "escalate"
            )
            self.assertEqual(list(escalated["handle"]), ["F002"])


class LfsTests(unittest.TestCase):
    def test_pointer_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pointer = Path(tmp) / "big.json"
            pointer.write_text(
                "version https://git-lfs.github.com/spec/v1\noid sha256:abc\n"
            )
            self.assertTrue(cli._is_lfs_pointer(pointer))
            real = Path(tmp) / "real.json"
            real.write_text('{"detector_source": "wazuh"}\n')
            self.assertFalse(cli._is_lfs_pointer(real))


if __name__ == "__main__":
    unittest.main()
