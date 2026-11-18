# The four commands end to end, through main(), on a temporary runs directory.

import contextlib
import csv
import io
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import close, store
from meerkat import __version__, cli
from meerkat.cli import main
from tests.fixtures import (
    HEADER,
    ROWS,
    calibration_rows,
    linked_rows,
    plain_row,
    sampled_ids,
    use_weights,
    write_csv,
)


class CliTests(unittest.TestCase):
    def setUp(self):
        use_weights(self)
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.csv = write_csv(self.tmp / "incidents.csv")

    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                main([*argv, "--runs-dir", str(self.runs_dir)])
            except SystemExit as stop:
                code = stop.code
        return code, out.getvalue(), err.getvalue()

    def _queue_ids(self, *argv: str) -> list[str]:
        code, out, _ = self._run("queue", "--json", *argv)
        self.assertEqual(code, 0)
        return [row["IncidentId"] for row in json.loads(out)["queue"]]

    def test_queue_scores_a_file_and_lists_open_incidents_by_score(self):
        code, out, err = self._run("queue", str(self.csv))
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(lines[0].split()[:3], ["#", "incident", "score"])
        self.assertEqual([line.split()[1] for line in lines[1:4]], ["201", "202", "200"])
        self.assertIn("2 of 2 true positive", lines[1])
        self.assertIn("never graded", lines[2])
        self.assertIn("3 of 3 incidents in the queue", lines[4])
        self.assertEqual(lines[5], "Nothing closed yet: 2 of 19 graded true positives.")
        self.assertNotIn("100", [line.split()[1] for line in lines[1:4]])

    def test_queue_table_and_json_carry_the_reason(self):
        code, out, _ = self._run("queue", str(self.csv))
        lines = out.splitlines()
        self.assertRegex(lines[0], r"rule history\s+reason\s+time")
        self.assertIn("rule history raises it", lines[1])
        self.assertIn("no history", lines[2])
        rows = json.loads(self._run("queue", "--json")[1])["queue"]
        self.assertEqual([row["reason"] for row in rows],
                         ["rule history raises it", "no history", "rule history lowers it"])

    def test_inspect_shows_the_score_without_links_and_as_a_new_rule(self):
        self._run("queue", str(self.csv))
        out = self._run("inspect", "201")[1]
        self.assertRegex(out, r"score\s+0\.\d\d\nwithout links\s+0\.\d\d\n"
                              r"as a new rule\s+0\.\d\d\nreason\s+rule history raises it\n")
        record = json.loads(self._run("inspect", "201", "--json")[1])
        self.assertEqual(record["reason"], "rule history raises it")
        self.assertEqual(record["score_without_links"], record["score"])
        self.assertEqual(record["score_as_new_rule"], 0.5)

    def test_queue_without_a_file_reopens_the_latest_run(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])
        self.assertEqual(len(list(self.runs_dir.glob("*/meta.json"))), 1)

    def test_limit_and_all(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids("--limit", "1"), ["201"])
        self.assertEqual(self._queue_ids("--all"), ["201", "202", "200"])
        code, out, _ = self._run("queue", "--limit", "1")
        self.assertIn("1 of 3 incidents in the queue", out)

    def _three_runs(self) -> list[str]:
        days = ("2024-06-01", "2024-06-02", "2024-06-03")
        for day, ids in zip(days, (("a1", "a2"), ("b1", "b2"), ("c1",)), strict=True):
            rows = [plain_row(i, "5", time=f"{day}T00:00:00Z") for i in ids]
            self._run("queue", str(write_csv(self.tmp / f"{day}.csv", rows)))
        return [meta["run"] for meta in json.loads(self._run("runs", "--json")[1])]

    def test_queue_lists_the_open_incidents_of_every_run(self):
        first, _, _ = self._three_runs()
        self.assertEqual(self._queue_ids(), ["c1", "b1", "b2", "a1", "a2"])
        out = self._run("queue")[1]
        self.assertIn("\n5 of 5 incidents in the queue\n", out)
        report = json.loads(self._run("queue", "--json")[1])
        self.assertEqual((report["run"], report["open"], report["closed"], report["audit"]),
                         (None, 5, 0, 0))
        self.assertEqual(self._queue_ids("--limit", "2"), ["c1", "b1"])
        self.assertIn("2 of 5 incidents in the queue", self._run("queue", "--limit", "2")[1])
        self.assertEqual(self._queue_ids("--run", first), ["a1", "a2"])
        self.assertIn(f"\n2 of 2 incidents in the queue, run {first}\n",
                      self._run("queue", "--run", first)[1])
        report = json.loads(self._run("queue", "--run", first, "--json")[1])
        self.assertEqual((report["run"], report["open"]), (first, 2))

    def test_queue_lists_incoming_and_earlier_incidents(self):
        self._three_runs()
        fourth = write_csv(self.tmp / "d.csv", [plain_row("d1", "5", time="2024-06-04T00:00:00Z")])
        self.assertEqual(self._queue_ids(str(fourth)), ["d1", "c1", "b1", "b2", "a1", "a2"])
        report = json.loads(self._run("queue", "--json")[1])
        self.assertEqual(report["open"], 6)
        self.assertEqual(report["run"], None)
        saved = json.loads(self._run("queue", str(fourth), "--json")[1])
        self.assertEqual(saved["run"], store.list_runs(self.runs_dir)[-1]["run"])

    def test_a_reviewed_incident_leaves_the_list_of_every_run(self):
        self._three_runs()
        self._run("review", "b1", "fp")
        self.assertEqual(self._queue_ids(), ["b2", "a1", "a2", "c1"])
        self.assertEqual(json.loads(self._run("queue", "--json")[1])["open"], 4)

    def test_review_moves_the_queue(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("review", "201", "fp", "--note", "test account")
        self.assertEqual((code, out), (0, "201 graded FalsePositive\n"))
        self.assertEqual(self._queue_ids(), ["202", "200"])
        self._run("review", "200", "tp")
        self._run("review", "201", "tp")
        self.assertEqual(self._queue_ids(), ["202"])
        code, out, _ = self._run("inspect", "200", "--json")
        self.assertEqual(json.loads(out)["IncidentGrade"], "TruePositive")

    def test_a_grade_from_an_earlier_run_scores_a_later_run(self):
        self._run("queue", str(self.csv))
        later = (("1", "900", "z1", "2024-06-09T00:00:00Z", "42", "New rule", "", "",
                  "", "", ""),)
        later_csv = write_csv(self.tmp / "later.csv", later)
        self.assertEqual(self._queue_ids(str(later_csv)), ["201", "900", "202", "200"])
        code, out, _ = self._run("inspect", "900", "--json")
        self.assertEqual(json.loads(out)["score"], 0.5)
        self._run("review", "202", "tp")
        code, out, _ = self._run("inspect", "900", "--json")
        record = json.loads(out)
        self.assertEqual((record["rule_graded"], record["rule_true_positives"]), (1, 1))
        self.assertGreater(record["score"], 0.5)
        self.assertEqual(self._queue_ids(), ["201", "900", "200"])

    def test_queue_with_nothing_open(self):
        self._run("queue", str(write_csv(self.tmp / "graded.csv", ROWS[:5])))
        code, out, _ = self._run("queue")
        self.assertEqual((code, out), (0, "No open incidents.\n"))
        run = store.list_runs(self.runs_dir)[-1]["run"]
        self.assertEqual(self._run("queue", "--run", run)[1],
                         f"No open incidents in run {run}.\n")

    def test_inspect_text_and_json(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("inspect", "100")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"rule\s+7\n")
        self.assertRegex(out, r"MitreTechniques\s+T1078, T1078.004, T1114\n")
        self.assertRegex(out, r"grade\s+TruePositive\n")
        self.assertRegex(out, r"IpAddress\s+10.0.0.1, 10.0.0.2\n")
        self.assertNotIn("Sha256", out)
        self.assertRegex(out, r"rule history\s+2 of 2 true positive\nlinked incidents\s+none\n")
        code, out, _ = self._run("inspect", "100", "--json")
        record = json.loads(out)
        self.assertEqual(record["IpAddress"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(record["Sha256"], [])

    def test_linked_incidents_in_inspect_and_json(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("inspect", "201")
        self.assertRegex(out, r"\nlinked incidents\s+1 earlier \(1 true positive, "
                              r"0 benign positive, 0 false positive\)\n")
        record = json.loads(self._run("inspect", "201", "--json")[1])
        keys = ("linked", "linked_true_positive", "linked_benign_positive",
                "linked_false_positive")
        self.assertEqual([record[key] for key in keys], [1, 1, 0, 0])
        self.assertRegex(out, r"\n\nlinked incident\s+grade\s+time\s+rule\s+title\n"
                              r"100\s+TruePositive\s+2024-06-01T08:00:00Z\s+7\s+"
                              r"Suspicious sign in\n$")
        self.assertEqual(record["linked_incidents"], [{
            "IncidentId": "100", "IncidentGrade": "TruePositive",
            "Timestamp": "2024-06-01T08:00:00Z", "DetectorId": "7",
            "AlertTitle": "Suspicious sign in"}])
        self.assertNotIn("linked incident ", self._run("inspect", "202")[1])
        rows = json.loads(self._run("queue", "--json")[1])["queue"]
        self.assertEqual([[row[key] for key in keys] for row in rows],
                         [[1, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]])
        self.assertTrue(all(type(row[key]) is int for row in rows for key in keys))

    def test_inspect_limited_to_a_run(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("runs", "--json")
        first = json.loads(out)[0]["run"]
        later = (("1", "900", "z1", "2024-06-09T00:00:00Z", "42", "", "", "", "", "", ""),)
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(self._run("inspect", "900")[0], 0)
        code, _, err = self._run("inspect", "900", "--run", first)
        self.assertEqual(code, 1)
        self.assertIn("no incident '900'", err)

    def test_runs_lists_every_run(self):
        code, out, _ = self._run("runs")
        self.assertIn("No runs in", out)
        self._run("queue", str(self.csv))
        self._run("queue", str(self.csv))
        code, out, _ = self._run("runs")
        lines = out.splitlines()
        self.assertEqual(lines[0].split(), ["run", "created", "incidents", "source"])
        self.assertEqual([line.split()[2:] for line in lines[1:]],
                         [["7", "incidents.csv"]] * 2)
        code, out, _ = self._run("runs", "--json")
        self.assertEqual([run["incidents"] for run in json.loads(out)], [7, 7])

    def test_errors_exit_1_with_one_line(self):
        cases = (
            ("queue",),
            ("queue", str(self.tmp / "absent.csv")),
            ("queue", "--run", "missing"),
            ("review", "200", "tp"),
            ("inspect", "200"),
        )
        for argv in cases:
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertTrue(err.startswith("meerkat: error: "))
                self.assertEqual(err.count("\n"), 1)
        self._run("queue", str(self.csv))
        for argv in (("review", "nope", "tp"), ("inspect", "nope")):
            with self.subTest(argv):
                self.assertEqual(self._run(*argv)[0], 1)

    def test_a_refused_file_leaves_no_run(self):
        bad = write_csv(self.tmp / "bad.csv", (("1", "5"),), ("OrgId", "IncidentId"))
        self.assertEqual(self._run("queue", str(bad))[0], 1)
        self.assertEqual(self._run("runs", "--json")[1], "[]\n")

    def test_a_runs_directory_that_cannot_be_written(self):
        self.runs_dir = self.csv
        for argv in (("queue", str(self.csv)), ("review", "200", "tp")):
            with self.subTest(argv):
                code, _, err = self._run(*argv)
                self.assertEqual(code, 1)
                self.assertTrue(err.startswith("meerkat: error: "))

    def test_usage_errors_exit_2(self):
        self._run("queue", str(self.csv))
        cases = (
            (),
            ("triage",),
            ("review", "200", "malicious"),
            ("review", "200"),
            ("queue", "--limit", "0"),
            ("queue", "--limit", "many"),
            ("queue", "--limit", "5", "--all"),
            ("queue", str(self.csv), "--run", "x"),
        )
        for argv in cases:
            with self.subTest(argv):
                self.assertEqual(self._run(*argv)[0], 2)

    def test_terminal_escapes_and_markup_in_incident_text_are_not_obeyed(self):
        row = dict(zip(HEADER, ROWS[5], strict=True))
        row.update(IncidentId="666", AlertTitle="\x1b[2J[red]:skull:‮evil\r\nrow")
        hostile = write_csv(self.tmp / "hostile.csv", (tuple(row.values()),))
        for argv in (("queue", str(hostile)), ("inspect", "666")):
            with self.subTest(argv):
                code, out, _ = self._run(*argv)
                self.assertEqual(code, 0)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("‮", out)
                self.assertNotIn("\r", out)

    def _calibrate(self, audit: int, closed: int, graded: int = 19) -> None:
        rows = calibration_rows(audit, closed)
        self._run("queue", str(write_csv(self.tmp / "many.csv", rows)))
        for number in range(graded):
            self.assertEqual(self._run("review", f"t{number}", "tp")[0], 0)

    def _queue_json(self, *argv: str) -> dict:
        return json.loads(self._run("queue", "--json", *argv)[1])

    def _calibrate_linked(self) -> str:
        self._run("queue", str(write_csv(self.tmp / "many.csv", linked_rows(0, 2))))
        for number in range(19):
            self.assertEqual(self._run("review", f"t{number}", "tp")[0], 0)
        return sampled_ids(False, 1)[0]

    def test_footer_without_level_counts_true_positives(self):
        code, out, _ = self._run("queue", str(self.csv))
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines()[-1],
                         "Nothing closed yet: 2 of 19 graded true positives.")
        self._calibrate(2, 2, graded=0)
        self.assertEqual(self._run("queue")[1].splitlines()[-1],
                         "Nothing closed: too many graded true positives share the lowest score.")
        self.assertEqual(out.splitlines()[0].split()[:4], ["#", "incident", "score", "pile"])
        report = self._queue_json()
        self.assertEqual((report["closed"], report["audit"], report["close_level"]),
                         (0, 0, None))
        self.assertEqual(report["open"], 27)

    def test_graded_history_in_the_file_closes_incidents_without_a_review(self):
        closed_id = sampled_ids(False, 1)[0]
        first, second, third = (f"2024-06-0{day}T00:00:00Z" for day in (7, 8, 9))
        rows = [plain_row(f"p{i}", "3", "TruePositive", first) for i in range(19)]
        rows += [plain_row("q0", "1", "TruePositive", second)]
        rows += [plain_row(f"q{i}", "1", "FalsePositive", first) for i in range(1, 5)]
        rows += [plain_row(f"f{i}", "5", "FalsePositive", first) for i in range(10)]
        rows += [plain_row("keep", "1", time=third), plain_row(closed_id, "5", time=third)]
        self._run("queue", str(write_csv(self.tmp / "graded.csv", rows)))
        report = self._queue_json("--closed")
        self.assertIsNotNone(report["close_level"])
        self.assertEqual([row["IncidentId"] for row in report["queue"]], [closed_id])
        self.assertEqual([row["IncidentId"] for row in self._queue_json()["queue"]], ["keep"])
        self.assertFalse((self.runs_dir / "grades.csv").exists())

    def test_footer_with_a_level_and_the_audit_rows(self):
        self._calibrate(3, 2)
        audit_ids, closed_ids = sampled_ids(True, 3), sampled_ids(False, 2)
        code, out, _ = self._run("queue")
        lines = out.splitlines()
        self.assertEqual(
            lines[-2], "Set aside under the close level: 2 (target: at most 5% of true positives)")
        self.assertEqual(lines[-1], "Shown above as audit: 3")
        self.assertIn("4 of 4 incidents in the queue", lines[-3])
        shown = {line.split()[1]: line.split() for line in lines[1:-3]}
        self.assertEqual(set(shown), {"t19", *audit_ids})
        self.assertNotIn("audit", shown["t19"])
        for incident in audit_ids:
            self.assertEqual(shown[incident][3], "audit")
        self.assertFalse(set(closed_ids) & set(shown))

    def test_json_reports_the_level_and_the_pile_of_each_row(self):
        self._calibrate(3, 2)
        report = self._queue_json()
        self.assertAlmostEqual(report["close_level"], 1 / (1 + math.exp(0.25)))
        self.assertEqual(
            {key: report[key] for key in
             ("open", "closed", "audit", "miss_rate", "audit_share")},
            {"open": 6, "closed": 2, "audit": 3, "miss_rate": 0.05, "audit_share": 0.1})
        self.assertEqual(sorted(row["pile"] for row in report["queue"]),
                         ["audit", "audit", "audit", "queue"])
        closed = self._queue_json("--closed")
        self.assertEqual({row["pile"] for row in closed["queue"]}, {"closed"})
        self.assertEqual({row["IncidentId"] for row in closed["queue"]},
                         set(sampled_ids(False, 2)))
        self.assertEqual(closed["open"], 6)

    def test_closed_lists_the_pile_with_limit_and_all(self):
        self._calibrate(0, 3)
        code, out, _ = self._run("queue", "--closed", "--limit", "2")
        lines = out.splitlines()
        self.assertEqual(lines[0].split()[:4], ["#", "incident", "score", "pile"])
        self.assertEqual(len(lines), 5)
        self.assertIn("2 of 3 incidents set aside", lines[3])
        self.assertEqual(len(self._queue_json("--closed", "--all")["queue"]), 3)
        self.assertEqual(len(self._queue_json("--closed", "--limit", "1")["queue"]), 1)

    def test_an_empty_queue_with_closed_incidents_prints_the_footer_only(self):
        self._calibrate(0, 3)
        self._run("review", "t19", "tp")
        code, out, _ = self._run("queue")
        self.assertEqual(code, 0)
        self.assertEqual(
            out, "Set aside under the close level: 3 (target: at most 5% of true positives)\n"
                 "Shown above as audit: 0\n")

    def test_no_open_incidents_prints_plain_message(self):
        self._calibrate(0, 0)
        self._run("review", "t19", "tp")
        self.assertEqual(self._run("queue")[1], "No open incidents.\n")

    def test_review_records_the_score_and_pile_and_a_regrade_keeps_them(self):
        self._calibrate(3, 2)
        audit_id = sampled_ids(True, 1)[0]
        score = json.loads(self._run("inspect", audit_id, "--json")[1])["score"]
        self._run("review", audit_id, "bp")
        self._run("review", "t19", "fp")
        self._run("review", audit_id, "tp")
        with (self.runs_dir / "grades.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        mine = [row for row in rows if row["IncidentId"] == audit_id]
        self.assertEqual([row["grade"] for row in mine], ["BenignPositive", "TruePositive"])
        self.assertEqual({row["pile"] for row in mine}, {"audit"})
        self.assertEqual({round(float(row["score"]), 4) for row in mine}, {score})
        last = next(row for row in rows if row["IncidentId"] == "t19")
        self.assertEqual(last["pile"], "queue")
        # a true positive found in the audit weighs 10 and takes the level away
        report = self._queue_json()
        self.assertIsNone(report["close_level"])
        self.assertEqual((report["closed"], report["audit"]), (0, 0))

    def test_review_of_file_graded_true_positive_keeps_level(self):
        graded_id = sampled_ids(True, 1)[0]
        first, second, third = (f"2024-06-0{day}T00:00:00Z" for day in (7, 8, 9))
        rows = [plain_row(f"p{i}", "3", "TruePositive", first) for i in range(38)]
        rows += [plain_row(f"f{i}", "5", "FalsePositive", first) for i in range(10)]
        rows += [plain_row(graded_id, "5", "TruePositive", second),
                 plain_row("mid", "6", "TruePositive", second),
                 plain_row("other", "6", "FalsePositive", first),
                 plain_row("open", "3", time=third)]
        self._run("queue", str(write_csv(self.tmp / "graded.csv", rows)))
        level = self._queue_json()["close_level"]
        self.assertIsNotNone(level)
        score = json.loads(self._run("inspect", graded_id, "--json")[1])["score"]
        self.assertLess(score, level)
        self._run("review", graded_id, "tp")
        self.assertEqual(self._queue_json()["close_level"], level)
        with (self.runs_dir / "grades.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual([row["pile"] for row in rows], ["queue"])

    def test_footer_names_the_audit_sample_when_it_removes_the_level(self):
        self._calibrate(3, 2)
        self._run("review", sampled_ids(True, 1)[0], "tp")
        self.assertEqual(
            self._run("queue")[1].splitlines()[-1],
            "Nothing closed: a true positive found in the audit sample counts for ten.")

    def test_a_graded_incident_shows_the_pile_of_its_grade_row(self):
        self._calibrate(3, 2)
        audit_id = sampled_ids(True, 1)[0]
        self._run("review", audit_id, "fp")
        code, out, _ = self._run("inspect", audit_id)
        self.assertRegex(out, r"grade\s+FalsePositive\n")
        self.assertRegex(out, r"pile\s+audit\n")
        self.assertEqual(json.loads(self._run("inspect", audit_id, "--json")[1])["pile"],
                         "audit")
        self.assertEqual(json.loads(self._run("inspect", "t0", "--json")[1])["pile"],
                         "queue")
        closed_id = sampled_ids(False, 1)[0]
        self.assertRegex(self._run("inspect", closed_id)[1], r"reason\s+rule history lowers it\npile\s+closed\n")
        self.assertEqual(json.loads(self._run("inspect", closed_id, "--json")[1])["pile"],
                         "closed")

    def test_miss_rate_is_saved_and_used_by_later_commands(self):
        self._run("queue", str(self.csv))
        self._run("config", "miss_rate", "0.01")
        self.assertTrue((self.runs_dir / "settings.json").exists())
        self.assertEqual(self._queue_json()["miss_rate"], 0.01)
        self.assertEqual(self._run("queue")[1].splitlines()[-1],
                         "Nothing closed yet: 2 of 99 graded true positives.")
        self.assertEqual(self._run("inspect", "200")[0], 0)

    def test_a_quarter_percent_rate_is_shown_as_it_is(self):
        self._calibrate(3, 2)
        self._run("config", "miss_rate", "0.025")
        self.assertIn("(target: at most 2.5% of true positives)", self._run("queue")[1])
        self._run("config", "miss_rate", "0.005")
        self.assertIn("of 199 graded", self._run("queue")[1])
        self._run("config", "miss_rate", "0.1")
        self.assertIn("(target: at most 10% of true positives)", self._run("queue")[1])

    def test_review_records_the_pile_under_the_saved_miss_rate(self):
        self._calibrate(3, 2)
        closed_id = sampled_ids(False, 1)[0]
        self.assertEqual(self._queue_json()["closed"], 2)
        self._run("config", "miss_rate", "0.01")
        report = self._queue_json()
        self.assertEqual((report["closed"], report["audit"], report["close_level"]),
                         (0, 0, None))
        self._run("review", closed_id, "fp")
        with (self.runs_dir / "grades.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[-1]["pile"], "queue")
        self.assertEqual(json.loads(self._run("inspect", closed_id, "--json")[1])["pile"],
                         "queue")

    def test_config_prints_the_defaults_on_an_empty_runs_folder(self):
        code, out, err = self._run("config")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, f"miss_rate={close.DEFAULT_MISS_RATE}\nkeep_linked=true\n")
        self.assertFalse(self.runs_dir.exists())

    def test_config_sets_and_shows_each_setting(self):
        self.assertEqual(self._run("config", "miss_rate", "0.02")[1].splitlines()[0],
                         "miss_rate=0.02")
        self.assertEqual(self._run("config", "keep_linked", "false")[1].splitlines()[0],
                         "keep_linked=false")
        self.assertEqual(self._run("config")[1], "miss_rate=0.02\nkeep_linked=false\n")
        saved = json.loads((self.runs_dir / "settings.json").read_text())
        self.assertEqual(saved, {"miss_rate": 0.02, "keep_linked": False})

    def test_miss_rate_message_only_on_change(self):
        message = "Miss rate changed from 5% to 1%. Earlier grades keep the pile they were given."
        self.assertEqual(self._run("config", "miss_rate", "0.01")[1],
                         f"miss_rate=0.01\n{message}\n")
        self.assertEqual(self._run("config", "miss_rate", "0.01")[1], "miss_rate=0.01\n")
        self.assertEqual(self._run("config", "miss_rate", "0.05")[1].splitlines()[1],
                         "Miss rate changed from 1% to 5%. "
                         "Earlier grades keep the pile they were given.")
        self.assertEqual(self._run("config", "miss_rate", "0.05")[1], "miss_rate=0.05\n")

    def test_keep_linked_message_only_on_change(self):
        kept = "Incidents linked to a true positive are now kept in the queue."
        freed = "Incidents linked to a true positive can now be closed."
        self.assertEqual(self._run("config", "keep_linked", "true")[1], "keep_linked=true\n")
        self.assertEqual(self._run("config", "keep_linked", "false")[1],
                         f"keep_linked=false\n{freed}\n")
        self.assertEqual(self._run("config", "keep_linked", "false")[1], "keep_linked=false\n")
        self.assertEqual(self._run("config", "keep_linked", "true")[1],
                         f"keep_linked=true\n{kept}\n")

    def test_one_setting_changes_and_the_other_is_kept(self):
        self._run("config", "miss_rate", "0.01")
        self._run("config", "keep_linked", "false")
        saved = json.loads((self.runs_dir / "settings.json").read_text())
        self.assertEqual(saved, {"miss_rate": 0.01, "keep_linked": False})
        report = self._queue_json(str(self.csv))
        self.assertEqual((report["miss_rate"], report["keep_linked"]), (0.01, False))

    def test_config_with_one_argument_is_a_usage_error(self):
        for setting in ("miss_rate", "keep_linked"):
            with self.subTest(setting):
                code, out, err = self._run("config", setting)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("config takes SETTING and VALUE, or nothing", err)

    def test_a_bad_value_is_a_usage_error(self):
        bad = {"miss_rate": ("0", "1", "abc", "-0.1", "1.5"),
               "keep_linked": ("yes", "True", "1", "on", "")}
        expected = {"miss_rate": "miss_rate: expected a number between 0 and 1",
                    "keep_linked": "keep_linked: expected true or false"}
        for setting, values in bad.items():
            for value in values:
                with self.subTest(setting, value=value):
                    code, out, err = self._run("config", setting, value)
                    self.assertEqual((code, out), (2, ""))
                    self.assertIn(expected[setting], err)
        self.assertFalse((self.runs_dir / "settings.json").exists())

    def test_a_bad_settings_file_stops_config(self):
        self._run("queue", str(self.csv))
        (self.runs_dir / "settings.json").write_text("[]")
        for argv in (("config",), ("config", "miss_rate", "0.1")):
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("settings.json", err)

    def test_linked_true_positive_keeps_incident_in_queue(self):
        linked_id = self._calibrate_linked()
        lines = self._run("queue")[1].splitlines()
        self.assertEqual(
            lines[-3], "Set aside under the close level: 1 (target: at most 5% of true positives)")
        self.assertEqual(lines[-2], "Shown above as audit: 0")
        self.assertEqual(lines[-1], "Kept in the queue for a link to a true positive: 1")
        report = self._queue_json()
        self.assertEqual((report["keep_linked"], report["kept_linked"]), (True, 1))
        self.assertIn(linked_id, [row["IncidentId"] for row in report["queue"]])

    def test_without_the_rule_the_linked_incident_is_closed(self):
        linked_id = self._calibrate_linked()
        self._run("config", "keep_linked", "false")
        out = self._run("queue")[1]
        self.assertNotIn("Kept in the queue", out)
        self.assertIn("Set aside under the close level: 2", out)
        report = self._queue_json()
        self.assertEqual((report["keep_linked"], report["kept_linked"]), (False, 0))
        self.assertNotIn(linked_id, [row["IncidentId"] for row in report["queue"]])

    def test_review_records_the_queue_pile_of_a_linked_incident(self):
        linked_id = self._calibrate_linked()
        self._run("review", linked_id, "fp")
        with (self.runs_dir / "grades.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[-1]["pile"], "queue")

    def test_a_bad_settings_file_stops_every_scoring_command(self):
        self._run("queue", str(self.csv))
        (self.runs_dir / "settings.json").write_text("[]")
        for argv in (("queue",), ("review", "200", "tp"), ("inspect", "200")):
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("settings.json", err)
                self.assertEqual(err.count("\n"), 1)

    def test_queue_reads_a_file_through_a_preset_mapping(self):
        header = ("rule_id", "_time", "rule_name", "disposition_label")
        rows = (("n1", "2024-06-01T00:00:00Z", "r1", "True Positive - Suspicious Activity"),
                ("n2", "2024-06-02T00:00:00Z", "r1", "Undetermined"))
        path = write_csv(self.tmp / "notables.csv", rows, header)
        code, out, err = self._run("queue", str(path), "--mapping", "splunk")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("1 of 1 incidents in the queue", out)
        meta = json.loads(next(self.runs_dir.glob("*/meta.json")).read_text())
        self.assertEqual(meta["mapping"], "splunk")

    def test_mapping_without_a_file_is_a_usage_error(self):
        code, out, err = self._run("queue", "--mapping", "splunk")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--mapping needs FILE", err)

    def test_a_bad_mapping_is_one_line_and_not_a_traceback(self):
        code, out, err = self._run("queue", str(self.csv), "--mapping", "nowhere.toml")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("nowhere.toml: no such mapping", err)
        self.assertEqual(err.count("\n"), 1)
        self.assertFalse(self.runs_dir.exists())

    def _assert_one_line_error(self, argv, needle: str) -> None:
        code, out, err = self._run(*argv)
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("meerkat: error: "))
        self.assertEqual(err.count("\n"), 1)
        self.assertIn(needle, err)

    def test_a_pipe_closed_before_a_small_output_exits_quietly(self):
        command = [sys.executable, "-m", "meerkat", "queue", str(self.csv),
                   "--runs-dir", str(self.runs_dir)]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as process:
            process.stdout.close()
            error = process.stderr.read()
            self.assertEqual(process.wait(), 1)
        self.assertEqual(error, "")

    def test_closed_footer_names_the_list_and_the_audit_rows(self):
        self._calibrate(3, 2)
        lines = self._run("queue", "--closed")[1].splitlines()
        self.assertEqual(lines[-2].split(", run ")[0], "2 of 2 incidents set aside")
        self.assertEqual(lines[-1], "In the queue as audit: 3")
        plain = self._run("queue")[1].splitlines()
        self.assertEqual(plain[-2], "Set aside under the close level: 2 "
                                    "(target: at most 5% of true positives)")
        self.assertEqual(plain[-1], "Shown above as audit: 3")
        self.assertIn("4 of 4 incidents in the queue", plain[-3])

    def test_closed_footer_keeps_the_linked_line(self):
        self._calibrate_linked()
        lines = self._run("queue", "--closed")[1].splitlines()
        self.assertEqual(lines[-3].split(", run ")[0], "1 of 1 incidents set aside")
        self.assertEqual(lines[-2], "In the queue as audit: 0")
        self.assertEqual(lines[-1], "Kept in the queue for a link to a true positive: 1")

    def _table(self, columns: int | None, rows: list[tuple[str, ...]]) -> list[str]:
        class Terminal(io.StringIO):
            def isatty(self) -> bool:
                return columns is not None

        out = Terminal()
        size = os.terminal_size((columns or 80, 24))
        with (contextlib.redirect_stdout(out),
              mock.patch.object(cli.shutil, "get_terminal_size", return_value=size)):
            cli._print_table(("id", "score", "title"), rows)
        return out.getvalue().splitlines()

    def test_a_terminal_shortens_only_the_last_column(self):
        rows = [("1", "0.50", "x" * 100), ("22", "0.75", "short")]
        lines = self._table(30, rows)
        self.assertEqual(lines[0], "id  score  title")
        self.assertEqual(lines[1], "1   0.50   " + "x" * 19)
        self.assertEqual(lines[2], "22  0.75   short")
        self.assertTrue(all(len(line) <= 30 for line in lines))

    def test_a_terminal_narrower_than_the_fixed_columns_cuts_nothing_else(self):
        rows = [("1", "0.50", "x" * 100)]
        lines = self._table(8, rows)
        self.assertEqual(lines[0], "id  score  title")
        self.assertEqual(lines[1], "1   0.50   " + "x" * 100)

    def test_a_pipe_gets_every_character(self):
        rows = [("1", "0.50", "x" * 300)]
        self.assertEqual(self._table(None, rows)[1], "1   0.50   " + "x" * 300)

    def test_version_and_help_do_not_load_pandas(self):
        code = ("import sys; from meerkat.cli import main\n"
                "try:\n    main(sys.argv[1:])\n"
                "except SystemExit:\n    pass\n"
                "assert 'pandas' not in sys.modules and 'numpy' not in sys.modules")
        for argv in (["--version"], ["--help"], ["queue", "--help"]):
            with self.subTest(argv):
                done = subprocess.run([sys.executable, "-c", code, *argv],
                                      capture_output=True, text=True, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(__version__, subprocess.run(
            [sys.executable, "-m", "meerkat", "--version"],
            capture_output=True, text=True, check=False).stdout)


if __name__ == "__main__":
    unittest.main()
