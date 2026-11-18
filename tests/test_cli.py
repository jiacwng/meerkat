# The four commands end to end, through main(), on a temporary runs directory.

import contextlib
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import budget, store
from meerkat import __version__, cli
from meerkat.cli import main
from tests.fixtures import (
    HEADER,
    ROWS,
    budget_rows,
    plain_row,
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
        self.assertEqual(lines[4:], ["Total: 3  budget: none"])
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
        self.assertIn("\n1 of 3 shown\nTotal: 3  budget: none\n", out)

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
        self.assertIn("\nTotal: 5  budget: none\n", out)
        report = json.loads(self._run("queue", "--json")[1])
        self.assertEqual((report["run"], report["open"], report["to_read"],
                          report["below_budget"]), (None, 5, 5, 0))
        self.assertEqual(self._queue_ids("--limit", "2"), ["c1", "b1"])
        self.assertIn("\n2 of 5 shown\n", self._run("queue", "--limit", "2")[1])
        self.assertEqual(self._queue_ids("--run", first), ["a1", "a2"])
        self.assertIn(f"\nTotal: 2  budget: none  run: {first}\n",
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

    def test_review_file_records_every_grade_or_none(self):
        self._run("queue", str(self.csv))
        grades = self.tmp / "grades.csv"
        grades.write_text("IncidentId,IncidentGrade\n200,FalsePositive\n201,TruePositive\n")
        code, out, _ = self._run("review", "--file", str(grades))
        self.assertEqual((code, out), (0, f"2 incidents graded from {grades}\n"
                                          "True positives: 1\n"))
        self.assertEqual(self._queue_ids(), ["202"])
        record = json.loads(self._run("inspect", "201", "--json")[1])
        self.assertEqual(record["IncidentGrade"], "TruePositive")

        before = (self.runs_dir / "grades.csv").read_text()
        for text, message in (
                ("IncidentId,IncidentGrade\n202,TruePositive\nnope,TruePositive\n",
                 "no incident 'nope'"),
                ("IncidentId,IncidentGrade\n202,malicious\n", "'malicious' is not one of"),
                ("IncidentId,IncidentGrade\n,TruePositive\n", "a row has no IncidentId"),
                ("IncidentId,IncidentGrade\n", "no grade rows"),
                ("IncidentId\n202\n", "missing column IncidentGrade"),
                ("", "missing column IncidentId")):
            grades.write_text(text)
            code, _, err = self._run("review", "--file", str(grades))
            self.assertEqual(code, 1)
            self.assertIn(message, err)
            self.assertEqual(err.count("\n"), 1)
        self.assertEqual(self._run("review", "--file", str(self.tmp / "none.csv"))[0], 1)
        self.assertEqual((self.runs_dir / "grades.csv").read_text(), before)

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
        self.assertRegex(out, r"rule history\s+never graded\nlinked incidents\s+none\n")
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
            ("review",),
            ("review", "200", "tp", "--file", "grades.csv"),
            ("review", "--file", "grades.csv", "--note", "text"),
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

    def _queue_json(self, *argv: str) -> dict:
        return json.loads(self._run("queue", "--json", *argv)[1])

    def _grade_rows(self) -> list[dict]:
        with (self.runs_dir / "grades.csv").open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def _budget(self, budget: str = "4", rows=None) -> str:
        self._run("config", "budget", budget)
        rows = budget_rows() if rows is None else rows
        self._run("queue", str(write_csv(self.tmp / "many.csv", rows)))
        samples = store.read_samples(self.runs_dir)
        return samples[0]["drawn"][0] if samples and samples[0]["drawn"] else ""

    def test_without_a_budget_every_open_incident_is_listed(self):
        self._run("queue", str(write_csv(self.tmp / "many.csv", budget_rows())))
        lines = self._run("queue")[1].splitlines()
        self.assertEqual(lines[0].split()[:4], ["#", "incident", "score", "status"])
        self.assertEqual(len(lines), 13)
        self.assertEqual(lines[-1], "Total: 11  budget: none")
        report = self._queue_json()
        self.assertEqual({key: report[key] for key in
                          ("open", "budget", "sample_share", "to_read", "below_budget",
                           "sample", "unread_true_positives")},
                         {"open": 11, "budget": None, "sample_share": 0.1, "to_read": 11,
                          "below_budget": 0, "unread_true_positives": None,
                          "sample": {"drawn": 0, "graded": 0, "true_positive": 0}})
        self.assertEqual({row["status"] for row in report["queue"]}, {"ranked"})
        self.assertFalse(list(self.runs_dir.glob("*/sample.json")))

    def test_a_budget_lists_the_top_and_one_sampled_incident(self):
        sampled = self._budget()
        self.assertRegex(sampled, r"^l\d$")
        lines = self._run("queue")[1].splitlines()
        self.assertEqual([line.split()[1] for line in lines[1:5]], ["h2", "h1", "h0", sampled])
        self.assertEqual(lines[4].split()[3], "sample")
        self.assertEqual(lines[5:], ["Total: 11 (to read: 4, below the budget: 7)  budget: 4",
                                     "Sample: 1 drawn, 0 graded"])
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["below_budget"], report["sample"]["drawn"]),
                         (4, 7, 1))
        self.assertEqual([row["status"] for row in report["queue"]],
                         ["ranked"] * 3 + ["sample"] + ["below"] * 7)
        self.assertEqual([row["position"] for row in report["queue"]], list(range(1, 12)))

    def test_all_lists_the_incidents_below_the_budget_under_a_label(self):
        self._budget()
        lines = self._run("queue", "--all")[1].splitlines()
        self.assertEqual(lines[5], "Below the budget:")
        self.assertEqual(len(lines), 15)
        self.assertEqual([line.split()[0] for line in lines[6:13]],
                         [str(number) for number in range(5, 12)])
        self.assertNotIn("Below the budget:", self._run("queue")[1])

    def test_limit_cuts_the_list_and_json_lists_every_open_incident(self):
        self._budget()
        lines = self._run("queue", "--limit", "2")[1].splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[3], "2 of 4 shown")
        self.assertEqual(len(self._queue_json()["queue"]), 11)
        self.assertEqual(len(self._queue_json("--limit", "5")["queue"]), 5)

    def test_the_sample_stays_when_the_queue_or_the_file_is_read_again(self):
        sampled = self._budget()
        for _ in range(2):
            rows = self._queue_json()["queue"]
            self.assertEqual([row["IncidentId"] for row in rows if row["status"] == "sample"],
                             [sampled])
        self._run("queue", str(self.tmp / "many.csv"))
        self.assertEqual(len(list(self.runs_dir.glob("*/sample.json"))), 1)
        self.assertEqual(self._queue_json()["sample"]["drawn"], 1)

    def test_a_later_file_draws_from_its_own_incidents(self):
        self._run("review", self._budget(), "fp")
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(3)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        samples = store.read_samples(self.runs_dir)
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[1]["pool"], ["n2", "n1", "n0"])
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["sample"]["drawn"]), (4, 2))
        self.assertEqual([row["IncidentId"] for row in report["queue"]
                          if row["status"] == "sample"], samples[1]["drawn"])

    def test_no_new_sample_while_an_earlier_one_waits_for_its_grade(self):
        sampled = self._budget()
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(3)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(len(store.read_samples(self.runs_dir)), 1)
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["sample"]["drawn"]), (4, 1))
        self.assertEqual([row["IncidentId"] for row in report["queue"]
                          if row["status"] == "sample"], [sampled])

    def test_a_graded_sample_gives_the_estimate(self):
        sampled = self._budget()
        self._run("review", sampled, "fp")
        self.assertEqual(self._run("queue")[1].splitlines()[-2:], [
            "Total: 10 (to read: 4, below the budget: 6)  budget: 4",
            "Sample: 1 graded, 0 true positive. Unread true positives: 0 to 7 (95%)"])
        report = self._queue_json()
        self.assertEqual(report["sample"], {"drawn": 1, "graded": 1, "true_positive": 0})
        self.assertEqual(report["unread_true_positives"], {"estimate": 0, "low": 0, "high": 7})

    def test_a_true_positive_in_the_sample_raises_the_estimate(self):
        sampled = self._budget()
        self._run("review", sampled, "tp")
        self.assertEqual(self._queue_json()["unread_true_positives"],
                         {"estimate": 7, "low": 0, "high": 7})

    def test_a_budget_above_the_open_incidents_reads_them_all(self):
        self.assertEqual(self._budget("25"), "")
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["below_budget"]), (11, 0))
        self.assertEqual(self._run("queue")[1].splitlines()[-1],
                         "Total: 11 (to read: 11, below the budget: 0)  budget: 25")

    def _marked_rows(self) -> list:
        rows = [list(row) for row in budget_rows()]
        rows += [list(plain_row("linked", "9", time="2024-06-10T02:00:00Z")),
                 list(plain_row("fresh", "42", time="2024-06-10T02:01:00Z"))]
        for row in rows:
            if row[1] in ("p0", "linked"):
                row[9] = "ann"
        return rows

    def test_a_link_and_a_new_rule_are_marked_below_the_budget(self):
        self._run("config", "sample_share", "0")
        self.assertEqual(self._budget("3", self._marked_rows()), "")
        lines = self._run("queue", "--all")[1].splitlines()
        marks = {line.split()[1]: line.split()[3:5] for line in lines[5:15]}
        self.assertEqual(marks["fresh"], ["new", "rule"])
        self.assertEqual(marks["linked"][0], "linked")
        self.assertEqual(marks["l0"][0], "9")
        self.assertEqual(lines[-2:], [
            "Total: 13 (to read: 3, below the budget: 10)  budget: 3",
            "Below the budget: 1 linked to a true positive, 1 with a rule never graded"])
        self.assertEqual(self._run("queue")[1].splitlines()[-1], lines[-1])
        self.assertNotIn("linked", self._run("queue", "--limit", "3")[1].splitlines()[1])

    def test_review_records_the_status_and_a_regrade_keeps_it(self):
        sampled = self._budget()
        below = next(row["IncidentId"] for row in self._queue_json()["queue"]
                     if row["status"] == "below")
        score = json.loads(self._run("inspect", sampled, "--json")[1])["score"]
        for incident in (sampled, "h2", below, "p0"):
            self._run("review", incident, "bp")
        self._run("review", sampled, "tp")
        rows = self._grade_rows()
        self.assertEqual([row["status"] for row in rows],
                         ["sample", "ranked", "below", "", "sample"])
        mine = [row for row in rows if row["IncidentId"] == sampled]
        self.assertEqual([row["grade"] for row in mine], ["BenignPositive", "TruePositive"])
        self.assertEqual({round(float(row["score"]), 4) for row in mine}, {score})

    def test_review_file_counts_the_true_positives_by_status(self):
        sampled = self._budget()
        below = next(row["IncidentId"] for row in self._queue_json()["queue"]
                     if row["status"] == "below")
        grades = self.tmp / "grades.csv"
        grades.write_text("IncidentId,IncidentGrade\nh0,TruePositive\nh1,FalsePositive\n"
                          f"{sampled},TruePositive\n{below},TruePositive\n")
        self.assertEqual(self._run("review", "--file", str(grades))[1],
                         f"4 incidents graded from {grades}\n"
                         "True positives: 3 (to read: 1, sample: 1, below the budget: 1)\n")

    def test_inspect_shows_the_status(self):
        sampled = self._budget()
        self.assertRegex(self._run("inspect", sampled)[1],
                         r"reason\s+rule history lowers it\nstatus\s+sample\n")
        self.assertEqual(json.loads(self._run("inspect", "h2", "--json")[1])["status"], "ranked")
        self._run("review", sampled, "fp")
        self.assertRegex(self._run("inspect", sampled)[1], r"status\s+sample\n")
        self.assertEqual(json.loads(self._run("inspect", "p0", "--json")[1])["status"], "")

    def test_a_run_view_has_no_sample_line(self):
        self._budget()
        run = store.list_runs(self.runs_dir)[-1]["run"]
        self.assertEqual(
            self._run("queue", "--run", run)[1].splitlines()[-1],
            f"Total: 11 (to read: 4, below the budget: 7)  budget: 4  run: {run}")

    def test_no_open_incidents_prints_plain_message(self):
        self._budget()
        for row in self._queue_json()["queue"]:
            self._run("review", row["IncidentId"], "fp")
        self.assertEqual(self._run("queue")[1], "No open incidents.\n")

    def test_config_prints_the_defaults_on_an_empty_runs_folder(self):
        code, out, err = self._run("config")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, f"budget=none\nsample_share={budget.DEFAULT_SAMPLE_SHARE}\n")
        self.assertFalse(self.runs_dir.exists())

    def test_config_sets_shows_and_clears_each_setting(self):
        message = "A sample is drawn from the next file given to meerkat queue."
        self.assertEqual(self._run("config", "budget", "25")[1], f"budget=25\n{message}\n")
        self.assertEqual(self._run("config", "budget", "30")[1], "budget=30\n")
        self.assertEqual(self._run("config", "sample_share", "0.2")[1], "sample_share=0.2\n")
        self.assertEqual(self._run("config")[1], "budget=30\nsample_share=0.2\n")
        saved = json.loads((self.runs_dir / "settings.json").read_text())
        self.assertEqual(saved, {"budget": 30, "sample_share": 0.2})
        self.assertEqual(self._run("config", "budget", "none")[1], "budget=none\n")
        self.assertEqual(json.loads((self.runs_dir / "settings.json").read_text()),
                         {"sample_share": 0.2})
        self.assertEqual(self._queue_json(str(self.csv))["budget"], None)

    def test_config_with_one_argument_is_a_usage_error(self):
        for setting in ("budget", "sample_share"):
            with self.subTest(setting):
                code, out, err = self._run("config", setting)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("config takes SETTING and VALUE, or nothing", err)

    def test_a_bad_value_is_a_usage_error(self):
        bad = {"budget": ("0", "-3", "2.5", "abc", "None", ""),
               "sample_share": ("1", "abc", "-0.1", "1.5", "")}
        expected = {"budget": "budget: expected a whole number above 0",
                    "sample_share": "sample_share: expected a number from 0 up to 1"}
        for setting, values in bad.items():
            for value in values:
                with self.subTest(setting, value=value):
                    code, out, err = self._run("config", setting, value)
                    self.assertEqual((code, out), (2, ""))
                    self.assertIn(expected[setting], err)
        self.assertEqual(self._run("config", "miss_rate", "0.05")[0], 2)
        self.assertFalse((self.runs_dir / "settings.json").exists())

    def test_a_bad_settings_file_stops_config(self):
        self._run("queue", str(self.csv))
        (self.runs_dir / "settings.json").write_text("[]")
        for argv in (("config",), ("config", "budget", "5")):
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("settings.json", err)

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
        self.assertIn("\nTotal: 1  budget: none\n", out)
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
