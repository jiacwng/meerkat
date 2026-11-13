# The four commands end to end, through main(), on a temporary runs directory.

import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from meerkat import __version__
from meerkat.cli import main
from tests.fixtures import (
    HEADER,
    ROWS,
    calibration_rows,
    plain_row,
    sampled_ids,
    write_csv,
)


class CliTests(unittest.TestCase):
    def setUp(self):
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
        self.assertIn("3 of 3 open incidents", lines[4])
        self.assertEqual(lines[5], "Nothing closed yet: 2 of 19 graded true positives.")
        self.assertNotIn("100", [line.split()[1] for line in lines[1:4]])

    def test_queue_without_a_file_reopens_the_latest_run(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])
        self.assertEqual(len(list(self.runs_dir.glob("*/meta.json"))), 1)

    def test_limit_and_all(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids("--limit", "1"), ["201"])
        self.assertEqual(self._queue_ids("--all"), ["201", "202", "200"])
        code, out, _ = self._run("queue", "--limit", "1")
        self.assertIn("1 of 3 open incidents", out)

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
        self.assertEqual(self._queue_ids(str(later_csv)), ["900"])
        code, out, _ = self._run("inspect", "900", "--json")
        self.assertEqual(json.loads(out)["score"], 0.5)
        self._run("review", "202", "tp")
        code, out, _ = self._run("inspect", "900", "--json")
        record = json.loads(out)
        self.assertEqual((record["rule_graded"], record["rule_true_positives"]), (1, 1))
        self.assertGreater(record["score"], 0.5)
        self.assertEqual(self._queue_ids(), ["900"])

    def test_queue_with_nothing_open(self):
        self._run("queue", str(write_csv(self.tmp / "graded.csv", ROWS[:5])))
        code, out, _ = self._run("queue")
        self.assertEqual(code, 0)
        self.assertIn("No open incidents", out)

    def test_inspect_text_and_json(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("inspect", "100")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"rule\s+7\n")
        self.assertRegex(out, r"MitreTechniques\s+T1078, T1078.004, T1114\n")
        self.assertRegex(out, r"grade\s+TruePositive\n")
        self.assertRegex(out, r"IpAddress\s+10.0.0.1, 10.0.0.2\n")
        self.assertNotIn("Sha256", out)
        code, out, _ = self._run("inspect", "100", "--json")
        record = json.loads(out)
        self.assertEqual(record["IpAddress"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(record["Sha256"], [])

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
        for argv in (("review", "nope", "tp"), ("inspect", "nope"),
                     ("queue", "--run", "../..")):
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
                self.assertIn("[red]:skull:", out)
        code, _, err = self._run("inspect", "\x1b[2Jx")
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", err)

    def _calibrate(self, audit: int, closed: int, graded: int = 19) -> None:
        rows = calibration_rows(audit, closed)
        self._run("queue", str(write_csv(self.tmp / "many.csv", rows)))
        for number in range(graded):
            self.assertEqual(self._run("review", f"t{number}", "tp")[0], 0)

    def _queue_json(self, *argv: str) -> dict:
        return json.loads(self._run("queue", "--json", *argv)[1])

    def test_footer_without_a_level_counts_toward_the_needed_true_positives(self):
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
        self.assertEqual(report["open"], 24)

    def test_graded_history_in_the_file_closes_incidents_without_a_review(self):
        closed_id = sampled_ids(False, 1)[0]
        rows = [plain_row(f"p{i}", "3", "TruePositive") for i in range(19)]
        rows += [plain_row("q0", "1", "TruePositive")]
        rows += [plain_row(f"q{i}", "1", "FalsePositive") for i in range(1, 5)]
        rows += [plain_row(f"f{i}", "5", "FalsePositive") for i in range(10)]
        rows += [plain_row("keep", "1"), plain_row(closed_id, "5")]
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
            lines[-1], "2 more are under the close level (at most 5% of true positives). "
                       "3 others under it are above as audit.")
        self.assertIn("4 of 4 open incidents", lines[-2])
        shown = {line.split()[1]: line.split() for line in lines[1:-2]}
        self.assertEqual(set(shown), {"t19", *audit_ids})
        self.assertNotIn("audit", shown["t19"])
        for incident in audit_ids:
            self.assertEqual(shown[incident][3], "audit")
        self.assertFalse(set(closed_ids) & set(shown))

    def test_json_reports_the_level_and_the_pile_of_each_row(self):
        self._calibrate(3, 2)
        report = self._queue_json()
        self.assertAlmostEqual(report["close_level"], 0.5935, places=4)
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
        self.assertIn("2 of 3 open incidents", lines[3])
        self.assertEqual(len(self._queue_json("--closed", "--all")["queue"]), 3)
        self.assertEqual(len(self._queue_json("--closed", "--limit", "1")["queue"]), 1)

    def test_an_empty_queue_with_closed_incidents_prints_the_footer_only(self):
        self._calibrate(0, 3)
        self._run("review", "t19", "tp")
        code, out, _ = self._run("queue")
        self.assertEqual(code, 0)
        self.assertEqual(
            out, "3 more are under the close level (at most 5% of true positives). "
                 "0 others under it are above as audit.\n")

    def test_no_open_incident_at_all_keeps_the_old_message(self):
        self._calibrate(0, 0)
        self._run("review", "t19", "tp")
        run = json.loads(self._run("runs", "--json")[1])[0]["run"]
        self.assertEqual(self._run("queue")[1], f"No open incidents in run {run}.\n")

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
        self.assertRegex(self._run("inspect", closed_id)[1], r"score\s+0\.\d\d\npile\s+closed\n")
        self.assertEqual(json.loads(self._run("inspect", closed_id, "--json")[1])["pile"],
                         "closed")

    def test_a_grades_file_without_the_new_columns_is_refused(self):
        self._run("queue", str(self.csv))
        self.runs_dir.joinpath("grades.csv").write_text(
            "time,IncidentId,grade,note\nt,200,TruePositive,\n")
        for argv in (("queue",), ("review", "201", "tp"), ("inspect", "200")):
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("expected columns", err)
                self.assertEqual(err.count("\n"), 1)

    def test_version_and_help_do_not_load_pandas(self):
        code = ("import sys; from meerkat.cli import main\n"
                "try:\n    main(sys.argv[1:])\n"
                "except SystemExit:\n    pass\n"
                "assert 'pandas' not in sys.modules")
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
