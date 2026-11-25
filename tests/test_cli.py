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
from core.incidents import COLUMNS
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
        self.assertEqual(lines[0].split()[:3], ["#", "INCIDENT", "SCORE"])
        self.assertEqual([line.split()[1] for line in lines[1:4]], ["201", "202", "200"])
        self.assertEqual(lines[4:], ["", "OPEN           3 incidents in 3 rows, 3 listed"])
        self.assertNotIn("100", [line.split()[1] for line in lines[1:4]])

    def test_queue_table_shows_counts_and_the_user(self):
        code, out, _ = self._run("queue", str(self.csv))
        lines = out.splitlines()
        self.assertRegex(lines[0], r"GROUP\s+RULE_TP\s+SIMILAR_TP\s+FLAG\s+CATEGORY\s+HOST\s+USER\s+TIME\s+TITLE")
        self.assertRegex(lines[1], r"\s2/2\s+1/1\s+InitialAccess\s+alice\s+06-05 13:00\s")
        self.assertRegex(lines[2], r"\s0/0\s+0/0\s+Discovery\s+frank\s+06-05")
        self.assertRegex(lines[3], r"\s0/2\s+0/0\s+Exfiltration\s+erin\s+06-05")

    def test_severity_is_a_column_only_when_the_file_has_one(self):
        self.assertNotIn("SEVERITY", self._run("queue", str(self.csv))[1])
        rows = [(*plain_row("v1", "5"), "High"), (*plain_row("v2", "6"), "")]
        classified = write_csv(self.tmp / "severity.csv", rows, (*HEADER, "Severity"))
        lines = self._run("queue", str(classified))[1].splitlines()
        self.assertRegex(lines[0], r"CATEGORY\s+SEVERITY\s+HOST")
        self.assertRegex(next(line for line in lines if " v1 " in line), r"Category\s+High\s")
        self.assertRegex(self._run("details", "v1")[1], r"\nseverity\s+High\n")
        self.assertNotIn("severity", self._run("details", "v2")[1])
        self.assertEqual(json.loads(self._run("details", "v1", "--json")[1])["Severity"], "High")

    def test_details_counts_the_earlier_classifications_of_the_rule_and_of_the_similar_incidents(self):
        self._run("queue", str(self.csv))
        self.assertIn("SCORE\n"
                      "score           0.64\n"
                      "rule            2 TP  0 BP  0 FP  of 2 classified before\n"
                      "similar         1 TP  0 BP  0 FP  of 1 classified before\n"
                      "same rule       1 of 1\n", self._run("details", "201")[1])
        self.assertIn("rule            0 TP  1 BP  1 FP  of 2 classified before",
                      self._run("details", "200")[1])
        record = json.loads(self._run("details", "201", "--json")[1])
        self.assertEqual((record["rule_benign_positives"], record["similar_same_rule"]), (0, 1))
        self.assertNotIn("score_without_links", record)

    def test_a_group_is_one_row_and_classify_can_classify_all_of_it(self):
        rows = [("1", name, f"a{name}", "2024-06-10T00:00:00Z", "5", "Title", "Category", "",
                 "", "zed", "") for name in ("g1", "g2")]
        rows += [plain_row(f"s{number}", "5") for number in range(3)]
        self._run("queue", str(write_csv(self.tmp / "grouped.csv", rows)))
        report = json.loads(self._run("queue", "--json")[1])
        self.assertEqual((report["open"], report["grouped"], len(report["queue"])), (5, 1, 4))
        self.assertEqual(report["queue"][0]["members"], ["g2"])
        lines = self._run("queue")[1].splitlines()
        self.assertEqual(lines[1].split()[:4], ["1", "g1", "0.50", "2"])
        self.assertEqual(lines[-1], "OPEN           5 incidents in 4 rows, 4 listed")
        self.assertRegex(self._run("details", "g1")[1], r"\nGROUP\nincidents\s+g2\n")
        self.assertEqual(self._run("classify", "g1", "tp", "--group")[1],
                         "CLASSIFIED   incident g1   classification TruePositive   incidents 2\n"
                         "  classified   g1 g2\n")
        self.assertEqual(self._queue_ids(), ["s0", "s1", "s2"])
        self.assertRegex(self._run("details", "g2")[1],
                         r"\nHISTORY\nCLASSIFIED\s+CLASSIFICATION\s+COMMENT\n\S+\s+TruePositive\n")

    def test_a_group_row_shows_its_latest_time_and_classify_names_what_it_left_and_replaced(self):
        rows = [("1", "g1", "ag1", "2024-06-10T00:00:00Z", "5", "Title", "Category", "", "",
                 "amy", "10.9.9.9"),
                ("1", "g2", "ag2", "2024-06-11T05:00:00Z", "5", "Title", "Category", "", "",
                 "amy", "10.9.9.9")]
        rows += [plain_row(f"s{number}", "5") for number in range(3)]
        self._run("queue", str(write_csv(self.tmp / "grouped.csv", rows)))
        self.assertRegex(self._run("queue")[1].splitlines()[1],
                         r"^1  g2\s+0\.50\s+2\s.*\samy\s+06-11 05:00\s")
        self._run("classify", "g1", "bp")
        self.assertEqual(self._run("classify", "g2", "tp", "--group")[1],
                         "CLASSIFIED   incident g2   classification TruePositive   incidents 1\n"
                         "  classified   g2\n"
                         "  kept         g1 BenignPositive\n")
        self.assertEqual(self._run("classify", "g2", "fp")[1],
                         "CLASSIFIED   incident g2   classification FalsePositive   incidents 1"
                         "   replaced TruePositive\n")

    def test_a_budget_set_after_a_file_was_scored_draws_the_sample_at_once(self):
        self._run("queue", str(write_csv(self.tmp / "many.csv", budget_rows())))
        self.assertEqual(store.read_samples(self.runs_dir), [])
        self.assertEqual(self._run("config", "budget", "4")[1], "budget=4\n")
        samples = store.read_samples(self.runs_dir)
        self.assertEqual((len(samples), len(samples[0]["drawn"])), (1, 1))

    def test_a_changed_setting_draws_the_sample_again_until_one_of_its_rows_is_classified(self):
        self._budget()
        self._run("config", "sample_share", "0.5")
        drawn = store.read_samples(self.runs_dir)[0]["drawn"]
        self.assertEqual(len(drawn), 2)
        self._run("config", "budget", "25")
        self.assertEqual(store.read_samples(self.runs_dir), [])
        self.assertNotIn("to classify", self._run("budget")[1])
        self._run("config", "budget", "4")
        samples = store.read_samples(self.runs_dir)
        self.assertEqual(samples[0]["drawn"], drawn)
        self._run("classify", drawn[0], "fp")
        self._run("config", "sample_share", "0.1")
        self._run("config", "budget", "25")
        self.assertEqual(store.read_samples(self.runs_dir), samples)

    def test_classify_group_on_a_classified_incident_classifies_the_open_rest_of_its_group(self):
        rows = [("1", name, f"a{name}", "2024-06-10T00:00:00Z", "5", "Title", "Category", "",
                 "", "zed", "") for name in ("g1", "g2", "g3")]
        rows += [plain_row(f"s{number}", "5") for number in range(3)]
        self._run("queue", str(write_csv(self.tmp / "grouped.csv", rows)))
        self._run("classify", "g1", "tp")
        self.assertEqual(self._run("classify", "g1", "tp", "--group")[1],
                         "CLASSIFIED   incident g1   classification TruePositive   incidents 3\n"
                         "  classified   g1 g2 g3\n")
        self.assertEqual(self._queue_ids(), ["s0", "s1", "s2"])
        self.assertEqual(self._run("classify", "nope", "tp", "--group")[0], 1)

    def test_a_damaged_run_or_classification_file_is_one_line_and_not_a_traceback(self):
        self._run("queue", str(self.csv))
        self._run("classify", "200", "fp")
        classifications = self.runs_dir / "classifications.csv"
        kept = classifications.read_text()
        for text in ("", "time,IncidentId\nx,200\n", kept.replace("0.", "zero"), '"open quote'):
            classifications.write_text(text)
            for argv in (("queue",), ("details", "200"), ("classify", "200", "tp"), ("budget",),
                         ("config", "budget", "2")):
                with self.subTest(text=text, argv=argv):
                    self._assert_one_line_error(argv, "classifications.csv")
        classifications.write_text('"open quote')
        settings = self.runs_dir / "settings.json"
        before = settings.read_text() if settings.exists() else None
        self.assertEqual(self._run("config", "budget", "2")[0], 1)
        self.assertEqual(settings.read_text() if settings.exists() else None, before)
        classifications.write_text(kept)
        meta = next(self.runs_dir.glob("*/meta.json"))
        for text in ("not json", "[]", "{}", '{"created": 5, "file": "a", "incidents_in_file": 1}'):
            meta.write_text(text)
            for argv in (("queue",), ("runs",), ("queue", str(self.csv)), ("budget",)):
                with self.subTest(text=text, argv=argv):
                    self._assert_one_line_error(argv, "meta.json")

    def test_queue_without_a_file_reopens_the_latest_run(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids(), ["201", "202", "200"])
        self.assertEqual(len(list(self.runs_dir.glob("*/meta.json"))), 1)

    def test_limit_and_all(self):
        self._run("queue", str(self.csv))
        self.assertEqual(self._queue_ids("--limit", "1"), ["201"])
        self.assertEqual(self._queue_ids("--all"), ["201", "202", "200"])
        code, out, _ = self._run("queue", "--limit", "1")
        self.assertIn("\n\nOPEN           3 incidents in 3 rows, 1 of 3 listed\n", out)

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
        self.assertIn("\nOPEN           5 incidents in 5 rows, 5 listed\n", out)
        report = json.loads(self._run("queue", "--json")[1])
        self.assertEqual((report["run"], report["open"], report["to_read"],
                          report["below_budget"]), (None, 5, 5, 0))
        self.assertEqual(self._queue_ids("--limit", "2"), ["c1", "b1"])
        self.assertIn("\nOPEN           5 incidents in 5 rows, 2 of 5 listed\n",
                      self._run("queue", "--limit", "2")[1])
        self.assertEqual(self._queue_ids("--run", first), ["a1", "a2"])
        self.assertIn(f"\nOPEN           2 incidents in 2 rows, 2 listed\nRUN            {first}\n",
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

    def test_a_classified_incident_leaves_the_list_of_every_run(self):
        self._three_runs()
        self._run("classify", "b1", "fp")
        self.assertEqual(self._queue_ids(), ["b2", "a1", "a2", "c1"])
        self.assertEqual(json.loads(self._run("queue", "--json")[1])["open"], 4)

    def test_classify_file_records_every_classification_or_none(self):
        self._run("queue", str(self.csv))
        classifications = self.tmp / "classifications.csv"
        classifications.write_text("IncidentId,IncidentGrade\n200,FalsePositive\n201,TruePositive\n")
        code, out, _ = self._run("classify", "--file", str(classifications))
        self.assertEqual((code, out), (0, "CLASSIFIED   incidents 2   tp 1\n"))
        self.assertEqual(self._queue_ids(), ["202"])
        record = json.loads(self._run("details", "201", "--json")[1])
        self.assertEqual(record["IncidentGrade"], "TruePositive")

        before = (self.runs_dir / "classifications.csv").read_text()
        for text, message in (
                ("IncidentId,IncidentGrade\n202,TruePositive\nnope,TruePositive\n",
                 "no incident 'nope'"),
                ("IncidentId,IncidentGrade\n202,malicious\n", "'malicious' is not one of"),
                ("IncidentId,IncidentGrade\n,TruePositive\n", "a row has no IncidentId"),
                ("IncidentId,IncidentGrade\n", "no classification rows"),
                ("IncidentId\n202\n", "missing column IncidentGrade"),
                ("", "missing column IncidentId")):
            classifications.write_text(text)
            code, _, err = self._run("classify", "--file", str(classifications))
            self.assertEqual(code, 1)
            self.assertIn(message, err)
            self.assertEqual(err.count("\n"), 1)
        self.assertEqual(self._run("classify", "--file", str(self.tmp / "none.csv"))[0], 1)
        self.assertEqual((self.runs_dir / "classifications.csv").read_text(), before)

    def test_classify_moves_the_queue(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("classify", "201", "fp", "--comment", "test account")
        self.assertEqual((code, out), (0, "CLASSIFIED   incident 201   classification FalsePositive   incidents 1\n"))
        self.assertEqual(self._queue_ids(), ["202", "200"])
        self._run("classify", "200", "tp")
        self._run("classify", "201", "tp")
        self.assertEqual(self._queue_ids(), ["202"])
        code, out, _ = self._run("details", "200", "--json")
        self.assertEqual(json.loads(out)["IncidentGrade"], "TruePositive")

    def test_a_classification_from_an_earlier_run_scores_a_later_run(self):
        self._run("queue", str(self.csv))
        later = (("1", "900", "z1", "2024-06-09T00:00:00Z", "42", "New rule", "", "",
                  "", "", ""),)
        later_csv = write_csv(self.tmp / "later.csv", later)
        self.assertEqual(self._queue_ids(str(later_csv)), ["201", "900", "202", "200"])
        code, out, _ = self._run("details", "900", "--json")
        self.assertEqual(json.loads(out)["score"], 0.5)
        self._run("classify", "202", "tp")
        code, out, _ = self._run("details", "900", "--json")
        record = json.loads(out)
        self.assertEqual((record["rule_classified"], record["rule_true_positives"]), (1, 1))
        self.assertGreater(record["score"], 0.5)
        self.assertEqual(self._queue_ids(), ["201", "900", "200"])

    def test_queue_with_nothing_open(self):
        self._run("queue", str(write_csv(self.tmp / "classified.csv", ROWS[:5])))
        code, out, _ = self._run("queue")
        empty = "OPEN           0 incidents in 0 rows, 0 listed\n"
        self.assertEqual((code, out), (0, empty))
        run = store.list_runs(self.runs_dir)[-1]["run"]
        self.assertEqual(self._run("queue", "--run", run)[1], f"{empty}RUN            {run}\n")

    def test_details_text_and_json(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("details", "100")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"rule\s+7\n")
        self.assertRegex(out, r"techniques\s+T1078, T1078.004, T1114\n")
        self.assertRegex(out, r"classification\s+TruePositive\n")
        self.assertRegex(out, r"IpAddress\s+10\.0\.0\.1\s+\d+\s+\d+\s+\d+\s+\d+\n")
        self.assertNotIn("Sha256", out)
        self.assertRegex(out, r"rule\s+0 TP  0 BP  0 FP  of 0 classified before\n"
                              r"similar\s+0 TP  0 BP  0 FP  of 0 classified before\n")
        code, out, _ = self._run("details", "100", "--json")
        record = json.loads(out)
        self.assertEqual(record["IpAddress"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(record["Sha256"], [])

    def test_similar_incidents_in_details_and_json(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("details", "201")
        self.assertRegex(out, r"\nsimilar\s+1 TP  0 BP  0 FP  of 1 classified before\n")
        record = json.loads(self._run("details", "201", "--json")[1])
        keys = ("similar", "similar_true_positive", "similar_benign_positive",
                "similar_false_positive")
        self.assertEqual([record[key] for key in keys], [1, 1, 0, 0])
        self.assertRegex(out, r"\n\nSIMILAR\nINCIDENT\s+CLASSIFICATION\s+TIME\s+RULE\s+TITLE\n"
                              r"100\s+TruePositive\s+2024-06-01T08:00:00Z\s+7\s+"
                              r"Suspicious sign in\n$")
        self.assertEqual(record["similar_incidents"], [{
            "IncidentId": "100", "IncidentGrade": "TruePositive",
            "Timestamp": "2024-06-01T08:00:00Z", "DetectorId": "7",
            "AlertTitle": "Suspicious sign in",
            "shared": ["AccountName alice", "IpAddress 10.0.0.1"]}])
        self.assertNotIn("\nSIMILAR\n", self._run("details", "202")[1])
        rows = json.loads(self._run("queue", "--json")[1])["queue"]
        self.assertEqual([[row[key] for key in keys] for row in rows],
                         [[1, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]])
        self.assertTrue(all(type(row[key]) is int for row in rows for key in keys))

    def test_details_limited_to_a_run(self):
        self._run("queue", str(self.csv))
        code, out, _ = self._run("runs", "--json")
        first = json.loads(out)[0]["run"]
        later = (("1", "900", "z1", "2024-06-09T00:00:00Z", "42", "", "", "", "", "", ""),)
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(self._run("details", "900")[0], 0)
        code, _, err = self._run("details", "900", "--run", first)
        self.assertEqual(code, 1)
        self.assertIn("no incident '900'", err)

    def test_runs_lists_every_run(self):
        code, out, _ = self._run("runs")
        self.assertEqual(out, "RUNS     saved 0\n")
        self._run("queue", str(self.csv))
        self._run("queue", str(self.csv))
        code, out, _ = self._run("runs")
        lines = out.splitlines()
        self.assertEqual(lines[0].split(), ["RUN", "CREATED", "INCIDENTS_IN_FILE", "FILE"])
        self.assertEqual([line.split()[2:] for line in lines[1:]],
                         [["7", "incidents.csv"]])
        code, out, _ = self._run("runs", "--json")
        self.assertEqual([run["incidents_in_file"] for run in json.loads(out)], [7])

    def test_errors_exit_1_with_one_line(self):
        cases = (
            ("queue",),
            ("queue", str(self.tmp / "absent.csv")),
            ("queue", "--run", "missing"),
            ("classify", "200", "tp"),
            ("details", "200"),
        )
        for argv in cases:
            with self.subTest(argv):
                code, out, err = self._run(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertTrue(err.startswith("meerkat: error: "))
                self.assertEqual(err.count("\n"), 1)
        self._run("queue", str(self.csv))
        for argv in (("classify", "nope", "tp"), ("details", "nope")):
            with self.subTest(argv):
                self.assertEqual(self._run(*argv)[0], 1)

    def test_a_refused_file_leaves_no_run(self):
        bad = write_csv(self.tmp / "bad.csv", (("1", "5"),), ("OrgId", "IncidentId"))
        self.assertEqual(self._run("queue", str(bad))[0], 1)
        self.assertEqual(self._run("runs", "--json")[1], "[]\n")

    def test_a_runs_directory_that_cannot_be_written(self):
        self.runs_dir = self.csv
        for argv in (("queue", str(self.csv)), ("classify", "200", "tp")):
            with self.subTest(argv):
                code, _, err = self._run(*argv)
                self.assertEqual(code, 1)
                self.assertTrue(err.startswith("meerkat: error: "))

    def test_usage_errors_exit_2(self):
        self._run("queue", str(self.csv))
        cases = (
            (),
            ("triage",),
            ("classify", "200", "malicious"),
            ("classify", "200"),
            ("classify",),
            ("classify", "200", "tp", "--file", "classifications.csv"),
            ("classify", "--file", "classifications.csv", "--comment", "text"),
            ("queue", "--limit", "0"),
            ("queue", "--limit", "many"),
            ("queue", "--limit", "5", "--all"),
            ("queue", str(self.csv), "--run", "x"),
            ("serve", "--port", "99999"),
            ("serve", "--port", "-1"),
            ("serve", "--port", "http"),
        )
        for argv in cases:
            with self.subTest(argv):
                self.assertEqual(self._run(*argv)[0], 2)

    def test_terminal_escapes_and_markup_in_incident_text_are_not_obeyed(self):
        row = dict(zip(HEADER, ROWS[5], strict=True))
        row.update(IncidentId="666", AlertTitle="\x1b[2J[red]:skull:‮evil\r\nrow")
        hostile = write_csv(self.tmp / "hostile.csv", (tuple(row.values()),))
        for argv in (("queue", str(hostile)), ("details", "666")):
            with self.subTest(argv):
                code, out, _ = self._run(*argv)
                self.assertEqual(code, 0)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("‮", out)
                self.assertNotIn("\r", out)

    def test_budget_strips_terminal_escapes_from_the_incident_ids_it_lists(self):
        rows = [tuple(f"{value}\x1b[2J" if column == 1 and value.startswith("l") else value
                      for column, value in enumerate(row)) for row in budget_rows()]
        self.assertIn("\x1b", self._budget(rows=rows))
        code, out, _ = self._run("budget")
        self.assertEqual(code, 0)
        self.assertIn("  to classify", out)
        self.assertNotIn("\x1b", out)

    def _queue_json(self, *argv: str) -> dict:
        return json.loads(self._run("queue", "--json", *argv)[1])

    def _classification_rows(self) -> list[dict]:
        with (self.runs_dir / "classifications.csv").open(newline="", encoding="utf-8") as handle:
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
        self.assertEqual(lines[0].split()[:4], ["#", "INCIDENT", "SCORE", "GROUP"])
        self.assertEqual(len(lines), 14)
        self.assertEqual(lines[-1], "OPEN           11 incidents in 11 rows, 11 listed")
        self.assertEqual(self._run("budget")[1], "BUDGET   not set\n")
        report = self._queue_json()
        self.assertEqual({key: report[key] for key in
                          ("open", "budget", "sample_share", "to_read", "below_budget",
                           "sample", "tp_below_budget")},
                         {"open": 11, "budget": None, "sample_share": 0.1, "to_read": 11,
                          "below_budget": 0, "tp_below_budget": None,
                          "sample": {"drawn": 0, "classified": 0, "true_positive": 0,
                                     "not_sampled": 0}})
        self.assertEqual({row["placement"] for row in report["queue"]}, {"to read"})
        self.assertFalse(list(self.runs_dir.glob("*/sample.json")))

    def test_a_budget_lists_the_top_and_one_sampled_incident(self):
        sampled = self._budget()
        self.assertRegex(sampled, r"^l\d$")
        lines = self._run("queue")[1].splitlines()
        self.assertEqual([line.split()[1] for line in lines[1:5]], ["h2", "h1", "h0", sampled])
        self.assertEqual(lines[4].split()[5], "sample")
        self.assertEqual(lines[5:], [
            "", "OPEN           11 incidents in 11 rows, 4 listed",
            "BELOW BUDGET   7 rows, 0 similar TP, 0 unclassified rule"])
        self.assertNotIn("queue", json.loads(self._run("budget", "--json")[1]))
        self.assertEqual(self._run("budget")[1].splitlines(), [
            "BUDGET                4 rows",
            "BELOW BUDGET          7 rows, 7 incidents",
            "  similar TP          0",
            "  unclassified rule   0",
            "  oldest below        06-10 01:00",
            "SAMPLE                1 drawn, 0 classified",
            f"  to classify         {sampled}",
            "TP BELOW BUDGET       not estimated, 0 classified samples"])
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["below_budget"], report["sample"]["drawn"]),
                         (4, 7, 1))
        self.assertEqual([row["placement"] for row in report["queue"]],
                         ["to read"] * 3 + ["sample"] + ["below budget"] * 7)
        self.assertEqual([row["position"] for row in report["queue"]], list(range(1, 12)))

    def test_all_lists_the_incidents_below_the_budget_under_a_label(self):
        self._budget()
        lines = self._run("queue", "--all")[1].splitlines()
        self.assertTrue(lines[5].startswith("-- below budget 7 -"))
        self.assertEqual(len(lines), 16)
        self.assertEqual([line.split()[0] for line in lines[6:13]],
                         [str(number) for number in range(5, 12)])
        self.assertNotIn("-- below", self._run("queue")[1])

    def test_limit_cuts_the_list_and_json_lists_every_open_incident(self):
        self._budget()
        lines = self._run("queue", "--limit", "2")[1].splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[4], "OPEN           11 incidents in 11 rows, 2 of 4 listed")
        self.assertEqual(len(self._queue_json()["queue"]), 11)
        self.assertEqual(len(self._queue_json("--limit", "5")["queue"]), 5)

    def test_the_sample_stays_when_the_queue_or_the_file_is_read_again(self):
        sampled = self._budget()
        for _ in range(2):
            rows = self._queue_json()["queue"]
            self.assertEqual([row["IncidentId"] for row in rows if row["placement"] == "sample"],
                             [sampled])
        self._run("queue", str(self.tmp / "many.csv"))
        self.assertEqual(len(list(self.runs_dir.glob("*/sample.json"))), 1)
        self.assertEqual(self._queue_json()["sample"]["drawn"], 1)

    def test_a_later_file_draws_from_its_own_incidents(self):
        self._run("classify", self._budget(), "fp")
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(3)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        samples = store.read_samples(self.runs_dir)
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[1]["pool"], ["n2", "n1", "n0"])
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["sample"]["drawn"]), (4, 2))
        self.assertEqual([row["IncidentId"] for row in report["queue"]
                          if row["placement"] == "sample"], samples[1]["drawn"])

    def test_no_new_sample_while_an_earlier_one_waits_for_its_classification(self):
        sampled = self._budget()
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(3)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(len(store.read_samples(self.runs_dir)), 1)
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["sample"]["drawn"]), (4, 1))
        self.assertEqual([row["IncidentId"] for row in report["queue"]
                          if row["placement"] == "sample"], [sampled])

    def test_incidents_that_met_no_draw_are_counted_until_the_next_draw(self):
        sampled = self._budget()
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(3)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(self._queue_json()["sample"]["not_sampled"], 3)
        self.assertEqual(self._run("budget")[1].splitlines()[-2], "  not sampled         3")
        self._run("classify", sampled, "fp")
        self._run("queue", str(self.tmp / "later.csv"))
        self.assertEqual(self._queue_json()["sample"]["not_sampled"], 0)

    def test_a_classified_sample_gives_the_estimate(self):
        sampled = self._budget()
        self._run("classify", sampled, "fp")
        lines = self._run("budget")[1].splitlines()
        self.assertIn("BELOW BUDGET          6 rows, 6 incidents", lines)
        self.assertEqual(lines[-2:], ["SAMPLE                1 drawn, 1 classified, 0 TP",
                                      "TP BELOW BUDGET       0 to 6 of 6, 95% interval, "
                                      "from 1 classified"])
        report = self._queue_json()
        self.assertEqual(report["sample"], {"drawn": 1, "classified": 1, "true_positive": 0,
                                            "not_sampled": 0})
        self.assertEqual(report["tp_below_budget"], {"estimate": 0, "low": 0, "high": 6, "of": 6})

    def test_a_true_positive_in_the_sample_raises_the_estimate(self):
        sampled = self._budget()
        self._run("classify", sampled, "tp")
        self.assertEqual(self._queue_json()["tp_below_budget"],
                         {"estimate": 6, "low": 0, "high": 6, "of": 6})

    def test_a_budget_above_the_open_incidents_reads_them_all(self):
        self.assertEqual(self._budget("25"), "")
        report = self._queue_json()
        self.assertEqual((report["to_read"], report["below_budget"]), (11, 0))
        self.assertEqual(self._run("queue")[1].splitlines()[-2:], [
            "OPEN           11 incidents in 11 rows, 11 listed",
            "BELOW BUDGET   0 rows, 0 similar TP, 0 unclassified rule"])
        self.assertEqual(self._run("budget")[1].splitlines(), [
            "BUDGET            25 rows",
            "BELOW BUDGET      0 rows, 0 incidents",
            "SAMPLE            0 drawn, 0 classified",
            "TP BELOW BUDGET   not estimated, 0 classified samples"])

    def _marked_rows(self) -> list:
        rows = [list(row) for row in budget_rows()]
        rows += [list(plain_row("similar", "9", time="2024-06-10T02:00:00Z")),
                 list(plain_row("fresh", "42", time="2024-06-10T02:01:00Z"))]
        for row in rows:
            if row[1] in ("p0", "similar"):
                row[9] = "ann"
        return rows

    def test_a_link_and_an_unclassified_rule_are_marked_below_the_budget(self):
        self._run("config", "sample_share", "0")
        self.assertEqual(self._budget("3", self._marked_rows()), "")
        lines = self._run("queue", "--all")[1].splitlines()
        marks = {line.split()[1]: line.split()[5:7] for line in lines[5:15]}
        self.assertEqual(marks["fresh"], ["unclassified", "rule"])
        self.assertEqual(marks["similar"][0], "similar")
        self.assertNotIn(marks["l0"][0], ("similar", "unclassified", "sample"))
        self.assertEqual(lines[-2:], ["OPEN           13 incidents in 13 rows, 13 listed",
                                      "BELOW BUDGET   10 rows, 1 similar TP, 1 unclassified rule"])
        self.assertEqual(self._run("queue")[1].splitlines()[-1], lines[-1])
        self.assertEqual(self._run("budget")[1].splitlines(), [
            "BUDGET                3 rows",
            "BELOW BUDGET          10 rows, 10 incidents",
            "  similar TP          1",
            "  unclassified rule   1",
            "  oldest below        06-10 01:00",
            "SAMPLE                0 drawn, 0 classified",
            "  not sampled         10",
            "TP BELOW BUDGET       not estimated, 0 classified samples"])
        self.assertNotIn("similar", self._run("queue", "--limit", "3")[1].splitlines()[1])

    def test_classify_records_the_placement_and_a_reclassification_keeps_it(self):
        sampled = self._budget()
        below = next(row["IncidentId"] for row in self._queue_json()["queue"]
                     if row["placement"] == "below budget")
        score = json.loads(self._run("details", sampled, "--json")[1])["score"]
        for incident in (sampled, "h2", below, "p0"):
            self._run("classify", incident, "bp")
        self._run("classify", sampled, "tp")
        rows = self._classification_rows()
        self.assertEqual([row["placement"] for row in rows],
                         ["sample", "to read", "below budget", "", "sample"])
        mine = [row for row in rows if row["IncidentId"] == sampled]
        self.assertEqual([row["classification"] for row in mine], ["BenignPositive", "TruePositive"])
        self.assertEqual({round(float(row["score"]), 4) for row in mine}, {score})

    def test_classify_file_counts_the_true_positives_by_placement(self):
        sampled = self._budget()
        below = next(row["IncidentId"] for row in self._queue_json()["queue"]
                     if row["placement"] == "below budget")
        classifications = self.tmp / "classifications.csv"
        classifications.write_text("IncidentId,IncidentGrade\nh0,TruePositive\nh1,FalsePositive\n"
                          f"{sampled},TruePositive\n{below},TruePositive\n")
        self.assertEqual(self._run("classify", "--file", str(classifications))[1],
                         "CLASSIFIED   incidents 4   tp 3   tp_to_read 1   tp_sample 1   tp_below 1\n")

    def test_details_shows_the_placement(self):
        sampled = self._budget()
        self.assertRegex(self._run("details", sampled)[1],
                         r"\nplacement\s+sample\n")
        self.assertEqual(json.loads(self._run("details", "h2", "--json")[1])["placement"], "to read")
        self._run("classify", sampled, "fp")
        self.assertRegex(self._run("details", sampled)[1], r"placement\s+sample\n")
        self.assertEqual(json.loads(self._run("details", "p0", "--json")[1])["placement"], "")

    def test_a_run_view_has_no_sample_line(self):
        self._budget()
        run = store.list_runs(self.runs_dir)[-1]["run"]
        lines = self._run("queue", "--run", run)[1].splitlines()
        self.assertEqual(lines[-3:], ["OPEN           11 incidents in 11 rows, 4 listed",
                                      "BELOW BUDGET   7 rows, 0 similar TP, 0 unclassified rule",
                                      f"RUN            {run}"])

    def test_no_open_incidents_prints_plain_message(self):
        self._budget()
        for row in self._queue_json()["queue"]:
            self._run("classify", row["IncidentId"], "fp")
        self.assertEqual(self._run("queue")[1].splitlines(), [
            "OPEN           0 incidents in 0 rows, 0 listed",
            "BELOW BUDGET   0 rows, 0 similar TP, 0 unclassified rule"])
        self.assertEqual(self._run("budget")[1].splitlines(), [
            "BUDGET            4 rows",
            "BELOW BUDGET      0 rows, 0 incidents",
            "SAMPLE            1 drawn, 1 classified, 0 TP",
            "TP BELOW BUDGET   not estimated, 0 incidents below budget"])

    def test_incidents_below_the_budget_that_met_no_draw_are_not_estimated(self):
        self._budget()
        for row in self._queue_json()["queue"]:
            self._run("classify", row["IncidentId"], "fp")
        self._run("config", "sample_share", "0")
        later = [plain_row(f"n{i}", "9", time=f"2024-06-11T00:0{i}:00Z") for i in range(6)]
        self._run("queue", str(write_csv(self.tmp / "later.csv", later)))
        self.assertEqual(self._run("budget")[1].splitlines()[-3:], [
            "SAMPLE                1 drawn, 1 classified, 0 TP",
            "  not sampled         2",
            "TP BELOW BUDGET       not estimated, 2 not sampled"])

    def test_serve_with_a_file_saves_it_as_a_run_before_the_page_opens(self):
        with mock.patch("meerkat.web.serve") as served:
            code, out, err = self._run("serve", str(self.csv), "--no-browser")
        self.assertEqual((code, out, err), (0, "", ""))
        self.assertEqual([meta["file"] for meta in store.list_runs(self.runs_dir)],
                         [self.csv.name])
        served.assert_called_once_with(self.runs_dir, 0, 200, False)
        code, out, err = self._run("serve", "--mapping", "sentinel")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--mapping needs FILE", err)

    def test_query_prints_the_saved_query_and_its_columns_are_the_ones_read(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["query", "sentinel"])
        text = out.getvalue()
        self.assertEqual(err.getvalue(), "")
        self.assertIn("SecurityIncident", text)
        project = text.split("| project\n")[-1]
        named = [line.strip().split(" = ")[0].rstrip(",") for line in project.splitlines()]
        self.assertLessEqual(set(named), set(COLUMNS))
        self.assertLessEqual({"IncidentId", "Timestamp", "DetectorId", "IncidentGrade"}, set(named))
        self.assertEqual(self._run("query", "elastic")[0], 2)

    def test_config_prints_the_defaults_on_an_empty_runs_folder(self):
        code, out, err = self._run("config")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, f"budget=none\nsample_share={budget.DEFAULT_SAMPLE_SHARE}\n")
        self.assertFalse(self.runs_dir.exists())

    def test_config_sets_shows_and_clears_each_setting(self):
        self.assertEqual(self._run("config", "budget", "25")[1], "budget=25\n")
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
        for argv in (("queue",), ("classify", "200", "tp"), ("details", "200")):
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
        self.assertIn("\nOPEN           1 incidents in 1 rows, 1 listed\n", out)
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

    def _table(self, columns: int | None, rows: list[tuple[str, ...]],
               styles: list[str] | None = None) -> list[str]:
        class Terminal(io.StringIO):
            def isatty(self) -> bool:
                return columns is not None

        out = Terminal()
        size = os.terminal_size((columns or 80, 24))
        with (contextlib.redirect_stdout(out),
              mock.patch.object(cli.shutil, "get_terminal_size", return_value=size)):
            cli._print_table(("id", "score", "title"), rows, {"score"},
                             styles or [""] * len(rows))
        return out.getvalue().splitlines()

    def test_a_terminal_shortens_only_the_last_column(self):
        rows = [("1", "0.50", "x" * 100), ("22", "0.75", "short")]
        lines = self._table(30, rows)
        self.assertEqual(lines[0], "ID  SCORE  TITLE")
        self.assertEqual(lines[1], "1    0.50  " + "x" * 19)
        self.assertEqual(lines[2], "22   0.75  short")
        self.assertTrue(all(len(line) <= 30 for line in lines))

    def test_a_terminal_narrower_than_the_fixed_columns_cuts_nothing_else(self):
        rows = [("1", "0.50", "x" * 100)]
        lines = self._table(8, rows)
        self.assertEqual(lines[0], "ID  SCORE  TITLE")
        self.assertEqual(lines[1], "1    0.50  " + "x" * 100)

    def test_a_pipe_gets_every_character(self):
        rows = [("1", "0.50", "x" * 300)]
        self.assertEqual(self._table(None, rows)[1], "1    0.50  " + "x" * 300)

    def test_colour_reaches_a_terminal_only_and_no_color_turns_it_off(self):
        rows = [("1", "0.50", "kept"), ("2", "0.10", "below")]
        styles = ["", "dim"]
        with mock.patch.dict(os.environ):
            os.environ.pop("NO_COLOR", None)
            lines = self._table(80, rows, styles)
            self.assertEqual(lines[1], "1    0.50  kept")
            self.assertEqual(lines[2], "\x1b[2m2    0.10  below\x1b[0m")
            self.assertNotIn("\x1b", "".join(self._table(None, rows, styles)))
            os.environ["NO_COLOR"] = "1"
            self.assertNotIn("\x1b", "".join(self._table(80, rows, styles)))

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
