# Runs and grades on disk: what is written, what is read back, what is refused.

import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pandas as pd

from core import store
from core.incidents import read_incidents
from tests.fixtures import DEFENDER, ROWS, write_csv


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.incidents = read_incidents(write_csv(self.tmp / "incidents.csv"), DEFENDER)

    def _grade_of(self, incident_id: str) -> str:
        _, incidents = store.load_run(self.runs_dir, store.list_runs(self.runs_dir)[-1]["run"])
        return incidents.set_index("IncidentId").loc[incident_id, "IncidentGrade"]

    def test_run_round_trip(self):
        meta = store.save_run(self.runs_dir, self.incidents, "incidents.csv", "defender")
        loaded_meta, loaded = store.load_run(self.runs_dir, meta["run"])
        self.assertEqual(loaded_meta, {k: v for k, v in meta.items() if k != "mapping"})
        self.assertEqual(meta["incidents"], 7)
        self.assertTrue(loaded.equals(self.incidents))

    def test_two_runs_in_one_second_get_distinct_ids(self):
        first = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        second = store.save_run(self.runs_dir, self.incidents, "b.csv", "defender")
        self.assertNotEqual(first["run"], second["run"])
        self.assertEqual([m["source"] for m in store.list_runs(self.runs_dir)],
                         ["a.csv", "b.csv"])
        self.assertEqual(store.load_run(self.runs_dir, second["run"])[0]["source"], "b.csv")
        self.assertEqual(store.load_run(self.runs_dir, first["run"])[0]["source"], "a.csv")

    def test_runs_of_the_same_second_stay_in_saving_order(self):
        clock = self.enterContext(mock.patch.object(store, "datetime"))
        clock.now.return_value = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
        for number in range(11):
            store.save_run(self.runs_dir, self.incidents, f"{number}.csv", "defender")
        self.assertEqual([m["source"] for m in store.list_runs(self.runs_dir)],
                         [f"{number}.csv" for number in range(11)])

    def test_a_grade_that_is_not_a_grade_is_refused(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        (self.runs_dir / store.GRADES_FILE).write_text(
            "time,IncidentId,grade,note,score,pile\nt,200,Malicious,,0.5,queue\n")
        with self.assertRaisesRegex(store.StoreError, "grade 'Malicious' is not one of"):
            store.read_reviews(self.runs_dir)

    def test_no_runs(self):
        self.assertEqual(store.list_runs(self.runs_dir), [])
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_run(self.runs_dir, "missing")
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_history(self.runs_dir)

    def test_unknown_run_id_cannot_leave_the_runs_directory(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        for run_id in ("missing", "..", "../runs", ""):
            with self.subTest(run_id), self.assertRaisesRegex(store.StoreError, "no run"):
                store.load_run(self.runs_dir, run_id)

    def test_latest_review_wins_over_the_file_and_over_earlier_reviews(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        self.assertEqual(self._grade_of("200"), "")
        store.append_grade(self.runs_dir, "200", "FalsePositive", "", 0.5, "queue")
        store.append_grade(self.runs_dir, "200", "TruePositive", "second look, real",
                           0.5, "queue")
        store.append_grade(self.runs_dir, "102", "TruePositive", "", 0.5, "queue")
        self.assertEqual(self._grade_of("200"), "TruePositive")
        self.assertEqual(self._grade_of("102"), "TruePositive")
        self.assertEqual(self._grade_of("103"), "FalsePositive")

    def test_eight_reviews_at_the_same_instant_are_all_kept(self):
        script = (
            "import sys, time\n"
            "from pathlib import Path\n"
            "from core import store\n"
            "time.sleep(max(0.0, float(sys.argv[3]) - time.time()))\n"
            "store.append_grade(Path(sys.argv[1]), sys.argv[2], 'TruePositive', '', 0.5, 'queue')\n"
        )
        self.runs_dir.mkdir()
        start = str(time.time() + 1)
        root = Path(__file__).resolve().parents[1]
        workers = [
            subprocess.Popen([sys.executable, "-c", script, str(self.runs_dir), str(n), start],
                             cwd=root)
            for n in range(8)
        ]
        self.assertEqual([worker.wait() for worker in workers], [0] * 8)
        reviews = store.read_reviews(self.runs_dir)
        self.assertEqual(sorted(reviews["IncidentId"]), [str(n) for n in range(8)])

    def test_notes_with_commas_quotes_and_newlines_survive(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        store.append_grade(self.runs_dir, "200", "TruePositive", 'a, "b"\nc', 0.5, "queue")
        store.append_grade(self.runs_dir, "201", "BenignPositive", "", 0.5, "queue")
        self.assertEqual(self._grade_of("200"), "TruePositive")
        self.assertEqual(self._grade_of("201"), "BenignPositive")

    def test_a_review_stores_the_score_and_pile_it_had(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        self.assertTrue(store.read_reviews(self.runs_dir).empty)
        store.append_grade(self.runs_dir, "200", "TruePositive", "", 0.123456789, "audit")
        header = (self.runs_dir / store.GRADES_FILE).read_text().splitlines()[0]
        self.assertEqual(header, "time,IncidentId,grade,note,score,pile")
        reviews = store.read_reviews(self.runs_dir)
        self.assertEqual(reviews["score"].tolist(), [0.123456789])
        self.assertEqual(reviews["pile"].tolist(), ["audit"])

    def test_grades_with_missing_columns_a_bad_score_or_a_bad_pile_are_refused(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        head = "time,IncidentId,grade,note"
        cases = (
            (f"{head}\nt,200,TruePositive,\n", "expected columns"),
            (f"{head},score,pile\nt,200,TruePositive,,high,queue\n", "not a number"),
            (f"{head},score,pile\nt,200,TruePositive,,,queue\n", "not a number"),
            (f"{head},score,pile\nt,200,TruePositive,,0.5,later\n", "not one of"),
            (f"{head},score,pile\nt,200,TruePositive,,0.5,\n", "not one of"),
        )
        for text, message in cases:
            with self.subTest(text):
                (self.runs_dir / store.GRADES_FILE).write_text(text)
                run_id = store.list_runs(self.runs_dir)[0]["run"]
                reads = (store.read_reviews, lambda d: store.load_run(d, run_id),
                         store.load_history)
                for read in reads:
                    with self.assertRaisesRegex(store.StoreError, message) as raised:
                        read(self.runs_dir)
                    self.assertNotIn("\n", str(raised.exception))

    def test_history_has_one_row_per_incident_and_the_earlier_run_wins_a_tie(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        later = (
            ("1", "200", "a6", "2024-06-05T12:00:00Z", "7", "Retitled", "", "", "", "", ""),
            ("1", "300", "b1", "2024-06-06T00:00:00Z", "5", "New rule", "", "", "", "", ""),
        )
        second = read_incidents(write_csv(self.tmp / "later.csv", later), DEFENDER)
        store.save_run(self.runs_dir, second, "later.csv", "defender")
        history = store.load_history(self.runs_dir).set_index("IncidentId")
        self.assertEqual(len(history), 8)
        self.assertEqual(history.loc["200", "AlertTitle"], "Mail forwarding rule")
        self.assertIn("300", history.index)

    def _merged(self, *parts: tuple) -> pd.DataFrame:
        for number, rows in enumerate(parts):
            path = write_csv(self.tmp / f"part{number}.csv", rows)
            store.save_run(self.runs_dir, read_incidents(path, DEFENDER), path.name, "defender")
        return store.load_history(self.runs_dir).set_index("IncidentId")

    def test_an_incident_in_two_runs_takes_rule_and_title_from_the_earlier_time(self):
        later = ("1", "500", "b", "2024-06-02T00:00:00Z", "8", "Second", "Late", "", "", "", "")
        earlier = ("1", "500", "a", "2024-06-01T00:00:00Z", "7", "First", "Early", "", "", "", "")
        row = self._merged((later,), (earlier,)).loc["500"]
        self.assertEqual((row["Timestamp"], row["DetectorId"], row["AlertTitle"],
                          row["Category"]), ("2024-06-01T00:00:00Z", "7", "First", "Early"))

    def test_on_a_tie_the_earlier_run_gives_the_rule(self):
        first = ("1", "500", "a", "2024-06-01T00:00:00Z", "7", "First", "", "", "", "", "")
        second = ("1", "500", "b", "2024-06-01T00:00:00Z", "8", "Second", "", "", "", "", "")
        row = self._merged((first,), (second,)).loc["500"]
        self.assertEqual((row["DetectorId"], row["AlertTitle"]), ("7", "First"))

    def test_links_and_techniques_are_the_sorted_union_of_the_runs(self):
        first = ("1", "500", "a", "2024-06-01T00:00:00Z", "7", "", "", "T1114;T1078", "",
                 "bob", "10.0.0.2")
        second = ("1", "500", "b", "2024-06-02T00:00:00Z", "7", "", "", "T1078;T1566", "",
                  "alice", "10.0.0.2")
        row = self._merged((first,), (second,)).loc["500"]
        self.assertEqual(row["MitreTechniques"], "T1078|T1114|T1566")
        self.assertEqual(row["AccountName"], "alice|bob")
        self.assertEqual(row["IpAddress"], "10.0.0.2")
        self.assertEqual(row["Sha256"], "")

    def test_a_later_grade_is_kept_and_an_earlier_one_survives_a_blank(self):
        graded = ("1", "500", "a", "2024-06-01T00:00:00Z", "7", "", "", "", "FalsePositive",
                  "", "")
        regraded = ("1", "500", "b", "2024-06-02T00:00:00Z", "7", "", "", "", "TruePositive",
                    "", "")
        blank = ("1", "500", "c", "2024-06-03T00:00:00Z", "7", "", "", "", "", "", "")
        self.assertEqual(self._merged((graded,), (regraded,)).loc["500", "IncidentGrade"],
                         "TruePositive")
        self.assertEqual(self._merged((regraded,), (blank,)).loc["500", "IncidentGrade"],
                         "TruePositive")

    def test_an_incident_in_one_run_comes_out_unchanged(self):
        history = self._merged(ROWS)
        expected = self.incidents.set_index("IncidentId")
        self.assertTrue(history.sort_index().equals(expected.sort_index()))

    def test_damaged_files_are_reported(self):
        meta = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        (self.runs_dir / store.GRADES_FILE).write_text("who,what\nx,y\n")
        with self.assertRaisesRegex(store.StoreError, "expected columns"):
            store.load_run(self.runs_dir, meta["run"])
        (self.runs_dir / store.GRADES_FILE).unlink()
        (self.runs_dir / meta["run"] / "incidents.csv").unlink()
        with self.assertRaisesRegex(store.StoreError, "unreadable"):
            store.load_run(self.runs_dir, meta["run"])
        (self.runs_dir / meta["run"] / "meta.json").write_text('{"run": "../x"}')
        with self.assertRaisesRegex(store.StoreError, "unreadable run"):
            store.list_runs(self.runs_dir)

    def test_a_run_with_wrong_columns_or_a_bad_time_is_refused_naming_the_file(self):
        meta = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        path = self.runs_dir / meta["run"] / "incidents.csv"
        good = path.read_text()
        cases = (
            ("a,b\n1,2\n", "expected columns"),
            (good.replace("IncidentId,", "Incident,", 1), "expected columns"),
            (good.replace("2024-06-05T12:00:00Z", "1-01-01T00:00:00Z"), "is not ISO 8601"),
        )
        for text, message in cases:
            with self.subTest(message):
                path.write_text(text)
                reads = (lambda d: store.load_run(d, meta["run"]), store.load_history)
                for read in reads:
                    with self.assertRaisesRegex(store.StoreError, message) as raised:
                        read(self.runs_dir)
                    self.assertIn(str(path), str(raised.exception))
                    self.assertNotIn("\n", str(raised.exception))

    def test_history_with_an_incoming_file_needs_no_saved_run(self):
        history = store.load_history(self.runs_dir, self.incidents)
        self.assertEqual(len(history), 7)
        self.assertFalse(self.runs_dir.exists())

    def test_settings_round_trip_and_absence(self):
        self.assertEqual(store.read_settings(self.runs_dir), {})
        both = {"miss_rate": 0.01, "keep_linked": False}
        store.write_settings(self.runs_dir, both)
        self.assertEqual(store.read_settings(self.runs_dir), both)
        self.assertEqual((self.runs_dir / store.SETTINGS_FILE).read_text(),
                         '{\n  "miss_rate": 0.01,\n  "keep_linked": false\n}\n')

    def test_each_setting_can_be_saved_alone(self):
        for alone in ({"miss_rate": 0.01}, {"keep_linked": True}, {}):
            with self.subTest(alone):
                store.write_settings(self.runs_dir, alone)
                self.assertEqual(store.read_settings(self.runs_dir), alone)

    def test_a_bad_settings_file_is_refused(self):
        self.runs_dir.mkdir()
        cases = ("not json", "[0.01]", '{"miss_rate": "0.05"}', '{"miss_rate": true}',
                 '{"miss_rate": 0}', '{"miss_rate": 1}', '{"miss_rate": -0.1}',
                 '{"miss_rate": NaN}', '{"miss_rate": Infinity}', '{"other": 1}',
                 '{"miss_rate": 0.05, "other": 1}', '{"keep_linked": 1}',
                 '{"keep_linked": "true"}', '{"keep_linked": null}')
        for text in cases:
            with self.subTest(text):
                (self.runs_dir / store.SETTINGS_FILE).write_text(text)
                with self.assertRaisesRegex(store.StoreError, store.SETTINGS_FILE):
                    store.read_settings(self.runs_dir)

    def test_the_settings_file_is_not_a_run(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        store.write_settings(self.runs_dir, {"miss_rate": 0.01})
        self.assertEqual(len(store.list_runs(self.runs_dir)), 1)
        self.assertEqual(len(store.load_history(self.runs_dir)), 7)


if __name__ == "__main__":
    unittest.main()
