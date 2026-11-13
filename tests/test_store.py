# Runs and grades on disk: what is written, what is read back, what is refused.

import tempfile
import unittest
from pathlib import Path

from core import store
from core.incidents import read_incidents
from tests.fixtures import write_csv


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.incidents = read_incidents(write_csv(self.tmp / "incidents.csv"))

    def _grade_of(self, incident_id: str) -> str:
        _, incidents = store.load_run(self.runs_dir)
        return incidents.set_index("IncidentId").loc[incident_id, "IncidentGrade"]

    def test_run_round_trip(self):
        meta = store.save_run(self.runs_dir, self.incidents, "incidents.csv")
        loaded_meta, loaded = store.load_run(self.runs_dir)
        self.assertEqual(loaded_meta, meta)
        self.assertEqual(meta["incidents"], 7)
        self.assertTrue(loaded.equals(self.incidents))

    def test_two_runs_in_one_second_get_distinct_ids(self):
        first = store.save_run(self.runs_dir, self.incidents, "a.csv")
        second = store.save_run(self.runs_dir, self.incidents, "b.csv")
        self.assertNotEqual(first["run"], second["run"])
        self.assertEqual([m["source"] for m in store.list_runs(self.runs_dir)],
                         ["a.csv", "b.csv"])
        self.assertEqual(store.load_run(self.runs_dir)[0]["source"], "b.csv")
        self.assertEqual(store.load_run(self.runs_dir, first["run"])[0]["source"], "a.csv")

    def test_no_runs(self):
        self.assertEqual(store.list_runs(self.runs_dir), [])
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_run(self.runs_dir)
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_history(self.runs_dir)

    def test_unknown_run_id_cannot_leave_the_runs_directory(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv")
        for run_id in ("missing", "..", "../runs", ""):
            with self.subTest(run_id), self.assertRaisesRegex(store.StoreError, "no run"):
                store.load_run(self.runs_dir, run_id)

    def test_latest_review_wins_over_the_file_and_over_earlier_reviews(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv")
        self.assertEqual(self._grade_of("200"), "")
        store.append_grade(self.runs_dir, "200", "FalsePositive", "")
        store.append_grade(self.runs_dir, "200", "TruePositive", "second look, real")
        store.append_grade(self.runs_dir, "102", "TruePositive", "")
        self.assertEqual(self._grade_of("200"), "TruePositive")
        self.assertEqual(self._grade_of("102"), "TruePositive")
        self.assertEqual(self._grade_of("103"), "FalsePositive")

    def test_notes_with_commas_quotes_and_newlines_survive(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv")
        store.append_grade(self.runs_dir, "200", "TruePositive", 'a, "b"\nc')
        store.append_grade(self.runs_dir, "201", "BenignPositive", "")
        self.assertEqual(self._grade_of("200"), "TruePositive")
        self.assertEqual(self._grade_of("201"), "BenignPositive")

    def test_history_joins_runs_and_keeps_the_latest_copy(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv")
        later = (
            ("1", "200", "a6", "2024-06-05T12:00:00Z", "7", "Retitled", "", "", "", "", ""),
            ("1", "300", "b1", "2024-06-06T00:00:00Z", "5", "New rule", "", "", "", "", ""),
        )
        second = read_incidents(write_csv(self.tmp / "later.csv", later))
        store.save_run(self.runs_dir, second, "later.csv")
        history = store.load_history(self.runs_dir).set_index("IncidentId")
        self.assertEqual(len(history), 8)
        self.assertEqual(history.loc["200", "AlertTitle"], "Retitled")
        self.assertIn("300", history.index)

    def test_damaged_files_are_reported(self):
        meta = store.save_run(self.runs_dir, self.incidents, "a.csv")
        (self.runs_dir / store.GRADES_FILE).write_text("who,what\nx,y\n")
        with self.assertRaisesRegex(store.StoreError, "expected columns"):
            store.load_run(self.runs_dir)
        (self.runs_dir / store.GRADES_FILE).unlink()
        (self.runs_dir / meta["run"] / "incidents.csv").unlink()
        with self.assertRaisesRegex(store.StoreError, "unreadable"):
            store.load_run(self.runs_dir)
        (self.runs_dir / meta["run"] / "meta.json").write_text('{"run": "../x"}')
        with self.assertRaisesRegex(store.StoreError, "unreadable run"):
            store.list_runs(self.runs_dir)


if __name__ == "__main__":
    unittest.main()
