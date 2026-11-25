# Runs and classifications on disk: what is written, what is read back, what is refused.

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pandas as pd

from core import store
from core.incidents import CLOSED
from tests.fixtures import ROWS, read_file, write_csv


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runs_dir = self.tmp / "runs"
        self.incidents = read_file(write_csv(self.tmp / "incidents.csv"))

    def _classification_of(self, incident_id: str) -> str:
        incidents = store.load_history(self.runs_dir)
        return incidents.set_index("IncidentId").loc[incident_id, "IncidentGrade"]

    def test_run_round_trip(self):
        meta = store.save_run(self.runs_dir, self.incidents, "incidents.csv", "defender")
        loaded_meta, loaded = store.load_run(self.runs_dir, meta["run"])
        self.assertEqual(loaded_meta, {k: v for k, v in meta.items() if k != "source"})
        self.assertEqual(meta["incidents_in_file"], 7)
        self.assertTrue(loaded.equals(self.incidents))

    def test_two_runs_in_one_second_get_distinct_ids(self):
        first = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        second = store.save_run(self.runs_dir, self.incidents.iloc[1:], "b.csv", "defender")
        self.assertNotEqual(first["run"], second["run"])
        self.assertEqual([m["file"] for m in store.list_runs(self.runs_dir)],
                         ["a.csv", "b.csv"])
        self.assertEqual(store.load_run(self.runs_dir, second["run"])[0]["file"], "b.csv")
        self.assertEqual(store.load_run(self.runs_dir, first["run"])[0]["file"], "a.csv")

    def test_the_same_incidents_are_saved_once(self):
        first = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        again = store.save_run(self.runs_dir, self.incidents, "b.csv", "defender")
        self.assertEqual(again["run"], first["run"])
        self.assertEqual(len(store.list_runs(self.runs_dir)), 1)

    def test_no_runs(self):
        self.assertEqual(store.list_runs(self.runs_dir), [])
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_run(self.runs_dir, "missing")
        with self.assertRaisesRegex(store.StoreError, "no runs"):
            store.load_history(self.runs_dir)

    def test_latest_classification_wins_over_the_file_and_over_earlier_classifications(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        self.assertEqual(self._classification_of("200"), "")
        store.append_classification(self.runs_dir, "200", "FalsePositive", "", 0.5, "to read")
        store.append_classification(self.runs_dir, "200", "TruePositive", "second look, real",
                           0.5, "to read")
        store.append_classification(self.runs_dir, "102", "TruePositive", "", 0.5, "to read")
        self.assertEqual(self._classification_of("200"), "TruePositive")
        self.assertEqual(self._classification_of("102"), "TruePositive")
        self.assertEqual(self._classification_of("103"), "FalsePositive")

    def test_comments_with_commas_quotes_and_newlines_survive(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        store.append_classification(self.runs_dir, "200", "TruePositive", 'a, "b"\nc', 0.5, "to read")
        store.append_classification(self.runs_dir, "201", "BenignPositive", "", 0.5, "to read")
        self.assertEqual(self._classification_of("200"), "TruePositive")
        self.assertEqual(self._classification_of("201"), "BenignPositive")

    def test_a_classification_stores_the_score_and_placement_it_had(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        self.assertTrue(store.read_classifications(self.runs_dir).empty)
        store.append_classification(self.runs_dir, "200", "TruePositive", "", 0.123456789, "sample")
        header = (self.runs_dir / store.CLASSIFICATIONS_FILE).read_text().splitlines()[0]
        self.assertEqual(header, "time,IncidentId,classification,comment,score,placement")
        classifications = store.read_classifications(self.runs_dir)
        self.assertEqual(classifications["score"].tolist(), [0.123456789])
        self.assertEqual(classifications["placement"].tolist(), ["sample"])

    def test_history_merges_repeats_to_one_row(self):
        store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")
        later = (
            ("1", "200", "a6", "2024-06-05T12:00:00Z", "7", "Retitled", "", "", "", "", ""),
            ("1", "300", "b1", "2024-06-06T00:00:00Z", "5", "New rule", "", "", "", "", ""),
        )
        second = read_file(write_csv(self.tmp / "later.csv", later))
        store.save_run(self.runs_dir, second, "later.csv", "defender")
        history = store.load_history(self.runs_dir).set_index("IncidentId")
        self.assertEqual(len(history), 8)
        self.assertEqual(history.loc["200", "AlertTitle"], "Mail forwarding rule")
        self.assertIn("300", history.index)

    def _merged(self, *parts: tuple) -> pd.DataFrame:
        for number, rows in enumerate(parts):
            path = write_csv(self.tmp / f"part{number}.csv", rows)
            store.save_run(self.runs_dir, read_file(path), path.name, "defender")
        return store.load_history(self.runs_dir).set_index("IncidentId")

    def test_incident_in_two_runs_takes_rule_from_earlier_time(self):
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

    def test_the_newest_file_gives_the_classification_and_a_blank_reopens(self):
        classified = ("1", "500", "a", "2024-06-01T00:00:00Z", "7", "", "", "", "FalsePositive",
                  "", "")
        reclassified = ("1", "500", "b", "2024-06-02T00:00:00Z", "7", "", "", "", "TruePositive",
                    "", "")
        blank = ("1", "500", "c", "2024-06-03T00:00:00Z", "7", "", "", "", "", "", "")
        self.assertEqual(self._merged((classified,), (reclassified,)).loc["500", "IncidentGrade"],
                         "TruePositive")
        self.assertEqual(self._merged((reclassified,), (blank,)).loc["500", "IncidentGrade"], "")

    def test_an_incident_closed_in_the_newest_file_leaves_the_history(self):
        store.save_run(self.runs_dir, self.incidents, "monday.csv", "defender")
        closed = self.incidents["IncidentId"].isin(["200", "103"])
        tuesday = self.incidents.assign(
            IncidentGrade=self.incidents["IncidentGrade"].mask(closed, CLOSED))
        store.save_run(self.runs_dir, tuesday, "tuesday.csv", "defender")
        self.assertEqual(sorted(store.load_history(self.runs_dir)["IncidentId"]),
                         ["100", "101", "102", "201", "202"])
        store.save_run(self.runs_dir, self.incidents[~closed], "wednesday.csv", "defender")
        self.assertEqual(len(store.load_history(self.runs_dir)), 5)
        store.save_run(self.runs_dir, self.incidents.iloc[::-1], "thursday.csv", "defender")
        self.assertEqual(self._classification_of("200"), "")
        self.assertEqual(self._classification_of("103"), "FalsePositive")

    def test_a_classification_given_here_holds_until_a_later_file_names_the_incident(self):
        times = [datetime(2026, 1, day, tzinfo=UTC) for day in (1, 2, 3, 4)]
        with mock.patch.object(store, "datetime") as clock:
            clock.now.side_effect = times
            store.save_run(self.runs_dir, self.incidents, "monday.csv", "defender")
            for incident in ("200", "201"):
                store.append_classification(self.runs_dir, incident, "TruePositive", "", 0.5,
                                            "to read")
            only = self.incidents[self.incidents["IncidentId"] == "200"]
            store.save_run(self.runs_dir, only, "tuesday.csv", "defender")
        self.assertEqual(self._classification_of("200"), "")
        self.assertEqual(self._classification_of("201"), "TruePositive")

    def test_an_incident_in_one_run_comes_out_unchanged(self):
        history = self._merged(ROWS)
        expected = self.incidents.set_index("IncidentId")
        self.assertTrue(history.sort_index().equals(expected.sort_index()))

    def test_settings_round_trip_and_absence(self):
        self.assertEqual(store.read_settings(self.runs_dir), {})
        both = {"budget": 25, "sample_share": 0.2}
        store.write_settings(self.runs_dir, both)
        self.assertEqual(store.read_settings(self.runs_dir), both)
        self.assertEqual((self.runs_dir / store.SETTINGS_FILE).read_text(),
                         '{\n  "budget": 25,\n  "sample_share": 0.2\n}\n')

    def test_a_sample_is_kept_with_its_run(self):
        self.assertEqual(store.read_samples(self.runs_dir), [])
        first = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")["run"]
        store.save_run(self.runs_dir, self.incidents, "b.csv", "defender")
        sample = {"pool": ["200", "202"], "drawn": ["202"]}
        store.save_sample(self.runs_dir, first, sample)
        self.assertEqual(store.read_samples(self.runs_dir), [sample])
        for text in ("not json", "[]", '{"pool": ["200"]}', '{"pool": [200], "drawn": []}',
                     '{"pool": "200", "drawn": 5}', '{"pool": ["200"], "drawn": ["202"]}'):
            with self.subTest(text):
                (self.runs_dir / first / store.SAMPLE_FILE).write_text(text)
                with self.assertRaisesRegex(store.StoreError, store.SAMPLE_FILE):
                    store.read_samples(self.runs_dir)

    def test_a_damaged_run_or_classification_file_is_refused(self):
        run = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")["run"]
        (self.runs_dir / store.CLASSIFICATIONS_FILE).write_text("time,IncidentId\nx,200\n")
        with self.assertRaisesRegex(store.StoreError, store.CLASSIFICATIONS_FILE):
            store.read_classifications(self.runs_dir)
        for text in ("not json", "[]", '{"created": "2024-06-01T00:00:00Z"}'):
            with self.subTest(text):
                (self.runs_dir / run / "meta.json").write_text(text)
                with self.assertRaisesRegex(store.StoreError, "meta.json"):
                    store.list_runs(self.runs_dir)

    def test_a_run_saved_without_a_column_of_this_version_is_refused(self):
        run = store.save_run(self.runs_dir, self.incidents, "a.csv", "defender")["run"]
        saved = self.runs_dir / run / "incidents.csv"
        self.incidents.drop(columns="Severity").to_csv(saved, index=False)
        with self.assertRaisesRegex(store.StoreError, "another version"):
            store.load_history(self.runs_dir)

    def test_a_bad_settings_file_is_refused(self):
        self.runs_dir.mkdir()
        cases = ("not json", "[0.01]", '{"sample_share": "0.1"}', '{"sample_share": true}',
                 '{"sample_share": 1}', '{"sample_share": -0.1}', '{"sample_share": NaN}',
                 '{"sample_share": Infinity}', '{"other": 1}', '{"budget": 5, "other": 1}',
                 '{"budget": 0}', '{"budget": 2.5}', '{"budget": "5"}', '{"budget": true}',
                 '{"budget": null}', '{"miss_rate": 0.05}')
        for text in cases:
            with self.subTest(text):
                (self.runs_dir / store.SETTINGS_FILE).write_text(text)
                with self.assertRaisesRegex(store.StoreError, store.SETTINGS_FILE):
                    store.read_settings(self.runs_dir)


if __name__ == "__main__":
    unittest.main()
