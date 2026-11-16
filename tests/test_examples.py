# The shipped example files read, carry no placeholder ids and score through the CLI.

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import features, store
from core.incidents import GRADES, LINKS, SEPARATOR, read_incidents
from meerkat.cli import main
from tests.fixtures import DEFENDER, use_weights

EXAMPLES = Path(__file__).parent.parent / "examples"


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.incidents = read_incidents(EXAMPLES / "incidents.csv", DEFENDER)

    def test_defender_mapping_reads_one_organisation(self):
        self.assertGreater(len(self.incidents), 0)
        rows = pd.read_csv(EXAMPLES / "incidents.csv", dtype=str, usecols=["OrgId"])
        self.assertEqual(rows["OrgId"].nunique(), 1)

    def test_grades_file_holds_exactly_the_open_incidents(self):
        grades = pd.read_csv(EXAMPLES / "grades.csv", dtype=str, keep_default_na=False)
        opened = self.incidents.loc[self.incidents["IncidentGrade"] == "", "IncidentId"]
        self.assertEqual(set(grades["IncidentId"]), set(opened))
        self.assertEqual(len(grades), len(opened))
        self.assertTrue(grades["IncidentGrade"].isin(GRADES).all())

    def test_no_link_value_is_a_placeholder(self):
        for column in LINKS:
            values = self.incidents[column].str.split(SEPARATOR).explode()
            counts = values[values != ""].value_counts()
            self.assertTrue((counts / len(self.incidents)
                             <= features.PLACEHOLDER_SHARE).all(), column)

    def test_incidents_split_by_alert_day_merge_back_into_the_single_file(self):
        rows = pd.read_csv(EXAMPLES / "incidents.csv", dtype=str, keep_default_na=False)
        days = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601").dt.date
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        runs_dir = folder / "runs"
        for day, part in rows.groupby(days):
            path = folder / f"{day}.csv"
            part.to_csv(path, index=False)
            store.save_run(runs_dir, read_incidents(path, DEFENDER), path.name, "defender")
        merged = store.load_history(runs_dir).sort_values("IncidentId")
        single = self.incidents.sort_values("IncidentId")
        pd.testing.assert_frame_equal(merged.reset_index(drop=True),
                                      single.reset_index(drop=True))

    def test_queue_lists_incidents(self):
        use_weights(self)
        runs_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["queue", str(EXAMPLES / "incidents.csv"), "--json",
                  "--runs-dir", str(runs_dir)])
        self.assertGreater(len(json.loads(out.getvalue())["queue"]), 0)

    def test_readme_quotes_the_footer_the_quick_start_prints(self):
        runs_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["queue", str(EXAMPLES / "incidents.csv"), "--runs-dir", str(runs_dir)])
        count, closed, kept = out.getvalue().splitlines()[-3:]
        readme = (EXAMPLES.parent / "README.md").read_text(encoding="utf-8")
        self.assertIn(count, readme)
        self.assertIn(closed, readme)
        self.assertIn(kept, readme)


if __name__ == "__main__":
    unittest.main()
