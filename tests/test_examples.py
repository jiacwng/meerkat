# The shipped example files read, carry no placeholder ids and score through the CLI.

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import features, store
from core.incidents import CLASSIFICATIONS, LINKS, SEPARATOR
from meerkat.cli import main
from tests.fixtures import read_file

EXAMPLES = Path(__file__).parent.parent / "examples"


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.incidents = read_file(EXAMPLES / "incidents.csv")

    def test_the_example_holds_one_organisation(self):
        self.assertGreater(len(self.incidents), 0)
        rows = pd.read_csv(EXAMPLES / "incidents.csv", dtype=str, usecols=["OrgId"])
        self.assertEqual(rows["OrgId"].nunique(), 1)

    def test_classifications_file_holds_exactly_the_open_incidents(self):
        classifications = pd.read_csv(EXAMPLES / "classifications.csv", dtype=str, keep_default_na=False)
        opened = self.incidents.loc[self.incidents["IncidentGrade"] == "", "IncidentId"]
        self.assertEqual(set(classifications["IncidentId"]), set(opened))
        self.assertEqual(len(classifications), len(opened))
        self.assertTrue(classifications["IncidentGrade"].isin(CLASSIFICATIONS).all())

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
            store.save_run(runs_dir, read_file(path), path.name, "defender")
        merged = store.load_history(runs_dir).sort_values("IncidentId")
        single = self.incidents.sort_values("IncidentId")
        pd.testing.assert_frame_equal(merged.reset_index(drop=True),
                                      single.reset_index(drop=True))

    def _quick_start(self, runs_dir: Path) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["config", "budget", "10", "--runs-dir", str(runs_dir)])
            main(["queue", str(EXAMPLES / "incidents.csv"), "--runs-dir", str(runs_dir)])
        return out.getvalue()

    def test_readme_quotes_the_footer_the_quick_start_prints(self):
        runs_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        footer = self._quick_start(runs_dir).split("\n\n")[-1].splitlines()
        self.assertEqual(footer[0], "OPEN           47 incidents in 46 rows, 10 listed")
        readme = (EXAMPLES.parent / "README.md").read_text(encoding="utf-8")
        for line in footer:
            self.assertIn(line, readme)

    def test_readme_quotes_what_budget_prints_once_the_sample_is_classified(self):
        runs_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self._quick_start(runs_dir)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["classify", store.read_samples(runs_dir)[0]["drawn"][0], "fp",
                  "--runs-dir", str(runs_dir)])
            out.truncate(0)
            out.seek(0)
            main(["budget", "--runs-dir", str(runs_dir)])
        readme = (EXAMPLES.parent / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"```text\n{out.getvalue()}```", readme)

    def test_classifications_file_counts_the_true_positives_in_the_list_and_below_it(self):
        runs_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self._quick_start(runs_dir)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["classify", "--file", str(EXAMPLES / "classifications.csv"), "--runs-dir", str(runs_dir)])
        self.assertEqual(out.getvalue().splitlines()[-1],
                         "CLASSIFIED   incidents 47   tp 35   tp_to_read 9   tp_sample 0   tp_below 26")
        sample = store.read_samples(runs_dir)[0]
        self.assertEqual((len(sample["pool"]), len(sample["drawn"])), (38, 1))


if __name__ == "__main__":
    unittest.main()
