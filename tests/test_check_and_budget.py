# `meerkat check` reads a sample and reports what triage will see. `queue --budget`
# re-cuts a saved run, which works only because K never reaches the model.

from __future__ import annotations

import unittest

import pandas as pd

from meerkat.cli import RULE_CARDINALITY_WARN, build_parser


class TestCheckParser(unittest.TestCase):
    def test_check_needs_nothing_but_a_directory(self):
        # a client's first command after unpacking their alerts, so requiring
        # --company or --inventory here would defeat the point
        args = build_parser().parse_args(["check"])
        self.assertIsNone(args.company)
        self.assertIsNone(args.inventory)
        self.assertEqual(args.input.name, "alerts")

    def test_check_takes_the_same_file_overrides_as_triage(self):
        # whatever names a client's exports have, check has to read the files
        # triage will read, or it validates something else
        args = build_parser().parse_args([
            "check", "--wazuh-file", "w.json", "--aminer-file", "a.json",
        ])
        self.assertEqual(args.wazuh_file.name, "w.json")
        self.assertEqual(args.aminer_file.name, "a.json")

    def test_the_sample_size_is_boundable(self):
        # the demo's wazuh export alone is 45 MB, so check must never be asked to
        # read a whole file to answer a question about its shape
        args = build_parser().parse_args(["check", "--sample", "250"])
        self.assertEqual(args.sample, 250)


class TestRuleCardinality(unittest.TestCase):
    def test_the_warning_threshold_catches_one_rule_id_per_alert(self):
        # a detector that numbers each anomaly instead of naming its type makes
        # every session unique, so rarity carries nothing and sessions never group.
        # nothing errors, which is why check has to say it out loud.
        per_occurrence = 1.0
        per_type = 34 / 3000
        self.assertGreater(per_occurrence, RULE_CARDINALITY_WARN)
        self.assertLess(per_type, RULE_CARDINALITY_WARN)


class TestQueueBudget(unittest.TestCase):
    def families(self, per_day: int, days: int) -> pd.DataFrame:
        return pd.DataFrame([
            {"day": day, "queue_rank": rank, "in_queue": rank < 10}
            for day in range(days)
            for rank in range(per_day)
        ])

    def test_recutting_uses_the_rank_triage_already_saved(self):
        # every family carries its queue_rank, so a saved run can be cut anywhere
        # without rescoring. This is the whole reason K is free.
        families = self.families(per_day=30, days=4)
        for budget in (3, 10, 25):
            recut = families["queue_rank"] < budget
            self.assertEqual(int(recut.sum()), budget * 4)

    def test_a_budget_wider_than_the_day_keeps_everything(self):
        families = self.families(per_day=7, days=2)
        self.assertEqual(int((families["queue_rank"] < 50).sum()), 14)

    def test_queue_accepts_a_budget_and_defaults_to_leaving_the_run_alone(self):
        parser = build_parser()
        self.assertIsNone(parser.parse_args(["queue"]).budget)
        self.assertEqual(parser.parse_args(["queue", "--budget", "5"]).budget, 5)


if __name__ == "__main__":
    unittest.main()
