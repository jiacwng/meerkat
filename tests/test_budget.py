# The budget line, the sample drawn below it and the estimate, on hand computed cases.

import unittest

import pandas as pd

from core import budget, groups, rank, store
from core.incidents import COLUMNS
from tests.fixtures import HEADER, plain_row, use_weights

IDS = [f"i{number}" for number in range(10)]
ALONE = {incident: incident for incident in (*IDS, "new", "a", "b", "c", "d", "e")}


def _classifications(**classified: str) -> dict[str, str]:
    return {incident: classified.get(incident, "") for incident in IDS}


def _estimate(samples: list[dict], classifications: dict[str, str]) -> dict:
    below = {incident for incident, classification in classifications.items() if classification == ""}
    return budget.estimate(samples, classifications, below)


class BudgetTests(unittest.TestCase):
    def test_slots_follow_the_budget_and_the_share(self):
        self.assertEqual(budget.slots(25, 0.1), 2)
        self.assertEqual(budget.slots(40, 0.2), 8)
        self.assertEqual(budget.slots(3, 0.1), 1)
        self.assertEqual(budget.slots(2, 0.9), 1)
        self.assertEqual(budget.slots(1, 0.5), 0)
        self.assertEqual(budget.slots(10, 0), 0)

    def test_split_fills_the_budget_from_the_top(self):
        opened = ["a", "b", "c", "d", "e"]
        self.assertEqual(list(budget.split(opened, 3, set(), ALONE).values()),
                         ["to read", "to read", "to read", "below budget", "below budget"])
        self.assertEqual(set(budget.split(opened, None, set(), ALONE).values()), {"to read"})
        self.assertEqual(set(budget.split(opened, 9, set(), ALONE).values()), {"to read"})

    def test_a_drawn_incident_takes_a_place_in_the_budget(self):
        opened = ["a", "b", "c", "d", "e"]
        self.assertEqual(budget.split(opened, 3, {"e"}, ALONE),
                         {"a": "to read", "b": "to read", "c": "below budget", "d": "below budget",
                          "e": "sample"})
        self.assertEqual(list(budget.split(opened, 3, set(), ALONE, 1).values()),
                         ["to read", "to read", "below budget", "below budget", "below budget"])

    def test_a_group_takes_one_place_in_the_budget(self):
        opened = ["a", "b", "c", "d", "e"]
        lead = {**ALONE, "b": "a", "c": "a"}
        self.assertEqual(budget.split(opened, 2, set(), lead),
                         {"a": "to read", "b": "to read", "c": "to read", "d": "to read",
                          "e": "below budget"})
        lead = {**ALONE, "e": "d"}
        self.assertEqual(list(budget.split(opened, 3, set(), lead).values()),
                         ["to read", "to read", "to read", "below budget", "below budget"])

    def test_draw_takes_the_sample_from_below_the_budget(self):
        sample = budget.draw(IDS, 4, 0.25, [], ALONE)
        self.assertEqual(sample["pool"], IDS[3:])
        self.assertEqual(len(sample["drawn"]), 1)
        self.assertIn(sample["drawn"][0], IDS[3:])
        self.assertEqual(sample, budget.draw(IDS, 4, 0.25, [], ALONE))
        self.assertEqual(len(budget.draw(IDS, 6, 0.5, [], ALONE)["drawn"]), 3)

    def test_an_incident_enters_one_pool_only(self):
        first = budget.draw(IDS, 4, 0.25, [], ALONE)
        again = budget.draw(IDS, 4, 0.25, [first], ALONE)
        self.assertEqual(again, {"pool": [], "drawn": []})
        waiting = budget.draw([*IDS, "new"], 4, 0.25, [first], ALONE)
        self.assertEqual(waiting, {"pool": [], "drawn": []})
        classified = [incident for incident in IDS if incident not in first["drawn"]]
        later = budget.draw([*classified, "new"], 4, 0.25, [first], ALONE)
        self.assertEqual(later, {"pool": ["new"], "drawn": ["new"]})

    def test_a_budget_above_the_open_incidents_draws_nothing(self):
        self.assertEqual(budget.draw(IDS, 25, 0.1, [], ALONE), {"pool": [], "drawn": []})
        self.assertEqual(budget.draw(IDS, 4, 0, [], ALONE), {"pool": [], "drawn": []})
        self.assertEqual(budget.draw(IDS, 1, 0.5, [], ALONE), {"pool": [], "drawn": []})

    def test_place_gives_open_incidents_a_placement_and_classified_ones_their_record(self):
        use_weights(self)
        rows = [plain_row("old", "5", "FalsePositive", "2024-06-09T00:00:00Z"),
                plain_row("seen", "5", "TruePositive", "2024-06-09T00:01:00Z")]
        rows += [plain_row(name, "5", time=f"2024-06-10T00:0{minute}:00Z")
                 for minute, name in enumerate(("a", "b", "c"))]
        frame = pd.DataFrame(rows, columns=HEADER)
        scored = rank.score(frame.reindex(columns=list(COLUMNS), fill_value=""))
        classifications = pd.DataFrame([("t", "seen", "TruePositive", "", 0.5, "sample")],
                               columns=store.CLASSIFICATION_COLUMNS)
        placed = budget.place(scored, classifications, 2, [{"pool": ["a"], "drawn": ["a"]}],
                              groups.leads(scored, {"a"}))
        self.assertEqual(dict(zip(placed["IncidentId"], placed["placement"], strict=True)),
                         {"c": "to read", "b": "below budget", "a": "sample", "seen": "sample",
                          "old": ""})

    def test_not_sampled_counts_open_incidents_below_the_budget_in_no_pool(self):
        placed = pd.DataFrame({
            "IncidentId": ["a", "b", "c", "d", "e"],
            "IncidentGrade": ["", "", "", "", "FalsePositive"],
            "placement": ["to read", "below budget", "below budget", "sample", "below budget"]})
        self.assertEqual(budget.not_sampled(placed, []), 2)
        self.assertEqual(budget.not_sampled(placed, [{"pool": ["b", "d"], "drawn": ["d"]}]), 1)

    def test_no_classified_sample_gives_no_estimate(self):
        found = _estimate([{"pool": IDS, "drawn": ["i0", "i1"]}], _classifications())
        self.assertEqual(found, {"drawn": 2, "classified": 0, "true_positive": 0,
                                 "tp_below_budget": None})

    def test_a_clean_sample_still_leaves_an_upper_bound(self):
        # 0 of 2: the Wilson upper bound is 3.8415 / 5.8415 = 0.658 of a pool of 10
        classifications = _classifications(i0="FalsePositive", i1="BenignPositive")
        found = _estimate([{"pool": IDS, "drawn": ["i0", "i1"]}], classifications)
        self.assertEqual((found["classified"], found["true_positive"]), (2, 0))
        self.assertEqual(found["tp_below_budget"], {"estimate": 0, "low": 0, "high": 7})

    def test_a_true_positive_in_the_sample_scales_to_the_pool(self):
        # 1 of 2 over a pool of 10 is 5, less the one found; the bound stops at the 8 unread
        classifications = _classifications(i0="TruePositive", i1="FalsePositive")
        found = _estimate([{"pool": IDS, "drawn": ["i0", "i1"]}], classifications)
        self.assertEqual(found["tp_below_budget"], {"estimate": 4, "low": 0, "high": 8})

    def test_the_bound_counts_only_the_incidents_now_below_the_budget(self):
        sample = [{"pool": IDS, "drawn": ["i0", "i1"]}]
        classifications = _classifications(i0="TruePositive", i1="FalsePositive")
        raised = budget.estimate(sample, classifications, {"i8", "i9"})
        self.assertEqual(raised["tp_below_budget"], {"estimate": 2, "low": 0, "high": 2})
        none = budget.estimate(sample, classifications, set())
        self.assertEqual(none["tp_below_budget"], {"estimate": 0, "low": 0, "high": 0})

    def test_a_true_positive_read_later_is_taken_off_the_estimate(self):
        sample = [{"pool": IDS, "drawn": ["i0", "i1"]}]
        before = _estimate(sample, _classifications(i0="TruePositive", i1="FalsePositive"))
        after = _estimate(sample, _classifications(i0="TruePositive", i1="FalsePositive",
                                                i5="TruePositive"))
        self.assertEqual(after["tp_below_budget"]["estimate"],
                         before["tp_below_budget"]["estimate"] - 1)
        self.assertEqual(after["tp_below_budget"]["high"], 7)

    def test_a_pool_with_no_classified_sample_is_scaled_by_the_others(self):
        classifications = {**_classifications(i0="TruePositive", i1="FalsePositive"), "n0": "", "n1": ""}
        samples = [{"pool": IDS, "drawn": ["i0", "i1"]}, {"pool": ["n0", "n1"], "drawn": ["n0"]}]
        found = _estimate(samples, classifications)
        self.assertEqual((found["drawn"], found["classified"]), (3, 2))
        self.assertEqual(found["tp_below_budget"]["estimate"], 5)


if __name__ == "__main__":
    unittest.main()
