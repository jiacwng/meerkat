import unittest

import pandas as pd

from core.triage_policy import daily_queue, enrich_alerts


class QueueTests(unittest.TestCase):
    def test_queue_takes_plain_top_k_families_per_day(self):
        # the budget is spent per day, so one loud day cannot swallow the slots
        # the next day needs and each day gets its own two picks
        families = pd.DataFrame({
            "day": [1, 1, 1, 2, 2],
            "ranking_score": [0.7, 0.9, 0.8, 0.2, 0.6],
            "evidence_probability": [0.8, 0.95, 0.9, 0.3, 0.7],
            "start": [10.0, 20.0, 30.0, 86410.0, 86420.0],
            "representative_session_id": ["a", "b", "c", "d", "e"],
        })

        queue = daily_queue(families, k=2)

        self.assertEqual(
            list(queue["representative_session_id"]), ["b", "c", "e", "d"]
        )

    def test_display_probability_does_not_control_queue_order(self):
        # evidence_probability is Platt output for display, so retuning the
        # calibrator can never reorder what an analyst opens first
        families = pd.DataFrame({
            "day": [1, 1],
            "ranking_score": [0.9, 0.8],
            "evidence_probability": [0.1, 0.99],
            "start": [10.0, 20.0],
            "representative_session_id": ["raw-first", "display-first"],
        })

        queue = daily_queue(families, k=1)

        self.assertEqual(queue.iloc[0]["representative_session_id"], "raw-first")

    def test_ties_use_start_then_session_id(self):
        # a forest voting over 300 trees produces equal scores often, so the
        # order has to be fully determined or two runs print different queues
        families = pd.DataFrame({
            "day": [1, 1, 1],
            "ranking_score": [0.5, 0.5, 0.5],
            "start": [20.0, 10.0, 10.0],
            "representative_session_id": ["c", "b", "a"],
        })

        queue = daily_queue(families, k=3)

        self.assertEqual(list(queue["representative_session_id"]), ["a", "b", "c"])


class EnrichmentTests(unittest.TestCase):
    def test_batch_enrichment_adds_attack_mapping(self):
        # the batch path applies the same rule override map_alert does, so
        # wazuh 31516 lands on T1505.003 though the alert carries native T1055
        frame = pd.DataFrame({
            "detector_source": ["wazuh"],
            "rule_id": ["31516"],
            "native_technique_ids": ["T1055"],
        })

        enriched = enrich_alerts(frame)

        self.assertEqual(enriched.loc[0, "technique_ids"], "T1505.003")
        self.assertEqual(enriched.loc[0, "tactics"], ("Persistence",))
        self.assertEqual(enriched.loc[0, "mapping_source"], "rule")


if __name__ == "__main__":
    unittest.main()
