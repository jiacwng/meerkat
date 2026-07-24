import unittest

import pandas as pd

from core.inventory import Asset, Inventory
from core.sessions import build_families, build_sessions


def inventory() -> Inventory:
    asset = Asset("server", ("10.0.0.1",), ("intranet", "servers"))
    return Inventory("demo", {"10.0.0.1": asset}, {"server": "10.0.0.1"})


def alerts() -> pd.DataFrame:
    return pd.DataFrame({
        "timestamp": [0.0, 600.0, 1201.0, 1300.0],
        "entity_id": ["10.0.0.1"] * 4,
        "detector_source": ["wazuh"] * 4,
        "rule_id": ["100", "100", "100", "200"],
        "severity": [5.0, 10.0, 15.0, 3.0],
        "native_technique_ids": ["", "T1110", "", ""],
        "alert_category": ["authentication", "policy", "", ""],
        "rule_groups": ["auth", "auth;policy", "", ""],
        "entity_in_inventory": [True] * 4,
        "event_label": ["", "brute_force", "", ""],
        "window_id": [-1, 0, -1, -1],
    })


class SessionTests(unittest.TestCase):
    def test_session_closes_only_after_more_than_600_seconds_of_silence(self):
        sessions = build_sessions(alerts(), "demo", inventory(), gap_s=600.0)

        self.assertEqual(len(sessions), 3)
        self.assertEqual(list(sessions["size"]), [2, 1, 1])
        self.assertEqual(list(sessions["start"]), [0.0, 1201.0, 1300.0])

    def test_session_keeps_labels_roles_and_alert_provenance_out_of_features(self):
        sessions = build_sessions(alerts(), "demo", inventory())
        first = sessions.iloc[0]

        self.assertTrue(bool(first["positive"]))
        self.assertEqual(first["labelled_windows"], frozenset({0}))
        self.assertEqual(first["event_categories"], frozenset({"brute_force"}))
        self.assertEqual(first["asset_roles"], ("intranet", "servers"))
        self.assertEqual(first["alert_rows"], [0, 1])

    def test_session_keeps_temporal_windows_without_calling_them_strict(self):
        marked_alerts = alerts()
        marked_alerts.loc[2, "window_id"] = 1

        sessions = build_sessions(marked_alerts, "demo", inventory())
        unlabelled_session = sessions.iloc[1]

        self.assertIn("temporal_overlap_windows", sessions)
        self.assertEqual(unlabelled_session["labelled_windows"], frozenset())
        self.assertEqual(
            unlabelled_session["temporal_overlap_windows"],
            frozenset({1}),
        )

    def test_live_unlabelled_alerts_can_still_be_grouped(self):
        live_alerts = alerts().drop(columns=["event_label", "window_id"])

        sessions = build_sessions(live_alerts, "live-batch", inventory())

        self.assertFalse(sessions["positive"].any())
        self.assertTrue(sessions["labelled_windows"].map(len).eq(0).all())
        self.assertIn("temporal_overlap_windows", sessions)
        self.assertTrue(
            sessions["temporal_overlap_windows"].map(len).eq(0).all()
        )

    def test_categorical_entity_ids_keep_inventory_roles(self):
        normalized = alerts()
        normalized["entity_id"] = normalized["entity_id"].astype("category")

        sessions = build_sessions(normalized, "demo", inventory())

        self.assertTrue(
            sessions["asset_roles"].map(
                lambda roles: roles == ("intranet", "servers")
            ).all()
        )

    def test_session_keeps_observable_family_metadata(self):
        sessions = build_sessions(alerts(), "demo", inventory())
        first = sessions.iloc[0]

        self.assertEqual(
            first["alert_category_set"],
            frozenset({"authentication", "policy"}),
        )
        self.assertEqual(
            first["technique_id_set"],
            frozenset({"T1110"}),
        )
        self.assertEqual(
            first["rule_group_set"],
            frozenset({"auth", "policy"}),
        )
        self.assertTrue(sessions["detectors_nearby_10m"].eq(1.0).all())

    def test_nearby_detector_count_uses_the_same_entity(self):
        mixed = pd.concat(
            [
                alerts(),
                pd.DataFrame([{
                    "timestamp": 100.0,
                    "entity_id": "10.0.0.1",
                    "detector_source": "suricata",
                    "rule_id": "network",
                    "severity": 2.0,
                    "native_technique_ids": "",
                    "alert_category": "network",
                    "rule_groups": "",
                    "entity_in_inventory": True,
                    "event_label": "",
                    "window_id": -1,
                }]),
            ],
            ignore_index=True,
        )

        sessions = build_sessions(mixed, "demo", inventory())

        nearby = sessions.loc[
            sessions["start"].le(600.0),
            "detectors_nearby_10m",
        ]
        self.assertTrue(nearby.eq(2.0).all())


class FamilyTests(unittest.TestCase):
    def test_family_uses_max_child_score_and_keeps_every_child(self):
        sessions = build_sessions(alerts(), "demo", inventory())
        sessions["ranking_score"] = [0.4, 0.9, 0.7]

        families = build_families(sessions)
        rule_100 = families[families["rule_id"].eq("100")].iloc[0]

        self.assertEqual(rule_100["ranking_score"], 0.9)
        self.assertEqual(rule_100["representative_session_id"], "demo#1")
        self.assertEqual(rule_100["child_session_ids"], ["demo#1", "demo#0"])
        self.assertEqual(rule_100["n_child_sessions"], 2)
        self.assertEqual(rule_100["alert_count"], 3)
        self.assertEqual(rule_100["child_score_max"], 0.9)
        self.assertEqual(rule_100["child_score_mean"], 0.65)
        self.assertEqual(rule_100["child_score_std"], 0.25)
        self.assertEqual(rule_100["family_span_s"], 1201.0)
        self.assertEqual(rule_100["alert_category_count"], 2)
        self.assertEqual(rule_100["technique_count"], 1)
        self.assertEqual(rule_100["rule_group_count"], 2)

    def test_family_unions_temporal_windows_from_all_children(self):
        marked_alerts = alerts()
        marked_alerts.loc[2, "window_id"] = 1
        sessions = build_sessions(marked_alerts, "demo", inventory())
        sessions["ranking_score"] = [0.4, 0.9, 0.7]

        families = build_families(sessions)
        rule_100 = families[families["rule_id"].eq("100")].iloc[0]

        self.assertIn("temporal_overlap_windows", families)
        self.assertEqual(rule_100["labelled_windows"], frozenset({0}))
        self.assertEqual(
            rule_100["temporal_overlap_windows"],
            frozenset({0, 1}),
        )


if __name__ == "__main__":
    unittest.main()
