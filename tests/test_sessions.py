# alerts to sessions and families, the features built from them, and the queue

import unittest

import numpy as np
import pandas as pd

from core.features import build_session_feature_matrix, fit_session_feature_schema
from core.inventory import Asset, Inventory
from core.sessions import build_families, build_sessions
from core.triage_policy import daily_queue, enrich_alerts


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
        # the gap is a strict greater-than, so alerts exactly 600 s apart stay
        # one burst and the 601 s step up to 1201.0 is what opens a new one
        sessions = build_sessions(alerts(), "demo", inventory(), gap_s=600.0)

        self.assertEqual(len(sessions), 3)
        self.assertEqual(list(sessions["size"]), [2, 1, 1])
        self.assertEqual(list(sessions["start"]), [0.0, 1201.0, 1300.0])

    def test_session_keeps_labels_roles_and_alert_provenance_out_of_features(self):
        # the CLI slices the alert table by alert_rows and evaluation counts
        # labelled_windows, so both ride on the session beside the features
        sessions = build_sessions(alerts(), "demo", inventory())
        first = sessions.iloc[0]

        self.assertTrue(bool(first["positive"]))
        self.assertEqual(first["labelled_windows"], frozenset({0}))
        self.assertEqual(first["event_categories"], frozenset({"brute_force"}))
        self.assertEqual(first["asset_roles"], ("intranet", "servers"))
        self.assertEqual(first["alert_rows"], [0, 1])

        # and out of the matrix: labelled_windows is ground truth, alert_rows
        # is a position in one company's file, and asset_roles reaches the
        # forest as the role_ block rather than as the tuple itself
        X = build_session_feature_matrix(
            sessions, fit_session_feature_schema(sessions)
        )
        for column in ("labelled_windows", "asset_roles", "alert_rows"):
            with self.subTest(column=column):
                self.assertIn(column, sessions.columns)
                self.assertNotIn(column, X.columns)
        self.assertIn("role_servers", X.columns)

    def test_session_keeps_temporal_windows_without_calling_them_strict(self):
        # an alert inside an attack window with no event_label is only a time
        # overlap, so window 1 lands there and labelled_windows stays empty
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
        # a client feed has no event_label or window_id column at all, so
        # build_sessions fills both in rather than raising a KeyError
        live_alerts = alerts().drop(columns=["event_label", "window_id"])

        sessions = build_sessions(live_alerts, "live-batch", inventory())

        self.assertFalse(sessions["positive"].any())
        self.assertTrue(sessions["labelled_windows"].map(len).eq(0).all())
        self.assertIn("temporal_overlap_windows", sessions)
        self.assertTrue(
            sessions["temporal_overlap_windows"].map(len).eq(0).all()
        )

    def test_categorical_entity_ids_keep_inventory_roles(self):
        # normalize hands entity_id back as a category to save memory, and the
        # inventory is keyed on plain strings, so roles survive that dtype
        normalized = alerts()
        normalized["entity_id"] = normalized["entity_id"].astype("category")

        sessions = build_sessions(normalized, "demo", inventory())

        self.assertTrue(
            sessions["asset_roles"].map(
                lambda roles: roles == ("intranet", "servers")
            ).all()
        )

    def test_session_keeps_observable_family_metadata(self):
        # alert_category_count, technique_count and rule_group_count all feed
        # the re-ranker, so the semicolon-joined strings split into sets first
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
        # two detectors on one host inside ten minutes is the corroboration the
        # re-ranker leans on, counted per entity so a busy neighbour is ignored
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
        # a family ranks on its best child and still lists the quieter burst as
        # S2, and the spread is a population std so two children give 0.25
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
        # coverage is scored on the family an analyst opens, so a child that
        # only overlaps window 1 still contributes it to the parent
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


def session_rows() -> pd.DataFrame:
    return pd.DataFrame({
        "scenario": ["train", "train"],
        "entity_id": ["10.0.0.1", "10.0.0.2"],
        "detector_source": ["wazuh", "suricata"],
        "rule_id": ["common", "rare"],
        "size": [10, 1],
        "log_size": [np.log1p(10), np.log1p(1)],
        "duration_s": [60.0, 0.0],
        "alerts_per_min": [5.0, 1.0],
        "severity_max": [1.0, 0.5],
        "severity_mean": [0.8, 0.5],
        "has_technique": [1.0, 0.0],
        "in_inventory": [1.0, 1.0],
        "detectors_on_entity": [2.0, 1.0],
        "groups_on_entity": [3.0, 1.0],
        "log_alerts_on_entity": [np.log1p(20), np.log1p(1)],
        "asset_roles": [("servers",), ("employee",)],
        "configured_roles": [
            ("employee", "servers", "unused_role"),
            ("employee", "servers", "unused_role"),
        ],
        "pair_counts": [
            ((("wazuh", "common"), 10),),
            ((("suricata", "rare"), 1),),
        ],
    })


class SessionFeatureTests(unittest.TestCase):
    def test_schema_learns_categories_and_rule_counts_from_training_only(self):
        # the training companies fix the column set, so a detector, rule or
        # role first seen on the held-out company adds none and reads as unseen
        train = session_rows()
        schema = fit_session_feature_schema(train)
        test = train.iloc[[0]].copy()
        test["detector_source"] = "new_detector"
        test["rule_id"] = "unseen"
        test["asset_roles"] = [("new_role",)]
        test["pair_counts"] = [((("new_detector", "unseen"), 10),)]

        X = build_session_feature_matrix(test, schema)

        self.assertIn("detector_wazuh", X.columns)
        self.assertNotIn("detector_new_detector", X.columns)
        self.assertNotIn("role_new_role", X.columns)
        self.assertEqual(X.loc[test.index[0], "is_unseen_rule"], 1.0)
        self.assertEqual(X.loc[test.index[0], "log_rarity"], 0.0)
        self.assertEqual(schema.detectors, ("wazuh", "suricata"))
        self.assertIn("unused_role", schema.roles)

    def test_rarity_is_continuous_and_identity_is_not_a_feature(self):
        # rarity carries how often a rule fired as -log1p(count), which keeps
        # the rule name out of the matrix so no model recognises a company
        train = session_rows()
        schema = fit_session_feature_schema(train)

        X = build_session_feature_matrix(train, schema)

        self.assertAlmostEqual(X.loc[0, "log_rarity"], -np.log1p(10))
        self.assertAlmostEqual(X.loc[1, "log_rarity"], -np.log1p(1))
        self.assertNotIn("entity_id", X.columns)
        self.assertNotIn("rule_id", X.columns)
        self.assertNotIn("name", X.columns)
        self.assertEqual(list(X.columns), list(schema.feature_names))


class MixedSessionTests(unittest.TestCase):
    # a key that drops detector_source or rule_id lets one session hold several
    # of each. The features must describe what the session contains rather than
    # whichever alert happened to land first.
    def mixed(self, pairs) -> pd.DataFrame:
        row = session_rows().iloc[[0]].copy()
        row["pair_counts"] = [tuple(pairs)]
        row["size"] = sum(count for _, count in pairs)
        return row

    def test_schema_counts_every_rule_in_a_mixed_session(self):
        # counts come off pair_counts, so a session holding two rules gives 3
        # to one and 7 to the other rather than counting only the first pair
        train = self.mixed([(("wazuh", "a"), 3), (("suricata", "b"), 7)])

        schema = fit_session_feature_schema(train)

        self.assertEqual(schema.rule_counts[("wazuh", "a")], 3)
        self.assertEqual(schema.rule_counts[("suricata", "b")], 7)
        self.assertEqual(schema.detectors, ("wazuh", "suricata"))

    def test_detector_columns_hold_the_share_of_alerts_not_a_one_hot(self):
        # a session under a looser key can hold two detectors, so each column
        # takes that detector's share and 3 wazuh to 1 suricata reads 0.75
        train = self.mixed([(("wazuh", "a"), 3), (("suricata", "b"), 1)])
        schema = fit_session_feature_schema(train)

        X = build_session_feature_matrix(train, schema)

        self.assertAlmostEqual(X.loc[0, "detector_wazuh"], 0.75)
        self.assertAlmostEqual(X.loc[0, "detector_suricata"], 0.25)

    def test_rarity_weights_each_rule_by_how_much_of_the_session_it_is(self):
        # one rare alert among nine common ones must not drag the whole
        # session's rarity down, so each rule counts for its share of alerts
        train = self.mixed([(("wazuh", "common"), 9), (("wazuh", "rare"), 1)])
        schema = fit_session_feature_schema(train)

        X = build_session_feature_matrix(train, schema)

        expected = 0.9 * -np.log1p(9) + 0.1 * -np.log1p(1)
        self.assertAlmostEqual(X.loc[0, "log_rarity"], expected)

    def test_a_partly_unseen_session_is_partly_flagged(self):
        # a rule missing from training is unseen rather than quiet, so a
        # quarter flags unseen and only the known three quarters carry rarity
        schema = fit_session_feature_schema(
            self.mixed([(("wazuh", "known"), 4)])
        )
        test = self.mixed([(("wazuh", "known"), 3), (("wazuh", "novel"), 1)])

        X = build_session_feature_matrix(test, schema)

        self.assertAlmostEqual(X.loc[0, "is_unseen_rule"], 0.25)
        self.assertAlmostEqual(X.loc[0, "log_rarity"], 0.75 * -np.log1p(4))

    def test_one_pair_reproduces_the_old_one_hot_and_lookup(self):
        # the key in use today gives exactly one pair per session, so the new
        # weighting has to collapse back onto what it replaced
        train = self.mixed([(("wazuh", "only"), 6)])
        schema = fit_session_feature_schema(train)

        X = build_session_feature_matrix(train, schema)

        self.assertEqual(X.loc[0, "detector_wazuh"], 1.0)
        self.assertEqual(X.loc[0, "is_unseen_rule"], 0.0)
        self.assertAlmostEqual(X.loc[0, "log_rarity"], -np.log1p(6))


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
