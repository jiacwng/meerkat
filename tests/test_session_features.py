import unittest

import numpy as np
import pandas as pd

from core.features import build_session_feature_matrix, fit_session_feature_schema


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


if __name__ == "__main__":
    unittest.main()
