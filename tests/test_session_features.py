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
    })


class SessionFeatureTests(unittest.TestCase):
    def test_schema_learns_categories_and_rule_counts_from_training_only(self):
        train = session_rows()
        schema = fit_session_feature_schema(train)
        test = train.iloc[[0]].copy()
        test["detector_source"] = "new_detector"
        test["rule_id"] = "unseen"
        test["asset_roles"] = [("new_role",)]

        X = build_session_feature_matrix(test, schema)

        self.assertIn("detector_wazuh", X.columns)
        self.assertNotIn("detector_new_detector", X.columns)
        self.assertNotIn("role_new_role", X.columns)
        self.assertEqual(X.loc[test.index[0], "is_unseen_rule"], 1.0)
        self.assertEqual(X.loc[test.index[0], "log_rarity"], 0.0)
        self.assertEqual(schema.detectors, ("wazuh", "suricata"))
        self.assertIn("unused_role", schema.roles)

    def test_rarity_is_continuous_and_identity_is_not_a_feature(self):
        train = session_rows()
        schema = fit_session_feature_schema(train)

        X = build_session_feature_matrix(train, schema)

        self.assertAlmostEqual(X.loc[0, "log_rarity"], -np.log1p(10))
        self.assertAlmostEqual(X.loc[1, "log_rarity"], -np.log1p(1))
        self.assertNotIn("entity_id", X.columns)
        self.assertNotIn("rule_id", X.columns)
        self.assertNotIn("name", X.columns)
        self.assertEqual(list(X.columns), list(schema.feature_names))


if __name__ == "__main__":
    unittest.main()
