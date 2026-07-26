import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from core import classifier


class ClassifierTests(unittest.TestCase):
    def test_model_scores_boolean_session_targets(self):
        # predict_scores reads column 1 of predict_proba, so the forest has to
        # keep False before True or every ranking score comes out inverted
        X = pd.DataFrame({"signal": [0.0, 0.1, 0.9, 1.0]})
        target = pd.Series([False, False, True, True])

        model = classifier.fit_model(X, target, n_estimators=10, seed=0)
        scores = classifier.predict_scores(model, X)

        self.assertEqual(set(model.classes_), {False, True})
        self.assertEqual(scores.shape, (4,))
        self.assertGreater(scores[3], scores[0])

    def test_sigmoid_calibrator_returns_increasing_probabilities(self):
        # the confidence percentage is display only, so it has to stay monotone
        # in the ranking score or the queue order and the number disagree
        scores = np.array([0.0, 0.1, 0.2, 0.8, 0.9, 1.0])
        target = np.array([0, 0, 0, 1, 1, 1])

        calibrator = classifier.fit_calibrator(scores, target)
        probabilities = calibrator.predict(scores)

        self.assertTrue(np.all(np.diff(probabilities) > 0))
        self.assertTrue(np.all((probabilities >= 0) & (probabilities <= 1)))

    def test_explanation_reports_active_globally_important_features(self):
        # a feature sitting at 0 on this row is skipped, so an all-zero column
        # never turns up among the reasons shown beside a family
        X = pd.DataFrame({
            "volume": [0.0, 0.1, 0.9, 1.0],
            "role_server": [0.0, 0.0, 1.0, 1.0],
            "inactive": [0.0, 0.0, 0.0, 0.0],
        })
        model = classifier.fit_model(
            X, pd.Series([False, False, True, True]), n_estimators=10, seed=0
        )

        explanation = classifier.explain_session(model, X.iloc[-1], top=2)

        self.assertLessEqual(len(explanation), 2)
        self.assertTrue(all(name != "inactive" for name, _, _ in explanation))

    def test_model_round_trip(self):
        # every read command reopens a bundle skops wrote, so a reloaded forest
        # has to score an unseen row identically to the one still in memory
        model = classifier.fit_model(
            pd.DataFrame({"signal": [0.0, 1.0]}),
            pd.Series([False, True]),
            n_estimators=5,
            seed=0,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.pkl"
            classifier.save_model(model, path)
            loaded = classifier.load_model(path)

        np.testing.assert_allclose(
            classifier.predict_scores(model, pd.DataFrame({"signal": [0.2]})),
            classifier.predict_scores(loaded, pd.DataFrame({"signal": [0.2]})),
        )

    def test_family_reranker_scores_family_aggregates(self):
        # role columns are rebuilt from asset_roles at predict time, so their
        # sorted order is pinned or a family's role lands in the wrong column
        rows = []
        for position, positive in enumerate((False, False, True, True)):
            signal = float(positive)
            row = dict.fromkeys(classifier.FAMILY_NUMERIC_FEATURES, signal)
            row["asset_roles"] = (
                ("servers",) if position % 2 else ("clients",)
            )
            row["family_positive"] = positive
            rows.append(row)
        families = pd.DataFrame(rows)

        reranker = classifier.fit_family_reranker(families)
        scores = reranker.predict(families)

        self.assertEqual(scores.shape, (4,))
        self.assertGreater(scores[-1], scores[0])
        self.assertEqual(reranker.roles, ("clients", "servers"))


if __name__ == "__main__":
    unittest.main()
