# The client retraining path: soft labels from bags, a rescaled re-ranker and a
# forest swapped into an otherwise frozen bundle.

from __future__ import annotations

import unittest
import unittest.mock
from pathlib import Path

import numpy as np
import pandas as pd

from core import classifier
from core.classifier import FAMILY_NUMERIC_FEATURES
from meerkat.cli import _validate_retrain_result, build_parser


def features(n: int, signal: np.ndarray) -> pd.DataFrame:
    return pd.DataFrame({"signal": signal, "noise": np.zeros(n)})


def families(scores: list[float], roles: tuple[str, ...] = ("server",)) -> pd.DataFrame:
    rows = []
    for score in scores:
        row = dict.fromkeys(FAMILY_NUMERIC_FEATURES, 1.0)
        row["child_score_max"] = score
        row["child_score_mean"] = score
        row["asset_roles"] = roles
        rows.append(row)
    return pd.DataFrame(rows)


class TestSoftLabels(unittest.TestCase):
    def test_a_session_in_no_bag_trains_as_a_clean_negative(self):
        # sessions outside every incident are the only hard labels a client
        # has, so the forest separates on them with nothing asserted positive
        X = features(6, np.array([0.0, 0.0, 0.0, 1.0, 1.0, 1.0]))
        prior = np.array([0.0, 0.0, 0.0, 0.5, 0.5, 0.5])

        model = classifier.fit_soft_labels(X, prior, n_estimators=20, seed=0)
        scores = classifier.predict_scores(model, X)

        self.assertGreater(scores[3:].mean(), scores[:3].mean())

    def test_training_refuses_when_no_session_is_in_a_bag(self):
        # an incident file whose hosts or times never meet the alerts leaves
        # nothing to learn from, and an all-negative forest would hide that
        X = features(4, np.zeros(4))
        with self.assertRaises(ValueError):
            classifier.fit_soft_labels(X, np.zeros(4), n_estimators=5, seed=0)

    def test_a_prior_above_one_is_clipped_rather_than_trusted(self):
        # the prior is a sample weight split across two stacked copies of the
        # row, so 4.0 would give the negative copy a weight of -3.0
        X = features(4, np.array([0.0, 0.0, 1.0, 1.0]))
        model = classifier.fit_soft_labels(
            X, np.array([0.0, 0.0, 4.0, 4.0]), n_estimators=10, seed=0
        )
        self.assertEqual(model.predict_proba(X).shape[1], 2)

    def test_an_unreviewed_session_is_dropped_rather_than_trained_as_clean(self):
        # sessions 0-1 reviewed and clean, 2-3 never looked at, 4-5 in a bag
        X = features(6, np.array([0.0, 0.0, 9.0, 9.0, 1.0, 1.0]))
        prior = np.array([0.0, 0.0, 0.0, 0.0, 0.5, 0.5])
        reviewed = np.array([True, True, False, False, True, True])

        model = classifier.fit_soft_labels(
            X, prior, reviewed, n_estimators=20, seed=0
        )

        # the unreviewed rows never entered training, so the forest cannot have
        # learned their signal value of 9.0 as a negative
        self.assertEqual(model.n_features_in_, X.shape[1])
        seen = classifier.predict_scores(model, X)
        self.assertGreater(seen[4:].mean(), seen[:2].mean())

    def test_reviewed_periods_that_exclude_every_negative_are_refused(self):
        # a period file covering only the incident hours leaves both classes
        # made of the same rows, so it stops rather than fitting noise
        X = features(4, np.array([0.0, 0.0, 1.0, 1.0]))
        with self.assertRaises(ValueError) as caught:
            classifier.fit_soft_labels(
                X,
                np.array([0.0, 0.0, 0.5, 0.5]),
                np.array([False, False, True, True]),
                n_estimators=5,
                seed=0,
            )
        self.assertIn("nothing left to learn a negative from", str(caught.exception))

    def test_no_reviewed_argument_keeps_every_session_outside_a_bag(self):
        # passing no period file has to behave exactly like marking everything
        # reviewed, so adding the flag later cannot move a client's scores
        X = features(4, np.array([0.0, 0.0, 1.0, 1.0]))
        prior = np.array([0.0, 0.0, 0.5, 0.5])
        without = classifier.fit_soft_labels(X, prior, None, n_estimators=20, seed=0)
        all_reviewed = classifier.fit_soft_labels(
            X, prior, np.ones(4, dtype=bool), n_estimators=20, seed=0
        )
        np.testing.assert_allclose(
            classifier.predict_scores(without, X),
            classifier.predict_scores(all_reviewed, X),
        )

    def test_a_larger_prior_pushes_bagged_sessions_higher(self):
        # the prior is the weight on the positive copy, so a ticket spread
        # over few sessions pulls them further up than one spread over many
        X = features(8, np.array([0.0] * 4 + [1.0] * 4))
        low = classifier.predict_scores(
            classifier.fit_soft_labels(
                X, np.array([0.0] * 4 + [0.1] * 4), n_estimators=30, seed=0
            ),
            X,
        )
        high = classifier.predict_scores(
            classifier.fit_soft_labels(
                X, np.array([0.0] * 4 + [0.9] * 4), n_estimators=30, seed=0
            ),
            X,
        )
        self.assertGreater(high[4:].mean(), low[4:].mean())


def reached(hits: int, total: int) -> list[bool]:
    return [True] * hits + [False] * (total - hits)


class TestRetrainGate(unittest.TestCase):
    def test_a_model_that_reaches_nothing_is_refused(self):
        # a retrained forest reaching none of the held-out incidents is broken
        # however good its other numbers look, so approval stops there
        with self.assertRaises(ValueError) as caught:
            _validate_retrain_result(reached(0, 10), reached(0, 10))
        self.assertIn("none of the 10", str(caught.exception))

    def test_a_regression_is_refused(self):
        # the client is choosing between the shipped bundle and this one, so
        # reaching 3 where the shipped one reached 8 can never be saved
        with self.assertRaises(ValueError):
            _validate_retrain_result(reached(8, 10), reached(3, 10))

    def test_two_identical_models_give_no_reason_to_swap(self):
        # identical reach on every incident gives the sign test nothing to
        # work with, so a same-scoring retrain is not worth deploying
        with self.assertRaises(ValueError) as caught:
            _validate_retrain_result(reached(8, 10), reached(8, 10))
        self.assertIn("disagree on 0", str(caught.exception))

    def test_five_disagreements_cannot_call_a_winner(self):
        # a two-sided sign test on five same-direction pairs reaches only 0.0625
        with self.assertRaises(ValueError):
            _validate_retrain_result(reached(0, 10), reached(5, 10))

    def test_six_disagreements_in_the_right_direction_approve(self):
        # six same-direction pairs put the two-sided sign test at 0.031, the
        # first count that can call the difference real
        _validate_retrain_result(reached(0, 10), reached(6, 10))

    def test_retrain_accepts_an_optional_reviewed_period_file(self):
        # --reviewed-periods has to parse as a Path and stay optional, since
        # the three required flags already make a valid retrain
        args = build_parser().parse_args([
            "retrain",
            "--company", "acme",
            "--incidents", "incidents.csv",
            "--inventory", "inventory.json",
            "--reviewed-periods", "reviewed.csv",
        ])
        self.assertEqual(args.reviewed_periods, Path("reviewed.csv"))


class TestRescaleReranker(unittest.TestCase):
    def setUp(self):
        trained = families([0.1, 0.2, 0.8, 0.9])
        trained["family_positive"] = [False, False, True, True]
        self.reranker = classifier.fit_family_reranker(trained)

    def test_the_learned_coefficients_are_kept(self):
        # those coefficients need out-of-fold folds across environments that
        # one client does not have, so rescaling leaves them alone
        rescaled = classifier.rescale_reranker(self.reranker, families([0.01, 0.02]))
        np.testing.assert_array_equal(
            self.reranker.model.named_steps["model"].coef_,
            rescaled.model.named_steps["model"].coef_,
        )

    def test_the_scaler_moves_to_the_new_distribution(self):
        # a client forest scores lower and tighter than the AIT one, so the
        # stored mean has to drop to where the new scores actually sit
        rescaled = classifier.rescale_reranker(
            self.reranker, families([0.001, 0.002, 0.003, 0.004])
        )
        before = self.reranker.model.named_steps["scale"].mean_[0]
        after = rescaled.model.named_steps["scale"].mean_[0]
        self.assertNotAlmostEqual(before, after)
        self.assertLess(after, before)

    def test_rescaling_leaves_the_original_untouched(self):
        # retrain compares the shipped bundle against the rescaled one in the
        # same process, so the baseline arm has to keep its own scaler
        before = self.reranker.model.named_steps["scale"].mean_.copy()
        classifier.rescale_reranker(self.reranker, families([0.001, 0.002]))
        np.testing.assert_array_equal(
            before, self.reranker.model.named_steps["scale"].mean_
        )

    def test_a_compressed_forest_still_gets_a_usable_spread(self):
        # squashed scores put every family at the same distance from the AIT mean,
        # which is what stops the forest reaching the ranking at all
        compressed = families([0.001, 0.002, 0.003, 0.004])
        frozen = self.reranker.predict(compressed)
        rescaled = classifier.rescale_reranker(self.reranker, compressed).predict(
            compressed
        )
        self.assertGreater(rescaled.std(), frozen.std())


if __name__ == "__main__":
    unittest.main()


class TestCompareModels(unittest.TestCase):
    # the gate's decision logic, now callable without going through cmd_retrain.
    # It was only reachable through a hundred-line command before.
    def verdict(self, shipped_hits: int, candidate_hits: list[int], total: int) -> dict:
        from meerkat import cli

        # the real _incident_reach returns a boolean numpy array, so the double
        # must too or .sum() below is a list attribute error
        def hits(n):
            return np.asarray(reached(n, total), dtype=bool)

        calls = iter([hits(shipped_hits)]
                     + [hits(h) for h in candidate_hits]
                     + [hits(shipped_hits)])

        with unittest.mock.patch.object(
            cli, "incident_reach_for", side_effect=lambda *a, **k: next(calls)
        ), unittest.mock.patch.object(cli, "rescale_bundle", side_effect=lambda b, s: b):
            return cli.compare_models(
                object(), [object()] * len(candidate_hits),
                None, None, list(range(total)), None, 10,
            )

    def test_a_majority_of_seeds_must_beat_the_shipped_bundle(self):
        approved = self.verdict(0, [8, 8, 8, 0, 0], 10)
        self.assertTrue(approved["approved"])
        self.assertEqual(sum(approved["passed"]), 3)

    def test_a_minority_is_refused(self):
        # four of the five forests reach nothing, so the first recorded reason is
        # the zero-reach refusal rather than the discordance one
        refused = self.verdict(0, [8, 0, 0, 0, 0], 10)
        self.assertFalse(refused["approved"])
        self.assertEqual(sum(refused["passed"]), 1)
        self.assertIn("none of the 10", refused["reason"])

    def test_two_indistinguishable_models_are_refused_for_disagreeing_too_little(self):
        # every forest reaches the same five incidents the shipped bundle does, so
        # there is no reason to swap a production model for an equal one
        refused = self.verdict(5, [5, 5, 5], 10)
        self.assertFalse(refused["approved"])
        self.assertIn("disagree on 0", refused["reason"])

    def test_the_median_seed_is_kept_rather_than_the_best(self):
        # picking the best would select on the same held-out incidents the gate
        # just spent, which is how a model looks good on paper and not in use
        chosen = self.verdict(0, [6, 9, 7], 10)
        self.assertEqual(chosen["median_index"], 2)
