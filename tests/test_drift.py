# Drift reports covariate shift and refuses to claim anything about accuracy.
# Two bugs in the first version of the PSI code were found by running it on real
# alerts rather than by reasoning about the formula, so several of these pin the
# exact shapes that broke.

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from core.drift import (
    PSI_MAJOR,
    PSI_STABLE,
    TrainingProfile,
    _reference,
    build_profile,
    compare_profile,
    population_stability_index,
    verdict_for,
)


def psi(training: np.ndarray, current: np.ndarray) -> float:
    edges, expected = _reference(training)
    return population_stability_index(edges, expected, current)


class TestPSI(unittest.TestCase):
    def test_a_distribution_against_itself_is_zero(self):
        values = np.random.default_rng(0).normal(size=2000)
        self.assertAlmostEqual(psi(values, values), 0.0, places=9)

    def test_psi_is_scale_invariant_in_sample_size(self):
        # a client scoring a tenth of the alerts has not drifted, so PSI must
        # compare shares rather than counts
        training = np.array([0.0] * 930 + [1.0] * 70)
        tenth = np.array([0.0] * 93 + [1.0] * 7)
        self.assertLess(psi(training, tenth), PSI_STABLE)

    def test_a_binary_feature_that_has_not_moved_reads_stable(self):
        # the first version stored decile EDGES only and assumed 10% per bin. A
        # binary feature's nine deciles collapse to one cut, and the data was never
        # spread evenly across the bins that implies: has_technique scored PSI 3.583
        # on AIT while nothing about it had changed.
        training = np.array([0.0] * 930 + [1.0] * 70)
        self.assertLess(psi(training, training), PSI_STABLE)

    def test_a_binary_feature_that_really_moved_reads_major(self):
        # and the fix must not buy stability by making everything stable. numpy's
        # left-closed bins put every zero into the upper bin, so an unmoved feature
        # and a real fifty-fifty shift BOTH scored 0.
        training = np.array([0.0] * 930 + [1.0] * 70)
        moved = np.array([0.0] * 500 + [1.0] * 500)
        self.assertGreater(psi(training, moved), PSI_MAJOR)

    def test_a_feature_that_collapsed_to_one_value_is_flagged(self):
        training = np.array([0.0] * 930 + [1.0] * 70)
        self.assertGreater(psi(training, np.zeros(1000)), PSI_MAJOR)

    def test_an_empty_bin_does_not_produce_infinity(self):
        # the log term blows up on a zero share, so both sides are floored
        training = np.concatenate([np.zeros(500), np.ones(500)])
        self.assertTrue(np.isfinite(psi(training, np.full(500, 5.0))))

    def test_no_reference_and_no_data_are_both_zero(self):
        self.assertEqual(population_stability_index((), (), np.ones(10)), 0.0)
        self.assertEqual(population_stability_index((1.0,), (0.5, 0.5), np.array([])), 0.0)

    def test_the_thresholds_are_the_published_credit_risk_ones(self):
        self.assertEqual((PSI_STABLE, PSI_MAJOR), (0.10, 0.25))
        self.assertEqual(verdict_for(0.05), "stable")
        self.assertEqual(verdict_for(0.15), "moderate")
        self.assertEqual(verdict_for(0.40), "major")


def matrix(n: int, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "log_size": rng.normal(2.0, 0.5, n),
        "in_inventory": np.ones(n),
        "detector_wazuh": rng.integers(0, 2, n).astype(float),
        "role_server": np.ones(n),
    })


class TestProfile(unittest.TestCase):
    def test_roles_are_left_out_of_the_profile(self):
        # roles describe the client's inventory rather than their alert stream, and
        # `meerkat check` already reports role coverage directly
        profile = build_profile(matrix(500), np.zeros(500))
        self.assertIn("log_size", profile.feature_bins)
        self.assertNotIn("role_server", profile.feature_bins)

    def test_the_profile_records_size_and_detector_mix(self):
        X = matrix(400)
        profile = build_profile(X, np.zeros(400))
        self.assertEqual(profile.n_sessions, 400)
        self.assertAlmostEqual(profile.inventory_coverage, 1.0)
        self.assertIn("wazuh", profile.detector_mix)

    def test_the_same_data_shows_no_drift_against_its_own_profile(self):
        X = matrix(800, seed=1)
        drifts = compare_profile(build_profile(X, np.zeros(800)), X)
        self.assertTrue(drifts)
        for d in drifts:
            self.assertEqual(d.verdict, "stable", d.name)

    def test_shifted_data_shows_drift(self):
        X = matrix(800, seed=1)
        moved = X.copy()
        moved["log_size"] = moved["log_size"] + 4.0
        drifts = compare_profile(build_profile(X, np.zeros(800)), moved)
        worst = drifts[0]
        self.assertEqual(worst.name, "log_size")
        self.assertEqual(worst.verdict, "major")

    def test_a_feature_the_client_does_not_have_is_skipped(self):
        # a bundle profiled on three detectors scoring a client with two must not
        # invent a comparison for the missing column
        X = matrix(300)
        profile = build_profile(X, np.zeros(300))
        thinner = X.drop(columns=["detector_wazuh"])
        names = {d.name for d in compare_profile(profile, thinner)}
        self.assertNotIn("detector_wazuh", names)
        self.assertIn("log_size", names)

    def test_an_empty_profile_compares_to_nothing_rather_than_crashing(self):
        self.assertEqual(compare_profile(TrainingProfile(), matrix(50)), [])


if __name__ == "__main__":
    unittest.main()
