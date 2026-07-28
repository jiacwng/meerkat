# the scoring model: forest, calibration, drift, benchmark folds, retraining

from __future__ import annotations

import tempfile
import unittest
import unittest.mock
import zipfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
from skops import io as sio

from bench import evaluate as bench_eval
from bench.evaluate import (
    _out_of_fold_families,
    _out_of_fold_reranker_scores,
    _queue_metrics,
    build_bundle,
    evaluate_scenarios,
    prepare_sessions,
)
from core import classifier
from core.classifier import FAMILY_NUMERIC_FEATURES
from core.drift import (
    PSI_MAJOR,
    PSI_STABLE,
    UNSEEN_RULE_WARN,
    TrainingProfile,
    _reference,
    build_profile,
    compare_profile,
    population_stability_index,
    unseen_rule_share,
    verdict_for,
)
from core.features import SCHEMA_INDEX_NAMES, SessionFeatureSchema
from core.incidents import (
    assign_bag_priors,
    assign_reviewed,
    entity_for,
    load_incidents,
    load_reviewed_periods,
    unresolved_hosts,
)
from core.inventory import Asset, Inventory
from core.scenario_eval import add_window_ids, refit_forest
from meerkat.cli import _validate_retrain_result, build_parser


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


# The refusals in load_model are the whole reason the format check is a gate
# rather than a dispatch: it used to fall through to pickle.load for anything
# that was not a skops zip, so every downloaded bundle ran whatever it carried.
# Each path below is a different way of arriving with a file that is not a
# bundle this build wrote.


@dataclass
class NotOurType:
    payload: str = "whatever a bundle from elsewhere carries"


class TestBundleGate(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())

    def refuse(self, path: Path) -> str:
        with self.assertRaises(classifier.UntrustedBundleError) as caught:
            classifier.load_model(path)
        return str(caught.exception)

    def test_a_file_that_is_not_a_skops_bundle_is_refused_not_unpickled(self):
        # this is the one that mattered: a pickle used to be loaded, which runs
        # whatever it contains before anything has decided to trust it
        path = self.directory / "model.skops"
        path.write_bytes(b"\x80\x05\x95\x0c\x00\x00\x00\x00\x00\x00\x00")
        message = self.refuse(path)
        self.assertIn("not a skops bundle", message)
        self.assertIn("meerkat retrain", message)

    def test_an_unfetched_lfs_pointer_is_named_as_one(self):
        # the shipped bundle is stored in Git LFS, so a clone without it holds
        # a 130-byte text file where the model should be. "not a skops bundle"
        # is true and useless; the fix is two commands.
        path = self.directory / "meerkat_bundle.skops"
        path.write_bytes(
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
            b"size 15042836\n"
        )
        message = self.refuse(path)
        self.assertIn("unfetched Git LFS pointer", message)
        self.assertIn("git lfs pull", message)

    def test_a_type_outside_the_allowlist_is_refused_and_named(self):
        # skops lists every type needing explicit trust, so the test is what
        # falls outside TRUSTED_TYPES rather than what falls inside it
        path = self.directory / "elsewhere.skops"
        sio.dump(NotOurType(), path)
        self.assertNotIn(
            "tests.test_model.NotOurType", classifier.TRUSTED_TYPES
        )
        message = self.refuse(path)
        self.assertIn("does not trust", message)
        self.assertIn("NotOurType", message)

    def test_a_bundle_without_schema_json_never_reaches_skops(self):
        # every zip passed the magic-number check, so this arrived inside skops
        # and came back as a KeyError on the missing member
        path = self.directory / "empty.skops"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("nothing.txt", "x")
        self.assertIn("not a skops bundle", self.refuse(path))

    def test_a_sidecar_that_is_valid_json_but_not_an_object_is_refused(self):
        # a bundle from elsewhere brings its own sidecar, so it is as untrusted
        # as the bundle. A list reached .get and raised AttributeError.
        path = self.directory / "bundle.skops"
        path.write_bytes(b"PK\x03\x04")
        for body in ("[]", '"x"', "3"):
            classifier.provenance_path(path).write_text(body, encoding="utf-8")
            with self.subTest(body=body):
                with self.assertRaises(classifier.UntrustedBundleError) as caught:
                    classifier.read_provenance(path)
                self.assertIn("not the object", str(caught.exception))

    def test_a_missing_sidecar_reads_as_no_record_rather_than_a_crash(self):
        # the CLI turns this None into the "no provenance" note; a bundle
        # without a sidecar still loads, it just proves nothing about itself
        path = self.directory / "bundle.skops"
        path.write_bytes(b"PK\x03\x04")
        self.assertFalse(classifier.provenance_path(path).exists())
        self.assertIsNone(classifier.read_provenance(path))

    def test_a_written_sidecar_matches_the_file_it_was_written_beside(self):
        model = classifier.fit_model(
            pd.DataFrame({"signal": [0.0, 1.0]}), pd.Series([False, True]),
            n_estimators=2, seed=0,
        )
        path = self.directory / "bundle.skops"
        classifier.save_model(model, path)
        self.assertTrue(classifier.read_provenance(path)["matches_file"])
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertFalse(classifier.read_provenance(path)["matches_file"])


# Drift reports covariate shift and refuses to claim anything about accuracy.
# Two bugs in the first version of the PSI code were found by running it on real
# alerts rather than by reasoning about the formula, so several of these pin the
# exact shapes that broke.


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


class TestUnseenRuleShare(unittest.TestCase):
    # the module calls this the drift that matters most for a ranking built on
    # rule identity, and it costs no stored statistic: the schema already holds
    # every (detector, rule) pair the forest was fitted on
    def schema(self, *pairs: tuple[str, str]) -> SessionFeatureSchema:
        index = pd.MultiIndex.from_tuples(list(pairs), names=SCHEMA_INDEX_NAMES)
        return SessionFeatureSchema(
            rule_counts=pd.Series([10] * len(pairs), index=index, dtype="int64"),
            detectors=("wazuh",),
            roles=(),
        )

    def share(self, schema, sessions: list[tuple]) -> float:
        return unseen_rule_share(schema, pd.Series(sessions, dtype=object))

    def test_every_rule_known_is_no_unseen_share(self):
        schema = self.schema(("wazuh", "5710"), ("wazuh", "31101"))
        share = self.share(schema, [
            ((("wazuh", "5710"), 4),), ((("wazuh", "31101"), 6),),
        ])
        self.assertEqual(share, 0.0)

    def test_a_rule_the_model_never_saw_counts_its_alerts_not_its_sessions(self):
        # one session of 90 alerts on an unknown rule is 90% of the stream, and
        # counting sessions instead would report 50%
        schema = self.schema(("wazuh", "5710"))
        share = self.share(schema, [
            ((("wazuh", "5710"), 10),), ((("wazuh", "unknown"), 90),),
        ])
        self.assertAlmostEqual(share, 0.9)

    def test_the_same_rule_id_under_another_detector_is_unseen(self):
        # the schema is keyed on the pair, so a client whose suricata numbers
        # its rules the way wazuh does gets no rarity signal from them
        schema = self.schema(("wazuh", "5710"))
        share = self.share(schema, [((("suricata", "5710"), 5),)])
        self.assertEqual(share, 1.0)

    def test_a_session_mixing_known_and_unknown_rules_splits_by_alert_count(self):
        schema = self.schema(("wazuh", "5710"))
        share = self.share(
            schema, [((("wazuh", "5710"), 3), (("wazuh", "new"), 1))]
        )
        self.assertAlmostEqual(share, 0.25)

    def test_no_alerts_at_all_is_zero_rather_than_a_division_by_zero(self):
        self.assertEqual(self.share(self.schema(("wazuh", "5710")), []), 0.0)
        self.assertEqual(self.share(self.schema(("wazuh", "5710")), [()]), 0.0)

    def test_the_warning_threshold_sits_where_drift_reports_it(self):
        # `meerkat drift` prints the red note above this share and stays quiet
        # below it, so the constant is the whole contract
        self.assertEqual(UNSEEN_RULE_WARN, 0.20)
        schema = self.schema(("wazuh", "5710"))
        quiet = self.share(schema, [
            ((("wazuh", "5710"), 9), (("wazuh", "new"), 1)),
        ])
        loud = self.share(schema, [
            ((("wazuh", "5710"), 6), (("wazuh", "new"), 4)),
        ])
        self.assertLess(quiet, UNSEEN_RULE_WARN)
        self.assertGreater(loud, UNSEEN_RULE_WARN)


def scenario_data(name: str, day: int):
    start = day * 86400.0
    entity = f"10.0.{day}.1"
    frame = pd.DataFrame({
        "timestamp": [start + 1, start + 2, start + 3, start + 4],
        "entity_id": [entity] * 4,
        "detector_source": ["wazuh"] * 4,
        "rule_id": ["positive", "quiet-a", "quiet-b", "quiet-c"],
        "severity": [12.0, 2.0, 2.0, 2.0],
        "native_technique_ids": ["T1110", "", "", ""],
        "alert_category": ["authentication", "", "", ""],
        "rule_groups": ["auth", "", "", ""],
        "entity_in_inventory": [True] * 4,
        "event_label": ["attack", "", "", ""],
        "attack_window": ["phase", "phase", "", ""],
    })
    asset = Asset(f"host-{name}", (entity,), ("servers",))
    inventory = Inventory(name, {entity: asset}, {asset.hostname: entity})
    windows = [(start, start + 2, "phase")]
    return frame, inventory, windows


class ScenarioEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.frames = {}
        self.inventories = {}
        self.windows = {}
        for day, name in enumerate(("alpha", "beta", "gamma"), start=1):
            frame, inventory, windows = scenario_data(name, day)
            self.frames[name] = frame
            self.inventories[name] = inventory
            self.windows[name] = windows

    def test_prepare_sessions_keeps_scenarios_separate(self):
        # session ids are prefixed with the company, so concatenating seven
        # training tables cannot collide two companies' session 0
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )

        self.assertEqual(set(sessions), {"alpha", "beta", "gamma"})
        self.assertTrue(
            all(table["session_id"].str.startswith(f"{name}#").all()
                for name, table in sessions.items())
        )

    def test_prepare_sessions_uses_timestamps_for_temporal_overlap(self):
        # quiet-a fires inside the attack window with no event_label of its
        # own, so it counts as a temporal overlap and nothing stricter
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )
        quiet = sessions["alpha"].loc[
            sessions["alpha"]["rule_id"].eq("quiet-a")
        ].iloc[0]

        self.assertIn("temporal_overlap_windows", sessions["alpha"])
        self.assertEqual(quiet["labelled_windows"], frozenset())
        self.assertEqual(quiet["temporal_overlap_windows"], frozenset({0}))

    def test_window_id_follows_normalized_phase_at_shared_boundary(self):
        # two attack phases can share an instant, so the alert's own
        # attack_window name breaks the tie at t=10 rather than window order
        frame = pd.DataFrame({
            "timestamp": [10.0],
            "attack_window": ["first"],
        })
        windows = [
            (0.0, 10.0, "first"),
            (10.0, 20.0, "second"),
        ]

        marked = add_window_ids(frame, windows)

        self.assertEqual(int(marked.loc[0, "window_id"]), 0)

    def test_evaluation_uses_unseen_scenarios_and_returns_queue_metrics(self):
        # every company takes a turn as the held-out one, so three folds come
        # back carrying both window counts and the calibration Brier scores
        report = evaluate_scenarios(
            self.frames,
            self.inventories,
            self.windows,
            budgets=(1,),
            n_estimators=5,
            seeds=(0,),
        )

        self.assertEqual(set(report.per_fold["scenario"]), set(self.frames))
        rankers = set(report.per_fold["ranker"])
        self.assertIn("family re-ranker", rankers)
        self.assertEqual(len(report.per_fold), 3 * len(rankers))
        self.assertEqual(set(report.summary["budget"]), {1})
        self.assertEqual(len(report.summary), len(rankers))
        self.assertEqual(len(report.calibration), 3)
        self.assertEqual(len(report.calibration_summary), 1)
        self.assertIn("pooled_calibrated_brier", report.calibration_summary)
        # the floor row is one whole day per item, so per-queue columns are NaN
        ranked = report.per_fold[
            ~report.per_fold["ranker"].str.startswith("floor")
        ]
        self.assertTrue((ranked["daily_duplicate_concentration"] == 0).all())
        self.assertIn("floor: one item per day", rankers)
        self.assertIn("alerts_in_queue", report.per_fold)
        self.assertIn("share_of_day_alerts", report.per_fold)
        self.assertIn("strict_windows", report.per_fold)
        self.assertIn("temporal_overlap_windows", report.per_fold)
        self.assertIn("strict_windows_mean", report.summary)
        self.assertIn("temporal_overlap_windows_mean", report.summary)

    def test_family_calibration_scores_each_scenario_out_of_fold(self):
        # a calibrator fed scores from families its re-ranker trained on
        # learns an overconfident mapping, so alpha is scored by beta+gamma
        rows = []
        for scenario in ("alpha", "beta", "gamma"):
            for positive in (False, True):
                row = {
                    feature: float(positive)
                    for feature in FAMILY_NUMERIC_FEATURES
                }
                row["scenario"] = scenario
                row["asset_roles"] = ("servers",)
                row["family_positive"] = positive
                rows.append(row)
        families = pd.DataFrame(rows)
        fitted_on = []

        class FakeReranker:
            def predict(self, test):
                return np.full(len(test), 0.5)

        def fake_fit(train):
            fitted_on.append(set(train["scenario"]))
            return FakeReranker()

        with patch.object(
            bench_eval,
            "fit_family_reranker",
            side_effect=fake_fit,
        ):
            scored = _out_of_fold_reranker_scores(families)

        self.assertEqual(len(scored), len(families))
        for scenario, training_scenarios in zip(
            ("alpha", "beta", "gamma"),
            fitted_on,
        ):
            self.assertNotIn(scenario, training_scenarios)

    def test_reranker_child_scores_are_out_of_fold(self):
        # the re-ranker has to see the kind of child scores it will meet at
        # inference, so no fold's forest trained on the scenario it scores
        sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )
        fitted_on = []

        def fake_score(fold, n_estimators, seed, pu_c=None):
            fitted_on.append(
                (fold.test_scenario, set(fold.training_scenarios))
            )
            scored = fold.test.copy()
            scored["ranking_score"] = 0.5
            return scored, None, None

        with patch.object(
            bench_eval,
            "score_fold",
            side_effect=fake_score,
        ):
            families = _out_of_fold_families(
                sessions,
                tuple(sessions),
                n_estimators=5,
                seed=0,
            )

        self.assertGreater(len(families), 0)
        for test_scenario, training_scenarios in fitted_on:
            self.assertNotIn(test_scenario, training_scenarios)

    def test_evaluation_queues_family_reranker_scores(self):
        # the queue must rank on the re-ranked family score, so a fake
        # re-ranker returning 0.123 is what reaches daily_queue
        queued_scores = []
        real_daily_queue = bench_eval.daily_queue

        class FakeReranker:
            def predict(self, families):
                return np.full(len(families), 0.123)

        def capture_queue(families, budget):
            queued_scores.append(families["ranking_score"].copy())
            return real_daily_queue(families, budget)

        with (
            patch.object(
                bench_eval,
                "fit_family_reranker",
                return_value=FakeReranker(),
            ),
            patch.object(
                bench_eval,
                "daily_queue",
                side_effect=capture_queue,
            ),
        ):
            evaluate_scenarios(
                self.frames,
                self.inventories,
                self.windows,
                budgets=(1,),
                n_estimators=5,
                seeds=(0,),
            )

        learned = [s for s in queued_scores if s.eq(0.123).all()]
        self.assertEqual(len(learned), len(self.frames))

    def test_queue_reports_strict_and_temporal_window_coverage_together(self):
        # the headline 58 of 60 counts strictly labelled windows, so the
        # looser overlap count is reported beside it and never in its place
        families = pd.DataFrame([{
            "labelled_windows": frozenset({0}),
            "temporal_overlap_windows": frozenset({0, 1}),
            "event_categories": frozenset({"attack"}),
            "day": 0,
            "entity_id": "10.0.0.1",
            "detector_source": "wazuh",
            "rule_id": "100",
            "family_positive": True,
            "labelled_alert_count": 1,
            "alert_count": 2,
            "n_child_sessions": 1,
        }])

        metrics = _queue_metrics(
            families,
            families,
            total_labelled_alerts=1,
            budget=1,
        )

        self.assertIn("strict_windows", metrics)
        self.assertIn("temporal_overlap_windows", metrics)
        self.assertEqual(metrics["strict_windows"], 1)
        self.assertEqual(metrics["temporal_overlap_windows"], 2)


class ClientRetrainingTests(unittest.TestCase):
    def setUp(self):
        self.frames, self.inventories, self.windows = {}, {}, {}
        for day, name in enumerate(("alpha", "beta", "gamma"), start=1):
            frame, inventory, windows = scenario_data(name, day)
            self.frames[name] = frame
            self.inventories[name] = inventory
            self.windows[name] = windows
        self.sessions = prepare_sessions(
            self.frames, self.inventories, self.windows, gap_s=600.0
        )
        self.bundle = build_bundle(self.sessions, n_estimators=10, seed=0)
        self.client = self.sessions["alpha"]

    def _prior(self, positives: int) -> pd.Series:
        prior = pd.Series(0.0, index=self.client.index)
        prior.iloc[:positives] = 0.5
        return prior

    def test_a_thin_label_set_is_refused_rather_than_fitted(self):
        # two bagged sessions would still fit a forest that looks trained, so
        # the floor of ten is checked before anything is fitted
        with self.assertRaises(ValueError) as caught:
            refit_forest(
                self.bundle, self.client, self._prior(2),
                n_estimators=10, min_positives=10,
            )
        self.assertIn("at least 10", str(caught.exception))

    def test_the_reranker_coefficients_survive_a_retrain(self):
        # those coefficients came from out-of-fold folds across eight
        # environments, which one client cannot reproduce, so they are kept
        retrained = refit_forest(
            self.bundle, self.client, self._prior(3),
            n_estimators=10, min_positives=1,
        )
        np.testing.assert_array_equal(
            self.bundle.reranker.model.named_steps["model"].coef_,
            retrained.reranker.model.named_steps["model"].coef_,
        )

    def test_the_calibrator_is_carried_over_untouched(self):
        # the calibrator is defined across environments too, so the client
        # keeps the same object and its confidence stays comparable
        retrained = refit_forest(
            self.bundle, self.client, self._prior(3),
            n_estimators=10, min_positives=1,
        )
        self.assertIs(retrained.calibrator, self.bundle.calibrator)

    def test_the_forest_is_replaced_not_reused(self):
        # the point of a retrain is a forest fitted on the client's own
        # alerts, so the shipped one is dropped rather than fitted further
        retrained = refit_forest(
            self.bundle, self.client, self._prior(3),
            n_estimators=10, min_positives=1,
        )
        self.assertIsNot(retrained.forest, self.bundle.forest)

    def test_the_scaler_is_refitted_on_the_client_families(self):
        # a client forest scores lower and tighter, so the AIT means in the
        # scaler would put every family the same distance from centre
        retrained = refit_forest(
            self.bundle, self.client, self._prior(3),
            n_estimators=10, min_positives=1,
        )
        before = self.bundle.reranker.model.named_steps["scale"].mean_
        after = retrained.reranker.model.named_steps["scale"].mean_
        self.assertFalse(np.array_equal(before, after))

    def test_pu_training_reaches_the_bundle(self):
        # pu_c has to reach the fit rather than be accepted and dropped. This
        # used to compare the two forests' predictions, which is not a property
        # the code guarantees: with ten trees on this fixture they can agree,
        # and whether they do changed between scikit-learn versions.
        with patch.object(
            bench_eval, "fit_model_pu", wraps=bench_eval.fit_model_pu
        ) as pu_fit:
            build_bundle(self.sessions, n_estimators=10, seed=0, pu_c=0.5)
        self.assertTrue(pu_fit.called)
        self.assertEqual(pu_fit.call_args.kwargs["c"], 0.5)

    def test_without_pu_c_the_supervised_fit_is_used(self):
        with patch.object(
            bench_eval, "fit_model_pu", wraps=bench_eval.fit_model_pu
        ) as pu_fit:
            build_bundle(self.sessions, n_estimators=10, seed=0)
        self.assertFalse(pu_fit.called)


# The client retraining path: soft labels from bags, a rescaled re-ranker and a
# forest swapped into an otherwise frozen bundle.


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
        # row, so 4.0 would give the negative copy a weight of -3.0. Clipping to
        # 1.0 is the whole behaviour, so 4.0 has to score exactly like 1.0.
        X = features(4, np.array([0.0, 0.0, 1.0, 1.0]))
        over = classifier.fit_soft_labels(
            X, np.array([0.0, 0.0, 4.0, 4.0]), n_estimators=10, seed=0
        )
        at_one = classifier.fit_soft_labels(
            X, np.array([0.0, 0.0, 1.0, 1.0]), n_estimators=10, seed=0
        )
        np.testing.assert_allclose(
            classifier.predict_scores(over, X),
            classifier.predict_scores(at_one, X),
        )

    def test_an_unreviewed_session_is_dropped_rather_than_trained_as_clean(self):
        # sessions 0-1 reviewed and clean, 2-3 never looked at, 4-5 in a bag
        X = features(6, np.array([0.0, 0.0, 9.0, 9.0, 1.0, 1.0]))
        prior = np.array([0.0, 0.0, 0.0, 0.0, 0.5, 0.5])
        reviewed = np.array([True, True, False, False, True, True])

        model = classifier.fit_soft_labels(
            X, prior, reviewed, n_estimators=20, seed=0
        )

        # the unreviewed rows never entered training, so the forest cannot have
        # learned their signal value of 9.0 as a negative. Training them as clean
        # drops them to 0.0, below the reviewed negatives; dropping them leaves
        # them above, because 9.0 sits on the bagged side of the only split.
        self.assertEqual(model.n_features_in_, X.shape[1])
        seen = classifier.predict_scores(model, X)
        self.assertGreater(seen[2:4].mean(), seen[:2].mean())
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
            "--environment", "acme",
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
        ), unittest.mock.patch(
            # rescale_bundle is imported inside compare_models now, so the patch
            # targets the module it is read from at call time
            "core.scenario_eval.rescale_bundle", side_effect=lambda b, s: b,
        ):
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


# incident records to training labels


def inventory() -> Inventory:
    web = Asset("web-01", ("10.0.0.1",), ("server",))
    mail = Asset("mail-01", ("10.0.0.2",), ("mail_server",))
    return Inventory(
        company="acme",
        assets_by_ip={"10.0.0.1": web, "10.0.0.2": mail},
        ip_by_hostname={"web-01": "10.0.0.1", "mail-01": "10.0.0.2"},
    )


def write(rows: str) -> Path:
    path = Path(tempfile.mkdtemp()) / "incidents.csv"
    path.write_text(rows, encoding="utf-8")
    return path


def sessions(*spans: tuple[str, float, float]) -> pd.DataFrame:
    return pd.DataFrame(
        [{"entity_id": e, "start": s, "end": t} for e, s, t in spans]
    )


class TestLoadIncidents(unittest.TestCase):
    def test_only_confirmed_ocsf_verdicts_are_kept(self):
        # a SOC exports the whole OCSF verdict enum, and only the four saying
        # an attack happened can seed a bag; test is a purple team run
        path = write(
            "start,end,host,verdict\n"
            "0,10,web-01,Unknown\n"
            "0,10,web-01,False Positive\n"
            "0,10,web-01,True Positive\n"
            "0,10,web-01,Disregard\n"
            "0,10,web-01,Suspicious\n"
            "0,10,web-01,Benign\n"
            "0,10,web-01,Test\n"
            "0,10,web-01,Insufficient Data\n"
            "0,10,web-01,Security Risk\n"
            "0,10,web-01,Managed Externally\n"
            "0,10,web-01,Duplicate\n"
            "0,10,web-01,Other\n"
            "0,10,web-01,escalate\n"
            "0,10,web-01,malicious\n"
        )
        self.assertEqual(
            list(load_incidents(path)["verdict"]),
            ["true_positive", "test", "security_risk", "malicious"],
        )

    def test_verdict_case_and_spacing_do_not_matter(self):
        # ticketing systems export "True Positive" with their own casing and
        # padding, and matching has to survive that before a row is dropped
        path = write("start,end,host,verdict\n0,10,web-01, True_Positive \n")
        self.assertEqual(len(load_incidents(path)), 1)

    def test_missing_column_names_what_is_missing(self):
        # a client writes this CSV by hand, so the failure names the column
        # rather than surfacing as a KeyError deep inside the retrain
        path = write("start,end,host\n0,10,web-01\n")
        with self.assertRaises(ValueError) as caught:
            load_incidents(path)
        self.assertIn("verdict", str(caught.exception))

    def test_empty_file_is_rejected(self):
        # a header-only export would otherwise reach training and fail there
        # as "no session falls inside an incident"
        with self.assertRaises(ValueError):
            load_incidents(write("start,end,host,verdict\n"))

    def test_an_all_negative_file_says_so_rather_than_returning_nothing(self):
        # a client exporting only closed false positives is told their 2 rows
        # were read, since an empty result looks like an unreadable file
        path = write(
            "start,end,host,verdict\n"
            "0,10,web-01,False Positive\n"
            "0,10,web-01,Benign\n"
        )
        with self.assertRaises(ValueError) as caught:
            load_incidents(path)
        self.assertIn("2 rows", str(caught.exception))

    def test_an_iso_timestamp_is_refused_by_the_float_conversion(self):
        # PINS CURRENT BEHAVIOUR, WHICH IS NOT GOOD BEHAVIOUR. start and end are
        # epoch seconds and a client pasting the format their ticketing system
        # shows gets pandas' own message, which names the value and neither the
        # column, the row nor the file. Every other refusal in this loader says
        # which column and how many rows. The CLI wraps it as "the incident
        # records could not be read", so it is not a traceback, but the reader
        # is left to work out that "start" was the column and epoch seconds the
        # unit. This test exists so a fix is a visible change rather than a
        # silent one.
        path = write(
            "start,end,host,verdict\n"
            "2026-01-21T00:00:00,2026-01-21T01:00:00,web-01,true_positive\n"
        )
        with self.assertRaises(ValueError) as caught:
            load_incidents(path)
        message = str(caught.exception)
        self.assertIn("could not convert string to float", message)
        self.assertIn("2026-01-21T00:00:00", message)
        # what a named error would carry, and does not
        self.assertNotIn("start", message)
        self.assertNotIn("epoch", message)

    def test_a_reviewed_period_file_refuses_the_same_way(self):
        # load_reviewed_periods casts the same two columns, so --reviewed-periods
        # written in the same format fails in the same undiagnosed way
        path = write("start,end\n2026-01-21T00:00:00,2026-01-21T01:00:00\n")
        with self.assertRaises(ValueError) as caught:
            load_reviewed_periods(path)
        self.assertIn("could not convert string to float", str(caught.exception))


class TestHostResolution(unittest.TestCase):
    def test_hostname_and_address_both_resolve(self):
        # a ticket names a host however the analyst typed it and sessions are
        # keyed on the address, so both spellings reach 10.0.0.1
        self.assertEqual(entity_for("web-01", inventory()), "10.0.0.1")
        self.assertEqual(entity_for("10.0.0.2", inventory()), "10.0.0.2")

    def test_unknown_host_is_reported_not_guessed(self):
        # a ticket for a machine outside the inventory contributes no bag, so
        # retrain lists it up front rather than losing the ticket silently
        self.assertEqual(entity_for("printer", inventory()), "")
        incidents = pd.DataFrame([{"host": "printer"}, {"host": "web-01"}])
        self.assertEqual(unresolved_hosts(incidents, inventory()), ["printer"])


class TestReviewedPeriods(unittest.TestCase):
    def test_no_period_file_preserves_the_old_all_reviewed_behaviour(self):
        # --reviewed-periods is optional, and without it every session outside
        # a bag counts as reviewed and trains as a negative
        reviewed = assign_reviewed(
            sessions(("10.0.0.1", 10.0, 20.0), ("10.0.0.2", 30.0, 40.0)),
            None,
        )
        self.assertEqual(list(reviewed), [True, True])

    def test_only_sessions_fully_inside_a_reviewed_period_are_marked(self):
        # a burst half outside the reviewed hours was only half looked at, so
        # both ends have to be contained before it can be a negative
        periods = pd.DataFrame([{"start": 10.0, "end": 30.0}])
        table = sessions(
            ("10.0.0.1", 10.0, 20.0),
            ("10.0.0.1", 5.0, 15.0),
            ("10.0.0.1", 31.0, 40.0),
        )
        self.assertEqual(
            list(assign_reviewed(table, periods)),
            [True, False, False],
        )

    def test_reviewed_period_csv_loads_start_and_end(self):
        # the period file needs two columns and they arrive as text, so both
        # are parsed to float before any session comparison
        periods = load_reviewed_periods(write("start,end\n10,20\n"))
        self.assertEqual(periods.to_dict("records"), [{"start": 10.0, "end": 20.0}])


class TestBagPriors(unittest.TestCase):
    def test_a_session_outside_every_incident_is_a_clean_negative(self):
        # a prior of 0.0 is what makes a session a training negative, so a
        # burst nowhere near a ticket must pick up no weight at all
        table = sessions(("10.0.0.1", 100.0, 200.0))
        incidents = pd.DataFrame(
            [{"start": 900.0, "end": 1000.0, "host": "web-01"}]
        )
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [0.0])

    def test_prior_is_shared_across_the_bag(self):
        # k=1 split over four sessions stops one vague all-day ticket from
        # carrying four times the weight of a precise one
        table = sessions(
            ("10.0.0.1", 10.0, 20.0),
            ("10.0.0.1", 30.0, 40.0),
            ("10.0.0.1", 50.0, 60.0),
            ("10.0.0.1", 70.0, 80.0),
        )
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        prior = assign_bag_priors(table, incidents, inventory())
        # k=1 over four sessions, and the ticket's total weight stays at 1.0
        self.assertTrue(all(abs(value - 0.25) < 1e-9 for value in prior))
        self.assertAlmostEqual(prior.sum(), 1.0)

    def test_prior_never_exceeds_one_in_a_small_bag(self):
        # a one-session bag puts the whole ticket on that burst, and the clip
        # holds it at 1.0 where fit_soft_labels expects a probability
        table = sessions(("10.0.0.1", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [1.0])

    def test_an_incident_only_claims_its_own_host(self):
        # an incident is a time range plus a host, so a second machine busy in
        # the same hour stays a clean negative
        table = sessions(("10.0.0.1", 10.0, 20.0), ("10.0.0.2", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        prior = assign_bag_priors(table, incidents, inventory())
        self.assertGreater(prior.iloc[0], 0.0)
        self.assertEqual(prior.iloc[1], 0.0)

    def test_a_session_overlapping_the_edge_still_joins(self):
        # a burst rarely starts and ends inside the reported window
        table = sessions(("10.0.0.1", 90.0, 150.0))
        incidents = pd.DataFrame([{"start": 100.0, "end": 200.0, "host": "web-01"}])
        self.assertGreater(assign_bag_priors(table, incidents, inventory()).iloc[0], 0.0)

    def test_an_unresolved_host_contributes_no_bag(self):
        # with no address for printer there is nothing to compare a session
        # against, so the ticket is skipped rather than matched everywhere
        table = sessions(("10.0.0.1", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "printer"}])
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [0.0])

    def test_overlapping_incidents_do_not_depend_on_csv_order(self):
        # two tickets can cover one burst, and keeping the larger share both
        # ways leaves the labels identical when the export order changes
        table = sessions(
            ("10.0.0.1", 0.0, 5.0),
            ("10.0.0.1", 10.0, 15.0),
            ("10.0.0.1", 20.0, 25.0),
            ("10.0.0.1", 30.0, 35.0),
        )
        incidents = pd.DataFrame([
            {"start": 0.0, "end": 15.0, "host": "web-01"},
            {"start": 10.0, "end": 35.0, "host": "web-01"},
        ])

        forward = assign_bag_priors(table, incidents, inventory(), numerator=1.0)
        reverse = assign_bag_priors(
            table, incidents.iloc[::-1].reset_index(drop=True), inventory(),
            numerator=1.0,
        )

        expected = [0.5, 0.5, 1 / 3, 1 / 3]
        self.assertEqual(list(forward), expected)
        self.assertEqual(list(reverse), expected)


if __name__ == "__main__":
    unittest.main()
