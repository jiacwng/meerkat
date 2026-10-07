# ranking explanations: the family re-ranker's score split into per-feature pushes

import unittest
from unittest import mock

import numpy as np
import pandas as pd
from rich.console import Console

from core.classifier import (
    FAMILY_NUMERIC_FEATURES,
    _family_feature_matrix,
    fit_family_reranker,
)
from core.features import CONTRIBUTION_PREFIX
from meerkat import cli
from tests.fixtures import HAS_BUNDLE, SHIPPED_BUNDLE, triage_client


def _families() -> pd.DataFrame:
    rng = np.random.default_rng(0)
    rows = []
    for position in range(40):
        positive = position % 4 == 0
        row = {name: float(rng.normal()) for name in FAMILY_NUMERIC_FEATURES}
        row["child_score_max"] += 2.0 * positive
        row["asset_roles"] = ("server",) if position % 2 else ("employee",)
        row["family_positive"] = positive
        rows.append(row)
    return pd.DataFrame(rows)


def _with_pushes(pushes: dict[str, float], roles=()) -> pd.Series:
    row = {CONTRIBUTION_PREFIX + name: value for name, value in pushes.items()}
    row["asset_roles"] = tuple(roles)
    return pd.Series(row)


def _capture(render, *args) -> str:
    with cli.console.capture() as capture:
        render(*args)
    return capture.get()


class ContributionTests(unittest.TestCase):
    def test_the_pushes_and_intercept_rebuild_the_score(self):
        families = _families()
        reranker = fit_family_reranker(families)
        pushes, intercept = reranker.contributions(families)
        logit = intercept + pushes.sum(axis=1).to_numpy()
        np.testing.assert_allclose(
            1.0 / (1.0 + np.exp(-logit)), reranker.predict(families), rtol=1e-9
        )
        self.assertEqual(
            list(pushes.columns),
            list(_family_feature_matrix(families, reranker.roles).columns),
        )

    @unittest.skipUnless(
        HAS_BUNDLE, "needs models/meerkat_bundle.skops, which is stored with Git LFS"
    )
    def test_a_saved_run_stores_pushes_that_rebuild_its_scores(self):
        families = triage_client().run.families
        columns = [c for c in families.columns if c.startswith(CONTRIBUTION_PREFIX)]
        self.assertTrue(columns)
        self.assertTrue(all(families[c].dtype == float for c in columns))
        bundle = cli._load_bundle(SHIPPED_BUNDLE)
        intercept = float(bundle.reranker.model.named_steps["model"].intercept_[0])
        logit = intercept + families[columns].sum(axis=1).to_numpy()
        np.testing.assert_allclose(
            1.0 / (1.0 + np.exp(-logit)), families["ranking_score"], rtol=1e-9
        )


class PhraseTests(unittest.TestCase):
    def test_every_family_feature_has_a_phrase(self):
        for name in FAMILY_NUMERIC_FEATURES:
            self.assertIn(name, cli.FAMILY_FEATURE_PHRASES)
        self.assertEqual(cli.feature_phrase("role_server"), "asset role server")

    def test_an_unknown_feature_renders_as_its_name(self):
        family = _with_pushes({"some_new_feature": 1.0})
        self.assertIn("some_new_feature", _capture(cli._render_why, family))


class RenderTests(unittest.TestCase):
    PUSHES = {
        "child_score_max": 3.0,
        "child_score_mean": 1.0,
        "child_score_std": -1.0,
        "detectors_nearby_10m": 2.0,
        "alert_count": -1.0,
        "role_server": 1.0,
        "role_dns_server": 5.0,
    }

    def test_inspect_shows_shares_and_merges_session_evidence(self):
        text = _capture(cli._render_why, _with_pushes(self.PUSHES, roles=("server",)))
        self.assertIn("largest contributions", text)
        self.assertEqual(text.count("session evidence"), 1)
        # 3 + 1 - 1 = 3 of a total 3 + 2 + 1 + 1 = 7
        self.assertRegex(text, r"raises  session evidence +43%")
        self.assertRegex(text, r"lowers  alert count +14%")
        self.assertNotIn("dns_server", text)
        self.assertNotIn("exact", text)
        self.assertNotIn("logit", text)

    def test_the_queue_names_the_largest_raise_that_is_not_session_evidence(self):
        family = _with_pushes(self.PUSHES, roles=("server",))
        self.assertEqual(cli.top_raise(family), "detectors within 10 minutes")
        self.assertEqual(cli.top_raise(_with_pushes({"child_score_max": 2.0})), "")

    def test_the_queue_table_carries_the_column(self):
        family = _with_pushes(self.PUSHES, roles=("server",))
        family = pd.concat([family, pd.Series({
            "handle": "F1", "day": 0, "start": 0.0, "host_label": "web01",
            "detector_source": "wazuh", "title": "t", "rule_id": "1",
            "alert_count": 1, "ranking_score": 0.5, "family_id": "f",
        })])
        with mock.patch.object(cli, "console", Console(width=220)):
            with cli.console.capture() as capture:
                cli.render_queue(pd.DataFrame([family]), {}, "Review queue")
        self.assertIn("detectors within 10 minutes", capture.get())

    def test_a_run_without_pushes_says_to_re_run_triage(self):
        family = pd.Series({"asset_roles": ()})
        self.assertIn("re-run triage", _capture(cli._render_why, family))
        self.assertEqual(cli.top_raise(family), "")


if __name__ == "__main__":
    unittest.main()
