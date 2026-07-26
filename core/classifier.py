"""Train the session ranker, family re-ranker and evidence calibrator.

The forest scores sessions. The family re-ranker combines child scores and
family context, and the calibrator turns that score into a display probability.

Public API:
    fit_model(X, session_positive)            -> fitted forest
    predict_scores(model, X)                  -> raw ranking score per session
    fit_family_reranker(families)             -> FamilyReranker
    fit_calibrator(family_scores, positive)   -> EvidenceCalibrator
    explain_session(model, feature_row)       -> active important features
    save_model(model, path) / load_model(path)
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from skops import io as sio

from core.features import SCHEMA_INDEX_NAMES

FAMILY_NUMERIC_FEATURES = (
    "child_score_max",
    "child_score_mean",
    "child_score_std",
    "n_child_sessions",
    "family_span_s",
    "alert_count",
    "detectors_on_entity",
    "groups_on_entity",
    "log_alerts_on_entity",
    "detectors_nearby_10m",
    "alert_category_count",
    "technique_count",
    "rule_group_count",
)


@dataclass
class EvidenceCalibrator:
    model: LogisticRegression   # Platt scaling, one variable

    def predict(self, ranking_scores: np.ndarray) -> np.ndarray:
        scores = np.asarray(ranking_scores, dtype=float).reshape(-1, 1)
        return self.model.predict_proba(scores)[:, 1]


@dataclass
class FamilyReranker:
    model: Pipeline
    roles: tuple[str, ...]

    def predict(self, families: pd.DataFrame) -> np.ndarray:
        X = _family_feature_matrix(families, self.roles)
        return self.model.predict_proba(X)[:, 1]


def _family_feature_matrix(
    families: pd.DataFrame,
    roles: tuple[str, ...],
) -> pd.DataFrame:
    X = families[list(FAMILY_NUMERIC_FEATURES)].astype(float).copy()
    for role in roles:
        X[f"role_{role}"] = families["asset_roles"].map(
            lambda asset_roles: float(role in asset_roles)
        )
    return X


def fit_family_reranker(families: pd.DataFrame) -> FamilyReranker:
    roles = tuple(sorted({
        role
        for asset_roles in families["asset_roles"]
        for role in asset_roles
    }))
    X = _family_feature_matrix(families, roles)
    model = Pipeline([
        ("scale", StandardScaler()),
        (
            "model",
            LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
            ),
        ),
    ])
    model.fit(X, families["family_positive"])
    return FamilyReranker(model=model, roles=roles)


# The re-ranker's scaler holds the mean and spread of every feature as they were
# on the training environments. A client forest scores differently, and a soft
# label one scores lower and tighter, so those constants no longer describe the
# numbers arriving. Refit the scaler on the client's own families and keep the
# coefficients, which need out-of-fold folds across environments that a client
# does not have.
def rescale_reranker(reranker: FamilyReranker, families: pd.DataFrame) -> FamilyReranker:
    X = _family_feature_matrix(families, reranker.roles)
    fitted = clone(reranker.model)
    fitted.named_steps["scale"].fit(X)
    fitted.named_steps["model"].coef_ = reranker.model.named_steps["model"].coef_.copy()
    fitted.named_steps["model"].intercept_ = (
        reranker.model.named_steps["model"].intercept_.copy()
    )
    fitted.named_steps["model"].classes_ = (
        reranker.model.named_steps["model"].classes_.copy()
    )
    fitted.named_steps["model"].n_features_in_ = X.shape[1]
    return FamilyReranker(model=fitted, roles=reranker.roles)


def fit_model(
    X: pd.DataFrame,
    session_positive: pd.Series,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        # 1 session in 44 is positive; one in nine is the family rate. Dropping
        # this was measured and loses coverage once labels are incomplete.
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, session_positive)
    return model


def predict_scores(
    model: RandomForestClassifier,
    X: pd.DataFrame,
) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


# Training from bag labels. A session inside an incident carries a share of one
# expected attack rather than a verdict, so it enters twice, weighted both ways.
# Nothing is asserted positive, because which burst was the attack is unknown.
def fit_soft_labels(
    X: pd.DataFrame,
    prior: np.ndarray,
    reviewed: np.ndarray | None = None,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    prior = np.clip(np.asarray(prior, dtype=float), 0.0, 1.0)
    in_bag = prior > 0
    if not in_bag.any():
        raise ValueError("no session falls inside an incident")
    # a session nobody reviewed is not a negative, it is unlabelled, and training it
    # as clean teaches the forest that undetected attacks are normal. With no
    # reviewed-period file every session counts as reviewed and this drops out.
    negative = ~in_bag
    if reviewed is not None:
        negative = negative & np.asarray(reviewed, dtype=bool)
        if (~in_bag).any() and not negative.any():
            raise ValueError(
                "the reviewed periods exclude every session outside an incident, "
                "so there is nothing left to learn a negative from"
            )
    X_stacked = pd.concat([X[negative], X[in_bag], X[in_bag]], axis=0)
    y = np.concatenate([
        np.zeros(negative.sum()), np.ones(in_bag.sum()), np.zeros(in_bag.sum()),
    ])
    weight = np.concatenate([
        np.ones(negative.sum()), prior[in_bag], 1.0 - prior[in_bag],
    ])
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_stacked, y, sample_weight=weight)
    return model


# Elkan-Noto, two-step weighted form. Real attacks that nobody wrote down sit in
# the unlabelled pool, so calling that pool negative teaches the forest they are
# normal. Each unlabelled session enters twice instead, split between the classes
# by how likely it is to be one. c is P(labelled | positive).
def fit_model_pu(
    X: pd.DataFrame,
    labelled_positive: pd.Series,
    c: float,
    n_estimators: int = 300,
    seed: int = 0,
) -> RandomForestClassifier:
    if not 0.0 < c <= 1.0:
        raise ValueError(f"c must be in (0, 1], got {c}")
    labelled = np.asarray(labelled_positive, dtype=bool)
    if c == 1.0 or labelled.all() or not labelled.any():
        return fit_model(X, labelled_positive, n_estimators, seed)

    # scores must be out-of-bag: in-sample the forest has memorised these rows,
    # nearly every unlabelled one scores 0 and the correction never fires
    stage_one = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
        oob_score=True,
        bootstrap=True,
    )
    stage_one.fit(X, labelled)
    scores = stage_one.oob_decision_function_[:, 1]
    # a row that never sat out of a bag has no oob estimate
    missing = np.isnan(scores)
    if missing.any():
        scores[missing] = predict_scores(stage_one, X[missing])

    # step two: for an unlabelled session, the odds it is a missed positive
    scores = np.clip(scores, 1e-6, 1 - 1e-6)
    weight = ((1.0 - c) / c) * (scores / (1.0 - scores))
    weight = np.clip(weight, 0.0, 1.0)

    unlabelled = ~labelled
    X_stacked = pd.concat([X[labelled], X[unlabelled], X[unlabelled]], axis=0)
    y_stacked = np.concatenate([
        np.ones(labelled.sum()),
        np.ones(unlabelled.sum()),
        np.zeros(unlabelled.sum()),
    ])
    sample_weight = np.concatenate([
        np.ones(labelled.sum()),
        weight[unlabelled],
        1.0 - weight[unlabelled],
    ])

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_stacked, y_stacked, sample_weight=sample_weight)
    return model


def fit_calibrator(
    family_scores: np.ndarray,
    family_positive: np.ndarray,
) -> EvidenceCalibrator:
    # the scores must come from folds the forest never trained on, otherwise the
    # calibrator learns an overconfident mapping
    scores = np.asarray(family_scores, dtype=float).reshape(-1, 1)
    target = np.asarray(family_positive, dtype=int)
    model = LogisticRegression(max_iter=1000).fit(scores, target)
    return EvidenceCalibrator(model)


def explain_session(
    model: RandomForestClassifier,
    feature_row: pd.Series,
    top: int = 3,
) -> list[tuple[str, float, float]]:
    # these are model-wide importances, not a reason for this one session
    active = []
    for position, name in enumerate(model.feature_names_in_):
        value = feature_row[name]
        if value != 0:
            active.append(
                (name, float(value), float(model.feature_importances_[position]))
            )
    active.sort(key=lambda item: item[2], reverse=True)
    return active[:top]


# skops rebuilds nothing outside this list, so an edited bundle cannot smuggle in
# a type that runs on load
TRUSTED_TYPES = (
    "core.classifier.EvidenceCalibrator",
    "core.classifier.FamilyReranker",
    "core.drift.TrainingProfile",
    "core.features.SessionFeatureSchema",
    "core.scenario_eval.TriageBundle",
    "collections.OrderedDict",
    "numpy.dtype",
    "sklearn.ensemble._forest.RandomForestClassifier",
    "sklearn.linear_model._logistic.LogisticRegression",
    "sklearn.pipeline.Pipeline",
    "sklearn.preprocessing._data.StandardScaler",
    "sklearn.tree._classes.DecisionTreeClassifier",
    "sklearn.tree._tree.Tree",
)

SKOPS_SUFFIX = ".skops"


# skops cannot reduce a pandas Series, so flatten schema.rule_counts here rather
# than change SessionFeatureSchema and disturb the feature code
def _to_wire(model: object) -> object:
    schema = getattr(model, "schema", None)
    counts = getattr(schema, "rule_counts", None)
    if not isinstance(counts, pd.Series):
        return model
    # skops cannot reduce a pandas Series and JSON cannot key on a tuple, so the
    # (detector, rule) index travels beside the values as parallel lists
    wire = {"index": [list(key) for key in counts.index], "values": counts.tolist()}
    return replace(model, schema=replace(schema, rule_counts=wire))


def _from_wire(model: object) -> object:
    schema = getattr(model, "schema", None)
    wire = getattr(schema, "rule_counts", None)
    if not isinstance(wire, dict):
        return model
    index = pd.MultiIndex.from_tuples(
        [tuple(key) for key in wire["index"]], names=SCHEMA_INDEX_NAMES
    )
    counts = pd.Series(wire["values"], index=index, dtype="int64", name="size")
    return replace(model, schema=replace(schema, rule_counts=counts))


def save_model(model: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sio.dump(_to_wire(model), path)
    _write_provenance(model, path)


def load_model(path: Path) -> object:
    # THE FORMAT CHECK IS A GATE, NOT A DISPATCH. This used to fall through to
    # pickle.load for anything that was not a skops zip, which handed every
    # downloaded bundle arbitrary code execution and made the allowlist below
    # decorative. A file that is not a skops bundle is refused outright.
    if not _is_skops(path):
        with path.open("rb") as file:
            head = file.read(64)
        if head.startswith(b"version https://git-lfs"):
            raise UntrustedBundleError(
                f"{path.name} is an unfetched Git LFS pointer, not a model. "
                "Run `git lfs install && git lfs pull`."
            )
        raise UntrustedBundleError(
            f"{path.name} is not a skops bundle. Loading it would mean unpickling "
            "a file this build cannot verify, which runs whatever it contains. "
            "Retrain with `meerkat train`, or fetch a bundle written by this "
            "version of Meerkat."
        )
    # skops lists every type needing explicit trust, ours included, so the
    # test is what falls outside the allowlist
    unexpected = set(sio.get_untrusted_types(file=path)) - set(TRUSTED_TYPES)
    if unexpected:
        raise UntrustedBundleError(
            f"{path.name} contains types this build does not trust: "
            f"{', '.join(sorted(unexpected))}. It was not written by "
            f"`meerkat train`; refusing to load it."
        )
    return _from_wire(sio.load(path, trusted=list(TRUSTED_TYPES)))


class UntrustedBundleError(Exception):
    pass


def _is_skops(path: Path) -> bool:
    # skops writes a zip; a pickle never starts with the zip magic
    with path.open("rb") as file:
        return file.read(4) == b"PK\x03\x04"


def provenance_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".json")


def _write_provenance(model: object, path: Path) -> None:
    import sklearn

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    record = {
        "sha256": digest,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "written_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "training_scenarios": list(getattr(model, "training_scenarios", ()) or ()),
        "n_estimators": getattr(model, "n_estimators", None),
        "seed": getattr(model, "seed", None),
        "roles": list(getattr(getattr(model, "schema", None), "roles", ()) or ()),
    }
    provenance_path(path).write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )


# the hash only proves the file is unchanged since it was written; it does not make
# an untrusted bundle safe, since the sidecar could be rewritten too
def read_provenance(path: Path) -> dict | None:
    sidecar = provenance_path(path)
    if not sidecar.exists():
        return None
    record = json.loads(sidecar.read_text(encoding="utf-8"))
    record["matches_file"] = (
        record.get("sha256") == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    return record
