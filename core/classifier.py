# The models: a random forest that scores sessions, a logistic re-ranker that
# scores families, and a calibrator that turns that score into a probability. Also
# saves a model bundle and refuses to load one that is not ours.

from __future__ import annotations

import hashlib
import json
import platform
import zipfile
from dataclasses import dataclass, is_dataclass, replace
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

    def contributions(self, families: pd.DataFrame) -> tuple[pd.DataFrame, float]:
        X = _family_feature_matrix(families, self.roles)
        scaler = self.model.named_steps["scale"]
        logistic = self.model.named_steps["model"]
        standardized = (X.to_numpy(dtype=float) - scaler.mean_) / scaler.scale_
        pushes = pd.DataFrame(
            standardized * logistic.coef_[0], index=families.index, columns=X.columns
        )
        return pushes, float(logistic.intercept_[0])


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
        ("model", LogisticRegression(class_weight="balanced", max_iter=1000)),
    ])
    model.fit(X, families["family_positive"])
    return FamilyReranker(model=model, roles=roles)


# A client forest scores on another scale than the one the re-ranker's scaler was
# fitted on. Refit the scaler on the client's families and keep the coefficients,
# which need out-of-fold folds across environments that a client does not have.
def rescale_reranker(reranker: FamilyReranker, families: pd.DataFrame) -> FamilyReranker:
    X = _family_feature_matrix(families, reranker.roles)
    fitted = clone(reranker.model)
    fitted.named_steps["scale"].fit(X)
    source = reranker.model.named_steps["model"]
    target = fitted.named_steps["model"]
    for name in ("coef_", "intercept_", "classes_"):
        setattr(target, name, getattr(source, name).copy())
    target.n_features_in_ = X.shape[1]
    return FamilyReranker(model=fitted, roles=reranker.roles)


def _new_forest(n_estimators: int, seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )


def fit_model(
    X: pd.DataFrame,
    session_positive: pd.Series,
    n_estimators: int = 200,
    seed: int = 0,
) -> RandomForestClassifier:
    model = _new_forest(n_estimators, seed)
    model.fit(X, session_positive)
    return model


def predict_scores(
    model: RandomForestClassifier,
    X: pd.DataFrame,
) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


def fit_soft_labels(
    X: pd.DataFrame,
    prior: np.ndarray,
    reviewed: np.ndarray | None = None,
    n_estimators: int = 200,
    seed: int = 0,
) -> RandomForestClassifier:
    prior = np.clip(np.asarray(prior, dtype=float), 0.0, 1.0)
    in_bag = prior > 0
    if not in_bag.any():
        raise ValueError("no session falls inside an incident")
    negative = ~in_bag
    if not negative.any() and reviewed is None:
        raise ValueError(
            "every session falls inside an incident, so there is nothing to "
            "learn a negative from; supply incidents covering part of the period"
        )
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
    model = _new_forest(n_estimators, seed)
    model.fit(X_stacked, y, sample_weight=weight)
    return model


def fit_calibrator(
    family_scores: np.ndarray,
    family_positive: np.ndarray,
) -> EvidenceCalibrator:
    scores = np.asarray(family_scores, dtype=float).reshape(-1, 1)
    target = np.asarray(family_positive, dtype=int)
    return EvidenceCalibrator(LogisticRegression(max_iter=1000).fit(scores, target))


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


def _to_wire(model: object) -> object:
    schema = getattr(model, "schema", None)
    counts = getattr(schema, "rule_counts", None)
    if not isinstance(counts, pd.Series):
        return model
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


def is_lfs_pointer(path: Path) -> bool:
    with path.open("rb") as file:
        return file.read(64).startswith(b"version https://git-lfs")


def load_model(path: Path) -> object:
    if not _is_skops(path):
        if is_lfs_pointer(path):
            raise UntrustedBundleError(
                f"{path.name} is an unfetched Git LFS pointer, not a model. "
                "Run `git lfs install && git lfs pull`."
            )
        raise UntrustedBundleError(
            f"{path.name} is not a skops bundle. Loading it would mean unpickling "
            "a file this build cannot verify, which runs whatever it contains. "
            "Retrain with `meerkat retrain`, or fetch a bundle written by this "
            "version of Meerkat."
        )
    _refuse_oversized_bundle(path)
    unexpected = set(sio.get_untrusted_types(file=path)) - set(TRUSTED_TYPES)
    if unexpected:
        raise UntrustedBundleError(
            f"{path.name} contains types this build does not trust: "
            f"{', '.join(sorted(unexpected))}. It was not written by "
            f"`meerkat retrain`; refusing to load it."
        )
    model = sio.load(path, trusted=list(TRUSTED_TYPES))
    _refuse_malformed_forest(path, model)
    return _from_wire(model)


class UntrustedBundleError(Exception):
    pass


def _is_skops(path: Path) -> bool:
    with path.open("rb") as file:
        if file.read(4) != b"PK\x03\x04":
            return False
    try:
        with zipfile.ZipFile(path) as archive:
            archive.getinfo("schema.json")
    except (zipfile.BadZipFile, KeyError, OSError):
        return False
    return True


# skops expands every member before it checks the allowlist, so the declared sizes
# are bounded first. It stores members uncompressed, so a real bundle sits at ratio
# 1 and both limits are far above anything it reaches.
MAX_BUNDLE_UNPACKED = 256 * 1024 * 1024
MAX_BUNDLE_RATIO = 50


def _refuse_oversized_bundle(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
    unpacked = sum(entry.file_size for entry in entries)
    packed = sum(entry.compress_size for entry in entries)
    if unpacked > MAX_BUNDLE_UNPACKED:
        raise UntrustedBundleError(
            f"{path.name} declares {unpacked / 1e6:.0f} MB of members, over the "
            f"{MAX_BUNDLE_UNPACKED / 1e6:.0f} MB limit a bundle may unpack to "
            "(the shipped one is about 15 MB); refusing to load it."
        )
    if packed and unpacked > packed * MAX_BUNDLE_RATIO:
        raise UntrustedBundleError(
            f"{path.name} unpacks to {unpacked / packed:.0f} times its size on "
            f"disk, over the {MAX_BUNDLE_RATIO}x limit for a bundle; refusing "
            "to load it."
        )


def _sequence(value: object) -> tuple:
    return tuple(value) if isinstance(value, (list, tuple)) else ()


def _iter_trees(model: object):
    seen: set[int] = set()
    stack = [model]
    while stack:
        value = stack.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        tree = getattr(value, "tree_", None)
        if tree is not None:
            yield tree
        stack.extend(_sequence(getattr(value, "estimators_", None)))
        stack.extend(
            step[1] for step in _sequence(getattr(value, "steps", None))
            if isinstance(step, (list, tuple)) and len(step) == 2
        )
        if is_dataclass(value) and not isinstance(value, type):
            stack.extend(vars(value).values())


# sklearn's Tree.__setstate__ checks the dtype and shape of the arrays it is given
# and never their contents, so a child index past the node count loads fine and
# then reads out of bounds when scoring. This turns that one shape of malformed
# bundle into an error message; it does not make an untrusted bundle safe.
def _refuse_malformed_forest(path: Path, model: object) -> None:
    def malformed(detail: str) -> UntrustedBundleError:
        return UntrustedBundleError(f"{path.name} is malformed: {detail}.")

    for tree in _iter_trees(model):
        count = int(getattr(tree, "node_count", -1))
        arrays = [
            np.atleast_1d(np.asarray(getattr(tree, name, ())))
            for name in ("children_left", "children_right", "feature")
        ]
        children, feature = arrays[:2], arrays[2]
        if count < 1 or any(
            array.ndim != 1 or len(array) != count for array in arrays
        ):
            raise malformed(
                f"a tree declares {count} nodes and carries a different "
                "number; refusing to score with it"
            )
        for side in children:
            if ((side < -1) | (side >= count)).any():
                raise malformed(
                    f"a tree has a child index outside its {count} nodes; "
                    "refusing to score with it"
                )
        used = feature[children[0] != -1]
        n_features = int(getattr(tree, "n_features", 0))
        if used.size and ((used < 0) | (used >= n_features)).any():
            raise malformed(
                f"a tree splits on a feature outside the {n_features} it was "
                "fitted on; refusing to score with it"
            )


def provenance_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".json")


def _write_provenance(model: object, path: Path) -> None:
    import sklearn

    forest = getattr(model, "forest", model)
    params = forest.get_params() if hasattr(forest, "get_params") else {}
    record = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "written_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "training_scenarios": list(getattr(model, "training_scenarios", ()) or ()),
        "n_estimators": getattr(model, "n_estimators", None),
        "seed": getattr(model, "seed", None),
        "roles": list(getattr(getattr(model, "schema", None), "roles", ()) or ()),
        "max_depth": params.get("max_depth"),
        "min_samples_leaf": params.get("min_samples_leaf"),
        "class_weight": params.get("class_weight"),
        "ranking_weights": getattr(model, "ranking_weights", "shipped"),
    }
    provenance_path(path).write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )


def read_provenance(path: Path) -> dict | None:
    sidecar = provenance_path(path)
    if not sidecar.exists():
        return None
    try:
        record = json.loads(sidecar.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
        raise UntrustedBundleError(
            f"{sidecar.name} is not valid JSON, so it records nothing about "
            f"what wrote {path.name}; refusing to read it."
        ) from error
    if not isinstance(record, dict):
        raise UntrustedBundleError(
            f"{sidecar.name} is a {type(record).__name__}, not the object "
            f"`meerkat retrain` writes beside {path.name}; refusing to read it."
        )
    record["matches_file"] = (
        record.get("sha256") == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    return record
