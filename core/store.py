# Keeps each run as <runs_dir>/<run id>/ and every classification in <runs_dir>/classifications.csv.

import csv
import json
import math
import os
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from core.incidents import CLOSED, COLUMNS, collapse

CLASSIFICATIONS_FILE = "classifications.csv"
SETTINGS_FILE = "settings.json"
SAMPLE_FILE = "sample.json"
CLASSIFICATION_COLUMNS = ("time", "IncidentId", "classification", "comment", "score",
                          "placement")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class StoreError(ValueError):
    pass


def save_run(runs_dir: Path, incidents: pd.DataFrame, file: str,
             source: str) -> dict:
    text = incidents.to_csv(index=False, lineterminator="\n")
    for meta in list_runs(runs_dir):
        saved = runs_dir / meta["run"] / "incidents.csv"
        if saved.read_text(encoding="utf-8") == text:
            return meta
    now = datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    run_id, attempt = stamp, 1
    runs_dir.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            (runs_dir / run_id).mkdir()
            break
        except FileExistsError:
            attempt += 1
            run_id = f"{stamp}-{attempt}"
    meta = {
        "run": run_id,
        "created": now.strftime(TIME_FORMAT),
        "file": file,
        "source": source,
        "incidents_in_file": len(incidents),
    }
    (runs_dir / run_id / "incidents.csv").write_text(text, encoding="utf-8", newline="\n")
    (runs_dir / run_id / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def list_runs(runs_dir: Path) -> list[dict]:
    if not runs_dir.is_dir():
        return []
    runs = []
    for meta_file in sorted(runs_dir.glob("*/meta.json")):
        try:
            meta = json.loads(meta_file.read_text())
        except (OSError, ValueError) as error:
            raise StoreError(f"{meta_file}: unreadable ({error})") from None
        if not (isinstance(meta, dict) and isinstance(meta.get("created"), str)
                and isinstance(meta.get("file"), str)
                and isinstance(meta.get("incidents_in_file"), int)):
            raise StoreError(f"{meta_file}: expected created, file and incidents_in_file")
        runs.append({
            "run": meta_file.parent.name,
            "created": meta["created"],
            "file": meta["file"],
            "incidents_in_file": meta["incidents_in_file"],
        })
    return sorted(runs, key=lambda meta: (meta["created"], meta["run"]))


def load_run(runs_dir: Path, run_id: str) -> tuple[dict, pd.DataFrame]:
    runs = list_runs(runs_dir)
    if not runs:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    meta = next((run for run in runs if run["run"] == run_id), None)
    if meta is None:
        raise StoreError(f"no run {run_id!r} in {runs_dir}")
    return meta, _read_run(runs_dir, meta["run"])


def load_history(runs_dir: Path) -> pd.DataFrame:
    # an incident takes its alerts from every file that holds it, and its state from the newest
    runs = list_runs(runs_dir)
    if not runs:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    frames = [_read_run(runs_dir, meta["run"]).assign(loaded=meta["created"]) for meta in runs]
    rows = pd.concat(frames, ignore_index=True)
    newest = rows.drop_duplicates("IncidentId", keep="last").set_index("IncidentId")
    closed = rows["IncidentId"].map(newest["IncidentGrade"]) == CLOSED
    rows = rows.loc[~closed & (rows["DetectorId"] != ""), list(COLUMNS)]
    repeated = rows["IncidentId"].duplicated(keep=False)
    if repeated.any():
        rows = pd.concat([rows[~repeated], collapse(rows[repeated])], ignore_index=True)
    history = rows.assign(IncidentGrade=rows["IncidentId"].map(newest["IncidentGrade"]))
    return _apply_classifications(runs_dir, history, history["IncidentId"].map(newest["loaded"]))


def read_settings(runs_dir: Path) -> dict:
    settings_file = runs_dir / SETTINGS_FILE
    if not settings_file.exists():
        return {}
    try:
        settings = json.loads(settings_file.read_text())
    except (OSError, ValueError) as error:
        raise StoreError(f"{settings_file}: unreadable ({error})") from None
    if not isinstance(settings, dict):
        raise StoreError(f"{settings_file}: expected an object")
    for key, value in settings.items():
        if key == "budget":
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StoreError(f"{settings_file}: budget must be a whole number above 0")
        elif key == "sample_share":
            if (isinstance(value, bool) or not isinstance(value, int | float)
                    or not math.isfinite(value) or not 0 <= value < 1):
                raise StoreError(f"{settings_file}: sample_share must be a number from 0 "
                                 "up to 1")
        else:
            raise StoreError(f"{settings_file}: unknown setting {key!r}")
    return settings


def write_settings(runs_dir: Path, settings: dict) -> None:
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / SETTINGS_FILE).write_text(json.dumps(settings, indent=2) + "\n")


def save_sample(runs_dir: Path, run_id: str, sample: dict) -> None:
    (runs_dir / run_id / SAMPLE_FILE).write_text(json.dumps(sample) + "\n")


def drop_sample(runs_dir: Path, run_id: str) -> None:
    (runs_dir / run_id / SAMPLE_FILE).unlink()


def has_sample(runs_dir: Path, run_id: str) -> bool:
    return (runs_dir / run_id / SAMPLE_FILE).exists()


def read_samples(runs_dir: Path) -> list[dict]:
    found = []
    for meta in list_runs(runs_dir):
        sample_file = runs_dir / meta["run"] / SAMPLE_FILE
        if not sample_file.exists():
            continue
        try:
            sample = json.loads(sample_file.read_text())
        except (OSError, ValueError) as error:
            raise StoreError(f"{sample_file}: unreadable ({error})") from None
        if not (isinstance(sample, dict) and set(sample) == {"pool", "drawn"}
                and all(isinstance(sample[name], list) for name in ("pool", "drawn"))
                and all(isinstance(incident, str)
                        for name in ("pool", "drawn") for incident in sample[name])
                and set(sample["drawn"]) <= set(sample["pool"])):
            raise StoreError(f"{sample_file}: expected the pool and the drawn incident ids")
        found.append(sample)
    return found


def append_classification(runs_dir: Path, incident_id: str, classification: str,
                          comment: str, score: float, placement: str) -> None:
    classifications_file = runs_dir / CLASSIFICATIONS_FILE
    with classifications_file.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if os.fstat(handle.fileno()).st_size == 0:
            writer.writerow(CLASSIFICATION_COLUMNS)
        writer.writerow((_now(), incident_id, classification, comment, repr(score), placement))


def read_classifications(runs_dir: Path) -> pd.DataFrame:
    earlier = runs_dir / "grades.csv"
    if earlier.exists():
        raise StoreError(f"{earlier}: saved by another version of meerkat, remove "
                         f"{runs_dir} and load its files again")
    classifications_file = runs_dir / CLASSIFICATIONS_FILE
    if not classifications_file.exists():
        empty = pd.DataFrame({name: [] for name in CLASSIFICATION_COLUMNS})
        return empty.astype({"score": float})
    try:
        classifications = pd.read_csv(classifications_file, dtype=str, keep_default_na=False)
        if not set(CLASSIFICATION_COLUMNS) <= set(classifications.columns):
            raise ValueError(f"expected the columns {', '.join(CLASSIFICATION_COLUMNS)}")
        return classifications.astype({"score": float})
    except (OSError, ValueError) as error:
        raise StoreError(f"{classifications_file}: unreadable ({error})") from None


def _read_run(runs_dir: Path, run_id: str) -> pd.DataFrame:
    saved = runs_dir / run_id / "incidents.csv"
    try:
        incidents = pd.read_csv(saved, dtype=str, keep_default_na=False)
    except (OSError, ValueError) as error:
        raise StoreError(f"{saved}: unreadable ({error})") from None
    if list(incidents.columns) != list(COLUMNS):
        raise StoreError(f"{saved}: saved by another version of meerkat, remove "
                         f"{saved.parent} and load its file again")
    return incidents


def _apply_classifications(runs_dir: Path, incidents: pd.DataFrame,
                           loaded: pd.Series) -> pd.DataFrame:
    # a classification given here holds until a later file names the incident again
    classifications = read_classifications(runs_dir)
    if classifications.empty:
        return incidents
    latest = classifications.drop_duplicates("IncidentId", keep="last").set_index("IncidentId")
    given = incidents["IncidentId"].map(latest["classification"])
    since = incidents["IncidentId"].map(latest["time"]).fillna("")
    return incidents.assign(
        IncidentGrade=given.where(since >= loaded).fillna(incidents["IncidentGrade"]))


def _now() -> str:
    return datetime.now(UTC).strftime(TIME_FORMAT)
