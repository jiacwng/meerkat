# Keeps each run as <runs_dir>/<run id>/ and every review in <runs_dir>/grades.csv.

import csv
import json
import math
import os
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from core.incidents import collapse

GRADES_FILE = "grades.csv"
SETTINGS_FILE = "settings.json"
SAMPLE_FILE = "sample.json"
GRADE_COLUMNS = ("time", "IncidentId", "grade", "note", "score", "status")


class StoreError(ValueError):
    pass


def save_run(runs_dir: Path, incidents: pd.DataFrame, source: str,
             mapping: str) -> dict:
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
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "mapping": mapping,
        "incidents": len(incidents),
    }
    incidents.to_csv(runs_dir / run_id / "incidents.csv", index=False)
    (runs_dir / run_id / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def list_runs(runs_dir: Path) -> list[dict]:
    if not runs_dir.is_dir():
        return []
    runs = []
    for meta_file in sorted(runs_dir.glob("*/meta.json")):
        meta = json.loads(meta_file.read_text())
        runs.append({
            "run": meta_file.parent.name,
            "created": meta["created"],
            "source": meta["source"],
            "incidents": meta["incidents"],
        })
    return sorted(runs, key=lambda meta: (meta["created"], meta["run"]))


def load_run(runs_dir: Path, run_id: str) -> tuple[dict, pd.DataFrame]:
    runs = list_runs(runs_dir)
    if not runs:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    meta = next((run for run in runs if run["run"] == run_id), None)
    if meta is None:
        raise StoreError(f"no run {run_id!r} in {runs_dir}")
    return meta, _apply_grades(runs_dir, _read_run(runs_dir, meta["run"]))


def load_history(runs_dir: Path, incoming: pd.DataFrame | None = None) -> pd.DataFrame:
    # an incident present in several runs becomes one row, as if all its alerts came in one file
    runs = list_runs(runs_dir)
    if not runs and incoming is None:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    frames = [_read_run(runs_dir, meta["run"]) for meta in runs]
    if incoming is not None:
        frames.append(incoming)
    history = pd.concat(frames, ignore_index=True)
    repeated = history["IncidentId"].duplicated(keep=False)
    if repeated.any():
        history = pd.concat([history[~repeated], collapse(history[repeated])], ignore_index=True)
    return _apply_grades(runs_dir, history)


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


def append_grade(runs_dir: Path, incident_id: str, grade: str, note: str,
                 score: float, status: str) -> None:
    grades_file = runs_dir / GRADES_FILE
    with grades_file.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if os.fstat(handle.fileno()).st_size == 0:
            writer.writerow(GRADE_COLUMNS)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        writer.writerow((now, incident_id, grade, note, repr(score), status))


def read_reviews(runs_dir: Path) -> pd.DataFrame:
    grades_file = runs_dir / GRADES_FILE
    if not grades_file.exists():
        empty = pd.DataFrame({name: [] for name in GRADE_COLUMNS})
        return empty.astype({"score": float})
    reviews = pd.read_csv(grades_file, dtype=str, keep_default_na=False)
    return reviews.astype({"score": float})


def _read_run(runs_dir: Path, run_id: str) -> pd.DataFrame:
    return pd.read_csv(runs_dir / run_id / "incidents.csv", dtype=str, keep_default_na=False)


def _apply_grades(runs_dir: Path, incidents: pd.DataFrame) -> pd.DataFrame:
    reviews = read_reviews(runs_dir)
    if reviews.empty:
        return incidents
    reviews = reviews.drop_duplicates("IncidentId", keep="last")
    latest = incidents["IncidentId"].map(reviews.set_index("IncidentId")["grade"])
    return incidents.assign(IncidentGrade=latest.fillna(incidents["IncidentGrade"]))
