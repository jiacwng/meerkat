# Keeps each run as <runs_dir>/<run id>/ and every review in <runs_dir>/grades.csv.

import csv
import json
import math
import os
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from core.incidents import COLUMNS, DESCRIPTIVE, LINKS, SEPARATOR, distinct

GRADES_FILE = "grades.csv"
SETTINGS_FILE = "settings.json"
GRADE_COLUMNS = ("time", "IncidentId", "grade", "note", "score", "pile")


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
    return _apply_grades(runs_dir, _merge_repeats(history))


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
        if key == "miss_rate":
            if (isinstance(value, bool) or not isinstance(value, int | float)
                    or not math.isfinite(value) or not 0 < value < 1):
                raise StoreError(f"{settings_file}: miss_rate must be a number between 0 and 1")
        elif key == "keep_linked":
            if not isinstance(value, bool):
                raise StoreError(f"{settings_file}: keep_linked must be true or false")
        else:
            raise StoreError(f"{settings_file}: unknown setting {key!r}")
    return settings


def write_settings(runs_dir: Path, settings: dict) -> None:
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / SETTINGS_FILE).write_text(json.dumps(settings, indent=2) + "\n")


def append_grade(runs_dir: Path, incident_id: str, grade: str, note: str,
                 score: float, pile: str) -> None:
    grades_file = runs_dir / GRADES_FILE
    with grades_file.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if os.fstat(handle.fileno()).st_size == 0:
            writer.writerow(GRADE_COLUMNS)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        writer.writerow((now, incident_id, grade, note, repr(score), pile))


def read_reviews(runs_dir: Path) -> pd.DataFrame:
    grades_file = runs_dir / GRADES_FILE
    if not grades_file.exists():
        empty = pd.DataFrame({name: [] for name in GRADE_COLUMNS})
        return empty.astype({"score": float})
    reviews = pd.read_csv(grades_file, dtype=str, keep_default_na=False)
    return reviews.astype({"score": float})


def _read_run(runs_dir: Path, run_id: str) -> pd.DataFrame:
    return pd.read_csv(runs_dir / run_id / "incidents.csv", dtype=str, keep_default_na=False)


def _merge_repeats(history: pd.DataFrame) -> pd.DataFrame:
    repeated = history["IncidentId"].duplicated(keep=False)
    if not repeated.any():
        return history.reset_index(drop=True)
    rows = history[repeated]
    grades = rows["IncidentGrade"].replace("", pd.NA).groupby(rows["IncidentId"]).last()

    times = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601")
    earliest_first = rows.loc[times.sort_values(kind="stable").index]
    merged = earliest_first.groupby("IncidentId", sort=False)[
        ["Timestamp", "DetectorId", *DESCRIPTIVE]].first()
    merged["IncidentGrade"] = grades
    for column in ("MitreTechniques", *LINKS):
        merged[column] = distinct(rows, column, split=SEPARATOR)
    merged = merged.fillna("").reset_index()[list(COLUMNS)]
    return pd.concat([history[~repeated], merged], ignore_index=True)


def _apply_grades(runs_dir: Path, incidents: pd.DataFrame) -> pd.DataFrame:
    reviews = read_reviews(runs_dir)
    if reviews.empty:
        return incidents
    reviews = reviews.drop_duplicates("IncidentId", keep="last")
    latest = incidents["IncidentId"].map(reviews.set_index("IncidentId")["grade"])
    return incidents.assign(IncidentGrade=latest.fillna(incidents["IncidentGrade"]))
