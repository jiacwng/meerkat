# Keeps each run as <runs_dir>/<run id>/ and every review in <runs_dir>/grades.csv.

import csv
import json
import math
import os
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from core.close import PILES
from core.incidents import COLUMNS, DESCRIPTIVE, GRADES, LINKS, SEPARATOR, distinct

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

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
        try:
            meta = json.loads(meta_file.read_text())
            runs.append({
                "run": meta_file.parent.name,
                "created": str(meta["created"]),
                "source": str(meta["source"]),
                "incidents": int(meta["incidents"]),
            })
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise StoreError(f"{meta_file}: unreadable run ({error!r})") from None
    return sorted(runs, key=lambda meta: (meta["created"], len(meta["run"]), meta["run"]))


def load_run(runs_dir: Path, run_id: str | None = None) -> tuple[dict, pd.DataFrame]:
    runs = list_runs(runs_dir)
    if not runs:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    if run_id is None:
        meta = runs[-1]
    else:
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


@contextmanager
def _locked(grades_file: Path):
    with grades_file.with_name(grades_file.name + ".lock").open("a") as lock:
        if sys.platform == "win32":
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            except OSError:
                raise StoreError(f"{grades_file} is in use, try again") from None
            try:
                yield
            finally:
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield


def append_grade(runs_dir: Path, incident_id: str, grade: str, note: str,
                 score: float, pile: str) -> None:
    grades_file = runs_dir / GRADES_FILE
    with _locked(grades_file), grades_file.open("a", newline="", encoding="utf-8") as handle:
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
    reviews = _read_csv(grades_file)
    if list(reviews.columns) != list(GRADE_COLUMNS):
        raise StoreError(f"{grades_file}: expected columns {', '.join(GRADE_COLUMNS)}")
    scores = pd.to_numeric(reviews["score"], errors="coerce")
    scores = scores.where(scores.abs() != float("inf"))
    bad_scores = reviews.loc[scores.isna(), "score"]
    if len(bad_scores):
        raise StoreError(f"{grades_file}: score {bad_scores.iloc[0]!r} is not a number")
    bad_grades = reviews.loc[~reviews["grade"].isin(GRADES), "grade"]
    if len(bad_grades):
        raise StoreError(
            f"{grades_file}: grade {bad_grades.iloc[0]!r} is not one of {', '.join(GRADES)}")
    bad_piles = reviews.loc[~reviews["pile"].isin(PILES), "pile"]
    if len(bad_piles):
        raise StoreError(
            f"{grades_file}: pile {bad_piles.iloc[0]!r} is not one of {', '.join(PILES)}")
    return reviews.assign(score=scores)


def _read_run(runs_dir: Path, run_id: str) -> pd.DataFrame:
    path = runs_dir / run_id / "incidents.csv"
    incidents = _read_csv(path)
    if list(incidents.columns) != list(COLUMNS):
        raise StoreError(f"{path}: expected columns {', '.join(COLUMNS)}")
    times = pd.to_datetime(incidents["Timestamp"], utc=True, format="ISO8601", errors="coerce")
    if times.isna().any():
        bad = incidents.loc[times.isna(), "Timestamp"].iloc[0]
        raise StoreError(f"{path}: Timestamp {bad!r} is not ISO 8601")
    return incidents


def _read_csv(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, dtype=str, keep_default_na=False)
    except (OSError, ValueError) as error:
        raise StoreError(f"{path}: unreadable ({error})") from None


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
