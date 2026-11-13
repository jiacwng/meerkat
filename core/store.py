# Keeps each run as <runs_dir>/<run id>/ and every review in <runs_dir>/grades.csv.

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

GRADES_FILE = "grades.csv"
GRADE_COLUMNS = ("time", "IncidentId", "grade", "note")


class StoreError(ValueError):
    pass


def save_run(runs_dir: Path, incidents: pd.DataFrame, source: str) -> dict:
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
    return sorted(runs, key=lambda meta: (meta["created"], meta["run"]))


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


def load_history(runs_dir: Path) -> pd.DataFrame:
    # an incident present in several runs is taken from the latest one
    runs = list_runs(runs_dir)
    if not runs:
        raise StoreError(f"no runs in {runs_dir}; score a file with: meerkat queue FILE")
    frames = [_read_run(runs_dir, meta["run"]) for meta in runs]
    history = pd.concat(frames, ignore_index=True)
    history = history.drop_duplicates("IncidentId", keep="last")
    return _apply_grades(runs_dir, history.reset_index(drop=True))


def append_grade(runs_dir: Path, incident_id: str, grade: str, note: str) -> None:
    grades_file = runs_dir / GRADES_FILE
    is_new = not grades_file.exists()
    with grades_file.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if is_new:
            writer.writerow(GRADE_COLUMNS)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        writer.writerow((now, incident_id, grade, note))


def _read_run(runs_dir: Path, run_id: str) -> pd.DataFrame:
    return _read_csv(runs_dir / run_id / "incidents.csv")


def _read_csv(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, dtype=str, keep_default_na=False)
    except (OSError, ValueError) as error:
        raise StoreError(f"{path}: unreadable ({error})") from None


def _apply_grades(runs_dir: Path, incidents: pd.DataFrame) -> pd.DataFrame:
    grades_file = runs_dir / GRADES_FILE
    if not grades_file.exists():
        return incidents
    reviews = _read_csv(grades_file)
    if list(reviews.columns) != list(GRADE_COLUMNS):
        raise StoreError(f"{grades_file}: expected columns {', '.join(GRADE_COLUMNS)}")
    reviews = reviews.drop_duplicates("IncidentId", keep="last")
    latest = incidents["IncidentId"].map(reviews.set_index("IncidentId")["grade"])
    return incidents.assign(IncidentGrade=latest.fillna(incidents["IncidentGrade"]))
