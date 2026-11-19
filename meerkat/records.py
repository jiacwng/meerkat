# The queue, one incident and a recorded grade as plain data, for the terminal and the page.

from pathlib import Path

import pandas as pd

from core import budget, features, rank, store
from core.incidents import LINKS, SEPARATOR

LINKED_SHOWN = ("IncidentId", "IncidentGrade", "Timestamp", "DetectorId", "AlertTitle")


def settings(runs_dir: Path) -> dict:
    return {"budget": None, "sample_share": budget.DEFAULT_SAMPLE_SHARE,
            **store.read_settings(runs_dir)}


def scored(runs_dir: Path, incoming: pd.DataFrame | None = None) -> pd.DataFrame:
    return rank.score(store.load_history(runs_dir, incoming))


def placed(runs_dir: Path, scores: pd.DataFrame,
           chosen: dict) -> tuple[pd.DataFrame, list[dict]]:
    samples = store.read_samples(runs_dir)
    reviews = store.read_reviews(runs_dir)
    return budget.place(scores, reviews, chosen["budget"], samples), samples


def queue(runs_dir: Path, scores: pd.DataFrame, chosen: dict, run: str | None = None,
          run_ids: pd.Series | None = None) -> dict:
    found, samples = placed(runs_dir, scores, chosen)
    opened = found[found["IncidentGrade"] == ""]
    if run_ids is not None:
        opened = opened[opened["IncidentId"].isin(run_ids)]
    under = (opened["status"] == "below").to_numpy()
    opened = opened.iloc[under.argsort(kind="stable")]
    grades = dict(zip(found["IncidentId"], found["IncidentGrade"], strict=True))
    sampled = budget.estimate(samples, grades)
    return {
        "run": run, "open": len(opened), "budget": chosen["budget"],
        "sample_share": chosen["sample_share"],
        "to_read": int((~under).sum()), "below_budget": int(under.sum()),
        "sample": {"drawn": sampled["drawn"], "graded": sampled["graded"],
                   "true_positive": sampled["true_positive"],
                   "not_sampled": budget.not_sampled(found, samples)},
        "unread_true_positives": sampled["unread_true_positives"],
        "queue": [as_record(row, position)
                  for position, row in enumerate(opened.to_dict("records"), start=1)],
    }


def incident(runs_dir: Path, scores: pd.DataFrame, incident_id: str,
             run: str | None = None) -> dict:
    history, _ = placed(runs_dir, scores, settings(runs_dir))
    found = history
    if run is not None:
        _, in_run = store.load_run(runs_dir, run)
        found = found[found["IncidentId"].isin(in_run["IncidentId"])]
    found = found[found["IncidentId"] == incident_id]
    if found.empty:
        raise store.StoreError(f"no incident {incident_id!r} in {runs_dir}")
    record = as_record(found.iloc[0].to_dict())
    for column in ("MitreTechniques", *LINKS):
        record[column] = [value for value in record[column].split(SEPARATOR) if value]
    mine = {column: set(record[column]) for column in LINKS}
    record["linked_incidents"] = [
        {**{name: other[name] for name in LINKED_SHOWN},
         "shared": [f"{column} {value}" for column in LINKS
                    for value in other[column].split(SEPARATOR) if value in mine[column]]}
        for other in features.linked_to(history, incident_id).to_dict("records")]
    return record


def grade(runs_dir: Path, scores: pd.DataFrame, grades: list[tuple[str, str]],
          note: str) -> list[str]:
    found, _ = placed(runs_dir, scores, settings(runs_dir))
    found = found.set_index("IncidentId")
    for incident_id, _ in grades:
        if incident_id not in found.index:
            raise store.StoreError(f"no incident {incident_id!r} in {runs_dir}")
    reviews = store.read_reviews(runs_dir)
    first = reviews.drop_duplicates("IncidentId").set_index("IncidentId")

    true_positives = []
    for incident_id, given in grades:
        source = first if incident_id in first.index else found
        score, status = float(source.at[incident_id, "score"]), source.at[incident_id, "status"]
        store.append_grade(runs_dir, incident_id, given, note, score, status)
        if given == budget.TRUE_POSITIVE:
            true_positives.append(status)
    return true_positives


def as_record(row: dict, position: int | None = None) -> dict:
    record = dict(row)
    for column in ("score", "score_without_links", "score_as_new_rule"):
        record[column] = round(float(row[column]), 4)
    for column in ("rule_graded", "rule_true_positives", "linked", "linked_true_positive",
                   "linked_benign_positive", "linked_false_positive"):
        record[column] = int(row[column])
    if position is not None:
        record = {"position": position, **record}
    return record
