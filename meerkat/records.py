# The queue, one incident and a recorded classification as plain data, for the terminal and the page.

from pathlib import Path

import pandas as pd

from core import budget, features, groups, rank, store
from core.incidents import CLASSIFICATIONS, LINKS, SEPARATOR, read_incidents
from core.mapping import load_mapping
from meerkat import defender

SIMILAR_SHOWN = ("IncidentId", "IncidentGrade", "Timestamp", "DetectorId", "AlertTitle")
HOST = ("DeviceName", "DeviceId")
USER = ("AccountUpn", "AccountName", "AccountSid", "AccountObjectId")


def settings(runs_dir: Path) -> dict:
    return {"budget": None, "sample_share": budget.DEFAULT_SAMPLE_SHARE,
            **store.read_settings(runs_dir)}


def scored(runs_dir: Path, incoming: pd.DataFrame | None = None) -> pd.DataFrame:
    return rank.score(store.load_history(runs_dir, incoming))


def load(runs_dir: Path, path: Path, file: str, mapping_name: str) -> tuple[pd.DataFrame, str]:
    if file.lower().endswith(".json"):
        return keep(runs_dir, defender.read_incidents(path), file, "defender")
    mapping = load_mapping(mapping_name)
    return keep(runs_dir, read_incidents(path, mapping), file, mapping.name)


def keep(runs_dir: Path, incoming: pd.DataFrame, file: str,
         mapping_name: str) -> tuple[pd.DataFrame, str]:
    scores = scored(runs_dir, incoming)
    run = store.save_run(runs_dir, incoming, file, mapping_name)["run"]
    draw_sample(runs_dir, run, settings(runs_dir), scores)
    return scores, run


def draw_sample(runs_dir: Path, run: str, chosen: dict, scores: pd.DataFrame) -> None:
    if chosen["budget"] is None or store.has_sample(runs_dir, run):
        return
    opened = scores.loc[scores["IncidentGrade"] == "", "IncidentId"].tolist()
    samples = store.read_samples(runs_dir)
    lead = groups.leads(scores, budget.drawn_ids(samples))
    sample = budget.draw(opened, chosen["budget"], chosen["sample_share"], samples, lead)
    if sample["pool"]:
        store.save_sample(runs_dir, run, sample)


def change_setting(runs_dir: Path, name: str, value: float | None,
                   scores: pd.DataFrame | None = None) -> None:
    saved = store.read_settings(runs_dir)
    if value is None:
        saved.pop(name, None)
    else:
        saved[name] = value
    runs = store.list_runs(runs_dir)
    if runs and scores is None:
        scores = scored(runs_dir)
    store.write_settings(runs_dir, saved)
    if runs:
        # the newest sample is drawn again unless one of its rows is already classified
        newest = runs[-1]["run"]
        classified = set(scores.loc[scores["IncidentGrade"] != "", "IncidentId"])
        if (store.has_sample(runs_dir, newest)
                and not classified & set(store.read_samples(runs_dir)[-1]["drawn"])):
            store.drop_sample(runs_dir, newest)
        draw_sample(runs_dir, newest, settings(runs_dir), scores)


def placed(runs_dir: Path, scores: pd.DataFrame,
           chosen: dict) -> tuple[pd.DataFrame, list[dict]]:
    samples = store.read_samples(runs_dir)
    recorded = store.read_classifications(runs_dir)
    lead = groups.leads(scores, budget.drawn_ids(samples))
    return budget.place(scores, recorded, chosen["budget"], samples, lead), samples


def queue(runs_dir: Path, scores: pd.DataFrame, chosen: dict, run: str | None = None,
          run_ids: pd.Series | None = None) -> dict:
    found, samples = placed(runs_dir, scores, chosen)
    opened = found[found["IncidentGrade"] == ""]
    if run_ids is not None:
        opened = opened[opened["IncidentId"].isin(run_ids)]
    together = {name: part.to_dict("records")
                for name, part in opened.groupby("group_lead", sort=False)}
    rows = opened.drop_duplicates("group_lead")
    under = (rows["placement"] == "below budget").to_numpy()
    rows = rows.iloc[under.argsort(kind="stable")]
    classifications = dict(zip(found["IncidentId"], found["IncidentGrade"], strict=True))
    unread = found.loc[(found["IncidentGrade"] == "") & (found["placement"] == "below budget"),
                       "IncidentId"]
    sampled = budget.estimate(samples, classifications, set(unread))
    waiting = opened.loc[opened["placement"] == "below budget", "Timestamp"]
    missed = budget.not_sampled(found, samples)
    interval = sampled["tp_below_budget"]
    if interval is not None:
        interval = {**interval, "of": len(unread) - missed} if len(unread) > missed else None
    files = {meta["run"]: meta["file"] for meta in store.list_runs(runs_dir)}
    return {
        "file": files[run] if run is not None else list(files.values())[-1],
        "below_oldest": waiting.min() if len(waiting) else None,
        "run": run, "open": len(opened), "grouped": len(opened) - len(rows),
        "budget": chosen["budget"], "sample_share": chosen["sample_share"],
        "to_read": int((~under).sum()), "below_budget": int(under.sum()),
        "sample": {"drawn": sampled["drawn"], "classified": sampled["classified"],
                   "true_positive": sampled["true_positive"],
                   "not_sampled": missed},
        "tp_below_budget": interval,
        "classifications": list(CLASSIFICATIONS), "links": list(LINKS),
        "queue": [{**as_record(row, position), "host": _first(together[row["group_lead"]], HOST),
                   "user": _first(together[row["group_lead"]], USER), "flag": _flag(row),
                   "latest": max(other["Timestamp"] for other in together[row["group_lead"]]),
                   "members": [other["IncidentId"] for other in together[row["group_lead"]]][1:]}
                  for position, row in enumerate(rows.to_dict("records"), start=1)],
    }


def _first(rows: list[dict], columns: tuple[str, ...]) -> str:
    for column in columns:
        values = list(dict.fromkeys(value for row in rows
                                    for value in row[column].split(SEPARATOR) if value))
        if values:
            return values[0] if len(values) == 1 else f"{values[0]} +{len(values) - 1}"
    return ""


def _flag(row: dict) -> str:
    if row["placement"] != "below budget":
        return "sample" if row["placement"] == "sample" else ""
    if row["similar_true_positive"] >= 1:
        return "similar TP"
    return "unclassified rule" if row["rule_classified"] == 0 else ""


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
    record["similar_incidents"] = [
        {**{name: other[name] for name in SIMILAR_SHOWN},
         "shared": [f"{column} {value}" for column in LINKS
                    for value in other[column].split(SEPARATOR) if value in mine[column]]}
        for other in features.similar_to(history, incident_id).to_dict("records")]
    record["similar_same_rule"] = sum(other["DetectorId"] == record["DetectorId"]
                                      for other in record["similar_incidents"])
    entities = [_entity(column, value, record["similar_incidents"])
                for column in LINKS for value in record[column]]
    record["entities"] = sorted(entities, key=lambda entity: -entity["classified_before"])
    together = history[(history["group_lead"] == record["group_lead"]) & (history["group_lead"] != "")]
    record["members"] = [other for other in together["IncidentId"] if other != incident_id]
    recorded = store.read_classifications(runs_dir)
    recorded = recorded[recorded["IncidentId"] == incident_id]
    record["classification_history"] = recorded[["time", "classification",
                                                 "comment"]].to_dict("records")
    return record


def _entity(column: str, value: str, similar: list[dict]) -> dict:
    found = [other["IncidentGrade"] for other in similar
             if f"{column} {value}" in other["shared"]]
    return {"field": column, "value": value, "classified_before": len(found),
            **{name: found.count(name) for name in CLASSIFICATIONS}}


def classify(runs_dir: Path, scores: pd.DataFrame, classifications: list[tuple[str, str]],
             comment: str) -> list[str]:
    found, _ = placed(runs_dir, scores, settings(runs_dir))
    found = found.set_index("IncidentId")
    for incident_id, _ in classifications:
        if incident_id not in found.index:
            raise store.StoreError(f"no incident {incident_id!r} in {runs_dir}")
    recorded = store.read_classifications(runs_dir)
    first = recorded.drop_duplicates("IncidentId").set_index("IncidentId")

    true_positives = []
    for incident_id, given in classifications:
        source = first if incident_id in first.index else found
        score = float(source.at[incident_id, "score"])
        placement = source.at[incident_id, "placement"]
        store.append_classification(runs_dir, incident_id, given, comment, score, placement)
        if given == budget.TRUE_POSITIVE:
            true_positives.append(placement)
    return true_positives


def with_group(runs_dir: Path, scores: pd.DataFrame, incident_id: str) -> list[str]:
    mine = scores["IncidentId"] == incident_id
    if not mine.any():
        raise store.StoreError(f"no incident {incident_id!r} in {runs_dir}")
    reopened = scores.assign(IncidentGrade=scores["IncidentGrade"].mask(mine, ""))
    lead = groups.leads(reopened, budget.drawn_ids(store.read_samples(runs_dir)))
    return [incident_id, *(other for other, top in lead.items()
                           if other != incident_id and top == lead[incident_id])]


def classified_with(runs_dir: Path, scores: pd.DataFrame, incident_id: str) -> dict[str, str]:
    # the group as it would be if no incident in it had been classified yet
    recorded = store.read_classifications(runs_dir).drop_duplicates("IncidentId", keep="last")
    given = dict(zip(recorded["IncidentId"], recorded["classification"], strict=True))
    classified = scores["IncidentId"].isin(list(given)) | (scores["IncidentId"] == incident_id)
    reopened = scores.assign(IncidentGrade=scores["IncidentGrade"].mask(classified, ""))
    lead = groups.leads(reopened, budget.drawn_ids(store.read_samples(runs_dir)))
    return {other: classification for other, classification in given.items()
            if other != incident_id and lead.get(other) == lead[incident_id]}


def as_record(row: dict, position: int | None = None) -> dict:
    record = dict(row)
    record["score"] = round(float(row["score"]), 4)
    for column in (*features.RULE, "similar", "similar_true_positive",
                   "similar_benign_positive", "similar_false_positive"):
        record[column] = int(row[column])
    if position is not None:
        record = {"position": position, **record}
    return record
