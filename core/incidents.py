# Reads an incident CSV through a column mapping into one row per incident.

from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from core.mapping import Mapping

REQUIRED = ("IncidentId", "Timestamp", "DetectorId")
DESCRIPTIVE = ("AlertTitle", "Category")
LINKS = (
    "DeviceId", "DeviceName", "AccountObjectId", "AccountSid", "AccountUpn",
    "AccountName", "IpAddress", "Sha256", "Url",
)
GRADES = ("TruePositive", "BenignPositive", "FalsePositive")
COLUMNS = (*REQUIRED, "IncidentGrade", *DESCRIPTIVE, "MitreTechniques", *LINKS)
SEPARATOR = "|"


class IncidentError(ValueError):
    pass


def read_incidents(path, mapping: "Mapping") -> pd.DataFrame:
    # an incident takes its time, rule, title and category from its earliest row
    rows = _read_rows(path, mapping)
    rows = rows.sort_values("Timestamp", kind="stable")
    by_incident = rows.groupby("IncidentId", sort=False)

    incidents = by_incident[["Timestamp", "DetectorId", *DESCRIPTIVE]].first()
    grades = rows["IncidentGrade"].replace("", pd.NA)
    incidents["IncidentGrade"] = grades.groupby(rows["IncidentId"]).first()
    incidents["MitreTechniques"] = _distinct(rows, "MitreTechniques", split=";")
    for column in LINKS:
        incidents[column] = _distinct(rows, column)
    return incidents.fillna("").reset_index()[list(COLUMNS)]


def _read_rows(path, mapping: "Mapping") -> pd.DataFrame:
    wanted = {*mapping.columns.values(), "OrgId"}
    try:
        rows = pd.read_csv(path, dtype=str, keep_default_na=False,
                           usecols=lambda name: name in wanted)
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except (OSError, UnicodeDecodeError, pd.errors.ParserError,
            pd.errors.EmptyDataError) as error:
        raise IncidentError(f"{path}: not a readable CSV ({error})") from None

    missing = [mapping.columns[name] for name in REQUIRED
               if mapping.columns[name] not in rows.columns]
    if missing:
        raise IncidentError(f"{path}: missing column {', '.join(missing)}")
    if rows.empty:
        raise IncidentError(f"{path}: no incident rows")
    if "OrgId" in rows.columns and rows["OrgId"].nunique() > 1:
        raise IncidentError(
            f"{path}: {rows['OrgId'].nunique()} organisations in OrgId, "
            "a file holds one organisation")

    rows = rows.rename(columns={source: name for name, source in mapping.columns.items()})
    rows = rows.reindex(columns=list(COLUMNS), fill_value="")
    rows = rows.apply(lambda column: column.str.strip())
    for name in REQUIRED:
        blank = int((rows[name] == "").sum())
        if blank:
            raise IncidentError(f"{path}: {blank} rows have no {mapping.columns[name]}")
    words = {"": "", **mapping.grades}
    unknown = rows.loc[~rows["IncidentGrade"].isin(words), "IncidentGrade"]
    if len(unknown):
        raise IncidentError(
            f"{path}: {mapping.columns['IncidentGrade']} {unknown.iloc[0]!r} "
            f"is not one of {', '.join(mapping.grades)}")
    rows["IncidentGrade"] = rows["IncidentGrade"].map(words)
    try:
        times = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601")
    except ValueError as error:
        raise IncidentError(
            f"{path}: {mapping.columns['Timestamp']} is not ISO 8601 ({error})") from None
    rows["Timestamp"] = times.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return rows


def _distinct(rows: pd.DataFrame, column: str, split: str | None = None) -> pd.Series:
    values = rows[["IncidentId", column]]
    if split:
        values = values.assign(**{column: values[column].str.split(split)})
        values = values.explode(column)
        values[column] = values[column].str.strip()
    values = values[values[column] != ""].drop_duplicates().sort_values(column)
    return values.groupby("IncidentId")[column].agg(SEPARATOR.join)
