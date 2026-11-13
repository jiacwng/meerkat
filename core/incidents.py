# Reads an incident CSV in GUIDE's column names into one row per incident.

import pandas as pd

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


def read_incidents(path) -> pd.DataFrame:
    # an incident takes its time, rule, title and category from its earliest row
    rows = _read_rows(path)
    rows = rows.sort_values("Timestamp", kind="stable")
    by_incident = rows.groupby("IncidentId", sort=False)

    incidents = by_incident[["Timestamp", "DetectorId", *DESCRIPTIVE]].first()
    grades = rows["IncidentGrade"].replace("", pd.NA)
    incidents["IncidentGrade"] = grades.groupby(rows["IncidentId"]).first()
    incidents["MitreTechniques"] = _distinct(rows, "MitreTechniques", split=";")
    for column in LINKS:
        incidents[column] = _distinct(rows, column)
    return incidents.fillna("").reset_index()[list(COLUMNS)]


def _read_rows(path) -> pd.DataFrame:
    wanted = {*COLUMNS, "OrgId"}
    try:
        rows = pd.read_csv(path, dtype=str, keep_default_na=False,
                           usecols=lambda name: name in wanted)
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except (OSError, UnicodeDecodeError, pd.errors.ParserError,
            pd.errors.EmptyDataError) as error:
        raise IncidentError(f"{path}: not a readable CSV ({error})") from None

    missing = [name for name in REQUIRED if name not in rows.columns]
    if missing:
        raise IncidentError(f"{path}: missing column {', '.join(missing)}")
    if rows.empty:
        raise IncidentError(f"{path}: no incident rows")
    if "OrgId" in rows.columns and rows["OrgId"].nunique() > 1:
        raise IncidentError(
            f"{path}: {rows['OrgId'].nunique()} organisations in OrgId, "
            "a file holds one organisation")

    rows = rows.reindex(columns=list(COLUMNS), fill_value="")
    rows = rows.apply(lambda column: column.str.strip())
    for name in REQUIRED:
        blank = int((rows[name] == "").sum())
        if blank:
            raise IncidentError(f"{path}: {blank} rows have no {name}")
    unknown = rows.loc[~rows["IncidentGrade"].isin(("", *GRADES)), "IncidentGrade"]
    if len(unknown):
        raise IncidentError(
            f"{path}: IncidentGrade {unknown.iloc[0]!r} is not one of "
            f"{', '.join(GRADES)}")
    try:
        times = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601")
    except ValueError as error:
        raise IncidentError(f"{path}: Timestamp is not ISO 8601 ({error})") from None
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
