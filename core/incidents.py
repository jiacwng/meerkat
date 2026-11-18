# Reads an incident CSV through a column mapping into one row per incident.

import csv
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
    return collapse(_read_rows(path, mapping))


def read_grades(path) -> list[tuple[str, str]]:
    try:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            names = reader.fieldnames or ()
            rows = list(reader)
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except (OSError, UnicodeDecodeError, csv.Error) as error:
        raise IncidentError(f"{path}: not a readable CSV ({error})") from None
    for name in ("IncidentId", "IncidentGrade"):
        if name not in names:
            raise IncidentError(f"{path}: missing column {name}")
    if not rows:
        raise IncidentError(f"{path}: no grade rows")
    grades = []
    for row in rows:
        incident = (row["IncidentId"] or "").strip()
        grade = (row["IncidentGrade"] or "").strip()
        if not incident:
            raise IncidentError(f"{path}: a row has no IncidentId")
        if grade not in GRADES:
            raise IncidentError(
                f"{path}: IncidentGrade {grade!r} is not one of {', '.join(GRADES)}")
        grades.append((incident, grade))
    return grades


def collapse(rows: pd.DataFrame) -> pd.DataFrame:
    # an incident takes its time, rule, title and category from its earliest row
    grades = rows["IncidentGrade"].replace("", pd.NA).groupby(rows["IncidentId"]).last()
    rows = rows.sort_values("Timestamp", kind="stable")
    by_incident = rows.groupby("IncidentId", sort=False)

    incidents = by_incident[["Timestamp", "DetectorId", *DESCRIPTIVE]].first()
    incidents["IncidentGrade"] = grades
    for column in ("MitreTechniques", *LINKS):
        incidents[column] = _distinct(rows, column)
    return incidents.fillna("").reset_index()[list(COLUMNS)]


def _read_rows(path, mapping: "Mapping") -> pd.DataFrame:
    wanted = {*mapping.columns.values(), "OrgId"}
    try:
        rows = pd.read_csv(path, dtype=str, keep_default_na=False,
                           usecols=lambda name: name in wanted)
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except UnicodeDecodeError:
        with open(path, "rb") as handle:
            utf16 = handle.read(2) in (b"\xff\xfe", b"\xfe\xff")
        raise IncidentError(
            f"{path}: is {'UTF-16' if utf16 else 'not UTF-8'}, save it as UTF-8") from None
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise IncidentError(f"{path}: not a readable CSV ({error})") from None

    missing = [mapping.columns[name] for name in REQUIRED
               if mapping.columns[name] not in rows.columns]
    if missing:
        separator = _header_separator(path, mapping)
        if separator is not None:
            raise IncidentError(
                f"{path}: columns are separated by {separator!r}, expected ','")
        raise IncidentError(f"{path}: missing column {', '.join(missing)}")
    if rows.empty:
        raise IncidentError(f"{path}: no incident rows")
    if "OrgId" in rows.columns:
        organisations = rows["OrgId"].str.strip()
        organisations = organisations[organisations != ""]
        if organisations.nunique() > 1:
            raise IncidentError(
                f"{path}: {organisations.nunique()} organisations in OrgId, "
                "a file holds one organisation")

    rows = rows.rename(columns={source: name for name, source in mapping.columns.items()})
    rows = rows.reindex(columns=list(COLUMNS), fill_value="")
    rows = rows.apply(lambda column: column.str.strip())
    for name in LINKS:
        rows[name] = rows[name].str.replace(SEPARATOR, "%7C", regex=False)
    rows["MitreTechniques"] = rows["MitreTechniques"].str.replace(";", SEPARATOR, regex=False)
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
    name = mapping.columns["Timestamp"]
    times = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601", errors="coerce")
    if times.isna().any():
        raise IncidentError(
            f"{path}: {name} {rows['Timestamp'][times.isna()].iloc[0]!r} is not ISO 8601, "
            "like 2024-06-15T10:00:00Z")
    seconds = times.dt.tz_localize(None).to_numpy().astype("datetime64[s]")
    text = pd.Series(seconds.astype(str), index=rows.index) + "Z"
    rows["Timestamp"] = text
    return rows


def _header_separator(path, mapping: "Mapping") -> str | None:
    with open(path, encoding="utf-8-sig", newline="") as handle:
        header = handle.readline()
    for separator in (";", "\t"):
        names = next(csv.reader([header], delimiter=separator))
        if all(mapping.columns[name] in names for name in REQUIRED):
            return separator
    return None


def _distinct(rows: pd.DataFrame, column: str) -> pd.Series:
    values = rows[["IncidentId", column]]
    values = values.assign(**{column: values[column].str.split(SEPARATOR)})
    values = values.explode(column)
    values[column] = values[column].str.strip()
    values = values[values[column] != ""].drop_duplicates().sort_values(column)
    return values.groupby("IncidentId")[column].agg(SEPARATOR.join)
