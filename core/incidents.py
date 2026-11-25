# Reads incidents in meerkat's own columns and folds rows in those columns into one row per incident.

import csv

import pandas as pd

REQUIRED = ("IncidentId", "Timestamp", "DetectorId")
DESCRIPTIVE = ("AlertTitle", "Category", "Severity", "IncidentUrl")
LINKS = (
    "DeviceId", "DeviceName", "AccountObjectId", "AccountSid", "AccountUpn",
    "AccountName", "IpAddress", "Sha256", "Url",
)
CLASSIFICATIONS = ("TruePositive", "BenignPositive", "FalsePositive")
COLUMNS = (*REQUIRED, "IncidentGrade", *DESCRIPTIVE, "MitreTechniques", *LINKS)
SEPARATOR = "|"
CLOSED = "closed"


class IncidentError(ValueError):
    pass


def read_table(path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except UnicodeDecodeError:
        with open(path, "rb") as handle:
            utf16 = handle.read(2) in (b"\xff\xfe", b"\xfe\xff")
        raise IncidentError(
            f"{path}: is {'UTF-16' if utf16 else 'not UTF-8'}, save it as UTF-8") from None
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise IncidentError(f"{path}: not a readable CSV ({error})") from None


def read_incidents(path, table: pd.DataFrame) -> pd.DataFrame:
    missing = [name for name in REQUIRED if name not in table.columns]
    if missing:
        raise IncidentError(f"{path}: missing column {', '.join(missing)}")
    if "OrgId" in table.columns:
        organisations = table["OrgId"].str.strip()
        organisations = organisations[organisations != ""]
        if organisations.nunique() > 1:
            raise IncidentError(
                f"{path}: {organisations.nunique()} organisations in OrgId, "
                "a file holds one organisation")
    rows = table.reindex(columns=list(COLUMNS), fill_value="")
    rows = rows.apply(lambda column: column.str.strip())
    unknown = rows.loc[~rows["IncidentGrade"].isin(("", *CLASSIFICATIONS)), "IncidentGrade"]
    if len(unknown):
        raise IncidentError(f"{path}: IncidentGrade {unknown.iloc[0]!r} is not one of "
                            f"{', '.join(CLASSIFICATIONS)}")
    for name in LINKS:
        rows[name] = rows[name].str.replace(SEPARATOR, "%7C", regex=False)
    rows["MitreTechniques"] = rows["MitreTechniques"].str.replace(";", SEPARATOR, regex=False)
    return finish(path, rows, {name: name for name in COLUMNS})


def finish(path, rows: pd.DataFrame, names: dict[str, str]) -> pd.DataFrame:
    if rows.empty:
        raise IncidentError(f"{path}: no incident rows")
    for name in REQUIRED:
        blank = int((rows[name] == "").sum())
        if blank:
            raise IncidentError(f"{path}: {blank} rows have no {names[name]}")
    times = pd.to_datetime(rows["Timestamp"], utc=True, format="ISO8601", errors="coerce")
    if times.isna().any():
        raise IncidentError(
            f"{path}: {names['Timestamp']} {rows['Timestamp'][times.isna()].iloc[0]!r} is not "
            "a time meerkat reads, like 2024-06-15T10:00:00Z")
    seconds = times.dt.tz_localize(None).to_numpy().astype("datetime64[s]")
    rows = rows.assign(Timestamp=pd.Series(seconds.astype(str), index=rows.index) + "Z")
    return collapse(rows)


def read_classifications(path) -> list[tuple[str, str]]:
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
        raise IncidentError(f"{path}: no classification rows")
    classifications = []
    for row in rows:
        incident = (row["IncidentId"] or "").strip()
        classification = (row["IncidentGrade"] or "").strip()
        if not incident:
            raise IncidentError(f"{path}: a row has no IncidentId")
        if classification not in CLASSIFICATIONS:
            raise IncidentError(
                f"{path}: IncidentGrade {classification!r} is not one of "
                f"{', '.join(CLASSIFICATIONS)}")
        classifications.append((incident, classification))
    return classifications


def collapse(rows: pd.DataFrame) -> pd.DataFrame:
    # an incident takes its time, rule, title and category from its earliest row
    classifications = rows["IncidentGrade"].replace("", pd.NA).groupby(rows["IncidentId"]).last()
    rows = rows.sort_values("Timestamp", kind="stable")
    by_incident = rows.groupby("IncidentId", sort=False)

    incidents = by_incident[["Timestamp", "DetectorId", *DESCRIPTIVE]].first()
    incidents["IncidentGrade"] = classifications
    # the link is opened from the page, so only an https address is kept
    incidents["IncidentUrl"] = incidents["IncidentUrl"].where(
        incidents["IncidentUrl"].str.startswith("https://", na=False), "")
    for column in ("MitreTechniques", *LINKS):
        incidents[column] = _distinct(rows, column)
    return incidents.fillna("").reset_index()[list(COLUMNS)]


def _distinct(rows: pd.DataFrame, column: str) -> pd.Series:
    values = rows[["IncidentId", column]]
    values = values.assign(**{column: values[column].str.split(SEPARATOR)})
    values = values.explode(column)
    values[column] = values[column].str.strip()
    values = values[values[column] != ""].drop_duplicates().sort_values(column)
    return values.groupby("IncidentId")[column].agg(SEPARATOR.join)
