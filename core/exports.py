# Picks the reader of an incident file by its header: Defender's queue export, a Splunk search export or meerkat's own columns.

import csv
import re

import pandas as pd

from core.incidents import (
    CLASSIFICATIONS,
    CLOSED,
    COLUMNS,
    LINKS,
    SEPARATOR,
    IncidentError,
    finish,
    read_incidents,
    read_table,
)

TRUE_POSITIVE, BENIGN_POSITIVE, FALSE_POSITIVE = CLASSIFICATIONS

DEFENDER_COLUMNS = (
    "Incident name", "Incident Id", "Priority score", "Tags", "Severity",
    "Investigation state", "Categories", "Impacted assets", "Active alerts", "Service sources",
    "Detection sources", "Product names", "Last update time", "Last activity", "Policy name",
    "Data sensitivity", "Status", "Assigned to", "Classification", "Determination",
    "Device groups", "Creation time", "Workspaces", "Cloud Scopes", "First activity",
    "Policy rule name", "Data stream", "Sensitivity labels", "Alert subscription ID",
    "Tenant name", "System tags",
)
DEFENDER_READ = {
    "IncidentId": "Incident Id", "Timestamp": "Creation time", "DetectorId": "Policy name",
    "AlertTitle": "Incident name", "Category": "Categories", "Severity": "Severity",
}
DEFENDER_LINK = "https://security.microsoft.com/incident2/{incident}/overview?tid={tenant}"
DEFENDER_STATUS = ("Active", "In Progress", "Awaiting Customer Action", "Resolved")
DEFENDER_CLASSIFICATION = {
    "Not set": CLOSED, "True alert": TRUE_POSITIVE, "Benign Positive": BENIGN_POSITIVE,
    "False alert": FALSE_POSITIVE,
}
ASSETS = {
    "Devices": "DeviceName", "Accounts": "AccountName", "Mailboxes": None, "Apps": None,
    "Cloud Resources": None, "AI agents": None,
}
ASSET_LABEL = re.compile(r"(?:^|,)([A-Za-z][A-Za-z ]*): ")
# the portal puts an apostrophe before a cell that a spreadsheet would read as a formula
FORMULA = re.compile(r"^'(?=[=+\-@])")

SPLUNK_COLUMNS = (
    "_time", "event_id", "rule_id", "rule_name", "rule_title", "security_domain", "urgency",
    "status_group", "status_label", "disposition_label", "owner", "src", "dest", "user",
)
SPLUNK_READ = {
    "IncidentId": "rule_id", "Timestamp": "_time", "DetectorId": "rule_name",
    "AlertTitle": "rule_title", "Category": "security_domain",
    "IncidentGrade": "disposition_label", "IpAddress": "src", "DeviceName": "dest",
    "AccountName": "user",
}
SPLUNK_DISPOSITION = {
    "Undetermined": "", "Other": "",
    "True Positive - Suspicious Activity": TRUE_POSITIVE,
    "Benign Positive - Suspicious But Expected": BENIGN_POSITIVE,
    "False Positive - Incorrect Analytic Logic": FALSE_POSITIVE,
    "False Positive - Inaccurate Data": FALSE_POSITIVE,
}
SPLUNK_TIME = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?) (?:GMT|UTC)$")


def read(path, defender_tenant: str | None = None) -> tuple[pd.DataFrame, str]:
    table = read_table(path)
    for source, mark, reader in LAYOUTS:
        if mark in table.columns:
            incidents = reader(path, table)
            if source == "defender" and defender_tenant:
                incidents["IncidentUrl"] = [
                    DEFENDER_LINK.format(incident=incident, tenant=defender_tenant)
                    if incident.isascii() and incident.isdigit() else ""
                    for incident in incidents["IncidentId"]]
            return incidents, source
    with open(path, encoding="utf-8-sig", newline="") as handle:
        header = handle.readline()
    for separator in (";", "\t"):
        names = set(next(csv.reader([header], delimiter=separator)))
        if any(mark in names for _, mark, _ in LAYOUTS):
            raise IncidentError(f"{path}: columns are separated by {separator!r}, expected ','")
    raise IncidentError(
        f"{path}: not a Defender queue export, a Splunk search export or a file with "
        "meerkat's columns IncidentId, Timestamp and DetectorId")


def read_defender(path, table: pd.DataFrame) -> pd.DataFrame:
    _known_columns(path, table, DEFENDER_COLUMNS, "the Defender queue export")
    _required(path, table, (*DEFENDER_READ.values(), "Status", "Classification",
                            "Impacted assets"))
    cells = table.apply(lambda column: column.str.strip().str.replace(FORMULA, "", regex=True))
    cells = cells.replace("-", "")
    rows = pd.DataFrame("", index=cells.index, columns=list(COLUMNS))
    for name, source in DEFENDER_READ.items():
        rows[name] = cells[source]
    rows["DetectorId"] = rows["DetectorId"].where(rows["DetectorId"] != "", rows["AlertTitle"])
    _known_words(path, cells["Status"], "Status", DEFENDER_STATUS)
    _known_words(path, cells["Classification"], "Classification", DEFENDER_CLASSIFICATION)
    rows["IncidentGrade"] = cells["Classification"].map(DEFENDER_CLASSIFICATION).where(
        cells["Status"] == "Resolved", "")
    assets = [_assets(path, cell, position + 1)
              for position, cell in enumerate(cells["Impacted assets"])]
    for column in filter(None, ASSETS.values()):
        rows[column] = [found.get(column, "") for found in assets]
    return finish(path, rows, {name: DEFENDER_READ.get(name, name) for name in COLUMNS})


def read_splunk(path, table: pd.DataFrame) -> pd.DataFrame:
    _known_columns(path, table, SPLUNK_COLUMNS, "a Splunk notable event")
    _required(path, table, ("rule_id", "_time", "rule_name"))
    cells = table.apply(lambda column: column.str.strip())
    rows = pd.DataFrame("", index=cells.index, columns=list(COLUMNS))
    for name, source in SPLUNK_READ.items():
        if source in cells.columns:
            rows[name] = cells[source]
    _known_words(path, rows["IncidentGrade"], "disposition_label", ("", *SPLUNK_DISPOSITION))
    rows["IncidentGrade"] = rows["IncidentGrade"].map({"": "", **SPLUNK_DISPOSITION})
    rows["Timestamp"] = rows["Timestamp"].str.replace(SPLUNK_TIME, r"\1T\2Z", regex=True)
    # a multi value field holds one value per line
    for name in LINKS:
        rows[name] = rows[name].map(lambda cell: SEPARATOR.join(
            value.strip().replace(SEPARATOR, "%7C") for value in cell.splitlines()
            if value.strip()))
    return finish(path, rows, {name: SPLUNK_READ.get(name, name) for name in COLUMNS})


LAYOUTS = (
    ("defender", "Incident Id", read_defender),
    ("splunk", "rule_id", read_splunk),
    ("meerkat", "IncidentId", read_incidents),
)


def _known_columns(path, table: pd.DataFrame, known: tuple[str, ...], layout: str) -> None:
    unknown = [name for name in table.columns if name not in known]
    if unknown:
        raise IncidentError(f"{path}: column {unknown[0]!r} is not a column of {layout}")


def _required(path, table: pd.DataFrame, names: tuple[str, ...]) -> None:
    missing = [name for name in names if name not in table.columns]
    if missing:
        raise IncidentError(f"{path}: missing column {', '.join(missing)}")


def _known_words(path, cells: pd.Series, column: str, known) -> None:
    unknown = ~cells.isin(list(known))
    if unknown.any():
        row = int(unknown.to_numpy().argmax()) + 1
        raise IncidentError(f"{path}: {column} {cells[unknown].iloc[0]!r} in row {row} is not "
                            f"one of {', '.join(word for word in known if word)}")


def _assets(path, cell: str, row: int) -> dict[str, str]:
    if not cell:
        return {}
    parts = ASSET_LABEL.split(cell)
    if parts[0]:
        raise IncidentError(f"{path}: Impacted assets {cell!r} in row {row} does not start "
                            "with a group such as Devices:")
    found = {}
    for label, values in zip(parts[1::2], parts[2::2], strict=True):
        if label not in ASSETS:
            raise IncidentError(f"{path}: Impacted assets group {label!r} in row {row} is not "
                                f"one of {', '.join(ASSETS)}")
        if ASSETS[label]:
            found[ASSETS[label]] = SEPARATOR.join(
                value.strip().replace(SEPARATOR, "%7C") for value in values.split(",")
                if value.strip())
    return found
