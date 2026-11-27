# Reads Defender XDR incidents from the JSON that Microsoft Graph answers to GET /security/incidents?$expand=alerts.

import json

import pandas as pd

from core.incidents import (
    CLASSIFICATIONS,
    CLOSED,
    COLUMNS,
    SEPARATOR,
    IncidentError,
    collapse,
)

STATUSES = ("active", "resolved", "inProgress", "redirected", "awaitingAction",
            "unknownFutureValue")
CLASSIFICATION = {
    "unknown": "", "unknownFutureValue": "",
    "truePositive": CLASSIFICATIONS[0],
    "informationalExpectedActivity": CLASSIFICATIONS[1],
    "falsePositive": CLASSIFICATIONS[2],
}
EVIDENCE = {
    "#microsoft.graph.security.deviceEvidence": {
        "DeviceId": ("mdeDeviceId",), "DeviceName": ("deviceDnsName",)},
    "#microsoft.graph.security.userEvidence": {
        "AccountObjectId": ("userAccount", "azureAdUserId"),
        "AccountSid": ("userAccount", "userSid"),
        "AccountUpn": ("userAccount", "userPrincipalName"),
        "AccountName": ("userAccount", "accountName")},
    "#microsoft.graph.security.ipEvidence": {"IpAddress": ("ipAddress",)},
    "#microsoft.graph.security.fileEvidence": {"Sha256": ("fileDetails", "sha256")},
    "#microsoft.graph.security.urlEvidence": {"Url": ("url",)},
}


def read_graph(path) -> pd.DataFrame:
    try:
        with open(path, "rb") as handle:
            answer = json.loads(handle.read())
    except FileNotFoundError:
        raise IncidentError(f"{path}: no such file") from None
    except (OSError, ValueError, RecursionError) as error:
        raise IncidentError(f"{path}: not a readable JSON file ({error})") from None
    pages = answer if isinstance(answer, list) else [answer]
    if not pages or not all(isinstance(page, dict) and isinstance(page.get("value"), list)
                            for page in pages):
        raise IncidentError(f"{path}: expected the answer of Microsoft Graph, a JSON object "
                            "with the list of incidents under value")
    rows = []
    for incident in (incident for page in pages for incident in page["value"]):
        try:
            rows += _rows(incident)
        except (TypeError, ValueError, AttributeError) as error:
            raise IncidentError(f"{path}: an incident is not as Microsoft Graph documents it, "
                                f"{error}") from None
    if not rows:
        raise IncidentError(f"{path}: no incidents under value")
    table = pd.DataFrame(rows, columns=list(COLUMNS))
    times = pd.to_datetime(table["Timestamp"], utc=True, format="ISO8601", errors="coerce")
    if times.isna().any():
        raise IncidentError(f"{path}: createdDateTime {table['Timestamp'][times.isna()].iloc[0]!r}"
                            " is not a time meerkat reads, like 2024-06-15T10:00:00Z")
    table["Timestamp"] = times.dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # an incident takes the rule of its earliest alert that names one
    named = table[table["DetectorId"] != ""].sort_values("Timestamp", kind="stable")
    rule = named.groupby("IncidentId")["DetectorId"].first()
    table["DetectorId"] = table["IncidentId"].map(rule).fillna("")
    unruled = table.loc[(table["DetectorId"] == "") & (table["IncidentGrade"] != CLOSED),
                        "IncidentId"]
    if len(unruled):
        raise IncidentError(f"{path}: incident {unruled.iloc[0]!r} is open or classified and "
                            "none of its alerts has a detectorId")
    return collapse(table)


def _rows(incident: dict) -> list[dict]:
    if not isinstance(incident, dict):
        raise TypeError("the incident is not an object")
    number = _required(incident, "id")
    try:
        state = _state(incident)
        alerts = incident.get("alerts") or []
        if not isinstance(alerts, list):
            raise TypeError("alerts is not a list")
        rows = []
        if not alerts:
            row = dict.fromkeys(COLUMNS, "")
            row.update(IncidentId=number, Timestamp=_required(incident, "createdDateTime"),
                       IncidentGrade=state)
            rows.append(row)
        for alert in alerts:
            row = dict.fromkeys(COLUMNS, "")
            row.update(
                IncidentId=number, Timestamp=_required(alert, "createdDateTime"),
                DetectorId=_text(alert, "detectorId"), IncidentGrade=state,
                AlertTitle=_text(alert, "title"), Category=", ".join(_texts(alert, "categories")),
                Severity=_text(incident, "severity"),
                IncidentUrl=_text(incident, "incidentWebUrl"),
                MitreTechniques=SEPARATOR.join(_texts(alert, "mitreTechniques")))
            evidence = alert.get("evidence") or []
            if not isinstance(evidence, list):
                raise TypeError("evidence is not a list")
            for found in evidence:
                for column, keys in EVIDENCE.get(found.get("@odata.type"), {}).items():
                    value = _nested(found, keys)
                    if value:
                        row[column] = SEPARATOR.join(filter(None, (row[column], value)))
            rows.append(row)
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError(f"incident {number!r}: {error}") from None
    return rows


def _state(incident: dict) -> str:
    status = _required(incident, "status")
    classification = _text(incident, "classification") or "unknown"
    if status not in STATUSES:
        raise ValueError(f"status {status!r} is not one of {', '.join(STATUSES)}")
    if classification not in CLASSIFICATION:
        raise ValueError(f"classification {classification!r} is not one of "
                         f"{', '.join(CLASSIFICATION)}")
    match status:
        case "redirected":
            return CLOSED
        case "resolved":
            return CLASSIFICATION[classification] or CLOSED
        case _:
            return ""


def _text(found: dict, key: str) -> str:
    value = found.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TypeError(f"{key} is not a string")
    return value.strip()


def _required(found: dict, key: str) -> str:
    value = _text(found, key)
    if not value:
        raise ValueError(f"no {key}")
    return value


def _texts(found: dict, key: str) -> list[str]:
    values = found.get(key) or []
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"{key} is not a list of strings")
    return [value.strip() for value in values if value.strip()]


def _nested(found: dict, keys: tuple[str, ...]) -> str:
    for key in keys[:-1]:
        found = found.get(key) or {}
    return _text(found, keys[-1]).replace(SEPARATOR, "%7C")
