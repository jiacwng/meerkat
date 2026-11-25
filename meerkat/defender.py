# Reads the file `meerkat query defender` saves: Defender XDR incidents as Microsoft Graph answers.

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

CLASSIFICATION = {
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


def read_incidents(path) -> pd.DataFrame:
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
    try:
        incidents = _table([incident for page in pages for incident in page["value"]])
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise IncidentError(f"{path}: an incident is not as Microsoft Graph documents it "
                            f"({error!r})") from None
    if incidents.empty:
        raise IncidentError(f"{path}: no incident with an alert, and none closed")
    return incidents


def _table(found: list[dict]) -> pd.DataFrame:
    rows = []
    for incident in found:
        state = _state(incident)
        alerts = [alert for alert in incident.get("alerts") or []
                  if alert.get("detectorId") and alert.get("createdDateTime")]
        if state == CLOSED and not alerts:
            # a merged incident has lost its alerts, and the row still has to say it is closed
            row = dict.fromkeys(COLUMNS, "")
            row["IncidentId"] = str(incident["id"])
            row["Timestamp"] = incident["createdDateTime"]
            row["IncidentGrade"] = CLOSED
            rows.append(row)
        for alert in alerts:
            row = dict.fromkeys(COLUMNS, "")
            row["IncidentId"] = str(incident["id"])
            row["Timestamp"] = alert["createdDateTime"]
            row["DetectorId"] = alert["detectorId"]
            row["IncidentGrade"] = state
            row["AlertTitle"] = alert.get("title") or ""
            row["Category"] = alert.get("category") or ""
            row["Severity"] = incident.get("severity") or ""
            row["IncidentUrl"] = incident.get("incidentWebUrl") or ""
            row["MitreTechniques"] = SEPARATOR.join(alert.get("mitreTechniques") or [])
            for evidence in alert.get("evidence") or []:
                for column, path in EVIDENCE.get(evidence.get("@odata.type"), {}).items():
                    value = _value(evidence, path)
                    if value:
                        row[column] = SEPARATOR.join(filter(None, (row[column], value)))
            rows.append(row)
    table = pd.DataFrame(rows, columns=list(COLUMNS))
    if table.empty:
        return table
    times = pd.to_datetime(table["Timestamp"], utc=True, format="ISO8601")
    table["Timestamp"] = times.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return collapse(table)


def _state(incident: dict) -> str:
    status = incident["status"]
    if status == "redirected":
        return CLOSED
    if status != "resolved":
        return ""
    return CLASSIFICATION.get(incident.get("classification"), CLOSED)


def _value(evidence: dict, path: tuple[str, ...]) -> str:
    value = evidence
    for key in path:
        value = (value or {}).get(key)
    return str(value or "").strip().replace(SEPARATOR, "%7C")
