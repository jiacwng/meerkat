# Reads a file of Microsoft Defender XDR incidents as Microsoft Graph returns them, with their alerts.

import json

import pandas as pd

from core.incidents import CLASSIFICATIONS, COLUMNS, SEPARATOR, IncidentError, collapse

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
    if not isinstance(answer, dict) or not isinstance(answer.get("value"), list):
        raise IncidentError(f"{path}: expected a JSON object with the list of incidents "
                            "under value")
    try:
        incidents = _table(answer["value"])
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise IncidentError(f"{path}: an incident is not as Microsoft Graph documents it "
                            f"({error!r})") from None
    if incidents.empty:
        raise IncidentError(f"{path}: no incident with an alert")
    return incidents


def _table(found: list[dict]) -> pd.DataFrame:
    rows = []
    for incident in found:
        for alert in incident.get("alerts") or []:
            if not alert.get("detectorId") or not alert.get("createdDateTime"):
                continue
            row = dict.fromkeys(COLUMNS, "")
            row["IncidentId"] = str(incident["id"])
            row["Timestamp"] = alert["createdDateTime"]
            row["DetectorId"] = alert["detectorId"]
            row["IncidentGrade"] = CLASSIFICATION.get(incident.get("classification"), "")
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


def _value(evidence: dict, path: tuple[str, ...]) -> str:
    value = evidence
    for key in path:
        value = (value or {}).get(key)
    return str(value or "").strip().replace(SEPARATOR, "%7C")
