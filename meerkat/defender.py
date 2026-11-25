# Reads incidents and their classification from Microsoft Defender XDR through Microsoft Graph, read only.

import json
import os
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import pandas as pd

from core.incidents import CLASSIFICATIONS, COLUMNS, SEPARATOR, collapse

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"
VARIABLES = ("MEERKAT_TENANT_ID", "MEERKAT_CLIENT_ID", "MEERKAT_CLIENT_SECRET")
TIMEOUT = 60
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


class PullError(ValueError):
    pass


def fetch(since: str | None) -> list[dict]:
    missing = [name for name in VARIABLES if not os.environ.get(name)]
    if missing:
        raise PullError(f"set the environment variable {', '.join(missing)}")
    tenant, client, secret = (os.environ[name] for name in VARIABLES)
    form = urlencode({"client_id": client, "scope": SCOPE, "client_secret": secret,
                      "grant_type": "client_credentials"}).encode()
    address = f"{LOGIN}/{quote(tenant, safe='')}/oauth2/v2.0/token"
    token = _read(Request(address, data=form)).get("access_token")
    if not isinstance(token, str):
        raise PullError(f"{address}: the answer holds no access_token")

    query = {"$expand": "alerts"}
    if since is not None:
        query["$filter"] = f"lastUpdateDateTime ge {since}"
    link = f"{GRAPH}/security/incidents?{urlencode(query, quote_via=quote)}"
    found = []
    while link:
        # the token goes to Graph only, wherever a next page link points
        if not link.startswith(GRAPH):
            raise PullError(f"{link}: a next page outside {GRAPH}")
        page = _read(Request(link, headers={"Authorization": f"Bearer {token}"}))
        if not isinstance(page.get("value"), list):
            raise PullError(f"{link}: the answer holds no list of incidents")
        found += page["value"]
        link = page.get("@odata.nextLink")
    return found


def incidents(found: list[dict]) -> tuple[pd.DataFrame, str | None]:
    try:
        updated = max((incident["lastUpdateDateTime"] for incident in found), default=None)
        return _table(found), updated
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise PullError(f"{GRAPH}: an incident is not as Microsoft Graph documents it "
                        f"({error!r})") from None


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


def _read(request: Request) -> dict:
    with urlopen(request, timeout=TIMEOUT) as answer:
        body = answer.read()
    try:
        found = json.loads(body)
    except ValueError:
        raise PullError(f"{request.full_url}: the answer is not JSON") from None
    if not isinstance(found, dict):
        raise PullError(f"{request.full_url}: the answer is not a JSON object")
    return found
