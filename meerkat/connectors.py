from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.normalize import get_timestamp, read_alert_record


class ConnectorError(Exception):
    pass


@dataclass
class Window:
    start: float
    end: float

    def contains(self, moment: float) -> bool:
        return self.start <= moment < self.end


@dataclass
class IndexerConfig:
    host: str
    port: int = 9200
    index: str = "wazuh-alerts-*"
    user: str | None = None
    password: str | None = None
    token: str | None = None
    verify_tls: bool = True
    page_size: int = 500
    keep_alive: str = "1m"
    timeout: float = 30.0


def parse_moment(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        pass
    stamp = datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.timestamp()


def day_window(day: str) -> Window:
    start = datetime.fromisoformat(day)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return Window(start.timestamp(), (start + timedelta(days=1)).timestamp())


def read_window_file(path: Path, window: Window) -> list[dict]:
    records = []
    with path.open(encoding="utf-8-sig", errors="replace") as handle:
        for position, line in enumerate(handle):
            record = read_alert_record(line, path, position)
            if record is None:
                continue
            try:
                moment = get_timestamp(record, "wazuh")
            except (KeyError, ValueError, TypeError):
                continue
            if window.contains(moment):
                records.append(record)
    return records


def write_records(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")


def _send(config: IndexerConfig, method: str, path: str, body: dict | None) -> dict:
    url = f"https://{config.host}:{config.port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if config.token:
        request.add_header("Authorization", config.token)
    elif config.user is not None:
        raw = f"{config.user}:{config.password or ''}".encode()
        request.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    context = ssl.create_default_context()
    if not config.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            request, context=context, timeout=config.timeout
        ) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise ConnectorError("the indexer rejected the credentials") from error
        raise ConnectorError(f"the indexer returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", error)
        raise ConnectorError(
            f"cannot reach the indexer at {config.host}:{config.port}: {reason}"
        ) from error
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise ConnectorError("the indexer returned a response that is not JSON") from error
    except RecursionError as error:
        raise ConnectorError(
            "the indexer returned a response nested too deeply to parse"
        ) from error


def _open_pit(config: IndexerConfig) -> str | None:
    path = f"/{config.index}/_search/point_in_time?keep_alive={config.keep_alive}"
    try:
        return _send(config, "POST", path, None).get("pit_id")
    except ConnectorError:
        return None


def _close_pit(config: IndexerConfig, pit_id: str) -> None:
    try:
        _send(config, "DELETE", "/_search/point_in_time", {"pit_id": pit_id})
    except ConnectorError:
        pass


def query_window(config: IndexerConfig, window: Window) -> list[dict]:
    pit_id = _open_pit(config)
    query = {
        "range": {
            "@timestamp": {
                "gte": datetime.fromtimestamp(window.start, UTC).isoformat(),
                "lt": datetime.fromtimestamp(window.end, UTC).isoformat(),
            }
        }
    }
    sort = [{"@timestamp": "asc"}, {"_id": "asc"}]
    path = "/_search" if pit_id else f"/{config.index}/_search"
    records: list[dict] = []
    after = None
    try:
        while True:
            body: dict = {"size": config.page_size, "sort": sort, "query": query}
            if pit_id:
                body["pit"] = {"id": pit_id, "keep_alive": config.keep_alive}
            if after is not None:
                body["search_after"] = after
            result = _send(config, "POST", path, body)
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break
            try:
                records.extend(hit["_source"] for hit in hits)
                after = hits[-1]["sort"]
            except KeyError as error:
                raise ConnectorError(
                    "the indexer returned a hit without _source or sort"
                ) from error
            pit_id = result.get("pit_id", pit_id)
    finally:
        if pit_id:
            _close_pit(config, pit_id)
    return records
