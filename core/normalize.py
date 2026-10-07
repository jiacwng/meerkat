# Reads Wazuh, Suricata and AMiner alert exports and normalizes them into one alert
# table with the same columns whatever detector wrote the alert.

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path

import pandas as pd

from core.inventory import Inventory, load_inventory

CHUNK_ROWS = 10_000

COLUMNS = [
    "detector_source", "timestamp", "name", "host", "entity_id", "observer_id",
    "entity_in_inventory", "severity", "attack_window", "native_technique_ids",
    "rule_id", "source_file",
    "native_event_id", "source_position", "source_ip", "destination_ip", "source_port",
    "destination_port", "network_protocol", "application_protocol",
    "source_user", "target_user", "command", "executable", "working_directory",
    "web_request", "http_method", "http_status", "http_hostname",
    "http_user_agent", "alert_category", "rule_groups", "rule_fired_times",
    "flow_bytes_to_server", "flow_bytes_to_client", "flow_packets_to_server",
    "flow_packets_to_client", "tls_server_name", "tls_version", "tls_ja3",
    "dns_query", "analysis_component_type", "training_mode",
    "affected_log_paths", "affected_log_frequencies", "log_resource",
    "log_lines_count", "critical_value", "probability_threshold",
    "anomaly_scores", "cpu_total_pct", "cpu_nice_pct",
]

CATEGORICAL_COLUMNS = [
    "detector_source", "name", "host", "entity_id", "observer_id", "attack_window",
    "native_technique_ids", "rule_id", "native_event_id", "source_file", "source_ip",
    "destination_ip", "network_protocol", "application_protocol",
    "alert_category", "rule_groups", "analysis_component_type",
    "affected_log_paths", "log_resource", "http_method", "tls_version",
]


@dataclass
class ExtractedFields:
    name: str
    host: str
    entity_id: str
    observer_id: str
    entity_in_inventory: bool
    severity: float
    native_technique_ids: str = ""   # ";"-joined ATT&CK IDs
    rule_id: str = ""                # stable detector rule identity
    native_event_id: str = ""
    source_user: str = ""
    target_user: str = ""
    command: str = ""
    executable: str = ""
    working_directory: str = ""
    web_request: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: float = float("nan")
    destination_port: float = float("nan")
    network_protocol: str = ""
    application_protocol: str = ""
    http_method: str = ""
    http_status: float = float("nan")
    http_hostname: str = ""
    http_user_agent: str = ""
    alert_category: str = ""
    rule_groups: str = ""
    rule_fired_times: float = float("nan")
    flow_bytes_to_server: float = float("nan")
    flow_bytes_to_client: float = float("nan")
    flow_packets_to_server: float = float("nan")
    flow_packets_to_client: float = float("nan")
    tls_server_name: str = ""
    tls_version: str = ""
    tls_ja3: str = ""
    dns_query: str = ""
    analysis_component_type: str = ""
    training_mode: float = float("nan")
    affected_log_paths: str = ""
    affected_log_frequencies: str = ""
    log_resource: str = ""
    log_lines_count: float = float("nan")
    critical_value: float = float("nan")
    probability_threshold: float = float("nan")
    anomaly_scores: str = ""
    cpu_total_pct: float = float("nan")
    cpu_nice_pct: float = float("nan")


def optional_float(value: object) -> float:
    if value is None or value == "":
        return float("nan")
    return float(value)


def load_attack_windows(labels_path: Path, scenario: str) -> list[tuple[float, float, str]]:
    with labels_path.open(encoding="utf-8") as fh:
        return [
            (float(row["start"]), float(row["end"]), row["attack"])
            for row in csv.DictReader(fh)
            if row["scenario"] == scenario
        ]


def find_attack_window(timestamp: float, windows: list[tuple[float, float, str]]) -> str:
    for start, end, phase in windows:
        if start <= timestamp <= end:
            return phase
    return ""


def get_timestamp(record: dict, detector: str) -> float:
    if detector == "aminer":
        return float(record["LogData"]["Timestamps"][0])
    stamp = datetime.fromisoformat(record.get("@timestamp") or record["timestamp"])
    # an export without a zone is UTC, not the reading machine's local time
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.timestamp()


def extract_wazuh_fields(
    record: dict,
    inventory: Inventory,
) -> ExtractedFields:
    rule = record["rule"]
    data = record.get("data", {})
    audit = data.get("audit", {})
    agent = record["agent"]
    agent_ip = str(agent.get("ip") or "")
    host = record.get("predecoder", {}).get("hostname")
    if not host:
        asset = inventory.assets_by_ip.get(agent_ip)
        host = asset.hostname if asset else agent_ip or agent["name"]
    mitre = rule.get("mitre") or {}
    mitre_ids = mitre.get("id") or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    native_event_id = str(data.get("id") or "")
    http_status = float("nan")
    if native_event_id.isdigit() and 100 <= int(native_event_id) <= 599:
        http_status = float(native_event_id)
    return ExtractedFields(
        name=rule["description"],
        host=host,
        entity_id=agent_ip or str(host),
        observer_id=agent_ip or str(agent.get("name") or ""),
        entity_in_inventory=agent_ip in inventory,
        severity=float(rule["level"]),
        native_technique_ids=";".join(str(one) for one in mitre_ids),
        rule_id=str(rule.get("id", "")),
        native_event_id=native_event_id,
        source_user=str(data.get("srcuser") or ""),
        target_user=str(data.get("dstuser") or ""),
        command=str(data.get("command") or ""),
        executable=str(data.get("exe") or audit.get("exe") or ""),
        working_directory=str(
            data.get("pwd") or data.get("cwd") or audit.get("cwd") or ""
        ),
        web_request=str(data.get("url") or data.get("http", {}).get("url") or ""),
        source_ip=str(data.get("srcip") or data.get("src_ip") or ""),
        destination_ip=str(data.get("dstip") or data.get("dest_ip") or ""),
        source_port=optional_float(data.get("srcport") or data.get("src_port")),
        destination_port=optional_float(
            data.get("dstport") or data.get("dest_port")
        ),
        network_protocol=str(data.get("protocol") or data.get("proto") or "").lower(),
        http_status=http_status,
        rule_groups=";".join(str(group) for group in rule.get("groups") or []),
        rule_fired_times=optional_float(rule.get("firedtimes")),
    )


def extract_suricata_fields(
    record: dict,
    inventory: Inventory,
) -> ExtractedFields:
    data = record["data"]
    alert = data["alert"]
    source_ip = str(data.get("src_ip") or "")
    destination_ip = str(data.get("dest_ip") or "")
    if destination_ip in inventory:
        entity_id = destination_ip
    elif source_ip in inventory:
        entity_id = source_ip
    else:
        entity_id = destination_ip or source_ip

    agent = record.get("agent", {})
    observer_id = str(agent.get("ip") or agent.get("name") or "")
    asset = inventory.assets_by_ip.get(entity_id)

    flow = data.get("flow", {})
    http = data.get("http", {})
    tls = data.get("tls", {})
    ja3 = tls.get("ja3", {})
    dns_queries = data.get("dns", {}).get("query", [])
    dns_query = ""
    if dns_queries:
        first_query = dns_queries[0]
        if isinstance(first_query, dict):
            dns_query = str(first_query.get("rrname") or "")

    metadata = alert.get("metadata") or {}
    embedded = metadata.get("mitre_technique_id") or []
    if isinstance(embedded, str):
        embedded = [embedded]

    return ExtractedFields(
        name=alert["signature"],
        host=asset.hostname if asset else entity_id,
        entity_id=entity_id,
        observer_id=observer_id,
        entity_in_inventory=entity_id in inventory,
        severity=float(alert["severity"]),
        native_technique_ids=";".join(str(t) for t in embedded),
        rule_id=str(alert.get("signature_id", "")),
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=optional_float(data.get("src_port")),
        destination_port=optional_float(data.get("dest_port")),
        network_protocol=str(data.get("proto") or "").lower(),
        application_protocol=str(data.get("app_proto") or "").lower(),
        web_request=str(http.get("url") or ""),
        http_method=str(http.get("http_method") or ""),
        http_status=optional_float(http.get("status")),
        http_hostname=str(http.get("hostname") or ""),
        http_user_agent=str(http.get("http_user_agent") or ""),
        alert_category=str(alert.get("category") or ""),
        flow_bytes_to_server=optional_float(flow.get("bytes_toserver")),
        flow_bytes_to_client=optional_float(flow.get("bytes_toclient")),
        flow_packets_to_server=optional_float(flow.get("pkts_toserver")),
        flow_packets_to_client=optional_float(flow.get("pkts_toclient")),
        tls_server_name=str(tls.get("sni") or ""),
        tls_version=str(tls.get("version") or ""),
        tls_ja3=str(ja3.get("hash") or ""),
        dns_query=dns_query,
    )


def aminer_log_resources(record: dict) -> list[str]:
    resources = (record.get("LogData") or {}).get("LogResources")
    if not resources:
        single = (record.get("AnalysisComponent") or {}).get("LogResource")
        resources = [single] if single else []
    if isinstance(resources, str):
        resources = [resources]
    if not isinstance(resources, list):
        return []
    return [str(resource) for resource in resources]


def aminer_host_candidates(record: dict) -> set[str]:
    candidates = set()
    raw_lines = record["LogData"]["RawLogData"]
    for raw_line in raw_lines:
        raw = str(raw_line).strip()
        if raw.startswith("{"):
            try:
                embedded = json.loads(raw)
                candidates.add(str(embedded["host"]["name"]))
            except (json.JSONDecodeError, KeyError, TypeError, RecursionError):
                pass

        match = re.match(
            r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
            r"([A-Za-z0-9._-]+)\s+",
            raw,
        )
        if match:
            candidates.add(match.group(1))

    return candidates


def _metricbeat_cpu_pct(embedded: object, key: str) -> float:
    value = embedded
    for step in ("system", "cpu", key, "pct"):
        if not isinstance(value, dict):
            return float("nan")
        value = value.get(step)
    try:
        return float(value) * 100
    except (TypeError, ValueError):
        return float("nan")


def extract_aminer_fields(
    record: dict,
    inventory: Inventory,
) -> ExtractedFields:
    observer_id = str((record.get("AMiner") or {}).get("ID") or "")
    analysis = record["AnalysisComponent"]
    component = analysis["AnalysisComponentName"]
    log_data = record["LogData"]
    entity_id = observer_id
    for resource in aminer_log_resources(record):
        match = re.search(r"/var/log/logstash/([^/]+)/", str(resource))
        if match:
            forwarded_ip = inventory.ip_by_hostname.get(match.group(1).casefold())
            if forwarded_ip:
                entity_id = forwarded_ip
                break

    reported_hosts = aminer_host_candidates(record)
    # a central miner gives every host the same id, so read the host from the log
    if entity_id not in inventory.assets_by_ip:
        for name in sorted(reported_hosts):
            resolved = inventory.ip_by_hostname.get(name.casefold())
            if resolved is None and name in inventory.assets_by_ip:
                resolved = name
            if resolved:
                entity_id = resolved
                break
    asset = inventory.assets_by_ip.get(entity_id)
    if len(reported_hosts) == 1:
        host = next(iter(reported_hosts))
    else:
        host = asset.hostname if asset else entity_id
    training_value = analysis.get("TrainingMode")
    training_mode = (
        float(bool(training_value))
        if training_value is not None else float("nan")
    )
    raw = str(record["LogData"]["RawLogData"][0]).strip()

    web_request = ""
    http_method = ""
    http_status = float("nan")
    dns_query = ""
    paths = analysis.get("AffectedLogAtomPaths") or []
    values = analysis.get("AffectedLogAtomValues") or []
    for path, value in zip(paths, values):
        if path.endswith("/request"):
            web_request = str(value)
        elif path.endswith("/method"):
            http_method = str(value)
        elif path.endswith("/status"):
            http_status = optional_float(value)
        elif path.endswith("/domain"):
            dns_query = str(value)

    cpu_total_pct = float("nan")
    cpu_nice_pct = float("nan")
    if raw.startswith("{"):
        try:
            embedded = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            embedded = {}
        cpu_total_pct = _metricbeat_cpu_pct(embedded, "total")
        cpu_nice_pct = _metricbeat_cpu_pct(embedded, "nice")

    source_user = ""
    target_user = ""
    command = ""
    working_directory = ""
    # `.*?PWD=` rescans to the end at every "sudo:", which is quadratic on a
    # hostile line, so the input is capped; a real sudo record is far shorter
    sudo = re.search(
        r"sudo:\s+(\S+)\s+:.*?PWD=([^;]+)\s*;\s*USER=([^;]+)\s*;\s*COMMAND=(.*)$",
        raw[:4096],
    )
    if sudo:
        source_user = sudo.group(1)
        working_directory = sudo.group(2).strip()
        target_user = sudo.group(3).strip()
        command = sudo.group(4).strip()
    else:
        su = re.search(r"Successful su for (\S+) by (\S+)", raw)
        if su:
            target_user = su.group(1)
            source_user = su.group(2)

    return ExtractedFields(
        name=component,
        host=host,
        entity_id=entity_id,
        observer_id=observer_id,
        entity_in_inventory=entity_id in inventory,
        severity=float("nan"),
        rule_id=str(component),
        source_user=source_user,
        target_user=target_user,
        command=command,
        working_directory=working_directory,
        web_request=web_request,
        http_method=http_method,
        http_status=http_status,
        dns_query=dns_query,
        analysis_component_type=str(analysis.get("AnalysisComponentType") or ""),
        training_mode=training_mode,
        affected_log_paths=";".join(str(path) for path in paths),
        affected_log_frequencies=";".join(
            str(value) for value in analysis.get("AffectedLogAtomFrequencies") or []
        ),
        log_resource=";".join(aminer_log_resources(record)),
        log_lines_count=optional_float(log_data.get("LogLinesCount")),
        critical_value=optional_float(analysis.get("CriticalValue")),
        probability_threshold=optional_float(
            analysis.get("ProbabilityThreshold")
        ),
        anomaly_scores=";".join(
            str(value) for value in analysis.get("AnomalyScores") or []
        ),
        cpu_total_pct=cpu_total_pct,
        cpu_nice_pct=cpu_nice_pct,
    )


def as_wrapped_suricata(record: dict) -> dict | None:
    if record.get("event_type") != "alert" or "alert" not in record:
        return None
    stamp = record.get("timestamp")
    if not stamp:
        return None
    return {"@timestamp": stamp, "data": record}


def classify_wazuh_record(record: dict) -> str:
    if record.get("decoder", {}).get("name") == "snort":
        return ""
    if "alert" in record.get("data", {}):
        return "suricata"
    if not isinstance(record.get("rule"), dict) or "agent" not in record:
        return ""
    return "wazuh"


READERS: dict[str, Callable[[dict, Inventory], ExtractedFields]] = {
    "wazuh": extract_wazuh_fields,
    "suricata": extract_suricata_fields,
    "aminer": extract_aminer_fields,
}


def normalize_record(
    record: dict,
    detector: str,
    windows: list[tuple[float, float, str]],
    inventory: Inventory,
) -> dict:
    reader = READERS.get(detector)
    if reader is None:
        raise ValueError(
            f"no reader for detector {detector!r}; known detectors are "
            f"{', '.join(sorted(READERS))}"
        )
    fields = reader(record, inventory)
    timestamp = get_timestamp(record, detector)
    return {
        **vars(fields),
        "detector_source": detector,
        "timestamp": timestamp,
        "attack_window": find_attack_window(timestamp, windows),
    }


# cast after the chunks are joined: per-chunk categories would not match and the
# concatenation would fall back to object dtype
def finalize_normalized_frame(df: pd.DataFrame) -> pd.DataFrame:
    for column in CATEGORICAL_COLUMNS:
        df[column] = df[column].astype("category")
    if "event_label" in df.columns:
        df["event_label"] = df["event_label"].astype("category")
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


WAZUH_FAMILY = "wazuh"
AMINER_FAMILY = "aminer"
SURICATA_FAMILY = "suricata"
FAMILY_ORDER = (AMINER_FAMILY, SURICATA_FAMILY, WAZUH_FAMILY)
LABEL_ORDER = (WAZUH_FAMILY, SURICATA_FAMILY, AMINER_FAMILY)
SNIFF_LINES = 5
SNIFF_LINE_BYTES = 1 << 20


def classify_alert_family(record: dict) -> str:
    if "AnalysisComponent" in record or "LogData" in record:
        return AMINER_FAMILY
    if "rule" in record and "agent" in record:
        return WAZUH_FAMILY
    data = record.get("data")
    if isinstance(data, dict) and "alert" in data:
        return WAZUH_FAMILY
    event_type = record.get("event_type")
    if isinstance(event_type, str) and isinstance(record.get(event_type), dict):
        return SURICATA_FAMILY
    return ""


def sniff_alert_family(path: Path) -> str:
    try:
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            read = 0
            while read < SNIFF_LINES:
                line = fh.readline(SNIFF_LINE_BYTES)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                read += 1
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, RecursionError, ValueError):
                    continue
                if isinstance(record, dict):
                    family = classify_alert_family(record)
                    if family:
                        return family
    except OSError:
        return ""
    return ""


class AlertFileError(Exception):
    pass


def read_alert_record(line: str, path: Path, position: int) -> dict | None:
    # a malformed record names its file and line. Returning None means "skip a
    # blank"; anything else is fatal, because silently dropping records would
    # change the answer without saying so.
    if not line.strip():
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError as error:
        raise AlertFileError(
            f"{path.name} line {position + 1} is not valid JSON: {error.msg}. "
            "Alert files are JSON lines, one object per line."
        ) from error
    except RecursionError as error:
        raise AlertFileError(
            f"{path.name} line {position + 1} nests too deeply to parse. "
            "Alert files are JSON lines, one object per line."
        ) from error
    if not isinstance(record, dict):
        raise AlertFileError(
            f"{path.name} line {position + 1} is a {type(record).__name__}, "
            "not an alert object."
        )
    return record


def sort_alert_files(files: list[tuple[Path, str]]) -> list[tuple[Path, str]]:
    return sorted(
        files, key=lambda pair: (FAMILY_ORDER.index(pair[1]), pair[0].name)
    )


def resolve_alert_files(
    raw_dir: Path,
    scenario: str,
    wazuh_path: Path | None = None,
    aminer_path: Path | None = None,
) -> list[tuple[Path, str]]:
    resolved_wazuh = wazuh_path or raw_dir / f"{scenario}_wazuh.json"
    resolved_aminer = aminer_path or raw_dir / f"{scenario}_aminer.json"
    named = [
        pair
        for pair in (
            (resolved_wazuh, WAZUH_FAMILY),
            (resolved_aminer, AMINER_FAMILY),
        )
        if pair[0].exists()
    ]
    explicit = {WAZUH_FAMILY: wazuh_path, AMINER_FAMILY: aminer_path}
    if named and any(path is not None for path in explicit.values()):
        return sort_alert_files(named)

    found = (
        sorted(raw_dir.glob("*.json"), key=lambda path: path.name)
        if raw_dir.is_dir() else []
    )
    sniffed = [
        (candidate, family)
        for candidate in found
        if (family := sniff_alert_family(candidate))
    ]

    if named:
        covered = {family for _, family in named}
        chosen = {path for path, _ in named}
        return sort_alert_files(named + [
            pair for pair in sniffed
            if pair[1] not in covered and pair[0] not in chosen
        ])

    # an explicit path that does not exist is a typo worth reporting, so the family
    # it named is not filled in from the directory instead
    usable = [pair for pair in sniffed if explicit.get(pair[1]) is None]
    if usable:
        return sort_alert_files(usable)

    names = [p.name for p in found]
    hint = (
        f"\n{len(names)} json file(s) are there: {', '.join(names[:8])}"
        f"\npoint at one directly with --wazuh-file or --aminer-file"
        if names else
        f"\nno json files in {raw_dir} at all"
    )
    raise FileNotFoundError(
        f"no alert file for '{scenario}': looked for {resolved_wazuh.name} "
        f"(wazuh and suricata) and {resolved_aminer.name} in {raw_dir}.{hint}"
    )


def read_family_record(record: dict, family: str) -> tuple[dict, str] | None:
    if family == AMINER_FAMILY:
        analysis = record.get("AnalysisComponent")
        log_data = record.get("LogData")
        if not isinstance(analysis, dict) or not isinstance(log_data, dict):
            return None
        if "AnalysisComponentName" not in analysis:
            return None
        for key in ("RawLogData", "Timestamps"):
            value = log_data.get(key)
            if not isinstance(value, list) or not value:
                return None
        return record, "aminer"
    if family == SURICATA_FAMILY:
        wrapped = as_wrapped_suricata(record)
        return (wrapped, "suricata") if wrapped is not None else None
    detector = classify_wazuh_record(record)
    return (record, detector) if detector else None


def suricata_fingerprint(record: dict) -> tuple:
    data = record.get("data") or {}
    alert = data.get("alert") or {}

    def number(value: object) -> object:
        if isinstance(value, (dict, list, set, tuple)):
            return repr(value)
        try:
            converted = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError):
            return str(value)
        if not isfinite(converted):
            return str(value)
        return int(converted)

    return (
        str(data.get("timestamp")),
        number(alert.get("signature_id")),
        number(data.get("flow_id")),
    )


def load_event_labels(csv_dir: Path, scenario: str) -> list[str]:
    with (csv_dir / f"{scenario}_alerts.txt").open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        next(reader)
        return ["" if row[6] == "-" else row[6] for row in reader]


def label_offsets(files: Sequence[tuple[Path, str]]) -> dict[Path, int]:
    ordered = sorted(files, key=lambda pair: LABEL_ORDER.index(pair[1]))
    offsets: dict[Path, int] = {}
    offset = 0
    for index, (path, _) in enumerate(ordered):
        offsets[path] = offset
        if index + 1 < len(ordered):
            with path.open(encoding="utf-8-sig", errors="replace") as fh:
                offset += sum(1 for _ in fh)
    return offsets


def iter_normalized_rows(
    raw_dir: Path,
    labels_path: Path | None,
    scenario: str,
    inventory_path: Path,
    event_csv_dir: Path | None = None,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
    files: Sequence[tuple[Path, str]] | None = None,
) -> Iterator[dict]:
    resolved = (
        list(files) if files is not None
        else resolve_alert_files(raw_dir, scenario, wazuh_file, aminer_file)
    )
    windows = load_attack_windows(labels_path, scenario) if labels_path else []
    inventory = load_inventory(inventory_path)

    event_labels: list[str] | None = None
    offsets: dict[Path, int] = {}
    if event_csv_dir is not None:
        event_labels = load_event_labels(event_csv_dir, scenario)
        offsets = label_offsets(resolved)

    # a wazuh agent that tails eve.json forwards the alert the sensor's own file
    # already holds. Only a copy in a later file is a duplicate, and the counts
    # keep a burst of identical alerts in one file intact.
    watch_duplicates = sum(
        family in (WAZUH_FAMILY, SURICATA_FAMILY) for _, family in resolved
    ) > 1
    seen: Counter[tuple] = Counter()

    for path, family in resolved:
        offset = offsets.get(path, 0)
        mine: Counter[tuple] = Counter()
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            for position, line in enumerate(fh):
                record = read_alert_record(line, path, position)
                if record is None:
                    continue
                alert = read_family_record(record, family)
                if alert is None:
                    continue
                parsed, detector = alert
                if watch_duplicates and detector == "suricata":
                    fingerprint = suricata_fingerprint(parsed)
                    if seen[fingerprint] > mine[fingerprint]:
                        mine[fingerprint] += 1
                        continue
                    mine[fingerprint] += 1
                row = normalize_record(parsed, detector, windows, inventory)
                row["source_file"] = path.name
                row["source_position"] = position
                if event_labels is not None:
                    row["event_label"] = event_labels[offset + position]
                yield row
        seen += mine


def normalize_scenario(
    raw_dir: Path,
    labels_path: Path | None,
    scenario: str,
    inventory_path: Path,
    event_csv_dir: Path | None = None,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
) -> pd.DataFrame:
    columns = COLUMNS + ["event_label"] if event_csv_dir is not None else COLUMNS
    chunks: list[pd.DataFrame] = []
    batch: list[dict] = []
    for row in iter_normalized_rows(
        raw_dir, labels_path, scenario, inventory_path, event_csv_dir,
        wazuh_file, aminer_file,
    ):
        batch.append(row)
        if len(batch) >= CHUNK_ROWS:
            chunks.append(pd.DataFrame(batch, columns=columns))
            batch = []
    if batch:
        chunks.append(pd.DataFrame(batch, columns=columns))
    if not chunks:
        return finalize_normalized_frame(pd.DataFrame([], columns=columns))
    frame = chunks[0] if len(chunks) == 1 else pd.concat(chunks, ignore_index=True)
    return finalize_normalized_frame(frame)
