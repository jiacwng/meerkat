"""Load the merged AIT-ADS alert file into one normalized alert table.

Public API:
    normalize_scenario(raw_dir, labels_path, scenario, inventory_path) -> pd.DataFrame
    iter_normalized_chunks(...)  -> bounded frames instead of one big list
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from core.inventory import Inventory, load_inventory

# a row dict costs about four times the same row inside a frame, so convert in
# batches and drop the dicts. Below ~5,000 the frame itself dominates and peak
# stops improving.
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
    # every detector must fill these, whatever its own schema looks like
    name: str
    host: str
    entity_id: str
    observer_id: str
    entity_in_inventory: bool
    severity: float
    native_technique_ids: str = ""   # ";"-joined ATT&CK IDs, wazuh only
    rule_id: str = ""                # stable detector rule identity, for mapping config
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
    windows = []
    with labels_path.open(encoding="utf-8") as fh:
        c = csv.DictReader(fh)
        for row in c:
            if row["scenario"] == scenario:
                windows.append((float(row["start"]), float(row["end"]), row["attack"]))
    return windows


def find_attack_window(timestamp: float, windows: list[tuple[float, float, str]]) -> str:
    for start, end, phase in windows:
        if start <= timestamp <= end:
            return phase
    
    return ""


def get_timestamp(record: dict, detector: str) -> float:
    # AMiner already stores the timestamp;
    # wazuh/suricata store an ISO-8601 string ending in "Z" for UTC
    if detector == "aminer":
        return float(record["LogData"]["Timestamps"][0])
    stamp = datetime.fromisoformat(record["@timestamp"])
    # a SIEM export that omits the zone is otherwise read in the reading
    # machine's local time, so the same file lands in different days, sessions
    # and attack windows depending on who runs it
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
    # a single id is sometimes a bare string, and a string is iterable, so
    # "T1059" used to join to "T;1;0;5;9" and technique_count read 5 not 1
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
    # prefer a monitored endpoint, destination wins when both are known
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

    return ExtractedFields(
        name=alert["signature"],
        host=asset.hostname if asset else entity_id,
        entity_id=entity_id,
        observer_id=observer_id,
        entity_in_inventory=entity_id in inventory,
        severity=float(alert["severity"]),
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
    


def aminer_host_candidates(record: dict) -> set[str]:
    candidates = set()
    raw_lines = record["LogData"]["RawLogData"]
    for raw_line in raw_lines:
        raw = str(raw_line).strip()

        # a log line the miner flagged is attacker-influenced, so a "{" that is
        # not json, or json without a host, is a bad line rather than a crash.
        # json.loads answers deep nesting with RecursionError rather than
        # JSONDecodeError, and one `{"a":{"a":...` line used to end the run.
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


def extract_aminer_fields(
    record: dict,
    inventory: Inventory,
) -> ExtractedFields:
    observer_id = str(record["AMiner"]["ID"])
    analysis = record["AnalysisComponent"]
    component = analysis["AnalysisComponentName"]
    log_data = record["LogData"]
    entity_id = observer_id
    for resource in log_data.get("LogResources") or []:
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
        cpu = embedded.get("system", {}).get("cpu", {})
        total = cpu.get("total", {}).get("pct")
        nice = cpu.get("nice", {}).get("pct")
        # metricbeat writes these as a 0-1 fraction despite the pct name
        if total is not None:
            cpu_total_pct = float(total) * 100
        if nice is not None:
            cpu_nice_pct = float(nice) * 100

    source_user = ""
    target_user = ""
    command = ""
    working_directory = ""
    # `.*?PWD=` rescans to the end at every "sudo:", so a log line of repeated
    # "sudo: a : " costs 15s at 160KB and ten minutes at 1MB. The line is
    # attacker-written, and a real sudo record never runs past a few hundred
    # characters, so cap the input rather than reshape a working pattern.
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
        # aminer has no numeric rule ids; the analysis component IS its stable identity
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
        log_resource=";".join(
            str(resource) for resource in log_data.get("LogResources") or []
        ),
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


def classify_wazuh_record(record: dict) -> str:
    if record.get("decoder", {}).get("name") == "snort":
        return ""
    if "alert" in record.get("data", {}):
        return "suricata"
    # a wazuh alert always carries rule and agent. Claiming anything else is one
    # sent the extractor straight into a KeyError the user then read as a
    # traceback, so an object without them is not recognised rather than fatal.
    if not isinstance(record.get("rule"), dict) or "agent" not in record:
        return ""
    return "wazuh"


# the chain this replaced ended in else, so any other tool was read as AMiner
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
        "detector_source": detector,
        "timestamp": timestamp,
        "name": fields.name,
        "host": fields.host,
        "entity_id": fields.entity_id,
        "observer_id": fields.observer_id,
        "entity_in_inventory": fields.entity_in_inventory,
        "severity": fields.severity,
        "attack_window": find_attack_window(timestamp, windows),
        "native_technique_ids": fields.native_technique_ids,
        "rule_id": fields.rule_id,
        "native_event_id": fields.native_event_id,
        "source_user": fields.source_user,
        "target_user": fields.target_user,
        "command": fields.command,
        "executable": fields.executable,
        "working_directory": fields.working_directory,
        "web_request": fields.web_request,
        "source_ip": fields.source_ip,
        "destination_ip": fields.destination_ip,
        "source_port": fields.source_port,
        "destination_port": fields.destination_port,
        "network_protocol": fields.network_protocol,
        "application_protocol": fields.application_protocol,
        "http_method": fields.http_method,
        "http_status": fields.http_status,
        "http_hostname": fields.http_hostname,
        "http_user_agent": fields.http_user_agent,
        "alert_category": fields.alert_category,
        "rule_groups": fields.rule_groups,
        "rule_fired_times": fields.rule_fired_times,
        "flow_bytes_to_server": fields.flow_bytes_to_server,
        "flow_bytes_to_client": fields.flow_bytes_to_client,
        "flow_packets_to_server": fields.flow_packets_to_server,
        "flow_packets_to_client": fields.flow_packets_to_client,
        "tls_server_name": fields.tls_server_name,
        "tls_version": fields.tls_version,
        "tls_ja3": fields.tls_ja3,
        "dns_query": fields.dns_query,
        "analysis_component_type": fields.analysis_component_type,
        "training_mode": fields.training_mode,
        "affected_log_paths": fields.affected_log_paths,
        "affected_log_frequencies": fields.affected_log_frequencies,
        "log_resource": fields.log_resource,
        "log_lines_count": fields.log_lines_count,
        "critical_value": fields.critical_value,
        "probability_threshold": fields.probability_threshold,
        "anomaly_scores": fields.anomaly_scores,
        "cpu_total_pct": fields.cpu_total_pct,
        "cpu_nice_pct": fields.cpu_nice_pct,
    }


def _normalized_columns(with_event_label: bool) -> list[str]:
    return COLUMNS + ["event_label"] if with_event_label else COLUMNS


# separate from frame construction because a chunked reader has to concatenate
# first: casting per chunk gives each chunk its own categories, and concatenating
# those falls back to object dtype
def finalize_normalized_frame(df: pd.DataFrame) -> pd.DataFrame:
    for column in CATEGORICAL_COLUMNS:
        df[column] = df[column].astype("category")
    if "event_label" in df.columns:
        df["event_label"] = df["event_label"].astype("category")
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


WAZUH_FAMILY = "wazuh"
AMINER_FAMILY = "aminer"
SNIFF_LINES = 5


def classify_alert_family(record: dict) -> str:
    # the two exports share no top-level field. aminer writes what fired and the
    # log it read (AnalysisComponent / LogData); wazuh writes the rule and the
    # agent that reported it. suricata rides in the wazuh file with that same
    # rule+agent pair and its own data.alert, so it is the wazuh family here and
    # classify_wazuh_record splits the two apart per record at parse time.
    if "AnalysisComponent" in record or "LogData" in record:
        return AMINER_FAMILY
    if "rule" in record and "agent" in record:
        return WAZUH_FAMILY
    data = record.get("data")
    if isinstance(data, dict) and "alert" in data:
        return WAZUH_FAMILY
    return ""


def sniff_alert_family(path: Path, max_lines: int = SNIFF_LINES) -> str:
    # a wazuh export is tens of MB, so the family is decided from the first few
    # records and the rest of the file is never read. Anything unreadable, not
    # json, or json of neither shape is not an alert file.
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            read = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                read += 1
                if read > max_lines:
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
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
        # json.loads recurses, so a record nested a few thousand deep raises
        # this instead and used to end the whole ingest with a traceback
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


def resolve_alert_files(
    raw_dir: Path,
    scenario: str,
    wazuh_path: Path | None = None,
    aminer_path: Path | None = None,
) -> tuple[Path, Path]:
    # <company>_wazuh.json is AIT's layout and stays the convenient default, but a
    # real export is called whatever the SIEM called it, so either file can be named
    # outright. Returns both paths whether or not they exist; callers test that.
    default_wazuh = raw_dir / f"{scenario}_wazuh.json"
    default_aminer = raw_dir / f"{scenario}_aminer.json"
    resolved_wazuh = wazuh_path or default_wazuh
    resolved_aminer = aminer_path or default_aminer
    if resolved_wazuh.exists() or resolved_aminer.exists():
        return resolved_wazuh, resolved_aminer

    # nothing under the convention, so the name stops mattering: read the head of
    # each json file and let its format say which detector wrote it. Two exports
    # of the same family means a directory of archives, and first by name is both
    # the earliest for a dated name and the same choice on every run.
    found = (
        sorted(raw_dir.glob("*.json"), key=lambda path: path.name)
        if raw_dir.is_dir() else []
    )
    by_family: dict[str, Path] = {}
    for candidate in found:
        family = sniff_alert_family(candidate)
        if family and family not in by_family:
            by_family[family] = candidate
    if by_family:
        sniffed_wazuh = wazuh_path or by_family.get(WAZUH_FAMILY) or default_wazuh
        sniffed_aminer = aminer_path or by_family.get(AMINER_FAMILY) or default_aminer
        # an explicit path that does not exist is a typo worth reporting, so only
        # take the sniffed pair once something in it is actually readable
        if sniffed_wazuh.exists() or sniffed_aminer.exists():
            return sniffed_wazuh, sniffed_aminer

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


def iter_normalized_rows(
    raw_dir: Path,
    labels_path: Path | None,
    scenario: str,
    inventory_path: Path,
    event_csv_dir: Path | None = None,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
) -> Iterator[dict]:
    wazuh_path, aminer_path = resolve_alert_files(
        raw_dir, scenario, wazuh_file, aminer_file
    )
    # the miner is optional; the wazuh file carries both wazuh and suricata
    have_aminer = aminer_path.exists()
    have_wazuh = wazuh_path.exists()
    # an unseen company has no label file, so it carries no attack windows
    windows = load_attack_windows(labels_path, scenario) if labels_path else []
    inventory = load_inventory(inventory_path)

    # the label CSV follows raw file order, wazuh then aminer, so the wazuh half
    # stays aligned at offset 0 whether or not aminer is there
    event_labels: list[str] | None = None
    aminer_offset = 0
    if event_csv_dir is not None:
        from core.event_labels import load_scenario_labels
        _, _, _, event_labels = load_scenario_labels(event_csv_dir, scenario)
        if have_aminer and have_wazuh:
            with wazuh_path.open(encoding="utf-8-sig", errors="replace") as fh:
                aminer_offset = sum(1 for _ in fh)

    # a log line is attacker-influenced, so one bad byte anywhere in a 45MB export
    # would otherwise take the whole ingest down with a UnicodeDecodeError. The
    # replacement character still parses as JSON and still counts as one line, so
    # the event-label join stays aligned.
    if have_aminer:
        with aminer_path.open(encoding="utf-8-sig", errors="replace") as fh:
            for position, line in enumerate(fh):
                record = read_alert_record(line, aminer_path, position)
                if record is None:
                    continue
                row = normalize_record(
                    record,
                    "aminer",
                    windows,
                    inventory,
                )
                row["source_file"] = aminer_path.name
                row["source_position"] = position
                if event_labels is not None:
                    row["event_label"] = event_labels[aminer_offset + position]
                yield row

    if have_wazuh:
        with wazuh_path.open(encoding="utf-8-sig", errors="replace") as fh:
            for position, line in enumerate(fh):
                # a concatenated export often carries a blank line between parts,
                # and one of them used to abort the whole run. position still
                # advances, so the event-label join stays aligned.
                record = read_alert_record(line, wazuh_path, position)
                if record is None:
                    continue
                detector = classify_wazuh_record(record)
                if detector:
                    row = normalize_record(
                        record,
                        detector,
                        windows,
                        inventory,
                    )
                    row["source_file"] = wazuh_path.name
                    row["source_position"] = position
                    if event_labels is not None:
                        row["event_label"] = event_labels[position]
                    yield row


def iter_normalized_chunks(
    raw_dir: Path,
    labels_path: Path | None,
    scenario: str,
    inventory_path: Path,
    event_csv_dir: Path | None = None,
    chunk_rows: int = CHUNK_ROWS,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
) -> Iterator[pd.DataFrame]:
    columns = _normalized_columns(event_csv_dir is not None)
    batch: list[dict] = []
    for row in iter_normalized_rows(
        raw_dir, labels_path, scenario, inventory_path, event_csv_dir,
        wazuh_file, aminer_file,
    ):
        batch.append(row)
        if len(batch) >= chunk_rows:
            yield pd.DataFrame(batch, columns=columns)
            batch = []
    if batch:
        yield pd.DataFrame(batch, columns=columns)


def normalize_scenario(
    raw_dir: Path,
    labels_path: Path | None,
    scenario: str,
    inventory_path: Path,
    event_csv_dir: Path | None = None,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
) -> pd.DataFrame:
    chunks = list(
        iter_normalized_chunks(
            raw_dir, labels_path, scenario, inventory_path, event_csv_dir,
            wazuh_file=wazuh_file, aminer_file=aminer_file,
        )
    )
    if not chunks:
        return finalize_normalized_frame(
            pd.DataFrame([], columns=_normalized_columns(event_csv_dir is not None))
        )
    frame = chunks[0] if len(chunks) == 1 else pd.concat(chunks, ignore_index=True)
    del chunks
    return finalize_normalized_frame(frame)
