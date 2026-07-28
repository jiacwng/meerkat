# turn one CAM-LDS scenario into the files core.inventory and core.normalize read

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from pathlib import Path, PurePosixPath
from typing import TextIO

FACTS = "facts.json"
ATTACKMATE = "logs/attackmate.json"
WAZUH_ALERTS = "logs/alerts/alerts.json"
WAZUH_ALERT_DIR = "logs/alerts/"
SURICATA_EVE = "logs/log/suricata/eve.json"
SURICATA_CONFIG = "configs/suricata/"
WAZUH_AGENT_CONFIG = "configs/ossec.conf"
NEXTCLOUD_CONFIG = "configs/nextcloud/"
DNSMASQ_CONFIG = "configs/etc/dnsmasq.d/"

LABEL_COLUMNS = ("scenario", "attack", "start", "end")
# the biggest real member is a 673 MB alert export; past this it is not data
MAX_MEMBER_BYTES = 2_000_000_000
MAX_RATIO = 200
MAX_JSON_BYTES = 20_000_000
TAIL_SECONDS = 60.0

# a dnsmasq drop-in only answers for a zone once it carries one of these
DNS_DIRECTIVES = ("address=", "host-record=", "auth-zone=", "auth-server=", "local=/")
MAIL_PORTS = frozenset({"25", "143", "465", "587", "993"})


class ScenarioError(Exception):
    pass


@dataclass(frozen=True)
class Host:
    name: str
    directory: str
    addresses: tuple[str, ...]
    gateway: str
    network: str
    roles: tuple[str, ...] = ()


@dataclass
class Conversion:
    scenario: str
    hosts: list[Host]
    attacker: str
    windows: list[tuple[float, float, str]]
    alert_counts: dict[str, int] = field(default_factory=dict)
    alerts_dir: Path | None = None
    inventory_path: Path | None = None
    labels_path: Path | None = None

    def assets(self) -> list[Host]:
        return [host for host in self.hosts if host.name != self.attacker]


class Archive:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._zip = zipfile.ZipFile(path) if zipfile.is_zipfile(path) else None
        if self._zip is not None:
            names = [name for name in self._zip.namelist() if not name.endswith("/")]
        elif path.is_dir():
            names = [
                item.relative_to(path).as_posix()
                for item in path.rglob("*")
                if item.is_file()
            ]
        else:
            raise ScenarioError(f"{path} is neither a zip nor a directory")
        self.root = _scenario_root(names, path)
        prefix = f"{self.root}/" if self.root else ""
        self.names = tuple(
            sorted(name[len(prefix):] for name in names if name.startswith(prefix))
        )
        self.label = self.root.rsplit("/", 1)[-1] if self.root else path.name

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()

    def exists(self, name: str) -> bool:
        return name in self.names

    def has_prefix(self, prefix: str) -> bool:
        return any(name.startswith(prefix) for name in self.names)

    def lines(self, name: str) -> Iterator[str]:
        full = f"{self.root}/{name}" if self.root else name
        if self._zip is not None:
            self._refuse_bomb(full)
            with self._zip.open(full) as raw:
                yield from io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        else:
            with (self.path / full).open(encoding="utf-8", errors="replace") as fh:
                yield from fh

    # the largest real member is a 673 MB alert export, so anything past this is
    # not data. A 292 KB member expanding to 300 MB is a bomb, not a config.
    def _refuse_bomb(self, full: str) -> None:
        info = self._zip.getinfo(full)  # type: ignore[union-attr]
        if info.file_size > MAX_MEMBER_BYTES:
            raise ScenarioError(
                f"{full} expands to {info.file_size / 1e9:.1f} GB, refusing to read"
            )
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise ScenarioError(
                f"{full} expands {info.file_size // info.compress_size}x, "
                "refusing to read"
            )

    def read_json(self, name: str) -> dict:
        # a config or facts file is kilobytes; a hostile one is not read whole
        text = []
        size = 0
        for line in self.lines(name):
            size += len(line)
            if size > MAX_JSON_BYTES:
                raise ScenarioError(f"{name} is larger than {MAX_JSON_BYTES} bytes")
            text.append(line)
        return json.loads("".join(text))

    def directories(self) -> list[str]:
        return sorted(
            name[: -len(f"/{FACTS}")]
            for name in self.names
            if name.endswith(f"/{FACTS}") and name.count("/") == 1
        )


def _scenario_root(names: list[str], path: Path) -> str:
    roots = {
        name[: -len(f"/{FACTS}")].rpartition("/")[0]
        for name in names
        if name.endswith(f"/{FACTS}")
    }
    if not roots:
        raise ScenarioError(f"no <host>/{FACTS} anywhere under {path}")
    if len(roots) > 1:
        raise ScenarioError(
            f"{path} holds more than one scenario: {', '.join(sorted(roots))}"
        )
    return roots.pop()


def read_hosts(archive: Archive) -> list[Host]:
    hosts = []
    for directory in archive.directories():
        facts = archive.read_json(f"{directory}/{FACTS}")
        default = facts.get("ansible_default_ipv4") or {}
        primary = str(default.get("address") or "")
        # the default address goes first, because the inventory keys a hostname on it
        others = sorted(
            str(address)
            for address in facts.get("ansible_all_ipv4_addresses") or []
            if str(address) != primary
        )
        network = ""
        if default.get("network") and default.get("prefix"):
            network = f"{default['network']}/{default['prefix']}"
        hosts.append(Host(
            name=str(facts.get("ansible_hostname") or directory),
            directory=directory,
            addresses=tuple(address for address in [primary, *others] if address),
            gateway=str(default.get("gateway") or ""),
            network=network,
        ))
    return hosts


def find_attacker(archive: Archive, hosts: list[Host]) -> str:
    # the machine that ran the playbook is the one holding the ground truth
    for host in hosts:
        if archive.exists(f"{host.directory}/{ATTACKMATE}"):
            return host.name
    return ""


def _runs_dns(archive: Archive, host: Host) -> bool:
    for name in archive.names:
        if not name.startswith(f"{host.directory}/{DNSMASQ_CONFIG}"):
            continue
        text = "".join(archive.lines(name))
        if any(directive in text for directive in DNS_DIRECTIVES):
            return True
    return False


def _runs_mail(archive: Archive, host: Host) -> bool:
    for name in archive.names:
        if not name.startswith(f"{host.directory}/configs/") or "compose" not in name:
            continue
        text = "".join(archive.lines(name))
        published = re.findall(r"[\"']?(\d+):\d+[\"']?", text)
        if MAIL_PORTS.intersection(published):
            return True
    return False


def host_roles(archive: Archive, host: Host, others: list[Host]) -> tuple[str, ...]:
    # every machine in this testbed is a headless server image, none is a desktop
    roles = ["server"]
    if archive.has_prefix(f"{host.directory}/{SURICATA_CONFIG}"):
        roles.append("ids")
    running_wazuh = (
        archive.exists(f"{host.directory}/{WAZUH_AGENT_CONFIG}")
        or archive.has_prefix(f"{host.directory}/{WAZUH_ALERT_DIR}")
    )
    if running_wazuh:
        roles.append("monitoring_agent")
    if _runs_dns(archive, host):
        roles.append("dns_server")
    if archive.has_prefix(f"{host.directory}/{NEXTCLOUD_CONFIG}"):
        roles.append("file_share")
    if _runs_mail(archive, host):
        roles.append("mail_server")

    gateways = {other.gateway for other in others if other.name != host.name}
    if gateways.intersection(host.addresses):
        roles.append("router")
        # the border box is the router whose own next hop is outside the scenario
        inside = {address for other in others for address in other.addresses}
        if host.gateway not in inside:
            roles.append("firewall")
    return tuple(roles)


def external_network(hosts: list[Host]) -> str:
    # the segment the border box routes out to, read from its own default route
    for host in hosts:
        if "firewall" in host.roles:
            return host.network
    return ""


def zone_role(host: Host, external: str) -> str:
    if not external:
        return ""
    network = ipaddress.ip_network(external, strict=False)
    for address in host.addresses:
        if ipaddress.ip_address(address) in network:
            return "internet_facing"
    return "internal"


def _with_roles(host: Host, roles: tuple[str, ...]) -> Host:
    return Host(host.name, host.directory, host.addresses, host.gateway,
                host.network, roles)


def build_hosts(archive: Archive) -> tuple[list[Host], str]:
    hosts = read_hosts(archive)
    placed = [_with_roles(host, host_roles(archive, host, hosts)) for host in hosts]
    external = external_network(placed)
    zoned = []
    for host in placed:
        zone = zone_role(host, external)
        zoned.append(_with_roles(host, host.roles + ((zone,) if zone else ())))
    return zoned, find_attacker(archive, hosts)


def build_inventory(hosts: list[Host], attacker: str, company: str) -> dict:
    return {
        "company": company,
        "assets": [
            {
                "hostname": host.name,
                "ip_addresses": list(host.addresses),
                "roles": sorted(host.roles),
            }
            # the attacker never enters an inventory, its alerts are the answer
            for host in hosts if host.name != attacker
        ],
    }


def scenario_timezone(archive: Archive, hosts: list[Host]) -> tzinfo:
    # attackmate writes a local time with no zone, so take the zone the hosts ran in
    for host in hosts:
        facts = archive.read_json(f"{host.directory}/{FACTS}")
        offset = str((facts.get("ansible_date_time") or {}).get("tz_offset") or "")
        if offset:
            return datetime.strptime(offset, "%z").tzinfo or UTC
    return UTC


def read_attack_steps(archive: Archive, hosts: list[Host]) -> list[dict]:
    for host in hosts:
        name = f"{host.directory}/{ATTACKMATE}"
        if archive.exists(name):
            return [json.loads(line) for line in archive.lines(name) if line.strip()]
    return []


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


# an archive is third-party content, so anything it names is hostile until it
# has been through here. A hostname decides a file name, and "../victim" wrote
# outside the output directory and overwrote whatever was there.
def _safe_name(text: str, kind: str) -> str:
    slug = _slug(text)
    if not slug:
        raise ScenarioError(f"{kind} {text!r} has no usable characters")
    return slug


def _inside(path: Path, directory: Path) -> Path:
    resolved = path.resolve()
    if resolved.parent != directory.resolve():
        raise ScenarioError(f"{path} escapes the output directory")
    return resolved


# the same control characters _csv_safe strips, because a hostile hostname
# reaches the operator's terminal through the conversion report
def _printable(text: str) -> str:
    return "".join(" " if ord(ch) < 32 or 127 <= ord(ch) < 160 else ch for ch in text)


def _csv_safe(value: object) -> str:
    # a cell opening with these is a formula in excel and sheets
    text = _printable(str(value))
    return "'" + text if text[:1] in "=+-@\t\r" else text


def step_name(position: int, step: dict) -> str:
    tokens = str(step.get("cmd") or "").split()
    if not tokens:
        return f"{position:02d}_{_slug(str(step.get('type') or 'step'))}"
    head = _slug(PurePosixPath(tokens[0]).stem)
    # the first bare word after the program is its subcommand: docker run, hydra imap
    for token in tokens[1:]:
        if token.isalpha() and len(token) > 1:
            return f"{position:02d}_{head}_{_slug(token)}"
    return f"{position:02d}_{head}"


def step_epoch(step: dict, zone: tzinfo) -> float:
    stamp = datetime.fromisoformat(str(step["start-datetime"]))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=zone)
    return stamp.timestamp()


def attack_windows(
    steps: list[dict],
    zone: tzinfo,
    tail_seconds: float = TAIL_SECONDS,
) -> list[tuple[float, float, str]]:
    if not steps:
        return []
    starts = [step_epoch(step, zone) for step in steps]
    # a sleep carries no metadata, so only the steps attackmate marked count
    marked = [
        index for index, step in enumerate(steps)
        if (step.get("parameters") or {}).get("metadata")
    ]
    windows = []
    for order, index in enumerate(marked):
        # the runner is sequential, so the next marked start is this one's end
        if order + 1 < len(marked):
            end = starts[marked[order + 1]]
        else:
            end = starts[-1] + tail_seconds
        windows.append((starts[index], end, step_name(index + 1, steps[index])))
    return windows


def write_attack_windows(
    path: Path,
    scenario: str,
    windows: list[tuple[float, float, str]],
) -> None:
    # one csv holds every scenario, so keep the rows this run is not replacing
    kept: list[dict] = []
    if path.exists():
        with path.open(encoding="utf-8", newline="") as fh:
            kept = [
                {column: row.get(column, "") for column in LABEL_COLUMNS}
                for row in csv.DictReader(fh)
                if row.get("scenario") != scenario
            ]
    path.parent.mkdir(parents=True, exist_ok=True)
    # data/labels.csv is committed ground truth, so it is replaced only once the
    # new file is complete. Writing in place lost it when a row failed halfway.
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=list(LABEL_COLUMNS), extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(kept)
        for start, end, attack in windows:
            writer.writerow({
                "scenario": _csv_safe(scenario), "attack": _csv_safe(attack),
                "start": start, "end": end,
            })
    temporary.replace(path)


def wazuh_alert_files(archive: Archive, host: Host) -> list[str]:
    live = f"{host.directory}/{WAZUH_ALERTS}"
    if archive.exists(live):
        return [live]
    # only a manager that rotated its file keeps the day in the dated copies
    return [
        name for name in archive.names
        if name.startswith(f"{host.directory}/{WAZUH_ALERT_DIR}")
        and name.endswith(".json")
    ]


def _copy_lines(archive: Archive, names: list[str], out: TextIO, alerts_only: bool) -> int:
    written = 0
    for name in names:
        for line in archive.lines(name):
            if not line.strip():
                continue
            # eve.json is mostly netflow, dns and stats, which the reader drops
            if alerts_only and not _is_eve_alert(line):
                continue
            out.write(line if line.endswith("\n") else line + "\n")
            written += 1
    return written


def _is_eve_alert(line: str) -> bool:
    try:
        return json.loads(line).get("event_type") == "alert"
    except json.JSONDecodeError:
        return False


def _write_alerts(
    archive: Archive,
    names: list[str],
    out_path: Path,
    alerts_only: bool,
) -> int:
    with out_path.open("w", encoding="utf-8", newline="\n") as out:
        written = _copy_lines(archive, names, out, alerts_only)
    # an empty file sniffs as no detector at all, so leave nothing behind
    if not written:
        out_path.unlink()
    return written


def copy_alerts(archive: Archive, hosts: list[Host], out_dir: Path) -> dict[str, int]:
    # resolve_alert_files reads every json file here and sniffs what wrote it
    counts: dict[str, int] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    for host in hosts:
        # the archive names the file, so the name is slugged and the path checked
        stem = _safe_name(host.name, "host name")
        sources = wazuh_alert_files(archive, host)
        if sources:
            target = _inside(out_dir / f"{stem}_alerts.json", out_dir)
            counts[f"{stem}_alerts.json"] = _write_alerts(
                archive, sources, target, False
            )
        eve = f"{host.directory}/{SURICATA_EVE}"
        if archive.exists(eve):
            target = _inside(out_dir / f"{stem}_eve.json", out_dir)
            counts[f"{stem}_eve.json"] = _write_alerts(archive, [eve], target, True)
    return counts


def convert(
    archive: Archive,
    out_dir: Path,
    scenario: str,
    tail_seconds: float = TAIL_SECONDS,
) -> Conversion:
    hosts, attacker = build_hosts(archive)
    zone = scenario_timezone(archive, hosts)
    windows = attack_windows(read_attack_steps(archive, hosts), zone, tail_seconds)

    inventory_path = out_dir / "inventory" / f"{scenario}.json"
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(
        json.dumps(build_inventory(hosts, attacker, scenario), indent=2) + "\n",
        encoding="utf-8",
    )
    labels_path = out_dir / "labels.csv"
    write_attack_windows(labels_path, scenario, windows)
    counts = copy_alerts(archive, hosts, out_dir)

    return Conversion(
        scenario=scenario,
        hosts=hosts,
        attacker=attacker,
        windows=windows,
        alert_counts=counts,
        alerts_dir=out_dir,
        inventory_path=inventory_path,
        labels_path=labels_path,
    )


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def format_report(result: Conversion) -> str:
    lines = [
        f"{result.scenario}: {len(result.assets())} assets, "
        f"{len(result.windows)} attack windows"
    ]
    for host in result.hosts:
        if host.name == result.attacker:
            note = "attacker, left out of the inventory"
        else:
            note = ", ".join(sorted(host.roles)) or "no roles"
        lines.append(
            f"  {_printable(host.name):<10} "
            f"{_printable(', '.join(host.addresses)):<48} {note}"
        )
    if result.windows:
        first = min(start for start, _, _ in result.windows)
        last = max(end for _, end, _ in result.windows)
        lines.append(f"  windows  {_stamp(first)} .. {_stamp(last)}")
    lines.append(f"  alerts written under {result.alerts_dir}:")
    for name, count in sorted(result.alert_counts.items()):
        lines.append(f"    {count:>6}  {name}")
    lines.append(f"  {result.inventory_path}")
    lines.append(f"  {result.labels_path}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert one CAM-LDS scenario into the layout meerkat reads"
    )
    parser.add_argument("source", type=Path, help="scenario zip or extracted directory")
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--scenario", default=None,
                        help="label for the written files, default the archive's")
    parser.add_argument("--tail-seconds", type=float, default=TAIL_SECONDS,
                        help="length given to the last attack window")
    args = parser.parse_args(argv)

    try:
        archive = Archive(args.source)
    except (ScenarioError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    try:
        result = convert(
            archive, args.out_dir, args.scenario or archive.label, args.tail_seconds
        )
    finally:
        archive.close()
    print(format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
