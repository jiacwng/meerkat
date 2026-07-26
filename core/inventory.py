"""Load the company assets available before alert processing.

Public API:
    load_inventory(path)                        -> Inventory
    import_ait_inventory(source_path, out_path) -> convert one AIT YAML file
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.roles import canonicalize


@dataclass(frozen=True)
class Asset:
    hostname: str
    ip_addresses: tuple[str, ...]
    groups: tuple[str, ...]


@dataclass(frozen=True)
class Inventory:
    company: str
    assets_by_ip: dict[str, Asset]
    ip_by_hostname: dict[str, str]
    # names outside CANONICAL_ROLES, reported rather than fatal
    unknown_roles: tuple[str, ...] = ()

    def __contains__(self, ip: str) -> bool:
        return ip in self.assets_by_ip

    def assets_without_roles(self) -> tuple[str, ...]:
        return tuple(sorted({
            asset.hostname
            for asset in self.assets_by_ip.values()
            if not asset.groups
        }))


def load_inventory(path: Path) -> Inventory:
    # this is the one file the tool asks a person to hand-edit, so a trailing
    # comma or a dropped key is the expected failure and must not be a traceback
    try:
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.name} is not valid JSON: {error.msg}") from error
    if not isinstance(config, dict) or "assets" not in config:
        raise ValueError(
            f'{path.name} must be an object with an "assets" list; '
            "`meerkat inventory` writes one in the right shape"
        )
    assets_by_ip = {}
    ip_by_hostname = {}

    unknown_roles: set[str] = set()
    for item in config["assets"]:
        # "roles" is the documented key, "groups" is what AIT and Wazuh use.
        # a string is iterable, so "webserver" used to become six one-letter
        # roles and the asset silently ended up with none
        if not isinstance(item, dict):
            raise ValueError(
                f"{path.name}: every entry under \"assets\" must be an object"
            )
        for required in ("hostname", "ip_addresses"):
            if required not in item:
                raise ValueError(
                    f"{path.name}: an asset is missing \"{required}\""
                )
        declared = item.get("roles") or item.get("groups") or []
        if isinstance(declared, str):
            declared = [declared]
        raw_groups = tuple(str(group) for group in declared)
        # the attacker machine never enters the inventory, grouping alerts on it
        # would be reading the answer
        if "attacker" in raw_groups:
            continue

        # only names the model was trained on can score, so translate and keep
        # track of anything unplaced
        groups, unplaced = canonicalize(raw_groups)
        unknown_roles.update(unplaced)

        asset = Asset(
            hostname=str(item["hostname"]),
            ip_addresses=tuple(str(ip) for ip in item["ip_addresses"]),
            groups=groups,
        )
        for ip in asset.ip_addresses:
            assets_by_ip[ip] = asset
        # `meerkat inventory` emits address-less assets and only warns, so the
        # loader has to survive its own scaffolding
        if asset.ip_addresses:
            ip_by_hostname[asset.hostname.casefold()] = asset.ip_addresses[0]

    return Inventory(
        # the company name is only a label, so a file without one still loads
        company=str(config.get("company", path.stem)),
        assets_by_ip=assets_by_ip,
        ip_by_hostname=ip_by_hostname,
        unknown_roles=tuple(sorted(unknown_roles)),
    )


def import_ait_inventory(source_path: Path, output_path: Path) -> None:
    # PyYAML is only needed to read the AIT files, so it stays out of the
    # runtime path and out of requirements.txt
    import yaml

    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    assets = []
    for item in source.values():
        groups = [str(group) for group in item.get("groups", [])]
        if "attacker" in groups:
            continue
        assets.append({
            "hostname": str(item["hostname"]),
            "ip_addresses": [str(ip) for ip in item["ipv4_addresses"]],
            "groups": groups,
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"company": source_path.stem, "assets": assets}, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Convert official AIT inventories")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    for source_path in sorted(args.source_dir.glob("*.yaml")):
        import_ait_inventory(
            source_path,
            args.output_dir / f"{source_path.stem}.json",
        )


if __name__ == "__main__":
    main()
