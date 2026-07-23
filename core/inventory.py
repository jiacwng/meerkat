"""Load the company assets available before alert processing.

Public API:
    load_inventory(path)                        -> Inventory
    import_ait_inventory(source_path, out_path) -> convert one AIT YAML file
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


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

    def __contains__(self, ip: str) -> bool:
        return ip in self.assets_by_ip


def load_inventory(path: Path) -> Inventory:
    config = json.loads(path.read_text(encoding="utf-8"))
    assets_by_ip = {}
    ip_by_hostname = {}

    for item in config["assets"]:
        groups = tuple(str(group) for group in item.get("groups", []))
        # the attacker machine never enters the inventory, grouping alerts on it
        # would be reading the answer
        if "attacker" in groups:
            continue

        asset = Asset(
            hostname=str(item["hostname"]),
            ip_addresses=tuple(str(ip) for ip in item["ip_addresses"]),
            groups=groups,
        )
        for ip in asset.ip_addresses:
            assets_by_ip[ip] = asset
        ip_by_hostname[asset.hostname.casefold()] = asset.ip_addresses[0]

    return Inventory(
        company=str(config["company"]),
        assets_by_ip=assets_by_ip,
        ip_by_hostname=ip_by_hostname,
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
