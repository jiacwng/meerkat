# Loads the asset inventory: which hosts a company has, what role each plays and
# how critical it is. Roles feed the model; criticality is shown and filtered on.

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.roles import canonicalize

# Splunk ES asset priority, with "unset" for its "unknown". Nothing that scores
# reads it.
CRITICALITY_LEVELS = ("critical", "high", "medium", "low")
UNSET = "unset"


@dataclass(frozen=True)
class Asset:
    hostname: str
    ip_addresses: tuple[str, ...]
    groups: tuple[str, ...]
    criticality: str = UNSET


@dataclass(frozen=True)
class Inventory:
    company: str
    assets_by_ip: dict[str, Asset]
    ip_by_hostname: dict[str, str]
    unknown_roles: tuple[str, ...] = ()
    unknown_criticalities: tuple[str, ...] = ()

    def __contains__(self, ip: str) -> bool:
        return ip in self.assets_by_ip

    def assets_without_roles(self) -> tuple[str, ...]:
        return tuple(sorted({
            asset.hostname
            for asset in self.assets_by_ip.values()
            if not asset.groups
        }))

    def assets_without_criticality(self) -> tuple[str, ...]:
        return tuple(sorted({
            asset.hostname
            for asset in self.assets_by_ip.values()
            if asset.criticality == UNSET
        }))


def _read_criticality(value: object) -> tuple[str, str | None]:
    if value is None:
        return UNSET, None
    if not isinstance(value, str):
        return UNSET, repr(value)
    tier = value.strip().lower()
    if tier in ("", UNSET):
        return UNSET, None
    if tier in CRITICALITY_LEVELS:
        return tier, None
    return UNSET, value


def load_inventory(path: Path) -> Inventory:
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
    unknown_criticalities: set[str] = set()
    for item in config["assets"]:
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

        groups, unplaced = canonicalize(raw_groups)
        unknown_roles.update(unplaced)
        criticality, unknown = _read_criticality(item.get("criticality"))
        if unknown is not None:
            unknown_criticalities.add(unknown)

        asset = Asset(
            hostname=str(item["hostname"]),
            ip_addresses=tuple(str(ip) for ip in item["ip_addresses"]),
            groups=groups,
            criticality=criticality,
        )
        for ip in asset.ip_addresses:
            assets_by_ip[ip] = asset
        if asset.ip_addresses:
            ip_by_hostname[asset.hostname.casefold()] = asset.ip_addresses[0]

    return Inventory(
        company=str(config.get("company", path.stem)),
        assets_by_ip=assets_by_ip,
        ip_by_hostname=ip_by_hostname,
        unknown_roles=tuple(sorted(unknown_roles)),
        unknown_criticalities=tuple(sorted(unknown_criticalities)),
    )
