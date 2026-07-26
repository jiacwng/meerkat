# Asset role is one feature column per role name, so an inventory using different
# names contributes nothing to a model trained elsewhere. Device types follow the
# OCSF Device type_id enum; the rest are ours because no standard defines them.

from __future__ import annotations

# https://schema.ocsf.io/objects/device, lowercased. Unknown and Other are
# skipped: an absent role already says that.
DEVICE_TYPE_ROLES = (
    "server",
    "desktop",
    "laptop",
    "tablet",
    "mobile",
    "virtual",
    "iot",
    "browser",
    "firewall",
    "switch",
    "hub",
    "router",
    "ids",
    "ips",
    "load_balancer",
)

ZONE_ROLES = (
    "internet_facing",
    "internal",
    "dmz",
    "behind_proxy",
    "nat_forwarded",
)

# what runs on the box, which a device type does not cover
SERVICE_ROLES = (
    "mail_server",
    "dns_server",
    "file_share",
    "monitoring_agent",
)

PEOPLE_ROLES = (
    "employee",
    "internal_employee",
    "remote_employee",
    "external_user",
    "external_mail",
)

CANONICAL_ROLES = DEVICE_TYPE_ROLES + ZONE_ROLES + SERVICE_ROLES + PEOPLE_ROLES

# one-to-one on purpose: merging two names would drop a distinction the forest uses
LEGACY_ROLE_ALIASES = {
    "internet": "internet_facing",
    "intranet": "internal",
    "servers": "server",
    "mailserver": "mail_server",
    "dnsservers": "dns_server",
    "share": "file_share",
    "proxied": "behind_proxy",
    "dnat": "nat_forwarded",
    "ext_user": "external_user",
    "ext_mail": "external_mail",
    "beatservers": "monitoring_agent",
}

_KNOWN = frozenset(CANONICAL_ROLES)


def canonicalize(groups: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    canonical, unknown = [], []
    for group in groups or ():
        name = str(group).strip().casefold()
        if not name:
            continue
        mapped = LEGACY_ROLE_ALIASES.get(name, name)
        if mapped in _KNOWN:
            canonical.append(mapped)
        else:
            unknown.append(name)

    # order by the vocabulary, so two inventories listing the same roles in a
    # different order still produce the same tuple
    found = set(canonical)
    ordered = tuple(role for role in CANONICAL_ROLES if role in found)
    return ordered, tuple(sorted(set(unknown)))


def role_sources() -> dict[str, str]:
    sources = {}
    for role in DEVICE_TYPE_ROLES:
        sources[role] = "OCSF Device type_id"
    for role in ZONE_ROLES:
        sources[role] = "meerkat (OCSF zone has no enum)"
    for role in SERVICE_ROLES:
        sources[role] = "meerkat (service, not a device type)"
    for role in PEOPLE_ROLES:
        sources[role] = "meerkat (no standard covers ownership)"
    return sources
