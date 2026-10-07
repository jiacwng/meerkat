# Turns a client's incident records into training labels. A ticket says an incident
# ran on a host between two times, not which alerts were the attack, so nothing is
# asserted positive: every session inside an incident joins a bag and carries k/n
# of the ticket's weight, and sessions in no bag are negatives. k/n is a bag-size
# discount, not a probability: it keeps each ticket's total weight at k, whatever
# its width.

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

from core.inventory import Inventory

# OCSF Incident Finding verdicts that mean an attack happened; "test" is a purple
# team run, which is known-good supervision
POSITIVE_VERDICTS = frozenset({
    "true_positive", "security_risk", "test", "malicious",
})
BAG_SIZE_DISCOUNT = 1.0
REQUIRED_COLUMNS = ("start", "end", "host", "verdict")


def _epoch_seconds(values: pd.Series, column: str, path: Path) -> pd.Series:
    # epoch seconds or ISO 8601 only, so an ambiguous 12/01/2026 is not guessed
    numeric = pd.to_numeric(values, errors="coerce")
    parsed = pd.to_datetime(
        values.where(numeric.isna()), errors="coerce", utc=True,
        format="ISO8601",
    )
    seconds = (parsed - pd.Timestamp(0, tz="UTC")) / pd.Timedelta(seconds=1)
    combined = numeric.fillna(seconds)
    bad = combined.isna()
    if bad.any():
        raise ValueError(
            f"{path} has {int(bad.sum())} row(s) whose {column} is neither "
            "epoch seconds nor ISO 8601"
        )
    return combined.astype(float)


def load_incidents(path: Path) -> pd.DataFrame:
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"{path} has no incident rows")
    missing = [c for c in REQUIRED_COLUMNS if c not in rows[0]]
    if missing:
        raise ValueError(
            f"{path} is missing {', '.join(missing)}; "
            f"expected columns {', '.join(REQUIRED_COLUMNS)}"
        )
    frame = pd.DataFrame(rows)
    frame["start"] = _epoch_seconds(frame["start"], "start", path)
    frame["end"] = _epoch_seconds(frame["end"], "end", path)
    frame["verdict"] = (
        frame["verdict"].str.strip().str.lower().str.replace(" ", "_")
    )
    finite = frame["start"].notna() & frame["end"].notna()
    finite &= frame["start"].abs().ne(float("inf")) & frame["end"].abs().ne(float("inf"))
    if not finite.all():
        raise ValueError(
            f"{path} has {int((~finite).sum())} row(s) whose start or end is not "
            "a finite number; times are epoch seconds"
        )
    inverted = frame["start"] > frame["end"]
    if inverted.any():
        raise ValueError(
            f"{path} has {int(inverted.sum())} row(s) whose start is after its "
            "end; check the column order"
        )

    kept = frame[frame["verdict"].isin(POSITIVE_VERDICTS)].reset_index(drop=True)
    if kept.empty:
        raise ValueError(
            f"{path} has {len(frame)} rows and none carry a verdict meaning an "
            f"attack happened; expected one of {', '.join(sorted(POSITIVE_VERDICTS))}"
        )
    return kept


def entity_for(host: str, inventory: Inventory) -> str:
    host = str(host).strip()
    if host in inventory.assets_by_ip:
        return host
    return inventory.ip_by_hostname.get(host.casefold(), "")


def assign_bag_priors(
    sessions: pd.DataFrame,
    incidents: pd.DataFrame,
    inventory: Inventory,
) -> pd.Series:
    prior = pd.Series(0.0, index=sessions.index, dtype=float)
    entities = sessions["entity_id"].astype(str)
    for row in incidents.itertuples():
        entity = entity_for(row.host, inventory)
        if not entity:
            continue
        # a burst rarely starts and ends inside the reported window, so any overlap
        # puts a session in the bag
        overlap = (
            entities.eq(entity)
            & sessions["start"].le(row.end)
            & sessions["end"].ge(row.start)
        )
        count = int(overlap.sum())
        if count:
            candidate = BAG_SIZE_DISCOUNT / count
            prior.loc[overlap] = prior.loc[overlap].clip(lower=candidate)
    return prior.clip(upper=1.0)


def unresolved_hosts(incidents: pd.DataFrame, inventory: Inventory) -> list[str]:
    return sorted({
        str(row.host) for row in incidents.itertuples()
        if not entity_for(row.host, inventory)
    })
