# Turn a client's incident records into training labels.
#
# A SOC can say "an incident ran on this host between these times". It cannot say
# which of the alerts inside that window were the attack, and neither can we, so
# nothing is asserted positive. Every session inside an incident joins a bag and
# carries k/n of the ticket's weight; sessions in no bag are clean negatives.
# Measured on AIT: labels are 93.9% pure at bag level against 75.5% at session
# level.
#
# k/n IS A BAG-SIZE DISCOUNT, NOT A PROBABILITY, and the distinction is measured
# rather than stylistic. The true witness rate is 0.755 pooled with a median of
# 1.000, so most bags are entirely positive; using that measured rate as the weight
# scores 41.33 at K=5, the same as no weighting at all. What k/n actually does is
# equalise how much each ticket influences the fit: without it one vague all-day
# ticket contributes as many training rows as twenty precise ones, and in the worst
# AIT environment a single window carried 48.5% of the positive signal. k=1 keeps
# every ticket's total weight at exactly 1.0 whatever its width. k=1 to k=5 differ
# by less than seed noise (paired over ten seeds, p = 0.34), so k=1 is chosen for
# having a reason rather than a score.

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

from core.inventory import Inventory

# OCSF Incident Finding verdict names that mean an attack happened. "test" is
# there because a purple team or Atomic Red Team run is known-good supervision.
POSITIVE_VERDICTS = frozenset({
    "true_positive", "security_risk", "test", "malicious",
})
BAG_SIZE_DISCOUNT = 1.0
REQUIRED_COLUMNS = ("start", "end", "host", "verdict")
REVIEWED_COLUMNS = ("start", "end")


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
    # a swapped start and end matches nothing and used to be diagnosed as
    # "every incident is recent". A non-finite time fails both sides of the
    # holdout comparison, so the row vanished from training AND from scoring.
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
        # otherwise this surfaces much later as "0 sessions fall inside an incident"
        raise ValueError(
            f"{path} has {len(frame)} rows and none carry a verdict meaning an "
            f"attack happened; expected one of {', '.join(sorted(POSITIVE_VERDICTS))}"
        )
    return kept


def load_reviewed_periods(path: Path) -> pd.DataFrame:
    with path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    missing = [c for c in REVIEWED_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(
            f"{path} is missing {', '.join(missing)}; "
            f"expected columns {', '.join(REVIEWED_COLUMNS)}"
        )
    frame = pd.DataFrame(rows, columns=REVIEWED_COLUMNS)
    frame["start"] = _epoch_seconds(frame["start"], "start", path)
    frame["end"] = _epoch_seconds(frame["end"], "end", path)
    return frame


def assign_reviewed(
    sessions: pd.DataFrame,
    periods: pd.DataFrame | None,
) -> pd.Series:
    if periods is None:
        return pd.Series(True, index=sessions.index, dtype=bool)

    reviewed = pd.Series(False, index=sessions.index, dtype=bool)
    for period in periods.itertuples():
        reviewed |= (
            sessions["start"].ge(period.start)
            & sessions["end"].le(period.end)
        )
    return reviewed


def entity_for(host: str, inventory: Inventory) -> str:
    host = str(host).strip()
    if host in inventory.assets_by_ip:
        return host
    return inventory.ip_by_hostname.get(host.casefold(), "")


def assign_bag_priors(
    sessions: pd.DataFrame,
    incidents: pd.DataFrame,
    inventory: Inventory,
    numerator: float = BAG_SIZE_DISCOUNT,
) -> pd.Series:
    prior = pd.Series(0.0, index=sessions.index, dtype=float)
    entities = sessions["entity_id"].astype(str)
    for row in incidents.itertuples():
        entity = entity_for(row.host, inventory)
        if not entity:
            continue
        # a session belongs to the incident if it overlaps the reported window at
        # all, since a burst rarely starts and ends inside it
        overlap = (
            entities.eq(entity)
            & sessions["start"].le(row.end)
            & sessions["end"].ge(row.start)
        )
        count = int(overlap.sum())
        if count:
            candidate = numerator / count
            prior.loc[overlap] = prior.loc[overlap].clip(lower=candidate)
    return prior.clip(upper=1.0)


def unresolved_hosts(incidents: pd.DataFrame, inventory: Inventory) -> list[str]:
    return sorted({
        str(row.host) for row in incidents.itertuples()
        if not entity_for(row.host, inventory)
    })
