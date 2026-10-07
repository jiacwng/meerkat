# The meerkat command line. triage scores a company's alerts into a saved run
# directory; queue, attack, runs, inspect, review, browse and export reopen it
# without scoring again. pull, inventory and check prepare the input, retrain
# and drift compare the model with the client's data, demo scores the bundled
# example, and bare `meerkat` says where things stand. Order in this file: run state, rendering, commands, parser.

from __future__ import annotations

import argparse
import contextlib
import errno
import getpass
import hashlib
import html
import io
import json
import os
import pickle
import re
import shutil
import sys
import tomllib
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from itertools import islice
from pathlib import Path
from typing import NoReturn

import numpy as np
import pandas as pd
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.terminal_theme import DIMMED_MONOKAI

from core.attack_mapping import (
    TACTIC_ORDER,
    HostChain,
    export_navigator_layer,
    host_chain,
    technique_name,
    with_local_mappings,
)
from core.drift import (
    PSI_MAJOR,
    UNSEEN_RULE_WARN,
    compare_profile,
    unseen_rule_share,
)
from core.features import CONTRIBUTION_PREFIX, build_session_feature_matrix
from core.incidents import (
    assign_bag_priors,
    entity_for,
    load_incidents,
    unresolved_hosts,
)
from core.inventory import CRITICALITY_LEVELS, UNSET, load_inventory
from core.normalize import (
    AMINER_FAMILY,
    SURICATA_FAMILY,
    WAZUH_FAMILY,
    AlertFileError,
    iter_normalized_rows,
    normalize_scenario,
    resolve_alert_files,
)
from core.roles import CANONICAL_ROLES, role_sources
from core.sessions import SECONDS_PER_DAY, build_sessions
from core.triage_policy import enrich_alerts, queue_order
from meerkat import __version__

DEFAULT_MODEL = Path("models/meerkat_bundle.skops")
DEFAULT_RUNS = Path("runs")
DEFAULT_INPUT = Path("alerts")

DEMO_COMPANY = "russellmitchell"
DEMO_RAW = Path("data/raw")
DEMO_INVENTORY_DIR = Path("data/raw/inventory")
REVIEW_DECISIONS = ("escalate", "benign", "false-positive")
DETECTOR_LABELS = {"wazuh": "Wazuh", "suricata": "Suricata", "aminer": "AMiner"}
FAMILY_LABELS = {
    WAZUH_FAMILY: "wazuh and suricata",
    SURICATA_FAMILY: "suricata",
    AMINER_FAMILY: "log anomaly",
}

# Rule names, hostnames, user agents and commands are written by whoever triggered
# the alert. rich parses [tags] in anything printed and strips no control
# character, so every alert-derived string goes through safe(): it removes C0, C1
# and the bidi overrides and escapes markup.
_CONTROL_RANGES = (
    (0x00, 0x09), (0x0B, 0x20), (0x7F, 0xA0), (0x202A, 0x202F), (0x2066, 0x206A)
)
_CONTROL = re.compile(
    "[{}]".format("".join(
        chr(point)
        for low, high in _CONTROL_RANGES
        for point in range(low, high)
    ))
)


def safe(value: object) -> str:
    return escape(_CONTROL.sub("", str(value)))


def _exit_on_closed_pipe() -> NoReturn:
    # `queue | head` closes the pipe early, which is an exit and not a crash. The
    # interpreter flushes stdout again on exit, so point it at devnull first.
    with contextlib.suppress(OSError, ValueError):
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    raise SystemExit(0)


class _Console(Console):
    def on_broken_pipe(self) -> None:
        self.quiet = True
        _exit_on_closed_pipe()


console = _Console()
# errors go to stderr so `meerkat queue --json | jq` stays parseable when one fails
errors = _Console(stderr=True)

EXIT_ERROR = 1
EXIT_DECLINED = 3
EXIT_DRIFT = 4


def _fail(message: str) -> NoReturn:
    errors.print(message)
    raise SystemExit(EXIT_ERROR)


def detector_label(detector_source: str) -> str:
    return DETECTOR_LABELS.get(str(detector_source), str(detector_source))


def canon_handle(text: str) -> str:
    match = re.fullmatch(r"([A-Za-z])0*(\d+)", str(text).strip())
    return f"{match.group(1).upper()}{match.group(2)}" if match else str(text).upper()


hints_enabled = True


def _hint(text: str) -> None:
    if hints_enabled:
        errors.print(f"[dim]{text}[/dim]")


def _page(render, disabled: bool) -> None:
    if (not disabled and sys.stdout.isatty()
            and (os.environ.get("PAGER") or shutil.which("less"))):
        os.environ.setdefault("LESS", "-FRX")
        with console.pager(styles=True):
            render()
    else:
        render()


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(company: str) -> str:
    now = datetime.now(UTC)
    return safe_run_id(f"{company}-{now:%Y%m%d-%H%M%S}-{now.microsecond // 1000:03d}")


def _most_common(values: np.ndarray, fallback: str) -> str:
    values = values[values != ""]
    return str(pd.Series(values).mode().iloc[0]) if len(values) else fallback


def decorate_families(
    families: pd.DataFrame,
    alerts: pd.DataFrame,
    budget: int,
) -> pd.DataFrame:
    ordered = queue_order(families).reset_index(drop=True)
    ordered["handle"] = [f"F{i + 1}" for i in range(len(ordered))]
    ordered["queue_rank"] = ordered.groupby("day", sort=False).cumcount()
    ordered["in_queue"] = ordered["queue_rank"] < budget

    names = alerts["name"].astype(str).to_numpy()
    hosts = alerts["host"].astype(str).to_numpy()
    ordered["title"] = [
        _most_common(names[list(rows)], "") for rows in ordered["alert_rows"]
    ]
    ordered["host_label"] = [
        _most_common(hosts[list(rows)], str(entity))
        for rows, entity in zip(ordered["alert_rows"], ordered["entity_id"])
    ]
    return ordered


@dataclass
class RunState:
    run_id: str
    directory: Path
    meta: dict
    families: pd.DataFrame
    sessions: pd.DataFrame
    alerts: pd.DataFrame

    def queue_families(self, show_all: bool) -> pd.DataFrame:
        return self.families if show_all else self.families[self.families["in_queue"]]

    def family_by_handle(self, handle: str) -> pd.Series:
        match = self.families[self.families["handle"].eq(canon_handle(handle))]
        if match.empty:
            raise KeyError(f"no family {handle} in run {self.run_id}")
        return match.iloc[0]

    def session_handles(self, family: pd.Series) -> list[tuple[str, str]]:
        return [
            (f"S{position + 1}", session_id)
            for position, session_id in enumerate(family["child_session_ids"])
        ]

    def session_row(self, session_id: str) -> pd.Series:
        return self.sessions[self.sessions["session_id"].eq(session_id)].iloc[0]

    def session_by_handle(self, family: pd.Series, handle: str) -> pd.Series:
        session_id = dict(self.session_handles(family)).get(canon_handle(handle))
        if session_id is None:
            raise KeyError(f"no session {handle} under {family['handle']}")
        return self.session_row(session_id)

    def family_alerts(self, family: pd.Series) -> pd.DataFrame:
        return self.alerts.iloc[list(family["alert_rows"])]

    def session_alerts(self, session: pd.Series) -> pd.DataFrame:
        return self.alerts.iloc[list(session["alert_rows"])]

    @cached_property
    def host_chains(self) -> dict[tuple[str, int], HostChain]:
        mapped = self.alerts[self.alerts["tactics"].map(bool)]
        days = (mapped["timestamp"] // SECONDS_PER_DAY).astype(int)
        hosts = mapped["entity_id"].astype(str)
        return {
            (host, int(day)): host_chain(group["timestamp"], group["tactics"])
            for (host, day), group in mapped.groupby([hosts, days], sort=False)
        }

    def host_chain(self, family: pd.Series) -> HostChain:
        key = (str(family["entity_id"]), int(family["day"]))
        return self.host_chains.get(key, HostChain([], ()))

    def with_chain(self, families: pd.DataFrame) -> pd.DataFrame:
        lengths = [self.host_chain(family).length for _, family in families.iterrows()]
        return families.assign(chain=lengths)

    def family_tactics(self, family: pd.Series) -> set[str]:
        found: set[str] = set()
        for tactics in self.family_alerts(family)["tactics"]:
            found.update(tactics)
        return found

    def related_families(self, family: pd.Series) -> pd.DataFrame:
        same = self.families[
            self.families["entity_id"].eq(family["entity_id"])
            & self.families["handle"].ne(family["handle"])
        ].copy()
        if same.empty:
            return same
        same["gap_s"] = (same["start"] - family["start"]).abs()
        return same.sort_values("gap_s", kind="stable")


# A run is unpickled on open, so only the (module, name) pairs a saved pandas frame
# needs are allowed. A whole package is never trusted: numpy ships an exec wrapper
# and pandas a pickle reader with no allowlist.
_PICKLE_ALLOWED = frozenset({
    ("builtins", "slice"),
    ("numpy", "dtype"),
    ("numpy", "ndarray"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.numeric", "_frombuffer"),
    ("pandas", "Categorical"),
    ("pandas", "CategoricalDtype"),
    ("pandas", "DataFrame"),
    ("pandas", "Index"),
    ("pandas", "RangeIndex"),
    ("pandas", "StringDtype"),
    ("pandas.arrays", "StringArray"),
    ("pandas._libs.arrays", "__pyx_unpickle_NDArrayBacked"),
    ("pandas._libs.internals", "_unpickle_block"),
    ("pandas.core.arrays.categorical", "Categorical"),
    ("pandas.core.dtypes.dtypes", "CategoricalDtype"),
    ("pandas.core.frame", "DataFrame"),
    ("pandas.core.indexes.base", "Index"),
    ("pandas.core.indexes.base", "_new_Index"),
    ("pandas.core.indexes.range", "RangeIndex"),
    ("pandas.core.internals.managers", "BlockManager"),
})


class _RunUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in _PICKLE_ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked type in run file: {module}.{name}")


def _read_run_frame(path: Path) -> pd.DataFrame:
    try:
        with path.open("rb") as handle:
            return _RunUnpickler(handle).load()
    except (pickle.UnpicklingError, EOFError, AttributeError, ImportError) as error:
        raise ValueError(f"{path.name} is not a readable run file: {error}") from error
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{path.name} was saved by another pandas version and cannot be "
            f"read by pandas {pd.__version__}; re-run triage"
        ) from error


def save_run(
    runs_dir: Path,
    run_id: str,
    meta: dict,
    families: pd.DataFrame,
    sessions: pd.DataFrame,
    alerts: pd.DataFrame,
) -> Path:
    directory = runs_dir / run_id
    suffix = 1
    while (directory / "run.json").exists():
        suffix += 1
        directory = runs_dir / f"{run_id}-{suffix}"
    directory.mkdir(parents=True, exist_ok=True)
    families.to_pickle(directory / "families.pkl")
    sessions.to_pickle(directory / "sessions.pkl")
    alerts.to_pickle(directory / "alerts.pkl")
    (directory / "run.json").write_text(
        json.dumps({**meta, "run_id": run_id, "saved_at": _now_iso()}, indent=2),
        encoding="utf-8",
    )
    (runs_dir / "latest.txt").write_text(directory.name, encoding="utf-8")
    return directory


def latest_run_id(runs_dir: Path) -> str | None:
    pointer = runs_dir / "latest.txt"
    if not pointer.exists():
        return None
    return pointer.read_text(encoding="utf-8").strip() or None


def load_run(runs_dir: Path, run_id: str | None = None) -> RunState:
    if run_id is None:
        run_id = latest_run_id(runs_dir)
    if run_id is None:
        where = "" if runs_dir.is_absolute() else (
            f"\n{runs_dir} is resolved from the current directory, so a run "
            "written from somewhere else is not found here. Pass --runs-dir "
            "with the directory triage wrote to."
        )
        raise FileNotFoundError(
            f"no runs in {runs_dir}, run `meerkat triage` first{where}"
        )
    directory = runs_dir / safe_run_id(run_id)
    if not (directory / "run.json").exists():
        raise FileNotFoundError(f"run {run_id} not found in {runs_dir}")
    return RunState(
        run_id=run_id,
        directory=directory,
        meta=json.loads((directory / "run.json").read_text(encoding="utf-8")),
        families=_read_run_frame(directory / "families.pkl"),
        sessions=_read_run_frame(directory / "sessions.pkl"),
        alerts=_read_run_frame(directory / "alerts.pkl"),
    )


# A session's identity has to survive a retrain, and its id, handle, start and row
# offsets all move with it. Where each alert sits in the raw detector file does not,
# so the key digests that.
def session_label_key(session: pd.Series, alerts: pd.DataFrame) -> str:
    rows = alerts.iloc[list(session["alert_rows"])]
    origin = sorted(
        f"{file}:{position}"
        for file, position in zip(rows["source_file"], rows["source_position"])
    )
    seed = (
        f"{session['entity_id']}|{session['detector_source']}"
        f"|{session['rule_id']}|{'|'.join(origin)}"
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def append_review(
    directory: Path,
    run_id: str,
    family_id: str,
    handle: str,
    decision: str,
    note: str,
    session_key: str | None = None,
    session_handle: str | None = None,
    analyst: str | None = None,
) -> dict:
    _BANDS_CACHE.pop(directory.parent, None)
    if analyst is None:
        try:
            analyst = getpass.getuser()
        except OSError:
            analyst = ""
    entry = {
        "timestamp": _now_iso(),
        "analyst": analyst,
        "run_id": run_id,
        "family_id": family_id,
        "handle": handle,
        "decision": decision,
        "note": note,
        "session_key": session_key,
        "session_handle": session_handle,
    }
    with (directory / "reviews.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")
    return entry


def review_history(directory: Path) -> list[dict]:
    path = directory / "reviews.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and isinstance(
            entry.get("family_id"), str
        ) and isinstance(entry.get("decision"), str):
            entries.append(entry)
    return entries


def replay_reviews(directory: Path) -> dict[str, dict[str, dict]]:
    # the audit log replayed in order: per family, the last entry covering each
    # scope. "*" is a family-wide decision, which replaces every earlier session
    # entry; a session entry covers only its own session.
    covered: dict[str, dict[str, dict]] = {}
    for entry in review_history(directory):
        scopes = covered.setdefault(entry["family_id"], {})
        handle = entry.get("session_handle")
        if handle:
            scopes.pop(handle, None)
            scopes[handle] = entry
        else:
            covered[entry["family_id"]] = {"*": entry}
    return covered


def current_reviews(directory: Path) -> dict[str, dict]:
    # one decision per family: the family-wide one if it exists, otherwise the
    # latest session entry
    return {
        family_id: scopes.get("*") or list(scopes.values())[-1]
        for family_id, scopes in replay_reviews(directory).items()
    }


EVIDENCE_PANELS = (
    ("Finding / Detection", (
        ("rule", "rule_id"),
        ("severity", "severity"),
        ("category", "alert_category"),
        ("rule groups", "rule_groups"),
        ("anomaly score", "anomaly_scores"),
        ("threshold", "probability_threshold"),
        ("critical value", "critical_value"),
    )),
    ("Identity / Authentication", (
        ("source user", "source_user"),
        ("target user", "target_user"),
    )),
    ("Process / System", (
        ("command", "command"),
        ("executable", "executable"),
        ("working dir", "working_directory"),
    )),
    ("Network", (
        ("source ip", "source_ip"),
        ("dest ip", "destination_ip"),
        ("source port", "source_port"),
        ("dest port", "destination_port"),
        ("transport", "network_protocol"),
        ("app proto", "application_protocol"),
        ("bytes to server", "flow_bytes_to_server"),
        ("bytes to client", "flow_bytes_to_client"),
    )),
    ("Network / HTTP", (
        ("request", "web_request"),
        ("method", "http_method"),
        ("status", "http_status"),
        ("hostname", "http_hostname"),
        ("user agent", "http_user_agent"),
    )),
    ("Network / DNS", (
        ("query", "dns_query"),
    )),
    ("Network / TLS", (
        ("sni", "tls_server_name"),
        ("version", "tls_version"),
        ("ja3", "tls_ja3"),
    )),
    ("Provenance", (
        ("detector", "detector_source"),
        ("source file", "source_file"),
        ("source position", "source_position"),
        ("native event id", "native_event_id"),
    )),
)


def fmt_time(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), tz=UTC).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def fmt_date(day: int) -> str:
    return datetime.fromtimestamp(int(day) * 86400, tz=UTC).strftime(
        "%Y-%m-%d"
    )


def fmt_span(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def _http_outcome(alert_slice: pd.DataFrame) -> str:
    if "http_status" not in alert_slice.columns:
        return ""
    statuses = pd.to_numeric(
        alert_slice["http_status"], errors="coerce"
    ).dropna().astype(int)
    if statuses.empty:
        return ""

    succeeded = statuses[statuses.between(200, 399)]
    total = len(statuses)
    noun = "request" if total == 1 else "requests"

    def codes(values) -> str:
        return ", ".join(str(code) for code in sorted(set(values)))

    if total == 1:
        verdict = "succeeded" if len(succeeded) else "failed"
        return f"1 {noun}, {verdict} ({codes(statuses)})"
    if not len(succeeded):
        return f"{total} {noun}, none succeeded ({codes(statuses)})"
    if len(succeeded) == total:
        return f"{total} {noun}, all succeeded ({codes(statuses)})"
    return (
        f"{total} {noun}, {len(succeeded)} succeeded "
        f"({codes(succeeded)}) of {codes(statuses)}"
    )


VALUES_SHOWN = 6


def _values(alert_slice: pd.DataFrame, field: str) -> str | None:
    if field not in alert_slice.columns:
        return None
    column = alert_slice[field]
    if column.dtype.kind == "f":
        column = column.dropna()
        seen = list(dict.fromkeys(column.tolist()))
        rendered = [f"{value:g}" for value in seen]
    else:
        column = column.astype(str)
        column = column[column.ne("")]
        rendered = list(dict.fromkeys(column.tolist()))
    if not rendered:
        return None
    shown = rendered[:VALUES_SHOWN]
    extra = len(rendered) - len(shown)
    text = ", ".join(shown)
    return text + (f"  (+{extra} more; --distinct {field})" if extra else "")


def _render_panels(alert_slice: pd.DataFrame) -> None:
    for title, rows in EVIDENCE_PANELS:
        lines = []
        for label, field in rows:
            value = _values(alert_slice, field)
            if value is not None:
                lines.append((label, value))
        if not lines:
            continue
        console.print(f"[bold cyan]{title}[/bold cyan]")
        width = max(len(label) for label, _ in lines)
        for label, value in lines:
            console.print(f"  {label.rjust(width)} : {safe(value)}")
        console.print()


def _render_host_chain(run: RunState, family: pd.Series) -> None:
    chain = run.host_chain(family)
    console.print("[bold cyan]ATT&CK chain on this host[/bold cyan]")
    if not chain.steps:
        console.print("  [dim]no mapped tactic on this host that day[/dim]\n")
        return
    width = max(len(tactic) for tactic, _ in chain.steps)
    for step, (tactic, timestamp) in enumerate(chain.steps, start=1):
        console.print(f"  {step}. {tactic.ljust(width)}  {fmt_time(timestamp)[11:]}")
    if chain.off_chain:
        console.print(f"  also seen off the chain: {', '.join(chain.off_chain)}")
    console.print(
        "  [dim]tactics mapped per alert; the chain orders them by time only[/dim]\n"
    )


SESSION_EVIDENCE = "session evidence"
FAMILY_FEATURE_PHRASES = {
    "child_score_max": SESSION_EVIDENCE,
    "child_score_mean": SESSION_EVIDENCE,
    "child_score_std": SESSION_EVIDENCE,
    "n_child_sessions": "number of sessions",
    "family_span_s": "time span",
    "alert_count": "alert count",
    "detectors_on_entity": "detectors on this host that day",
    "groups_on_entity": "sessions on this host that day",
    "log_alerts_on_entity": "alert volume on this host that day",
    "detectors_nearby_10m": "detectors within 10 minutes",
    "alert_category_count": "distinct alert categories",
    "technique_count": "distinct ATT&CK techniques",
    "rule_group_count": "distinct rule groups",
}
TOP_CONTRIBUTIONS = 5


def feature_phrase(name: str) -> str:
    if name.startswith("role_"):
        return f"asset role {name[len('role_'):]}"
    return FAMILY_FEATURE_PHRASES.get(name, name)


def family_contributions(family: pd.Series) -> list[tuple[str, float]]:
    roles = set(family.get("asset_roles") or ())
    merged: dict[str, float] = {}
    for column, value in family.items():
        if not str(column).startswith(CONTRIBUTION_PREFIX):
            continue
        name = str(column)[len(CONTRIBUTION_PREFIX):]
        if name.startswith("role_") and name[len("role_"):] not in roles:
            continue
        phrase = feature_phrase(name)
        merged[phrase] = merged.get(phrase, 0.0) + float(value)
    return sorted(merged.items(), key=lambda item: abs(item[1]), reverse=True)


def top_raise(family: pd.Series) -> str:
    for phrase, value in family_contributions(family):
        if value > 0 and phrase != SESSION_EVIDENCE:
            return phrase
    return ""


def _render_why(family: pd.Series) -> None:
    console.print("[bold cyan]Ranking signals, largest contributions[/bold cyan]")
    contributions = family_contributions(family)
    total = sum(abs(value) for _, value in contributions)
    if not total:
        console.print("  [dim]this run holds no contributions; re-run triage[/dim]\n")
        return
    shown = contributions[:TOP_CONTRIBUTIONS]
    width = max(len(phrase) for phrase, _ in shown)
    for phrase, value in shown:
        direction = "raises" if value > 0 else "lowers"
        console.print(
            f"  {direction}  {phrase.ljust(width)}  {abs(value) / total:4.0%}"
        )
    console.print("  [dim]share of the total push on this family's score[/dim]\n")


ESC_BAND_FLOOR = 5


def escalation_bands(runs_dir: Path) -> dict[float, tuple[int, int]]:
    # the analyst's own reviews across every run, keyed by score band. The deployed
    # model never trained on the days it scored, so these are out of sample.
    bands: dict[float, tuple[int, int]] = {}
    if not runs_dir.is_dir():
        return bands
    for directory in sorted(runs_dir.iterdir()):
        families_pkl = directory / "families.pkl"
        try:
            if not directory.is_dir() or not families_pkl.exists():
                continue
            reviewed = replay_reviews(directory)
            if not reviewed:
                continue
            families = _read_run_frame(families_pkl)
        except (OSError, ValueError):
            continue
        scores = dict(zip(families["family_id"], families["ranking_score"]))
        for family_id, scopes in reviewed.items():
            if family_id not in scores:
                continue
            band = round(float(scores[family_id]), 1)
            count, escalated = bands.get(band, (0, 0))
            bands[band] = (
                count + 1,
                escalated + any(e["decision"] == "escalate" for e in scopes.values()),
            )
    return bands


def esc_label(score: float, bands: dict[float, tuple[int, int]] | None) -> str:
    reviewed, escalated = (bands or {}).get(round(float(score), 1), (0, 0))
    if reviewed < ESC_BAND_FLOOR:
        return ""
    return f"{100 * escalated / reviewed:.0f} ({reviewed})"


_BANDS_CACHE: dict[Path, dict[float, tuple[int, int]]] = {}


def bands_for(runs_dir: Path) -> dict[float, tuple[int, int]]:
    if runs_dir not in _BANDS_CACHE:
        _BANDS_CACHE[runs_dir] = escalation_bands(runs_dir)
    return _BANDS_CACHE[runs_dir]


QUEUE_COLUMNS = (
    ("handle", {"no_wrap": True, "min_width": 6}),
    ("date", {"no_wrap": True}),
    ("start", {"no_wrap": True}),
    ("host", {"no_wrap": True, "max_width": 18, "overflow": "ellipsis"}),
    ("crit", {"no_wrap": True}),
    ("detector", {"no_wrap": True}),
    ("finding", {"no_wrap": True, "max_width": 40, "overflow": "ellipsis"}),
    ("why", {"no_wrap": True, "max_width": 28, "overflow": "ellipsis"}),
    ("alerts", {"justify": "right", "no_wrap": True}),
    ("chain", {"justify": "right", "no_wrap": True}),
    ("score", {"justify": "right", "no_wrap": True, "min_width": 5}),
    ("esc%", {"justify": "right", "no_wrap": True, "min_width": 7}),
    ("review", {"no_wrap": True, "min_width": 6}),
)
QUEUE_DROPPED_WHEN_NARROW = (
    (),
    ("why", "chain", "esc%"),
    ("why", "chain", "esc%", "start", "crit"),
)


def _queue_table(title, rows, hidden) -> Table:
    table = Table(title=f"{title}  |  F1 = top priority",
                  title_justify="left", header_style="bold")
    shown = [name not in hidden for name, _ in QUEUE_COLUMNS]
    for (name, options), keep in zip(QUEUE_COLUMNS, shown):
        if keep:
            table.add_column(name, **options)
    for cells in rows:
        table.add_row(*(cell for cell, keep in zip(cells, shown) if keep))
    return table


def render_queue(
    families: pd.DataFrame,
    reviews: dict[str, dict],
    title: str,
    bands: dict[float, tuple[int, int]] | None = None,
) -> None:
    from rich.measure import Measurement

    if not len(families):
        console.print(f"[dim]{title}: no families match[/dim]")
        return
    rows = []
    for _, family in families.iterrows():
        review = reviews.get(family["family_id"], {})
        rows.append([
            family["handle"],
            fmt_date(family["day"]),
            fmt_time(family["start"])[11:16],
            safe(family["host_label"]),
            _criticality_label(family),
            detector_label(family["detector_source"]),
            safe(family["title"] or family["rule_id"])[:40],
            top_raise(family),
            str(int(family["alert_count"])),
            str(int(family.get("chain", 0)) or ""),
            f"{family['ranking_score']:.2f}",
            esc_label(family["ranking_score"], bands),
            review.get("decision", ""),
        ])
    for hidden in QUEUE_DROPPED_WHEN_NARROW:
        table = _queue_table(title, rows, hidden)
        unbounded = console.options.update_width(10_000)
        natural = Measurement.get(console, unbounded, table).maximum
        if natural <= console.width:
            break
    console.print(table)


def _criticality_label(family: pd.Series) -> str:
    return "" if family["criticality"] == UNSET else family["criticality"]


def family_heading(family: pd.Series) -> str:
    return (
        f"{family['handle']}  {safe(family['host_label'])} / "
        f"{detector_label(family['detector_source'])} / "
        f"{safe(family['title'] or family['rule_id'])}"
    )


def render_family(
    run: RunState,
    family: pd.Series,
    reviews: dict[str, dict],
) -> None:
    alert_slice = run.family_alerts(family)
    bands = bands_for(run.directory.parent)
    console.print(f"\n[bold]{family_heading(family)}[/bold]\n")
    console.print("[bold cyan]Overview[/bold cyan]")
    console.print(f"  entity        : {safe(family['entity_id'])}")
    if family["asset_roles"]:
        console.print(f"  asset         : {', '.join(family['asset_roles'])}")
    if _criticality_label(family):
        console.print(f"  criticality   : {family['criticality']}")
    console.print(f"  rule          : {safe(family['rule_id'])}")
    console.print(
        f"  window        : {fmt_time(family['start'])}"
        f"  ->  {fmt_time(family['end'])}  ({fmt_span(family['family_span_s'])})"
    )
    esc = esc_label(family["ranking_score"], bands)
    console.print(
        f"  ranking score : {family['ranking_score']:.3f}"
        + (f"   esc% {esc}" if esc else "")
    )
    rule_peers = run.families[
        run.families["detector_source"].eq(family["detector_source"])
        & run.families["rule_id"].eq(family["rule_id"])
        & run.families["family_id"].ne(family["family_id"])
    ]
    volume_comparison = ""
    if len(rule_peers) >= 3:
        median = float(rule_peers["alert_count"].median())
        ratio = int(family["alert_count"]) / median
        if ratio >= 2 or ratio <= 0.5:
            ratio_text = f"{ratio:.1f}".rstrip("0").rstrip(".")
            volume_comparison = (
                f", {ratio_text}x the median for this rule in this run"
            )
    alerts_n = int(family["alert_count"])
    sessions_n = int(family["n_child_sessions"])
    console.print(
        f"  volume        : {alerts_n} alert{'' if alerts_n == 1 else 's'}, "
        f"{sessions_n} session{'' if sessions_n == 1 else 's'}"
        f"{volume_comparison}"
    )
    outcome = _http_outcome(alert_slice)
    if outcome:
        console.print(f"  outcome       : {outcome}")
    techniques = sorted(family["technique_id_set"])
    if techniques:
        console.print(f"  techniques    : {_technique_text(techniques)}")
    review = reviews.get(family["family_id"])
    if review:
        console.print(
            f"  review        : {review['decision']}"
            + (f"  ({safe(review['note'])})" if review.get("note") else "")
        )
    console.print()

    _render_why(family)

    _render_session_list(run, family)
    if len(run.session_handles(family)) == 1:
        _render_panels(alert_slice)

    _render_host_chain(run, family)
    _render_related(run, family)


def _render_session_list(run: RunState, family: pd.Series) -> None:
    table = Table(title="Sessions  |  S1 = strongest", title_justify="left",
                  header_style="bold")
    table.add_column("handle")
    table.add_column("start")
    table.add_column("span")
    table.add_column("alerts", justify="right")
    table.add_column("score", justify="right")
    for handle, session_id in run.session_handles(family):
        session = run.session_row(session_id)
        table.add_row(
            handle,
            fmt_time(session["start"]),
            fmt_span(session["duration_s"]),
            str(int(session["size"])),
            f"{session['ranking_score']:.2f}",
        )
    console.print(table)
    console.print(
        "[dim]drill into one with `meerkat inspect "
        f"{family['handle']} S1`[/dim]\n"
    )


def _render_related(run: RunState, family: pd.Series) -> None:
    related = run.related_families(family)
    console.print("[bold cyan]Related families on this host[/bold cyan]")
    if related.empty:
        console.print("  [dim]none[/dim]\n")
        return
    for _, other in related.head(6).iterrows():
        corroborates = other["detector_source"] != family["detector_source"]
        note = "  [yellow]other detector[/yellow]" if corroborates else ""
        console.print(
            f"  {other['handle']}  {detector_label(other['detector_source'])}"
            f" / {safe(other['title'] or other['rule_id'])}"
            f"  score {other['ranking_score']:.2f}{note}"
        )
    console.print()


def render_session(
    family: pd.Series,
    handle: str,
    session: pd.Series,
    alert_slice: pd.DataFrame,
) -> None:
    console.print(
        f"\n[bold]{family['handle']} {handle}  "
        f"{safe(family['host_label'])} / "
        f"{detector_label(session['detector_source'])} / "
        f"{safe(family['title'] or session['rule_id'])}[/bold]\n"
    )
    console.print("[bold cyan]Overview[/bold cyan]")
    console.print(
        f"  burst  : {fmt_time(session['start'])}  ->  "
        f"{fmt_time(session['end'])}  ({fmt_span(session['duration_s'])})"
    )
    console.print(
        f"  volume : {int(session['size'])} alerts, "
        f"score {session['ranking_score']:.2f}"
    )
    native = (
        pd.to_numeric(alert_slice["severity"], errors="coerce").dropna()
        if "severity" in alert_slice.columns else pd.Series(dtype=float)
    )
    if len(native):
        level = native.max()
        rendered = str(int(level)) if float(level).is_integer() else f"{level:g}"
        console.print(
            f"  severity: {detector_label(session['detector_source'])} "
            f"{rendered} (native scale)"
        )
    stamps = pd.to_numeric(alert_slice["timestamp"], errors="coerce").dropna()
    span = float(session["duration_s"])
    if len(stamps) >= 5 and span > 0:
        inner = float(stamps.quantile(0.9) - stamps.quantile(0.1))
        if inner <= span * 0.1:
            shape = "single spike"
        elif inner <= span * 0.5:
            shape = "clustered bursts"
        else:
            shape = "steady across the window"
        console.print(f"  shape  : {shape}")
    outcome = _http_outcome(alert_slice)
    if outcome:
        console.print(f"  outcome: {outcome}")
    technique_ids = _slice_technique_ids(alert_slice)
    if technique_ids:
        console.print(f"  techniques: {_technique_text(technique_ids)}")
    console.print()
    _render_panels(alert_slice)


WHAT_DIFFERS = (
    "web_request", "http_status", "source_port", "destination_port",
    "dns_query", "tls_server_name", "command", "destination_user",
    "source_user",
)
ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _differs_field(alert_slice: pd.DataFrame) -> str:
    for field in WHAT_DIFFERS:
        if field not in alert_slice.columns:
            continue
        values = alert_slice[field].astype(str)
        values = values[~values.isin(("", "nan", "None"))]
        if values.nunique() > 1:
            return field
    return ""


def _technique_text(technique_ids) -> str:
    parts = []
    for technique_id in sorted(technique_ids):
        name = technique_name(technique_id)
        if name != technique_id:
            url = ATTACK_URL.format(technique_id.replace(".", "/"))
            parts.append(f"[link={url}]{safe(technique_id)}[/link] {safe(name)}")
        else:
            parts.append(safe(technique_id))
    return ", ".join(parts)


def _slice_technique_ids(alert_slice: pd.DataFrame) -> set[str]:
    ids: set[str] = set()
    for value in alert_slice.get("native_technique_ids", pd.Series(dtype=str)):
        for technique_id in str(value).split(";"):
            if technique_id and technique_id != "nan":
                ids.add(technique_id)
    return ids


def render_alert_rows(alert_slice: pd.DataFrame, limit: int) -> None:
    table = Table(
        title=f"Alerts (showing {min(limit, len(alert_slice))} of "
        f"{len(alert_slice)})  |  A1 = first in time",
        title_justify="left",
        header_style="bold",
    )
    differs = _differs_field(alert_slice)
    table.add_column("handle")
    table.add_column("time")
    table.add_column("detector")
    table.add_column("name")
    if differs:
        table.add_column(differs)
    table.add_column("source")

    def row(position: int) -> None:
        alert = alert_slice.iloc[position]
        cells = [
            f"A{position + 1}",
            fmt_time(alert["timestamp"]),
            detector_label(alert["detector_source"]),
            safe(alert["name"])[:44],
        ]
        if differs:
            value = alert[differs]
            rendered = f"{value:g}" if isinstance(value, float) else str(value)
            cells.append(safe(rendered)[:28])
        cells.append(safe(f"{alert['source_file']}:{alert['source_position']}"))
        table.add_row(*cells)

    total = len(alert_slice)
    if total > limit + 3:
        for position in range(limit - 3):
            row(position)
        table.add_row("...", f"{total - limit} more", "", "", *([""] if differs else []), "")
        for position in range(total - 3, total):
            row(position)
    else:
        for position in range(min(limit, total)):
            row(position)
    console.print(table)


ALERT_DETAIL_SKIP = ("alert_rows", "source_file", "source_position")


def render_alert_detail(
    family: pd.Series,
    session_handle: str,
    alert_handle: str,
    alert: pd.Series,
) -> None:
    console.print(
        f"\n[bold]{family['handle']} {session_handle} {alert_handle}  "
        f"{safe(str(alert['name']))}[/bold]\n"
    )
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("field", style="cyan")
    table.add_column("value")
    for field, value in alert.items():
        if field in ALERT_DETAIL_SKIP:
            continue
        text = str(value)
        if text in ("", "nan", "None", "[]", "set()"):
            continue
        if field == "native_technique_ids":
            table.add_row(str(field), _technique_text(text.split(";")))
            continue
        table.add_row(str(field), safe(text)[:220])
    console.print(table)
    console.print(
        f"\n[dim]source {safe(str(alert['source_file']))}:"
        f"{alert['source_position']}[/dim]"
    )


def render_distinct(alert_slice: pd.DataFrame, field: str) -> None:
    counts = (
        alert_slice[field].astype(str).replace("", pd.NA).dropna().value_counts()
    )
    table = Table(
        title=f"distinct {field}", title_justify="left", header_style="bold"
    )
    table.add_column(field)
    table.add_column("alerts", justify="right")
    for value, count in counts.items():
        table.add_row(safe(value)[:60], str(int(count)))
    console.print(table)


# a missing bundle has two causes: models/ is not part of the installed package, so
# running outside a clone points at an empty path, and inside a clone the file is
# usually waiting on git lfs pull
def _require_bundle(path: Path) -> None:
    if path.exists():
        return
    if path == DEFAULT_MODEL and not path.parent.exists():
        _fail(
            f"[red]no model at {safe(path)}[/red]\n"
            f"{safe(path)} is relative to the current directory, and models/ is not "
            "part of the installed package. Run from a clone of the "
            "repository, or pass --model with the path to a bundle.\n"
        )
    _fail(
        f"[red]no model at {safe(path)}[/red]\n"
        "if this is a clone, the bundle is stored with Git LFS:\n\n"
        "  git lfs install\n"
        "  git lfs pull\n"
    )


def _load_bundle(path: Path):
    _require_bundle(path)
    # imported here so the read commands never pay for the ML stack
    from core.classifier import UntrustedBundleError, load_model, read_provenance

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            bundle = load_model(path)
        except UntrustedBundleError as error:
            _fail(f"[red]{safe(str(error))}[/red]")
    mismatched = [
        w for w in caught
        if "InconsistentVersionWarning" in type(w.message).__name__
    ]
    if mismatched:
        import sklearn
        console.print(
            f"[yellow]note[/yellow] the bundled model was trained with a "
            f"different scikit-learn than the installed {sklearn.__version__}. "
            "It loads and scores normally; retrain with `meerkat retrain` to "
            "silence this."
        )
    record = read_provenance(path)
    if record is None:
        errors.print(
            f"[yellow]note[/yellow] {safe(path.name)} has no provenance sidecar, so "
            "there is no record of what trained it."
        )
    elif not record.get("matches_file", True):
        errors.print(
            f"[red]warning[/red] {safe(path.name)} does not match the sha256 in "
            f"{safe(path.name)}.json, so it changed after it was written. Retrain with "
            "`meerkat retrain` rather than trusting it."
        )
    return bundle


def _load_run(args) -> RunState:
    try:
        return load_run(args.runs_dir, args.run)
    except (FileNotFoundError, ValueError) as error:
        _fail(f"[red]{safe(error)}[/red]")


def _announce_run(run: RunState) -> None:
    company = run.meta.get("company", "?")
    budget = run.meta.get("budget", "?")
    console.print(
        f"[dim]run {run.run_id}  |  company {company}  |  "
        f"budget {budget}  |  {len(run.families)} families[/dim]"
    )


def _require(path: Path, what: str) -> None:
    if not path.exists():
        _fail(f"[red]{what} not found:[/red] {safe(path)}")


def _aminer_name(args, company: str) -> str:
    return args.aminer_file.name if args.aminer_file else f"{company}_aminer.json"


def _open_company(args) -> str:
    require_directory(args.input)
    company = resolve_company(args)
    if args.inventory is None:
        args.inventory = args.input / "inventory" / f"{company}.json"
    _require(args.inventory, "inventory")
    return company


def _role_problems(inventory, source: str) -> dict[str, str]:
    problems = {}
    unroled = inventory.assets_without_roles()
    if unroled:
        share = len(unroled) / max(len(set(inventory.assets_by_ip.values())), 1)
        problems["assets_without_roles"] = (
            f"[yellow]{len(unroled)} assets have no roles[/yellow] "
            f"({share:.0%} of {source}). Their alerts are scored "
            "without the role features. `meerkat inventory --list-roles` lists "
            "the vocabulary."
        )
    if inventory.unknown_roles:
        problems["unknown_roles"] = (
            f"[yellow]unrecognised roles[/yellow] "
            f"{', '.join(safe(role) for role in inventory.unknown_roles)} "
            "contribute nothing to a model trained elsewhere"
        )
    return problems


def _score_company(
    bundle,
    input_dir: Path,
    company: str,
    inventory_path: Path,
    wazuh_file: Path | None,
    aminer_file: Path | None,
    attack_mappings: dict,
):
    from core.scenario_eval import score_sessions

    inventory = load_inventory(inventory_path)
    for message in _role_problems(inventory, inventory_path.name).values():
        console.print(message)
    frame = normalize_scenario(
        input_dir, None, company, inventory_path,
        wazuh_file=wazuh_file, aminer_file=aminer_file,
    )
    if frame.empty:
        _fail("[red]no alerts parsed[/red]  the files resolved but held no rows")
    sessions = build_sessions(frame, company, inventory)
    alerts = enrich_alerts(frame, attack_mappings)
    scored_sessions, families = score_sessions(bundle, sessions)
    return scored_sessions, families, alerts


def _file_record(path: Path | None) -> dict | None:
    if path is None:
        return None
    return {
        "file": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _resolve_files(
    input_dir: Path,
    company: str,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
):
    try:
        return resolve_alert_files(input_dir, company, wazuh_file, aminer_file)
    except FileNotFoundError as error:
        _fail(f"[red]{safe(error)}[/red]")


def cmd_triage(args) -> None:
    _require_bundle(args.model)
    company = _open_company(args)
    alert_files = _resolve_files(
        args.input, company, args.wazuh_file, args.aminer_file
    )
    bundle = _load_bundle(args.model)
    mappings = _load_or_exit(
        with_local_mappings, args.attack_mappings, "the local ATT&CK mapping"
    )
    if not any(family == AMINER_FAMILY for _, family in alert_files):
        console.print(
            f"[yellow]no {_aminer_name(args, company)}[/yellow]  scoring wazuh "
            "and suricata only; log anomaly detections will be missing from "
            "the queue"
        )
    console.print(f"scoring {company} with {args.model}")
    scored_sessions, families, alerts = _score_company(
        bundle, args.input, company, args.inventory,
        args.wazuh_file, args.aminer_file, mappings,
    )
    families = decorate_families(families, alerts, args.budget)

    meta = {
        "company": company,
        "budget": args.budget,
        "model": str(args.model),
        "input": str(args.input),
        "training_scenarios": list(bundle.training_scenarios),
        "families": int(len(families)),
        "sessions": int(len(scored_sessions)),
        "alerts": int(len(alerts)),
        "attack_mappings": _file_record(args.attack_mappings),
    }
    directory = save_run(
        args.runs_dir, new_run_id(company), meta, families, scored_sessions, alerts
    )
    console.print(f"[green]saved run[/green] {directory}")
    _print_queue(
        RunState(directory.name, directory, meta, families, scored_sessions, alerts),
        QueueFilter(),
    )


@dataclass
class QueueFilter:
    show_all: bool = False
    host: str | None = None
    detector: str | None = None
    rule: str | None = None
    review_state: str | None = None
    day: str | None = None
    criticality: str | None = None
    tactic: str | None = None

    @property
    def whole_run(self) -> bool:
        # a filter narrows the whole run, not only each day's top-K, so it reaches
        # families below the queue line too; --day picks one day and keeps its top-K
        return self.show_all or any((
            self.host, self.detector, self.rule, self.review_state,
            self.criticality, self.tactic,
        ))


def _select_families(run: RunState, filters: QueueFilter) -> pd.DataFrame:
    families = run.queue_families(filters.whole_run)
    if filters.day:
        dates = families["day"].map(fmt_date)
        if filters.day not in set(dates):
            _fail(
                f"[red]no day {safe(filters.day)} in this run[/red]  available: "
                + ", ".join(sorted(set(run.families["day"].map(fmt_date))))
            )
        families = families[dates.eq(filters.day)]
    if filters.host:
        families = families[
            families["host_label"].astype(str).eq(filters.host)
            | families["entity_id"].astype(str).eq(filters.host)
        ]
    if filters.detector:
        families = families[
            families["detector_source"].astype(str).eq(filters.detector)
        ]
    if filters.rule:
        families = families[
            families["rule_id"].astype(str).str.contains(
                filters.rule, case=False, regex=False
            )
        ]
    if filters.criticality:
        families = families[families["criticality"].astype(str).eq(filters.criticality)]
    if filters.tactic:
        mapped = [
            filters.tactic in run.family_tactics(family)
            for _, family in families.iterrows()
        ]
        families = families[pd.Series(mapped, index=families.index, dtype=bool)]
    if filters.review_state:
        decided = {
            family_id
            for family_id, entry in current_reviews(run.directory).items()
            if entry["decision"] == filters.review_state
        }
        families = families[families["family_id"].isin(decided)]
    return families


def _print_queue(run: RunState, filters: QueueFilter) -> None:
    _announce_run(run)
    scope = (
        "all scored families" if filters.whole_run
        else f"top {run.meta['budget']} per day"
    )
    if filters.day:
        scope += f", {filters.day}"
    render_queue(
        run.with_chain(_select_families(run, filters)),
        current_reviews(run.directory),
        f"Review queue ({scope})",
        bands_for(run.directory.parent),
    )


QUEUE_JSON_FIELDS = (
    "handle", "day", "host_label", "entity_id", "detector_source", "rule_id",
    "title", "alert_count", "n_child_sessions", "queue_rank", "in_queue",
    "ranking_score", "criticality", "start", "end",
)


def _alert_record(row: pd.Series) -> dict:
    return {
        field: sorted(value) if isinstance(value, (set, frozenset)) else value
        for field, value in row.items()
    }


def queue_records(run, families) -> list[dict]:
    reviews = current_reviews(run.directory)
    records = []
    for _, family in families.iterrows():
        record = {
            field: family[field] for field in QUEUE_JSON_FIELDS if field in family
        }
        record["chain"] = run.host_chain(family).length
        record["family_id"] = family["family_id"]
        record["run_id"] = run.run_id
        review = reviews.get(family["family_id"])
        record["review"] = review["decision"] if review else None
        records.append(record)
    return records


def _tactic_name(text: str) -> str:
    for tactic in TACTIC_ORDER:
        if tactic.casefold() == text.strip().casefold():
            return tactic
    raise argparse.ArgumentTypeError(
        f"not an ATT&CK tactic; use one of: {', '.join(TACTIC_ORDER)}"
    )


def cmd_queue(args) -> None:
    run = _load_run(args)
    if args.budget:
        run.families["in_queue"] = run.families["queue_rank"] < args.budget
        run.meta["budget"] = args.budget
    filters = QueueFilter(
        args.all, args.host, args.detector, args.rule, args.review_state,
        args.day, args.criticality, args.tactic,
    )
    if args.json:
        families = _select_families(run, filters)
        print(json.dumps(queue_records(run, families), indent=2, default=str))
        return
    _print_queue(run, filters)
    top = run.families[run.families["in_queue"]]
    if len(top):
        _hint(
            f"next: `meerkat inspect {top.iloc[0]['handle']}` opens the top "
            "family"
        )


MAPPING_SOURCE_LABELS = {
    "rule": "reviewed", "native": "native", "suppressed": "suppressed", "": "unmapped",
}


def attack_rules(run: RunState) -> list[dict]:
    alerts = run.alerts
    rows = []
    for (detector, rule_id), part in alerts.groupby(
        [alerts["detector_source"].astype(str), alerts["rule_id"].astype(str)],
        sort=False,
    ):
        sources = {MAPPING_SOURCE_LABELS[str(s)] for s in part["mapping_source"]}
        techniques = sorted({
            technique
            for joined in part["technique_ids"].astype(str)
            for technique in joined.split(";")
            if technique
        })
        rows.append({
            "detector": detector,
            "rule_id": rule_id,
            "alerts": len(part),
            "source": "native" if "native" in sources else sources.pop(),
            "techniques": [
                {"id": technique, "name": technique_name(technique)}
                for technique in techniques
            ],
        })
    rows.sort(key=lambda row: (row["source"] != "unmapped", -row["alerts"]))
    return rows


def cmd_attack(args) -> None:
    run = _load_run(args)
    rows = attack_rules(run)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    _announce_run(run)
    table = Table(title="ATT&CK mapping by rule  |  unmapped first",
                  title_justify="left", header_style="bold")
    table.add_column("detector", no_wrap=True)
    table.add_column("rule", max_width=40, overflow="ellipsis")
    table.add_column("alerts", justify="right")
    table.add_column("mapping", no_wrap=True)
    table.add_column("techniques")
    for row in rows:
        table.add_row(
            detector_label(row["detector"]),
            safe(row["rule_id"]),
            str(row["alerts"]),
            row["source"],
            ", ".join(
                f"{technique['id']} {technique['name']}"
                for technique in row["techniques"]
            ),
        )
    console.print(table)
    _hint(
        "add or correct a rule with a local mapping file: --attack-mappings FILE "
        "on triage"
    )


def cmd_runs(args) -> None:
    latest = latest_run_id(args.runs_dir)
    directories = sorted(
        d for d in args.runs_dir.glob("*") if (d / "run.json").exists()
    ) if args.runs_dir.exists() else []
    if args.json:
        print(json.dumps([
            {
                **json.loads((d / "run.json").read_text(encoding="utf-8")),
                "latest": d.name == latest,
            }
            for d in directories
        ], indent=2, default=str))
        return
    if not directories:
        console.print(f"[dim]no runs in {args.runs_dir}[/dim]")
        return
    table = Table(title="Saved runs", title_justify="left", header_style="bold")
    table.add_column("run", no_wrap=True, min_width=30)
    table.add_column("company")
    table.add_column("budget", justify="right")
    table.add_column("families", justify="right")
    table.add_column("saved")
    for directory in directories:
        meta = json.loads((directory / "run.json").read_text(encoding="utf-8"))
        marker = "  [green](latest)[/green]" if directory.name == latest else ""
        table.add_row(
            directory.name + marker,
            str(meta.get("company", "")),
            str(meta.get("budget", "")),
            str(meta.get("families", "")),
            str(meta.get("saved_at", "")),
        )
    console.print(table)


def _check_field(field: str, columns: set[str]) -> None:
    if field not in columns:
        _fail(
            f"[red]unknown field {safe(repr(field))}[/red]  fields: "
            f"{', '.join(sorted(columns))}"
        )


def _render_raw(alert_slice, raw_dir: Path, limit: int) -> None:
    for source_file, group in alert_slice.head(limit).groupby(
        "source_file", sort=False, observed=True
    ):
        path = raw_dir / str(source_file)
        wanted = {int(position): None for position in group["source_position"]}
        if not path.exists():
            console.print(f"[yellow]raw source {safe(path)} not available[/yellow]")
            continue
        with path.open(encoding="utf-8", errors="replace") as file:
            for index, line in enumerate(file):
                if index in wanted:
                    wanted[index] = line
                    if all(value is not None for value in wanted.values()):
                        break
        for position, line in wanted.items():
            console.print(f"[dim]{safe(source_file)}:{position}[/dim]")
            if line is None:
                console.print("[yellow]line not found[/yellow]")
                continue
            try:
                console.print_json(json.dumps(json.loads(line)))
            except (json.JSONDecodeError, RecursionError):
                console.print(safe(line.rstrip()))


def _find_family(run: RunState, handle: str) -> pd.Series:
    try:
        return run.family_by_handle(handle)
    except KeyError as error:
        hint = (
            "  sessions and alerts live inside a family: `meerkat inspect F1 S1` "
            "then `... S1 A1`"
            if canon_handle(handle)[:1] in ("S", "A") else ""
        )
        _fail(f"[red]{safe(error.args[0])}[/red]{hint}")


def _find_session(run: RunState, family: pd.Series, handle: str) -> pd.Series:
    try:
        return run.session_by_handle(family, handle)
    except KeyError as error:
        _fail(f"[red]{safe(error.args[0])}[/red]")


def alert_position(handle: str) -> int:
    canon = canon_handle(handle)
    return int(canon[1:]) if canon[:1] == "A" and canon[1:].isdigit() else 0


def _inspect_payload(
    run: RunState, family: pd.Series, session: pd.Series | None, args
) -> dict:
    only_family = run.families[run.families["family_id"].eq(family["family_id"])]
    sessions = []
    for handle, session_id in run.session_handles(family):
        row = run.session_row(session_id)
        sessions.append({
            "handle": handle,
            "start": float(row["start"]),
            "end": float(row["end"]),
            "duration_s": float(row["duration_s"]),
            "alerts": int(row["size"]),
            "score": float(row["ranking_score"]),
        })
    payload = {
        "run_id": run.run_id,
        "family": queue_records(run, only_family)[0],
        "sessions": sessions,
    }
    if session is not None:
        alerts = [
            {"handle": f"A{position + 1}", **_alert_record(row)}
            for position, (_, row) in enumerate(run.session_alerts(session).iterrows())
        ]
        if args.alert:
            wanted = canon_handle(args.alert)
            alerts = [record for record in alerts if record["handle"] == wanted]
        payload["session"] = canon_handle(args.session)
        payload["alerts"] = alerts
    return payload


def _inspect_alert(
    run: RunState, family: pd.Series, session: pd.Series | None, args
) -> None:
    if session is None:
        _fail(
            "[red]an alert handle needs its session[/red]  "
            "e.g. `meerkat inspect F3 S1 A2`"
        )
    ordered = run.session_alerts(session)
    session_handle = canon_handle(args.session)
    position = alert_position(args.alert)
    if not 1 <= position <= len(ordered):
        _fail(
            f"[red]no alert {safe(args.alert)}[/red]  "
            f"{safe(session_handle)} holds A1..A{len(ordered)}"
        )
    render_alert_detail(
        family, session_handle, f"A{position}", ordered.iloc[position - 1]
    )
    if args.raw:
        _render_raw(ordered.iloc[[position - 1]], _raw_dir_for(run, args), 1)
    else:
        _hint(
            f"next: `meerkat inspect {family['handle']} {session_handle} "
            f"A{position} --raw` shows the source line as the detector wrote it"
        )


def cmd_inspect(args) -> None:
    run = _load_run(args)
    if not args.json:
        _announce_run(run)
    columns = set(run.alerts.columns)
    if args.distinct:
        _check_field(args.distinct, columns)

    family = _find_family(run, args.handle)
    session = _find_session(run, family, args.session) if args.session else None
    alert_slice = (
        run.family_alerts(family) if session is None else run.session_alerts(session)
    )

    if args.json:
        payload = _inspect_payload(run, family, session, args)
        print(json.dumps(payload, indent=2, default=str))
        return
    if args.alert:
        _inspect_alert(run, family, session, args)
        return

    if args.distinct:
        render_distinct(alert_slice, args.distinct)
        return

    reviews = current_reviews(run.directory)
    wants_rows = bool(args.alerts or args.raw)
    session_handle = canon_handle(args.session) if args.session else None

    def render() -> None:
        if session is not None:
            render_session(family, session_handle, session, alert_slice)
        else:
            render_family(run, family, reviews)
        if wants_rows:
            limit = args.alerts or (5 if args.raw else 20)
            if args.raw:
                _render_raw(alert_slice, _raw_dir_for(run, args), limit)
            else:
                render_alert_rows(alert_slice, limit)

    _page(render, args.no_pager)

    if session is not None:
        _hint(
            f"next: `meerkat inspect {family['handle']} {session_handle} A1` "
            f"opens one alert, `meerkat inspect {family['handle']}` returns to "
            f"the family, `meerkat review {family['handle']} escalate "
            f"--session {session_handle}` records it"
        )
    else:
        _hint(
            f"next: `meerkat inspect {family['handle']} S1` opens the top "
            "session, `meerkat queue` returns to the queue"
        )


def cmd_review(args) -> None:
    run = _load_run(args)
    family = _find_family(run, args.handle)
    handles = run.session_handles(family)
    # Dismissing a family is exact: if nothing in it was an attack, nothing in any
    # of its sessions was. Escalating one only means at least one burst was
    # malicious, so that direction has to name the burst.
    if args.decision == "escalate" and not args.session:
        _fail(
            f"[red]{family['handle']} holds {len(handles)} sessions[/red]  "
            "escalate needs --session S1 to say which burst was malicious, "
            "or --session all if the whole family was\n"
            + "\n".join(f"  {handle}" for handle, _ in handles)
        )

    session = None
    session_handle = None
    if args.session and args.session.lower() != "all":
        session = _find_session(run, family, args.session)
        session_handle = args.session.upper()

    entry = append_review(
        run.directory, run.run_id, family["family_id"], family["handle"],
        args.decision, args.note or "",
        session_key=(
            session_label_key(session, run.alerts) if session is not None else None
        ),
        session_handle=session_handle,
        analyst=args.analyst,
    )
    scope = (
        f"{family['handle']}/{session_handle}" if session is not None
        else family["handle"]
    )
    console.print(
        f"[green]recorded[/green] {scope} -> {entry['decision']}"
        + (f"  ({safe(entry['note'])})" if entry["note"] else "")
    )
    if session is None:
        console.print(f"[dim]covers all {len(handles)} sessions[/dim]")
    console.print(f"[dim]{safe(family['family_id'])}  run {run.run_id}[/dim]")


def _incident_reach(families, incidents, inventory, budget):
    queue = families[families["queue_rank"] < budget]
    reached = []
    for row in incidents.itertuples():
        entity = entity_for(row.host, inventory)
        if not entity:
            reached.append(False)
            continue
        hit = (
            queue["entity_id"].astype(str).eq(entity)
            & queue["start"].le(row.end)
            & queue["end"].ge(row.start)
        )
        reached.append(bool(hit.any()))
    return np.asarray(reached, dtype=bool)


# a two-sided sign test on n same-direction pairs gives p = 2 * 0.5**n, so five
# pairs reach 0.0625 and six reach 0.031; below six no difference can be called real
MIN_DISCORDANT = 6

RETRAIN_TREES = 200
RETRAIN_FITS = 5
MIN_BAGGED_SESSIONS = 10


def _validate_retrain_result(old, new) -> None:
    old = np.asarray(old, dtype=bool)
    new = np.asarray(new, dtype=bool)
    if not new.any():
        raise ValueError(
            f"the retrained forest reaches none of the {len(new)} held-out incidents"
        )
    if new.sum() < old.sum():
        raise ValueError("the retrained forest reaches fewer incidents")
    discordant = int((old != new).sum())
    if discordant < MIN_DISCORDANT:
        raise ValueError(
            f"the two models disagree on {discordant} of {len(old)} held-out "
            f"incidents, and {MIN_DISCORDANT} are needed before a difference can be "
            "called real; supply incidents covering more days, or lower --budget"
        )


def incident_reach_for(
    candidate, held, alerts, held_incidents, inventory, budget: int
):
    from core.scenario_eval import score_sessions

    families = decorate_families(score_sessions(candidate, held)[1], alerts, budget)
    return _incident_reach(families, held_incidents, inventory, budget)


def compare_models(
    shipped,
    candidates: list,
    held,
    alerts,
    held_incidents,
    inventory,
    budget: int,
) -> dict:
    from core.scenario_eval import rescale_bundle

    def reach(candidate):
        return incident_reach_for(
            candidate, held, alerts, held_incidents, inventory, budget
        )

    shipped_reach = reach(shipped)
    verdicts, reasons = [], []
    results = [reach(candidate) for candidate in candidates]
    for result in results:
        try:
            _validate_retrain_result(shipped_reach, result)
            verdicts.append(True)
        except ValueError as error:
            verdicts.append(False)
            reasons.append(str(error))
    # the median seed, never the best: picking the best would select on the same
    # held-out incidents the gate just spent
    order = sorted(range(len(results)), key=lambda i: int(results[i].sum()))
    return {
        "shipped": shipped_reach,
        "rescaled": reach(rescale_bundle(shipped, held)),
        "candidates": results,
        "passed": verdicts,
        "reason": reasons[0] if reasons else "",
        "median_index": order[len(order) // 2] if order else 0,
        "approved": sum(verdicts) * 2 > len(verdicts),
    }


def cmd_retrain(args) -> None:
    from core.classifier import save_model
    from core.scenario_eval import refit_forest

    _require(args.incidents, "incident records")
    company = _open_company(args)
    _require_bundle(args.model)

    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    incidents = _load_or_exit(load_incidents, args.incidents, "the incident records")
    unresolved = unresolved_hosts(incidents, inventory)
    if unresolved:
        console.print(
            f"[yellow]{len(unresolved)} incident hosts are not in the "
            f"inventory[/yellow]  "
            f"{', '.join(safe(host) for host in unresolved[:5])}"
        )
    bundle = _load_bundle(args.model)
    alerts = normalize_scenario(
        args.input, None, company, args.inventory,
        wazuh_file=args.wazuh_file, aminer_file=args.aminer_file,
    )
    sessions = build_sessions(alerts, company, inventory)

    # train on the earlier days and keep the last ones to check the result, so no
    # reported number comes from days the forest has already seen
    days = sorted(sessions["day"].unique())
    failures = []
    if len(days) <= args.holdout_days:
        failures.append(
            f"{len(days)} days of alerts, need more than {args.holdout_days}"
        )
        cutoff = days[0]
    else:
        cutoff = days[-args.holdout_days]
    train = sessions[sessions["day"] < cutoff].copy()
    held = sessions[sessions["day"] >= cutoff].copy()

    # split the incidents on the same instant as the sessions. Passing all of them
    # would let a burst that spans the cutoff be labelled by a held-out incident.
    boundary = cutoff * SECONDS_PER_DAY
    train_incidents = incidents[incidents["start"] < boundary]
    held_incidents = incidents[incidents["start"] >= boundary]
    prior = assign_bag_priors(train, train_incidents, inventory)
    bags = int((prior > 0).sum())
    console.print(
        f"{len(sessions)} sessions over {len(days)} days, "
        f"{len(incidents)} incidents, {len(train_incidents)} for training and "
        f"{len(held_incidents)} held out, {bags} sessions inside one"
    )
    if not len(train_incidents):
        failures.append(
            f"every incident falls in the last {args.holdout_days} days, "
            "so training has nothing to learn from; lower --holdout-days, "
            "or supply incidents covering an earlier period"
        )
    if bags < MIN_BAGGED_SESSIONS:
        failures.append(
            f"only {bags} sessions fall inside an incident; at least "
            f"{MIN_BAGGED_SESSIONS} are needed to retrain"
        )
    if failures:
        _fail("\n".join(f"[red]{safe(failure)}[/red]" for failure in failures))
    # one forest per seed, because a single fit decides approval on a metric coarse
    # enough for seed noise to flip it
    try:
        candidates = [
            refit_forest(bundle, train, prior, RETRAIN_TREES, seed=offset)
            for offset in range(RETRAIN_FITS)
        ]
    except ValueError as error:
        _fail(f"[red]{safe(error)}[/red]")

    verdict = compare_models(
        bundle, candidates, held, alerts, held_incidents, inventory, args.budget
    )
    console.print(
        f"held-out incidents reached at budget {args.budget}, "
        f"of {len(held_incidents)}: shipped {int(verdict['shipped'].sum())}, "
        f"rescale only {int(verdict['rescaled'].sum())}, retrained "
        f"{', '.join(str(int(r.sum())) for r in verdict['candidates'])}"
    )
    if not verdict["approved"]:
        errors.print(
            f"[yellow]not saved[/yellow]  only {sum(verdict['passed'])} of "
            f"{len(verdict['passed'])} seeds beat the shipped bundle; "
            f"{verdict['reason']}"
        )
        raise SystemExit(EXIT_DECLINED)

    save_model(candidates[verdict["median_index"]], args.out)
    console.print(
        f"[green]saved[/green] {args.out}  "
        f"{sum(verdict['passed'])} of {len(verdict['passed'])} seeds passed, "
        "median kept"
    )
    console.print(
        "[dim]refit: forest (your sessions)  rescaled: re-ranker scale "
        "(your families)  kept: ranking weights (shipped), calibrator[/dim]"
    )


CHECK_SAMPLE = 5_000
# above this share of distinct rule ids the detector probably numbers each anomaly
# instead of naming its type, which corrupts rarity and the session key
RULE_CARDINALITY_WARN = 0.5
UNMAPPED_SHOWN = 5


def _unmapped_rules(frame: pd.DataFrame) -> list[dict]:
    plain = frame[
        ~frame["tactics"].map(bool) & frame["mapping_source"].ne("suppressed")
    ]
    counts = (
        plain.groupby(
            [plain["detector_source"].astype(str), plain["rule_id"].astype(str)]
        )
        .size()
        .sort_values(ascending=False, kind="stable")
        .head(UNMAPPED_SHOWN)
    )
    return [
        {"detector": detector, "rule_id": rule_id, "alerts": int(count)}
        for (detector, rule_id), count in counts.items()
    ]


def _sample_alerts(args, company: str, alert_files, mappings) -> pd.DataFrame:
    per_file = max(1, args.sample // len(alert_files))
    rows = []
    for entry in alert_files:
        rows.extend(islice(
            iter_normalized_rows(
                args.input, None, company, args.inventory, files=[entry]
            ),
            per_file,
        ))
    if not rows:
        _fail("[red]no alerts parsed[/red]  the files resolved but held no rows")
    return enrich_alerts(pd.DataFrame(rows), mappings)


def _check_findings(inventory, frame, source: str, report: dict) -> list[tuple[str | None, str]]:
    findings = list(_role_problems(inventory, source).items())
    if inventory.unknown_criticalities:
        findings.append((
            "unknown_criticality",
            f"[yellow]unrecognised criticality[/yellow] "
            f"{', '.join(safe(c) for c in inventory.unknown_criticalities)}  "
            f"use {', '.join(CRITICALITY_LEVELS)}, or leave it blank",
        ))
    uncritical = inventory.assets_without_criticality()
    report["assets_without_criticality"] = len(uncritical)
    if uncritical:
        findings.append((
            None,
            f"[yellow]{len(uncritical)} inventory assets have no criticality"
            "[/yellow]  the queue shows them blank and `--criticality` skips them",
        ))
    ratio = frame["rule_id"].nunique() / len(frame)
    report["rule_cardinality"] = round(ratio, 3)
    if ratio > RULE_CARDINALITY_WARN and len(frame) >= 500:
        findings.append((
            "rule_cardinality",
            f"[yellow]{frame['rule_id'].nunique()} distinct rule ids across "
            f"{len(frame)} alerts[/yellow]  sessions group on rule id, so "
            "Meerkat reads it as naming a kind of alert rather than one "
            "occurrence. At this ratio sessions do not group and rule rarity "
            "carries no signal.",
        ))
    return findings


def _print_check(report, frame, aminer_name, outside_hosts, findings, args) -> None:
    console.print(f"reading up to {args.sample} alerts from {args.input}")
    for file in report["files"]:
        console.print(
            f"  [green]found[/green] {file['holds']:19} {file['name']}  "
            f"{file['mb']:.1f} MB"
        )
    if "missing_detector" in report:
        console.print(
            f"  [dim]absent[/dim] {report['missing_detector']:19} {aminer_name}"
        )
    table = Table(title=f"check ({len(frame)} alerts sampled)",
                  title_justify="left", header_style="bold")
    table.add_column("detector")
    table.add_column("alerts", justify="right")
    table.add_column("hosts", justify="right")
    table.add_column("in inventory", justify="right")
    table.add_column("distinct rules", justify="right")
    table.add_column("ATT&CK mapped", justify="right")
    for part in report["detectors"]:
        table.add_row(
            detector_label(part["detector"]),
            str(part["alerts"]),
            str(part["hosts"]),
            f"{part['in_inventory']}/{part['alerts']}",
            str(part["distinct_rules"]),
            f"{part['attack_mapped'] / part['alerts']:.0%}",
        )
    console.print(table)
    start, end = report["window"]
    console.print(f"  covering {fmt_time(start)} to {fmt_time(end)}")
    if report["unmapped_rules"]:
        console.print(
            "[yellow]busiest rules with no ATT&CK tactic[/yellow]  "
            "`meerkat attack` lists every rule; a local mapping file adds them"
        )
        for entry in report["unmapped_rules"]:
            console.print(
                f"  {detector_label(entry['detector'])} {safe(entry['rule_id'])}"
                f"  {entry['alerts']} alerts"
            )
    if "outside_inventory_share" in report:
        console.print(
            f"[yellow]{report['outside_inventory_share']:.0%} of alerts are on "
            f"hosts outside the inventory[/yellow]  "
            f"{', '.join(safe(name) for name in outside_hosts)}\n"
            "  those alerts are scored without role features. A network alert "
            "names both ends of a connection, so addresses outside your estate "
            "appear here too."
        )
    for _, message in findings:
        errors.print(message)
    if report["problems"]:
        console.print(
            f"[yellow]{len(report['problems'])} thing(s) to look at before "
            "triaging[/yellow]"
        )
    else:
        console.print("[green]ready to triage[/green]")


def cmd_check(args) -> None:
    company = _open_company(args)
    alert_files = _resolve_files(
        args.input, company, args.wazuh_file, args.aminer_file
    )
    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    mappings = _load_or_exit(
        with_local_mappings, args.attack_mappings, "the local ATT&CK mapping"
    )
    frame = _sample_alerts(args, company, alert_files, mappings)

    report: dict = {
        "environment": company,
        "files": [
            {
                "name": path.name,
                "holds": FAMILY_LABELS[family],
                "mb": round(path.stat().st_size / 1_000_000, 1),
            }
            for path, family in alert_files
        ],
        "problems": [],
    }
    if not any(family == AMINER_FAMILY for _, family in alert_files):
        report["missing_detector"] = FAMILY_LABELS[AMINER_FAMILY]
    report["sampled"] = len(frame)
    report["detectors"] = [
        {
            "detector": str(detector),
            "alerts": len(part),
            "hosts": int(part["entity_id"].nunique()),
            "in_inventory": int(part["entity_in_inventory"].astype(bool).sum()),
            "distinct_rules": int(part["rule_id"].nunique()),
            "attack_mapped": int(part["tactics"].map(bool).sum()),
        }
        for detector, part in frame.groupby("detector_source", sort=True)
    ]
    report["window"] = [float(frame["timestamp"].min()), float(frame["timestamp"].max())]
    report["unmapped_rules"] = _unmapped_rules(frame)

    unmatched = frame.loc[~frame["entity_in_inventory"].astype(bool), "entity_id"]
    outside_hosts = sorted(set(unmatched.astype(str)))[:5]
    if len(unmatched):
        report["outside_inventory_share"] = round(len(unmatched) / len(frame), 3)

    findings = _check_findings(inventory, frame, args.inventory.name, report)
    report["problems"] = [key for key, _ in findings if key]
    report["ready"] = not report["problems"]
    if args.json:
        for _, message in findings:
            errors.print(message)
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_check(
            report, frame, _aminer_name(args, company), outside_hosts, findings, args
        )
    if report["problems"]:
        raise SystemExit(EXIT_ERROR)


VERDICT_STYLE = {"stable": "green", "moderate": "yellow", "major": "red"}
# below this many sessions on either side, unmoved features read as major drift
DRIFT_MIN_TRAINING = 300


def _drift_report(bundle, sessions, families, drifts, alerts_count) -> dict:
    profile = bundle.profile
    unseen = unseen_rule_share(bundle.schema, sessions["pair_counts"])
    major = [d for d in drifts if d.verdict == "major"]
    report: dict = {
        "alerts": alerts_count,
        "sessions": len(sessions),
        "families": len(families),
        "trained_sessions": profile.n_sessions,
        "unseen_rule_share": round(float(unseen), 4),
        "outside_inventory_share": round(
            1.0 - float(sessions["in_inventory"].mean()), 4
        ),
        "features": [
            {"feature": d.name, "psi": round(float(d.psi), 4), "verdict": d.verdict,
             "training_median": float(d.training_median),
             "current_median": float(d.current_median)}
            for d in drifts
        ],
    }
    # the queue is a top-K cut, so a shift confined to the bottom of the score
    # distribution changes nothing an analyst sees; report the boundary separately
    trained_edges = profile.family_score_bins[0]
    if trained_edges:
        boundary = float(np.quantile(families["ranking_score"].to_numpy(), 0.9))
        report["top_decile_score"] = round(boundary, 4)
        report["top_decile_score_at_training"] = round(float(trained_edges[-1]), 4)
    report["major_features"] = len(major)
    report["drifted"] = bool(major or unseen > UNSEEN_RULE_WARN)
    return report


def _print_drift(args, report, profile, drifts) -> None:
    console.print(
        f"{report['alerts']} alerts, {report['sessions']} sessions, "
        f"{report['families']} families against a model trained on "
        f"{profile.n_sessions} sessions"
    )
    unseen = report["unseen_rule_share"]
    console.print(
        f"  rules the model never saw: [bold]{unseen:.1%}[/bold] of alerts"
        + ("  [red]<- the model has no rarity signal for these[/red]"
           if unseen > UNSEEN_RULE_WARN else "")
    )
    console.print(
        "  sessions on hosts outside the inventory: "
        f"[bold]{report['outside_inventory_share']:.1%}[/bold]"
        f"  (training had {1 - profile.inventory_coverage:.1%})"
    )
    if profile.n_sessions < DRIFT_MIN_TRAINING:
        console.print(
            f"[yellow]this model was fitted on {profile.n_sessions} sessions"
            f"[/yellow]  below about {DRIFT_MIN_TRAINING} the comparison is mostly "
            "noise: unmoved features read as major drift roughly half the time"
        )
    if report["sessions"] < DRIFT_MIN_TRAINING:
        console.print(
            f"[yellow]these alerts make {report['sessions']} sessions[/yellow]  "
            f"below about {DRIFT_MIN_TRAINING} the comparison is mostly noise; "
            "compare several days at once"
        )

    table = Table(title="feature drift, worst first", title_justify="left",
                  header_style="bold")
    table.add_column("feature")
    table.add_column("PSI", justify="right")
    table.add_column("verdict")
    table.add_column("training median", justify="right")
    table.add_column("now", justify="right")
    shown = drifts if args.all else (
        [d for d in drifts if d.verdict != "stable"] or drifts[:5]
    )[:args.top]
    for d in shown:
        style = VERDICT_STYLE[d.verdict]
        table.add_row(
            safe(d.name), f"{d.psi:.3f}", f"[{style}]{d.verdict}[/{style}]",
            f"{d.training_median:.3f}", f"{d.current_median:.3f}",
        )
    console.print(table)
    if "top_decile_score" in report:
        console.print(
            f"  top-decile family score: [bold]{report['top_decile_score']:.3f}"
            f"[/bold] now, {report['top_decile_score_at_training']:.3f} at training"
        )
    if report["drifted"]:
        console.print(
            f"[yellow]{report['major_features']} feature(s) past PSI {PSI_MAJOR}"
            "[/yellow]  this reports that the input moved. It does not measure "
            "whether the ranking is still right, which needs confirmed outcomes."
        )
    elif drifts:
        console.print(f"[green]no major drift[/green]  worst PSI {drifts[0].psi:.3f}")
    else:
        console.print("[green]no comparable features[/green]")


def cmd_drift(args) -> None:
    from core.scenario_eval import score_sessions

    company = _open_company(args)
    bundle = _load_bundle(args.model)
    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    alerts = normalize_scenario(
        args.input, None, company, args.inventory,
        wazuh_file=args.wazuh_file, aminer_file=args.aminer_file,
    )
    sessions = build_sessions(alerts, company, inventory)
    drifts = compare_profile(
        bundle.profile, build_session_feature_matrix(sessions, bundle.schema)
    )
    _, families = score_sessions(bundle, sessions)
    report = _drift_report(bundle, sessions, families, drifts, len(alerts))
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_drift(args, report, bundle.profile, drifts)
    if report["drifted"]:
        raise SystemExit(EXIT_DRIFT)


def cmd_export(args) -> None:
    run = _load_run(args)
    _announce_run(run)
    if args.queue_only:
        families = run.queue_families(show_all=False)
        rows = [row for indices in families["alert_rows"] for row in indices]
        alerts = run.alerts.iloc[rows]
    else:
        alerts = run.alerts
    output = args.output or (run.directory / "navigator_layer.json")
    count = export_navigator_layer(
        alerts["technique_ids"], output,
        name=f"Meerkat observed techniques ({run.meta.get('company', '')})",
    )
    console.print(f"[green]exported[/green] {count} techniques to {output}")
    console.print(
        "[dim]open at mitre-attack.github.io/attack-navigator, "
        "Open Existing Layer[/dim]"
    )


# Excel evaluates a cell starting with one of these; a leading tab or newline is
# listed because the character after it then starts the cell
_CSV_FORMULA_LEAD = frozenset("=+-@\t\n")


def _csv_safe(value):
    if not isinstance(value, str):
        return value
    value = _CONTROL.sub("", value)
    if value and value[0] in _CSV_FORMULA_LEAD:
        return "'" + value
    return value


def decision_rows(run, families) -> list[dict]:
    decisions = replay_reviews(run.directory)
    rows = []
    for _, family in families.iterrows():
        scopes = decisions.get(family["family_id"], {})
        for handle, session_id in run.session_handles(family):
            session = run.session_row(session_id)
            entry = scopes.get(handle) or scopes.get("*")
            decided_by = ""
            if entry is not None:
                decided_by = "session" if entry.get("session_handle") else "family"
            for position, (_, alert) in enumerate(
                run.session_alerts(session).iterrows()
            ):
                rows.append({
                    "family": family["handle"],
                    "finding": family["title"] or family["rule_id"],
                    "host": family["host_label"],
                    "detector": alert["detector_source"],
                    "rule_id": alert["rule_id"],
                    "session": handle,
                    "alert": f"A{position + 1}",
                    "time": fmt_time(alert["timestamp"]),
                    "name": alert["name"],
                    "decision": entry["decision"] if entry else "",
                    "decided_by": decided_by,
                    "analyst": entry.get("analyst", "") if entry else "",
                    "note": entry.get("note", "") if entry else "",
                    "source": f"{alert['source_file']}:{alert['source_position']}",
                })
    return rows


def _suffix(fmt: str) -> str:
    return "json" if fmt == "json" else "csv"


def _write_rows(rows: list[dict], output: Path, fmt: str) -> None:
    if fmt == "json":
        output.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
    else:
        pd.DataFrame(rows).map(_csv_safe).to_csv(output, index=False)


def cmd_export_decisions(args) -> None:
    run = _load_run(args)
    families = run.queue_families(args.all)
    if len(families) > 100:
        errors.print(f"collecting {len(families)} families...")
    rows = decision_rows(run, families)
    if args.decided_only:
        rows = [row for row in rows if row["decision"]]
    output = args.output or (run.directory / f"decisions.{_suffix(args.format)}")
    _write_rows(rows, output, args.format)
    reviewed = sum(1 for row in rows if row["decision"])
    if not reviewed:
        errors.print(
            "[yellow]no reviews recorded on these families yet[/yellow]  "
            "the grid carries empty decision columns"
        )
    console.print(
        f"[green]exported[/green] {len(rows)} alert rows "
        f"({reviewed} carrying a decision) to {output}"
    )


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ background:#0d0f0d; margin:0; padding:2rem; }}
pre {{ color:#b9bcba; font-family:Consolas,Menlo,monospace; font-size:14px;
       line-height:1.4; margin:0 auto; max-width:72rem; overflow-x:auto; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _recorded_html(render, title: str) -> str:
    # the page is the terminal render, recorded; every render prints through the
    # module's console, so it is swapped for a recording one while render runs
    global console, hints_enabled
    recorder = Console(
        file=io.StringIO(), record=True, force_terminal=True, width=120,
        legacy_windows=False,
    )
    saved = console, hints_enabled
    console, hints_enabled = recorder, False
    try:
        render()
    finally:
        console, hints_enabled = saved
    body = recorder.export_html(
        inline_styles=True, code_format="<pre>{code}</pre>", theme=DIMMED_MONOKAI,
    )
    return HTML_PAGE.format(title=html.escape(title), body=body)


def _family_entries(family, decisions) -> list[tuple[str, dict]]:
    scopes = decisions.get(family["family_id"], {})
    ordered = []
    if "*" in scopes:
        ordered.append(("family", scopes["*"]))
    sessions = [handle for handle in scopes if handle != "*"]
    for handle in sorted(sessions, key=lambda h: int(h[1:])):
        ordered.append((handle, scopes[handle]))
    return ordered


def _print_decisions(family, decisions) -> None:
    for scope, entry in _family_entries(family, decisions):
        line = (
            f"  decision      : [bold]{entry['decision']}[/bold] ({scope})"
            f"  by {safe(entry.get('analyst', '') or '?')}"
            f"  {entry['timestamp'][:16].replace('T', ' ')}"
        )
        if entry.get("note"):
            line += f"  [dim]{safe(entry['note'])}[/dim]"
        console.print(line)


def cmd_export_html(args) -> None:
    run = _load_run(args)
    reviews = current_reviews(run.directory)
    decisions = replay_reviews(run.directory)
    if args.handle:
        family = _find_family(run, args.handle)
        handle = family["handle"]

        def render() -> None:
            render_family(run, family, reviews)
            _print_decisions(family, decisions)

        title = f"meerkat {run.run_id} {handle}"
        default_name = f"family-{handle.lower()}.html"
    else:
        queued = run.queue_families(show_all=False)
        escalated, closed, unreviewed = [], [], []
        for _, family in queued.iterrows():
            entries = _family_entries(family, decisions)
            verdicts = {entry["decision"] for _, entry in entries}
            if "escalate" in verdicts:
                escalated.append(family)
            elif entries:
                closed.append(family)
            else:
                unreviewed.append(family)
        if not decisions:
            errors.print(
                "[yellow]no reviews recorded on this run yet[/yellow]  "
                "the page lists the whole queue as unreviewed"
            )

        def render() -> None:
            console.print(f"[bold]meerkat review report  {run.run_id}[/bold]")
            console.print(
                f"queue {len(queued)}  |  escalated {len(escalated)}  |  "
                f"closed {len(closed)}  |  unreviewed {len(unreviewed)}\n"
            )
            for family in escalated:
                render_family(run, family, reviews)
                _print_decisions(family, decisions)
            if closed:
                table = Table(title="Closed", title_justify="left",
                              header_style="bold")
                for name in ("handle", "scope", "host", "finding",
                             "decision", "analyst", "note"):
                    table.add_column(name)
                for family in closed:
                    for scope, entry in _family_entries(family, decisions):
                        table.add_row(
                            family["handle"], scope,
                            safe(family["host_label"]),
                            safe(family["title"] or family["rule_id"])[:40],
                            entry["decision"],
                            safe(entry.get("analyst", "")),
                            safe(entry.get("note", "")),
                        )
                console.print(table)
            if len(unreviewed):
                render_queue(
                    run.with_chain(pd.DataFrame(unreviewed)), reviews,
                    f"Unreviewed ({len(unreviewed)} of {len(queued)})",
                    bands_for(run.directory.parent),
                )

        title = f"meerkat {run.run_id}"
        default_name = "report.html"
    output = args.output or (run.directory / default_name)
    output.write_text(_recorded_html(render, title), encoding="utf-8")
    console.print(f"[green]exported[/green] {output}")


def cmd_export_queue(args) -> None:
    run = _load_run(args)
    records = queue_records(run, run.queue_families(args.all))
    output = args.output or (run.directory / f"queue.{_suffix(args.format)}")
    _write_rows(records, output, args.format)
    console.print(f"[green]exported[/green] {len(records)} families to {output}")


def cmd_demo(args) -> None:
    from core.classifier import is_lfs_pointer

    for detector in ("wazuh", "aminer"):
        path = args.raw_dir / f"{DEMO_COMPANY}_{detector}.json"
        if not path.exists() or is_lfs_pointer(path):
            _fail(
                f"[red]demo data missing: {safe(path)}[/red]\n"
                "the raw AIT files are stored with Git LFS. fetch them with:\n\n"
                "  git lfs install\n"
                "  git lfs pull\n"
            )
    cmd_triage(argparse.Namespace(
        model=args.model, input=args.raw_dir, company=DEMO_COMPANY,
        inventory=DEMO_INVENTORY_DIR / f"{DEMO_COMPANY}.json",
        wazuh_file=None, aminer_file=None, attack_mappings=None,
        budget=args.budget, runs_dir=args.runs_dir,
    ))
    console.print(
        "\n[dim]next: `meerkat inspect F1` to open the top family, "
        "`meerkat export navigator` for the ATT&CK layer[/dim]"
    )


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def safe_run_id(run_id: str) -> str:
    # a run directory is unpickled on open, so the id has to be one path
    # component; traversal here is code execution, not a wrong directory
    cleaned = str(run_id).strip()
    if not cleaned or Path(cleaned).name != cleaned or cleaned in (".", ".."):
        raise ValueError(f"{run_id!r} is not a run id")
    return cleaned


def _company_label(value: str) -> str:
    try:
        return safe_run_id(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error))


def _load_or_exit(load, path: Path, what: str):
    try:
        return load(path)
    except (ValueError, OSError) as error:
        _fail(f"[red]{what} could not be read[/red]  {safe(error)}")


def _raw_dir_for(run: RunState, args) -> Path:
    return args.raw_dir or Path(run.meta.get("input", str(DEFAULT_INPUT)))


def require_directory(path: Path) -> None:
    if not path.exists():
        _fail(
            f"[red]no alert directory at {safe(path)}[/red]  create it and put your "
            "detector exports inside, or point --input at the folder that "
            "already holds them."
        )
    if not path.is_dir():
        _fail(
            f"[red]--input must be a directory[/red]  {safe(path)} is a file. Point it "
            "at the folder holding your alert exports."
        )


_UNSET = object()
_CONFIGURABLE = (
    ("company", "MEERKAT_ENVIRONMENT", "environment"),
    ("input", "MEERKAT_INPUT", "input"),
    ("inventory", "MEERKAT_INVENTORY", "inventory"),
    ("attack_mappings", "MEERKAT_ATTACK_MAPPINGS", "attack_mappings"),
    ("model", "MEERKAT_MODEL", "model"),
    ("runs_dir", "MEERKAT_RUNS_DIR", "runs_dir"),
)


def _load_config() -> tuple[dict, str]:
    candidates = (
        Path("meerkat.toml"),
        Path.home() / ".config" / "meerkat" / "config.toml",
    )
    for path in candidates:
        if not path.exists():
            continue
        try:
            with path.open("rb") as handle:
                return tomllib.load(handle), str(path)
        except tomllib.TOMLDecodeError as error:
            _fail(f"[red]{safe(path)} is not valid TOML[/red]  {safe(error)}")
    return {}, ""


def _apply_config(args) -> None:
    config, source = _load_config()
    hard = {
        "input": DEFAULT_INPUT, "model": DEFAULT_MODEL, "runs_dir": DEFAULT_RUNS,
    }
    for attribute, variable, key in _CONFIGURABLE:
        if getattr(args, attribute, None) is not _UNSET:
            continue
        raw = os.environ.get(variable)
        if raw is None and key in config:
            raw = str(config[key])
        if raw is None:
            setattr(args, attribute, hard.get(attribute))
            continue
        try:
            value = _company_label(raw) if attribute == "company" else Path(raw)
        except argparse.ArgumentTypeError as error:
            where = variable if os.environ.get(variable) else source
            _fail(f"[red]bad {key} in {safe(where)}[/red]  {safe(error)}")
        setattr(args, attribute, value)


def cmd_browse(args) -> None:
    from meerkat.browse import browse_loop
    run = _load_run(args)
    _announce_run(run)
    browse_loop(run)


def cmd_orientation(args) -> None:
    latest = latest_run_id(args.runs_dir)
    if latest is None:
        console.print("no runs yet")
        console.print(
            "[dim]start: `meerkat demo` scores the bundled example, "
            "`meerkat check --input DIR` reads your own alerts, "
            "`meerkat --help` lists everything[/dim]"
        )
        return
    try:
        meta = json.loads(
            (args.runs_dir / latest / "run.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        meta = {}
    reviews = current_reviews(args.runs_dir / latest)
    console.print(f"latest run [bold]{safe(latest)}[/bold]")
    console.print(
        f"  environment {safe(str(meta.get('company', '?')))}  |  "
        f"budget {meta.get('budget', '?')}  |  "
        f"{meta.get('families', '?')} families from "
        f"{meta.get('alerts', '?')} alerts  |  "
        f"{len(reviews)} reviewed"
    )
    console.print(
        "[dim]next: `meerkat queue` to work it, `meerkat inspect F1` to open "
        "the top family, `meerkat triage --input DIR` to score a new day[/dim]"
    )


def resolve_company(args) -> str:
    if args.company:
        return args.company
    try:
        return safe_run_id(args.input.resolve().name)
    except ValueError:
        _fail(
            f"[red]cannot name a run after {safe(args.input)}[/red]  a filesystem "
            "root has no directory name to use. Pass --environment with a "
            "label, or point --input at a named directory."
        )


def _add_environment(parser) -> None:
    parser.add_argument("--environment", dest="company", type=_company_label,
                        default=_UNSET, metavar="NAME",
                        help="run label; defaults to the input directory's name")


def _add_input(parser, help="directory holding the alert files") -> None:
    parser.add_argument("--input", type=Path, default=_UNSET, help=help)


def _add_inventory(parser) -> None:
    parser.add_argument("--inventory", type=Path, default=_UNSET,
                        help="asset inventory JSON; defaults to where "
                             "`meerkat inventory` writes it")


def _add_model(parser, help=None) -> None:
    parser.add_argument("--model", type=Path, default=_UNSET, help=help)


def _add_runs_dir(parser) -> None:
    parser.add_argument("--runs-dir", type=Path, default=_UNSET)


def _add_alert_files(parser) -> None:
    parser.add_argument("--wazuh-file", type=Path, default=None,
                        help="wazuh alert JSON, if it is not "
                             "<input>/<company>_wazuh.json")
    parser.add_argument("--aminer-file", type=Path, default=None,
                        help="aminer alert JSON, if it is not "
                             "<input>/<company>_aminer.json")


def _add_attack_mappings(parser) -> None:
    parser.add_argument("--attack-mappings", type=Path, default=_UNSET,
                        metavar="FILE",
                        help="local rule to ATT&CK mapping, merged over the "
                             "shipped one rule by rule")


def _add_run_selector(parser) -> None:
    parser.add_argument("--run", help="run id (default: latest successful)")
    _add_runs_dir(parser)


PULL_SOURCES = ("indexer", "file")


def _pull_window(args):
    from meerkat import connectors
    if args.day:
        if args.from_time or args.to_time:
            _fail("[red]give --day, or --from with --to[/red]")
        try:
            return connectors.day_window(args.day)
        except (ValueError, OverflowError):
            _fail(f"[red]--day is not a date: {safe(args.day)}[/red]")
    if not (args.from_time and args.to_time):
        _fail("[red]a window is required: --day, or both --from and --to[/red]")
    try:
        start = connectors.parse_moment(args.from_time)
        end = connectors.parse_moment(args.to_time)
        datetime.fromtimestamp(start, UTC)
        datetime.fromtimestamp(end, UTC)
    except (ValueError, OverflowError, OSError):
        _fail("[red]--from and --to take a date or epoch seconds[/red]")
    if end <= start:
        _fail("[red]--to must be after --from[/red]")
    return connectors.Window(start, end)


def _indexer_config(args):
    from meerkat import connectors
    config, _ = _load_config()
    raw = config.get("pull")
    section = raw if isinstance(raw, dict) else {}

    def pick(flag, variable, key, default=None):
        if flag is not None:
            return flag
        if os.environ.get(variable) is not None:
            return os.environ[variable]
        if key in section:
            return section[key]
        return default

    def secret(variable, key):
        if os.environ.get(variable) is not None:
            return os.environ[variable]
        return section.get(key)

    host = pick(args.host, "MEERKAT_INDEXER_HOST", "host")
    if not host:
        _fail(
            "[red]indexer mode needs a host[/red]  pass --host, set "
            "MEERKAT_INDEXER_HOST, or set host under \\[pull] in meerkat.toml"
        )
    verify = True
    if args.insecure:
        verify = False
    elif "verify_tls" in section:
        verify = section["verify_tls"]
        if not isinstance(verify, bool):
            _fail(
                "[red]verify_tls under \\[pull] must be true or false[/red]  "
                f"got {safe(repr(verify))}"
            )
    port_raw = pick(None, "MEERKAT_INDEXER_PORT", "port", 9200)
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        _fail(f"[red]indexer port is not a number: {safe(port_raw)}[/red]")
    return connectors.IndexerConfig(
        host=str(host),
        port=port,
        index=str(pick(None, "MEERKAT_INDEXER_INDEX", "index", "wazuh-alerts-*")),
        user=pick(args.user, "MEERKAT_INDEXER_USER", "user"),
        password=secret("MEERKAT_INDEXER_PASSWORD", "password"),
        token=secret("MEERKAT_INDEXER_TOKEN", "token"),
        verify_tls=verify,
    )


def cmd_pull(args) -> None:
    from meerkat import connectors
    company = resolve_company(args)
    window = _pull_window(args)
    args.input.mkdir(parents=True, exist_ok=True)
    wazuh_out = args.input / f"{company}_wazuh.json"
    eve_out = args.input / f"{company}_eve.json"
    targets = [wazuh_out]
    if args.source == "file" and args.eve_file:
        targets.append(eve_out)
    for path in targets:
        if path.exists():
            _fail(
                f"[red]{safe(path)} already exists[/red]  pull stops at an "
                "existing file; move or delete it first"
            )

    eve_records: list[dict] = []
    if args.source == "file":
        if not args.alerts_file:
            _fail(
                "[red]file mode needs --alerts-file[/red]  the wazuh "
                "alerts.json to read from"
            )
        records = connectors.read_window_file(args.alerts_file, window)
        if args.eve_file:
            eve_records = connectors.read_window_file(args.eve_file, window)
    else:
        config = _indexer_config(args)
        if not config.verify_tls:
            errors.print("[yellow]TLS verification disabled[/yellow]  credentials "
                         "are sent over an unverified channel")
        try:
            records = connectors.query_window(config, window)
        except connectors.ConnectorError as error:
            _fail(f"[red]{safe(error)}[/red]")

    total = len(records) + len(eve_records)
    if total == 0:
        errors.print("[yellow]no alerts in the window[/yellow]  nothing written")
        return

    connectors.write_records(wazuh_out, records)
    if eve_records:
        connectors.write_records(eve_out, eve_records)

    start_iso = datetime.fromtimestamp(window.start, UTC).isoformat()
    end_iso = datetime.fromtimestamp(window.end, UTC).isoformat()
    console.print(f"pulled {total} alerts for {safe(company)} ({args.source})")
    console.print(f"  window {start_iso} .. {end_iso}")
    console.print(f"  wrote {wazuh_out}")
    if eve_records:
        console.print(f"  wrote {eve_out}  ({len(eve_records)} suricata)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meerkat",
        description=(
            "Triage a SOC alert queue.\n\n"
            "analyst commands: triage, queue, inspect, review, browse\n"
            "input commands: pull, inventory, check\n"
            "run commands: attack, runs, export\n"
            "model commands: retrain, drift\n"
            "other: demo; bare `meerkat` says where things stand"
        ),
        epilog=(
            "first run:\n"
            "  meerkat demo                       score the bundled example\n"
            "\n"
            "your own data:\n"
            "  meerkat check --input DIR          read a sample and report what\n"
            "                                     triage will see\n"
            "  meerkat inventory myorg             scaffold the asset inventory,\n"
            "                                     then fill in the roles by hand\n"
            "  meerkat triage --environment myorg  score a day into a run\n"
            "  meerkat queue                      work the queue\n"
            "  meerkat inspect F003               open one family\n"
            "  meerkat review F003 escalate --session S1\n"
            "  meerkat retrain --environment myorg --incidents tickets.csv\n"
            "                                     refit on your own incidents\n"
            "\n"
            "alert files are found by content in --input; name one outright with\n"
            "--wazuh-file or --aminer-file when discovery is not wanted.\n"
            "\n"
            "defaults come from flags, then MEERKAT_* variables, then\n"
            "meerkat.toml (working directory, then ~/.config/meerkat/):\n"
            "  environment, input, inventory, attack_mappings, model, runs_dir\n"
            "\n"
            "exit codes: 0 ok, 1 error, 2 bad arguments, 3 retrain declined,\n"
            "            4 major drift found\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"meerkat {__version__}"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="plain output; NO_COLOR in the environment does the same",
    )
    sub = parser.add_subparsers(dest="command", required=False)

    triage = sub.add_parser("triage", help="score one environment into a run queue")
    _add_environment(triage)
    _add_input(triage)
    _add_inventory(triage)
    _add_alert_files(triage)
    _add_attack_mappings(triage)
    triage.add_argument("--budget", type=_positive, default=10)
    _add_model(triage)
    _add_runs_dir(triage)
    triage.set_defaults(func=cmd_triage)

    pull = sub.add_parser(
        "pull", help="fetch a window of Wazuh alerts into the input directory"
    )
    _add_environment(pull)
    _add_input(pull, help="directory the alerts are written to; default ./alerts")
    pull.add_argument("--source", choices=PULL_SOURCES, default="indexer",
                      help="indexer queries the Wazuh indexer; file reads a "
                           "local alerts.json")
    pull.add_argument("--from", dest="from_time", metavar="TIME",
                      help="window start, ISO 8601 or epoch seconds")
    pull.add_argument("--to", dest="to_time", metavar="TIME",
                      help="window end (exclusive), ISO 8601 or epoch seconds")
    pull.add_argument("--day", metavar="YYYY-MM-DD",
                      help="one UTC day as the window")
    pull.add_argument("--alerts-file", type=Path, default=None,
                      help="file mode: the wazuh alerts.json to read")
    pull.add_argument("--eve-file", type=Path, default=None,
                      help="file mode: a native suricata eve.json to read")
    pull.add_argument("--host", default=None,
                      help="indexer host, or MEERKAT_INDEXER_HOST / [pull] host")
    pull.add_argument("--user", default=None,
                      help="indexer username, or MEERKAT_INDEXER_USER; the password "
                           "or token comes from MEERKAT_INDEXER_PASSWORD, "
                           "MEERKAT_INDEXER_TOKEN, or the [pull] table in meerkat.toml")
    pull.add_argument("--insecure", action="store_true",
                      help="skip TLS verification, for a self-signed indexer")
    pull.set_defaults(func=cmd_pull)

    queue = sub.add_parser("queue", help="reopen a saved run's queue")
    queue.add_argument("--all", action="store_true", help="every scored family")
    queue.add_argument("--host", help="filter by host or entity")
    queue.add_argument("--detector", help="filter by detector source")
    queue.add_argument("--rule", help="filter by rule id substring")
    queue.add_argument("--criticality", choices=CRITICALITY_LEVELS,
                       help="filter by the asset's criticality tier")
    queue.add_argument("--tactic", type=_tactic_name, metavar="NAME",
                       help="families whose alerts map to this ATT&CK tactic")
    queue.add_argument("--review-state", choices=REVIEW_DECISIONS)
    queue.add_argument("--day", metavar="YYYY-MM-DD", help="one day's queue")
    queue.add_argument("--budget", type=_positive, default=None,
                       help="re-cut the queue at a different K; the ranking is "
                            "already saved, so this needs no rescoring")
    queue.add_argument("--json", action="store_true",
                       help="emit the queue as JSON instead of a table")
    _add_run_selector(queue)
    queue.set_defaults(func=cmd_queue)

    attack = sub.add_parser(
        "attack", help="every rule in a run with its ATT&CK mapping, unmapped first"
    )
    _add_run_selector(attack)
    attack.add_argument("--json", action="store_true",
                        help="emit the rules as JSON instead of a table")
    attack.set_defaults(func=cmd_attack)

    runs = sub.add_parser("runs", help="list saved runs")
    _add_runs_dir(runs)
    runs.add_argument("--json", action="store_true",
                      help="emit the run list as JSON instead of a table")
    runs.set_defaults(func=cmd_runs)

    inspect = sub.add_parser("inspect", help="open a family, session or alert")
    inspect.add_argument("handle", help="family handle, e.g. F3")
    inspect.add_argument("session", nargs="?", help="session handle, e.g. S1")
    inspect.add_argument("alert", nargs="?",
                         help="alert handle, e.g. A2, in the session's own order")
    inspect.add_argument("--distinct", metavar="field",
                         help="count the distinct values of one field")
    inspect.add_argument("--alerts", type=_positive, metavar="N",
                         help="show up to N alert rows")
    inspect.add_argument("--raw", action="store_true",
                         help="print the source lines as the detector wrote them")
    inspect.add_argument("--raw-dir", type=Path, default=None,
                         help="where the alert files live; defaults to the "
                              "directory the run recorded")
    inspect.add_argument("--json", action="store_true",
                         help="emit the family, sessions and alerts as JSON")
    inspect.add_argument("--no-pager", action="store_true")
    _add_run_selector(inspect)
    inspect.set_defaults(func=cmd_inspect)

    review = sub.add_parser("review", help="record a decision on a family or session")
    review.add_argument("handle", help="family handle, e.g. F3")
    review.add_argument("decision", choices=REVIEW_DECISIONS)
    review.add_argument(
        "--session",
        help="which burst, e.g. S1, or all. Required to escalate.",
    )
    review.add_argument("--note", default="",
                        help="free text stored with the decision")
    review.add_argument("--analyst", default=None,
                        help="who decided; defaults to the login name")
    _add_run_selector(review)
    review.set_defaults(func=cmd_review)

    export = sub.add_parser("export", help="export an artifact (support)")
    export_sub = export.add_subparsers(dest="artifact", required=True)
    navigator = export_sub.add_parser(
        "navigator",
        help="ATT&CK Navigator layer of the techniques seen in a saved run",
        description="Writes an ATT&CK Navigator layer from one saved run: the "
                    "latest, or --run ID. By default it covers every alert in "
                    "that run, including alerts whose family never entered the "
                    "queue. The layer is written inside that run's directory, "
                    "so runs do not overwrite each other. There is no combined "
                    "layer across runs; `meerkat runs` lists what is available.",
    )
    navigator.add_argument("--output", type=Path, default=None)
    navigator.add_argument(
        "--queue-only", action="store_true",
        help="only alerts belonging to families that entered the queue",
    )
    _add_run_selector(navigator)
    navigator.set_defaults(func=cmd_export)

    queue_out = export_sub.add_parser(
        "queue", help="the scored queue as csv or json, for a ticketing system"
    )
    queue_out.add_argument("--format", choices=("csv", "json"), default="csv")
    queue_out.add_argument("--output", type=Path, default=None)
    queue_out.add_argument("--all", action="store_true",
                           help="every scored family, not only the daily top-K")
    _add_run_selector(queue_out)
    queue_out.set_defaults(func=cmd_export_queue)

    decisions = export_sub.add_parser(
        "decisions",
        help="the review pass as a grid: every alert with its inherited decision",
        description="One row per alert of the queued families (or every scored "
                    "family with --all): the session it belongs to, and the "
                    "decision it inherits. A session review covers its alerts; "
                    "a family review covers every session without its own.",
    )
    decisions.add_argument("--format", choices=("csv", "json"), default="csv")
    decisions.add_argument("--output", type=Path, default=None)
    decisions.add_argument("--all", action="store_true",
                           help="every scored family, not only the daily top-K")
    decisions.add_argument("--decided-only", action="store_true",
                           help="only rows that carry a decision; the handoff "
                                "summary a shift ends with")
    _add_run_selector(decisions)
    decisions.set_defaults(func=cmd_export_decisions)

    html_export = export_sub.add_parser(
        "html",
        help="a static, self-contained page of the run or one family",
        description="Writes the queue and every queued family's view (or one "
                    "family with a handle) as a single HTML file: shareable, "
                    "attachable to a ticket, no server involved.",
    )
    html_export.add_argument("handle", nargs="?", default=None,
                      help="one family, e.g. F3; omit for the whole run")
    html_export.add_argument("--output", type=Path, default=None)
    _add_run_selector(html_export)
    html_export.set_defaults(func=cmd_export_html)

    browse = sub.add_parser(
        "browse",
        help="a prompt loop over the queue: type handles to drill in",
        description="Prints the queue, then reads commands at a `browse>` "
                    "prompt. `F3` opens a family, `S1` a session, `A2` an "
                    "alert; `review <decision> [note]` records a decision on "
                    "what is open; `b` walks back, `all`/`queue` switch scope, "
                    "`q` quits. Decisions land in the run's reviews.jsonl, "
                    "last entry per scope wins.",
    )
    _add_run_selector(browse)
    browse.set_defaults(func=cmd_browse)

    demo = sub.add_parser("demo", help="run the bundled russellmitchell demo")
    demo.set_defaults(func=cmd_demo, raw_dir=DEMO_RAW, model=DEFAULT_MODEL,
                      budget=10, runs_dir=DEFAULT_RUNS)

    inventory = sub.add_parser(
        "inventory", help="scaffold an asset inventory from a wazuh alert file"
    )
    inventory.add_argument("company", nargs="?", type=_company_label, default=None,
                           metavar="environment",
                           help="defaults to the input directory's name")
    _add_input(inventory)
    inventory.add_argument("--out", type=Path, help="default <input>/inventory/<company>.json")
    inventory.add_argument(
        "--limit", type=_positive, default=500_000,
        help="stop after this many alert lines",
    )
    inventory.add_argument(
        "--list-roles", action="store_true",
        help="print the role vocabulary and where each name comes from",
    )
    inventory.set_defaults(func=cmd_inventory)

    check = sub.add_parser(
        "check", help="read a sample of your alerts and report what triage will see"
    )
    _add_environment(check)
    _add_input(check)
    _add_inventory(check)
    _add_attack_mappings(check)
    check.add_argument("--sample", type=_positive, default=CHECK_SAMPLE,
                       help="how many alerts to read")
    check.add_argument("--json", action="store_true",
                       help="emit the report as JSON; warnings stay on stderr")
    _add_alert_files(check)
    check.set_defaults(func=cmd_check)

    drift = sub.add_parser(
        "drift", help="how far your alerts sit from what the model was trained on"
    )
    _add_environment(drift)
    _add_input(drift)
    _add_inventory(drift)
    _add_model(drift)
    drift.add_argument("--top", type=_positive, default=10,
                       help="how many features to list")
    drift.add_argument("--all", action="store_true",
                       help="list every feature, stable ones included")
    drift.add_argument("--json", action="store_true",
                       help="emit the full report as JSON, every feature included")
    _add_alert_files(drift)
    drift.set_defaults(func=cmd_drift)

    retrain = sub.add_parser(
        "retrain", help="refit the forest on your own alerts and incident records"
    )
    _add_environment(retrain)
    retrain.add_argument("--incidents", type=Path, required=True)
    _add_inventory(retrain)
    _add_input(retrain)
    _add_alert_files(retrain)
    _add_model(retrain, help="bundle to start from; its re-ranker is kept")
    retrain.add_argument("--out", type=Path, default=Path("models/retrained.skops"))
    retrain.add_argument("--holdout-days", type=_positive, default=7)
    retrain.add_argument("--budget", type=_positive, default=10)
    retrain.set_defaults(func=cmd_retrain)

    return parser


def cmd_inventory(args) -> None:
    if args.list_roles:
        for role, origin in role_sources().items():
            console.print(f"  {role:20} {origin}")
        return
    require_directory(args.input)
    company = resolve_company(args)
    alert_files = _resolve_files(args.input, company)
    source = next(
        (path for path, family in alert_files if family == WAZUH_FAMILY), None
    )
    if source is None:
        _fail(f"[red]wazuh alerts not found in:[/red] {safe(args.input)}")
    out = args.out or (args.input / "inventory" / f"{company}.json")

    # One asset per agent address, because that is what the pipeline keys a session
    # on. A wazuh alert carries agent.name and agent.ip but no roles, so roles are
    # the one part a person still fills in.
    names: dict[str, str] = {}
    read = 0
    with source.open(encoding="utf-8-sig") as handle:
        for read, line in enumerate(islice(handle, args.limit), start=1):
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            agent = record.get("agent") or {}
            address = str(agent.get("ip") or "").strip()
            if not address:
                continue
            hostname = str((record.get("predecoder") or {}).get("hostname") or "")
            names.setdefault(address, hostname.strip() or address)

    if not names:
        _fail(f"[red]no agent addresses found in {safe(source.name)}[/red]")

    assets = [
        {
            "hostname": names[address],
            "ip_addresses": [address],
            "roles": [],
            "criticality": "",
        }
        for address in sorted(names)
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"company": company, "assets": assets}, indent=2) + "\n",
        encoding="utf-8",
    )

    console.print(f"wrote {out}  {len(assets)} assets from {read} alert lines")
    console.print(
        "[yellow]roles are empty[/yellow]  the model reads asset role as a "
        "feature; assets left without one are scored without it"
    )
    console.print("roles available: " + ", ".join(CANONICAL_ROLES))
    console.print(
        "criticality is blank  set " + ", ".join(CRITICALITY_LEVELS)
        + " to show and filter by it; it never changes the score"
    )


def main(argv: list[str] | None = None) -> None:
    # rich prints box characters and ellipses, so keep the streams on utf-8 even
    # when a Windows console defaults to a legacy code page
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    if args.no_color:
        console.no_color = errors.no_color = True
    # bare `meerkat` orients instead of erroring, and needs a runs dir to look in
    if args.command is None:
        args.runs_dir = _UNSET
    _apply_config(args)
    try:
        if args.command is None:
            cmd_orientation(args)
            return
        args.func(args)
        sys.stdout.flush()
    except OSError as error:
        if isinstance(error, BrokenPipeError) or error.errno in (
            errno.EPIPE, errno.EINVAL
        ):
            _exit_on_closed_pipe()
        _fail(f"[red]{safe(error)}[/red]")
    except AlertFileError as error:
        _fail(f"[red]{safe(error)}[/red]")


if __name__ == "__main__":
    main()
