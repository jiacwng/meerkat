"""Meerkat command line: triage a company, work the queue.

This one file holds the whole CLI: the run directory and review state, the
terminal rendering, and the commands. The analyst commands are triage, queue,
inspect and review; the support commands are check, inventory, retrain, drift,
runs, export navigator, export queue and demo. Every command that reads a run
prints which run it used, and none of them score data again: triage writes a run
directory once and the rest reopen it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

import numpy as np
import pandas as pd
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from core.attack_mapping import (
    attack_story,
    export_navigator_layer,
    technique_name,
)
from core.classifier import (
    UntrustedBundleError,
    load_model,
    read_provenance,
    save_model,
)
from core.drift import (
    PSI_MAJOR,
    UNSEEN_RULE_WARN,
    compare_profile,
    unseen_rule_share,
)
from core.features import build_session_feature_matrix
from core.incidents import (
    assign_bag_priors,
    assign_reviewed,
    entity_for,
    load_incidents,
    load_reviewed_periods,
    unresolved_hosts,
)
from core.inventory import load_inventory
from core.normalize import (
    AMINER_FAMILY,
    SURICATA_FAMILY,
    WAZUH_FAMILY,
    AlertFileError,
    iter_normalized_rows,
    load_attack_windows,
    normalize_scenario,
    resolve_alert_files,
)
from core.roles import CANONICAL_ROLES, role_sources
from core.scenario_eval import (
    add_window_ids,
    refit_forest,
    rescale_bundle,
    score_sessions,
)
from core.sessions import SECONDS_PER_DAY, build_sessions
from core.triage_policy import enrich_alerts, queue_order
from meerkat import __version__

DEFAULT_MODEL = Path("models/meerkat_bundle.skops")
DEFAULT_RUNS = Path("runs")
# a plain convention a company can adopt, and deliberately NOT data/raw: pointing
# every command inside the benchmark's directory is what made the tool look
# inoperable until someone knew to pass --input
DEFAULT_INPUT = Path("alerts")

# the bundled demo is the only part of the product that knows the benchmark's
# layout. Nothing else may use these.
DEMO_COMPANY = "russellmitchell"
DEMO_RAW = Path("data/raw")
DEMO_LABELS = Path("data/labels.csv")
DEMO_INVENTORY_DIR = Path("data/raw/inventory")
DEMO_EVENT_CSV = Path("data/raw/alerts_csv")
REVIEW_DECISIONS = ("escalate", "benign", "false-positive")
DETECTOR_LABELS = {"wazuh": "Wazuh", "suricata": "Suricata", "aminer": "AMiner"}
# what `check` calls each kind of file: a wazuh export republishes suricata too
FAMILY_LABELS = {
    WAZUH_FAMILY: "wazuh and suricata",
    SURICATA_FAMILY: "suricata",
    AMINER_FAMILY: "log anomaly",
}

# rich parses [tags] in anything printed, and a Table cell does not strip ESC.
# Rule names, hostnames, user agents, urls and commands are all written by whoever
# triggered the alert, so an unescaped one can raise MarkupError and take out the
# whole queue view, draw a live hyperlink inside evidence text, or clear the
# analyst's terminal mid-table. Every alert-derived string goes through safe().
# C0 and C1, plus the bidi overrides. rich strips neither, and a bidi
# override reorders the line it lands in and knocks the table's columns out
# of alignment. Built from code points so the pattern never has to appear as
# literal control characters in this file.
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


console = Console()
# errors go to stderr so `meerkat queue --json | jq` stays parseable when one fails
errors = Console(stderr=True)

# 0 success, 2 argparse usage. A script has to tell a refused retrain, which is the
# gate working, apart from a crash, so declining gets its own code.
EXIT_ERROR = 1
EXIT_DECLINED = 3
EXIT_DRIFT = 4


# --------------------------------------------------------------------------
# run state: the run directory, display handles and the review log
#
# A run is one triage of one company. Its scored families, sessions and alerts
# live in a run directory so the read commands reopen it without scoring again,
# and a pointer file names the latest good run. Handles like F003 and S1 are
# run-local labels an analyst can type; the canonical family_id is kept beside
# every handle so a review or export always records which run it came from.
# --------------------------------------------------------------------------

def detector_label(detector_source: str) -> str:
    return DETECTOR_LABELS.get(str(detector_source), str(detector_source))


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(company: str) -> str:
    stamp = f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{datetime.now(UTC).microsecond // 1000:03d}"
    return safe_run_id(f"{company}-{stamp}")


def _family_label(alert_slice: pd.DataFrame) -> str:
    names = alert_slice["name"].astype(str)
    names = names[names.ne("")]
    return str(names.mode().iloc[0]) if len(names) else ""


def _host_label(alert_slice: pd.DataFrame, entity_id: str) -> str:
    hosts = alert_slice["host"].astype(str)
    hosts = hosts[hosts.ne("")]
    return str(hosts.mode().iloc[0]) if len(hosts) else str(entity_id)


def decorate_families(
    families: pd.DataFrame,
    alerts: pd.DataFrame,
    budget: int,
) -> pd.DataFrame:
    # order every scored family the way the queue orders them, then hand out
    # F001, F002... down that list so the top-K per day keep the low numbers
    ordered = queue_order(families).reset_index(drop=True)
    ordered["handle"] = [f"F{i + 1:03d}" for i in range(len(ordered))]
    ordered["queue_rank"] = ordered.groupby("day", sort=False).cumcount()
    ordered["in_queue"] = ordered["queue_rank"] < budget

    titles, hosts = [], []
    for rows, entity in zip(ordered["alert_rows"], ordered["entity_id"]):
        alert_slice = alerts.iloc[list(rows)]
        titles.append(_family_label(alert_slice))
        hosts.append(_host_label(alert_slice, entity))
    ordered["title"] = titles
    ordered["host_label"] = hosts
    return ordered


@dataclass
class RunState:
    run_id: str
    directory: Path
    meta: dict
    families: pd.DataFrame
    sessions: pd.DataFrame
    alerts: pd.DataFrame

    def family_by_handle(self, handle: str) -> pd.Series:
        match = self.families[self.families["handle"].eq(handle.upper())]
        if match.empty:
            raise KeyError(f"no family {handle} in run {self.run_id}")
        return match.iloc[0]

    def session_handles(self, family: pd.Series) -> list[tuple[str, str]]:
        # S1 is the family's best-scoring child, in the order build_families
        # already sorted the children
        return [
            (f"S{position + 1}", session_id)
            for position, session_id in enumerate(family["child_session_ids"])
        ]

    def session_by_handle(self, family: pd.Series, handle: str) -> pd.Series:
        pairs = dict(self.session_handles(family))
        session_id = pairs.get(handle.upper())
        if session_id is None:
            raise KeyError(f"no session {handle} under {family['handle']}")
        return self.sessions[self.sessions["session_id"].eq(session_id)].iloc[0]

    def family_alerts(self, family: pd.Series) -> pd.DataFrame:
        return self.alerts.iloc[list(family["alert_rows"])]

    def session_alerts(self, session: pd.Series) -> pd.DataFrame:
        return self.alerts.iloc[list(session["alert_rows"])]

    def related_families(self, family: pd.Series) -> pd.DataFrame:
        # other families on the same host, closest in time first, so a
        # corroborating detector on the same machine is one glance away
        same = self.families[
            self.families["entity_id"].eq(family["entity_id"])
            & self.families["handle"].ne(family["handle"])
        ].copy()
        if same.empty:
            return same
        same["gap_s"] = (same["start"] - family["start"]).abs()
        return same.sort_values("gap_s", kind="stable")


def save_run(
    runs_dir: Path,
    run_id: str,
    meta: dict,
    families: pd.DataFrame,
    sessions: pd.DataFrame,
    alerts: pd.DataFrame,
) -> Path:
    directory = runs_dir / run_id
    # never write into a finished run. Two triages in the same millisecond used
    # to interleave their pickles and the later latest.txt won, with both
    # reporting success.
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
    # only now the run is complete, so the latest pointer never names a run that
    # failed halfway through
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
        # DEFAULT_RUNS is relative to the working directory, like DEFAULT_MODEL,
        # so triaging in one directory and queueing in another used to advise
        # running the triage that had already been run
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
        families=pd.read_pickle(directory / "families.pkl"),
        sessions=pd.read_pickle(directory / "sessions.pkl"),
        alerts=pd.read_pickle(directory / "alerts.pkl"),
    )


# A session's identity has to survive a retrain. session_id is a row counter, the
# S1 handles are ordered by score, and the start timestamp moves when one late
# alert lands inside a 600 s gap and merges two bursts. Even the session's row
# offsets move, because they are positions inside whatever range that run covered.
# What does not move is where each alert sits in the raw detector file, so the key
# digests those.
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
) -> dict:
    entry = {
        "timestamp": _now_iso(),
        "run_id": run_id,
        "family_id": family_id,
        "handle": handle,
        "decision": decision,
        "note": note,
        # absent means the decision covers every session in the family
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
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def current_reviews(directory: Path) -> dict[str, dict]:
    # the last line wins, earlier lines stay as an audit trail
    latest: dict[str, dict] = {}
    for entry in review_history(directory):
        latest[entry["family_id"]] = entry
    return latest


# --------------------------------------------------------------------------
# rendering
#
# The queue is a table. A family or session is a summary followed by evidence
# panels. Panels follow one fixed order borrowed from ECS/OCSF and are keyed on
# normalized field meaning, never on the detector, so a new detector mapped into
# the same fields needs no new panel here.
# --------------------------------------------------------------------------

# panel title -> normalized fields it reads, in the fixed render order
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
    # the analyst is asking whether anything got through, so lead with that and
    # keep the codes as detail. Only HTTP carries success in the schema.
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


def _values(alert_slice: pd.DataFrame, field: str, cap: int = 6) -> str | None:
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
    shown = rendered[:cap]
    extra = len(rendered) - len(shown)
    text = ", ".join(shown)
    return text + (f"  (+{extra} more)" if extra else "")


def _render_panels(alert_slice: pd.DataFrame) -> None:
    present = []
    for title, rows in EVIDENCE_PANELS:
        lines = []
        for label, field in rows:
            value = _values(alert_slice, field)
            if value is not None:
                lines.append((label, value))
        if not lines:
            continue
        present.append(title)
        console.print(f"[bold cyan]{title}[/bold cyan]")
        width = max(len(label) for label, _ in lines)
        for label, value in lines:
            console.print(f"  {label.rjust(width)} : {safe(value)}")
        console.print()
    console.print(
        "[dim]Available evidence: "
        + (", ".join(present) if present else "none")
        + "[/dim]\n"
    )


def _render_attack_observations(alert_slice: pd.DataFrame) -> None:
    # host is a category over every hostname in the company, so cast it to a
    # plain string first or the grouping walks empty categories and breaks
    plain = alert_slice.assign(host=alert_slice["host"].astype(str))
    story = attack_story(plain)
    steps = [step for host_steps in story.values() for step in host_steps]
    console.print("[bold cyan]Related ATT&CK observations[/bold cyan]")
    if not steps:
        console.print("  [dim]no mapped technique on these alerts[/dim]\n")
        return
    for host, host_steps in story.items():
        if not host_steps:
            continue
        chain = "  ->  ".join(
            f"{tactic} ({fmt_time(timestamp)[11:]})"
            for timestamp, tactic in host_steps
        )
        console.print(f"  {safe(host)}: {chain}")
    console.print(
        "  [dim]independently mapped tactics, not a confirmed single "
        "campaign[/dim]\n"
    )


def _render_why(family: pd.Series) -> None:
    signals = [f"best child session score {family['child_score_max']:.2f}"]
    nearby = int(family["detectors_nearby_10m"])
    if nearby > 1:
        signals.append(
            f"{nearby} detectors active on this host within 10 minutes"
        )
    signals.append(
        f"{int(family['alert_count'])} alerts across "
        f"{int(family['n_child_sessions'])} session(s)"
    )
    if int(family["technique_count"]) > 0:
        signals.append(
            f"maps to {int(family['technique_count'])} ATT&CK technique(s)"
        )
    console.print("[bold cyan]Ranking signals[/bold cyan]")
    for signal in signals:
        console.print(f"  - {signal}")
    console.print()


def render_queue(
    families: pd.DataFrame,
    reviews: dict[str, dict],
    title: str,
) -> None:
    table = Table(title=title, title_justify="left", header_style="bold")
    table.add_column("handle", no_wrap=True)
    table.add_column("date", no_wrap=True)
    table.add_column("host", no_wrap=True, max_width=18, overflow="ellipsis")
    table.add_column("detector", no_wrap=True)
    table.add_column("finding", no_wrap=True, max_width=40, overflow="ellipsis")
    table.add_column("alerts", justify="right", no_wrap=True)
    table.add_column("score", justify="right", no_wrap=True)
    table.add_column("conf%", justify="right", no_wrap=True)
    table.add_column("review", no_wrap=True)
    if not len(families):
        console.print(f"[dim]{title}: no families match[/dim]")
        return
    for _, family in families.iterrows():
        review = reviews.get(family["family_id"], {})
        table.add_row(
            family["handle"],
            fmt_date(family["day"]),
            safe(family["host_label"]),
            detector_label(family["detector_source"]),
            safe(family["title"] or family["rule_id"])[:40],
            str(int(family["alert_count"])),
            f"{family['ranking_score']:.2f}",
            f"{family['evidence_probability'] * 100:.0f}",
            review.get("decision", ""),
        )
    console.print(table)


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
    console.print(f"\n[bold]{family_heading(family)}[/bold]")
    # family_id is built from the entity and the rule id, so it carries the same
    # attacker-written text they do
    console.print(f"[dim]family_id {safe(family['family_id'])}[/dim]")
    console.print(f"[dim]run {run.run_id}[/dim]\n")
    console.print("[bold cyan]Overview[/bold cyan]")
    console.print(f"  entity        : {safe(family['entity_id'])}")
    if family["asset_roles"]:
        # canonicalize() keeps only CANONICAL_ROLES, so these are ours
        console.print(f"  asset         : {', '.join(family['asset_roles'])}")
    console.print(f"  rule          : {safe(family['rule_id'])}")
    console.print(
        f"  window        : {fmt_time(family['start'])}"
        f"  ->  {fmt_time(family['end'])}  ({fmt_span(family['family_span_s'])})"
    )
    console.print(
        f"  ranking score : {family['ranking_score']:.3f}"
        f"   confidence {family['evidence_probability'] * 100:.0f}%"
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
        # the id comes off the alert and technique_name hands an unknown one back
        # verbatim, so neither half of this is ours
        named = ", ".join(
            f"{safe(tid)} {safe(technique_name(tid))}" for tid in techniques
        )
        console.print(f"  techniques    : {named}")
    review = reviews.get(family["family_id"])
    if review:
        console.print(
            f"  review        : {review['decision']}"
            + (f"  ({safe(review['note'])})" if review.get("note") else "")
        )
    console.print()

    _render_why(family)

    handles = run.session_handles(family)
    if len(handles) == 1:
        # one session, so its evidence is the family's evidence, no extra drill
        _render_panels(alert_slice)
    else:
        _render_session_list(run, family)

    _render_attack_observations(alert_slice)
    _render_related(run, family)


def _render_session_list(run: RunState, family: pd.Series) -> None:
    table = Table(title="Sessions", title_justify="left", header_style="bold")
    table.add_column("handle")
    table.add_column("start")
    table.add_column("span")
    table.add_column("alerts", justify="right")
    table.add_column("score", justify="right")
    for handle, session_id in run.session_handles(family):
        session = run.sessions[run.sessions["session_id"].eq(session_id)].iloc[0]
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
    outcome = _http_outcome(alert_slice)
    if outcome:
        console.print(f"  outcome: {outcome}")
    console.print()
    _render_panels(alert_slice)


def render_alert_rows(alert_slice: pd.DataFrame, limit: int) -> None:
    table = Table(
        title=f"Alerts (showing {min(limit, len(alert_slice))} of "
        f"{len(alert_slice)})",
        title_justify="left",
        header_style="bold",
    )
    table.add_column("time")
    table.add_column("detector")
    table.add_column("name")
    table.add_column("source")
    for _, alert in alert_slice.head(limit).iterrows():
        table.add_row(
            fmt_time(alert["timestamp"]),
            detector_label(alert["detector_source"]),
            safe(alert["name"])[:44],
            safe(f"{alert['source_file']}:{alert['source_position']}"),
        )
    console.print(table)


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


# --------------------------------------------------------------------------
# shared command helpers
# --------------------------------------------------------------------------

# every command checked this for itself and `drift` did not, so a missing
# bundle raised a traceback there and a clean message everywhere else. Call it
# early, before reading any alerts, so the answer is immediate.
#
# There are two ways to arrive with no bundle and they need different answers.
# DEFAULT_MODEL is relative to the working directory and models/ is not part of
# the installed package, so running from anywhere but a clone finds nothing at
# all. Inside a clone the file is usually there but unfetched from Git LFS.
def _require_bundle(path: Path) -> None:
    if path.exists():
        return
    if path == DEFAULT_MODEL and not path.parent.exists():
        errors.print(
            f"[red]no model at {path}[/red]\n"
            f"{path} is relative to the current directory, and models/ is not "
            "part of the installed package. Run from a clone of the "
            "repository, or pass --model with the path to a bundle.\n"
        )
    else:
        errors.print(
            f"[red]no model at {path}[/red]\n"
            "if this is a clone, the bundle is stored with Git LFS:\n\n"
            "  git lfs install\n"
            "  git lfs pull\n"
        )
    raise SystemExit(EXIT_ERROR)


def _load_bundle(path: Path):
    _require_bundle(path)
    # sklearn warns once per estimator on a version mismatch, which is a wall of
    # noise for one fact
    # the refusal message is the control that tells the user what is wrong with
    # the file, so it has to arrive as a message. An uncaught exception already
    # exits 1, so catching it here keeps the exit code and drops the traceback.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            bundle = load_model(path)
        except UntrustedBundleError as error:
            errors.print(f"[red]{safe(str(error))}[/red]")
            raise SystemExit(EXIT_ERROR) from None
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
    # the hash says the file is unchanged since it was written. It says nothing
    # about who wrote it, and an attacker shipping a bundle ships a matching
    # sidecar too, so say what it does and does not prove.
    record = read_provenance(path)
    if record is None:
        errors.print(
            f"[yellow]note[/yellow] {path.name} has no provenance sidecar, so "
            "there is no record of what trained it."
        )
    elif not record.get("matches_file", True):
        errors.print(
            f"[red]warning[/red] {path.name} does not match the sha256 in "
            f"{path.name}.json, so it changed after it was written. Retrain with "
            "`meerkat retrain` rather than trusting it."
        )
    return bundle


def _load_run(args) -> RunState:
    try:
        return load_run(args.runs_dir, args.run)
    except (FileNotFoundError, ValueError) as error:
        errors.print(f"[red]{error}[/red]")
        raise SystemExit(EXIT_ERROR)


def _announce_run(run: RunState) -> None:
    company = run.meta.get("company", "?")
    budget = run.meta.get("budget", "?")
    console.print(
        f"[dim]run {run.run_id}  |  company {company}  |  "
        f"budget {budget}  |  {len(run.families)} families[/dim]"
    )


def _is_lfs_pointer(path: Path) -> bool:
    with path.open("rb") as file:
        return file.read(64).startswith(b"version https://git-lfs")


def _require(path: Path, what: str) -> None:
    # checked up front, so a missing file reports itself instead of surfacing as
    # a traceback halfway through normalization
    if not path.exists():
        errors.print(f"[red]{what} not found:[/red] {path}")
        raise SystemExit(EXIT_ERROR)


def _aminer_name(args, company: str) -> str:
    # the miner file is absent here, so name the one that was looked for
    named = getattr(args, "aminer_file", None)
    return named.name if named else f"{company}_aminer.json"


def _open_company(args) -> str:
    # triage, check and drift all start on the same three questions: is the
    # input there, what is this company called, and where is its inventory
    require_directory(args.input)
    company = resolve_company(args)
    if args.inventory is None:
        args.inventory = args.input / "inventory" / f"{company}.json"
    _require(args.inventory, "inventory")
    return company


def _score_company(
    bundle,
    input_dir: Path,
    company: str,
    inventory_path: Path,
    labels_path: Path | None,
    event_csv_dir: Path | None,
    wazuh_file: Path | None = None,
    aminer_file: Path | None = None,
):
    inventory = load_inventory(inventory_path)
    # an inventory scaffolded by `meerkat inventory` has empty roles until
    # someone fills them in, and the queue changes quietly rather than failing,
    # so the condition is worth reporting. What it costs was measured on one
    # benchmark, so report the state and leave the decision alone.
    unroled = inventory.assets_without_roles()
    if unroled:
        share = len(unroled) / max(len(set(inventory.assets_by_ip.values())), 1)
        console.print(
            f"[yellow]{len(unroled)} assets have no roles[/yellow] "
            f"({share:.0%} of {inventory_path.name}). Their alerts are scored "
            "without the role features. `meerkat inventory --list-roles` lists "
            "the vocabulary."
        )
    if inventory.unknown_roles:
        # an unrecognised role is whatever the inventory file said, which is why
        # `check` escapes this same value
        console.print(
            f"[yellow]unrecognised roles[/yellow] "
            f"{', '.join(safe(role) for role in inventory.unknown_roles)} "
            "contribute nothing to a model trained elsewhere"
        )
    windows = (
        load_attack_windows(labels_path, company)
        if labels_path and labels_path.exists()
        else []
    )
    frame = normalize_scenario(
        input_dir, labels_path, company, inventory_path, event_csv_dir,
        wazuh_file=wazuh_file, aminer_file=aminer_file,
    )
    # the same condition `check` reports. Without it the empty feature matrix
    # reaches the forest and sklearn answers with its own traceback.
    if frame.empty:
        errors.print(
            "[red]no alerts parsed[/red]  the files resolved but held no rows"
        )
        raise SystemExit(EXIT_ERROR)
    # mark the window ids once so the session alert_rows and the saved alert
    # table share one row order and line up by position
    marked = add_window_ids(frame, windows)
    sessions = build_sessions(marked, company, inventory)
    alerts = enrich_alerts(marked)
    scored_sessions, families = score_sessions(bundle, sessions)
    return scored_sessions, families, alerts


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------

def cmd_triage(args) -> None:
    _require_bundle(args.model)
    company = _open_company(args)
    try:
        alert_files = resolve_alert_files(
            args.input, company, args.wazuh_file, args.aminer_file
        )
    except FileNotFoundError as error:
        errors.print(f"[red]{error}[/red]")
        raise SystemExit(EXIT_ERROR)
    bundle = _load_bundle(args.model)
    # the miner is optional, but say so: dropping it costs coverage
    if not any(family == AMINER_FAMILY for _, family in alert_files):
        console.print(
            f"[yellow]no {_aminer_name(args, company)}[/yellow]  scoring wazuh "
            "and suricata only; log anomaly detections will be missing from "
            "the queue"
        )
    console.print(f"scoring {company} with {args.model}")
    scored_sessions, families, alerts = _score_company(
        bundle, args.input, company, args.inventory,
        args.labels, args.event_csv_dir,
        wazuh_file=args.wazuh_file, aminer_file=args.aminer_file,
    )
    families = decorate_families(families, alerts, args.budget)

    run_id = new_run_id(company)
    meta = {
        "company": company,
        "budget": args.budget,
        "model": str(args.model),
        "input": str(args.input),
        "training_scenarios": list(bundle.training_scenarios),
        "families": int(len(families)),
        "sessions": int(len(scored_sessions)),
        "alerts": int(len(alerts)),
    }
    directory = save_run(
        args.runs_dir, run_id, meta, families, scored_sessions, alerts
    )
    console.print(f"[green]saved run[/green] {directory}")
    _print_queue(
        load_run(args.runs_dir, run_id), show_all=False,
        host=None, detector=None, rule=None, review_state=None,
    )


# --------------------------------------------------------------------------
# queue
# --------------------------------------------------------------------------

def _select_families(
    run, show_all, host, detector, rule, review_state, day=None
):
    # a filter narrows the whole run, not only the day's top-K, so "show me
    # everything on this host" reaches families below the queue line too. --day
    # is a different thing: it picks one day and keeps that day's top-K.
    full_scope = show_all or any([host, detector, rule, review_state])
    families = run.families if full_scope else run.families[run.families["in_queue"]]
    if day:
        dates = families["day"].map(fmt_date)
        if day not in set(dates):
            # stderr, or `queue --json | jq` gets 46 bytes of prose on stdout and
            # fails to parse, which is the contract stated at the top of this file
            errors.print(
                f"[red]no day {day} in this run[/red]  available: "
                + ", ".join(sorted(set(run.families["day"].map(fmt_date))))
            )
            raise SystemExit(EXIT_ERROR)
        families = families[dates.eq(day)]
    if host:
        families = families[
            families["host_label"].astype(str).eq(host)
            | families["entity_id"].astype(str).eq(host)
        ]
    if detector:
        families = families[families["detector_source"].astype(str).eq(detector)]
    if rule:
        families = families[
            families["rule_id"].astype(str).str.contains(rule, case=False, regex=False)
        ]
    if review_state:
        reviews = current_reviews(run.directory)
        keep = {
            family_id
            for family_id, entry in reviews.items()
            if entry["decision"] == review_state
        }
        families = families[families["family_id"].isin(keep)]
    return families


def _print_queue(
    run, show_all, host, detector, rule, review_state, day=None
) -> None:
    _announce_run(run)
    families = _select_families(
        run, show_all, host, detector, rule, review_state, day
    )
    reviews = current_reviews(run.directory)
    if show_all or any([host, detector, rule, review_state]):
        scope = "all scored families"
    else:
        scope = f"top {run.meta['budget']} per day"
    if day:
        scope += f", {day}"
    render_queue(families, reviews, f"Review queue ({scope})")


QUEUE_JSON_FIELDS = (
    "handle", "day", "host_label", "entity_id", "detector_source", "rule_id",
    "title", "alert_count", "n_child_sessions", "queue_rank", "in_queue",
    "ranking_score", "evidence_probability", "start", "end",
)


def queue_records(run, families) -> list[dict]:
    reviews = current_reviews(run.directory)
    records = []
    for _, family in families.iterrows():
        record = {
            field: family[field] for field in QUEUE_JSON_FIELDS if field in family
        }
        record["family_id"] = family["family_id"]
        record["run_id"] = run.run_id
        review = reviews.get(family["family_id"])
        record["review"] = review["decision"] if review else None
        records.append(record)
    return records


def cmd_queue(args) -> None:
    run = _load_run(args)
    if args.budget:
        # K never reaches the model, so a saved run can be cut anywhere. Every
        # family already carries its queue_rank from triage.
        run.families["in_queue"] = run.families["queue_rank"] < args.budget
        run.meta["budget"] = args.budget
    if args.json:
        families = _select_families(
            run, args.all, args.host, args.detector, args.rule,
            args.review_state, args.day,
        )
        print(json.dumps(queue_records(run, families), indent=2, default=str))
        return
    _print_queue(
        run, args.all, args.host, args.detector, args.rule, args.review_state,
        args.day,
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
    table.add_column("run")
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


# --------------------------------------------------------------------------
# inspect
# --------------------------------------------------------------------------

def _parse_pairs(pairs, columns) -> list[tuple[str, str]]:
    parsed = []
    for pair in pairs or []:
        if "=" not in pair:
            errors.print(f"[red]expected field=value, got {pair!r}[/red]")
            raise SystemExit(EXIT_ERROR)
        field, value = pair.split("=", 1)
        if field not in columns:
            errors.print(
                f"[red]unknown field {field!r}[/red]  "
                "check the normalized schema"
            )
            raise SystemExit(EXIT_ERROR)
        parsed.append((field, value))
    return parsed


def _match(series, value):
    if series.dtype.kind == "f":
        try:
            return series == float(value)
        except ValueError:
            return series.astype(str).eq(value)
    return series.astype(str).eq(value)


def _apply_filters(alert_slice, wheres, excludes):
    for field, value in wheres:
        alert_slice = alert_slice[_match(alert_slice[field], value)]
    for field, value in excludes:
        alert_slice = alert_slice[~_match(alert_slice[field], value)]
    return alert_slice


def _render_raw(alert_slice, raw_dir: Path, limit: int) -> None:
    for source_file, group in alert_slice.head(limit).groupby(
        "source_file", sort=False
    ):
        path = raw_dir / str(source_file)
        wanted = {int(position): None for position in group["source_position"]}
        if not path.exists():
            console.print(f"[yellow]raw source {safe(path)} not available[/yellow]")
            continue
        # one byte that is not utf-8 anywhere in the file used to be a traceback
        # here, while every ingest path replaces it and carries on
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


def cmd_inspect(args) -> None:
    run = _load_run(args)
    _announce_run(run)
    columns = set(run.alerts.columns)
    wheres = _parse_pairs(args.where, columns)
    excludes = _parse_pairs(args.exclude, columns)
    if args.distinct and args.distinct not in columns:
        errors.print(f"[red]unknown field {args.distinct!r}[/red]")
        raise SystemExit(EXIT_ERROR)

    try:
        family = run.family_by_handle(args.handle)
    except KeyError as error:
        errors.print(f"[red]{error.args[0]}[/red]")
        raise SystemExit(EXIT_ERROR)

    if args.session:
        try:
            session = run.session_by_handle(family, args.session)
        except KeyError as error:
            errors.print(f"[red]{error.args[0]}[/red]")
            raise SystemExit(EXIT_ERROR)
        alert_slice = run.session_alerts(session)
    else:
        session = None
        alert_slice = run.family_alerts(family)

    alert_slice = _apply_filters(alert_slice, wheres, excludes)
    reviews = current_reviews(run.directory)

    if args.distinct:
        render_distinct(alert_slice, args.distinct)
        return

    wants_rows = bool(args.alerts or args.raw or wheres or excludes)
    if session is not None:
        render_session(family, args.session.upper(), session, alert_slice)
    else:
        render_family(run, family, reviews)

    if wants_rows:
        limit = args.alerts or (5 if args.raw else 20)
        if args.raw:
            _render_raw(alert_slice, _raw_dir_for(run, args), limit)
        else:
            render_alert_rows(alert_slice, limit)


# --------------------------------------------------------------------------
# review
# --------------------------------------------------------------------------

def cmd_review(args) -> None:
    run = _load_run(args)
    try:
        family = run.family_by_handle(args.handle)
    except KeyError as error:
        errors.print(f"[red]{error.args[0]}[/red]")
        raise SystemExit(EXIT_ERROR)

    # Dismissing a family is exact: if nothing in it was an attack, nothing in any
    # of its sessions was. Escalating one is not, because it only means at least
    # one burst was malicious, so that direction has to name the burst.
    handles = run.session_handles(family)
    session = None
    if args.decision == "escalate" and not args.session:
        errors.print(
            f"[red]{family['handle']} holds {len(handles)} sessions[/red]  "
            "escalate needs --session S1 to say which burst was malicious, "
            "or --session all if the whole family was"
        )
        for handle, _ in handles:
            errors.print(f"  {handle}")
        raise SystemExit(EXIT_ERROR)

    if args.session and args.session.lower() != "all":
        try:
            session = run.session_by_handle(family, args.session)
        except KeyError as error:
            errors.print(f"[red]{error.args[0]}[/red]")
            raise SystemExit(EXIT_ERROR)

    entry = append_review(
        run.directory, run.run_id, family["family_id"], family["handle"],
        args.decision, args.note or "",
        session_key=(session_label_key(session, run.alerts) if session is not None else None),
        session_handle=args.session.upper() if args.session else None,
    )
    scope = (
        f"{family['handle']}/{args.session.upper()}" if session is not None
        else family["handle"]
    )
    console.print(
        f"[green]recorded[/green] {scope} -> {entry['decision']}"
        + (f"  ({safe(entry['note'])})" if entry["note"] else "")
    )
    if session is None:
        console.print(f"[dim]covers all {len(handles)} sessions[/dim]")
    console.print(f"[dim]{safe(family['family_id'])}  run {run.run_id}[/dim]")


# --------------------------------------------------------------------------
# retrain
# --------------------------------------------------------------------------

def _incident_reach(families, incidents, inventory, budget):
    # one boolean per incident rather than a count, because the approval test needs
    # to know WHICH incidents the two models disagree about
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
# pairs reach 0.0625 and six reach 0.031. Below six the comparison cannot call a
# difference real however many incidents were supplied.
MIN_DISCORDANT = 6


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
    # A client chooses between two things they could deploy: the bundle as
    # downloaded, or a retrained one. The rescale-only arm is measured so they can
    # see how much of any gain needed no labels at all, and it is reported rather
    # than gated on.
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
    _require(args.incidents, "incident records")
    _require(args.inventory, "inventory")
    _require_bundle(args.model)
    require_directory(args.input)
    company = resolve_company(args)

    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    incidents = _load_or_exit(load_incidents, args.incidents, "the incident records")
    unresolved = unresolved_hosts(incidents, inventory)
    if unresolved:
        # the host column of the incident CSV, so it is written by whoever
        # filled in the tickets
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
    if len(days) <= args.holdout_days:
        errors.print(
            f"[red]{len(days)} days of alerts, need more than "
            f"{args.holdout_days}[/red]"
        )
        raise SystemExit(EXIT_ERROR)
    cutoff = days[-args.holdout_days]
    train = sessions[sessions["day"] < cutoff].copy()
    held = sessions[sessions["day"] >= cutoff].copy()

    reviewed_periods = (
        load_reviewed_periods(args.reviewed_periods)
        if args.reviewed_periods else None
    )
    train["reviewed"] = assign_reviewed(train, reviewed_periods)
    # split the incidents on the same instant as the sessions. Passing all of them
    # would let a burst that spans the cutoff be labelled by a held-out incident.
    boundary = cutoff * SECONDS_PER_DAY
    train_incidents = incidents[incidents["start"] < boundary]
    held_incidents = incidents[incidents["start"] >= boundary]
    prior = assign_bag_priors(train, train_incidents, inventory, args.prior_k)
    bags = int((prior > 0).sum())
    console.print(
        f"{len(sessions)} sessions over {len(days)} days, "
        f"{len(incidents)} incidents, {len(train_incidents)} for training and "
        f"{len(held_incidents)} held out, {bags} sessions inside one"
    )
    if not len(train_incidents):
        errors.print(
            f"[red]every incident falls in the last {args.holdout_days} days, "
            "so training has nothing to learn from[/red]  lower --holdout-days, "
            "or supply incidents covering an earlier period"
        )
        raise SystemExit(EXIT_ERROR)
    # one forest per seed, because a single fit decides approval on a metric coarse
    # enough for seed noise to flip it
    try:
        candidates = [
            refit_forest(
                bundle, train, prior, n_estimators=args.trees, seed=args.seed + offset,
                min_positives=args.min_positives,
            )
            for offset in range(args.fits)
        ]
    except ValueError as error:
        errors.print(f"[red]{error}[/red]")
        raise SystemExit(EXIT_ERROR)

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
        # the gate did its job, so this is a decision rather than a failure
        raise SystemExit(EXIT_DECLINED)

    retrained = candidates[verdict["median_index"]]
    save_model(retrained, args.out)
    console.print(
        f"[green]saved[/green] {args.out}  "
        f"{sum(verdict['passed'])} of {len(verdict['passed'])} seeds passed, "
        "median kept"
    )


# --------------------------------------------------------------------------
# check: read a bounded sample and answer "will triage work on this"
#
# bench/check.py answers a different question, whether the eight benchmark
# environments are on disk, so almost nothing is shared beyond the idea.
# --------------------------------------------------------------------------

CHECK_SAMPLE = 5_000
# above this share of distinct rule ids, the detector is probably numbering each
# anomaly instead of naming its type, which quietly ruins rarity and the session key
RULE_CARDINALITY_WARN = 0.5


def cmd_check(args) -> None:
    company = _open_company(args)
    try:
        alert_files = resolve_alert_files(
            args.input, company, args.wazuh_file, args.aminer_file
        )
    except FileNotFoundError as error:
        errors.print(f"[red]{error}[/red]")
        raise SystemExit(EXIT_ERROR)

    console.print(f"reading up to {args.sample} alerts from {args.input}")
    for path, family in alert_files:
        size = path.stat().st_size / 1_000_000
        label = FAMILY_LABELS[family]
        console.print(f"  [green]found[/green] {label:19} {path.name}  {size:.1f} MB")
    if not any(family == AMINER_FAMILY for _, family in alert_files):
        label = FAMILY_LABELS[AMINER_FAMILY]
        console.print(
            f"  [dim]absent[/dim] {label:19} {_aminer_name(args, company)}"
        )

    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    # one generator drains the first file before reaching the second, so a flat
    # sample of a company with 4,056 miner and 32,302 host alerts reports the miner
    # alone. Take a share from each file instead.
    per_file = max(1, args.sample // len(alert_files))
    rows = []
    for entry in alert_files:
        rows.extend(islice(
            iter_normalized_rows(
                args.input, None, company, args.inventory, files=[entry],
            ),
            per_file,
        ))
    if not rows:
        errors.print("[red]no alerts parsed[/red]  the files resolved but held no rows")
        raise SystemExit(EXIT_ERROR)

    frame = pd.DataFrame(rows)
    table = Table(title=f"check ({len(frame)} alerts sampled)",
                  title_justify="left", header_style="bold")
    table.add_column("detector")
    table.add_column("alerts", justify="right")
    table.add_column("hosts", justify="right")
    table.add_column("in inventory", justify="right")
    table.add_column("distinct rules", justify="right")
    for detector, part in frame.groupby("detector_source", sort=True):
        matched = int(part["entity_in_inventory"].astype(bool).sum())
        table.add_row(
            detector_label(str(detector)),
            str(len(part)),
            str(part["entity_id"].nunique()),
            f"{matched}/{len(part)}",
            str(part["rule_id"].nunique()),
        )
    console.print(table)

    start, end = frame["timestamp"].min(), frame["timestamp"].max()
    console.print(f"  covering {fmt_time(start)} to {fmt_time(end)}")

    problems = 0
    # entity_id is what the inventory is keyed on, so name the entity. Printing
    # host instead reported web01 as outside an inventory that held it, because
    # the address beside that name was the part that did not match.
    unmatched = frame.loc[~frame["entity_in_inventory"].astype(bool), "entity_id"]
    if len(unmatched):
        share = len(unmatched) / len(frame)
        names = sorted(set(unmatched.astype(str)))[:5]
        # a network alert names both ends of a connection, so internet addresses
        # appear here and can never be in an asset inventory. Report it without
        # failing: the exit code is for things an operator can act on.
        console.print(
            f"[yellow]{share:.0%} of alerts are on hosts outside the inventory"
            f"[/yellow]  {', '.join(safe(n) for n in names)}\n"
            "  those alerts are scored without role features. A network alert "
            "names both ends of a connection, so addresses outside your estate "
            "appear here too."
        )

    unroled = inventory.assets_without_roles()
    if unroled:
        errors.print(
            f"[yellow]{len(unroled)} inventory assets have no roles[/yellow]  "
            "their alerts are scored without the role features. "
            "`meerkat inventory --list-roles` lists the vocabulary."
        )
        problems += 1
    if inventory.unknown_roles:
        errors.print(
            f"[yellow]unrecognised roles[/yellow] "
            f"{', '.join(safe(r) for r in inventory.unknown_roles)}  "
            "these contribute nothing to a model trained elsewhere"
        )
        problems += 1

    # rarity and the session key both assume rule_id names a KIND of alert. A
    # detector numbering each anomaly individually degrades the model with no
    # error at all, so say it here rather than let it pass silently.
    ratio = frame["rule_id"].nunique() / len(frame)
    # under 500 alerts a high distinct-rule share is just a small sample
    if ratio > RULE_CARDINALITY_WARN and len(frame) >= 500:
        errors.print(
            f"[yellow]{frame['rule_id'].nunique()} distinct rule ids across "
            f"{len(frame)} alerts[/yellow]  sessions group on rule id, so "
            "Meerkat reads it as naming a kind of alert rather than one "
            "occurrence. At this ratio sessions do not group and rule rarity "
            "carries no signal."
        )
        problems += 1

    if problems:
        console.print(f"[yellow]{problems} thing(s) to look at before triaging[/yellow]")
        raise SystemExit(EXIT_ERROR)
    console.print("[green]ready to triage[/green]")


# --------------------------------------------------------------------------
# drift: how far the current alerts sit from what the model was trained on
#
# This needs NO incidents, which is the point. Evaluation needs confirmed
# tickets and a client is short of those. It reports covariate shift only:
# it can say the input moved and it cannot say the queue got worse.
# --------------------------------------------------------------------------

VERDICT_STYLE = {"stable": "green", "moderate": "yellow", "major": "red"}
# measured: with no shift on either side, 85% of features read "major" at 10
# training sessions and 50% at 30. By 300 it is 0%.
DRIFT_MIN_TRAINING = 300


def cmd_drift(args) -> None:
    company = _open_company(args)
    bundle = _load_bundle(args.model)
    profile = getattr(bundle, "profile", None)
    if profile is None:
        errors.print(
            f"[red]{args.model.name} carries no training profile[/red]  it predates "
            "drift reporting. Refit with `meerkat retrain` to record one."
        )
        raise SystemExit(EXIT_ERROR)

    inventory = _load_or_exit(load_inventory, args.inventory, "the inventory")
    alerts = normalize_scenario(
        args.input, None, company, args.inventory,
        wazuh_file=args.wazuh_file, aminer_file=args.aminer_file,
    )
    sessions = build_sessions(alerts, company, inventory)
    X = build_session_feature_matrix(sessions, bundle.schema)
    scored, families = score_sessions(bundle, sessions)

    console.print(
        f"{len(alerts)} alerts, {len(sessions)} sessions, {len(families)} families "
        f"against a model trained on {profile.n_sessions} sessions"
    )

    unseen = unseen_rule_share(bundle.schema, sessions["pair_counts"])
    console.print(
        f"  rules the model never saw: [bold]{unseen:.1%}[/bold] of alerts"
        + ("  [red]<- the model has no rarity signal for these[/red]"
           if unseen > UNSEEN_RULE_WARN else "")
    )
    outside = 1.0 - float(sessions["in_inventory"].mean())
    console.print(
        f"  sessions on hosts outside the inventory: [bold]{outside:.1%}[/bold]"
        f"  (training had {1 - profile.inventory_coverage:.1%})"
    )

    if profile.n_sessions < DRIFT_MIN_TRAINING:
        console.print(
            f"[yellow]this model was fitted on {profile.n_sessions} sessions"
            f"[/yellow]  below about {DRIFT_MIN_TRAINING} the comparison is mostly "
            "noise: unmoved features read as major drift roughly half the time"
        )

    drifts = compare_profile(profile, X)
    table = Table(title="feature drift, worst first", title_justify="left",
                  header_style="bold")
    table.add_column("feature")
    table.add_column("PSI", justify="right")
    table.add_column("verdict")
    table.add_column("training median", justify="right")
    table.add_column("now", justify="right")
    shown = [d for d in drifts if d.verdict != "stable"] or drifts[:5]
    for d in shown[:args.top]:
        style = VERDICT_STYLE[d.verdict]
        table.add_row(
            safe(d.name), f"{d.psi:.3f}", f"[{style}]{d.verdict}[/{style}]",
            f"{d.training_median:.3f}", f"{d.current_median:.3f}",
        )
    console.print(table)

    # the queue is a top-K cut, so a shift confined to the bottom of the score
    # distribution changes nothing an analyst sees. Report the boundary separately.
    trained_edges = profile.family_score_bins[0]
    if trained_edges:
        boundary = float(np.quantile(families["ranking_score"].to_numpy(), 0.9))
        trained_boundary = trained_edges[-1]
        console.print(
            f"  top-decile family score: [bold]{boundary:.3f}[/bold] now, "
            f"{trained_boundary:.3f} at training"
        )

    major = [d for d in drifts if d.verdict == "major"]
    if major or unseen > UNSEEN_RULE_WARN:
        console.print(
            f"[yellow]{len(major)} feature(s) past PSI {PSI_MAJOR}[/yellow]  "
            "this reports that the input moved. It does not measure whether the "
            "ranking is still right, which needs confirmed outcomes."
        )
        raise SystemExit(EXIT_DRIFT)
    console.print(f"[green]no major drift[/green]  worst PSI {drifts[0].psi:.3f}"
                  if drifts else "[green]no comparable features[/green]")


# --------------------------------------------------------------------------
# export navigator
# --------------------------------------------------------------------------

def cmd_export(args) -> None:
    run = _load_run(args)
    _announce_run(run)
    if args.queue_only:
        families = run.families[run.families["in_queue"]]
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


# Excel evaluates a cell starting with one of these. A leading tab or newline is
# in the set because the character after it starts the cell instead; \r is not,
# because _CONTROL has already stripped it by the time this is read.
_CSV_FORMULA_LEAD = frozenset("=+-@\t\n")


def _csv_safe(value):
    if not isinstance(value, str):
        return value
    # strip control characters first: this file is opened in a spreadsheet and
    # cat'd in a terminal, and rule names and hostnames are attacker-written
    value = _CONTROL.sub("", value)
    # a hostname is attacker-controlled, so quote the leading character rather
    # than the whole cell. This used to test `value[:1] in "=+-@\t\r"`, and ""
    # is in every string, so every blank cell in every export came out as a
    # lone apostrophe.
    if value and value[0] in _CSV_FORMULA_LEAD:
        return "'" + value
    return value


def cmd_export_queue(args) -> None:
    run = _load_run(args)
    families = run.families if args.all else run.families[run.families["in_queue"]]
    records = queue_records(run, families)
    suffix = "json" if args.format == "json" else "csv"
    output = args.output or (run.directory / f"queue.{suffix}")
    if args.format == "json":
        output.write_text(
            json.dumps(records, indent=2, default=str), encoding="utf-8"
        )
    else:
        pd.DataFrame(records).map(_csv_safe).to_csv(output, index=False)
    console.print(f"[green]exported[/green] {len(records)} families to {output}")


# --------------------------------------------------------------------------
# demo
# --------------------------------------------------------------------------

def cmd_demo(args) -> None:
    wazuh = args.raw_dir / f"{DEMO_COMPANY}_wazuh.json"
    aminer = args.raw_dir / f"{DEMO_COMPANY}_aminer.json"
    for path in (wazuh, aminer):
        if not path.exists() or _is_lfs_pointer(path):
            errors.print(
                f"[red]demo data missing: {path}[/red]\n"
                "the raw AIT files are stored with Git LFS. fetch them with:\n\n"
                "  git lfs install\n"
                "  git lfs pull\n"
            )
            raise SystemExit(EXIT_ERROR)

    # the event-label CSVs are evaluation ground truth and are not shipped, so
    # a clone triages without them and reports no window coverage
    labels = DEMO_LABELS if DEMO_LABELS.exists() else None
    event_csv = DEMO_EVENT_CSV if DEMO_EVENT_CSV.exists() else None
    cmd_triage(argparse.Namespace(
        model=args.model, input=args.raw_dir, company=DEMO_COMPANY,
        inventory=DEMO_INVENTORY_DIR / f"{DEMO_COMPANY}.json",
        labels=labels, event_csv_dir=event_csv,
        wazuh_file=None, aminer_file=None,
        budget=args.budget, runs_dir=args.runs_dir,
    ))
    console.print(
        "\n[dim]next: `meerkat inspect F001` to open the top family, "
        "`meerkat export navigator` for the ATT&CK layer[/dim]"
    )


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def safe_run_id(run_id: str) -> str:
    # a run directory is unpickled on open, so the id has to be one path
    # component. Traversal here is code execution, not a wrong directory.
    cleaned = str(run_id).strip()
    if not cleaned or Path(cleaned).name != cleaned or cleaned in (".", ".."):
        raise ValueError(f"{run_id!r} is not a run id")
    return cleaned


def _company_label(value: str) -> str:
    # the label becomes a run directory name, so it takes the run id rule. It
    # used to be checked in new_run_id, after normalizing and scoring the whole
    # dataset, so `--company ../evil` cost the full run before it failed.
    try:
        return safe_run_id(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error))


def _load_or_exit(load, path: Path, what: str):
    # core raises ValueError with a message written for a person. Letting it
    # escape turned every one of them into a traceback.
    try:
        return load(path)
    except (ValueError, OSError) as error:
        # some of these quote the cell they choked on, and an incident CSV with
        # a start of "[/b]" then reached rich as markup and raised MarkupError
        # from inside the handler written to avoid a traceback
        errors.print(f"[red]{what} could not be read[/red]  {safe(error)}")
        raise SystemExit(EXIT_ERROR)


def _raw_dir_for(run: RunState, args) -> Path:
    return args.raw_dir or Path(run.meta.get("input", str(DEFAULT_INPUT)))


def require_directory(path: Path) -> None:
    # a missing directory used to fall through to the inventory check, so a
    # first-time user with nothing in place was told the inventory was missing.
    # The inventory is written from the alerts, so that is the wrong end.
    if not path.exists():
        errors.print(
            f"[red]no alert directory at {path}[/red]  create it and put your "
            "detector exports inside, or point --input at the folder that "
            "already holds them."
        )
        raise SystemExit(EXIT_ERROR)
    if not path.is_dir():
        errors.print(
            f"[red]--input must be a directory[/red]  {path} is a file. Point it "
            "at the folder holding your alert exports."
        )
        raise SystemExit(EXIT_ERROR)


def resolve_company(args) -> str:
    # the company name used to double as a filename prefix. Discovery is by format
    # now, so it is only a run label, and the input directory names it well enough
    # that a single-site user never has to pass it.
    if getattr(args, "company", None):
        return args.company
    # a drive or filesystem root resolves to an empty name, and there is nothing
    # there to label the run with
    try:
        return safe_run_id(args.input.resolve().name)
    except ValueError:
        errors.print(
            f"[red]cannot name a run after {args.input}[/red]  a filesystem "
            "root has no directory name to use as the company. Pass --company "
            "with a label, or point --input at a named directory."
        )
        raise SystemExit(EXIT_ERROR)


def _positive_float(value: str) -> float:
    number = float(value)
    if not number > 0 or number != number or number in (float("inf"),):
        raise argparse.ArgumentTypeError("must be a finite number above 0")
    return number


def _add_alert_files(parser) -> None:
    # --input plus AIT's <company>_wazuh.json naming stays the default, and either
    # file can be named outright when the export is called something else
    parser.add_argument("--wazuh-file", type=Path, default=None,
                        help="wazuh alert JSON, if it is not "
                             "<input>/<company>_wazuh.json")
    parser.add_argument("--aminer-file", type=Path, default=None,
                        help="aminer alert JSON, if it is not "
                             "<input>/<company>_aminer.json")


def _add_run_selector(parser) -> None:
    parser.add_argument("--run", help="run id (default: latest successful)")
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meerkat",
        description=(
            "Triage a SOC alert queue.\n\n"
            "analyst commands: triage, queue, inspect, review\n"
            "support commands: check, inventory, retrain, drift, export, demo"
        ),
        epilog=(
            "first run:\n"
            "  meerkat demo                       score the bundled example\n"
            "\n"
            "your own data:\n"
            "  meerkat check --input DIR          read a sample and report what\n"
            "                                     triage will see\n"
            "  meerkat inventory ACME             scaffold the asset inventory,\n"
            "                                     then fill in the roles by hand\n"
            "  meerkat triage --company ACME      score a day into a run\n"
            "  meerkat queue                      work the queue\n"
            "  meerkat inspect F003               open one family\n"
            "  meerkat review F003 escalate --session S1\n"
            "  meerkat retrain --company ACME --incidents tickets.csv\n"
            "                                     refit on your own incidents\n"
            "\n"
            "alert files default to <input>/<company>_wazuh.json; pass\n"
            "--wazuh-file or --aminer-file when yours are named differently.\n"
            "\n"
            "exit codes: 0 ok, 1 error, 2 bad arguments, 3 retrain declined,\n"
            "            4 major drift found\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"meerkat {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)


    triage = sub.add_parser("triage", help="score one company into a run queue")
    triage.add_argument("--company", type=_company_label, default=None,
                        help="run label; defaults to the input directory's name")
    triage.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                        help="directory with <company>_wazuh.json etc.")
    triage.add_argument("--inventory", type=Path, default=None,
                        help="asset inventory JSON; defaults to where "
                             "`meerkat inventory` writes it")
    _add_alert_files(triage)
    triage.add_argument("--labels", type=Path, default=None,
                        help="optional label CSV, for evaluation only")
    triage.add_argument("--event-csv-dir", type=Path, default=None)
    triage.add_argument("--budget", type=_positive, default=10)
    triage.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    triage.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    triage.set_defaults(func=cmd_triage)

    queue = sub.add_parser("queue", help="reopen a saved run's queue")
    queue.add_argument("--all", action="store_true", help="every scored family")
    queue.add_argument("--host", help="filter by host or entity")
    queue.add_argument("--detector", help="filter by detector source")
    queue.add_argument("--rule", help="filter by rule id substring")
    queue.add_argument("--review-state", choices=REVIEW_DECISIONS)
    queue.add_argument("--day", metavar="YYYY-MM-DD", help="one day's queue")
    queue.add_argument("--budget", type=_positive, default=None,
                       help="re-cut the queue at a different K; the ranking is "
                            "already saved, so this needs no rescoring")
    queue.add_argument("--json", action="store_true",
                       help="emit the queue as JSON instead of a table")
    _add_run_selector(queue)
    queue.set_defaults(func=cmd_queue)

    runs = sub.add_parser("runs", help="list saved runs")
    runs.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    runs.add_argument("--json", action="store_true",
                      help="emit the run list as JSON instead of a table")
    runs.set_defaults(func=cmd_runs)

    inspect = sub.add_parser("inspect", help="open a family or session")
    inspect.add_argument("handle", help="family handle, e.g. F003")
    inspect.add_argument("session", nargs="?", help="session handle, e.g. S1")
    inspect.add_argument("--where", action="append", metavar="field=value")
    inspect.add_argument("--exclude", action="append", metavar="field=value")
    inspect.add_argument("--distinct", metavar="field")
    inspect.add_argument("--alerts", type=_positive, metavar="N")
    inspect.add_argument("--raw", action="store_true")
    inspect.add_argument("--raw-dir", type=Path, default=None,
                         help="where the alert files live; defaults to the "
                              "directory the run recorded")
    _add_run_selector(inspect)
    inspect.set_defaults(func=cmd_inspect)

    review = sub.add_parser("review", help="record a decision on a family or session")
    review.add_argument("handle", help="family handle, e.g. F003")
    review.add_argument("decision", choices=REVIEW_DECISIONS)
    review.add_argument(
        "--session",
        help="which burst, e.g. S1, or all. Required to escalate.",
    )
    review.add_argument("--note", default="")
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

    demo = sub.add_parser("demo", help="run the bundled russellmitchell demo")
    demo.add_argument("--raw-dir", type=Path, default=DEMO_RAW)
    demo.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    demo.add_argument("--budget", type=_positive, default=10)
    demo.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    demo.set_defaults(func=cmd_demo)

    inventory = sub.add_parser(
        "inventory", help="scaffold an asset inventory from a wazuh alert file"
    )
    inventory.add_argument("company", nargs="?", type=_company_label, default=None,
                           help="defaults to the input directory's name")
    inventory.add_argument("--input", type=Path, default=DEFAULT_INPUT)
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
    check.add_argument("--company", type=_company_label, default=None,
                       help="run label; defaults to the input directory's name")
    check.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    check.add_argument("--inventory", type=Path, default=None)
    check.add_argument("--sample", type=_positive, default=CHECK_SAMPLE,
                       help="how many alerts to read")
    _add_alert_files(check)
    check.set_defaults(func=cmd_check)

    drift = sub.add_parser(
        "drift", help="how far your alerts sit from what the model was trained on"
    )
    drift.add_argument("--company", type=_company_label, default=None)
    drift.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    drift.add_argument("--inventory", type=Path, default=None)
    drift.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    drift.add_argument("--top", type=_positive, default=10,
                       help="how many features to list")
    _add_alert_files(drift)
    drift.set_defaults(func=cmd_drift)

    retrain = sub.add_parser(
        "retrain", help="refit the forest on your own alerts and incident records"
    )
    retrain.add_argument("--company", type=_company_label, default=None,
                         help="run label; defaults to the input directory's name")
    retrain.add_argument("--incidents", type=Path, required=True)
    retrain.add_argument(
        "--reviewed-periods", type=Path,
        help="CSV of start,end periods whose alerts were fully reviewed",
    )
    retrain.add_argument("--inventory", type=Path, required=True)
    retrain.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    _add_alert_files(retrain)
    retrain.add_argument("--model", type=Path, default=DEFAULT_MODEL,
                         help="bundle to start from; its re-ranker is kept")
    retrain.add_argument("--out", type=Path, default=Path("models/retrained.skops"))
    retrain.add_argument("--holdout-days", type=_positive, default=7)
    retrain.add_argument("--budget", type=_positive, default=10)
    tuning = retrain.add_argument_group(
        "tuning",
        "defaults are what the benchmark shipped with; leave them alone unless "
        "you are measuring something",
    )
    tuning.add_argument("--prior-k", type=_positive_float, default=1.0,
                        help="bag-size discount; a ticket contributes k/n per "
                             "session and k=1 keeps every ticket's total at 1.0")
    tuning.add_argument("--min-positives", type=_positive, default=10)
    tuning.add_argument("--trees", type=int, default=300)
    tuning.add_argument("--seed", type=int, default=0)
    tuning.add_argument("--fits", type=_positive, default=5,
                        help="forests to fit; a majority must beat the shipped one")
    retrain.set_defaults(func=cmd_retrain)

    return parser


# wazuh alerts carry agent.name and agent.ip but not agent groups, so roles are
# the one part a human still has to fill in
def cmd_inventory(args) -> None:
    if getattr(args, "list_roles", False):
        for role, origin in role_sources().items():
            console.print(f"  {role:20} {origin}")
        return
    require_directory(args.input)
    company = resolve_company(args)
    # scaffolding reads the same file triage will, so a differently named export
    # scaffolds as readily as the benchmark's convention
    try:
        alert_files = resolve_alert_files(args.input, company)
    except FileNotFoundError as error:
        errors.print(f"[red]{error}[/red]")
        raise SystemExit(EXIT_ERROR)
    # an asset is one agent address, and only a wazuh export carries agent.ip
    source = next(
        (path for path, family in alert_files if family == WAZUH_FAMILY), None
    )
    if source is None:
        errors.print(f"[red]wazuh alerts not found in:[/red] {args.input}")
        raise SystemExit(EXIT_ERROR)
    out = args.out or (args.input / "inventory" / f"{company}.json")

    # One asset per agent address, because that is what the pipeline keys a
    # session on. Grouping by agent.name instead collapsed every machine behind a
    # manager reporting one name into a single asset, and they then shared one set
    # of roles: on the bundled data that turned ten machines into one.
    names: dict[str, str] = {}
    read = 0
    with source.open(encoding="utf-8-sig") as handle:
        for line in handle:
            if read >= args.limit:
                break
            read += 1
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            agent = record.get("agent") or {}
            address = str(agent.get("ip") or "").strip()
            if not address:
                continue
            # predecoder.hostname is what the machine calls itself. Falling back
            # to the address rather than the agent name matches how
            # extract_wazuh_fields labels a host, and avoids three machines all
            # being called after the collector.
            hostname = str((record.get("predecoder") or {}).get("hostname") or "")
            names.setdefault(address, hostname.strip() or address)

    if not names:
        errors.print(f"[red]no agent addresses found in {source.name}[/red]")
        raise SystemExit(EXIT_ERROR)

    assets = [
        {
            "hostname": names[address],
            "ip_addresses": [address],
            "roles": [],
        }
        for address in sorted(names)
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"company": company, "assets": assets}, indent=2) + "\n",
        encoding="utf-8",
    )

    console.print(f"wrote {out}  {len(assets)} assets from {read} alert lines")
    # say what the model does with roles, not what filling them in is worth:
    # that was measured on one benchmark and does not transfer
    console.print(
        "[yellow]roles are empty[/yellow]  the model reads asset role as a "
        "feature; assets left without one are scored without it"
    )
    console.print("roles available: " + ", ".join(CANONICAL_ROLES))


def main(argv: list[str] | None = None) -> None:
    # rich prints box characters and ellipses, so keep stdout on utf-8 even when
    # a Windows console defaults to a legacy code page
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except AlertFileError as error:
        # the message already names the file and the line, which is the whole
        # point: one bad record in a 45 MB export should not print a traceback.
        # It names a file the operator may not have chosen, so it is escaped too.
        errors.print(f"[red]{safe(error)}[/red]")
        raise SystemExit(EXIT_ERROR)


if __name__ == "__main__":
    main()
