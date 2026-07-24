"""Meerkat command line: train a model, triage a company, work the queue.

This one file holds the whole CLI: the run directory and review state, the
terminal rendering, and the commands. The analyst commands are triage, queue,
inspect and review; the support commands are train, export navigator and demo.
Every command that reads a run prints which run it used, and none of them score
data again: triage writes a run directory once and the rest reopen it.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from rich.console import Console
from rich.table import Table

from core.attack_mapping import (
    attack_story,
    export_navigator_layer,
    technique_name,
)
from core.classifier import load_model, save_model
from core.inventory import load_inventory
from core.normalize import load_attack_windows, normalize_scenario
from core.scenario_eval import (
    SCENARIOS,
    add_window_ids,
    build_bundle,
    load_inventories,
    load_scenarios,
    prepare_sessions,
    score_sessions,
)
from core.sessions import build_sessions
from core.triage_policy import daily_queue, enrich_alerts
from meerkat import __version__


DEFAULT_MODEL = Path("models/meerkat_bundle.joblib")
DEFAULT_RUNS = Path("runs")
DEFAULT_RAW = Path("data/raw")
DEFAULT_LABELS = Path("data/labels.csv")
DEFAULT_INVENTORY_DIR = Path("data/raw/inventory")
DEFAULT_EVENT_CSV = Path("data/raw/alerts_csv")
DEMO_COMPANY = "russellmitchell"
REVIEW_DECISIONS = ("escalate", "benign", "false-positive")
DETECTOR_LABELS = {"wazuh": "Wazuh", "suricata": "Suricata", "aminer": "AMiner"}

console = Console()


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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(company: str) -> str:
    return f"{company}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"


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
    ordered = families.sort_values(
        ["day", "ranking_score", "start", "representative_session_id"],
        ascending=[True, False, True, True],
        kind="stable",
    ).reset_index(drop=True)
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
    (runs_dir / "latest.txt").write_text(run_id, encoding="utf-8")
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
        raise FileNotFoundError(
            f"no runs in {runs_dir}, run `meerkat triage` first"
        )
    directory = runs_dir / run_id
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


def append_review(
    directory: Path,
    run_id: str,
    family_id: str,
    handle: str,
    decision: str,
    note: str,
) -> dict:
    entry = {
        "timestamp": _now_iso(),
        "run_id": run_id,
        "family_id": family_id,
        "handle": handle,
        "decision": decision,
        "note": note,
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

PANEL_FIELDS = {field for _, rows in EVIDENCE_PANELS for _, field in rows}


def fmt_time(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def fmt_date(day: int) -> str:
    return datetime.fromtimestamp(int(day) * 86400, tz=timezone.utc).strftime(
        "%Y-%m-%d"
    )


def fmt_span(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


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
            console.print(f"  {label.rjust(width)} : {value}")
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
        console.print(f"  {host}: {chain}")
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
    table.add_column("prob%", justify="right", no_wrap=True)
    table.add_column("review", no_wrap=True)
    if not len(families):
        console.print(f"[dim]{title}: no families match[/dim]")
        return
    for _, family in families.iterrows():
        review = reviews.get(family["family_id"], {})
        table.add_row(
            family["handle"],
            fmt_date(family["day"]),
            str(family["host_label"]),
            detector_label(family["detector_source"]),
            (family["title"] or family["rule_id"])[:40],
            str(int(family["alert_count"])),
            f"{family['ranking_score']:.2f}",
            f"{family['evidence_probability'] * 100:.0f}",
            review.get("decision", ""),
        )
    console.print(table)


def family_heading(family: pd.Series) -> str:
    return (
        f"{family['handle']}  {family['host_label']} / "
        f"{detector_label(family['detector_source'])} / "
        f"{family['title'] or family['rule_id']}"
    )


def render_family(
    run: RunState,
    family: pd.Series,
    reviews: dict[str, dict],
) -> None:
    console.print(f"\n[bold]{family_heading(family)}[/bold]")
    console.print(f"[dim]family_id {family['family_id']}[/dim]")
    console.print(f"[dim]run {run.run_id}[/dim]\n")
    console.print("[bold cyan]Overview[/bold cyan]")
    console.print(f"  entity        : {family['entity_id']}")
    console.print(f"  rule          : {family['rule_id']}")
    console.print(
        f"  window        : {fmt_time(family['start'])}"
        f"  ->  {fmt_time(family['end'])}  ({fmt_span(family['family_span_s'])})"
    )
    console.print(
        f"  ranking score : {family['ranking_score']:.3f}"
        f"   probability {family['evidence_probability'] * 100:.0f}%"
    )
    console.print(
        f"  volume        : {int(family['alert_count'])} alerts, "
        f"{int(family['n_child_sessions'])} session(s)"
    )
    techniques = sorted(family["technique_id_set"])
    if techniques:
        named = ", ".join(f"{tid} {technique_name(tid)}" for tid in techniques)
        console.print(f"  techniques    : {named}")
    review = reviews.get(family["family_id"])
    if review:
        console.print(
            f"  review        : {review['decision']}"
            + (f"  ({review['note']})" if review.get("note") else "")
        )
    console.print()

    _render_why(family)

    alert_slice = run.family_alerts(family)
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
            f" / {other['title'] or other['rule_id']}"
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
        f"{family['host_label']} / "
        f"{detector_label(session['detector_source'])} / "
        f"{family['title'] or session['rule_id']}[/bold]\n"
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
            str(alert["name"])[:44],
            f"{alert['source_file']}:{alert['source_position']}",
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
        table.add_row(str(value)[:60], str(int(count)))
    console.print(table)


# --------------------------------------------------------------------------
# shared command helpers
# --------------------------------------------------------------------------

def _load_run(args) -> RunState:
    try:
        return load_run(args.runs_dir, args.run)
    except FileNotFoundError as error:
        console.print(f"[red]{error}[/red]")
        raise SystemExit(1)


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
        console.print(f"[red]{what} not found:[/red] {path}")
        raise SystemExit(1)


def _score_company(
    bundle,
    input_dir: Path,
    company: str,
    inventory_path: Path,
    labels_path: Path | None,
    event_csv_dir: Path | None,
):
    inventory = load_inventory(inventory_path)
    windows = (
        load_attack_windows(labels_path, company)
        if labels_path and labels_path.exists()
        else []
    )
    frame = normalize_scenario(
        input_dir, labels_path, company, inventory_path, event_csv_dir
    )
    # mark the window ids once so the session alert_rows and the saved alert
    # table share one row order and line up by position
    marked = add_window_ids(frame, windows)
    sessions = build_sessions(marked, company, inventory)
    alerts = enrich_alerts(marked)
    scored_sessions, families = score_sessions(bundle, sessions)
    return scored_sessions, families, alerts


# --------------------------------------------------------------------------
# train
# --------------------------------------------------------------------------

def cmd_train(args) -> None:
    scenarios = tuple(s for s in SCENARIOS if s != args.holdout)
    console.print(
        f"training on {len(scenarios)} companies"
        + (f", holding out {args.holdout}" if args.holdout else "")
    )
    frames = load_scenarios(
        args.raw_dir, args.labels, args.inventory_dir, scenarios,
        args.event_csv_dir,
    )
    inventories = load_inventories(args.inventory_dir, scenarios)
    windows = {
        scenario: load_attack_windows(args.labels, scenario)
        for scenario in scenarios
    }
    sessions = prepare_sessions(frames, inventories, windows)
    bundle = build_bundle(
        sessions, holdout=None, n_estimators=args.trees, seed=args.seed
    )
    save_model(bundle, args.model)
    console.print(
        f"[green]saved model[/green] {args.model}  "
        f"({args.trees} trees, seed {args.seed})"
    )


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------

def _window_metrics(families, budget: int, total_windows: int) -> dict:
    # only meaningful for a labelled company like the demo, where we can check
    # which official attack windows the top-K queue actually reaches
    labelled = families["labelled_alert_count"].sum()
    if labelled == 0:
        return {}
    queued = daily_queue(families, k=budget)
    strict = frozenset().union(*queued["labelled_windows"])
    overlap = frozenset().union(*queued["temporal_overlap_windows"])
    return {
        "labelled_alerts": int(labelled),
        "total_windows": total_windows,
        "strict_windows": len(strict),
        "temporal_overlap_windows": len(overlap),
    }


def cmd_triage(args) -> None:
    if not args.model.exists():
        console.print(
            f"[red]no model at {args.model}[/red]  run `meerkat train` first"
        )
        raise SystemExit(1)
    _require(args.inventory, "inventory")
    _require(args.input / f"{args.company}_wazuh.json", "wazuh alerts")
    _require(args.input / f"{args.company}_aminer.json", "aminer alerts")
    bundle = load_model(args.model)
    console.print(f"scoring {args.company} with {args.model}")
    scored_sessions, families, alerts = _score_company(
        bundle, args.input, args.company, args.inventory,
        args.labels, args.event_csv_dir,
    )
    families = decorate_families(families, alerts, args.budget)

    total_windows = (
        len(load_attack_windows(args.labels, args.company))
        if args.labels and args.labels.exists()
        else 0
    )
    run_id = new_run_id(args.company)
    meta = {
        "company": args.company,
        "budget": args.budget,
        "model": str(args.model),
        "input": str(args.input),
        "training_scenarios": list(bundle.training_scenarios),
        "families": int(len(families)),
        "sessions": int(len(scored_sessions)),
        "alerts": int(len(alerts)),
        **_window_metrics(families, args.budget, total_windows),
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
            console.print(
                f"[red]no day {day} in this run[/red]  available: "
                + ", ".join(sorted(set(run.families["day"].map(fmt_date))))
            )
            raise SystemExit(1)
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
            families["rule_id"].astype(str).str.contains(rule, case=False)
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


def cmd_queue(args) -> None:
    run = _load_run(args)
    _print_queue(
        run, args.all, args.host, args.detector, args.rule, args.review_state,
        args.day,
    )


def cmd_runs(args) -> None:
    latest = latest_run_id(args.runs_dir)
    directories = sorted(
        d for d in args.runs_dir.glob("*") if (d / "run.json").exists()
    ) if args.runs_dir.exists() else []
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
            console.print(f"[red]expected field=value, got {pair!r}[/red]")
            raise SystemExit(1)
        field, value = pair.split("=", 1)
        if field not in columns:
            console.print(
                f"[red]unknown field {field!r}[/red]  "
                "check the normalized schema"
            )
            raise SystemExit(1)
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
            console.print(f"[yellow]raw source {path} not available[/yellow]")
            continue
        with path.open(encoding="utf-8") as file:
            for index, line in enumerate(file):
                if index in wanted:
                    wanted[index] = line
                    if all(value is not None for value in wanted.values()):
                        break
        for position, line in wanted.items():
            console.print(f"[dim]{source_file}:{position}[/dim]")
            if line is None:
                console.print("[yellow]line not found[/yellow]")
                continue
            try:
                console.print_json(json.dumps(json.loads(line)))
            except json.JSONDecodeError:
                console.print(line.rstrip())


def cmd_inspect(args) -> None:
    run = _load_run(args)
    _announce_run(run)
    columns = set(run.alerts.columns)
    wheres = _parse_pairs(args.where, columns)
    excludes = _parse_pairs(args.exclude, columns)
    if args.distinct and args.distinct not in columns:
        console.print(f"[red]unknown field {args.distinct!r}[/red]")
        raise SystemExit(1)

    try:
        family = run.family_by_handle(args.handle)
    except KeyError as error:
        console.print(f"[red]{error.args[0]}[/red]")
        raise SystemExit(1)

    if args.session:
        try:
            session = run.session_by_handle(family, args.session)
        except KeyError as error:
            console.print(f"[red]{error.args[0]}[/red]")
            raise SystemExit(1)
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
            _render_raw(alert_slice, args.raw_dir, limit)
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
        console.print(f"[red]{error.args[0]}[/red]")
        raise SystemExit(1)
    entry = append_review(
        run.directory, run.run_id, family["family_id"], family["handle"],
        args.decision, args.note or "",
    )
    console.print(
        f"[green]recorded[/green] {family['handle']} -> {entry['decision']}"
        + (f"  ({entry['note']})" if entry["note"] else "")
    )
    console.print(f"[dim]{family['family_id']}  run {run.run_id}[/dim]")


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


# --------------------------------------------------------------------------
# demo
# --------------------------------------------------------------------------

def cmd_demo(args) -> None:
    wazuh = args.raw_dir / f"{DEMO_COMPANY}_wazuh.json"
    aminer = args.raw_dir / f"{DEMO_COMPANY}_aminer.json"
    for path in (wazuh, aminer):
        if not path.exists() or _is_lfs_pointer(path):
            console.print(
                f"[red]demo data missing: {path}[/red]\n"
                "the raw AIT files are stored with Git LFS. fetch them with:\n\n"
                "  git lfs install\n"
                "  git lfs pull\n"
            )
            raise SystemExit(1)

    if not args.model.exists():
        console.print(
            f"[yellow]no model at {args.model}, training one "
            f"(holdout {DEMO_COMPANY})[/yellow]"
        )
        cmd_train(argparse.Namespace(
            holdout=DEMO_COMPANY, raw_dir=args.raw_dir, labels=DEFAULT_LABELS,
            inventory_dir=DEFAULT_INVENTORY_DIR, event_csv_dir=DEFAULT_EVENT_CSV,
            trees=300, seed=0, model=args.model,
        ))

    cmd_triage(argparse.Namespace(
        model=args.model, input=args.raw_dir, company=DEMO_COMPANY,
        inventory=DEFAULT_INVENTORY_DIR / f"{DEMO_COMPANY}.json",
        labels=DEFAULT_LABELS, event_csv_dir=DEFAULT_EVENT_CSV,
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


def _add_run_selector(parser) -> None:
    parser.add_argument("--run", help="run id (default: latest successful)")
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meerkat",
        description=(
            "Triage a SOC alert queue.\n\n"
            "analyst commands: triage, queue, inspect, review\n"
            "support commands: train, export navigator, demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"meerkat {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    train = sub.add_parser("train", help="fit and save the model (support)")
    train.add_argument("--holdout", help="company to keep out of training")
    train.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    train.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    train.add_argument("--inventory-dir", type=Path, default=DEFAULT_INVENTORY_DIR)
    train.add_argument("--event-csv-dir", type=Path, default=DEFAULT_EVENT_CSV)
    train.add_argument("--trees", type=int, default=300)
    train.add_argument("--seed", type=int, default=0)
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    train.set_defaults(func=cmd_train)

    triage = sub.add_parser("triage", help="score one company into a run queue")
    triage.add_argument("--company", required=True, help="company name")
    triage.add_argument("--input", type=Path, default=DEFAULT_RAW,
                        help="directory with <company>_wazuh.json etc.")
    triage.add_argument("--inventory", type=Path, required=True,
                        help="the company asset inventory JSON")
    triage.add_argument("--labels", type=Path, default=None,
                        help="optional label CSV, for evaluation only")
    triage.add_argument("--event-csv-dir", type=Path, default=None)
    triage.add_argument("--budget", type=int, default=10)
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
    _add_run_selector(queue)
    queue.set_defaults(func=cmd_queue)

    runs = sub.add_parser("runs", help="list saved runs")
    runs.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    runs.set_defaults(func=cmd_runs)

    inspect = sub.add_parser("inspect", help="open a family or session")
    inspect.add_argument("handle", help="family handle, e.g. F003")
    inspect.add_argument("session", nargs="?", help="session handle, e.g. S1")
    inspect.add_argument("--where", action="append", metavar="field=value")
    inspect.add_argument("--exclude", action="append", metavar="field=value")
    inspect.add_argument("--distinct", metavar="field")
    inspect.add_argument("--alerts", type=_positive, metavar="N")
    inspect.add_argument("--raw", action="store_true")
    inspect.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    _add_run_selector(inspect)
    inspect.set_defaults(func=cmd_inspect)

    review = sub.add_parser("review", help="record a decision on a family")
    review.add_argument("handle", help="family handle, e.g. F003")
    review.add_argument("decision", choices=REVIEW_DECISIONS)
    review.add_argument("--note", default="")
    _add_run_selector(review)
    review.set_defaults(func=cmd_review)

    export = sub.add_parser("export", help="export an artifact (support)")
    export_sub = export.add_subparsers(dest="artifact", required=True)
    navigator = export_sub.add_parser(
        "navigator", help="ATT&CK Navigator layer of observed techniques"
    )
    navigator.add_argument("--output", type=Path, default=None)
    navigator.add_argument("--queue-only", action="store_true")
    _add_run_selector(navigator)
    navigator.set_defaults(func=cmd_export)

    demo = sub.add_parser("demo", help="run the bundled russellmitchell demo")
    demo.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    demo.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    demo.add_argument("--budget", type=int, default=10)
    demo.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> None:
    # rich prints box characters and ellipses, so keep stdout on utf-8 even when
    # a Windows console defaults to a legacy code page
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
