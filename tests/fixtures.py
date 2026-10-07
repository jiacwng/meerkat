# shared builders for the suite: alerts, families and sessions, client
# directories, saved runs, a small bundle, and the CLI driven in-process

from __future__ import annotations

import argparse
import contextlib
import functools
import io
import json
import os
import re
import tempfile
from pathlib import Path
from typing import NamedTuple
from unittest import mock

import numpy as np
import pandas as pd

from core.classifier import is_lfs_pointer, save_model
from meerkat import cli

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_BUNDLE = ROOT / "models" / "meerkat_bundle.skops"
HAS_BUNDLE = SHIPPED_BUNDLE.exists() and not is_lfs_pointer(SHIPPED_BUNDLE)
HAS_RUN = (ROOT / "runs" / "latest.txt").exists()


def make_alerts() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "timestamp": 100.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "entity_id": "10.0.0.5",
            "source_file": "acme_wazuh.json", "source_position": 10,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 400.0, "http_method": "GET", "web_request": "/a",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 160.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "entity_id": "10.0.0.5",
            "source_file": "acme_wazuh.json", "source_position": 11,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 404.0, "http_method": "GET", "web_request": "/b",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 900.0, "detector_source": "wazuh",
            "name": "Web server 400 error", "host": "intranet-server",
            "entity_id": "10.0.0.5",
            "source_file": "acme_wazuh.json", "source_position": 40,
            "rule_id": "31101", "severity": 5.0, "alert_category": "",
            "http_status": 400.0, "http_method": "GET", "web_request": "/c",
            "technique_ids": "T1595", "tactics": ("Reconnaissance",),
        },
        {
            "timestamp": 500.0, "detector_source": "suricata",
            "name": "ET SCAN probe", "host": "intranet-server",
            "entity_id": "10.0.0.5",
            "source_file": "acme_suricata.json", "source_position": 3,
            "rule_id": "2001", "severity": 2.0, "alert_category": "recon",
            "http_status": float("nan"), "http_method": "", "web_request": "",
            "technique_ids": "", "tactics": (),
        },
    ])


def make_families() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "day": 0, "entity_id": "10.0.0.5", "detector_source": "wazuh",
            "rule_id": "31101", "ranking_score": 0.9,
            "evidence_probability": 0.8, "start": 100.0, "end": 900.0,
            "family_span_s": 800.0, "representative_session_id": "acme#0",
            "alert_rows": [0, 1, 2], "alert_count": 3, "n_child_sessions": 2,
            "child_session_ids": ["acme#0", "acme#1"], "child_score_max": 0.9,
            "detectors_nearby_10m": 2.0, "technique_count": 1,
            "technique_id_set": frozenset({"T1595"}), "family_positive": True,
            "asset_roles": ("intranet", "servers"), "scenario": "acme",
            "criticality": "unset", "family_id": "acme#0#10.0.0.5#wazuh#31101",
        },
        {
            "day": 0, "entity_id": "10.0.0.5", "detector_source": "suricata",
            "rule_id": "2001", "ranking_score": 0.4,
            "evidence_probability": 0.3, "start": 500.0, "end": 500.0,
            "family_span_s": 0.0, "representative_session_id": "acme#2",
            "alert_rows": [3], "alert_count": 1, "n_child_sessions": 1,
            "child_session_ids": ["acme#2"], "child_score_max": 0.4,
            "detectors_nearby_10m": 2.0, "technique_count": 0,
            "technique_id_set": frozenset(), "family_positive": False,
            "asset_roles": (), "scenario": "acme", "criticality": "unset",
            "family_id": "acme#0#10.0.0.5#suricata#2001",
        },
    ])


def make_sessions() -> pd.DataFrame:
    return pd.DataFrame([
        {"session_id": "acme#0", "start": 100.0, "end": 160.0,
         "duration_s": 60.0, "size": 2, "ranking_score": 0.9,
         "detector_source": "wazuh", "rule_id": "31101", "alert_rows": [0, 1]},
        {"session_id": "acme#1", "start": 900.0, "end": 900.0,
         "duration_s": 0.0, "size": 1, "ranking_score": 0.7,
         "detector_source": "wazuh", "rule_id": "31101", "alert_rows": [2]},
        {"session_id": "acme#2", "start": 500.0, "end": 500.0,
         "duration_s": 0.0, "size": 1, "ranking_score": 0.4,
         "detector_source": "suricata", "rule_id": "2001", "alert_rows": [3]},
    ])


def make_run(
    runs: Path | None = None,
    run_id: str = "acme-1",
    *,
    alerts: pd.DataFrame | None = None,
    families: pd.DataFrame | None = None,
    budget: int = 2,
) -> Path:
    runs = Path(tempfile.mkdtemp()) if runs is None else runs
    alerts = make_alerts() if alerts is None else alerts
    families = make_families() if families is None else families
    decorated = cli.decorate_families(families, alerts, budget=budget)
    cli.save_run(
        runs, run_id, {"company": "acme", "budget": budget},
        decorated, make_sessions(), alerts,
    )
    return runs


def squashed(text: str) -> str:
    return re.sub(r"\s+", "", text)


def write_records(path: Path, *records: dict, bom: bool = False) -> Path:
    body = "".join(json.dumps(record) + "\n" for record in records)
    path.write_text("﻿" + body if bom else body, encoding="utf-8")
    return path


def write_inventory(path: Path, assets: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"company": "acme", "assets": assets}), encoding="utf-8"
    )
    return path


def write_company_inventory(
    path: Path, *assets: tuple[str, str, tuple[str, ...]]
) -> Path:
    config = {
        "company": "demo",
        "assets": [
            {"hostname": hostname, "ip_addresses": [ip], "groups": list(groups)}
            for hostname, ip, groups in assets
        ],
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def wazuh_record(
    timestamp: str = "2022-01-21T00:02:27.000000Z",
    *,
    rule_id: str = "52507",
    level: int = 3,
    description: str = "ClamAV database update",
    groups: tuple[str, ...] = ("clamd", "virus"),
    agent_ip: str = "172.19.130.4",
    agent_name: str = "wazuh-client",
    hostname: str = "mail",
    timestamp_key: str = "@timestamp",
) -> dict:
    return {
        "predecoder": {"hostname": hostname, "program_name": "freshclam"},
        "agent": {"ip": agent_ip, "name": agent_name, "id": "19"},
        "manager": {"name": "wazuh.manager"},
        "rule": {
            "level": level, "description": description,
            "groups": list(groups), "id": rule_id,
        },
        "decoder": {"name": "freshclam"},
        "data": {},
        timestamp_key: timestamp,
    }


def eve_alert_record(signature: str = "ET SCAN Nmap Scripting Engine") -> dict:
    return {
        "timestamp": "2022-01-21T00:20:00.123456+0000",
        "flow_id": 1741725479112999,
        "event_type": "alert",
        "src_ip": "10.0.0.9",
        "src_port": 44321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature_id": 2009582,
            "signature": signature,
            "category": "Attempted Information Leak",
            "severity": 2,
        },
    }


def aminer_export_record() -> dict:
    return {
        "AnalysisComponent": {
            "AnalysisComponentType": "NewMatchPathDetector",
            "AnalysisComponentName": "AMiner: New event type.",
            "TrainingMode": True,
            "AffectedLogAtomPaths": ["/model", "/model/time"],
        },
        "LogData": {
            "RawLogData": ["Jan 21 00:00:01 cloud-share CRON[4388]: session opened"],
            "Timestamps": [1642723201],
            "LogLinesCount": 1,
            "LogResources": ["/var/log/auth.log"],
        },
        "AMiner": {"ID": "172.19.130.106"},
    }


def client_directory(days: int = 3, per_day: int = 12) -> Path:
    # one host, two rules, alerts spread far enough apart to close sessions
    directory = Path(tempfile.mkdtemp())
    write_records(directory / "acme_wazuh.json", *[
        wazuh_record(
            f"2022-01-{21 + day:02d}T{n // 6:02d}:{(n * 5) % 60:02d}:00Z",
            rule_id="5710" if n % 2 else "31101", level=5,
            description="sshd auth failure", groups=("syslog", "sshd"),
            agent_ip="10.0.0.9", agent_name="collector", hostname="web01",
        )
        for day in range(days)
        for n in range(per_day)
    ])
    write_inventory(
        directory / "inventory" / "acme.json",
        [{"hostname": "web01", "ip_addresses": ["10.0.0.9"],
          "roles": ["server", "internet_facing"]}],
    )
    return directory


def tiny_bundle(path: Path) -> Path:
    from sklearn.ensemble import RandomForestClassifier

    forest = RandomForestClassifier(n_estimators=2, random_state=0).fit(
        pd.DataFrame({"a": np.arange(20.0), "b": np.zeros(20)}),
        np.array([0, 1] * 10),
    )
    save_model(forest, path)
    return path


class Triaged(NamedTuple):
    run: cli.RunState
    printed: str


@functools.cache
def triage_client(criticality: str = "", mappings: Path | None = None) -> Triaged:
    # triage is the slow step, so the same input is scored once for the suite
    directory = client_directory()
    if criticality:
        write_inventory(
            directory / "inventory" / "acme.json",
            [{"hostname": "web01", "ip_addresses": ["10.0.0.9"],
              "roles": ["server", "internet_facing"], "criticality": criticality}],
        )
    runs = Path(tempfile.mkdtemp())
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(io.StringIO()):
        cli.cmd_triage(argparse.Namespace(
            model=SHIPPED_BUNDLE, input=directory, company="acme",
            inventory=directory / "inventory" / "acme.json",
            wazuh_file=None, aminer_file=None, attack_mappings=mappings, budget=2, runs_dir=runs,
        ))
    return Triaged(cli.load_run(runs), printed.getvalue())


class CliResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def run_cli(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CliResult:
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        if env:
            stack.enter_context(mock.patch.dict(os.environ, env))
        if cwd is not None:
            previous = os.getcwd()
            os.chdir(cwd)
            stack.callback(os.chdir, previous)
        try:
            cli.main(list(arguments))
        except SystemExit as stop:
            code = stop.code if isinstance(stop.code, int) else int(stop.code is not None)
    return CliResult(code, out.getvalue(), err.getvalue())
