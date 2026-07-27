"""Check the AIT-ADS dataset layout before bench.train or bench.evaluate run.

Seven of the eight environments' alert files are gitignored, so a fresh clone
reaches bench.evaluate and gets a bare FileNotFoundError with nothing in it about
the 2.7 GB download it is missing. This module answers that first: what is here,
what is not, and the exact path each absent file needs.

Nothing here opens an alert file. The set is 2.7 GB and wilson_wazuh.json alone
is 673 MB, so existence and st_size are the whole check.

Public API:
    check_dataset(raw_dir, labels_path)  -> one ScenarioCheck per environment
    format_report(checks, labels_path)   -> the table, the summary, the guidance
    main(argv)                           -> exit code, 0 when all eight are usable
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from bench.evaluate import SCENARIOS
from core.normalize import (
    AMINER_FAMILY,
    SURICATA_FAMILY,
    WAZUH_FAMILY,
    load_attack_windows,
    resolve_alert_files,
)

ZENODO_RECORD = "8263181"
ZENODO_URL = "https://zenodo.org/records/8263181"
# bench/README.md quotes sizes in decimal MB, 673 MB for wilson_wazuh.json, so
# divide by 10**6 and not by 2**20 or the two disagree by seven percent
BYTES_PER_MB = 1_000_000

# the detector ceilings from bench/README.md. Losing the miner is not a dent in
# the coverage, it is a third of the attack windows, so the warning says so
WINDOWS_ALL_DETECTORS = 60
WINDOWS_WITHOUT_AMINER = 41
AMINER_ONLY_WINDOWS = WINDOWS_ALL_DETECTORS - WINDOWS_WITHOUT_AMINER

_COLUMNS = (
    f"{'environment':<18}{'wazuh':<9}{'size':<11}"
    f"{'aminer':<9}{'inventory':<11}{'windows':>7}"
)
_RULE = "-" * len(_COLUMNS)


@dataclass
class ScenarioCheck:
    scenario: str
    wazuh_path: Path
    wazuh_bytes: int | None
    aminer_path: Path
    aminer_bytes: int | None
    inventory_path: Path
    inventory_found: bool
    attack_windows: int

    @property
    def usable(self) -> bool:
        return (
            self.wazuh_bytes is not None
            and self.inventory_found
            and self.attack_windows > 0
        )

    @property
    def complete(self) -> bool:
        return self.usable and self.aminer_bytes is not None


def _file_bytes(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _resolve_pair(raw_dir: Path, scenario: str) -> tuple[Path, Path]:
    # resolve_alert_files is what decides which files the loader will accept, by
    # name first and by format second, so ask it instead of testing for
    # <scenario>_wazuh.json here and disagreeing with it later. Finding nothing
    # raises there, which for a check is the answer rather than a failure: fall
    # back to the two paths bench/README.md tells the reader to fill.
    default_wazuh = raw_dir / f"{scenario}_wazuh.json"
    default_aminer = raw_dir / f"{scenario}_aminer.json"
    try:
        resolved = resolve_alert_files(raw_dir, scenario)
    except FileNotFoundError:
        return default_wazuh, default_aminer
    # the table has one column per detector, so name the first file of each
    network = (WAZUH_FAMILY, SURICATA_FAMILY)
    return (
        next((p for p, f in resolved if f in network), default_wazuh),
        next((p for p, f in resolved if f == AMINER_FAMILY), default_aminer),
    )


def _count_windows(labels_path: Path, scenario: str) -> int:
    # a labels file that is absent, unreadable or not this csv all mean the same
    # thing to the caller: no windows for this environment
    try:
        return len(load_attack_windows(labels_path, scenario))
    except (OSError, KeyError, ValueError):
        return 0


def check_scenario(
    raw_dir: Path,
    labels_path: Path,
    scenario: str,
) -> ScenarioCheck:
    wazuh_path, aminer_path = _resolve_pair(raw_dir, scenario)
    inventory_path = raw_dir / "inventory" / f"{scenario}.json"
    return ScenarioCheck(
        scenario=scenario,
        wazuh_path=wazuh_path,
        wazuh_bytes=_file_bytes(wazuh_path),
        aminer_path=aminer_path,
        aminer_bytes=_file_bytes(aminer_path),
        inventory_path=inventory_path,
        inventory_found=inventory_path.is_file(),
        attack_windows=_count_windows(labels_path, scenario),
    )


def check_dataset(
    raw_dir: Path,
    labels_path: Path,
    scenarios: tuple[str, ...] = SCENARIOS,
) -> list[ScenarioCheck]:
    return [
        check_scenario(raw_dir, labels_path, scenario) for scenario in scenarios
    ]


def _table_row(check: ScenarioCheck) -> str:
    wazuh = "ok" if check.wazuh_bytes is not None else "MISSING"
    size = (
        f"{check.wazuh_bytes / BYTES_PER_MB:.1f} MB"
        if check.wazuh_bytes is not None else "-"
    )
    aminer = "ok" if check.aminer_bytes is not None else "WARN"
    inventory = "ok" if check.inventory_found else "MISSING"
    return (
        f"{check.scenario:<18}{wazuh:<9}{size:<11}"
        f"{aminer:<9}{inventory:<11}{check.attack_windows:>7}"
    )


def _summary_line(checks: list[ScenarioCheck]) -> str:
    total = len(checks)
    complete = sum(check.complete for check in checks)
    usable = sum(check.usable for check in checks)
    return (
        f"{complete} of {total} complete, "
        f"{usable - complete} usable without aminer, "
        f"{total - usable} missing required files"
    )


def _resolution_notes(checks: list[ScenarioCheck]) -> list[str]:
    # the loader falls back to picking an alert file by format, so the file it
    # would read is not always the one the layout names. Say which it is rather
    # than print "ok" against a neighbour's export.
    lines = []
    for check in checks:
        expected = f"{check.scenario}_wazuh.json"
        if check.wazuh_bytes is not None and check.wazuh_path.name != expected:
            lines.append(
                f"NOTE    {check.scenario} would load "
                f"{check.wazuh_path.as_posix()}, not {expected}; the loader "
                f"picks by format when the conventional name is absent"
            )
    return lines


def _aminer_warning(checks: list[ScenarioCheck]) -> list[str]:
    # only environments that will actually run. One whose wazuh file is missing
    # too is already an error, and naming it here would read as the smaller
    # problem of a reduced ceiling instead of a missing download.
    absent = [
        check for check in checks
        if check.aminer_bytes is None and check.wazuh_bytes is not None
    ]
    if not absent:
        return []
    directory = absent[0].aminer_path.parent.as_posix()
    return [
        f"WARNING no aminer file for {len(absent)} of {len(checks)} "
        f"environments, and no error:",
        f"        {', '.join(check.scenario for check in absent)}",
        f"        expected at {directory}/<name>_aminer.json",
        f"        With all three detectors {WINDOWS_ALL_DETECTORS} of "
        f"{WINDOWS_ALL_DETECTORS} attack windows are reachable.",
        f"        Without the AMiner log-anomaly detector only "
        f"{WINDOWS_WITHOUT_AMINER} of {WINDOWS_ALL_DETECTORS}: the other "
        f"{AMINER_ONLY_WINDOWS}",
        "        windows are visible to AMiner alone and to no other detector.",
    ]


def _errors(checks: list[ScenarioCheck], labels_path: Path) -> list[str]:
    broken = [check for check in checks if not check.usable]
    if not broken:
        return []
    lines = [
        f"ERROR   {len(broken)} of {len(checks)} environments cannot be "
        f"evaluated. Missing, by target path:",
    ]
    for check in broken:
        if check.wazuh_bytes is None:
            lines.append(
                f"        {check.scenario:<16} wazuh and suricata alerts "
                f"-> {check.wazuh_path.as_posix()}"
            )
        if not check.inventory_found:
            lines.append(
                f"        {check.scenario:<16} asset inventory           "
                f"-> {check.inventory_path.as_posix()}"
            )
        if check.attack_windows == 0:
            lines.append(
                f"        {check.scenario:<16} no rows for "
                f"'{check.scenario}' in {labels_path.as_posix()}"
            )
    lines.extend([
        "",
        "The sixteen alert files are not in this repository. Download the AIT",
        f"Alert Data Set, Zenodo record {ZENODO_RECORD} ({ZENODO_URL}),",
        "and unpack each file to the path named above. The inventories and the",
        "labels csv are committed, so a missing one means the checkout rather",
        "than the download. Layout and exact file names: bench/README.md",
    ])
    return lines


def format_report(checks: list[ScenarioCheck], labels_path: Path) -> str:
    lines = [_COLUMNS, _RULE]
    lines.extend(_table_row(check) for check in checks)
    lines.extend([_RULE, _summary_line(checks)])
    for block in (
        _resolution_notes(checks),
        _aminer_warning(checks),
        _errors(checks, labels_path),
    ):
        if block:
            lines.append("")
            lines.extend(block)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the AIT-ADS dataset layout bench/ needs"
    )
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    args = parser.parse_args(argv)

    checks = check_dataset(args.raw_dir, args.labels)
    print(format_report(checks, args.labels))
    return 0 if all(check.usable for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
