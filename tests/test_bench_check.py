# What a reproduction script depends on before it spends an hour on 2.7 GB: which
# files bench.check calls required, what a missing one costs, and the exit code.

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bench.check import SCENARIOS, check_dataset, format_report, main

WAZUH_MB = 1.5


def alert_file(path: Path, megabytes: float = WAZUH_MB) -> None:
    # deliberately not json: nothing in bench.check may parse an alert file, and
    # truncate gives a realistic byte count without writing megabytes
    with path.open("wb") as fh:
        fh.write(b"this is not json, and bench.check must never parse it\n")
        fh.truncate(int(megabytes * 1_000_000))


def layout(
    *,
    skip_wazuh: tuple[str, ...] = (),
    skip_aminer: tuple[str, ...] = (),
    skip_inventory: tuple[str, ...] = (),
    skip_labels: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    root = Path(tempfile.mkdtemp())
    raw = root / "raw"
    (raw / "inventory").mkdir(parents=True)
    rows = ["scenario,attack,start,end"]
    for scenario in SCENARIOS:
        if scenario not in skip_wazuh:
            alert_file(raw / f"{scenario}_wazuh.json")
        if scenario not in skip_aminer:
            alert_file(raw / f"{scenario}_aminer.json", 0.2)
        if scenario not in skip_inventory:
            (raw / "inventory" / f"{scenario}.json").write_text(
                '{"assets": []}', encoding="utf-8"
            )
        if scenario not in skip_labels:
            rows.append(f"{scenario},network_scans,1642993260.0,1642996606.0")
    labels = root / "labels.csv"
    labels.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return raw, labels


def run(raw: Path, labels: Path) -> tuple[int, str]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(["--raw-dir", str(raw), "--labels", str(labels)])
    return code, stdout.getvalue()


class TestCompleteLayout(unittest.TestCase):
    def test_a_full_download_passes_and_gates_open(self):
        # the whole point of the module is that `check && train && evaluate`
        # proceeds when the eight environments are actually all there
        code, report = run(*layout())
        self.assertEqual(code, 0)
        self.assertIn(f"{len(SCENARIOS)} of {len(SCENARIOS)} complete", report)
        self.assertNotIn("ERROR", report)
        self.assertNotIn("MISSING", report)

    def test_every_environment_gets_its_own_row(self):
        # a summary count alone does not say which environment to fix, so the
        # eight names evaluate.SCENARIOS will ask for are each on a line
        _, report = run(*layout())
        for scenario in SCENARIOS:
            self.assertIn(scenario, report)


class TestMissingRequiredFiles(unittest.TestCase):
    def test_a_missing_wazuh_file_fails_the_gate(self):
        # this is the case a fresh clone hits, seven times over, and it has to
        # stop the reproduction rather than let evaluate score a short dataset
        code, report = run(*layout(skip_wazuh=("wilson",)))
        self.assertEqual(code, 1)
        self.assertIn("ERROR", report)
        self.assertIn("wilson_wazuh.json", report)

    def test_a_missing_wazuh_file_names_the_download_and_the_target_path(self):
        # a bare "file not found" is what this module exists to replace: the
        # reader needs the Zenodo record, the path to fill, and the layout doc
        _, report = run(*layout(skip_wazuh=("fox",)))
        self.assertIn("8263181", report)
        self.assertIn("raw/fox_wazuh.json", report.replace("\\", "/"))
        self.assertIn("bench/README.md", report)

    def test_a_missing_inventory_is_an_error_too(self):
        # inventories are committed, so load_inventories failing means a broken
        # checkout and not a missing download; both stop evaluate the same way
        code, report = run(*layout(skip_inventory=("shaw",)))
        self.assertEqual(code, 1)
        self.assertIn("asset inventory", report)
        self.assertIn("inventory/shaw.json", report.replace("\\", "/"))

    def test_an_environment_absent_from_labels_is_reported_by_name(self):
        # labels.csv drives every positive, so an environment with no rows
        # scores zero windows and would read as a ranking failure
        _, report = run(*layout(skip_labels=("santos",)))
        self.assertIn("no rows for 'santos'", report)
        self.assertIn("labels.csv", report)


class TestOptionalAminer(unittest.TestCase):
    def test_a_missing_aminer_file_warns_and_the_gate_stays_open(self):
        # the miner is optional per environment, so its absence must not block a
        # reproduction that is otherwise complete
        code, report = run(*layout(skip_aminer=("harrison",)))
        self.assertEqual(code, 0)
        self.assertIn("WARNING", report)
        self.assertIn("harrison", report)
        self.assertNotIn("ERROR", report)

    def test_the_aminer_warning_carries_the_coverage_it_costs(self):
        # "optional" understates it: dropping the miner moves the ceiling from
        # 60 to 41 windows, and a number no ranker can beat belongs in the warning
        _, report = run(*layout(skip_aminer=("wheeler",)))
        self.assertIn("60", report)
        self.assertIn("41", report)
        self.assertIn("19", report)

    def test_an_environment_missing_both_files_is_only_an_error(self):
        # a coverage warning next to a missing download reads as the smaller
        # problem, so the aminer warning covers runnable environments only
        code, report = run(*layout(
            skip_wazuh=("wilson",), skip_aminer=("wilson", "harrison"),
        ))
        warning = report.split("WARNING")[1].split("ERROR")[0]
        self.assertEqual(code, 1)
        self.assertIn("harrison", warning)
        self.assertNotIn("wilson", warning)


class TestAgreesWithTheLoader(unittest.TestCase):
    def test_a_file_the_loader_picks_by_format_is_named_in_the_report(self):
        # resolve_alert_files falls back to picking by format, so a differently
        # named export counts as found. Printing a bare "ok" would credit an
        # environment with a neighbour's file, so say which file will be read.
        root = Path(tempfile.mkdtemp())
        raw = root / "raw"
        (raw / "inventory").mkdir(parents=True)
        (raw / "siem-export.json").write_text(
            '{"rule": {"id": "1"}, "agent": {"ip": "10.0.0.1"}}\n',
            encoding="utf-8",
        )
        (raw / "inventory" / "fox.json").write_text(
            '{"assets": []}', encoding="utf-8"
        )
        labels = root / "labels.csv"
        labels.write_text(
            "scenario,attack,start,end\nfox,network_scans,1.0,2.0\n",
            encoding="utf-8",
        )
        checks = [
            check for check in check_dataset(raw, labels)
            if check.scenario == "fox"
        ]
        report = format_report(checks, labels)
        self.assertIn("siem-export.json", report)
        self.assertIn("fox_wazuh.json", report)


class TestNeverReadsAlerts(unittest.TestCase):
    def test_alert_contents_are_never_parsed(self):
        # wilson_wazuh.json is 673 MB and the set is 2.7 GB, so a check that
        # opened them would cost more than the run it guards
        raw, labels = layout()
        code, report = run(raw, labels)
        self.assertEqual(code, 0)
        self.assertIn(f"{WAZUH_MB} MB", report)

    def test_size_comes_from_stat_and_not_from_counting_records(self):
        # pins the same thing at the API rather than the report: the byte count
        # is the file's size, which no amount of unparseable content changes
        raw, labels = layout()
        checks = {check.scenario: check for check in check_dataset(raw, labels)}
        self.assertEqual(
            checks["fox"].wazuh_bytes,
            (raw / "fox_wazuh.json").stat().st_size,
        )

    def test_a_report_of_a_bare_directory_still_renders(self):
        # the first thing a reader runs is a check against nothing, so an empty
        # data/raw has to produce the guidance instead of a traceback
        root = Path(tempfile.mkdtemp())
        checks = check_dataset(root, root / "labels.csv")
        report = format_report(checks, root / "labels.csv")
        self.assertIn("ERROR", report)
        self.assertIn("8263181", report)


if __name__ == "__main__":
    unittest.main()
