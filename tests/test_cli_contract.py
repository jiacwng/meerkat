# The parts of the CLI a script depends on: where alert files are found, which
# stream errors go to, and what the exit codes mean.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.normalize import resolve_alert_files
from meerkat.cli import EXIT_DECLINED, EXIT_ERROR, build_parser


def directory(*names: str) -> Path:
    made = Path(tempfile.mkdtemp())
    for name in names:
        (made / name).write_text("{}\n", encoding="utf-8")
    return made


class TestAlertFileDiscovery(unittest.TestCase):
    def test_the_ait_naming_still_works_with_no_flags(self):
        # every AIT company and the demo rely on <company>_wazuh.json, so
        # adding the override flags must not move the default path
        raw = directory("acme_wazuh.json", "acme_aminer.json")
        wazuh, aminer = resolve_alert_files(raw, "acme")
        self.assertEqual(wazuh.name, "acme_wazuh.json")
        self.assertEqual(aminer.name, "acme_aminer.json")

    def test_a_named_file_wins_over_the_convention(self):
        # a SIEM export is called whatever the SIEM called it, so a named file
        # is taken even with the conventional one in the same directory
        raw = directory("acme_wazuh.json")
        chosen = raw / "exported-alerts.json"
        chosen.write_text("{}\n", encoding="utf-8")
        wazuh, _ = resolve_alert_files(raw, "acme", wazuh_path=chosen)
        self.assertEqual(wazuh, chosen)

    def test_the_miner_alone_is_enough(self):
        # resolve_alert_files hands back both paths and lets the caller test
        # them, so a company running only the miner still resolves
        raw = directory("acme_aminer.json")
        wazuh, aminer = resolve_alert_files(raw, "acme")
        self.assertFalse(wazuh.exists())
        self.assertTrue(aminer.exists())

    def test_a_client_whose_export_is_named_differently_is_told_what_to_do(self):
        # the whole point: a real wazuh export is not called <company>_wazuh.json,
        # and the error has to name the files that ARE there and the flag to use
        raw = directory("alerts-2026-07-26.json", "archive.json")
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(raw, "acme")
        message = str(caught.exception)
        self.assertIn("alerts-2026-07-26.json", message)
        self.assertIn("--wazuh-file", message)

    def test_an_empty_directory_says_so_rather_than_listing_nothing(self):
        # an empty --input is usually the wrong directory, and a file list of
        # nothing would read as the files being there but unreadable
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(directory(), "acme")
        self.assertIn("no json files", str(caught.exception))


class TestExitCodes(unittest.TestCase):
    def test_a_declined_retrain_is_not_the_same_code_as_a_crash(self):
        # a wrapper script has to tell "the gate said no", which is the gate
        # working, apart from "the tool broke"
        self.assertNotEqual(EXIT_DECLINED, EXIT_ERROR)
        self.assertEqual(EXIT_ERROR, 1)
        self.assertEqual(EXIT_DECLINED, 3)


class TestParserContract(unittest.TestCase):
    def test_triage_finds_the_inventory_the_inventory_command_wrote(self):
        # --inventory parses as None so triage can fill in where `meerkat
        # inventory` wrote it, which needs --input and --company first
        args = build_parser().parse_args(["triage", "--company", "acme"])
        self.assertIsNone(args.inventory)

    def test_alert_file_overrides_reach_triage_and_retrain(self):
        # both commands normalize the same alert files, so the overrides are
        # attached to each rather than to triage alone
        parser = build_parser()
        triage = parser.parse_args([
            "triage", "--company", "acme", "--wazuh-file", "w.json",
        ])
        retrain = parser.parse_args([
            "retrain", "--company", "acme", "--incidents", "i.csv",
            "--inventory", "inv.json", "--aminer-file", "a.json",
        ])
        self.assertEqual(triage.wazuh_file, Path("w.json"))
        self.assertEqual(retrain.aminer_file, Path("a.json"))

    def test_the_bag_size_discount_defaults_to_one_per_ticket(self):
        # k=1 keeps every ticket's total weight at 1.0 whatever its width, and
        # five fits are what the majority gate counts
        args = build_parser().parse_args([
            "retrain", "--company", "acme", "--incidents", "i.csv",
            "--inventory", "inv.json",
        ])
        self.assertEqual(args.prior_k, 1.0)
        self.assertEqual(args.fits, 5)

    def test_the_read_commands_can_emit_json(self):
        # a wrapper script reads the queue and the run list, so both take
        # --json, and errors go to stderr to keep the pipe parseable
        parser = build_parser()
        self.assertTrue(parser.parse_args(["queue", "--json"]).json)
        self.assertTrue(parser.parse_args(["runs", "--json"]).json)

    def test_the_queue_can_leave_as_csv_for_a_ticketing_system(self):
        # a ticketing system imports csv more often than json, so csv is what
        # an analyst gets without having to think about the flag
        args = build_parser().parse_args(["export", "queue", "--format", "csv"])
        self.assertEqual(args.format, "csv")


if __name__ == "__main__":
    unittest.main()
