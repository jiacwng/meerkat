# Alert files are found by what is inside them, not by what they are called, so
# a company whose wazuh export is named alerts.json needs no override flag.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import normalize
from core.normalize import (
    AMINER_FAMILY,
    SNIFF_LINES,
    WAZUH_FAMILY,
    resolve_alert_files,
    sniff_alert_family,
)


def wazuh_record() -> dict:
    return {
        "predecoder": {"hostname": "mail", "program_name": "freshclam"},
        "agent": {"ip": "172.19.130.4", "name": "wazuh-client", "id": "19"},
        "manager": {"name": "wazuh.manager"},
        "rule": {
            "level": 3,
            "description": "ClamAV database update",
            "groups": ["clamd", "virus"],
            "id": "52507",
        },
        "decoder": {"name": "freshclam"},
        "@timestamp": "2022-01-21T00:02:27.000000Z",
    }


def suricata_record() -> dict:
    return {
        "agent": {"ip": "10.143.0.103", "name": "wazuh-client", "id": "16"},
        "data": {
            "src_ip": "10.143.0.103",
            "dest_ip": "91.189.95.85",
            "proto": "TCP",
            "event_type": "alert",
            "alert": {
                "severity": "3",
                "signature_id": "2013504",
                "signature": "ET POLICY GNU/Linux APT User-Agent Outbound",
                "category": "Not Suspicious Traffic",
            },
        },
        "rule": {"level": 3, "description": "Suricata: Alert", "id": "86601"},
        "decoder": {"name": "json"},
        "@timestamp": "2022-01-21T00:14:21.351932Z",
    }


def aminer_record() -> dict:
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


def raw_directory() -> Path:
    return Path(tempfile.mkdtemp())


def write_records(path: Path, *records: dict) -> Path:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return path


class FormatSniffing(unittest.TestCase):
    def test_a_wazuh_export_is_known_by_its_rule_and_agent(self):
        # every record in the real 45MB export carries both, and neither appears
        # anywhere in an aminer record, so the pair is what separates the two
        path = write_records(raw_directory() / "alerts.json", wazuh_record())
        self.assertEqual(sniff_alert_family(path), WAZUH_FAMILY)

    def test_a_suricata_record_still_reads_as_the_wazuh_family(self):
        # wazuh forwards suricata alerts into its own file, so a file starting
        # with one is a wazuh-family export, not a third kind of file
        path = write_records(
            raw_directory() / "alerts.json", suricata_record(), wazuh_record()
        )
        self.assertEqual(sniff_alert_family(path), WAZUH_FAMILY)

    def test_a_bare_suricata_record_has_no_rule_to_go_on(self):
        # a suricata alert exported without the wazuh envelope keeps only
        # data.alert, and losing those records would silently drop the IDS half
        bare = {"data": suricata_record()["data"], "@timestamp": "2022-01-21T00:14:21Z"}
        path = write_records(raw_directory() / "ids.json", bare)
        self.assertEqual(sniff_alert_family(path), WAZUH_FAMILY)

    def test_an_aminer_export_is_known_by_its_analysis_component(self):
        # the miner names the detector that fired and the log it read; a wazuh
        # record has neither field
        path = write_records(raw_directory() / "whatever.json", aminer_record())
        self.assertEqual(sniff_alert_family(path), AMINER_FAMILY)

    def test_a_file_that_is_not_json_is_not_an_alert_file(self):
        # --input points at a working directory, so pdfs and csvs sit beside the
        # export and must not raise out of discovery
        directory = raw_directory()
        text = directory / "notes.json"
        text.write_text("this is not json at all\n", encoding="utf-8")
        empty = directory / "empty.json"
        empty.write_text("", encoding="utf-8")
        self.assertEqual(sniff_alert_family(text), "")
        self.assertEqual(sniff_alert_family(empty), "")

    def test_json_of_neither_family_is_not_an_alert_file(self):
        # an inventory or a config file parses fine and would otherwise be fed to
        # the wazuh extractor, which needs record["rule"] and would crash
        directory = raw_directory()
        config = write_records(
            directory / "inventory.json", {"company": "acme", "assets": []}
        )
        listy = directory / "array.json"
        listy.write_text("[1, 2, 3]\n", encoding="utf-8")
        self.assertEqual(sniff_alert_family(config), "")
        self.assertEqual(sniff_alert_family(listy), "")

    def test_only_the_first_handful_of_lines_is_read(self):
        # the demo wazuh file is 45MB; classifying by reading it would cost more
        # than normalizing it, so the budget is a few lines and it is a hard stop
        path = raw_directory() / "late.json"
        junk = "\n".join("not json" for _ in range(SNIFF_LINES))
        path.write_text(
            junk + "\n" + json.dumps(wazuh_record()) + "\n", encoding="utf-8"
        )
        self.assertEqual(sniff_alert_family(path), "")

    def test_blank_lines_do_not_spend_the_budget(self):
        # a hand-edited export often ends with, or is padded by, empty lines and
        # those are not records
        path = raw_directory() / "padded.json"
        path.write_text(
            "\n\n\n" + json.dumps(aminer_record()) + "\n", encoding="utf-8"
        )
        self.assertEqual(sniff_alert_family(path), AMINER_FAMILY)


class ConventionFirst(unittest.TestCase):
    def test_the_ait_naming_resolves_without_sniffing_anything(self):
        # the demo and the benchmark run on <company>_wazuh.json, and the
        # convention is tried first so their output cannot move
        directory = raw_directory()
        write_records(directory / "acme_wazuh.json", wazuh_record())
        write_records(directory / "acme_aminer.json", aminer_record())
        with mock.patch.object(normalize, "sniff_alert_family") as sniffer:
            wazuh, aminer = resolve_alert_files(directory, "acme")
        sniffer.assert_not_called()
        self.assertEqual(wazuh.name, "acme_wazuh.json")
        self.assertEqual(aminer.name, "acme_aminer.json")

    def test_an_explicit_path_beats_the_convention_and_the_sniffer(self):
        # an analyst who names a file has looked at it, so the flag wins over
        # both guesses even when a conventional file sits right there
        directory = raw_directory()
        write_records(directory / "acme_wazuh.json", wazuh_record())
        chosen = write_records(directory / "yesterday.json", wazuh_record())
        wazuh, _ = resolve_alert_files(directory, "acme", wazuh_path=chosen)
        self.assertEqual(wazuh, chosen)


class SniffedDiscovery(unittest.TestCase):
    def test_a_wazuh_export_called_alerts_json_is_found(self):
        # alerts.json is what wazuh itself writes, and needing a flag for the
        # single most common filename in the product is the bug being fixed
        directory = raw_directory()
        exported = write_records(directory / "alerts.json", wazuh_record())
        wazuh, aminer = resolve_alert_files(directory, "acme")
        self.assertEqual(wazuh, exported)
        # both paths come back whether or not they exist; callers test .exists()
        self.assertEqual(aminer, directory / "acme_aminer.json")
        self.assertFalse(aminer.exists())

    def test_an_arbitrarily_named_aminer_export_is_found(self):
        # the miner's output is renamed as often as wazuh's, and a company
        # running only the miner has to resolve on its own
        directory = raw_directory()
        exported = write_records(directory / "aminer-out-2026-07-26.json", aminer_record())
        wazuh, aminer = resolve_alert_files(directory, "acme")
        self.assertEqual(aminer, exported)
        self.assertFalse(wazuh.exists())

    def test_both_families_are_assigned_from_one_directory(self):
        # a company hands over one dump per detector with no shared naming, and
        # each has to land in the right slot however they are ordered on disk
        directory = raw_directory()
        siem = write_records(directory / "zzz-siem-dump.json", wazuh_record())
        miner = write_records(directory / "aaa-miner-dump.json", aminer_record())
        wazuh, aminer = resolve_alert_files(directory, "acme")
        self.assertEqual(wazuh, siem)
        self.assertEqual(aminer, miner)

    def test_unreadable_files_are_skipped_rather_than_chosen(self):
        # the export usually arrives beside notes and configs, and one of those
        # winning the wazuh slot would crash in the extractor, not here
        directory = raw_directory()
        (directory / "a-notes.json").write_text("not json\n", encoding="utf-8")
        (directory / "b-empty.json").write_text("", encoding="utf-8")
        write_records(directory / "c-config.json", {"company": "acme"})
        exported = write_records(directory / "d-alerts.json", wazuh_record())
        wazuh, _ = resolve_alert_files(directory, "acme")
        self.assertEqual(wazuh, exported)

    def test_daily_archives_of_one_family_pick_the_first_by_name(self):
        # a directory of dated exports is one file per day; first by name is the
        # earliest for a dated name and is the same choice on every run
        directory = raw_directory()
        for day in ("03", "01", "02"):
            write_records(directory / f"alerts-2026-07-{day}.json", wazuh_record())
        first, _ = resolve_alert_files(directory, "acme")
        second, _ = resolve_alert_files(directory, "acme")
        self.assertEqual(first.name, "alerts-2026-07-01.json")
        self.assertEqual(second, first)

    def test_a_directory_with_nothing_recognisable_lists_what_was_there(self):
        # wrong --input is the usual cause, so the error has to show the files it
        # did look at and the flag that overrides the search
        directory = raw_directory()
        (directory / "archive.json").write_text("not json\n", encoding="utf-8")
        write_records(directory / "inventory.json", {"company": "acme"})
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(directory, "acme")
        message = str(caught.exception)
        self.assertIn("archive.json", message)
        self.assertIn("inventory.json", message)
        self.assertIn("--wazuh-file", message)
        self.assertIn("--aminer-file", message)

    def test_a_directory_that_does_not_exist_says_there_are_no_files(self):
        # a typo in --input must not read as "the export is unreadable"
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(raw_directory() / "missing", "acme")
        self.assertIn("no json files", str(caught.exception))

    def test_a_named_file_that_is_not_there_is_reported_not_replaced(self):
        # sniffing would happily hand back alerts.json instead, and silently
        # normalizing a different file than the one asked for hides the typo
        directory = raw_directory()
        write_records(directory / "alerts.json", wazuh_record())
        with self.assertRaises(FileNotFoundError) as caught:
            resolve_alert_files(directory, "acme", wazuh_path=directory / "typo.json")
        self.assertIn("typo.json", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
