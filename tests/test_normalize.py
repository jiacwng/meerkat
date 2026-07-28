# reading detector exports: which file is which, and what a record becomes

from __future__ import annotations

import importlib
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import event_labels, normalize
from core.normalize import (
    AMINER_FAMILY,
    SNIFF_LINES,
    SURICATA_FAMILY,
    WAZUH_FAMILY,
    resolve_alert_files,
    sniff_alert_family,
)

try:
    inventory = importlib.import_module("core.inventory")
except ModuleNotFoundError:
    inventory = None


def aminer_record(ip: str, raw: str, timestamp: float = 1.0) -> dict:
    return {
        "AnalysisComponent": {"AnalysisComponentName": "AMiner: test"},
        "LogData": {"RawLogData": [raw], "Timestamps": [timestamp]},
        "AMiner": {"ID": ip},
        "detector_source": "aminer",
    }


def company_inventory(*assets: tuple[str, str, tuple[str, ...]]) -> inventory.Inventory:
    assets_by_ip = {}
    ip_by_hostname = {}
    for hostname, ip, groups in assets:
        asset = inventory.Asset(hostname, (ip,), groups)
        assets_by_ip[ip] = asset
        ip_by_hostname[hostname.casefold()] = ip
    return inventory.Inventory("demo", assets_by_ip, ip_by_hostname)


def write_company_inventory(
    path: Path,
    *assets: tuple[str, str, tuple[str, ...]],
) -> Path:
    config = {
        "company": "demo",
        "assets": [
            {
                "hostname": hostname,
                "ip_addresses": [ip],
                "groups": list(groups),
            }
            for hostname, ip, groups in assets
        ],
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


class InventoryTests(unittest.TestCase):
    def test_loader_excludes_attacker_assets(self):
        # the AIT testbed lists the attacker machine in the same inventory, and
        # scoring it would teach the forest to rank the attack host itself
        self.assertIsNotNone(inventory)
        config = {
            "company": "demo",
            "assets": [
                {
                    "hostname": "server-a",
                    "ip_addresses": ["10.0.0.1"],
                    "groups": ["servers"],
                },
                {
                    "hostname": "attacker-0",
                    "ip_addresses": ["192.0.2.10"],
                    "groups": ["attacker"],
                },
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "company.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = inventory.load_inventory(path)

        self.assertIn("10.0.0.1", loaded)
        self.assertEqual(loaded.ip_by_hostname["server-a"], "10.0.0.1")
        self.assertNotIn("192.0.2.10", loaded)
        self.assertNotIn("attacker-0", loaded.ip_by_hostname)

    def test_loader_requires_an_inventory_file(self):
        # asset role is the largest feature block, so a missing inventory stops
        # the run rather than quietly scoring every host as roleless
        self.assertIsNotNone(inventory)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"

            with self.assertRaises(FileNotFoundError):
                inventory.load_inventory(path)

    @unittest.skipUnless(
        importlib.util.find_spec("yaml"),
        "AIT importer requires PyYAML",
    )
    def test_ait_importer_writes_runtime_json_without_attacker(self):
        # the testbed YAML is converted once into the runtime JSON, so the
        # attacker filter has to survive that conversion too
        source = (
            "server_a:\n"
            "  hostname: server-a\n"
            "  groups:\n"
            "    - servers\n"
            "  ipv4_addresses:\n"
            "    - 10.0.0.1\n"
            "attacker_0:\n"
            "  hostname: attacker-0\n"
            "  groups:\n"
            "    - attacker\n"
            "  ipv4_addresses:\n"
            "    - 192.0.2.10\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yaml_path = root / "demo.yaml"
            json_path = root / "demo.json"
            yaml_path.write_text(source, encoding="utf-8")

            inventory.import_ait_inventory(yaml_path, json_path)
            loaded = inventory.load_inventory(json_path)

        self.assertEqual(loaded.company, "demo")
        self.assertIn("10.0.0.1", loaded)
        self.assertNotIn("192.0.2.10", loaded)


class EntityAttributionTests(unittest.TestCase):
    def test_wazuh_separates_observer_and_entity(self):
        # the agent name describes the collector, so host comes from
        # predecoder.hostname and entity_id stays the address sessions key on
        record = {
            "rule": {"description": "Login failed", "level": 8},
            "predecoder": {"hostname": "server-a"},
            "agent": {"ip": "10.0.0.1", "name": "wazuh-client"},
        }
        assets = company_inventory(("config-name", "10.0.0.1", ("servers",)))

        fields = normalize.extract_wazuh_fields(record, assets)

        self.assertEqual(fields.host, "server-a")
        self.assertEqual(fields.entity_id, "10.0.0.1")
        self.assertEqual(fields.observer_id, "10.0.0.1")
        self.assertTrue(fields.entity_in_inventory)

    def test_suricata_known_destination_wins(self):
        # both endpoints are managed here, and taking the destination puts the
        # session on the machine being attacked
        record = {
            "data": {
                "alert": {"signature": "Lateral alert", "severity": 2},
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
            },
            "agent": {"ip": "10.0.0.254", "name": "gateway"},
        }
        assets = company_inventory(
            ("source", "10.0.0.1", ("servers",)),
            ("destination", "10.0.0.2", ("servers",)),
        )

        fields = normalize.extract_suricata_fields(record, assets)

        self.assertEqual(fields.entity_id, "10.0.0.2")
        self.assertEqual(fields.observer_id, "10.0.0.254")
        self.assertTrue(fields.entity_in_inventory)

    def test_suricata_known_source_wins_over_external_destination(self):
        # outbound traffic to an unmanaged address still has to attach to the
        # managed source, or every exfil alert lands on an entity nobody owns
        record = {
            "data": {
                "alert": {"signature": "Outbound alert", "severity": 2},
                "src_ip": "10.0.0.1",
                "dest_ip": "198.51.100.8",
            },
            "agent": {"ip": "10.0.0.254", "name": "gateway"},
        }
        assets = company_inventory(("source", "10.0.0.1", ("servers",)))

        fields = normalize.extract_suricata_fields(record, assets)

        self.assertEqual(fields.entity_id, "10.0.0.1")
        self.assertTrue(fields.entity_in_inventory)

    def test_suricata_unknown_endpoints_use_destination(self):
        # neither endpoint is in the inventory, so the destination is still a
        # stable key and entity_in_inventory stays False for the features
        record = {
            "data": {
                "alert": {"signature": "Unknown alert", "severity": 2},
                "src_ip": "198.51.100.8",
                "dest_ip": "203.0.113.9",
            },
            "agent": {"ip": "10.0.0.254", "name": "gateway"},
        }
        assets = company_inventory()

        fields = normalize.extract_suricata_fields(record, assets)

        self.assertEqual(fields.entity_id, "203.0.113.9")
        self.assertFalse(fields.entity_in_inventory)

    def test_aminer_forwarded_log_uses_source_entity(self):
        # logstash forwards other machines' logs to one AMiner box, so the
        # /var/log/logstash/<host>/ path decides which host owns the anomaly
        record = aminer_record(
            "10.143.0.35",
            json.dumps({"host": {"name": "intranet-server"}}),
        )
        record["LogData"]["LogResources"] = [
            "/var/log/logstash/intranet-server/system.cpu.log"
        ]
        assets = company_inventory(
            ("monitoring", "10.143.0.35", ("servers",)),
            ("intranet-server", "10.143.2.4", ("servers",)),
        )

        fields = normalize.extract_aminer_fields(record, assets)

        self.assertEqual(fields.host, "intranet-server")
        self.assertEqual(fields.entity_id, "10.143.2.4")
        self.assertEqual(fields.observer_id, "10.143.0.35")
        self.assertTrue(fields.entity_in_inventory)

    def test_aminer_syslog_hostname_does_not_change_entity(self):
        # an id that already names a machine is kept, whatever the log line says
        record = aminer_record(
            "192.168.98.239",
            "Jan 19 02:45:26 walker-mail dhclient[408]: DHCPREQUEST",
        )
        record["LogData"]["LogResources"] = ["/var/log/auth.log"]
        assets = company_inventory(
            ("walker-mail", "192.168.99.0", ("ext_mail",)),
            ("smith-mail", "192.168.98.239", ("ext_mail",)),
        )

        fields = normalize.extract_aminer_fields(record, assets)

        self.assertEqual(fields.host, "walker-mail")
        self.assertEqual(fields.entity_id, "192.168.98.239")
        self.assertEqual(fields.observer_id, "192.168.98.239")

    def test_a_central_miner_takes_the_host_from_the_log_line(self):
        # without this the whole estate groups onto one entity
        record = aminer_record(
            "aminer-collector-1",
            '{"host": {"name": "web01"}, "message": "sshd auth failure"}',
        )
        record["LogData"]["LogResources"] = ["/var/log/auth.log"]
        assets = company_inventory(("web01", "10.0.0.7", ("server",)))

        fields = normalize.extract_aminer_fields(record, assets)

        self.assertEqual(fields.entity_id, "10.0.0.7")
        self.assertEqual(fields.observer_id, "aminer-collector-1")

    def test_a_log_line_naming_nothing_leaves_the_miner_id_alone(self):
        # the fallback is for recovering a host, not for inventing one
        record = aminer_record(
            "aminer-collector-1", '{"host": {"name": "not-in-inventory"}}'
        )
        record["LogData"]["LogResources"] = ["/var/log/auth.log"]
        assets = company_inventory(("web01", "10.0.0.7", ("server",)))

        fields = normalize.extract_aminer_fields(record, assets)

        self.assertEqual(fields.entity_id, "aminer-collector-1")


class ReaderRegistryTests(unittest.TestCase):
    def test_an_unknown_detector_is_named_rather_than_read_as_aminer(self):
        # this used to raise KeyError: 'AMiner' for a detector nobody configured
        record = {"timestamp": 1.0, "host": "web01", "anomaly": "new user agent"}
        with self.assertRaises(ValueError) as caught:
            normalize.normalize_record(
                record, "loglizer", [], inventory.Inventory("acme", {}, {})
            )
        message = str(caught.exception)
        self.assertIn("loglizer", message)
        self.assertIn("wazuh", message)

    def test_every_detector_the_classifiers_emit_has_a_reader(self):
        # the classifiers emit these names, so the table has to match them
        self.assertEqual(
            set(normalize.READERS), {"wazuh", "suricata", "aminer"}
        )


class NativeMappingTests(unittest.TestCase):
    def test_wazuh_native_technique_ids_are_preserved(self):
        # rule.mitre.id arrives as a list and travels as a semicolon string,
        # since the mapping layer needs the native ids to fall back on
        record = {
            "rule": {
                "description": "Authentication failed",
                "level": 8,
                "mitre": {"id": ["T1110", "T1078"]},
            },
            "predecoder": {"hostname": "server-a"},
            "agent": {"name": "wazuh-client"},
        }

        fields = normalize.extract_wazuh_fields(record, company_inventory())

        self.assertEqual(fields.native_technique_ids, "T1110;T1078")


class RawScenarioTests(unittest.TestCase):
    def test_wazuh_preserves_privilege_evidence(self):
        # alice becoming root with a command and a working directory is what
        # the Process / System panel shows, so all five fields are carried
        record = {
            "rule": {"description": "Successful sudo", "level": 8},
            "data": {
                "srcuser": "alice",
                "dstuser": "root",
                "command": "id",
                "pwd": "/srv/app",
                "audit": {"exe": "/usr/bin/sudo"},
            },
            "predecoder": {"hostname": "server-a"},
            "agent": {"name": "server-a"},
        }


        fields = normalize.extract_wazuh_fields(record, company_inventory())

        self.assertEqual(fields.source_user, "alice")
        self.assertEqual(fields.target_user, "root")
        self.assertEqual(fields.command, "id")
        self.assertEqual(fields.executable, "/usr/bin/sudo")
        self.assertEqual(fields.working_directory, "/srv/app")

    def test_wazuh_preserves_detector_taxonomy_and_network_evidence(self):
        # rule_groups feeds the re-ranker's rule_group_count, and a numeric
        # data.id on a web rule is really the status, so 404 is an http_status
        record = {
            "rule": {
                "description": "Web request",
                "level": 5,
                "groups": ["web", "accesslog"],
                "firedtimes": 7,
            },
            "data": {
                "srcip": "10.0.0.8",
                "dstip": "10.0.0.9",
                "srcport": "49152",
                "dstport": "443",
                "protocol": "tcp",
                "id": "404",
            },
            "agent": {"ip": "10.0.0.9", "name": "wazuh-client"},
        }

        fields = normalize.extract_wazuh_fields(record, company_inventory())

        self.assertEqual(fields.entity_id, "10.0.0.9")
        self.assertEqual(fields.source_ip, "10.0.0.8")
        self.assertEqual(fields.destination_ip, "10.0.0.9")
        self.assertEqual(fields.destination_port, 443.0)
        self.assertEqual(fields.network_protocol, "tcp")
        self.assertEqual(fields.http_status, 404.0)
        self.assertEqual(fields.rule_groups, "web;accesslog")
        self.assertEqual(fields.rule_fired_times, 7.0)

    def test_wazuh_keeps_non_http_native_event_id(self):
        # apache writes AH01630 into that same data.id field, so a non-numeric
        # id stays a native event id and http_status is left missing
        record = {
            "rule": {"description": "Apache denied request", "level": 5},
            "data": {"id": "AH01630"},
            "agent": {"ip": "10.0.0.9", "name": "wazuh-client"},
        }

        fields = normalize.extract_wazuh_fields(record, company_inventory())

        self.assertEqual(fields.native_event_id, "AH01630")
        self.assertTrue(pd.isna(fields.http_status))

    def test_suricata_preserves_network_and_http_evidence(self):
        # the Network and Network / HTTP panels read normalized names, so a
        # suricata alert has to unpack its nested data.flow and data.http
        record = {
            "data": {
                "alert": {
                    "signature": "HTTP alert",
                    "severity": 2,
                    "category": "Web Application Attack",
                },
                "src_ip": "198.51.100.8",
                "dest_ip": "10.0.0.9",
                "src_port": 49152,
                "dest_port": 443,
                "proto": "TCP",
                "app_proto": "http",
                "flow": {
                    "bytes_toserver": 1200,
                    "bytes_toclient": 300,
                    "pkts_toserver": 8,
                    "pkts_toclient": 4,
                },
                "http": {
                    "url": "/admin?command=id",
                    "http_method": "GET",
                    "status": 200,
                    "hostname": "app.example",
                },
            },
            "agent": {"name": "gateway"},
        }

        fields = normalize.extract_suricata_fields(
            record,
            company_inventory(("webserver", "10.0.0.9", ("servers",))),
        )

        self.assertEqual(fields.entity_id, "10.0.0.9")
        self.assertEqual(fields.host, "webserver")
        self.assertEqual(fields.source_ip, "198.51.100.8")
        self.assertEqual(fields.destination_ip, "10.0.0.9")
        self.assertEqual(fields.alert_category, "Web Application Attack")
        self.assertEqual(fields.flow_bytes_to_server, 1200.0)
        self.assertEqual(fields.web_request, "/admin?command=id")
        self.assertEqual(fields.http_method, "GET")
        self.assertEqual(fields.http_status, 200.0)

    def test_suricata_uses_known_source_when_destination_is_not_managed(self):
        # the entity choice also picks the host label, so an outbound alert
        # reads as webserver rather than the external address it reached
        record = {
            "data": {
                "alert": {"signature": "Outbound alert", "severity": 2},
                "src_ip": "10.0.0.9",
                "dest_ip": "198.51.100.8",
            },
            "agent": {"name": "gateway"},
        }

        fields = normalize.extract_suricata_fields(
            record,
            company_inventory(("webserver", "10.0.0.9", ("servers",))),
        )

        self.assertEqual(fields.entity_id, "10.0.0.9")
        self.assertEqual(fields.host, "webserver")

    def test_aminer_preserves_affected_web_request(self):
        # AMiner reports the anomalous value under AffectedLogAtomValues, and
        # /model/fm/request/request is where a suspicious URL turns up
        record = aminer_record("10.0.0.1", "apache access line")
        record["AnalysisComponent"].update({
            "AffectedLogAtomPaths": ["/model/fm/request/request"],
            "AffectedLogAtomValues": ["/shell.php?command=id%20-a"],
        })

        fields = normalize.extract_aminer_fields(record, company_inventory())

        self.assertEqual(fields.web_request, "/shell.php?command=id%20-a")

    def test_aminer_preserves_detector_state_and_log_structure(self):
        # an AMiner detection has no severity, so the threshold and critical
        # value are the only numbers saying how far off the model a line was
        record = aminer_record("10.0.0.1", "dns log line")
        record["AnalysisComponent"].update({
            "AnalysisComponentType": "EntropyDetector",
            "TrainingMode": True,
            "AffectedLogAtomPaths": ["/model/query/domain", "/model/query/type"],
            "CriticalValue": 0.02,
            "ProbabilityThreshold": 0.05,
        })
        record["LogData"].update({
            "LogResources": ["/var/log/dnsmasq.log"],
            "LogLinesCount": 3,
        })

        fields = normalize.extract_aminer_fields(record, company_inventory())

        self.assertEqual(fields.entity_id, "10.0.0.1")
        self.assertEqual(fields.analysis_component_type, "EntropyDetector")
        self.assertEqual(fields.training_mode, 1.0)
        self.assertEqual(
            fields.affected_log_paths,
            "/model/query/domain;/model/query/type",
        )
        self.assertEqual(fields.log_resource, "/var/log/dnsmasq.log")
        self.assertEqual(fields.log_lines_count, 3.0)
        self.assertEqual(fields.critical_value, 0.02)
        self.assertEqual(fields.probability_threshold, 0.05)

    def test_aminer_missing_training_state_remains_unknown(self):
        # TrainingMode absent stays NaN, since folding it to False would claim
        # the detector was live when nothing in the record said so
        fields = normalize.extract_aminer_fields(
            aminer_record("10.0.0.1", "plain log line"),
            company_inventory(),
        )

        self.assertTrue(pd.isna(fields.training_mode))

    def test_aminer_preserves_metricbeat_cpu_values_as_percentages(self):
        # metricbeat reports cpu as a 0-1 fraction and the panel prints a
        # percent, so the scale is fixed once here rather than in the renderer
        raw = json.dumps({
            "host": {"name": "server-a"},
            "system": {
                "cpu": {
                    "total": {"pct": 1.0},
                    "nice": {"pct": 0.9362},
                }
            },
        })

        fields = normalize.extract_aminer_fields(
            aminer_record("10.0.0.1", raw),
            company_inventory(),
        )

        self.assertEqual(fields.cpu_total_pct, 100.0)
        self.assertEqual(fields.cpu_nice_pct, 93.62)

    def test_aminer_preserves_sudo_evidence(self):
        # the sudo line is free text in RawLogData, so alice, root, /srv/app
        # and id are parsed out into the same fields a wazuh alert fills
        raw = (
            "Feb  8 08:36:54 server-a sudo: alice : TTY=pts/0 ; "
            "PWD=/srv/app ; USER=root ; COMMAND=id"
        )

        fields = normalize.extract_aminer_fields(
            aminer_record("10.0.0.1", raw),
            company_inventory(),
        )

        self.assertEqual(fields.source_user, "alice")
        self.assertEqual(fields.target_user, "root")
        self.assertEqual(fields.working_directory, "/srv/app")
        self.assertEqual(fields.command, "id")

    def test_aminer_preserves_su_user_change(self):
        # su reports the pair the other way round, so www-data is the source
        # and alice the target, matching how sudo fills those two fields
        raw = (
            "Jan 18 13:14:31 server-a su[28816]: "
            "Successful su for alice by www-data"
        )

        fields = normalize.extract_aminer_fields(
            aminer_record("10.0.0.1", raw),
            company_inventory(),
        )

        self.assertEqual(fields.source_user, "www-data")
        self.assertEqual(fields.target_user, "alice")

    def test_classifies_raw_wazuh_records(self):
        # the AIT wazuh file carries every suricata alert twice, decoded once
        # as json and once as snort, so the snort copy is dropped
        # every real wazuh record carries rule and agent, so a record without
        # them is not claimed: the extractor would only reach a KeyError, which
        # a user then reads as a traceback
        wazuh = {"decoder": {"name": "sshd"}, "data": {},
                 "rule": {"id": "1", "level": 5, "description": "d"},
                 "agent": {"name": "w", "ip": "10.0.0.1"}}
        suricata = {"decoder": {"name": "json"}, "data": {"alert": {}}}
        duplicate = {"decoder": {"name": "snort"}, "data": {"alert": {}}}

        self.assertEqual(normalize.classify_wazuh_record(wazuh), "wazuh")
        self.assertEqual(normalize.classify_wazuh_record(suricata), "suricata")
        self.assertEqual(normalize.classify_wazuh_record(duplicate), "")
        self.assertEqual(normalize.classify_wazuh_record({}), "")
        self.assertEqual(
            normalize.classify_wazuh_record({"rule": {"id": "1"}}), ""
        )

    def test_normalize_scenario_combines_raw_files_and_skips_duplicate(self):
        # source_file and source_position are how `meerkat inspect --raw` finds
        # a line again, so dropping the snort copy must not renumber the rest
        aminer = aminer_record(
            "10.0.0.1",
            "Jan 21 00:00:00 mail app: event",
            timestamp=1.0,
        )
        wazuh = {
            "@timestamp": "1970-01-01T00:00:02+00:00",
            "decoder": {"name": "sshd"},
            "data": {},
            "rule": {"description": "Login failed", "level": 8, "id": "1"},
            "predecoder": {"hostname": "mail"},
            "agent": {"name": "mail"},
        }
        suricata = {
            "@timestamp": "1970-01-01T00:00:03+00:00",
            "decoder": {"name": "json"},
            "data": {
                "alert": {
                    "signature": "Network scan",
                    "severity": 2,
                    "signature_id": 2,
                }
            },
            "agent": {"name": "gateway"},
        }
        duplicate = dict(suricata, decoder={"name": "snort"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\n", encoding="utf-8")
            (raw / "demo_aminer.json").write_text(
                json.dumps(aminer) + "\n",
                encoding="utf-8",
            )
            (raw / "demo_wazuh.json").write_text(
                "".join(json.dumps(record) + "\n" for record in [wazuh, suricata, duplicate]),
                encoding="utf-8",
            )
            inventory_path = write_company_inventory(
                root / "company.json",
                ("mail", "10.0.0.1", ("servers",)),
            )

            result = normalize.normalize_scenario(
                raw,
                labels,
                "demo",
                inventory_path,
            )

        self.assertEqual(list(result.columns), normalize.COLUMNS)
        self.assertEqual(list(result["detector_source"]), ["aminer", "wazuh", "suricata"])
        self.assertEqual(list(result["source_position"]), [0, 0, 1])
        self.assertEqual(
            list(result["source_file"]),
            ["demo_aminer.json", "demo_wazuh.json", "demo_wazuh.json"],
        )

    def test_normalize_scenario_runs_without_a_log_anomaly_miner(self):
        # most companies run no log anomaly miner, so a missing
        # demo_aminer.json costs coverage and still produces a scored table
        wazuh = {
            "@timestamp": "1970-01-01T00:00:02+00:00",
            "decoder": {"name": "sshd"},
            "data": {},
            "rule": {"description": "Login failed", "level": 8, "id": "1"},
            "predecoder": {"hostname": "mail"},
            "agent": {"name": "mail"},
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\n", encoding="utf-8")
            (raw / "demo_wazuh.json").write_text(
                json.dumps(wazuh) + "\n",
                encoding="utf-8",
            )
            inventory_path = write_company_inventory(
                root / "company.json",
                ("mail", "10.0.0.1", ("servers",)),
            )

            result = normalize.normalize_scenario(
                raw,
                labels,
                "demo",
                inventory_path,
            )

        self.assertEqual(list(result["detector_source"]), ["wazuh"])
        self.assertEqual(list(result["source_file"]), ["demo_wazuh.json"])

    def test_normalize_scenario_names_both_files_when_neither_is_present(self):
        # a typo in --company surfaces here first, so the error names both
        # filenames it looked for
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\n", encoding="utf-8")
            inventory_path = write_company_inventory(
                root / "company.json",
                ("mail", "10.0.0.1", ("servers",)),
            )

            with self.assertRaises(FileNotFoundError) as caught:
                normalize.normalize_scenario(raw, labels, "demo", inventory_path)

        message = str(caught.exception)
        self.assertIn("demo_wazuh.json", message)
        self.assertIn("demo_aminer.json", message)

    def test_normalize_scenario_resolves_wazuh_file_alert_from_agent_ip(self):
        # a web accesslog alert carries no predecoder hostname, so the agent ip
        # is resolved through the inventory and both detectors say server-a
        aminer = aminer_record(
            "10.0.0.1",
            "Jan 21 00:00:00 server-a app: event",
            timestamp=1.0,
        )
        wazuh = {
            "@timestamp": "1970-01-01T00:00:02+00:00",
            "decoder": {"name": "web-accesslog"},
            "data": {},
            "rule": {"description": "Web alert", "level": 5, "id": "1"},
            "agent": {"ip": "10.0.0.1", "name": "wazuh-client"},
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\n", encoding="utf-8")
            (raw / "demo_aminer.json").write_text(
                json.dumps(aminer) + "\n",
                encoding="utf-8",
            )
            (raw / "demo_wazuh.json").write_text(
                json.dumps(wazuh) + "\n",
                encoding="utf-8",
            )
            inventory_path = write_company_inventory(
                root / "company.json",
                ("server-a", "10.0.0.1", ("servers",)),
            )

            result = normalize.normalize_scenario(
                raw,
                labels,
                "demo",
                inventory_path,
            )

        self.assertEqual(list(result["host"]), ["server-a", "server-a"])

    def test_label_audit_rejects_shift_hidden_by_repeated_names(self):
        # labels attach to raw records by position, and a repeated alert name
        # lets a one-row shift pass the name check, so times are compared too
        first = {
            "@timestamp": "1970-01-01T00:00:01+00:00",
            "decoder": {"name": "sshd"},
            "rule": {"description": "Repeated alert", "level": 5, "id": "1"},
            "predecoder": {"hostname": "mail"},
            "agent": {"name": "mail"},
        }
        second = dict(first, **{"@timestamp": "1970-01-01T00:00:02+00:00"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            csv_dir = root / "csv"
            raw.mkdir()
            csv_dir.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\n", encoding="utf-8")
            (raw / "demo_aminer.json").write_text("", encoding="utf-8")
            (raw / "demo_wazuh.json").write_text(
                json.dumps(first) + "\n" + json.dumps(second) + "\n",
                encoding="utf-8",
            )
            (csv_dir / "demo_alerts.txt").write_text(
                "time,name,ip,host,short,time_label,event_label\n"
                "2,Wazuh: Repeated alert,10.0.0.1,mail,W-Test,false_positive,-\n"
                "1,Wazuh: Repeated alert,10.0.0.1,mail,W-Test,false_positive,-\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(AssertionError, "positional fields disagree"):
                event_labels.audit_scenario(raw, csv_dir, labels, "demo")

    def test_label_audit_rejects_unexplained_time_label_mismatch(self):
        # a mismatch within a second of a window edge is a rounding artefact,
        # so only one 40 s outside the 0-10 window counts as a disagreement
        record = {
            "@timestamp": "1970-01-01T00:00:50+00:00",
            "decoder": {"name": "sshd"},
            "rule": {"description": "Login", "level": 5, "id": "1"},
            "predecoder": {"hostname": "mail"},
            "agent": {"name": "mail"},
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            csv_dir = root / "csv"
            raw.mkdir()
            csv_dir.mkdir()
            labels = root / "labels.csv"
            labels.write_text("scenario,attack,start,end\ndemo,scan,0,10\n", encoding="utf-8")
            (raw / "demo_aminer.json").write_text("", encoding="utf-8")
            (raw / "demo_wazuh.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
            (csv_dir / "demo_alerts.txt").write_text(
                "time,name,ip,host,short,time_label,event_label\n"
                "50,Wazuh: Login,10.0.0.1,mail,W-Test,scan,-\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(AssertionError, "unexplained time labels"):
                event_labels.audit_scenario(raw, csv_dir, labels, "demo")


# Alert files are found by what is inside them, not by what they are called, so
# a company whose wazuh export is named alerts.json needs no override flag.


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
        path = write_records(raw_directory() / "whatever.json", aminer_export_record())
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
            "\n\n\n" + json.dumps(aminer_export_record()) + "\n", encoding="utf-8"
        )
        self.assertEqual(sniff_alert_family(path), AMINER_FAMILY)


class ConventionFirst(unittest.TestCase):
    def test_the_ait_naming_wins_over_the_rest_of_the_directory(self):
        # the demo and the benchmark read one company out of a directory holding
        # all eight, so nobody else's export can join the answer
        directory = raw_directory()
        write_records(directory / "acme_wazuh.json", wazuh_record())
        write_records(directory / "acme_aminer.json", aminer_export_record())
        write_records(directory / "othercorp_wazuh.json", wazuh_record())
        write_records(directory / "othercorp_aminer.json", aminer_export_record())
        files = resolve_alert_files(directory, "acme")
        self.assertEqual(
            [(path.name, family) for path, family in files],
            [("acme_aminer.json", AMINER_FAMILY), ("acme_wazuh.json", WAZUH_FAMILY)],
        )

    def test_an_explicit_path_beats_the_convention_and_the_sniffer(self):
        # an analyst who names a file has looked at it, so the flag wins over
        # both guesses even when a conventional file sits right there
        directory = raw_directory()
        write_records(directory / "acme_wazuh.json", wazuh_record())
        chosen = write_records(directory / "yesterday.json", wazuh_record())
        files = resolve_alert_files(directory, "acme", wazuh_path=chosen)
        self.assertEqual([path for path, _ in files], [chosen])


class SniffedDiscovery(unittest.TestCase):
    def test_a_wazuh_export_called_alerts_json_is_found(self):
        # alerts.json is what wazuh itself writes, and needing a flag for the
        # single most common filename in the product is the bug being fixed
        directory = raw_directory()
        exported = write_records(directory / "alerts.json", wazuh_record())
        files = resolve_alert_files(directory, "acme")
        # only files that are there come back, and every one of them is read
        self.assertEqual(files, [(exported, WAZUH_FAMILY)])

    def test_an_arbitrarily_named_aminer_export_is_found(self):
        # the miner's output is renamed as often as wazuh's, and a company
        # running only the miner has to resolve on its own
        directory = raw_directory()
        exported = write_records(directory / "aminer-out-2026-07-26.json", aminer_export_record())
        files = resolve_alert_files(directory, "acme")
        self.assertEqual(files, [(exported, AMINER_FAMILY)])

    def test_both_families_are_assigned_from_one_directory(self):
        # a company hands over one dump per detector with no shared naming, and
        # each has to be recognised however they are ordered on disk
        directory = raw_directory()
        siem = write_records(directory / "zzz-siem-dump.json", wazuh_record())
        miner = write_records(directory / "aaa-miner-dump.json", aminer_export_record())
        files = resolve_alert_files(directory, "acme")
        self.assertEqual(files, [(miner, AMINER_FAMILY), (siem, WAZUH_FAMILY)])

    def test_unreadable_files_are_skipped_rather_than_chosen(self):
        # the export usually arrives beside notes and configs, and one of those
        # being read as alerts would crash in the extractor, not here
        directory = raw_directory()
        (directory / "a-notes.json").write_text("not json\n", encoding="utf-8")
        (directory / "b-empty.json").write_text("", encoding="utf-8")
        write_records(directory / "c-config.json", {"company": "acme"})
        exported = write_records(directory / "d-alerts.json", wazuh_record())
        files = resolve_alert_files(directory, "acme")
        self.assertEqual([path for path, _ in files], [exported])

    def test_every_daily_archive_of_one_family_is_read(self):
        # a directory of dated exports is one file per day, and taking the first
        # by name dropped the rest of the week with no message at all
        directory = raw_directory()
        for day in ("03", "01", "02"):
            write_records(directory / f"alerts-2026-07-{day}.json", wazuh_record())
        files = resolve_alert_files(directory, "acme")
        self.assertEqual(
            [path.name for path, _ in files],
            [
                "alerts-2026-07-01.json",
                "alerts-2026-07-02.json",
                "alerts-2026-07-03.json",
            ],
        )
        self.assertEqual(resolve_alert_files(directory, "acme"), files)

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


# Suricata writes eve.json itself, without the wazuh envelope, and a client tree
# often holds one of those beside the wazuh export rather than instead of it.


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


def eve_other_records() -> list[dict]:
    # every eve line carries the object its event_type names
    return [
        {"timestamp": "2022-01-21T00:20:01.000000+0000", "event_type": kind, kind: {}}
        for kind in ("netflow", "dns", "stats", "tls", "flow")
    ]


class NativeSuricataExports(unittest.TestCase):
    def build(self, *files: tuple[str, list[dict]]) -> Path:
        root = Path(tempfile.mkdtemp())
        raw = root / "raw"
        raw.mkdir()
        for name, records in files:
            write_records(raw / name, *records)
        (root / "labels.csv").write_text(
            "scenario,attack,start,end\n", encoding="utf-8"
        )
        write_company_inventory(
            root / "company.json", ("mail", "10.0.0.1", ("servers",))
        )
        return raw

    def normalized(self, raw: Path) -> pd.DataFrame:
        root = raw.parent
        return normalize.normalize_scenario(
            raw, root / "labels.csv", "demo", root / "company.json"
        )

    def test_a_wazuh_export_and_an_eve_file_in_one_tree_are_both_read(self):
        # CAM-LDS ships both, and returning one file per detector read the wazuh
        # half and dropped the eve half with no message at all
        raw = self.build(
            ("alerts.json", [wazuh_record()]),
            ("eve.json", [eve_alert_record()]),
        )
        self.assertEqual(
            [family for _, family in resolve_alert_files(raw, "demo")],
            [SURICATA_FAMILY, WAZUH_FAMILY],
        )
        frame = self.normalized(raw)
        self.assertEqual(
            sorted(frame["source_file"].astype(str)), ["alerts.json", "eve.json"]
        )
        self.assertEqual(
            sorted(frame["detector_source"].astype(str)), ["suricata", "wazuh"]
        )

    def test_an_eve_file_on_its_own_reads_as_suricata(self):
        # a company running suricata without wazuh has no envelope anywhere, and
        # the severity scale is the detector's own 1-3 either way
        frame = self.normalized(self.build(("eve.json", [eve_alert_record()])))
        self.assertEqual(list(frame["detector_source"].astype(str)), ["suricata"])
        self.assertEqual(list(frame["name"]), ["ET SCAN Nmap Scripting Engine"])
        self.assertEqual(list(frame["severity"]), [2.0])
        self.assertEqual(list(frame["host"].astype(str)), ["mail"])

    def test_the_lines_that_are_not_alerts_are_skipped_rather_than_fatal(self):
        # eve.json holds every event type suricata emits, so most of the file is
        # flow and dns records that no reader can turn into an alert
        raw = self.build(
            ("eve.json", [*eve_other_records(), eve_alert_record(), *eve_other_records()])
        )
        frame = self.normalized(raw)
        self.assertEqual(list(frame["detector_source"].astype(str)), ["suricata"])
        # the skipped lines still count, so `inspect --raw` finds the line again
        self.assertEqual(list(frame["source_position"]), [5])

    def test_an_alert_wazuh_forwarded_from_eve_json_is_counted_once(self):
        # a wazuh agent tailing /var/log/suricata/eve.json sends on the alert the
        # file already holds, and its decoder writes the numbers back as strings
        alert = eve_alert_record()
        forwarded = {
            "timestamp": "2022-01-21T00:20:05.000000+0000",
            "rule": {"description": "Suricata alert", "level": 6},
            "agent": {"id": "001", "name": "inetfw", "ip": "10.0.0.254"},
            "location": "/var/log/suricata/eve.json",
            "data": {
                **{k: str(v) for k, v in alert.items() if k != "alert"},
                "alert": {k: str(v) for k, v in alert["alert"].items()},
            },
        }
        raw = self.build(
            ("alerts.json", [forwarded]),
            ("eve.json", [alert]),
        )
        frame = self.normalized(raw)
        # the copy kept is suricata's own, so the file it came from says eve.json
        self.assertEqual(list(frame["source_file"].astype(str)), ["eve.json"])

    def test_a_deeply_nested_file_does_not_stop_the_run(self):
        # json.loads raises RecursionError, not a decode error, and the sniffer
        # reads every json file in the directory before anything is ingested
        raw = self.build(("alerts.json", [wazuh_record()]))
        (raw / "deep.json").write_text("[" * 60000 + "]" * 60000, encoding="utf-8")
        self.assertEqual(sniff_alert_family(raw / "deep.json"), "")
        self.assertEqual(len(self.normalized(raw)), 1)

    def test_a_line_shaped_like_a_miner_record_is_skipped(self):
        # a concatenated export decides its family from the first lines, and the
        # miner reader trusted that instead of checking each record
        self.assertIsNone(normalize.read_family_record({"LogData": 1}, "aminer"))
        self.assertIsNone(
            normalize.read_family_record({"AnalysisComponent": {}}, "aminer")
        )

    def test_a_named_file_is_never_listed_twice(self):
        # its first line sniffed as a third family, so the file was read twice
        # and the positional label join moved with it
        raw = self.build(("demo_wazuh.json", [wazuh_record()]))
        (raw / "demo_wazuh.json").write_text(
            json.dumps({"event_type": "data", "data": {"x": 1}}) + "\n"
            + json.dumps(wazuh_record()) + "\n",
            encoding="utf-8",
        )
        resolved = resolve_alert_files(raw, "demo")
        self.assertEqual(len({path for path, _ in resolved}), len(resolved))

    def test_a_burst_keeps_its_copies_when_the_other_file_has_one(self):
        # suricata logs the same signature twice on a burst; a set-based dedup
        # let one copy in the first file erase every copy in the second
        alert = eve_alert_record()
        forwarded = {
            "timestamp": "2022-01-21T00:20:05.000000+0000",
            "rule": {"description": "Suricata alert", "level": 6},
            "agent": {"id": "001", "name": "inetfw", "ip": "10.0.0.254"},
            "data": {
                **{k: str(v) for k, v in alert.items() if k != "alert"},
                "alert": {k: str(v) for k, v in alert["alert"].items()},
            },
        }
        raw = self.build(
            ("eve.json", [alert]),
            ("alerts.json", [forwarded] * 9),
        )
        frame = self.normalized(raw)
        suricata = frame[frame["detector_source"].astype(str).eq("suricata")]
        self.assertEqual(len(suricata), 9)

    def test_a_hostile_signature_id_does_not_stop_the_ingest(self):
        # an alert field is attacker-influenced: "inf" overflowed int() and a
        # nested object was unhashable, and either took the whole run down
        raw = self.build(
            ("alerts.json", [wazuh_record()]),
            ("eve.json", [
                self.hostile_eve("inf"),
                self.hostile_eve({"nested": 1}),
                self.hostile_eve("1e400"),
                eve_alert_record(),
            ]),
        )
        frame = self.normalized(raw)
        detectors = frame["detector_source"].astype(str)
        self.assertEqual(int(detectors.eq("suricata").sum()), 4)
        self.assertEqual(int(detectors.eq("wazuh").sum()), 1)

    def hostile_eve(self, signature_id):
        record = eve_alert_record()
        record["alert"]["signature_id"] = signature_id
        return record

    def test_two_copies_inside_one_file_are_both_kept(self):
        # suricata does log the same signature twice on a burst, and russellmitchell
        # has 20 such lines, so a repeat within one file is not a duplicate
        raw = self.build(("eve.json", [eve_alert_record(), eve_alert_record()]))
        self.assertEqual(len(self.normalized(raw)), 2)

    def test_an_eve_file_beside_the_conventional_export_is_read(self):
        # the convention covers wazuh and the miner, so suricata's own file is
        # the one it says nothing about and it used to be dropped
        raw = self.build(
            ("demo_wazuh.json", [wazuh_record()]),
            ("eve.json", [eve_alert_record()]),
        )
        self.assertEqual(
            [(path.name, family) for path, family in resolve_alert_files(raw, "demo")],
            [("eve.json", SURICATA_FAMILY), ("demo_wazuh.json", WAZUH_FAMILY)],
        )

    def test_a_named_file_is_still_the_only_one_read(self):
        # --wazuh-file is how an analyst says "this export, not the directory",
        # so an eve.json sitting beside it must not be added to the answer
        raw = self.build(
            ("yesterday.json", [wazuh_record()]),
            ("eve.json", [eve_alert_record()]),
        )
        chosen = raw / "yesterday.json"
        self.assertEqual(
            resolve_alert_files(raw, "demo", wazuh_path=chosen),
            [(chosen, WAZUH_FAMILY)],
        )

    def test_a_named_miner_file_is_still_the_only_one_read(self):
        # the same for --aminer-file: naming one file replaces the search, and
        # the eve file next to it is not a second opinion
        raw = self.build(
            ("miner.json", [aminer_export_record()]),
            ("eve.json", [eve_alert_record()]),
        )
        chosen = raw / "miner.json"
        self.assertEqual(
            resolve_alert_files(raw, "demo", aminer_path=chosen),
            [(chosen, AMINER_FAMILY)],
        )


if __name__ == "__main__":
    unittest.main()
