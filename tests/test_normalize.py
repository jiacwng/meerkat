import importlib
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import event_labels, normalize

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


class NativeMappingTests(unittest.TestCase):
    def test_wazuh_native_technique_ids_are_preserved(self):
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
        record = {
            "rule": {"description": "Apache denied request", "level": 5},
            "data": {"id": "AH01630"},
            "agent": {"ip": "10.0.0.9", "name": "wazuh-client"},
        }

        fields = normalize.extract_wazuh_fields(record, company_inventory())

        self.assertEqual(fields.native_event_id, "AH01630")
        self.assertTrue(pd.isna(fields.http_status))

    def test_suricata_preserves_network_and_http_evidence(self):
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
        record = aminer_record("10.0.0.1", "apache access line")
        record["AnalysisComponent"].update({
            "AffectedLogAtomPaths": ["/model/fm/request/request"],
            "AffectedLogAtomValues": ["/shell.php?command=id%20-a"],
        })

        fields = normalize.extract_aminer_fields(record, company_inventory())

        self.assertEqual(fields.web_request, "/shell.php?command=id%20-a")

    def test_aminer_preserves_detector_state_and_log_structure(self):
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
        fields = normalize.extract_aminer_fields(
            aminer_record("10.0.0.1", "plain log line"),
            company_inventory(),
        )

        self.assertTrue(pd.isna(fields.training_mode))

    def test_aminer_preserves_metricbeat_cpu_values_as_percentages(self):
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
        wazuh = {"decoder": {"name": "sshd"}, "data": {}}
        suricata = {"decoder": {"name": "json"}, "data": {"alert": {}}}
        duplicate = {"decoder": {"name": "snort"}, "data": {"alert": {}}}

        self.assertEqual(normalize.classify_wazuh_record(wazuh), "wazuh")
        self.assertEqual(normalize.classify_wazuh_record(suricata), "suricata")
        self.assertEqual(normalize.classify_wazuh_record(duplicate), "")

    def test_normalize_scenario_combines_raw_files_and_skips_duplicate(self):
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

    def test_normalize_scenario_resolves_wazuh_file_alert_from_agent_ip(self):
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


if __name__ == "__main__":
    unittest.main()
