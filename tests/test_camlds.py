# converting a CAM-LDS scenario: which host gets which role, and where a window ends

from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from bench.camlds import (
    TAIL_SECONDS,
    Archive,
    ScenarioError,
    attack_windows,
    build_hosts,
    build_inventory,
    convert,
    read_attack_steps,
    scenario_timezone,
    step_name,
    write_attack_windows,
)
from core.inventory import load_inventory
from core.normalize import load_attack_windows, sniff_alert_family

SCENARIO_ENV = "MEERKAT_CAMLDS_SCENARIO"


def facts(hostname: str, address: str, gateway: str, network: str, extra=()) -> dict:
    return {
        "ansible_hostname": hostname,
        "ansible_all_ipv4_addresses": [address, *extra],
        "ansible_default_ipv4": {
            "address": address,
            "gateway": gateway,
            "network": network,
            "prefix": "24",
        },
        "ansible_date_time": {"tz": "UTC", "tz_offset": "+0000"},
    }


WAZUH_ALERT = {
    "timestamp": "2026-01-21T09:52:47.749+0000",
    "rule": {"level": 3, "description": "Auditd", "id": "80730", "groups": ["audit"]},
    "agent": {"id": "000", "name": "siem"},
    "manager": {"name": "siem"},
}
EVE_ALERT = {
    "timestamp": "2026-01-21T10:01:10.365155+0000",
    "flow_id": 5551517,
    "in_iface": "ens4",
    "event_type": "alert",
    "src_ip": "198.51.100.66",
    "dest_ip": "10.0.0.5",
    "src_port": 44444,
    "dest_port": 8080,
    "proto": "TCP",
    "alert": {
        "signature": "ET POLICY ELF file download",
        "signature_id": 2000419,
        "severity": 2,
        "category": "Potentially Bad Traffic",
    },
}
EVE_FLOW = {
    "timestamp": "2026-01-21T10:01:11.000000+0000",
    "event_type": "flow",
    "src_ip": "10.0.0.5",
    "dest_ip": "10.0.0.9",
}
EVE_STATS = {"timestamp": "2026-01-21T10:01:12.000000+0000", "event_type": "stats"}

STEPS = [
    {
        "start-datetime": "2026-01-21T10:00:00.000000",
        "type": "shell",
        "cmd": "dnsenum -f /usr/share/list.txt --dnsserver 10.0.0.1 example.com",
        "parameters": {"metadata": {"techniques": "T1590.002", "tactics": "Recon"}},
    },
    {
        "start-datetime": "2026-01-21T10:00:30.000000",
        "type": "sleep",
        "cmd": "sleep",
        "parameters": {"metadata": None, "seconds": "30"},
    },
    {
        "start-datetime": "2026-01-21T10:01:00.000000",
        "type": "shell",
        "cmd": "docker -H tcp://localhost:1090 run --rm -t -u root alpine",
        "parameters": {"metadata": {"techniques": "T1610", "tactics": "Execution"}},
    },
    {
        "start-datetime": "2026-01-21T10:01:30.000000",
        "type": "sleep",
        "cmd": "sleep",
        "parameters": {"metadata": None, "seconds": "30"},
    },
]


def json_lines(records) -> str:
    return "".join(json.dumps(record) + "\n" for record in records)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_scenario(root: Path) -> Path:
    # a four-host cut of the real layout: border box, service host, siem, attacker
    scenario = root / "scenario_x"
    write(
        scenario / "fw" / "facts.json",
        json.dumps(facts("fw", "198.51.100.10", "198.51.100.1", "198.51.100.0",
                         extra=["10.0.0.1"])),
    )
    write(scenario / "fw" / "configs" / "suricata" / "suricata.yaml", "vars:\n")
    write(scenario / "fw" / "configs" / "ossec.conf", "<ossec_config/>\n")
    write(
        scenario / "fw" / "configs" / "etc" / "dnsmasq.d" / "app.conf",
        "address=/app.example.local/10.0.0.5\n",
    )
    write(
        scenario / "fw" / "logs" / "log" / "suricata" / "eve.json",
        json_lines([EVE_FLOW, EVE_ALERT, EVE_STATS]),
    )

    write(
        scenario / "app" / "facts.json",
        json.dumps(facts("app", "10.0.0.5", "10.0.0.1", "10.0.0.0")),
    )
    write(scenario / "app" / "configs" / "ossec.conf", "<ossec_config/>\n")
    write(
        scenario / "app" / "configs" / "nextcloud" / "docker-compose.yml",
        'services:\n  mail:\n    ports:\n      - "143:143"\n      - 8080:80\n',
    )

    write(
        scenario / "siem" / "facts.json",
        json.dumps(facts("siem", "10.0.0.9", "10.0.0.1", "10.0.0.0")),
    )
    write(
        scenario / "siem" / "logs" / "alerts" / "alerts.json",
        json_lines([WAZUH_ALERT, WAZUH_ALERT]),
    )

    write(
        scenario / "attacker" / "facts.json",
        json.dumps(facts("attacker", "198.51.100.66", "198.51.100.1", "198.51.100.0")),
    )
    write(scenario / "attacker" / "logs" / "attackmate.json", json_lines(STEPS))
    return scenario


def zip_scenario(scenario: Path, archive_path: Path) -> Path:
    with zipfile.ZipFile(archive_path, "w") as bundle:
        for item in sorted(scenario.rglob("*")):
            if item.is_file():
                bundle.write(
                    item, f"{scenario.name}/{item.relative_to(scenario).as_posix()}"
                )
    return archive_path


class TempScenario(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.scenario = build_scenario(self.root)
        self.out = self.root / "out"

    def tearDown(self) -> None:
        self._temp.cleanup()


class ArchiveTest(TempScenario):
    def test_directory_and_zip_agree(self):
        bundle = zip_scenario(self.scenario, self.root / "scenario_x.zip")
        from_dir = Archive(self.scenario)
        from_zip = Archive(bundle)
        try:
            self.assertEqual(from_dir.label, "scenario_x")
            self.assertEqual(from_zip.label, "scenario_x")
            self.assertEqual(from_dir.names, from_zip.names)
            self.assertEqual(
                [host.name for host in build_hosts(from_dir)[0]],
                [host.name for host in build_hosts(from_zip)[0]],
            )
        finally:
            from_dir.close()
            from_zip.close()

    def test_parent_directory_finds_the_scenario(self):
        archive = Archive(self.root)
        try:
            self.assertEqual(archive.root, "scenario_x")
            self.assertEqual(archive.directories(), ["app", "attacker", "fw", "siem"])
        finally:
            archive.close()

    def test_two_scenarios_side_by_side_are_refused(self):
        build_scenario(self.root / "second")
        (self.root / "second" / "scenario_x").rename(self.root / "scenario_y")
        with self.assertRaises(ScenarioError):
            Archive(self.root)

    def test_a_tree_without_facts_is_refused(self):
        with self.assertRaises(ScenarioError):
            Archive(self.root / "out")


class RolesTest(TempScenario):
    def setUp(self) -> None:
        super().setUp()
        self.archive = Archive(self.scenario)
        self.addCleanup(self.archive.close)
        hosts, self.attacker = build_hosts(self.archive)
        self.roles = {host.name: set(host.roles) for host in hosts}
        self.hosts = {host.name: host for host in hosts}

    def test_border_box_is_router_and_firewall(self):
        # fw holds 10.0.0.1, which is what app and siem route through
        self.assertIn("router", self.roles["fw"])
        self.assertIn("firewall", self.roles["fw"])
        self.assertNotIn("router", self.roles["app"])

    def test_zones_come_from_the_border_network(self):
        self.assertIn("internet_facing", self.roles["fw"])
        self.assertIn("internal", self.roles["app"])
        self.assertIn("internal", self.roles["siem"])

    def test_services_come_from_the_configs(self):
        self.assertIn("ids", self.roles["fw"])
        self.assertIn("dns_server", self.roles["fw"])
        self.assertIn("file_share", self.roles["app"])
        self.assertIn("mail_server", self.roles["app"])
        self.assertNotIn("ids", self.roles["app"])
        self.assertNotIn("file_share", self.roles["fw"])

    def test_monitoring_agent_covers_agents_and_the_manager(self):
        self.assertIn("monitoring_agent", self.roles["fw"])
        self.assertIn("monitoring_agent", self.roles["app"])
        # siem has no ossec.conf, it is the manager writing the alerts
        self.assertIn("monitoring_agent", self.roles["siem"])

    def test_a_dnsmasq_dropin_without_a_record_is_not_a_dns_server(self):
        write(
            self.scenario / "siem" / "configs" / "etc" / "dnsmasq.d" / "ubuntu-fan",
            "# ensure that any system dnsmasq does not bind to fan-*\nbind-interfaces\n",
        )
        archive = Archive(self.scenario)
        self.addCleanup(archive.close)
        roles = {host.name: set(host.roles) for host in build_hosts(archive)[0]}
        self.assertNotIn("dns_server", roles["siem"])

    def test_default_address_is_listed_first(self):
        self.assertEqual(self.hosts["fw"].addresses, ("198.51.100.10", "10.0.0.1"))

    def test_every_role_is_one_the_model_knows(self):
        inventory_path = self.out / "inventory" / "scenario_x.json"
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(
            json.dumps(build_inventory(
                list(self.hosts.values()), self.attacker, "scenario_x"
            )),
            encoding="utf-8",
        )
        inventory = load_inventory(inventory_path)
        self.assertEqual(inventory.unknown_roles, ())
        self.assertEqual(inventory.assets_without_roles(), ())

    def test_the_attacker_is_left_out(self):
        self.assertEqual(self.attacker, "attacker")
        assets = build_inventory(
            list(self.hosts.values()), self.attacker, "scenario_x"
        )["assets"]
        self.assertNotIn("attacker", [asset["hostname"] for asset in assets])
        self.assertNotIn(
            "198.51.100.66",
            [ip for asset in assets for ip in asset["ip_addresses"]],
        )


class WindowsTest(TempScenario):
    def setUp(self) -> None:
        super().setUp()
        self.archive = Archive(self.scenario)
        self.addCleanup(self.archive.close)
        hosts, _ = build_hosts(self.archive)
        self.steps = read_attack_steps(self.archive, hosts)
        self.zone = scenario_timezone(self.archive, hosts)

    def test_only_steps_with_metadata_become_windows(self):
        windows = attack_windows(self.steps, self.zone)
        self.assertEqual([name for _, _, name in windows],
                         ["01_dnsenum", "03_docker_run"])

    def test_a_step_ends_where_the_next_marked_step_starts(self):
        first, second = attack_windows(self.steps, self.zone)
        self.assertEqual(first[1], second[0])
        self.assertEqual(second[0] - first[0], 60.0)

    def test_the_last_window_gets_the_tail(self):
        _, second = attack_windows(self.steps, self.zone, tail_seconds=90.0)
        # the run's last record is a sleep 30s after the last marked step
        self.assertEqual(second[1] - second[0], 120.0)

    def test_a_naive_timestamp_is_read_in_the_hosts_own_zone(self):
        first, _ = attack_windows(self.steps, self.zone)
        self.assertEqual(first[0], 1768989600.0)

    def test_no_steps_makes_no_windows(self):
        self.assertEqual(attack_windows([], self.zone), [])


class StepNameTest(unittest.TestCase):
    def test_the_subcommand_is_kept(self):
        step = {"cmd": "docker -H tcp://localhost:1090 network list", "type": "shell"}
        self.assertEqual(step_name(16, step), "16_docker_network")

    def test_flags_and_addresses_are_not_subcommands(self):
        step = {"cmd": "dnsenum -f /usr/share/l.txt --dnsserver 1.2.3.4 a.com"}
        self.assertEqual(step_name(1, step), "01_dnsenum")

    def test_a_module_path_keeps_its_last_segment(self):
        step = {"cmd": "exploit/unix/webapp/nextcloud_workflows_rce"}
        self.assertEqual(step_name(10, step), "10_nextcloud_workflows_rce")

    def test_a_script_loses_its_extension(self):
        step = {"cmd": "./smtp-user-enum.pl -M VRFY -U users.txt -t mail.a.com"}
        self.assertEqual(step_name(2, step), "02_smtp_user_enum_vrfy")

    def test_a_step_without_a_command_falls_back_to_its_type(self):
        self.assertEqual(step_name(7, {"cmd": "", "type": "sliver"}), "07_sliver")


class LabelsTest(TempScenario):
    def test_other_scenarios_survive_a_rewrite(self):
        path = self.out / "labels.csv"
        write_attack_windows(path, "other", [(1.0, 2.0, "first")])
        write_attack_windows(path, "scenario_x", [(3.0, 4.0, "second")])
        write_attack_windows(path, "scenario_x", [(5.0, 6.0, "third")])
        self.assertEqual(load_attack_windows(path, "other"), [(1.0, 2.0, "first")])
        self.assertEqual(
            load_attack_windows(path, "scenario_x"), [(5.0, 6.0, "third")]
        )


class ConvertTest(TempScenario):
    def setUp(self) -> None:
        super().setUp()
        archive = Archive(self.scenario)
        self.addCleanup(archive.close)
        self.result = convert(archive, self.out, "scenario_x")

    def test_the_written_inventory_loads(self):
        inventory = load_inventory(self.result.inventory_path)
        self.assertEqual(inventory.company, "scenario_x")
        self.assertEqual(inventory.unknown_roles, ())
        self.assertEqual(sorted(inventory.ip_by_hostname), ["app", "fw", "siem"])

    def test_the_written_windows_load(self):
        windows = load_attack_windows(self.result.labels_path, "scenario_x")
        self.assertEqual(len(windows), 2)
        self.assertEqual(windows, self.result.windows)

    def test_one_alert_file_per_detector_per_host(self):
        self.assertEqual(
            self.result.alert_counts, {"siem_alerts.json": 2, "fw_eve.json": 1}
        )
        self.assertTrue((self.out / "siem_alerts.json").exists())
        self.assertTrue((self.out / "fw_eve.json").exists())

    def test_the_records_are_copied_unchanged(self):
        written = (self.out / "fw_eve.json").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(line) for line in written], [EVE_ALERT])
        alerts = (self.out / "siem_alerts.json").read_text(encoding="utf-8")
        self.assertEqual(
            [json.loads(line) for line in alerts.splitlines()],
            [WAZUH_ALERT, WAZUH_ALERT],
        )

    def test_each_file_says_which_detector_wrote_it(self):
        self.assertEqual(sniff_alert_family(self.out / "siem_alerts.json"), "wazuh")
        self.assertEqual(sniff_alert_family(self.out / "fw_eve.json"), "suricata")

    def test_a_sensor_that_never_fired_leaves_no_file(self):
        write(
            self.scenario / "app" / "logs" / "log" / "suricata" / "eve.json",
            json_lines([EVE_FLOW, EVE_STATS]),
        )
        archive = Archive(self.scenario)
        self.addCleanup(archive.close)
        result = convert(archive, self.out, "scenario_x")
        self.assertEqual(result.alert_counts["app_eve.json"], 0)
        self.assertFalse((self.out / "app_eve.json").exists())

    def test_a_rotated_manager_falls_back_to_the_dated_copies(self):
        (self.scenario / "siem" / "logs" / "alerts" / "alerts.json").unlink()
        write(
            self.scenario / "siem" / "logs" / "alerts" / "2026" / "Jan" / "a-21.json",
            json_lines([WAZUH_ALERT]),
        )
        archive = Archive(self.scenario)
        self.addCleanup(archive.close)
        result = convert(archive, self.out, "scenario_x")
        self.assertEqual(result.alert_counts["siem_alerts.json"], 1)


@unittest.skipUnless(
    os.environ.get(SCENARIO_ENV) and Path(os.environ[SCENARIO_ENV]).exists(),
    f"set {SCENARIO_ENV} to a CAM-LDS scenario zip or directory",
)
class RealScenarioTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.out = Path(self._temp.name)
        self.addCleanup(self._temp.cleanup)
        archive = Archive(Path(os.environ[SCENARIO_ENV]))
        self.addCleanup(archive.close)
        self.result = convert(archive, self.out, "camlds")

    def test_the_inventory_uses_roles_the_model_was_trained_on(self):
        inventory = load_inventory(self.result.inventory_path)
        self.assertEqual(inventory.unknown_roles, ())
        self.assertEqual(inventory.assets_without_roles(), ())
        self.assertTrue(inventory.assets_by_ip)

    def test_windows_run_forward_and_do_not_overlap(self):
        windows = load_attack_windows(self.result.labels_path, "camlds")
        self.assertTrue(windows)
        for (_, end, _), (start, _, _) in zip(windows, windows[1:]):
            self.assertEqual(end, start)
        for start, end, _ in windows:
            self.assertLessEqual(start, end)

    def test_every_written_file_names_its_detector(self):
        written = [
            self.out / name
            for name, count in self.result.alert_counts.items() if count
        ]
        self.assertTrue(written)
        for path in written:
            self.assertIn(sniff_alert_family(path), ("wazuh", "suricata"))

    def test_the_tail_is_the_only_window_length_not_read_from_the_log(self):
        windows = self.result.windows
        self.assertGreaterEqual(windows[-1][1] - windows[-1][0], TAIL_SECONDS)


if __name__ == "__main__":
    unittest.main()
