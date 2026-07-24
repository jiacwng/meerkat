import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core import attack_mapping


class AttackStoryTests(unittest.TestCase):
    def test_module_import_does_not_depend_on_working_directory(self):
        repo_root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(repo_root)

        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-c", "import core.attack_mapping"],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_story_represents_zero_one_and_multiple_tactic_hosts(self):
        alerts = pd.DataFrame(
            {
                "host": ["unmapped", "first", "progress", "progress"],
                "timestamp": [1.0, 2.0, 5.0, 3.0],
                "tactics": [
                    (),
                    ("Execution",),
                    ("Execution",),
                    ("Reconnaissance", "Discovery"),
                ],
            }
        )

        story = attack_mapping.attack_story(alerts)

        self.assertEqual(story["unmapped"], [])
        self.assertEqual(story["first"], [(2.0, "Execution")])
        self.assertEqual(
            story["progress"],
            [
                (3.0, "Reconnaissance"),
                (3.0, "Discovery"),
                (5.0, "Execution"),
            ],
        )

    def test_alert_context_does_not_include_future_tactics(self):
        alerts = pd.DataFrame(
            {
                "host": ["server-a", "server-a", "server-b"],
                "timestamp": [1.0, 3.0, 1.5],
                "tactics": [
                    ("Reconnaissance",),
                    ("Credential Access",),
                    ("Execution",),
                ],
            }
        )

        context = attack_mapping.alert_context(alerts, "server-a", 2.0)

        self.assertEqual(context, [(1.0, "Reconnaissance")])

    def test_coverage_counts_every_tactic_on_a_multi_tactic_alert(self):
        tactics = pd.Series([(), ("Execution",), ("Execution", "Persistence")])

        coverage = attack_mapping.tactic_coverage(tactics)

        self.assertEqual(coverage["Execution"], 2)
        self.assertEqual(coverage["Persistence"], 1)
        self.assertEqual(coverage["Reconnaissance"], 0)


class TechniqueLookupTests(unittest.TestCase):
    def test_one_technique_returns_its_tactic(self):
        tactics = attack_mapping.tactics_for_techniques("T1048.003")

        self.assertEqual(tactics, ("Exfiltration",))

    def test_multi_tactic_technique_preserves_every_tactic(self):
        tactics = attack_mapping.tactics_for_techniques("T1078")

        self.assertEqual(
            tactics,
            ("Initial Access", "Persistence", "Privilege Escalation", "Stealth"),
        )

    def test_multiple_ids_merge_and_deduplicate_tactics(self):
        tactics = attack_mapping.tactics_for_techniques("T1078;T1078;T1110")

        self.assertEqual(
            tactics,
            (
                "Initial Access",
                "Persistence",
                "Privilege Escalation",
                "Stealth",
                "Credential Access",
            ),
        )

    def test_unknown_technique_has_no_invented_tactic(self):
        self.assertEqual(attack_mapping.tactics_for_techniques("T9999"), ())

    def test_unknown_technique_name_falls_back_to_id(self):
        self.assertEqual(attack_mapping.technique_name("T9999"), "T9999")


class MappingPolicyTests(unittest.TestCase):
    def test_configured_rule_overrides_wrong_native_id(self):
        # wazuh 31516 "Suspicious URL access": native says T1055, config corrects it
        mapping = attack_mapping.map_alert("wazuh", "31516", "T1055")

        self.assertEqual(mapping.technique_ids, "T1505.003")
        self.assertEqual(mapping.tactics, ("Persistence",))
        self.assertEqual(mapping.source, "rule")

    def test_suppressed_rule_silences_native_tags(self):
        # wazuh 9701 "Dovecot Authentication Success": reviewed as routine noise
        mapping = attack_mapping.map_alert("wazuh", "9701", "T1078")

        self.assertEqual(mapping, attack_mapping.AlertMapping("", (), "suppressed"))

    def test_unconfigured_rule_falls_through_to_native(self):
        mapping = attack_mapping.map_alert("wazuh", "424242", "T1110")

        self.assertEqual(mapping.technique_ids, "T1110")
        self.assertEqual(mapping.tactics, ("Credential Access",))
        self.assertEqual(mapping.source, "native")

    def test_no_config_and_no_native_abstains(self):
        mapping = attack_mapping.map_alert("suricata", "2230010", "")

        self.assertEqual(mapping, attack_mapping.AlertMapping("", (), ""))

    def test_unknown_native_technique_is_preserved_without_tactics(self):
        mapping = attack_mapping.map_alert("wazuh", "424242", "T9999")

        self.assertEqual(mapping.technique_ids, "T9999")
        self.assertEqual(mapping.tactics, ())
        self.assertEqual(mapping.source, "native")


class DetectionMappingConfigTests(unittest.TestCase):
    def test_invalid_configured_technique_fails_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "detection_mappings.json"
            bad.write_text('{"wazuh": {"1": ["T9999"]}}', encoding="utf-8")

            with self.assertRaises(ValueError):
                attack_mapping.load_detection_mappings(bad)

    def test_committed_config_only_contains_known_techniques(self):
        mappings = attack_mapping.load_detection_mappings(
            attack_mapping.PROJECT_ROOT / "data" / "detection_mappings.json"
        )

        self.assertIn("wazuh", mappings)
        self.assertNotIn("_comment", mappings)


if __name__ == "__main__":
    unittest.main()
