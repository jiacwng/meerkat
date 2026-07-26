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
        # the module reads its JSON mappings at import, so the path resolves
        # from the module file rather than wherever the shell happens to be
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
        # the story is per host and ordered by time, so the t=3 alert's two
        # tactics both land before t=5 and an unmapped host stays empty
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
        # the panel shows what led up to an alert, so a tactic seen after its
        # timestamp would read as evidence nobody had at the time
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
        # one alert can map to two tactics and both count, and a tactic
        # nobody triggered still reports 0 so the table keeps its shape
        tactics = pd.Series([(), ("Execution",), ("Execution", "Persistence")])

        coverage = attack_mapping.tactic_coverage(tactics)

        self.assertEqual(coverage["Execution"], 2)
        self.assertEqual(coverage["Persistence"], 1)
        self.assertEqual(coverage["Reconnaissance"], 0)


class TechniqueLookupTests(unittest.TestCase):
    def test_one_technique_returns_its_tactic(self):
        # sub-technique ids like T1048.003 have to resolve in the same table
        # the parent ids use
        tactics = attack_mapping.tactics_for_techniques("T1048.003")

        self.assertEqual(tactics, ("Exfiltration",))

    def test_multi_tactic_technique_preserves_every_tactic(self):
        # T1078 valid accounts sits under four tactics, and keeping only the
        # first would drop most of the story an analyst is reading
        tactics = attack_mapping.tactics_for_techniques("T1078")

        self.assertEqual(
            tactics,
            ("Initial Access", "Persistence", "Privilege Escalation", "Stealth"),
        )

    def test_multiple_ids_merge_and_deduplicate_tactics(self):
        # native ids arrive semicolon joined and often repeat, so the merge
        # keeps first-seen order and lists each tactic once
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
        # an id outside the shipped table gets no tactic guessed for it,
        # since a wrong tactic in the panel is worse than a blank one
        self.assertEqual(attack_mapping.tactics_for_techniques("T9999"), ())

    def test_unknown_technique_name_falls_back_to_id(self):
        # an unnamed technique still has to print something an analyst can
        # look up, so the id stands in for the name
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
        # only a few hundred rules are mapped by hand, so an unconfigured one
        # keeps whatever ATT&CK id the detector shipped with
        mapping = attack_mapping.map_alert("wazuh", "424242", "T1110")

        self.assertEqual(mapping.technique_ids, "T1110")
        self.assertEqual(mapping.tactics, ("Credential Access",))
        self.assertEqual(mapping.source, "native")

    def test_no_config_and_no_native_abstains(self):
        # most suricata signatures carry no technique at all, and inventing
        # one would put a fake tactic in the Navigator export
        mapping = attack_mapping.map_alert("suricata", "2230010", "")

        self.assertEqual(mapping, attack_mapping.AlertMapping("", (), ""))

    def test_unknown_native_technique_is_preserved_without_tactics(self):
        # the detector's id is kept even when the tactic table cannot resolve
        # it, so an analyst can still search T9999 upstream
        mapping = attack_mapping.map_alert("wazuh", "424242", "T9999")

        self.assertEqual(mapping.technique_ids, "T9999")
        self.assertEqual(mapping.tactics, ())
        self.assertEqual(mapping.source, "native")


class DetectionMappingConfigTests(unittest.TestCase):
    def test_invalid_configured_technique_fails_validation(self):
        # detection_mappings.json is hand-edited, and a typo there would
        # spread one wrong technique across every alert on that rule
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "detection_mappings.json"
            bad.write_text('{"wazuh": {"1": ["T9999"]}}', encoding="utf-8")

            with self.assertRaises(ValueError):
                attack_mapping.load_detection_mappings(bad)

    def test_committed_config_only_contains_known_techniques(self):
        # the committed file goes through the same validation, and _comment
        # keys are stripped so they never look like a detector name
        mappings = attack_mapping.load_detection_mappings(
            attack_mapping.PROJECT_ROOT / "data" / "detection_mappings.json"
        )

        self.assertIn("wazuh", mappings)
        self.assertNotIn("_comment", mappings)


if __name__ == "__main__":
    unittest.main()
