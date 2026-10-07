# ATT&CK mapping and the asset role vocabulary

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core import attack_mapping
from core.inventory import load_inventory
from core.roles import CANONICAL_ROLES, LEGACY_ROLE_ALIASES, canonicalize


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
    def test_committed_config_only_contains_known_techniques(self):
        # the committed file goes through the same validation, and _comment
        # keys are stripped so they never look like a detector name
        mappings = attack_mapping.load_detection_mappings(
            attack_mapping.DATA_DIR / "detection_mappings.json"
        )

        self.assertIn("wazuh", mappings)
        self.assertNotIn("_comment", mappings)


# the role vocabulary and the inventory contract that carries it


class TestCanonicalize(unittest.TestCase):
    def test_the_alias_table_is_one_to_one_closed_and_disjoint_from_the_vocabulary(self):
        # two aliases sharing a target would merge two role columns into one and
        # change the feature width a shipped model expects. A target outside
        # CANONICAL_ROLES drops that asset's role, and an alias that is itself
        # canonical would be rewritten before the canonical lookup saw it.
        targets = list(LEGACY_ROLE_ALIASES.values())
        self.assertEqual(len(targets), len(set(targets)), "an alias merges two roles")
        for alias, target in LEGACY_ROLE_ALIASES.items():
            self.assertIn(target, CANONICAL_ROLES, f"{alias} maps outside the vocabulary")
            self.assertNotIn(alias, CANONICAL_ROLES)

    def test_testbed_names_translate(self):
        # the AIT inventories say servers, internet and beatservers, and those
        # have to reach the same columns a client's OCSF names do
        roles, unknown = canonicalize(["servers", "internet", "beatservers"])
        self.assertEqual(roles, ("server", "internet_facing", "monitoring_agent"))
        self.assertEqual(unknown, ())

    def test_canonical_names_pass_through(self):
        # an inventory already written in the canonical vocabulary has to
        # survive untouched, so the alias table leaves server and dmz alone
        roles, unknown = canonicalize(["server", "dmz"])
        self.assertEqual(roles, ("server", "dmz"))
        self.assertEqual(unknown, ())

    def test_unknown_names_are_reported_not_raised(self):
        # a client will invent role names, and refusing the whole inventory
        # over one would cost every other asset its roles
        roles, unknown = canonicalize(["server", "finance-laptops"])
        self.assertEqual(roles, ("server",))
        self.assertEqual(unknown, ("finance-laptops",))

    def test_order_does_not_depend_on_how_the_inventory_lists_them(self):
        # roles are ordered by the vocabulary, so two inventories listing the
        # same roles in a different order build the same feature row
        first, _ = canonicalize(["dmz", "server"])
        second, _ = canonicalize(["server", "dmz"])
        self.assertEqual(first, second)

    def test_duplicates_and_case_collapse(self):
        # one asset can spell a role three ways in a single file, and the
        # tuple has to collapse to the one entry the features match on
        roles, _ = canonicalize(["Server", "servers", "SERVER"])
        self.assertEqual(roles, ("server",))


class TestInventoryContract(unittest.TestCase):
    def _write(self, assets: list[dict]) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "acme.json"
        path.write_text(
            json.dumps({"company": "acme", "assets": assets}), encoding="utf-8"
        )
        return path

    def test_legacy_groups_key_still_works(self):
        # the AIT inventories and every file written before the rename use
        # groups, and re-editing them by hand is a migration nobody wants
        path = self._write(
            [{"hostname": "web", "ip_addresses": ["10.0.0.1"], "groups": ["servers"]}]
        )
        inventory = load_inventory(path)
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].groups, ("server",))

    def test_unknown_roles_surface_on_the_inventory(self):
        # `meerkat triage` warns about names contributing nothing to a model
        # trained elsewhere, and it reads that list off the loaded inventory
        path = self._write(
            [{"hostname": "web", "ip_addresses": ["10.0.0.1"], "roles": ["nas-box"]}]
        )
        inventory = load_inventory(path)
        self.assertEqual(inventory.unknown_roles, ("nas-box",))

    def test_shipped_inventories_use_only_known_roles_and_the_demo_carries_tiers(self):
        # these eight inventories define the role columns the model trains
        # on, so one unrecognised name there shrinks the feature block.
        # Resolve from this file: a glob relative to the working directory
        # matched nothing outside the repo root and the loop never ran.
        directory = Path(__file__).resolve().parents[1] / "data" / "raw" / "inventory"
        paths = sorted(directory.glob("*.json"))
        self.assertEqual(len(paths), 8, f"expected eight inventories in {directory}")
        for path in paths:
            with self.subTest(company=path.stem):
                self.assertEqual(load_inventory(path).unknown_roles, ())
        demo = load_inventory(directory / "russellmitchell.json")
        self.assertEqual(demo.assets_without_criticality(), ())
        self.assertEqual(demo.unknown_criticalities, ())


if __name__ == "__main__":
    unittest.main()
