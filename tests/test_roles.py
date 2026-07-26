# the role vocabulary and the inventory contract that carries it

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.inventory import load_inventory
from core.roles import CANONICAL_ROLES, LEGACY_ROLE_ALIASES, canonicalize


class TestCanonicalize(unittest.TestCase):
    def test_every_alias_lands_on_a_canonical_name(self):
        # an alias pointing outside CANONICAL_ROLES drops that asset's role
        # silently, so the table has to close on itself
        for alias, target in LEGACY_ROLE_ALIASES.items():
            self.assertIn(target, CANONICAL_ROLES, f"{alias} maps outside the vocabulary")

    def test_aliases_are_one_to_one_so_the_feature_space_keeps_its_shape(self):
        # two aliases sharing a target would merge two role columns into one
        # and change the feature width a shipped model expects
        targets = list(LEGACY_ROLE_ALIASES.values())
        self.assertEqual(len(targets), len(set(targets)), "an alias merges two roles")

    def test_no_alias_shadows_a_canonical_name(self):
        # a name in both tables would be rewritten before the canonical
        # lookup ever saw it, so the two vocabularies stay disjoint
        for alias in LEGACY_ROLE_ALIASES:
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

    def test_roles_key_is_accepted(self):
        # roles is the key `meerkat inventory` scaffolds and the README
        # documents, so it has to reach Asset.groups
        path = self._write(
            [{"hostname": "web", "ip_addresses": ["10.0.0.1"], "roles": ["server"]}]
        )
        inventory = load_inventory(path)
        self.assertEqual(inventory.assets_by_ip["10.0.0.1"].groups, ("server",))

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

    def test_shipped_inventories_use_only_known_roles(self):
        # these eight inventories define the role columns the model trains
        # on, so one unrecognised name there shrinks the feature block
        for path in sorted(Path("data/raw/inventory").glob("*.json")):
            with self.subTest(company=path.stem):
                self.assertEqual(load_inventory(path).unknown_roles, ())


if __name__ == "__main__":
    unittest.main()
