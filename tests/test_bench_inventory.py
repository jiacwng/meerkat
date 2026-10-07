# the AIT inventory converter, which lives in bench/ because it needs PyYAML

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from core.inventory import load_inventory


@unittest.skipUnless(importlib.util.find_spec("yaml"), "AIT importer requires PyYAML")
class AitInventoryTests(unittest.TestCase):
    def test_ait_importer_writes_runtime_json_without_attacker(self):
        # the attacker filter has to survive the YAML to JSON conversion too
        from bench.ait_inventory import import_ait_inventory

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

            import_ait_inventory(yaml_path, json_path)
            loaded = load_inventory(json_path)

        self.assertEqual(loaded.company, "demo")
        self.assertIn("10.0.0.1", loaded)
        self.assertNotIn("192.0.2.10", loaded)


if __name__ == "__main__":
    unittest.main()
