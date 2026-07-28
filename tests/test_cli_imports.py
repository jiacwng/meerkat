# the read commands must never pay for the ML stack; --help cost 4 s when they did

from __future__ import annotations

import subprocess
import sys
import unittest


class ImportBudget(unittest.TestCase):
    def test_the_cli_imports_without_the_ml_stack(self):
        # a fresh interpreter, so nothing this test process imported can leak in
        probe = (
            "import sys; import meerkat.cli; "
            "heavy = [m for m in ('sklearn', 'skops') if m in sys.modules]; "
            "sys.exit(', '.join(heavy) if heavy else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode, 0,
            f"the ML stack loads at CLI import: {result.stderr or result.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
