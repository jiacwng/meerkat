# what an install ships and what a benchmark run needs before it starts

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# What `pip install meerkat` actually gets. core.attack_mapping reads its JSON at
# import, so a data file left out of the wheel is not a missing feature, it is a
# traceback on every command; and bench/ is the benchmark harness, which stays out.


ROOT = Path(__file__).resolve().parents[1]
INSTALL_TIMEOUT = 120


def pip_works() -> bool:
    try:
        done = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


class InstalledPackageTests(unittest.TestCase):
    """Install into a throwaway directory and run the product out of it."""

    @classmethod
    def setUpClass(cls) -> None:
        if not pip_works():
            raise unittest.SkipTest("pip is not available")

        cls.target = Path(tempfile.mkdtemp(prefix="meerkat-install-"))
        # the subprocesses run from an empty directory so an accidental import
        # of the source tree cannot pass for the installed package
        cls.elsewhere = Path(tempfile.mkdtemp(prefix="meerkat-cwd-"))
        try:
            done = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install", ".",
                    "--target", str(cls.target),
                    "--no-deps", "--quiet",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=INSTALL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            cls.tearDownClass()
            raise unittest.SkipTest(f"pip install took over {INSTALL_TIMEOUT}s")

        if done.returncode != 0:
            cls.tearDownClass()
            raise AssertionError(f"pip install failed:\n{done.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        for directory in (cls.target, cls.elsewhere):
            shutil.rmtree(directory, ignore_errors=True)

    def run_installed(self, arguments: list[str]) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(self.target)
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=self.elsewhere,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )

    def test_the_installed_cli_imports_with_its_data_files(self):
        # the failure this guards against: data/ sat outside the package, so
        # importing the installed cli died on a missing attack_lookup.json
        done = self.run_installed(
            ["-c", "import meerkat.cli, core.attack_mapping as m; print(m.__file__)"]
        )

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(
            done.stdout.strip().startswith(str(self.target)),
            f"imported {done.stdout.strip()} instead of the installed copy",
        )

    def test_the_installed_command_runs(self):
        # the console script is meerkat.cli:main, which is what -m reaches
        done = self.run_installed(["-m", "meerkat.cli", "--help"])

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout.lower())

    def test_the_benchmark_harness_is_not_installed(self):
        # bench/ scores the product against AIT ground truth, which a client
        # does not have, so it is not part of what gets installed
        done = self.run_installed(["-c", "import bench"])

        self.assertNotEqual(done.returncode, 0, "bench must not be installed")
        self.assertIn("ModuleNotFoundError", done.stderr)


if __name__ == "__main__":
    unittest.main()
