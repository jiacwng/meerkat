# the surface contract: environment naming, config precedence, orientation

from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from meerkat import cli

ROOT = Path(__file__).resolve().parents[1]


def parse(arguments: list[str]):
    args = cli.build_parser().parse_args(arguments)
    cli._apply_config(args)
    return args


class EnvironmentFlag(unittest.TestCase):
    def test_the_new_spelling_sets_the_label(self):
        self.assertEqual(parse(["triage", "--environment", "acme"]).company, "acme")

    def test_the_old_spelling_is_gone(self):
        with self.assertRaises(SystemExit) as caught:
            parse(["check", "--company", "acme"])
        self.assertEqual(caught.exception.code, 2)


class ConfigPrecedence(unittest.TestCase):
    def setUp(self) -> None:
        self._cwd = os.getcwd()
        self._temp = tempfile.TemporaryDirectory()
        os.chdir(self._temp.name)
        self.addCleanup(self._temp.cleanup)
        self.addCleanup(os.chdir, self._cwd)

    def test_the_file_fills_what_flags_left_unset(self):
        Path("meerkat.toml").write_text(
            'environment = "tomlenv"\ninput = "exports"\n', encoding="utf-8"
        )
        args = parse(["check"])
        self.assertEqual(args.company, "tomlenv")
        self.assertEqual(args.input, Path("exports"))

    def test_a_flag_beats_the_file(self):
        Path("meerkat.toml").write_text('environment = "tomlenv"\n', encoding="utf-8")
        self.assertEqual(parse(["check", "--environment", "flagenv"]).company, "flagenv")

    def test_a_variable_beats_the_file(self):
        Path("meerkat.toml").write_text('environment = "tomlenv"\n', encoding="utf-8")
        os.environ["MEERKAT_ENVIRONMENT"] = "varenv"
        self.addCleanup(os.environ.pop, "MEERKAT_ENVIRONMENT", None)
        self.assertEqual(parse(["check"]).company, "varenv")

    def test_nothing_set_keeps_the_defaults(self):
        args = parse(["check"])
        self.assertIsNone(args.company)
        self.assertEqual(args.input, cli.DEFAULT_INPUT)

    def test_the_demo_ignores_the_file(self):
        Path("meerkat.toml").write_text('runs_dir = "elsewhere"\n', encoding="utf-8")
        self.assertEqual(parse(["demo"]).runs_dir, cli.DEFAULT_RUNS)


class Completion(unittest.TestCase):
    def test_the_script_lists_commands_and_their_flags(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.cmd_completion(argparse.Namespace())
        script = output.getvalue()
        self.assertIn("triage", script)
        self.assertIn("--environment", script)
        self.assertIn("complete -F _meerkat meerkat", script)


class NoColor(unittest.TestCase):
    def test_the_flag_parses_before_the_subcommand(self):
        self.assertTrue(parse(["--no-color", "runs"]).no_color)


class Orientation(unittest.TestCase):
    def run_bare(self, cwd: Path) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, "-m", "meerkat.cli"],
            cwd=cwd, env=environment, capture_output=True, text=True,
        )

    def test_bare_invocation_orients_instead_of_erroring(self):
        with tempfile.TemporaryDirectory() as empty:
            result = self.run_bare(Path(empty))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no runs yet", result.stdout)
        self.assertIn("meerkat demo", result.stdout)

    @unittest.skipUnless(
        (ROOT / "runs" / "latest.txt").exists(),
        "needs the local demo run; a clone has no runs directory",
    )
    def test_the_orientation_names_the_latest_run(self):
        result = self.run_bare(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("latest run", result.stdout)
        self.assertIn("meerkat queue", result.stdout)


if __name__ == "__main__":
    unittest.main()
