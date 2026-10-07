# the surface contract: environment naming, config precedence, orientation

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from meerkat import cli
from tests.fixtures import HAS_RUN, ROOT, run_cli


def parse(arguments: list[str]):
    args = cli.build_parser().parse_args(arguments)
    cli._apply_config(args)
    return args


class EnvironmentFlag(unittest.TestCase):
    def test_the_new_spelling_sets_the_label(self):
        self.assertEqual(parse(["triage", "--environment", "acme"]).company, "acme")


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


class WhatDiffers(unittest.TestCase):
    def test_the_varying_field_is_found_and_constants_are_skipped(self):
        import pandas as pd
        slice_ = pd.DataFrame({
            "web_request": ["/a", "/a", "/a"],
            "source_port": ["1", "2", "3"],
        })
        self.assertEqual(cli._differs_field(slice_), "source_port")

    def test_nothing_varies_means_no_column(self):
        import pandas as pd
        slice_ = pd.DataFrame({"web_request": ["/a", "/a"]})
        self.assertEqual(cli._differs_field(slice_), "")


class TechniqueText(unittest.TestCase):
    def test_only_vetted_ids_become_links(self):
        text = cli._technique_text(["T1595", "T9999"])
        self.assertIn("[link=https://attack.mitre.org/techniques/T1595/]", text)
        self.assertNotIn("T9999/", text)


class Orientation(unittest.TestCase):
    def test_bare_invocation_orients_instead_of_erroring(self):
        with tempfile.TemporaryDirectory() as empty:
            result = run_cli([], cwd=Path(empty))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no runs yet", result.stdout)
        self.assertIn("meerkat demo", result.stdout)

    @unittest.skipUnless(
        HAS_RUN, "needs the local demo run; a clone has no runs directory"
    )
    def test_the_orientation_names_the_latest_run(self):
        result = run_cli([], cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("latest run", result.stdout)
        self.assertIn("meerkat queue", result.stdout)


if __name__ == "__main__":
    unittest.main()
