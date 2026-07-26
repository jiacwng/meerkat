import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVG_NAMESPACE = "{http://www.w3.org/2000/svg}"


def svg_terminal_text(path: Path) -> str:
    root = ET.parse(path).getroot()
    matrix = next(
        group
        for group in root.iter(f"{SVG_NAMESPACE}g")
        if (group.get("class") or "").endswith("-matrix")
    )
    return "".join(
        "".join(node.itertext())
        for node in matrix.iter(f"{SVG_NAMESPACE}text")
    )


def command_output(arguments: list[str], columns: int) -> str:
    environment = os.environ.copy()
    environment["COLUMNS"] = str(columns)
    environment["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-m", "meerkat.cli", *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def without_whitespace(text: str) -> str:
    return re.sub(r"\s+", "", text)


HAS_RUN = (ROOT / "runs" / "latest.txt").exists()


@unittest.skipUnless(
    HAS_RUN,
    "needs a saved run; produced locally by `meerkat demo`, absent in CI "
    "because the raw alerts live in Git LFS",
)
class ReadmeAssetTests(unittest.TestCase):
    def assert_matches_command(
        self,
        asset: str,
        arguments: list[str],
        columns: int,
    ) -> None:
        expected = svg_terminal_text(ROOT / "docs" / "assets" / asset)
        actual = command_output(arguments, columns)
        self.assertEqual(without_whitespace(expected), without_whitespace(actual))

    def test_queue_screenshot_matches_live_command(self):
        # a screenshot goes stale the moment the rendering changes, so the SVG
        # text is diffed against the live command at the same 136 columns
        self.assert_matches_command(
            "queue.svg", ["queue", "--day", "2022-01-21"], 136
        )

    def test_inspect_screenshot_matches_live_command(self):
        # F212 is the family the README walks a reader through, so its panels
        # have to still render the way the committed SVG shows them
        self.assert_matches_command("inspect.svg", ["inspect", "F212"], 120)


class WalkthroughCaptureTests(unittest.TestCase):
    # inventory, check and drift were captured against a directory of client
    # alerts that is not in the repo, so they cannot be diffed against a live
    # run the way queue and inspect are. What is checked instead is that each
    # one is a real terminal export and still carries the figures the README
    # quotes beside it.
    def terminal_text(self, asset: str) -> str:
        path = ROOT / "docs" / "assets" / asset
        text = svg_terminal_text(path)
        self.assertTrue(text.strip(), f"{asset} rendered no text")
        return without_whitespace(text.replace("\xa0", " "))

    def test_the_captures_are_rich_terminal_exports(self):
        for asset in ("inventory.svg", "check.svg", "drift.svg"):
            with self.subTest(asset=asset):
                root = ET.parse(ROOT / "docs" / "assets" / asset).getroot()
                self.assertEqual(root.get("class"), "rich-terminal")

    def test_each_capture_still_carries_the_numbers_around_it(self):
        expected = {
            "inventory.svg": ("10assets", "rolesareempty"),
            "check.svg": ("2476/2500", "227/942", "1558/1558", "readytotriage"),
            "drift.svg": ("36358alerts", "3169sessions", "1771families", "2.883"),
        }
        for asset, fragments in expected.items():
            text = self.terminal_text(asset)
            for fragment in fragments:
                with self.subTest(asset=asset, fragment=fragment):
                    self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
