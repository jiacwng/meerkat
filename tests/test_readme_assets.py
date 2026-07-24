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
        self.assert_matches_command(
            "queue.svg", ["queue", "--day", "2022-01-21"], 136
        )

    def test_inspect_screenshot_matches_live_command(self):
        self.assert_matches_command("inspect.svg", ["inspect", "F212"], 120)


if __name__ == "__main__":
    unittest.main()
