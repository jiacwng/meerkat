# the README and manual recorded outputs and the pipeline figure, checked
# against a saved run

import json
import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SVG_NAMESPACE = "{http://www.w3.org/2000/svg}"
README = ROOT / "README.md"


def figure_caption(asset: str) -> str:
    # the alt text is the README's own description of the capture, so every
    # figure in it is a claim about what that SVG shows
    readme = README.read_text(encoding="utf-8")
    match = re.search(
        rf'src="docs/assets/{re.escape(asset)}"\s*\n\s*alt="(.*?)"', readme, re.S
    )
    if match is None:
        raise AssertionError(f"README no longer embeds docs/assets/{asset}")
    return " ".join(match.group(1).split())


def saved_run() -> tuple[dict, pd.DataFrame]:
    runs = ROOT / "runs"
    directory = runs / (runs / "latest.txt").read_text(encoding="utf-8").strip()
    meta = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    return meta, pd.read_pickle(directory / "families.pkl")


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


def manual_fence(heading: str) -> str:
    text = (ROOT / "docs" / "manual.md").read_text(encoding="utf-8")
    section = text.index(f"### meerkat {heading}\n")
    start = text.index("```text\n", section) + len("```text\n")
    return text[start:text.index("\n```", start)]


def without_borders(text: str) -> str:
    # the manual records on linux, where rich draws heavy box glyphs; windows
    # consoles get light ones. The cells are what rot, so borders are ignored.
    return without_whitespace(re.sub(r"[─-╿]", "", text))


@unittest.skipUnless(
    HAS_RUN,
    "needs a saved run; produced locally by `meerkat demo`, absent in CI "
    "because the raw alerts live in Git LFS",
)
class ManualCaptureTests(unittest.TestCase):
    # the manual embeds recorded output as text, so it goes stale the same way
    # a screenshot does and is diffed against the live command the same way

    def test_the_manual_queue_capture_matches_the_live_command(self):
        self.assertEqual(
            without_borders(manual_fence("queue")),
            without_borders(
                command_output(["queue", "--day", "2022-01-21"], 138)
            ),
        )

    def test_the_manual_inspect_capture_matches_the_live_command(self):
        self.assertEqual(
            without_borders(manual_fence("inspect")),
            without_borders(command_output(["inspect", "F212"], 120)),
        )


@unittest.skipUnless(
    HAS_RUN,
    "needs a saved run; produced locally by `meerkat demo`, absent in CI "
    "because the raw alerts live in Git LFS",
)
class ReadmeCaptureTests(unittest.TestCase):
    def test_the_readme_queue_capture_matches_the_live_command(self):
        text = README.read_text(encoding="utf-8")
        start = text.index("```text\n") + len("```text\n")
        fence = text[start:text.index("\n```", start)]
        self.assertEqual(
            without_borders(fence),
            without_borders(
                command_output(["queue", "--day", "2022-01-21"], 138)
            ),
        )


class BadgeTests(unittest.TestCase):
    # the badge drifted three times because nothing checked it. Counting by
    # loading rather than running keeps this cheap inside the suite it counts.
    def test_the_badge_matches_what_a_clone_would_run(self):
        import re

        loader = unittest.TestLoader()

        def found(pattern: str) -> int:
            suite = loader.discover(str(ROOT / "tests"), pattern=pattern,
                                    top_level_dir=str(ROOT))
            return suite.countTestCases()

        # test_m8_*.py is gitignored, so a clone never sees those
        clone = found("test_*.py") - found("test_m8_*.py")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        claimed = int(re.search(r"tests-(\d+)%20passing", readme).group(1))
        self.assertEqual(claimed, clone)


@unittest.skipUnless(
    HAS_RUN,
    "needs a saved run; produced locally by `meerkat demo`, absent in CI "
    "because the raw alerts live in Git LFS",
)
class PipelineFigureTests(unittest.TestCase):
    # the figure is hand drawn, so nothing rebuilds it when the grouping changes.
    # An earlier version carried 3,169 sessions and 1,771 families, which belong
    # to the client directory the walkthrough captures come from. The figure
    # describes the demo, so these are the counts `meerkat demo` records, read
    # back off the run rather than copied into this file.
    def demo_counts(self) -> list[int]:
        meta, families = saved_run()
        return [
            meta["alerts"], meta["sessions"], meta["families"],
            int(families["in_queue"].sum()),
        ]

    def test_the_figure_carries_the_demo_numbers(self):
        figure = ET.parse(ROOT / "docs" / "assets" / "pipeline.svg").getroot()
        text = "".join(figure.itertext())
        for count in self.demo_counts():
            with self.subTest(count=count):
                self.assertIn(f"{count:,}", text)

    def test_the_readme_caption_quotes_the_same_run(self):
        # the figure and the sentence describing it are edited separately, so
        # a regrouping that moves the counts has to move both
        caption = figure_caption("pipeline.svg")
        for count in self.demo_counts():
            with self.subTest(count=count):
                self.assertIn(f"{count:,}", caption)


if __name__ == "__main__":
    unittest.main()
