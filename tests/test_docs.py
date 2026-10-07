# the README's recorded output and the pipeline figure, checked against a saved run

import json
import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

import pandas as pd

from tests.fixtures import HAS_RUN, ROOT

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


def without_borders(text: str) -> str:
    # the README records on linux, where rich draws heavy box glyphs; windows
    # consoles get light ones. The cells are what rot, so borders are ignored,
    # and so is the id of the run, which is new every time the demo is scored.
    text = re.sub(r"\brun \S+", "run", text)
    return without_whitespace(re.sub(r"[─-╿]", "", text))


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
                command_output(["queue", "--day", "2022-01-21"], 190)
            ),
        )


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
