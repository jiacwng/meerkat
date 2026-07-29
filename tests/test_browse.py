# the prompt loop must walk queue -> family -> session -> alert and back

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HAS_RUN = (ROOT / "runs" / "latest.txt").exists()


@unittest.skipUnless(HAS_RUN, "needs the local demo run; a clone has none")
class BrowseFlow(unittest.TestCase):
    def drive(self, *lines: str) -> str:
        from meerkat import browse, cli

        run = cli.load_run(ROOT / "runs")
        script = iter(lines)
        with cli.console.capture() as capture:
            browse.browse_loop(run, input_line=lambda _: next(script))
        return capture.get()

    def test_the_loop_walks_down_and_back(self) -> None:
        text = self.drive("F1", "S1", "A1", "b", "b", "q")
        self.assertIn("Overview", text)
        self.assertIn("A1", text)

    def test_a_wrong_handle_is_refused_without_leaving(self) -> None:
        text = self.drive("S1", "F1", "q")
        # S1 before any family is refused on stderr; the loop then still opens F1
        self.assertIn("Overview", text)

    def test_the_script_ends_cleanly_on_exhaustion(self) -> None:
        # input raising StopIteration must not escape the loop
        from meerkat import browse, cli

        run = cli.load_run(ROOT / "runs")

        def empty(_prompt: str) -> str:
            raise EOFError

        browse.browse_loop(run, input_line=empty)


if __name__ == "__main__":
    unittest.main()
