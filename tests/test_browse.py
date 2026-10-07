# the prompt loop must walk queue -> family -> session -> alert and back

from __future__ import annotations

import unittest

from meerkat import browse, cli
from tests.fixtures import make_run


class BrowseFlow(unittest.TestCase):
    def setUp(self) -> None:
        self.run = cli.load_run(make_run(), "acme-1")

    def drive(self, *lines: str) -> str:
        script = iter(lines)
        with cli.console.capture() as capture:
            browse.browse_loop(self.run, input_line=lambda _: next(script))
        return capture.get()

    def test_the_loop_walks_down_and_back(self) -> None:
        text = self.drive("F1", "S1", "A1", "b", "b", "q")
        self.assertIn("Overview", text)
        self.assertIn("A1", text)

    def test_the_script_ends_cleanly_on_exhaustion(self) -> None:
        # input raising EOFError must not escape the loop
        def empty(_prompt: str) -> str:
            raise EOFError

        browse.browse_loop(self.run, input_line=empty)


if __name__ == "__main__":
    unittest.main()
