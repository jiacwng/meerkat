# hostile input: run files, indexer responses and terminal markup

import argparse
import contextlib
import io
import os
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import meerkat.connectors as connectors
from meerkat import cli
from meerkat.cli import _read_run_frame


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class _NumpyGadget:
    # numpy ships an exec wrapper, so trusting the whole numpy package is not safe
    def __reduce__(self):
        from numpy.testing._private.utils import runstring
        return (runstring, ("import builtins; builtins._meerkat_gadget = 1", {}))


class _NestedPickle:
    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (pd.read_pickle, (self.path,))


class RunUnpicklerTests(unittest.TestCase):
    def test_refuses_an_exec_gadget_inside_numpy(self):
        import builtins

        path = Path(tempfile.mkdtemp()) / "families.pkl"
        path.write_bytes(pickle.dumps(_NumpyGadget()))
        with self.assertRaises(ValueError):
            _read_run_frame(path)
        self.assertFalse(hasattr(builtins, "_meerkat_gadget"))

    def test_refuses_a_nested_unrestricted_read(self):
        directory = Path(tempfile.mkdtemp())
        inner = directory / "inner.pkl"
        inner.write_bytes(pickle.dumps(_Evil()))
        path = directory / "families.pkl"
        path.write_bytes(pickle.dumps(_NestedPickle(str(inner))))
        with self.assertRaises(ValueError) as caught:
            _read_run_frame(path)
        self.assertIn("read_pickle", str(caught.exception))

    def test_loads_a_legit_run_frame(self):
        path = Path(tempfile.mkdtemp()) / "families.pkl"
        frame = pd.DataFrame({"a": [1, 2], "roles": [("x",), ("y",)]})
        frame.to_pickle(path)
        self.assertEqual(list(_read_run_frame(path)["a"]), [1, 2])

    def test_refuses_a_code_execution_pickle(self):
        path = Path(tempfile.mkdtemp()) / "evil.pkl"
        path.write_bytes(pickle.dumps(_Evil()))
        with self.assertRaises(ValueError) as caught:
            _read_run_frame(path)
        self.assertIn("blocked", str(caught.exception))


class MarkupTests(unittest.TestCase):
    def test_a_blocked_name_with_markup_exits_cleanly(self):
        runs = Path(tempfile.mkdtemp())
        run = runs / "acme-1"
        run.mkdir()
        (run / "run.json").write_text("{}", encoding="utf-8")
        for name in ("families.pkl", "sessions.pkl", "alerts.pkl"):
            (run / name).write_bytes(b"c[/x]\nname\n.")
        args = argparse.Namespace(runs_dir=runs, run="acme-1")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli._load_run(args)
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)

    def test_browse_prints_a_handle_with_markup(self):
        from meerkat import browse
        from tests.test_cli import make_alerts, make_families, make_sessions

        runs = Path(tempfile.mkdtemp())
        decorated = cli.decorate_families(make_families(), make_alerts(), budget=2)
        cli.save_run(runs, "acme-1", {"company": "acme", "budget": 2},
                     decorated, make_sessions(), make_alerts())
        run = cli.load_run(runs, "acme-1")
        script = iter(["F[/x]", "F1", "S[/x]", "S1", "A[/x]", "[/x]", "q"])
        with cli.errors.capture() as capture, cli.console.capture():
            browse.browse_loop(run, input_line=lambda _: next(script))
        printed = capture.get()
        for refusal in ("no family", "no session", "no alert", "unknown input"):
            self.assertIn(refusal, printed)

    def test_a_missing_path_with_markup_exits_cleanly(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli._require(Path("[/x]"), "inventory")
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)

    def test_an_os_error_with_markup_exits_cleanly(self):
        refused = PermissionError(13, "Permission denied", "[/x]")
        with (
            patch.object(cli, "cmd_completion", side_effect=refused),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["completion"])
        self.assertEqual(caught.exception.code, cli.EXIT_ERROR)


class ConnectorHardeningTests(unittest.TestCase):
    def test_redirects_are_not_followed(self):
        handler = connectors._NoRedirect()
        self.assertIsNone(handler.redirect_request(
            None, None, 302, "moved", {}, "https://evil.example/"
        ))

    def test_query_window_caps_total_records(self):
        config = connectors.IndexerConfig(host="h", page_size=2)
        page = {"hits": {"hits": [
            {"_source": {}, "sort": [1]},
            {"_source": {}, "sort": [2]},
        ]}}
        with (
            patch.object(connectors, "MAX_RECORDS", 3),
            patch.object(connectors, "_send") as send,
        ):
            send.side_effect = [{"pit_id": "p"}, page, page, {}]
            with self.assertRaises(connectors.ConnectorError):
                connectors.query_window(config, connectors.Window(0.0, 100.0))


if __name__ == "__main__":
    unittest.main()
