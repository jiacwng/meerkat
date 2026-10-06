# the ATT&CK host chain: computed per host and UTC day, shown, filtered, never scored

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd
from rich.console import Console

from core.attack_mapping import host_chain
from meerkat import cli
from tests.test_cli import make_alerts, make_families, make_sessions

RECON = "Reconnaissance"
ACCESS = "Initial Access"
EXECUTION = "Execution"
DISCOVERY = "Discovery"


def chain_of(*alerts):
    timestamps = [timestamp for timestamp, _ in alerts]
    tactics = [tactics for _, tactics in alerts]
    return host_chain(timestamps, tactics)


class ChainTests(unittest.TestCase):
    def test_no_mapped_alert_is_an_empty_chain(self):
        chain = chain_of((1.0, ()), (2.0, ()))
        self.assertEqual(chain.length, 0)
        self.assertEqual(chain.off_chain, ())

    def test_tactics_in_matrix_order_form_one_chain(self):
        chain = chain_of((1.0, (RECON,)), (5.0, (ACCESS,)), (9.0, (EXECUTION,)))
        self.assertEqual(chain.steps, [(RECON, 1.0), (ACCESS, 5.0), (EXECUTION, 9.0)])

    def test_a_tactic_that_goes_back_is_left_off_the_chain(self):
        chain = chain_of((1.0, (RECON,)), (2.0, (EXECUTION,)), (3.0, (ACCESS,)))
        self.assertEqual(chain.length, 2)
        self.assertEqual(len(chain.off_chain), 1)

    def test_time_order_wins_over_input_order(self):
        chain = chain_of((9.0, (EXECUTION,)), (1.0, (RECON,)))
        self.assertEqual(chain.steps, [(RECON, 1.0), (EXECUTION, 9.0)])

    def test_repeats_keep_the_chain_and_the_first_time(self):
        chain = chain_of((1.0, (RECON,)), (2.0, (RECON,)), (3.0, (EXECUTION,)))
        self.assertEqual(chain.steps, [(RECON, 1.0), (EXECUTION, 3.0)])

    def test_one_alert_gives_at_most_one_tactic(self):
        chain = chain_of((1.0, (RECON, DISCOVERY)))
        self.assertEqual(chain.length, 1)
        self.assertEqual(len(chain.off_chain), 1)

    def test_a_tactic_outside_the_matrix_is_ignored(self):
        chain = chain_of((1.0, ("Not A Tactic",)), (2.0, (RECON,)))
        self.assertEqual(chain.steps, [(RECON, 2.0)])
        self.assertEqual(chain.off_chain, ())

    def test_the_chain_maximises_distinct_tactics(self):
        # the greedy reading would take Execution first and stop at two
        chain = chain_of(
            (1.0, (EXECUTION,)), (2.0, (RECON,)), (3.0, (ACCESS,)),
            (4.0, (EXECUTION,)), (5.0, (DISCOVERY,)),
        )
        self.assertEqual(
            [tactic for tactic, _ in chain.steps], [RECON, ACCESS, EXECUTION, DISCOVERY]
        )


def _run(alert_tactics=None):
    alerts = make_alerts()
    if alert_tactics is not None:
        alerts["tactics"] = alert_tactics
    decorated = cli.decorate_families(make_families(), alerts, budget=2)
    runs = Path(tempfile.mkdtemp())
    cli.save_run(runs, "acme-1", {"company": "acme", "budget": 2},
                 decorated, make_sessions(), alerts)
    return cli.load_run(runs, "acme-1")


# alerts 0-2 belong to F1 (wazuh), alert 3 to F2 (suricata), all on one host and day
STEPPED = [(RECON,), (RECON,), (EXECUTION,), (ACCESS,)]


class ChainDisplayTests(unittest.TestCase):
    def test_inspect_shows_the_host_chain_in_order(self):
        run = _run(STEPPED)
        with cli.console.capture() as capture:
            cli.render_family(run, run.family_by_handle("F1"), {})
        text = capture.get()
        self.assertIn("ATT&CK chain on this host", text)
        self.assertIn("1. Reconnaissance  00:01:40", text)
        self.assertIn("2. Initial Access  00:08:20", text)
        self.assertIn("orders them by time only", text)

    def test_a_host_without_tactics_says_so(self):
        run = _run([(), (), (), ()])
        with cli.console.capture() as capture:
            cli.render_family(run, run.family_by_handle("F1"), {})
        self.assertIn("no mapped tactic on this host that day", capture.get())

    def test_the_queue_shows_the_chain_length_and_blank_at_zero(self):
        for tactics, expected in ((STEPPED, "3"), ([(), (), (), ()], None)):
            run = _run(tactics)
            with mock.patch.object(cli, "console", Console(width=200)):
                with cli.console.capture() as capture:
                    cli.render_queue(run.with_chain(run.families), {}, "Review queue")
            rows = [line for line in capture.get().splitlines() if "│ F1 " in line]
            cells = [cell.strip() for cell in rows[0].split("│")]
            chain_cell = cells[cli_column(capture.get(), "chain")]
            self.assertEqual(chain_cell, expected or "")

    def test_queue_json_carries_the_chain(self):
        run = _run(STEPPED)
        records = cli.queue_records(run, run.families)
        self.assertEqual({record["chain"] for record in records}, {3})


def cli_column(text: str, name: str) -> int:
    header = next(line for line in text.splitlines() if "handle" in line)
    return [cell.strip() for cell in header.split("┃")].index(name)


class TacticFilterTests(unittest.TestCase):
    def test_the_filter_keeps_families_whose_own_alerts_map_to_it(self):
        run = _run(STEPPED)
        selected = cli._select_families(
            run, False, None, None, None, None, None, None, ACCESS
        )
        self.assertEqual(list(selected["handle"]), ["F2"])

    def test_the_tactic_name_is_case_insensitive_and_checked(self):
        parser = cli.build_parser()
        args = parser.parse_args(["queue", "--tactic", "initial access"])
        self.assertEqual(args.tactic, ACCESS)
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit):
                parser.parse_args(["queue", "--tactic", "Pivoting"])
        self.assertIn("not an ATT&CK tactic", stderr.getvalue())


class ChainNeverScoresTests(unittest.TestCase):
    def test_the_chain_and_the_filter_leave_the_ranking_alone(self):
        run = _run(STEPPED)
        columns = ["family_id", "ranking_score", "queue_rank", "in_queue"]
        before = run.families[columns].copy()
        run.with_chain(run.families)
        cli._select_families(run, False, None, None, None, None, None, None, RECON)
        pd.testing.assert_frame_equal(run.families[columns], before)
        self.assertNotIn("chain", run.families.columns)


if __name__ == "__main__":
    unittest.main()
