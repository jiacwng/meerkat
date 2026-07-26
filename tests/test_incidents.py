# incident records to training labels

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from core.incidents import (
    assign_bag_priors,
    assign_reviewed,
    entity_for,
    load_incidents,
    load_reviewed_periods,
    unresolved_hosts,
)
from core.inventory import Asset, Inventory


def inventory() -> Inventory:
    web = Asset("web-01", ("10.0.0.1",), ("server",))
    mail = Asset("mail-01", ("10.0.0.2",), ("mail_server",))
    return Inventory(
        company="acme",
        assets_by_ip={"10.0.0.1": web, "10.0.0.2": mail},
        ip_by_hostname={"web-01": "10.0.0.1", "mail-01": "10.0.0.2"},
    )


def write(rows: str) -> Path:
    path = Path(tempfile.mkdtemp()) / "incidents.csv"
    path.write_text(rows, encoding="utf-8")
    return path


def sessions(*spans: tuple[str, float, float]) -> pd.DataFrame:
    return pd.DataFrame(
        [{"entity_id": e, "start": s, "end": t} for e, s, t in spans]
    )


class TestLoadIncidents(unittest.TestCase):
    def test_only_confirmed_ocsf_verdicts_are_kept(self):
        # a SOC exports the whole OCSF verdict enum, and only the four saying
        # an attack happened can seed a bag; test is a purple team run
        path = write(
            "start,end,host,verdict\n"
            "0,10,web-01,Unknown\n"
            "0,10,web-01,False Positive\n"
            "0,10,web-01,True Positive\n"
            "0,10,web-01,Disregard\n"
            "0,10,web-01,Suspicious\n"
            "0,10,web-01,Benign\n"
            "0,10,web-01,Test\n"
            "0,10,web-01,Insufficient Data\n"
            "0,10,web-01,Security Risk\n"
            "0,10,web-01,Managed Externally\n"
            "0,10,web-01,Duplicate\n"
            "0,10,web-01,Other\n"
            "0,10,web-01,escalate\n"
            "0,10,web-01,malicious\n"
        )
        self.assertEqual(
            list(load_incidents(path)["verdict"]),
            ["true_positive", "test", "security_risk", "malicious"],
        )

    def test_verdict_case_and_spacing_do_not_matter(self):
        # ticketing systems export "True Positive" with their own casing and
        # padding, and matching has to survive that before a row is dropped
        path = write("start,end,host,verdict\n0,10,web-01, True_Positive \n")
        self.assertEqual(len(load_incidents(path)), 1)

    def test_missing_column_names_what_is_missing(self):
        # a client writes this CSV by hand, so the failure names the column
        # rather than surfacing as a KeyError deep inside the retrain
        path = write("start,end,host\n0,10,web-01\n")
        with self.assertRaises(ValueError) as caught:
            load_incidents(path)
        self.assertIn("verdict", str(caught.exception))

    def test_empty_file_is_rejected(self):
        # a header-only export would otherwise reach training and fail there
        # as "no session falls inside an incident"
        with self.assertRaises(ValueError):
            load_incidents(write("start,end,host,verdict\n"))

    def test_an_all_negative_file_says_so_rather_than_returning_nothing(self):
        # a client exporting only closed false positives is told their 2 rows
        # were read, since an empty result looks like an unreadable file
        path = write(
            "start,end,host,verdict\n"
            "0,10,web-01,False Positive\n"
            "0,10,web-01,Benign\n"
        )
        with self.assertRaises(ValueError) as caught:
            load_incidents(path)
        self.assertIn("2 rows", str(caught.exception))


class TestHostResolution(unittest.TestCase):
    def test_hostname_and_address_both_resolve(self):
        # a ticket names a host however the analyst typed it and sessions are
        # keyed on the address, so both spellings reach 10.0.0.1
        self.assertEqual(entity_for("web-01", inventory()), "10.0.0.1")
        self.assertEqual(entity_for("10.0.0.2", inventory()), "10.0.0.2")

    def test_unknown_host_is_reported_not_guessed(self):
        # a ticket for a machine outside the inventory contributes no bag, so
        # retrain lists it up front rather than losing the ticket silently
        self.assertEqual(entity_for("printer", inventory()), "")
        incidents = pd.DataFrame([{"host": "printer"}, {"host": "web-01"}])
        self.assertEqual(unresolved_hosts(incidents, inventory()), ["printer"])


class TestReviewedPeriods(unittest.TestCase):
    def test_no_period_file_preserves_the_old_all_reviewed_behaviour(self):
        # --reviewed-periods is optional, and without it every session outside
        # a bag counts as reviewed and trains as a negative
        reviewed = assign_reviewed(
            sessions(("10.0.0.1", 10.0, 20.0), ("10.0.0.2", 30.0, 40.0)),
            None,
        )
        self.assertEqual(list(reviewed), [True, True])

    def test_only_sessions_fully_inside_a_reviewed_period_are_marked(self):
        # a burst half outside the reviewed hours was only half looked at, so
        # both ends have to be contained before it can be a negative
        periods = pd.DataFrame([{"start": 10.0, "end": 30.0}])
        table = sessions(
            ("10.0.0.1", 10.0, 20.0),
            ("10.0.0.1", 5.0, 15.0),
            ("10.0.0.1", 31.0, 40.0),
        )
        self.assertEqual(
            list(assign_reviewed(table, periods)),
            [True, False, False],
        )

    def test_reviewed_period_csv_loads_start_and_end(self):
        # the period file needs two columns and they arrive as text, so both
        # are parsed to float before any session comparison
        periods = load_reviewed_periods(write("start,end\n10,20\n"))
        self.assertEqual(periods.to_dict("records"), [{"start": 10.0, "end": 20.0}])


class TestBagPriors(unittest.TestCase):
    def test_a_session_outside_every_incident_is_a_clean_negative(self):
        # a prior of 0.0 is what makes a session a training negative, so a
        # burst nowhere near a ticket must pick up no weight at all
        table = sessions(("10.0.0.1", 100.0, 200.0))
        incidents = pd.DataFrame(
            [{"start": 900.0, "end": 1000.0, "host": "web-01"}]
        )
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [0.0])

    def test_prior_is_shared_across_the_bag(self):
        # k=1 split over four sessions stops one vague all-day ticket from
        # carrying four times the weight of a precise one
        table = sessions(
            ("10.0.0.1", 10.0, 20.0),
            ("10.0.0.1", 30.0, 40.0),
            ("10.0.0.1", 50.0, 60.0),
            ("10.0.0.1", 70.0, 80.0),
        )
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        prior = assign_bag_priors(table, incidents, inventory())
        # k=1 over four sessions, and the ticket's total weight stays at 1.0
        self.assertTrue(all(abs(value - 0.25) < 1e-9 for value in prior))
        self.assertAlmostEqual(prior.sum(), 1.0)

    def test_prior_never_exceeds_one_in_a_small_bag(self):
        # a one-session bag puts the whole ticket on that burst, and the clip
        # holds it at 1.0 where fit_soft_labels expects a probability
        table = sessions(("10.0.0.1", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [1.0])

    def test_an_incident_only_claims_its_own_host(self):
        # an incident is a time range plus a host, so a second machine busy in
        # the same hour stays a clean negative
        table = sessions(("10.0.0.1", 10.0, 20.0), ("10.0.0.2", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "web-01"}])
        prior = assign_bag_priors(table, incidents, inventory())
        self.assertGreater(prior.iloc[0], 0.0)
        self.assertEqual(prior.iloc[1], 0.0)

    def test_a_session_overlapping_the_edge_still_joins(self):
        # a burst rarely starts and ends inside the reported window
        table = sessions(("10.0.0.1", 90.0, 150.0))
        incidents = pd.DataFrame([{"start": 100.0, "end": 200.0, "host": "web-01"}])
        self.assertGreater(assign_bag_priors(table, incidents, inventory()).iloc[0], 0.0)

    def test_an_unresolved_host_contributes_no_bag(self):
        # with no address for printer there is nothing to compare a session
        # against, so the ticket is skipped rather than matched everywhere
        table = sessions(("10.0.0.1", 10.0, 20.0))
        incidents = pd.DataFrame([{"start": 0.0, "end": 100.0, "host": "printer"}])
        self.assertEqual(list(assign_bag_priors(table, incidents, inventory())), [0.0])

    def test_overlapping_incidents_do_not_depend_on_csv_order(self):
        # two tickets can cover one burst, and keeping the larger share both
        # ways leaves the labels identical when the export order changes
        table = sessions(
            ("10.0.0.1", 0.0, 5.0),
            ("10.0.0.1", 10.0, 15.0),
            ("10.0.0.1", 20.0, 25.0),
            ("10.0.0.1", 30.0, 35.0),
        )
        incidents = pd.DataFrame([
            {"start": 0.0, "end": 15.0, "host": "web-01"},
            {"start": 10.0, "end": 35.0, "host": "web-01"},
        ])

        forward = assign_bag_priors(table, incidents, inventory(), numerator=1.0)
        reverse = assign_bag_priors(
            table, incidents.iloc[::-1].reset_index(drop=True), inventory(),
            numerator=1.0,
        )

        expected = [0.5, 0.5, 1 / 3, 1 / 3]
        self.assertEqual(list(forward), expected)
        self.assertEqual(list(reverse), expected)


if __name__ == "__main__":
    unittest.main()
