# Picking the reader of an incident file: Graph's JSON answer or meerkat's own CSV columns.

import json
import tempfile
import unittest
from pathlib import Path

from core.exports import read
from core.incidents import IncidentError
from tests.fixtures import graph_incident, write_csv


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.answer = json.dumps({"value": [graph_incident("1")]})

    def test_a_json_file_is_read_as_a_graph_answer_by_its_name_or_its_first_byte(self):
        for name, text in (("incidents.json", self.answer), ("INCIDENTS.JSON", self.answer),
                           ("saved.csv", "﻿ \r\n" + self.answer),
                           ("saved", f"[{self.answer}]")):
            with self.subTest(name):
                path = self.tmp / name
                path.write_text(text, encoding="utf-8")
                incidents, source = read(path)
                self.assertEqual((incidents["IncidentId"].tolist(), source), (["1"], "defender"))

    def test_a_csv_in_meerkats_columns_is_read_as_meerkat(self):
        incidents, source = read(write_csv(self.tmp / "incidents.csv"))
        self.assertEqual((len(incidents), source), (7, "meerkat"))

    def test_a_json_file_that_is_not_json_is_refused_as_json(self):
        path = self.tmp / "incidents.json"
        path.write_text("IncidentId,Timestamp,DetectorId\n1,2024-06-01T00:00:00Z,7\n")
        with self.assertRaisesRegex(IncidentError, "not a readable JSON file"):
            read(path)

    def test_the_defender_portal_queue_csv_is_no_longer_read(self):
        path = self.tmp / "export.csv"
        path.write_text("Incident name,Incident Id,Status\nLockout,61,Active\n")
        with self.assertRaisesRegex(IncidentError, "not a Microsoft Graph incidents answer"):
            read(path)

    def test_a_missing_file_is_named(self):
        for name in ("absent.csv", "absent.json"):
            with self.subTest(name):
                with self.assertRaisesRegex(IncidentError, "no such file"):
                    read(self.tmp / name)


if __name__ == "__main__":
    unittest.main()
