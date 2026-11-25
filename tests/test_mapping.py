# Loading a mapping: the three presets, a site file, and every refusal.

import re
import tempfile
import unittest
from pathlib import Path

from core.incidents import COLUMNS, read_incidents
from core.mapping import PRESETS, MappingError, load_mapping


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _site(self, text: str) -> str:
        path = self.tmp / "site.toml"
        path.write_text(text)
        return str(path)

    def _refused(self, text: str, pattern: str) -> None:
        path = self._site(text)
        with self.assertRaisesRegex(MappingError, f"^{re.escape(path)}: {pattern}"):
            load_mapping(path)

    def test_presets_are_the_three_shipped_files(self):
        self.assertEqual(PRESETS, ("defender", "sentinel", "splunk"))

    def test_every_preset_covers_every_tool_column(self):
        for name in PRESETS:
            with self.subTest(name):
                mapping = load_mapping(name)
                self.assertEqual(mapping.name, name)
                self.assertEqual(list(mapping.columns), list(COLUMNS))
                self.assertEqual(set(mapping.classifications.values()) - {"", "closed"},
                                 {"TruePositive", "BenignPositive", "FalsePositive"})

    def test_an_empty_file_has_the_defender_columns(self):
        site = load_mapping(self._site(""))
        defender = load_mapping("defender")
        self.assertEqual(site.columns, defender.columns)
        self.assertEqual(site.name, "site.toml")

    def test_defender_reads_the_words_microsoft_documents(self):
        words = ["TruePositive", "Informational, expected activity", "FalsePositive",
                 "truePositive", "informationalExpectedActivity", "falsePositive", "unknown"]
        lines = ["IncidentId,Timestamp,DetectorId,IncidentGrade"]
        for number, word in enumerate(words):
            lines.append(f'{number},2024-05-20T17:00:07Z,rule,"{word}"')
        path = self.tmp / "incidents.csv"
        path.write_text("\n".join(lines) + "\n")
        incidents = read_incidents(path, load_mapping("defender"))
        self.assertEqual(list(incidents["IncidentGrade"]), [
            "TruePositive", "BenignPositive", "FalsePositive",
            "TruePositive", "BenignPositive", "FalsePositive", ""])

    def test_a_missing_path_is_refused_with_the_presets(self):
        with self.assertRaisesRegex(
                MappingError, "no such mapping; presets are defender, sentinel, splunk"):
            load_mapping(str(self.tmp / "absent.toml"))

    def test_a_directory_is_refused(self):
        with self.assertRaisesRegex(MappingError, "not a readable file"):
            load_mapping(str(self.tmp))

    def test_invalid_toml(self):
        self._refused("[columns\n", "not valid TOML")

    def test_unknown_table(self):
        self._refused("[extra]\n", "unknown table 'extra'")

    def test_unknown_column_key(self):
        self._refused('[columns]\nColour = "x"\n', r"\[columns\] has unknown column 'Colour'")

    def test_column_value_must_be_a_non_empty_string(self):
        for value in ('""', "3", '{ a = "b" }'):
            with self.subTest(value):
                self._refused(f"[columns]\nCategory = {value}\n",
                              r"\[columns\] Category must be a non empty string")

    def test_two_columns_cannot_read_one_source_column(self):
        self._refused('[columns]\nCategory = "AlertTitle"\n',
                      "AlertTitle and Category both read column 'AlertTitle'")

    def test_unknown_classification_key(self):
        self._refused('[classifications]\nMaybe = ["x"]\n', r"\[classifications\] has unknown key 'Maybe'")

    def test_classification_value_must_be_a_list_of_strings(self):
        for value in ('"x"', "[1]", '[""]'):
            with self.subTest(value):
                self._refused(f"[classifications]\nopen = {value}\n",
                              r"\[classifications\] open must be a list of non empty strings")

    def test_a_word_cannot_mean_two_classifications(self):
        self._refused('[classifications]\nTruePositive = ["x"]\nFalsePositive = ["x"]\n',
                      "classification word 'x' is listed under TruePositive and FalsePositive")
        self._refused('[classifications]\nopen = ["FalsePositive"]\n',
                      "classification word 'FalsePositive' is listed under FalsePositive and open")

    def test_a_file_with_a_byte_order_mark(self):
        path = self.tmp / "site.toml"
        path.write_bytes(b'\xef\xbb\xbf[columns]\nDetectorId = "rule"\n')
        self.assertEqual(load_mapping(str(path)).columns["DetectorId"], "rule")

    def test_an_unlisted_classification_keeps_its_own_name(self):
        mapping = load_mapping(self._site('[classifications]\nFalsePositive = ["Noise"]\n'))
        self.assertEqual(mapping.classifications, {
            "TruePositive": "TruePositive", "BenignPositive": "BenignPositive",
            "Noise": "FalsePositive"})


if __name__ == "__main__":
    unittest.main()
