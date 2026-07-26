# Alert text is written by whoever triggered the alert. These pin that a crafted
# rule name, hostname or user agent cannot crash the queue view, draw a live
# hyperlink inside evidence, or repaint the analyst's terminal.

from __future__ import annotations

import contextlib
import io
import unittest

import pandas as pd

from meerkat import cli

# a closing tag with nothing open is what rich raises MarkupError on
BROKEN_MARKUP = "Mozilla/5.0 [/b] compatible"
SMUGGLED_LINK = "[link=https://evil.example/harvest]GET /index.html[/link]"
CLEAR_SCREEN = "web-01\x1b[2J\x1b[1;1H"


def capture(call) -> str:
    # the CLI renders through its module-level rich console, which resolves
    # sys.stdout lazily, so redirecting stdout captures the output
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        call()
    return buffer.getvalue()


def alerts(**overrides) -> pd.DataFrame:
    row = {
        "timestamp": 100.0, "detector_source": "wazuh",
        "name": "Web server 400 error", "host": "intranet-server",
        "source_file": "acme_wazuh.json", "source_position": 10,
        "rule_id": "31101", "severity": 5.0, "alert_category": "",
        "http_status": 400.0, "http_method": "GET", "web_request": "/a",
        "http_user_agent": "curl/8.0",
        "technique_ids": "T1595", "tactics": ("Reconnaissance",),
    }
    row.update(overrides)
    return pd.DataFrame([row])


class TestSafe(unittest.TestCase):
    def test_a_stray_closing_tag_is_neutralised_with_a_backslash(self):
        # rich raises MarkupError on "[/b]" with nothing open, and there is no
        # try/except up to main(), so one user agent would kill the command
        self.assertIn("\\[/b]", cli.safe(BROKEN_MARKUP))
        self.assertIn("Mozilla/5.0", cli.safe(BROKEN_MARKUP))

    def test_the_escape_byte_is_removed_rather_than_escaped(self):
        # rich strips BEL and CR but leaves ESC alone inside a Table cell, and
        # "\x1b[2J" clears the analyst's screen mid-table. The bracket that
        # follows is left readable because rich never parses "[2J" as a tag.
        cleaned = cli.safe(CLEAR_SCREEN)
        self.assertNotIn("\x1b", cleaned)
        self.assertEqual(cleaned, "web-01[2J[1;1H")

    def test_ordinary_text_is_left_readable(self):
        self.assertEqual(cli.safe("intranet-server"), "intranet-server")
        self.assertEqual(cli.safe(404), "404")


class TestPanelRendering(unittest.TestCase):
    def test_a_crafted_user_agent_does_not_crash_the_evidence_panel(self):
        text = capture(
            lambda: cli._render_panels(alerts(http_user_agent=BROKEN_MARKUP))
        )
        self.assertIn("Mozilla/5.0", text)

    def test_a_url_cannot_smuggle_a_hyperlink_into_the_evidence(self):
        # an OSC-8 sequence would render as clickable text pointing at the
        # attacker while reading as ordinary evidence
        text = capture(
            lambda: cli._render_panels(alerts(web_request=SMUGGLED_LINK))
        )
        self.assertNotIn("\x1b]8;", text)
        self.assertIn("evil.example", text)


class TestQueueRendering(unittest.TestCase):
    def family(self, **overrides) -> pd.DataFrame:
        row = {
            "handle": "F001", "family_id": "acme#1#10.0.0.1#wazuh#31101",
            "day": 19013, "host_label": "web-01", "detector_source": "wazuh",
            "title": "Web server 400 error", "rule_id": "31101",
            "alert_count": 3, "ranking_score": 0.9,
            "evidence_probability": 0.8,
        }
        row.update(overrides)
        return pd.DataFrame([row])

    def test_one_crafted_hostname_does_not_blank_the_whole_queue(self):
        # the table renders every family, so an unescaped tag in one row would
        # take out every other row the analyst needed to see
        text = capture(
            lambda: cli.render_queue(
                self.family(host_label=BROKEN_MARKUP), {}, "Review queue"
            )
        )
        self.assertIn("Mozilla", text)

    def test_a_hostname_cannot_repaint_the_terminal_from_a_table_cell(self):
        text = capture(
            lambda: cli.render_queue(
                self.family(host_label=CLEAR_SCREEN), {}, "Review queue"
            )
        )
        self.assertNotIn("\x1b[2J", text)

    def test_a_crafted_rule_name_does_not_crash_the_family_heading(self):
        # the heading is printed as markup, so the tag has to arrive escaped
        heading = cli.family_heading(self.family(title=BROKEN_MARKUP).iloc[0])
        self.assertIn("\\[/b]", heading)
        capture(lambda: cli.console.print(heading))


if __name__ == "__main__":
    unittest.main()
