"""Ranked result display and match-score regressions; no network access."""

import copy
import os
import re
import unittest
from unittest.mock import patch

import scanner as s


def report_fixture(count=40, status="ambiguous"):
    rows = [{"label": "Example OS %02d" % n, "score": 100 - n, "coverage": 75.0}
            for n in range(count)]
    return {"target": "192.0.2.2", "source": "192.0.2.1", "result": {
        "status": status, "candidate": rows[0]["label"] if status == "candidate" and rows else None,
        "ranked": rows, "explanation": "Observed fingerprints overlap.", "compared_labels": count}}


class ResultsDisplayTests(unittest.TestCase):
    def test_default_table_has_25_rows_and_summary(self):
        text = s.format_os_results(report_fixture())
        self.assertIn("OS Detection Results for 192.0.2.2", text)
        for heading in ("Rank", "Operating System", "Confidence", "Coverage", "Match Bar"):
            self.assertIn(heading, text)
        self.assertIn("Example OS 24", text)
        self.assertNotIn("Example OS 25", text)
        self.assertIn("Showing: 25 of 40 retained matches", text)
        self.assertIn("Use --debug", text)
        self.assertIn("Source IP: 192.0.2.1", text)
        self.assertNotIn("\x1b", text)

    def test_debug_displays_all_retained_rows(self):
        text = s.format_os_results(report_fixture(), debug=True)
        self.assertIn("Example OS 39", text)
        self.assertIn("Showing: 40 of 40 retained matches", text)
        self.assertNotIn("Use --debug", text)

    def test_unknown_never_claims_best_match_even_at_100_percent(self):
        text = s.format_os_results(report_fixture(status="unknown"))
        self.assertIn("100.00%", text)
        self.assertIn("Status: UNKNOWN", text)
        self.assertIn("Closest reference:", text)
        self.assertIn("no OS identified", text)
        self.assertNotIn("Best match:", text)
        self.assertIn("not a calibrated OS probability", text)

    def test_candidate_and_ambiguous_have_distinct_summaries(self):
        self.assertIn("Best match: Example OS 00", s.format_os_results(report_fixture(status="candidate")))
        text = s.format_os_results(report_fixture())
        self.assertIn("Status: AMBIGUOUS", text)
        self.assertNotIn("Best match:", text)

    def test_empty_result_still_displays_summary(self):
        text = s.format_os_results(report_fixture(0, "unknown"))
        self.assertIn("No comparable OS fingerprints available", text)
        self.assertIn("Showing: 0 of 0", text)

    def test_bars_match_score_and_do_not_normalize_candidates(self):
        report = report_fixture(3)
        for row, score in zip(report["result"]["ranked"], (100, 50, 0)):
            row["score"] = score
        original = copy.deepcopy(report)
        text = s.format_os_results(report, width=120)
        self.assertIn("#" * 20, text)
        self.assertIn("#" * 10 + "." * 10, text)
        self.assertIn("." * 20, text)
        self.assertEqual(report, original)

    def test_wrapping_colors_and_control_characters(self):
        report = report_fixture(1)
        report["result"]["ranked"][0]["label"] = "Very long OS label " * 8 + "\x1b[31m\nending"
        for width in (78, 100, 120):
            text = s.format_os_results(report, width=width)
            colored = s.format_os_results(report, color=True, width=width)
            self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored), text)
            self.assertNotIn("\x1b", text)
            self.assertIn("ending", text)
            for line in text.splitlines():
                if line.startswith(("+", "|")):
                    self.assertEqual(len(line), width)

    def test_no_color_for_redirected_output_or_no_color_environment(self):
        with patch.object(s.sys.stdout, "isatty", return_value=False):
            self.assertFalse(s.terminal_color_enabled())
        with patch.object(s.sys.stdout, "isatty", return_value=True), patch.dict(os.environ, {"NO_COLOR": ""}):
            self.assertFalse(s.terminal_color_enabled())

    def test_matcher_retains_40_labels_and_keeps_weighted_confidence(self):
        entry = {"label": "Example", "tests": {"T1": {"R": "Y", "W": "1000"}},
                 "classes": [{"family": "Linux", "generation": "test"}], "cpe": [], "line": 1}
        entries = [dict(entry, label="OS %02d" % n) for n in range(45)]
        db = {"entries": entries, "points": {"T1": {"R": 75, "W": 25}}, "count": 45, "sha256": "test"}
        report = {"standard_fingerprint": {"T1": {"R": "Y", "W": "2000"}}, "ports": []}
        result = s.published_match(report, db)
        self.assertEqual(len(result["ranked"]), 40)
        self.assertEqual(result["compared_labels"], 45)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(all(row["confidence_percent"] == 75 for row in result["ranked"]))
        self.assertTrue(all(row["coverage"] == 100 for row in result["ranked"]))


if __name__ == "__main__":
    unittest.main()
