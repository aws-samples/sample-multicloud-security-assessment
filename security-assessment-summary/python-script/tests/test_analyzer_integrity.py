"""Regression tests for assessment input and compliance integrity."""

import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer


class AnalyzerIntegrityTests(unittest.TestCase):
    def run_analyzer(self, input_dir, output_path):
        return subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "analyze_security_data.py"),
             str(input_dir), str(output_path)],
            capture_output=True, text=True,
        )

    def test_invalid_selected_ocsf_fails_without_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            (input_dir / "bad.ocsf.json").write_text("{invalid", encoding="utf-8")
            output_path = root / "analysis.json"

            result = self.run_analyzer(input_dir, output_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Failed to parse OCSF JSON", result.stderr)
            self.assertFalse(output_path.exists())

    def test_mixed_valid_and_invalid_scans_fail_without_partial_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            (input_dir / "good.ocsf.json").write_text(json.dumps([{
                "cloud": {"provider": "aws"},
                "status_code": "PASS",
                "metadata": {"event_code": "check-a"},
            }]), encoding="utf-8")
            (input_dir / "bad.ocsf.json").write_text("{invalid", encoding="utf-8")
            output_path = root / "analysis.json"

            result = self.run_analyzer(input_dir, output_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Failed to parse OCSF JSON", result.stderr)
            self.assertFalse(output_path.exists())

    def test_selected_compliance_parse_failure_fails_without_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            (input_dir / "good.ocsf.json").write_text("[]", encoding="utf-8")
            (input_dir / "framework.csv").write_text(
                "STATUS;FRAMEWORK;REQUIREMENTS_ID\nPASS;Example;R1\n",
                encoding="utf-8",
            )
            output_path = root / "analysis.json"
            stderr = io.StringIO()
            with (mock.patch.object(analyzer.csv, "DictReader",
                                    side_effect=csv.Error("malformed compliance CSV")),
                  mock.patch.object(sys, "argv", [
                      "analyze_security_data.py", str(input_dir), str(output_path)
                  ]),
                  contextlib.redirect_stdout(io.StringIO()),
                  contextlib.redirect_stderr(stderr)):
                with self.assertRaises(SystemExit) as exit_result:
                    analyzer.main()

            self.assertNotEqual(exit_result.exception.code, 0)
            self.assertIn("Failed to parse compliance CSV", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_valid_empty_ocsf_is_not_a_parse_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "input"
            input_dir.mkdir()
            (input_dir / "empty.ocsf.json").write_text("[]", encoding="utf-8")
            output_path = root / "analysis.json"

            result = self.run_analyzer(input_dir, output_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            analysis = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(analysis["summary"]["total_checks"], 0)

    def test_requirement_needs_recognized_pass_in_every_observed_row(self):
        rows = [
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "all-pass", "STATUS": "PASS"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "all-pass", "STATUS": "passed"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "manual", "STATUS": "PASS"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "manual", "STATUS": "MANUAL"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "manual-first", "STATUS": "MANUAL"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "manual-first", "STATUS": "PASS"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "unknown", "STATUS": "UNKNOWN"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "not-explicit", "STATUS": "PASSIVE"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "failed", "STATUS": "PASS"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "failed", "STATUS": "FAIL"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "failed-spelling", "STATUS": "PASS"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "failed-spelling", "STATUS": "FAILED"},
            {"FRAMEWORK": "Example", "REQUIREMENTS_ID": "missing", "STATUS": ""},
        ]

        coverage = analyzer.analyze_compliance(rows)["Example"]

        self.assertEqual(coverage["total"], 13)
        self.assertEqual(coverage["pass"], 6)
        self.assertEqual(coverage["fail"], 2)
        self.assertEqual(coverage["requirements_total"], 8)
        self.assertEqual(coverage["requirements_passed"], 1)
        self.assertEqual(coverage["requirements_pass_rate"], 12.5)


if __name__ == "__main__":
    unittest.main()
