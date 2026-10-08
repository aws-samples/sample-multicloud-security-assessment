"""Regression coverage for analyzer/dashboard data-flow defects."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer
import generate_dashboard as dashboard


class AnalyzerRegressionTests(unittest.TestCase):
    def test_ocsf_uses_event_code_as_the_check_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "finding.ocsf.json"
            input_path.write_text(json.dumps([{
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "111122223333"},
                    "region": "us-east-1",
                },
                "status_code": "FAIL",
                "severity": "High",
                "metadata": {"event_code": "aws_iam_no_root_access_key"},
                "finding_info": {
                    "uid": "unique-per-resource-finding-id",
                    "title": "Root access key exists",
                },
            }]), encoding="utf-8")

            finding = analyzer.parse_ocsf_json(str(input_path))[0]

        self.assertEqual(finding["CHECK_ID"], "aws_iam_no_root_access_key")
        self.assertEqual(finding["REGION"], "us-east-1")

    def test_dashboard_data_contains_all_statuses_and_scope_region(self):
        analysis = analyzer.analyze_findings([
            {
                "PROVIDER": "aws", "STATUS": "PASS", "SEVERITY": "Info",
                "CHECK_ID": "check-a", "SERVICE_NAME": "S3",
                "SCOPE_ID": "111122223333", "REGION": "us-east-1",
            },
            {
                "PROVIDER": "aws", "STATUS": "FAIL", "SEVERITY": "Medium",
                "CHECK_ID": "check-b", "SERVICE_NAME": "S3",
                "SCOPE_ID": "111122223333", "REGION": "us-east-1",
            },
        ])

        self.assertEqual(len(analysis["detailed_findings"]), 1)
        self.assertEqual(len(analysis["dashboard_findings"]), 2)
        self.assertEqual(
            analysis["dashboard_findings"][0],
            {
                "provider": "aws", "status": "PASS", "severity": "Info",
                "service": "S3", "scope_id": "111122223333",
                "region": "us-east-1",
            },
        )

    def test_repeat_run_excludes_its_prior_default_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "source.csv").write_text(
                "STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;REGION;PROVIDER\n"
                "PASS;Info;check-a;S3;111122223333;us-east-1;aws\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(SCRIPTS_DIR / "analyze_security_data.py"),
                       str(input_dir)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run(command, check=True, capture_output=True, text=True)
            output = json.loads(
                (input_dir / "assessment-summary-aws" / "analysis.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(output["summary"]["total_checks"], 1)
        self.assertEqual(output["summary"]["findings_by_provider"].keys(), {"aws"})

    def test_explicit_analysis_file_in_input_root_is_excluded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            generated_file = input_dir / "analysis.json"
            generated_file.write_text(
                json.dumps([{"cloud": {"provider": "aws"}}]), encoding="utf-8"
            )

            files = analyzer.identify_files(
                str(input_dir), excluded_files=[generated_file]
            )

        self.assertEqual(files["prowler_json"], [])


class DashboardRegressionTests(unittest.TestCase):
    def test_scope_term_is_escaped_and_compliance_width_is_numeric(self):
        scope_term = 'scope"><img src=x onerror=alert(1)>'
        data = {
            "metadata": {"scope_term": scope_term},
            "summary": {
                "total_checks": 0, "pass_count": 0, "fail_count": 0,
                "findings_by_severity": {}, "findings_by_service": {},
            },
            "compliance_coverage": {
                "CIS": {"total": 2, "pass": 1, "pass_rate": "50.0"},
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "dashboard.html"
            dashboard.generate_html(data, str(output_path))
            rendered = output_path.read_text(encoding="utf-8")
            self.assertNotIn(scope_term, rendered)
            self.assertIn("scope&quot;&gt;&lt;img", rendered)
            self.assertIn('style="width: 50%; background-color:', rendered)

            data["compliance_coverage"]["CIS"]["pass_rate"] = "50%; color: red"
            invalid_output = Path(temp_dir) / "invalid.html"
            with self.assertRaisesRegex(ValueError, "Compliance pass rate must be numeric"):
                dashboard.generate_html(data, str(invalid_output))
            self.assertFalse(invalid_output.exists())

    def test_compliance_card_shows_check_and_requirement_denominators(self):
        coverage = analyzer.analyze_compliance([
            {"NAME": "CIS AWS v4.0.1", "REQUIREMENTS_ID": "1.1",
             "STATUS": "PASS", "ACCOUNTID": "scope-a"},
            {"NAME": "CIS AWS v4.0.1", "REQUIREMENTS_ID": "1.1",
             "STATUS": "PASS", "ACCOUNTID": "scope-b"},
            {"NAME": "CIS AWS v4.0.1", "REQUIREMENTS_ID": "1.2",
             "STATUS": "PASS", "ACCOUNTID": "scope-a"},
            {"NAME": "CIS AWS v4.0.1", "REQUIREMENTS_ID": "1.2",
             "STATUS": "FAIL", "ACCOUNTID": "scope-b"},
        ])

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "dashboard.html"
            dashboard.generate_html({
                "metadata": {"providers": ["aws"]},
                "summary": {
                    "total_checks": 0, "pass_count": 0, "fail_count": 0,
                    "findings_by_severity": {}, "findings_by_service": {},
                },
                "compliance_coverage": coverage,
            }, str(output_path))
            rendered = output_path.read_text(encoding="utf-8")

        self.assertIn("Total Checks: 4", rendered)
        self.assertIn("3 passed (75.0%)", rendered)
        self.assertIn("Requirements Met: 1 / 2 (50.0%)", rendered)

    def test_other_severity_is_in_dashboard_pie(self):
        analysis = analyzer.analyze_findings([
            {
                "PROVIDER": "aws", "STATUS": "FAIL",
                "SEVERITY": "High", "CHECK_ID": "high-check",
            },
            {
                "PROVIDER": "aws", "STATUS": "FAIL",
                "SEVERITY": "Informational", "CHECK_ID": "info-check",
            },
        ])
        chart = dashboard._build_severity_chart(
            analysis["findings_by_severity"]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "dashboard.html"
            dashboard.generate_html({
                "metadata": {"providers": ["aws"]},
                "summary": analysis,
                "dashboard_findings": analysis["dashboard_findings"],
                "top_failed_checks": analysis["top_failed_checks"],
            }, str(output_path))
            rendered = output_path.read_text(encoding="utf-8")

        self.assertEqual(chart["data"]["labels"], ["High", "Other"])
        self.assertEqual(chart["data"]["datasets"][0]["data"], [1, 1])
        self.assertEqual(sum(chart["data"]["datasets"][0]["data"]),
                         analysis["fail_count"])
        self.assertIn('"labels": ["High", "Other"]', rendered)

    def test_dashboard_uses_scope_id_and_all_statuses_for_account_metrics(self):
        findings = [
            {
                "scope_id": "111122223333", "status": "PASS",
                "severity": "Info", "service": "S3", "region": "us-east-1",
            },
            {
                "scope_id": "111122223333", "status": "FAIL",
                "severity": "Medium", "service": "S3", "region": "us-east-1",
            },
        ]

        accounts = dashboard._compute_per_account_stats(findings)
        regions = dashboard._compute_per_region_stats(findings)

        self.assertEqual(accounts[0]["account_id"], "111122223333")
        self.assertEqual(accounts[0]["total"], 2)
        self.assertEqual(accounts[0]["failed"], 1)
        self.assertEqual(accounts[0]["passed"], 1)
        self.assertEqual(accounts[0]["pass_rate"], 50.0)
        self.assertEqual(regions[0]["region"], "us-east-1")
        self.assertEqual(regions[0]["total"], 2)

    def test_status_filter_uses_explicit_pass_and_fail_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "dashboard.html"
            dashboard.generate_html({
                "metadata": {},
                "summary": {
                    "total_checks": 4,
                    "pass_count": 1,
                    "fail_count": 3,
                    "findings_by_severity": {
                        "critical": 0, "high": 1, "medium": 1,
                        "low": 1, "other": 0,
                    },
                    "findings_by_service": {},
                },
                "dashboard_findings": [
                    {
                        "scope_id": "111122223333", "status": "PASS",
                        "severity": "Info", "service": "S3",
                        "region": "us-east-1",
                    },
                    {
                        "scope_id": "111122223333", "status": "FAIL",
                        "severity": "High", "service": "S3",
                        "region": "us-east-1",
                    },
                    {
                        "scope_id": "111122223333", "status": "FAIL",
                        "severity": "Medium", "service": "S3",
                        "region": "us-east-1",
                    },
                    {
                        "scope_id": "111122223333", "status": "FAIL",
                        "severity": "Low", "service": "S3",
                        "region": "us-east-1",
                    },
                ],
                "top_failed_checks": [],
                "compliance_coverage": {},
            }, str(output_path))
            rendered = output_path.read_text(encoding="utf-8")

        self.assertIn('"Failed": {"critical": 0, "high": 1, "total": 3}', rendered)
        self.assertIn('"Passed": {"critical": 0, "high": 0, "total": 1}', rendered)
        self.assertNotIn("originalData.critical + originalData.high", rendered)


if __name__ == "__main__":
    unittest.main()
