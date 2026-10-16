# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regressions for scan selection, anonymization, and versioned compliance."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer


def run_analyzer(input_dir, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "analyze_security_data.py"),
         str(input_dir), *map(str, args)],
        capture_output=True, text=True,
    )


def write_csv(path):
    path.write_text(
        "STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;PROVIDER\n"
        "PASS;Info;pass-check;S3;111122223333;aws\n"
        "FAIL;High;fail-check;S3;111122223333;aws\n",
        encoding="utf-8",
    )


class AnalyzerFollowupTests(unittest.TestCase):
    def test_asff_only_scan_is_parsed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            stem = "prowler-output-111122223333-20261008000000"
            asff = input_dir / f"{stem}.asff.json"
            self.assertFalse(analyzer._is_compliance_json(asff))
            asff.write_text(json.dumps([{
                "ProductArn": "arn:aws:securityhub:us-east-1::product/prowler/prowler",
                "AwsAccountId": "111122223333",
                "Compliance": {"Status": "FAILED"},
                "Severity": {"Label": "HIGH"},
                "GeneratorId": "check-one",
                "Title": "One finding",
                "Resources": [{"Id": "resource-one", "Type": "AwsS3Bucket"}],
            }]), encoding="utf-8")
            output = root / "analysis.json"

            result = run_analyzer(input_dir, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["total_checks"], 1)
            self.assertEqual(data["summary"]["fail_count"], 1)
            self.assertEqual(data["metadata"]["files_processed"]["security_hub_json"], 1)

    def test_asff_and_ocsf_for_one_scan_are_counted_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            stem = "prowler-output-111122223333-20261008000000"
            (input_dir / f"{stem}.asff.json").write_text(json.dumps([{
                "ProductArn": "arn:aws:securityhub:us-east-1::product/prowler/prowler",
                "AwsAccountId": "111122223333",
                "Compliance": {"Status": "FAILED"},
                "GeneratorId": "check-one",
            }]), encoding="utf-8")
            (input_dir / f"{stem}.ocsf.json").write_text(json.dumps([{
                "cloud": {"provider": "aws", "account": {"uid": "111122223333"}},
                "status_code": "FAIL",
                "metadata": {"event_code": "check-one"},
            }]), encoding="utf-8")
            output = root / "analysis.json"

            result = run_analyzer(input_dir, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["total_checks"], 1)
            self.assertEqual(data["metadata"]["files_processed"]["security_hub_json"], 1)
            self.assertEqual(data["metadata"]["files_processed"]["prowler_json"], 1)

    def test_anonymization_sidecar_is_not_read_on_repeat_run(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            input_dir.mkdir()
            write_csv(input_dir / "findings.csv")
            keydir = Path(temp_dir) / "operator_keys"

            first = run_analyzer(input_dir, "--anonymize", "--anon-map-dir", str(keydir))
            second = run_analyzer(input_dir, "--anonymize", "--anon-map-dir", str(keydir))

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            # The de-anonymization key lives in the OPERATOR dir, never in the input or
            # deliverables tree, and is run-stamped (so repeat runs don't overwrite).
            self.assertFalse((input_dir / "anon_map.json").exists())
            keys = list(keydir.glob("anon_map_*.json"))
            self.assertGreaterEqual(len(keys), 2, "each run should write a stamped key")
            data = json.loads(
                (input_dir / "assessment-summary-aws" / "analysis.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(data["summary"]["total_checks"], 2)
            self.assertEqual(data["metadata"]["providers"], ["aws"])

    def test_old_default_output_is_not_read_with_new_output_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            write_csv(input_dir / "findings.csv")

            first = run_analyzer(input_dir)
            new_output = root / "different-output"
            second = run_analyzer(input_dir, "--output-dir", new_output)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            data = json.loads((new_output / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["total_checks"], 2)
            self.assertEqual(data["metadata"]["providers"], ["aws"])

    def test_compliance_versions_with_same_requirement_id_stay_separate(self):
        coverage = analyzer.analyze_compliance([
            {"FRAMEWORK": "CIS", "NAME": "CIS AWS Benchmark v3.0.0",
             "REQUIREMENTS_ID": "1.1", "STATUS": "PASS"},
            {"FRAMEWORK": "CIS", "NAME": "CIS AWS Benchmark v4.0.1",
             "REQUIREMENTS_ID": "1.1", "STATUS": "FAIL"},
        ])

        self.assertEqual(set(coverage), {
            "CIS AWS Benchmark v3.0.0", "CIS AWS Benchmark v4.0.1",
        })
        self.assertEqual(coverage["CIS AWS Benchmark v3.0.0"]["requirements_passed"], 1)
        self.assertEqual(coverage["CIS AWS Benchmark v4.0.1"]["requirements_passed"], 0)

    def test_anonymization_leak_fails_without_writing_deliverables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "findings.csv").write_text(
                "STATUS;SEVERITY;CHECK_ID;CHECK_TITLE;SERVICE_NAME;ACCOUNT_UID;PROVIDER\n"
                "FAIL;High;check-one;logs123456789012;S3;123456789012;aws\n",
                encoding="utf-8",
            )
            output = root / "deliverables" / "analysis.json"

            result = run_analyzer(input_dir, output, "--anonymize")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("anonymization incomplete", result.stderr)
            self.assertFalse(output.exists())
            self.assertFalse((root / "anon_map.json").exists())

    def test_each_severity_retains_phase_candidates(self):
        findings = [
            {"STATUS": "FAIL", "SEVERITY": "Critical", "CHECK_ID": f"critical-{i}"}
            for i in range(30)
        ] + [
            {"STATUS": "FAIL", "SEVERITY": "High", "CHECK_ID": "high-check"},
            {"STATUS": "FAIL", "SEVERITY": "Medium", "CHECK_ID": "medium-check"},
        ]

        analysis = analyzer.analyze_findings(findings)
        kept = {item["check_id"] for item in analysis["top_failed_checks"]}

        self.assertEqual(len(kept & {f"critical-{i}" for i in range(30)}), 25)
        self.assertIn("high-check", kept)
        self.assertIn("medium-check", kept)


if __name__ == "__main__":
    unittest.main()
