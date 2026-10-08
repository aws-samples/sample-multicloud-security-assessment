# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regression coverage for severity phases beyond the top 20 checks."""

import sys
import tempfile
import unittest
from pathlib import Path

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import generate_pdf


class PdfPhaseTests(unittest.TestCase):
    def test_later_severities_appear_in_phases_and_risk_matrix(self):
        checks = [
            {
                "check_title": f"Critical check {number:02d}",
                "service": "S3",
                "severity": "critical",
                "count": 1,
            }
            for number in range(1, 21)
        ]
        checks.extend([
            {
                "check_title": "High check after criticals",
                "service": "IAM",
                "severity": "high",
                "count": 1,
            },
            {
                "check_title": "Medium check after criticals",
                "service": "EC2",
                "severity": "medium",
                "count": 1,
            },
        ])
        data = {
            "metadata": {"customer": "Acme", "providers": ["aws"]},
            "summary": {
                "findings_by_severity": {
                    "critical": 20, "high": 1, "medium": 1, "low": 0,
                },
                "security_score": 0,
                "total_checks": 22,
                "pass_count": 0,
                "fail_count": 22,
            },
            "top_failed_checks": checks,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "plan.pdf"
            generate_pdf.build_pdf(data, str(output_path))
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))
            if PdfReader is None:
                return
            pages = [page.extract_text() for page in PdfReader(output_path).pages]

        top_table = next(page for page in pages if "Top Failed Security Checks" in page)
        phase_2 = next(page for page in pages if "4. Phase 2:" in page)
        phase_3 = next(page for page in pages if "5. Phase 3:" in page)
        risk_matrix = next(page for page in pages if "7. Risk Matrix" in page)

        self.assertIn("Critical check 15", top_table)
        self.assertNotIn("Critical check 16", top_table)
        self.assertIn("High check after criticals", phase_2)
        self.assertIn("Medium check after criticals", phase_3)
        self.assertNotIn("No findings at this severity.", phase_2)
        self.assertNotIn("No findings at this severity.", phase_3)
        for label, count in (("Critical", 20), ("High", 1), ("Medium", 1)):
            self.assertRegex(risk_matrix, rf"{label}\s+{count}\b")


if __name__ == "__main__":
    unittest.main()
