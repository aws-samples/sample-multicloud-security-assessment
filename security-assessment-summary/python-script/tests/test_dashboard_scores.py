# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Score regressions for dashboards containing unassessed findings."""

import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import generate_dashboard as dashboard


def finding(status, severity="Info"):
    return {
        "status": status,
        "severity": severity,
        "scope_id": "account-1",
        "service": "S3",
        "region": "us-east-1",
    }


def render_dashboard(summary, findings):
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "dashboard.html"
        dashboard.generate_html(
            {
                "metadata": {},
                "summary": summary,
                "dashboard_findings": findings,
            },
            str(output_path),
        )
        return output_path.read_text(encoding="utf-8")


class DashboardScoreTests(unittest.TestCase):
    def test_all_manual_preserves_precomputed_zero_in_html(self):
        findings = [finding("MANUAL") for _ in range(3)]
        rendered = render_dashboard(
            {"security_score": 0, "total_checks": len(findings)}, findings
        )
        fallback_rendered = render_dashboard({"total_checks": len(findings)}, findings)

        self.assertIn('<span class="score-value score-low">0%</span>', rendered)
        self.assertNotIn('<span class="score-value score-high">100.0%</span>', rendered)
        self.assertIn(
            '<span class="score-value score-low">0.0%</span>', fallback_rendered
        )

    def test_precomputed_zero_is_not_replaced_by_pass_only_fallback(self):
        rendered = render_dashboard(
            {"security_score": 0, "total_checks": 1}, [finding("PASS")]
        )

        self.assertIn('<span class="score-value score-low">0%</span>', rendered)

    def test_missing_score_fallback_ignores_unassessed_statuses(self):
        findings = [
            finding("PASSED"),
            finding("FAILED", "Critical"),
            finding("MANUAL"),
            finding("INFO"),
            finding("MUTED"),
        ]
        for summary in ({}, {"security_score": None}):
            with self.subTest(summary=summary):
                rendered = render_dashboard(summary, findings)
                self.assertIn(
                    '<span class="score-value score-medium">50.0%</span>',
                    rendered,
                )
        self.assertEqual(dashboard._compute_security_score([finding("MANUAL")]), 0.0)
        self.assertEqual(dashboard._compute_security_score([]), 0.0)
        self.assertEqual(dashboard._compute_risk_score([]), 0.0)

    def test_critical_fail_and_99_manual_have_full_group_risk(self):
        findings = [finding("FAIL", "Critical")] + [
            finding("MANUAL") for _ in range(99)
        ]

        self.assertEqual(dashboard._compute_security_score(findings), 0.0)
        self.assertEqual(dashboard._compute_risk_score(findings), 100.0)

        account = dashboard._compute_per_account_stats(findings)[0]
        service = dashboard._compute_per_service_stats(findings)[0]
        region = dashboard._compute_per_region_stats(findings)[0]
        for group in (account, service, region):
            with self.subTest(group=group):
                self.assertEqual(group["total"], 100)
                self.assertEqual(group["failed"], 1)
                self.assertEqual(group["risk_score"], 100.0)
        self.assertEqual(account["manual"], 99)
        self.assertEqual(account["pass_rate"], 0.0)
        self.assertEqual(service["failure_rate"], 100.0)

    def test_rates_and_risk_use_pass_fail_denominator(self):
        findings = [
            finding("PASS"),
            finding("FAIL", "Critical"),
            finding("MANUAL"),
            finding("INFO"),
            finding("MUTED"),
        ]

        self.assertEqual(dashboard._compute_security_score(findings), 50.0)
        self.assertEqual(dashboard._compute_risk_score(findings), 50.0)
        self.assertEqual(
            dashboard._compute_per_account_stats(findings)[0]["pass_rate"], 50.0
        )
        self.assertEqual(
            dashboard._compute_per_service_stats(findings)[0]["failure_rate"], 50.0
        )
        self.assertEqual(
            dashboard._compute_per_region_stats(findings)[0]["risk_score"], 50.0
        )


if __name__ == "__main__":
    unittest.main()
