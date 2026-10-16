# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regressions for the 2026-10-16 security scan of 609ba25: planted Terraform state and
backup-folder symlinks in the IaC output, quadratic GCP anonymization, legacy chart
names, generic output-folder signatures, and scan code / raw paths in the agent docs."""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer
import generate_iac
import generate_pdf
from test_review_round2 import gen


class PlantedTerraformStateTests(unittest.TestCase):
    def test_state_and_lock_files_are_terraform_loaded(self):
        for name in ("terraform.tfstate", "terraform.tfstate.backup", "x.tfstate",
                     "terraform.tfstate.d", ".terraform.lock.hcl"):
            self.assertTrue(generate_iac._terraform_loads(name), name)

    def test_planted_state_is_refused_then_quarantined_with_force(self):
        for name, is_dir in (("terraform.tfstate", False), (".terraform.lock.hcl", False),
                             ("terraform.tfstate.d", True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                out = Path(d) / "iac"
                out.mkdir()
                planted = out / name
                if is_dir:
                    planted.mkdir()
                else:
                    planted.write_text("{}", encoding="utf-8")
                r, _ = gen(d, "aws", "kms_rotation", out)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(name, r.stderr)
                self.assertFalse(list(out.glob("*.tf")))
                r, _ = gen(d, "aws", "kms_rotation", out, "--force")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse(os.path.lexists(planted))


class BackupFolderSymlinkTests(unittest.TestCase):
    def test_symlinked_backup_folder_is_refused_before_moving_anything(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        with tempfile.TemporaryDirectory() as d:
            outside = Path(d) / "outside"
            outside.mkdir()
            out = Path(d) / "iac"
            out.mkdir()
            handwritten = out / "providers.tf"
            handwritten.write_text("# operator file\n", encoding="utf-8")
            (out / ".cloud-sec-assessment-backup").symlink_to(outside)
            r, _ = gen(d, "aws", "kms_rotation", out, "--force")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(".cloud-sec-assessment-backup", r.stderr)
            self.assertEqual(handwritten.read_text(encoding="utf-8"), "# operator file\n")
            self.assertEqual(list(outside.iterdir()), [])


class GcpAnonymizationTests(unittest.TestCase):
    def test_lookback_is_not_quadratic(self):
        text = " ".join(f"http://x/projects/ab-{i:05d}/" for i in range(40000))
        start = time.monotonic()
        self.assertEqual(analyzer._gcp_project_ids(text), set())
        self.assertLess(time.monotonic() - start, 5)

    def test_api_links_still_match_and_doc_links_do_not(self):
        text = ('"https://compute.googleapis.com/compute/v1/projects/prod-123/zones/a" '
                '"https://cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding" '
                '"projects/dev-42/locations/x"')
        self.assertEqual(analyzer._gcp_project_ids(text), {"prod-123", "dev-42"})


class OutputFolderSignatureTests(unittest.TestCase):
    def test_readme_alone_does_not_mark_a_folder_as_output(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / "assessment-summary-2026"
            folder.mkdir()
            (folder / "Prowler_README.md").write_text("x", encoding="utf-8")
            scan = folder / "main.csv"
            scan.write_text("x", encoding="utf-8")
            self.assertFalse(analyzer._has_tool_artifacts(folder))
            self.assertFalse(analyzer._is_generated_output_file(scan, Path(d)))


class LegacyChartNameTests(unittest.TestCase):
    def test_pdf_ignores_legacy_chart_names(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "sev_donut.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            self.assertIsNone(generate_pdf._chart(d, "severity_donut"))

    def test_pptx_has_no_legacy_chart_fallback(self):
        js = (SCRIPTS_DIR / "generate_pptx.js").read_text(encoding="utf-8")
        self.assertNotIn("sev_donut", js)
        self.assertNotIn("svc_bar", js)


class AgentDocTests(unittest.TestCase):
    def test_quick_skill_never_puts_scan_code_in_the_deck(self):
        skill = (ROOT / "quick-skill" / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("with CLI/Terraform snippets", skill)
        self.assertNotIn("remediation_cli", skill)
        self.assertNotIn("remediation_iac", skill)

    def test_kiro_agent_never_pastes_paths_into_commands(self):
        agent = (ROOT / "kiro-agent" / "agent.md").read_text(encoding="utf-8")
        self.assertNotIn('"<input_folder>"', agent)
        self.assertNotIn('"<output_dir>/', agent)
        self.assertNotIn("'<output_dir>/", agent)
        self.assertNotIn('mkdir -p "', agent)


if __name__ == "__main__":
    unittest.main()
