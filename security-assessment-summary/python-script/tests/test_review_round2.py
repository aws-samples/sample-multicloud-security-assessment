# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regressions for the 2026-10-09 full-folder review (round 2): generated Terraform
must not lock out, widen access, or weaken the environment on apply/rollback; partial
results must be visible; output writes must not be redirectable; anonymization must
cover identifiers embedded in resource IDs."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer
import generate_dashboard
import generate_iac
import generate_readme
import safe_io

IAC = SCRIPTS_DIR / "generate_iac.py"
ANALYZER = SCRIPTS_DIR / "analyze_security_data.py"


def gen(directory, provider, selections, output=None, *extra):
    root = Path(directory)
    analysis = root / "analysis.json"
    analysis.write_text(json.dumps({"metadata": {"customer": "Example Customer"}}), encoding="utf-8")
    out = output or root / "iac"
    result = subprocess.run([sys.executable, str(IAC), str(analysis), selections, str(out),
                             "--provider", provider, *extra], capture_output=True, text=True)
    return result, out


def module(out, key):
    return next(out.glob(f"*_{key}.tf")).read_text(encoding="utf-8")


def var_block(out, name):
    text = (out / "variables.tf").read_text(encoding="utf-8")
    return re.search(rf'variable "{name}" \{{.*?\n\}}', text, re.S).group(0)


class GeneratedTerraformSafetyTests(unittest.TestCase):
    def test_entra_ca_is_report_only_with_break_glass_exclusions(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "azure", "entra_mfa")
            self.assertEqual(r.returncode, 0, r.stderr)
            body = module(out, "entra_mfa")
            self.assertIn("state        = var.conditional_access_state", body)
            self.assertNotIn('state        = "enabled"', body)
            self.assertNotIn('client_app_types = ["all"]', body)
            self.assertIn("excluded_users  = var.ca_excluded_user_ids", body)
            self.assertIn("precondition", body)
            self.assertIn('default     = "enabledForReportingButNotEnforced"',
                          var_block(out, "conditional_access_state"))
            # Group-only break-glass is allowed; the precondition enforces "user OR group".
            self.assertIn("length(var.ca_excluded_user_ids) + length(var.ca_excluded_group_ids) > 0", body)

    def test_gcp_firewall_denies_internet_and_scopes_allow_to_tags(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "gcp", "firewall_restrict")
            self.assertEqual(r.returncode, 0, r.stderr)
            body = module(out, "firewall_restrict")
            self.assertIn("deny {", body)
            # Both rules are scoped to tagged VMs; untagged VMs (and internal traffic to
            # them) are unaffected. RDP is allowed from the trusted ranges too.
            self.assertEqual(body.count("target_tags   = var.mgmt_target_tags"), 2)
            self.assertIn('ports    = ["22", "3389"]', body)
            cidrs = var_block(out, "allowed_mgmt_cidrs")
            self.assertNotIn("  default     =", cidrs)
            self.assertIn('c != "0.0.0.0/0"', cidrs)

    def test_oci_security_list_is_port_scoped(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "oci", "security_lists")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("tcp_options", module(out, "security_lists"))

    def test_sql_tde_requires_cmk_and_cannot_be_destroyed(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "azure", "disk_sql_encryption")
            self.assertEqual(r.returncode, 0, r.stderr)
            body = module(out, "disk_sql_encryption")
            self.assertIn("key_vault_key_id      = var.tde_key_vault_key_id", body)
            self.assertIn("prevent_destroy = true", body)

    def test_account_wide_aws_takeovers_are_opt_in_and_protected(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "aws", "s3_public_access,encryption_at_rest")
            self.assertEqual(r.returncode, 0, r.stderr)
            s3 = module(out, "s3_public_access")
            ebs = module(out, "encryption_at_rest")
            self.assertIn("count                   = var.manage_account_public_access_block ? 1 : 0", s3)
            self.assertIn("count  = var.manage_bucket_sse ? 1 : 0", s3)
            self.assertIn("count   = var.manage_ebs_default_encryption ? 1 : 0", ebs)
            self.assertEqual(s3.count("prevent_destroy = true"), 3)
            self.assertEqual(ebs.count("prevent_destroy = true"), 2)
            for name in ("manage_account_public_access_block", "manage_bucket_sse",
                         "manage_ebs_default_encryption"):
                self.assertNotIn("  default     =", var_block(out, name))

    def test_identity_mfa_is_not_offered_where_mfa_is_not_enforced(self):
        self.assertEqual(generate_iac.normalize_selection(
            "identity_mfa", "gcp", generate_iac.REMEDIATION_CATALOG["gcp"]), "")
        self.assertEqual(generate_iac.normalize_selection(
            "identity_mfa", "oci", generate_iac.REMEDIATION_CATALOG["oci"]), "")
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "gcp", "iam_least_privilege")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("length(var.permissions) > 0", var_block(out, "permissions"))


class IaCCleanupTests(unittest.TestCase):
    def test_edited_generated_file_is_refused_then_backed_up_with_force(self):
        with tempfile.TemporaryDirectory() as d:
            r, out = gen(d, "aws", "kms_rotation,iam_mfa")
            self.assertEqual(r.returncode, 0, r.stderr)
            edited = next(out.glob("*_iam_mfa.tf"))
            edited.write_text(edited.read_text(encoding="utf-8") + "\n# operator edit\n",
                              encoding="utf-8")
            untouched = next(out.glob("*_kms_rotation.tf"))
            # Without --force: refused and NOTHING changes (conflict check runs first).
            r, _ = gen(d, "aws", "flow_logs", out)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("edited since the last run", r.stderr)
            self.assertTrue(edited.exists() and untouched.exists())
            # With --force: edited file moved to backup, unmodified stale file removed.
            r, _ = gen(d, "aws", "flow_logs", out, "--force")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(edited.exists())
            self.assertFalse(untouched.exists())
            backups = list((out / ".cloud-sec-assessment-backup").rglob(edited.name))
            self.assertEqual(len(backups), 1)
            self.assertIn("# operator edit", backups[0].read_text(encoding="utf-8"))

    def test_planted_terraform_files_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iac"
            out.mkdir()
            planted = out / "backdoor.tf"
            planted.write_text('data "external" "x" { program = ["sh"] }\n', encoding="utf-8")
            (out / "zz.auto.tfvars").write_text('manage_bucket_sse = true\n', encoding="utf-8")
            r, _ = gen(d, "aws", "kms_rotation", out)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("backdoor.tf", r.stderr)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["backdoor.tf", "zz.auto.tfvars"])
            # --force quarantines them instead of leaving them for terraform to load.
            r, _ = gen(d, "aws", "kms_rotation", out, "--force")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(planted.exists())
            self.assertEqual(len(list((out / ".cloud-sec-assessment-backup").rglob("backdoor.tf"))), 1)

    def test_hand_written_module_named_file_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iac"
            out.mkdir()
            mine = out / "Example_Customer_aws_iam_mfa.tf"
            mine.write_text("# operator-owned\n", encoding="utf-8")
            r, _ = gen(d, "aws", "iam_mfa", out)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(mine.read_text(encoding="utf-8"), "# operator-owned\n")

    def test_symlinked_output_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "elsewhere"
            real.mkdir()
            link = Path(d) / "iac"
            link.symlink_to(real, target_is_directory=True)
            r, _ = gen(d, "aws", "kms_rotation", link)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(list(real.iterdir()), [])


class ReadmeRollbackTests(unittest.TestCase):
    def test_readme_documents_targeted_rollback_not_destroy(self):
        data = {"metadata": {"customer": "Acme", "providers": ["aws"]},
                "summary": {"total_checks": 1, "security_score": 50,
                            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                            "findings_by_service": {}}}
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "Acme_README.md"
            generate_readme.generate_readme(data, str(out))
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("```bash\nterraform destroy\n```", text)
            self.assertIn("Do not use `terraform destroy` to roll back", text)
            self.assertIn("aws s3control get-public-access-block", text)


MAIN_CSV = ("STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;PROVIDER;RESOURCE_UID\n"
            "FAIL;High;fail-check;S3;111122223333;aws;arn:aws:s3:::bucket\n")


def run_analyzer(*args):
    return subprocess.run([sys.executable, str(ANALYZER), *map(str, args)],
                          capture_output=True, text=True)


class PartialResultsVisibilityTests(unittest.TestCase):
    DATA = {"metadata": {"customer": "Acme", "providers": ["aws"],
                         "input_limits_applied": ["oversized input file skipped"]},
            "summary": {"total_checks": 1, "pass_count": 0, "fail_count": 1, "security_score": 50,
                        "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                        "findings_by_service": {}}}

    def test_dashboard_and_readme_show_partial_results(self):
        with tempfile.TemporaryDirectory() as d:
            html_path = Path(d) / "dash.html"
            generate_dashboard.generate_html(self.DATA, str(html_path))
            html = html_path.read_text(encoding="utf-8")
            self.assertIn('id="partial-results"', html)
            self.assertIn("oversized input file skipped", html)
            md = Path(d) / "Acme_README.md"
            generate_readme.generate_readme(self.DATA, str(md))
            self.assertIn("PARTIAL RESULTS", md.read_text(encoding="utf-8"))

    def test_complete_results_show_no_banner(self):
        data = json.loads(json.dumps(self.DATA))
        data["metadata"]["input_limits_applied"] = []
        with tempfile.TemporaryDirectory() as d:
            html_path = Path(d) / "dash.html"
            generate_dashboard.generate_html(data, str(html_path))
            self.assertNotIn('id="partial-results"', html_path.read_text(encoding="utf-8"))


class AnalyzerInputTests(unittest.TestCase):
    def test_customer_folder_named_assessment_summary_is_still_read(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "scan" / "assessment-summary-q3"
            inp.mkdir(parents=True)
            (inp / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            out = Path(d) / "analysis.json"
            r = run_analyzer(inp.parent, out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["summary"]["fail_count"], 1)

    def test_deep_path_is_recorded_as_partial(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "scan"
            deep = inp / "a" / "b" / "c"
            deep.mkdir(parents=True)
            (inp / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            (deep / "more.csv").write_text(MAIN_CSV, encoding="utf-8")
            out = Path(d) / "analysis.json"
            original = analyzer.MAX_RECURSION_DEPTH
            analyzer.MAX_RECURSION_DEPTH = 2
            argv = sys.argv
            sys.argv = ["analyze_security_data.py", str(inp), str(out)]
            try:
                analyzer.main()
            finally:
                analyzer.MAX_RECURSION_DEPTH = original
                sys.argv = argv
            limits = json.loads(out.read_text(encoding="utf-8"))["metadata"]["input_limits_applied"]
            self.assertTrue(any("folder levels" in item for item in limits), limits)

    def test_symlinked_default_output_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "aws"
            inp.mkdir()
            (inp / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            target = Path(d) / "attacker"
            target.mkdir()
            (inp / "assessment-summary-aws").symlink_to(target, target_is_directory=True)
            r = run_analyzer(inp)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("symlink", r.stderr)
            self.assertEqual(list(target.iterdir()), [])

    def test_anon_map_dir_inside_deliverables_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "scan"
            inp.mkdir()
            (inp / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            out_dir = Path(d) / "deliverables"
            r = run_analyzer(inp, out_dir / "analysis.json", "--anonymize",
                             "--anon-map-dir", out_dir / "keys")
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse((out_dir / "analysis.json").exists())

    def test_azure_subscription_in_resource_id_is_masked(self):
        sub = "0f0e0d0c-1111-2222-3333-444455556666"
        csv_text = ("STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;PROVIDER;RESOURCE_UID\n"
                    f"FAIL;High;storage-check;Storage;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;azure;"
                    f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Storage/x\n")
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "scan"
            inp.mkdir()
            (inp / "main.csv").write_text(csv_text, encoding="utf-8")
            out = Path(d) / "out" / "analysis.json"
            r = run_analyzer(inp, out, "--anonymize", "--anon-map-dir", Path(d) / "keys")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(sub, out.read_text(encoding="utf-8"))

    def test_gcp_project_in_any_field_is_masked_and_swept(self):
        findings = [{"PROVIDER": "gcp", "RESOURCE_UID": "", "STATUS_EXTENDED":
                     "Bucket projects/acme-prod-123/buckets/b is public"}]
        ids = analyzer.extract_embedded_scope_ids(findings)
        self.assertIn("acme-prod-123", ids)

    def test_gcp_pattern_ignores_doc_urls_and_other_providers(self):
        doc = "See https://cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding"
        self.assertEqual(analyzer._gcp_project_ids(doc), set())
        self.assertEqual(analyzer._gcp_project_ids(
            "https://www.googleapis.com/compute/v1/projects/acme-prod-123/zones/z"),
            {"acme-prod-123"})
        self.assertEqual(analyzer.extract_embedded_scope_ids(
            [{"PROVIDER": "aws", "RISK": "Bucket projects/acme-prod-123/x"}]), set())
        self.assertNotIn("locations", analyzer._gcp_project_ids("x/projects/locations/y"))
        self.assertEqual(analyzer.verify_anonymization({"a": "projects/acme-prod-123/x"}, {}),
                         ["acme-prod-123"])

    def test_stamped_anon_map_is_not_ingested(self):
        self.assertTrue(analyzer._should_skip_file(
            Path("/x/anon_map_aws_20261009T000000_1.json"), [], Path("/x"), False))


class SafeIoTests(unittest.TestCase):
    def test_hard_link_target_is_not_truncated(self):
        if os.name != "posix":
            self.skipTest("hard links")
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / "victim.txt"
            victim.write_text("keep me", encoding="utf-8")
            out = Path(d) / "out"
            out.mkdir()
            os.link(victim, out / "analysis.json")
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.open_write_nofollow(str(out / "analysis.json"), root=str(out))
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me")

    def test_no_directories_created_through_symlinked_subfolder(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "out"
            root.mkdir()
            outside = Path(d) / "outside"
            outside.mkdir()
            (root / "reports").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.open_write_nofollow(str(root / "reports" / "deep" / "x.html"), root=str(root))
            self.assertEqual(list(outside.iterdir()), [])


class ChartLabelTests(unittest.TestCase):
    def test_dollar_signs_in_labels_render_literally(self):
        try:
            import generate_charts
        except SystemExit:
            self.skipTest("matplotlib unavailable")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "svc.png"
            generate_charts.generate_service_bar({"$\\invalid{$": 3, "S3": 1}, str(out))
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
