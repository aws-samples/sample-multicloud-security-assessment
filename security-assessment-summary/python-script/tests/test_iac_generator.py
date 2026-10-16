# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Focused regression tests for generated Terraform."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_iac.py"


def run_generator(directory, provider, selections, customer="Example Customer", output=None,
                  extra=()):
    root = Path(directory)
    analysis = root / "analysis.json"
    analysis.write_text(json.dumps({"metadata": {"customer": customer}}), encoding="utf-8")
    destination = output or root / "iac"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(analysis), selections, str(destination),
         "--provider", provider, *extra],
        capture_output=True, text=True,
    )
    return result, destination


class IaCGeneratorTests(unittest.TestCase):
    def test_kms_only_declares_only_referenced_variables(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "kms_rotation")
            self.assertEqual(result.returncode, 0, result.stderr)

            variables = (output / "variables.tf").read_text(encoding="utf-8")
            declared = set(re.findall(r'variable "([^"]+)"', variables))
            self.assertEqual(declared, {"environment", "name_prefix", "region"})

            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            examples = set(re.findall(r"^([a-z_]+)\s*=", tfvars, re.MULTILINE))
            self.assertEqual(examples, declared)
            self.assertTrue((output / "Example_Customer_aws_kms_rotation.tf").exists())

    def test_gcp_bucket_labels_normalize_customer_and_environment(self):
        customer = "ACME Customer!" + ("X" * 80)
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(
                directory, "gcp", "gcs_public_access", customer=customer
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            locals_tf = (output / "locals.tf").read_text(encoding="utf-8")
            self.assertIn(
                'environment = substr(replace(lower(var.environment), '
                '"/[^a-z0-9_-]/", "_"), 0, 63)',
                locals_tf,
            )
            literal_labels = dict(re.findall(r'^\s+([a-z_]+)\s+=\s+"([^"]*)"$',
                                             locals_tf, re.MULTILINE))
            self.assertEqual(
                literal_labels,
                {
                    "managed_by": "terraform",
                    "purpose": "security_remediation",
                    "customer": ("acme_customer_" + ("x" * 80))[:63],
                },
            )
            for key, value in literal_labels.items():
                self.assertRegex(key, r"^[a-z][a-z0-9_-]{0,62}$")
                self.assertRegex(value, r"^[a-z0-9_-]{0,63}$")
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            self.assertEqual(
                set(re.findall(r'variable "([^"]+)"', variables)),
                {"environment", "project_id", "region", "bucket_name", "gcs_access_log_bucket"},
            )
            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            self.assertEqual(
                set(re.findall(r"^([a-z_]+)\s*=", tfvars, re.MULTILINE)),
                {"environment", "project_id", "region", "bucket_name", "gcs_access_log_bucket"},
            )

    def test_unknown_selection_fails_without_touching_prior_output(self):
        with tempfile.TemporaryDirectory() as directory:
            success, output = run_generator(directory, "aws", "kms_rotation")
            self.assertEqual(success.returncode, 0, success.stderr)
            (output / "keep.txt").write_text("untouched", encoding="utf-8")
            before = {path.name: path.read_bytes() for path in output.iterdir()}

            failure, _ = run_generator(directory, "aws", "kms_rotation,nonexistent",
                                       output=output)
            self.assertNotEqual(failure.returncode, 0)
            self.assertIn("nonexistent", failure.stderr)
            self.assertEqual(
                {path.name: path.read_bytes() for path in output.iterdir()}, before
            )

            absent = Path(directory) / "new-output"
            failure, _ = run_generator(directory, "aws", "kms_rotation,nonexistent",
                                       output=absent)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse(absent.exists())

    def test_cleanup_preserves_handwritten_files(self):
        # A hand-written providers.tf (same name as a generator shared file) must survive
        # a regeneration — only files recorded in the generator's manifest are removed.
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "security_groups,audit_logging")
            self.assertEqual(result.returncode, 0, result.stderr)
            handwritten = output / "operator_extra.tf"
            handwritten.write_text("# operator's own module", encoding="utf-8")

            # Without acknowledgement, an unknown Terraform file is refused (it could be
            # planted); the operator explicitly keeps their own with the flag.
            refused, _ = run_generator(directory, "aws", "security_groups", output=output)
            self.assertNotEqual(refused.returncode, 0)
            # Re-run with a reduced selection; audit_logging should be cleaned up.
            result2, _ = run_generator(directory, "aws", "security_groups", output=output,
                                       extra=("--keep-existing-terraform",))
            self.assertEqual(result2.returncode, 0, result2.stderr)
            self.assertTrue(handwritten.exists(), "hand-written file must be preserved")
            self.assertFalse((output / "Example_Customer_aws_audit_logging.tf").exists(),
                             "stale generated file should be removed")
            self.assertTrue((output / "Example_Customer_aws_security_groups.tf").exists())

    def test_azure_nsg_deny_is_high_priority_and_targeted(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "azure", "network_ingress")
            self.assertEqual(result.returncode, 0, result.stderr)
            nsg = next(output.glob("*nsg_restrict.tf")).read_text(encoding="utf-8")
            self.assertIn("priority                   = 100", nsg)
            self.assertNotIn("priority                   = 4096", nsg)
            self.assertIn('source_address_prefix      = "Internet"', nsg)

    def test_aws_flow_logs_retention_and_kms(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "flow_logs")
            self.assertEqual(result.returncode, 0, result.stderr)
            flow = (output / "Example_Customer_aws_flow_logs.tf").read_text(encoding="utf-8")
            self.assertIn("retention_in_days = var.log_retention_days", flow)
            self.assertIn("kms_key_id = var.log_kms_key_arn", flow)
            self.assertNotIn("retention_in_days = 14", flow)
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            # CIS-compliant default retention (>= 90) must be present and unquoted.
            self.assertRegex(variables, r"default\s*=\s*365")

    def test_refuses_to_overwrite_handwritten_shared_file(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "iac"
            out.mkdir()
            handwritten = out / "providers.tf"
            handwritten.write_text("# operator's own providers", encoding="utf-8")

            # Without --force: must refuse and leave the hand-written file intact.
            result, _ = run_generator(directory, "aws", "kms_rotation", output=out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to overwrite", result.stderr)
            self.assertEqual(handwritten.read_text(encoding="utf-8"),
                             "# operator's own providers")

    def test_force_overwrites_handwritten_shared_file(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "iac"
            out.mkdir()
            analysis = Path(directory) / "analysis.json"
            analysis.write_text(json.dumps({"metadata": {"customer": "Example Customer"}}),
                                encoding="utf-8")
            (out / "providers.tf").write_text("# operator's own providers", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(analysis), "kms_rotation", str(out),
                 "--provider", "aws", "--force"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("AUTO-GENERATED", (out / "providers.tf").read_text(encoding="utf-8"))

    def test_s3_module_has_tls_only_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "object_storage_public_access")
            self.assertEqual(result.returncode, 0, result.stderr)
            s3 = next(output.glob("*s3_public_access.tf")).read_text(encoding="utf-8")
            self.assertIn("DenyInsecureTransport", s3)
            self.assertIn('variable = "aws:SecureTransport"', s3)
            self.assertIn('values   = ["false"]', s3)

    def test_cloudtrail_bucket_is_hardened(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "audit_logging")
            self.assertEqual(result.returncode, 0, result.stderr)
            ct = next(output.glob("*audit_logging.tf")).read_text(encoding="utf-8")
            self.assertIn("aws_s3_bucket_versioning", ct)
            self.assertIn("aws_s3_bucket_object_lock_configuration", ct)
            self.assertIn("DenyInsecureTransport", ct)
            self.assertIn("AWSCloudTrailWrite", ct)
            self.assertIn("aws_s3_bucket_public_access_block", ct)


class ReviewFixIaCTests(unittest.TestCase):
    """Regressions for the 2026-10-09 review: generated Terraform must not break an
    existing customer environment when applied."""

    def _read(self, output, pattern):
        return next(output.glob(pattern)).read_text(encoding="utf-8")

    def test_s3_tls_policy_merges_existing_policy_and_is_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "s3_public_access")
            self.assertEqual(result.returncode, 0, result.stderr)
            s3 = self._read(output, "*s3_public_access.tf")
            self.assertIn("source_policy_documents", s3)
            self.assertIn("var.existing_bucket_policy_json", s3)
            self.assertIn("count  = var.enforce_tls_bucket_policy ? 1 : 0", s3)
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            block = re.search(r'variable "enforce_tls_bucket_policy" \{[^}]*\}', variables).group(0)
            self.assertNotIn("default", block)  # explicit decision, no default
            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            self.assertIn("REPLACES the bucket policy", tfvars)

    def test_egress_is_required_decision_with_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "security_groups")
            self.assertEqual(result.returncode, 0, result.stderr)
            sg = self._read(output, "*security_groups.tf")
            self.assertIn("cidr_blocks = var.allowed_egress_cidrs", sg)
            self.assertNotIn("10.0.0.0/8", sg)
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            block = re.search(r'variable "allowed_egress_cidrs" \{[^}]*\}', variables).group(0)
            self.assertNotIn("default", block)
            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            line = next(l for l in tfvars.splitlines() if l.startswith("allowed_egress_cidrs"))
            self.assertIn("REQUIRED", line)
            self.assertIn("AWS public endpoints", line)

    def test_cloudtrail_bucket_create_or_existing_and_source_conditions(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_generator(directory, "aws", "audit_logging")
            self.assertEqual(result.returncode, 0, result.stderr)
            trail = self._read(output, "*audit_logging.tf")
            # Every bucket-managing resource is conditional on create_log_bucket.
            for res in ("aws_s3_bucket", "aws_s3_bucket_versioning",
                        "aws_s3_bucket_object_lock_configuration",
                        "aws_s3_bucket_policy"):
                body = re.search(rf'resource "{res}" "trail_logs" \{{(.*?)\n\}}', trail, re.S).group(1)
                self.assertIn("count", body, res)
            self.assertIn("s3_bucket_name                = var.log_bucket_name", trail)
            self.assertEqual(trail.count('"aws:SourceArn"     = local.cloudtrail_arn'), 2)
            self.assertEqual(trail.count('"aws:SourceAccount"'), 2)
            self.assertIn("/AWSLogs/${data.aws_caller_identity.trail.account_id}/*", trail)
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            self.assertIn("must not exist", variables.replace("NOT", "not"))

    def test_rerun_over_pre_manifest_output_replaces_legacy_files(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "iac"
            out.mkdir()
            # Simulate an older generator version: generated headers, no manifest.
            (out / "providers.tf").write_text(
                "# \u26a0\ufe0f  AUTO-GENERATED \u2014 REVIEW BEFORE DEPLOY\nold\n", encoding="utf-8")
            (out / "variables.tf").write_text(
                "# Shared variable declarations for all remediation modules in this directory.\n",
                encoding="utf-8")
            stale = out / "Example_Customer_aws_iam_mfa.tf"
            stale.write_text("# Example Customer \u2014 IAM\n# x\n"
                             "# Variables are declared in variables.tf; providers/locals are shared.\n",
                             encoding="utf-8")
            hand = out / "my_network.tf"
            hand.write_text("# operator-owned\n", encoding="utf-8")
            result, _ = run_generator(directory, "aws", "kms_rotation", output=out,
                                      extra=("--keep-existing-terraform",))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(stale.exists(), "stale legacy module must be cleaned up")
            self.assertIn("AUTO-GENERATED", (out / "providers.tf").read_text(encoding="utf-8"))
            self.assertTrue(hand.exists(), "unrelated hand-written file must be kept")
            self.assertTrue((out / ".cloud-sec-assessment-manifest.json").exists())

    def test_hand_written_shared_file_still_refused_without_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "iac"
            out.mkdir()
            (out / "providers.tf").write_text("# mine\n", encoding="utf-8")
            result, _ = run_generator(directory, "aws", "kms_rotation", output=out)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((out / "providers.tf").read_text(encoding="utf-8"), "# mine\n")


if __name__ == "__main__":
    unittest.main()
