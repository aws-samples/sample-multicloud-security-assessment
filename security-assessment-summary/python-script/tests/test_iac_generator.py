"""Focused regression tests for generated Terraform."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_iac.py"


def run_generator(directory, provider, selections, customer="Example Customer", output=None):
    root = Path(directory)
    analysis = root / "analysis.json"
    analysis.write_text(json.dumps({"metadata": {"customer": customer}}), encoding="utf-8")
    destination = output or root / "iac"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(analysis), selections, str(destination),
         "--provider", provider],
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
                {"environment", "project_id", "region", "bucket_name"},
            )
            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            self.assertEqual(
                set(re.findall(r"^([a-z_]+)\s*=", tfvars, re.MULTILINE)),
                {"environment", "project_id", "region", "bucket_name"},
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


if __name__ == "__main__":
    unittest.main()
