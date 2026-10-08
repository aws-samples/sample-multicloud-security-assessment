"""Customer names must remain literal in generated Terraform."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_iac.py"


def generate_for(customer: str, directory: Path) -> Path:
    analysis = directory / "analysis.json"
    analysis.write_text(json.dumps({"metadata": {"customer": customer}}), encoding="utf-8")
    output = directory / "iac"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(analysis), "kms_rotation", str(output),
         "--provider", "aws"],
        capture_output=True, text=True,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return output


class CustomerNameLiteralTests(unittest.TestCase):
    def test_reported_customer_name(self):
        with tempfile.TemporaryDirectory() as temp:
            output = generate_for('Acme "${x}', Path(temp))
            self.assertIn(
                r'  default     = "acme-\"$${x}"',
                (output / "variables.tf").read_text(encoding="utf-8"),
            )
            self.assertIn(
                r'name_prefix = "acme-\"$${x}"',
                (output / "terraform.tfvars.example").read_text(encoding="utf-8"),
            )
            self.assertIn(
                r'    Customer    = "Acme \"$${x}"',
                (output / "locals.tf").read_text(encoding="utf-8"),
            )

    def test_customer_quotes_controls_and_template_markers(self):
        customer = 'Acme "${x} %{if true} C:\\root\n\t\b\f\x01\x85 $ %%{'
        expected_prefix = (
            r'"acme-\"$${x}-%%{if-true}-c:\\root\n\t\u0008\u000c\u0001\u0085-$-%%%{"'
        )
        expected_customer = (
            r'"Acme \"$${x} %%{if true} C:\\root\n\t\u0008\u000c\u0001\u0085 $ %%%{"'
        )

        with tempfile.TemporaryDirectory() as temp:
            output = generate_for(customer, Path(temp))
            variables = (output / "variables.tf").read_text(encoding="utf-8")
            tfvars = (output / "terraform.tfvars.example").read_text(encoding="utf-8")
            locals_tf = (output / "locals.tf").read_text(encoding="utf-8")
            resource = next(output.glob("*_aws_kms_rotation.tf")).read_text(encoding="utf-8")

            self.assertIn(f"  default     = {expected_prefix}\n", variables)
            self.assertIn(f"name_prefix = {expected_prefix}\n", tfvars)
            self.assertIn(f"    Customer    = {expected_customer}\n", locals_tf)
            self.assertTrue(resource.startswith(
                f"# {expected_customer[1:-1]} — KMS Key Rotation\n"
            ))
            for source in (variables, tfvars, locals_tf, resource):
                self.assertNotIn("\x01", source)
                self.assertNotIn("\x85", source)
                self.assertNotIn("\b", source)
                self.assertNotIn("\f", source)

    def test_ordinary_customer_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = generate_for("Example Customer", Path(temp))
            self.assertIn(
                '  default     = "example-customer"\n',
                (output / "variables.tf").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'name_prefix = "example-customer"\n',
                (output / "terraform.tfvars.example").read_text(encoding="utf-8"),
            )
            self.assertIn(
                '    Customer    = "Example Customer"\n',
                (output / "locals.tf").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
