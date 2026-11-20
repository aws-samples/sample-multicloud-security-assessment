"""Offline tests for scripts/check_prowler_permissions.py."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_prowler_permissions as cpp  # noqa: E402

UPSTREAM = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "*",
            "Action": ["bedrock:GetModel", "oam:GetSinkPolicy", "securityhub:BatchImportFindings"],
        },
        {
            "Effect": "Allow",
            "Action": ["apigateway:GET"],
            "Resource": ["arn:*:apigateway:*::/restapis/*", "arn:*:apigateway:*::/domainnames"],
        },
    ],
}

TEMPLATE_YAML = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ProwlerVersion:
    Type: String
    Default: "5.50.0"
Resources:
  ProwlerIntegrationCodeBuildRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ProwlerMemberRole
      ManagedPolicyArns:
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/SecurityAudit"
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/job-function/ViewOnlyAccess"
  ProwlerAdditionsPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Roles:
        - !Ref ProwlerIntegrationCodeBuildRole
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Resource: "*"
            Action:
              - bedrock:Get*
              - OAM:GetSinkPolicy
          - Effect: Allow
            Action:
              - securityhub:BatchImportFindings
            Resource: !Sub "arn:${AWS::Partition}:securityhub:*::product/prowler/prowler"
            Condition:
              StringEquals:
                securityhub:TargetAccount: !Sub "${AWS::AccountId}"
          - Effect: Allow
            Action:
              - apigateway:GET
            Resource:
              - !Sub arn:${AWS::Partition}:apigateway:*::/restapis/*
              - !Sub arn:${AWS::Partition}:apigateway:*::/domainnames
"""

EXCEPTIONS = {"securityhub:batchimportfindings": "scoped to the Prowler product"}


def load(text: str) -> dict:
    import yaml

    return yaml.load(text, Loader=cpp.CfnLoader)


def policy(template: dict) -> list:
    return template["Resources"]["ProwlerAdditionsPolicy"]["Properties"]["PolicyDocument"]["Statement"]


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.template = load(TEMPLATE_YAML)

    def run_check(self, templates=None, exceptions=EXCEPTIONS, upstream=UPSTREAM):
        if templates is None:
            templates = {Path("a.yaml"): self.template, Path("b.yaml"): copy.deepcopy(self.template)}
        return cpp.check(upstream, templates, exceptions)

    def test_covered_policy_passes(self):
        report = self.run_check()
        self.assertTrue(report.ok, report.errors)

    def test_wildcards_and_case_insensitive_actions(self):
        local = cpp.statement_grants(policy(self.template), template=True)
        self.assertTrue(cpp.grant_covers(local[0], cpp.Grant("bedrock:getmodel", "*")))
        self.assertIn(cpp.Grant("oam:getsinkpolicy", "*"), local)

    def test_missing_action_fails_with_suggestion(self):
        upstream = copy.deepcopy(UPSTREAM)
        upstream["Statement"][0]["Action"].append("inspector2:SearchVulnerabilities")
        report = self.run_check(upstream=upstream)
        self.assertFalse(report.ok)
        self.assertIn("inspector2:searchvulnerabilities on *", report.errors[0])
        self.assertIn("              - inspector2:SearchVulnerabilities", report.notes)
        self.assertEqual(report.notes.count("              - inspector2:SearchVulnerabilities"), 1)

    def test_missing_scoped_resource_fails(self):
        upstream = copy.deepcopy(UPSTREAM)
        upstream["Statement"][1]["Resource"].append("arn:*:apigateway:*::/domainnames/*")
        report = self.run_check(upstream=upstream)
        self.assertFalse(report.ok)
        self.assertIn("apigateway:get on arn:*:apigateway:*::/domainnames/*", report.errors[0])

    def test_conditional_grant_needs_exception(self):
        report = self.run_check(exceptions={})
        self.assertFalse(report.ok)
        self.assertIn("securityhub:batchimportfindings", report.errors[0])

    def test_drift_between_templates_fails(self):
        other = copy.deepcopy(self.template)
        policy(other)[0]["Action"].append("ssm:GetDocument")
        report = self.run_check(templates={Path("a.yaml"): self.template, Path("b.yaml"): other})
        self.assertTrue(any("differs between templates" in e for e in report.errors))

    def test_reordered_copy_is_not_drift(self):
        other = copy.deepcopy(self.template)
        policy(other)[0]["Action"].reverse()
        report = self.run_check(templates={Path("a.yaml"): self.template, Path("b.yaml"): other})
        self.assertTrue(report.ok, report.errors)

    def test_missing_managed_policy_fails(self):
        role = self.template["Resources"]["ProwlerIntegrationCodeBuildRole"]["Properties"]
        role["ManagedPolicyArns"] = role["ManagedPolicyArns"][:1]
        report = self.run_check(templates={Path("a.yaml"): self.template})
        self.assertTrue(any("ViewOnlyAccess" in e for e in report.errors))

    def test_stale_exceptions_fail(self):
        exceptions = dict(EXCEPTIONS, **{"oam:getsinkpolicy": "covered", "gone:action": "removed upstream"})
        report = self.run_check(exceptions=exceptions)
        self.assertTrue(any("oam:getsinkpolicy is fully granted" in e for e in report.errors))
        self.assertTrue(any("gone:action is no longer in the upstream" in e for e in report.errors))

    def test_version_must_be_pinned(self):
        self.assertEqual(cpp.prowler_version(self.template), "5.50.0")
        self.template["Parameters"]["ProwlerVersion"]["Default"] = "latest"
        with self.assertRaises(ValueError):
            cpp.prowler_version(self.template)

    def test_exception_requires_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exceptions.json"
            path.write_text(json.dumps({"exceptions": [{"action": "x:y", "reason": " "}]}))
            with self.assertRaises(ValueError):
                cpp.load_exceptions(path)


class RepositoryTemplateTests(unittest.TestCase):
    """Sanity checks on the real templates that need no network access."""

    def test_templates_parse_and_policies_match(self):
        templates = {p: cpp.load_template(p) for p in cpp.POLICY_TEMPLATES}
        canonical = {cpp.canonical_policy(cpp.policy_statements(t, p)) for p, t in templates.items()}
        self.assertEqual(len(canonical), 1, "ProwlerAdditionsPolicy copies differ")
        cpp.prowler_version(cpp.load_template(cpp.SCANNER_TEMPLATE))

    def test_exceptions_file_is_valid(self):
        self.assertIn("securityhub:batchimportfindings", cpp.load_exceptions(cpp.EXCEPTIONS_FILE))


if __name__ == "__main__":
    unittest.main()
