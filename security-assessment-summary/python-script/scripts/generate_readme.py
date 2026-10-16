#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
generate_readme.py — Generate a customer README tying all deliverables together.

Terraform is the single IaC language for all clouds; terminology and validation
steps adapt to the detected provider(s).

Usage:
    python3 generate_readme.py <analysis_json> <output_readme_path>
"""

import argparse
import json
import os
import re
import sys
from providers import PROVIDER_LABELS as PROVIDER_LABEL, PROVIDER_SCOPE_TERM as SCOPE_TERM, PROVIDER_CLI
import safe_io


def _md(value) -> str:
    """Escape an untrusted (scan-derived) value for safe inclusion in Markdown.

    Scan data (service names, scope ids, customer name, framework names) is untrusted:
    a value containing a pipe would break out of a Markdown table cell, and raw HTML
    (`<img onerror=...>`, `<script>`) would execute when the Markdown is rendered to
    HTML. We therefore:
      * escape HTML metacharacters (& < > ") so no raw HTML/script survives rendering,
      * escape Markdown table/structural metacharacters (| ` * _ [ ] and newlines) so
        the value stays confined to its cell and can't inject markup.
    """
    text = str(value)
    # HTML metacharacters first (so we don't double-escape the & we introduce).
    text = (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
    # Markdown structural metacharacters.
    text = text.replace("\\", "\\\\")
    for ch in ("|", "`", "*", "_", "[", "]", "{", "}", "#"):
        text = text.replace(ch, "\\" + ch)
    # Collapse newlines/CRs so a value can't start a new table row or break layout.
    text = text.replace("\r", " ").replace("\n", " ")
    return text


def _file_slug(customer: str, output_path: str) -> str:
    """Return the customer slug used in deliverable FILE names.

    Matches the agent's CUST_SLUG rule (``[A-Za-z0-9_-]`` only, everything else -> ``_``).
    Prefer the slug from this README's own file name (``<slug>_README.md``) so the
    listed names match what was actually written. The result contains no Markdown
    metacharacters, so it is safe inside a code span without escaping (escapes are NOT
    interpreted inside code spans and would show up literally).
    """
    base = os.path.basename(output_path or "")
    if base.endswith("_README.md") and len(base) > len("_README.md"):
        raw = base[: -len("_README.md")]
    else:
        raw = customer
    return re.sub(r"[^A-Za-z0-9_-]", "_", raw) or "Customer"


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _scope_term(providers):
    terms = {SCOPE_TERM.get(p, "scope") for p in providers}
    return terms.pop() if len(terms) == 1 else "scope"


def generate_readme(data: dict, output_path: str, output_root: str = None):
    meta = data.get("metadata", {})
    customer = meta.get("customer", "Customer")
    scan_date = meta.get("scan_date", "")
    providers = (data.get("metadata", {}).get("providers")
        or list(data.get("summary", {}).get("findings_by_provider", {}).keys())
        or data.get("providers")
        or [])
    provider_labels = [PROVIDER_LABEL.get(p, p.upper()) for p in providers]
    scopes = meta.get("scopes_assessed", meta.get("accounts_assessed", [])) or []
    summary = data["summary"]
    severity = summary["findings_by_severity"]
    score = summary["security_score"]
    by_service = summary["findings_by_service"]
    compliance = data.get("compliance_coverage", {})
    scope_term = _scope_term(providers)
    # Scan-derived display values are escaped for Markdown/HTML to prevent table-cell
    # breakout and HTML/script injection when the README is rendered.
    customer_md = _md(customer)
    provider_labels_md = ", ".join(_md(p) for p in provider_labels)
    scope_str = ", ".join(_md(s) for s in scopes) if scopes else "N/A"
    clis = " / ".join(sorted({PROVIDER_CLI.get(p, p) for p in providers}))

    s = []
    s.append(f"# {customer_md} — Cloud Security Assessment\n")
    s.append(f"**Assessment Date:** {scan_date}  ")
    s.append(f"**Cloud Provider(s):** {provider_labels_md}  ")
    s.append(f"**{scope_term.capitalize()}(s) Assessed:** {scope_str}  ")
    s.append(f"**Security Score:** {score}%  ")
    _other_str = f" | **Other:** {severity['other']}" if severity.get("other") else ""
    s.append(f"**Critical:** {severity['critical']} | **High:** {severity['high']} | "
             f"**Medium:** {severity['medium']} | **Low:** {severity['low']}{_other_str}\n")

    limits = meta.get("input_limits_applied") or []
    truncated = summary.get("detailed_findings_truncated") or data.get("detailed_findings_truncated")
    if limits:
        s.append("> ⚠️ **PARTIAL RESULTS.** Safety limits were applied while reading the scan "
                 "input, so some findings may be missing and the score is computed on partial "
                 "data. Re-run on a narrower input to get complete results.")
        for item in limits:
            s.append(f"> - {_md(item)}")
        s.append("")
    if truncated:
        s.append("> ℹ️ The detailed findings list is truncated; summary counts include all "
                 "findings.\n")

    s.append("## Overview\n")
    s.append(
        f"This package contains the results of a cloud security assessment performed on {scan_date}. "
        f"It evaluated {summary['total_checks']:,} security checks across {len(scopes)} "
        f"{scope_term}(s) on {provider_labels_md} using Prowler, achieving a security score of **{score}%**.\n"
    )
    s.append("### Deliverables\n")
    s.append("| File | Description |")
    s.append("|------|-------------|")
    # File names use the sanitized slug (what the agent writes), shown verbatim in code
    # spans — never the Markdown-escaped display name, whose backslashes/entities would
    # render literally inside backticks.
    slug = _file_slug(customer, output_path)
    s.append(f"| `reports/{slug}_Security_Dashboard.html` | Interactive security dashboard (open in browser) |")
    s.append(f"| `reports/{slug}_Security_Assessment_Deck.pptx` | Executive presentation (11 slides) |")
    s.append(f"| `{slug}_Security_Remediation_Plan.pdf` | Phased remediation plan |")
    s.append(f"| `{slug}_README.md` | This file |")
    s.append("| `iac/` | Terraform remediation modules |")
    s.append("")

    s.append("## ⚠️ Review Generated IaC Before Deploying\n")
    s.append(
        "The Terraform modules in `iac/` are **auto-generated** from Prowler's remediation data and "
        "touch sensitive controls (identity, network rules, logging, encryption/key stores). "
        "**Review each module, run `terraform plan`, and validate against your environment and "
        "change-management process before `terraform apply`.** They are a starting point, not "
        "guaranteed production-ready.\n"
    )

    s.append("## Prerequisites\n")
    s.append("- **Terraform** v1.5+ installed")
    s.append(f"- Provider CLI + credentials: **{clis}**")
    s.append("- `terraform validate` / `tflint` for pre-flight validation")
    s.append(f"- Access to the target {scope_term}(s): {scope_str}")
    s.append("")

    s.append("## Findings Summary\n")
    s.append("### By Severity\n")
    s.append("| Severity | Count | Action Timeline |")
    s.append("|----------|-------|-----------------|")
    s.append(f"| 🚨 Critical | {severity['critical']} | Day 1-3 |")
    s.append(f"| ⚠️ High | {severity['high']} | Week 1-2 |")
    s.append(f"| 📋 Medium | {severity['medium']} | Month 1 |")
    s.append(f"| ℹ️ Low | {severity['low']} | Ongoing |")
    if severity.get("other"):
        s.append(f"| ❔ Other | {severity['other']} | Triage |")
    s.append("")

    if len(providers) > 1 and data.get("summary", {}).get("findings_by_provider"):
        s.append("### By Cloud Provider\n")
        s.append("| Provider | Checks | Failed | Score |")
        s.append("|----------|--------|--------|-------|")
        for pk, pv in data["summary"]["findings_by_provider"].items():
            s.append(f"| {_md(pv.get('label', pk))} | {pv.get('total_checks','-')} | "
                     f"{pv.get('fail_count','-')} | {pv.get('security_score','-')}% |")
        s.append("")

    s.append("### By Service (Top 10)\n")
    s.append("| Service | Failed Checks |")
    s.append("|---------|---------------|")
    for svc, count in list(by_service.items())[:10]:
        s.append(f"| {_md(svc)} | {count} |")
    s.append("")

    if compliance:
        s.append("## Compliance Framework Coverage\n")
        # "Checks" columns count every check row across all assessed scopes; "Requirements"
        # de-duplicates by requirement ID so it reflects the framework's real size.
        s.append("| Framework | Pass Rate | Checks Passed | Checks Failed | Total Checks | Requirements Met |")
        s.append("|-----------|-----------|---------------|---------------|--------------|------------------|")
        for fw, info in compliance.items():
            _req = (f"{info.get('requirements_passed', 0)} / {info['requirements_total']} "
                    f"({info.get('requirements_pass_rate', 0)}%)") if info.get("requirements_total") else "—"
            s.append(f"| {_md(fw)} | {info['pass_rate']}% | {info['pass']} | {info['fail']} | {info['total']} | {_req} |")
        s.append("")

    s.append("## Remediation Modules (Terraform)\n")
    s.append("All modules are **Terraform** and located in `iac/`. The correct provider block "
             "(`aws` / `azurerm` / `google` / `oci`) is emitted per module.\n")
    s.append("### Deployment\n")
    s.append("```bash")
    s.append("cd iac/")
    s.append("# First run only: this folder must hold no state or lock file you did not create")
    s.append("ls -a | grep -Ei 'tfstate|\\.terraform' && echo 'STOP: review before init'")
    s.append("terraform init")
    s.append("terraform validate")
    s.append("terraform plan -out=tfplan   # REVIEW this plan carefully")
    s.append("terraform apply tfplan")
    s.append("```\n")
    s.append("### Before Apply: Capture Current Settings\n")
    s.append("Several modules take over an EXISTING account/project-wide setting (S3 account "
             "Block Public Access, default EBS encryption, bucket encryption/policy, Azure SQL TDE, "
             "GCP audit config). Record the current values first so a rollback can restore them "
             "exactly, and `terraform import` any setting that already exists:\n")
    s.append("```bash")
    s.append("# AWS")
    s.append("aws s3control get-public-access-block --account-id <account-id>")
    s.append("aws ec2 get-ebs-encryption-by-default && aws ec2 get-ebs-default-kms-key-id")
    s.append("aws s3api get-bucket-encryption --bucket <bucket>")
    s.append("aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text")
    s.append("# Azure")
    s.append("az sql server tde-key show --server <server> --resource-group <rg>")
    s.append("# GCP")
    s.append("gcloud projects get-iam-policy <project-id> --format=json   # auditConfigs")
    s.append("```\n")
    s.append("### Rollback\n")
    s.append("**Do not use `terraform destroy` to roll back.** Destroying a setting that existed "
             "before the apply (e.g. account-wide Block Public Access, default EBS encryption, a "
             "merged bucket policy, TDE, audit config) REMOVES it and leaves the environment "
             "weaker than before. These resources carry `lifecycle { prevent_destroy = true }` "
             "so `destroy` fails by design. Roll back per resource instead:\n")
    s.append("1. Stop managing the resource without changing it: "
             "`terraform state rm '<resource address>'`.")
    s.append("2. Restore the previous value you captured above with the provider CLI "
             "(e.g. `aws s3control put-public-access-block`, `aws s3api put-bucket-policy`).")
    s.append("3. Resources this run newly CREATED and NOT protected (e.g. a new security group, "
             "storage account, firewall rule) may be removed with "
             "`terraform destroy -target=<address>` after confirming nothing depends on them.")
    s.append("4. Newly created audit/key resources — CloudTrail trail and its log bucket, KMS / "
             "CMEK / Vault keys, the GCP audit config — also carry `prevent_destroy`. Removing "
             "them is a deliberate decision: delete the `prevent_destroy` line first, and note "
             "that an Object-Locked log bucket cannot be emptied until its retention expires "
             "and that deleting a key makes data encrypted with it unrecoverable.\n")

    s.append("## Post-Deployment Validation\n")
    s.append("After deploying, validate by:\n")
    for v in [
        "Re-run Prowler to confirm the findings are resolved",
        "Confirm encryption at rest and in transit on affected resources",
        "Verify audit/activity logging is active",
        "Confirm public access is blocked on storage",
        "If an MFA module was applied (AWS IAM policy / Azure Conditional Access): test "
        "enforcement with a test principal, and confirm break-glass accounts can still sign in",
        "Azure Conditional Access starts in report-only mode — review sign-in logs before "
        "setting conditional_access_state = \"enabled\"",
    ]:
        s.append(f"- [ ] {v}")
    s.append("")

    s.append("## Re-Assessment\n")
    s.append("```bash")
    s.append("pip install prowler")
    for p in providers:
        s.append(f"prowler {p} --output-formats csv,json,html")
    s.append("```\n")
    s.append("Schedule re-assessments monthly or after significant infrastructure changes.\n")

    s.append("---\n")
    s.append(f"*Generated on {scan_date} by the Cloud Security Assessment tool.*\n")

    # No os.makedirs here: open_write_nofollow creates missing folders only after
    # checking every existing component under the root for symlinks.
    output_dir = os.path.dirname(output_path)
    # Contain the write under the output folder (see safe_io.containment_root).
    with safe_io.open_write_nofollow(output_path,
                                     root=(output_root or output_dir or ".")) as fh:
        fh.write("\n".join(s))
    print(f"✅ README generated → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate customer README")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_readme", help="Path for output README.md")
    args = parser.parse_args()
    data = load_analysis(args.analysis_json)
    generate_readme(data, args.output_readme,
                    output_root=safe_io.containment_root(
                        args.output_readme, os.path.dirname(args.analysis_json)))


if __name__ == "__main__":
    main()
