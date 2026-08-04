#!/usr/bin/env python3
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
import sys


PROVIDER_CLI = {
    "aws": "aws",
    "azure": "az",
    "gcp": "gcloud",
    "oci": "oci",
}

PROVIDER_LABEL = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "oci": "OCI"}

SCOPE_TERM = {
    "aws": "account",
    "azure": "subscription",
    "gcp": "project",
    "oci": "tenancy",
}


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _scope_term(providers):
    terms = {SCOPE_TERM.get(p, "scope") for p in providers}
    return terms.pop() if len(terms) == 1 else "scope"


def generate_readme(data: dict, output_path: str):
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
    scope_str = ", ".join(scopes) if scopes else "N/A"
    clis = " / ".join(sorted({PROVIDER_CLI.get(p, p) for p in providers}))

    s = []
    s.append(f"# {customer} — Cloud Security Assessment\n")
    s.append(f"**Assessment Date:** {scan_date}  ")
    s.append(f"**Cloud Provider(s):** {', '.join(provider_labels)}  ")
    s.append(f"**{scope_term.capitalize()}(s) Assessed:** {scope_str}  ")
    s.append(f"**Security Score:** {score}%  ")
    s.append(f"**Critical:** {severity['critical']} | **High:** {severity['high']} | "
             f"**Medium:** {severity['medium']} | **Low:** {severity['low']}\n")

    s.append("## Overview\n")
    s.append(
        f"This package contains the results of a cloud security assessment performed on {scan_date}. "
        f"It evaluated {summary['total_checks']:,} security checks across {len(scopes)} "
        f"{scope_term}(s) on {', '.join(provider_labels)} using Prowler, achieving a security score of **{score}%**.\n"
    )
    s.append("### Deliverables\n")
    s.append("| File | Description |")
    s.append("|------|-------------|")
    s.append(f"| `reports/{customer}_Security_Dashboard.html` | Interactive security dashboard (open in browser) |")
    s.append(f"| `reports/{customer}_Security_Assessment_Deck.pptx` | Executive presentation (11 slides) |")
    s.append(f"| `{customer}_Security_Remediation_Plan.pdf` | Phased remediation plan |")
    s.append(f"| `{customer}_README.md` | This file |")
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
    s.append("")

    if len(providers) > 1 and data.get("findings_by_provider"):
        s.append("### By Cloud Provider\n")
        s.append("| Provider | Checks | Failed | Score |")
        s.append("|----------|--------|--------|-------|")
        for pk, pv in data["findings_by_provider"].items():
            s.append(f"| {pv.get('label', pk)} | {pv.get('total_checks','-')} | "
                     f"{pv.get('fail_count','-')} | {pv.get('security_score','-')}% |")
        s.append("")

    s.append("### By Service (Top 10)\n")
    s.append("| Service | Failed Checks |")
    s.append("|---------|---------------|")
    for svc, count in list(by_service.items())[:10]:
        s.append(f"| {svc} | {count} |")
    s.append("")

    if compliance:
        s.append("## Compliance Framework Coverage\n")
        s.append("| Framework | Pass Rate | Pass | Fail | Total |")
        s.append("|-----------|-----------|------|------|-------|")
        for fw, info in compliance.items():
            s.append(f"| {fw} | {info['pass_rate']}% | {info['pass']} | {info['fail']} | {info['total']} |")
        s.append("")

    s.append("## Remediation Modules (Terraform)\n")
    s.append("All modules are **Terraform** and located in `iac/`. The correct provider block "
             "(`aws` / `azurerm` / `google` / `oci`) is emitted per module.\n")
    s.append("### Deployment\n")
    s.append("```bash")
    s.append("cd iac/")
    s.append("terraform init")
    s.append("terraform validate")
    s.append("terraform plan -out=tfplan   # REVIEW this plan carefully")
    s.append("terraform apply tfplan")
    s.append("```\n")
    s.append("### Rollback\n")
    s.append("```bash")
    s.append("terraform destroy")
    s.append("```\n")

    s.append("## Post-Deployment Validation\n")
    s.append("After deploying, validate by:\n")
    for v in [
        "Re-run Prowler to confirm the findings are resolved",
        "Confirm encryption at rest and in transit on affected resources",
        "Verify audit/activity logging is active",
        "Confirm public access is blocked on storage",
        "Test identity/MFA enforcement with a test principal",
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

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(s))
    print(f"✅ README generated → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate customer README")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_readme", help="Path for output README.md")
    args = parser.parse_args()
    data = load_analysis(args.analysis_json)
    generate_readme(data, args.output_readme)


if __name__ == "__main__":
    main()
