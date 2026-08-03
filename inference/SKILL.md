---
name: resco-security-inference
display_name: ReSCo Security Assessment (External / Customer-Facing)
description: "External-facing variant of the ReSCo Security assessment skill. Analyze AWS ReSCo Security assessment outputs (Prowler scans, Security Hub exports, GuardDuty findings) and generate comprehensive customer-facing deliverables — activate when the user says 'resco security inference', 'external security assessment', 'customer-facing security assessment', 'security assessment for customer', or provides a folder of security scan files for an external customer deliverable. Does NOT log SA Tech Activity to AWSentral (external / customer-facing use only)."
icon: "🔒"
trigger: resco security inference, external security assessment, customer-facing security assessment, security assessment for customer, security posture review for customer
inputs:
  - name: input_folder_path
    description: "Path to folder containing security assessment files (Prowler CSVs, Security Hub JSON, compliance reports). Skill will prompt if not provided."
    type: path
    required: true
  - name: output_folder_path
    description: "Path to folder where deliverables will be saved. Skill creates a single top-level container: output-quick/ (holding reports/, README, remediation plan PDF, and iac/)"
    type: path
    required: true
tools: [fdfind, run_python, file_write, open_in_session_tab, send_message_to_acp_agent, file_copy, pptx_plan, file_read, run_javascript, file_edit, folder_create, file_move, folder_list]
depends-on: [canvas_pptx, html_design, highcharts]
---

## Overview

This is the **external / customer-facing variant** of the ReSCo Security assessment skill. It analyzes AWS security assessment outputs — primarily Prowler scan results (CSV, JSON, HTML), but also Security Hub exports and compliance reports — and generates comprehensive customer deliverables: an interactive HTML security dashboard, an AWS-branded PowerPoint presentation, CloudFormation/Terraform remediation scripts, and a phased remediation plan (PDF). It auto-detects the customer/account from filenames, extracts findings by severity and service, maps compliance frameworks, and can optionally delegate IaC generation to Kiro.

**Difference from `resco-security`:** This variant is intended for deliverables shared directly with external customers. It does NOT include any internal-only steps such as logging an SA Tech Activity to AWSentral. It produces only the customer-facing artifacts.

## Workflow

### Step 1: Gather Input & Output Paths
- **Mode**: `agentic`
- **Input**: User message (may contain paths) or conversation context
- **Output**: Validated `{{input_folder_path}}` and `{{output_folder_path}}`
- **Validate**: Both paths exist and input folder contains at least one readable file (.csv, .json, .html, .xlsx)
- **On failure**: Prompt user: "What folder contains the security assessment files?" and "Where should I save the deliverables?"

Create the output folder structure:
```
{{output_folder_path}}/
└── output-quick/          # Single top-level deliverables container
    ├── reports/           # HTML dashboard + PPTX deck
    ├── {Customer}_README.md
    ├── {Customer}_Security_Remediation_Plan.pdf
    └── iac/               # CloudFormation or Terraform scripts
```

### Step 2: Scan & Identify Assessment Files
- **Mode**: `deterministic`
- **Tool**: `fdfind` + `folder_list`
- **Input**: `{{input_folder_path}}`
- **Output**: List of all files categorized by type, accounts identified, frameworks found
- **Validate**: At least one security data file found
- **On failure**: Report "No security assessment files found."

**Important:** Do NOT assume specific filenames. Scan all files present. Look for:
- Prowler main CSVs (semicolon-delimited, columns include STATUS, SEVERITY, CHECK_ID, SERVICE_NAME, REMEDIATION_*)
- Prowler compliance CSVs (in compliance/ subfolder, framework-specific)
- Prowler HTML reports
- Prowler OCSF JSON outputs
- Security Hub JSON exports
- Any Excel/PDF security reports

Auto-detect: Account IDs from filenames (e.g., "prowler-output-007564470903-..." → Account 007564470903). Customer name: ask user if not determinable from files.

### Step 3: Extract & Analyze Security Data
- **Mode**: `deterministic`
- **Tool**: `run_python` (csv, json, pandas)
- **Input**: List of assessment files from Step 2
- **Output**: Structured data with: total_checks, pass_count, fail_count, findings_by_severity (critical/high/medium/low), findings_by_service, top_failed_checks, compliance_frameworks, accounts_assessed, security_score, detailed_findings (each with: check_id, check_title, status, severity, service, resource_id, risk, remediation_text, remediation_cli, remediation_terraform, compliance_mapping)

**Prowler CSV parsing (main output):**
- Delimiter: semicolon (`;`)
- Key columns: STATUS, SEVERITY, CHECK_ID, CHECK_TITLE, SERVICE_NAME, RESOURCE_UID, RISK, REMEDIATION_RECOMMENDATION_TEXT, REMEDIATION_CODE_CLI, REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_NATIVEIAC, COMPLIANCE, CATEGORIES
- Filter: focus on STATUS=FAIL findings
- Group by: severity, service, check_id

**Prowler compliance CSV parsing:**
- Delimiter: semicolon (`;`)
- Key columns: STATUS, CHECKID, REQUIREMENTS_ID, REQUIREMENTS_DESCRIPTION, REQUIREMENTS_ATTRIBUTES_SERVICE, REQUIREMENTS_ATTRIBUTES_SECTION, FRAMEWORK
- Use for compliance mapping and framework coverage reporting

**Compute security score:** (pass_count / total_checks) * 100

- **Validate**: Data contains at least findings with severity levels
- **On failure**: Report which files failed and continue with available data

### Step 4: Generate HTML Dashboard
- **Mode**: `agentic`
- **Tool**: `file_write` (load html_design + highcharts skills first; use CDN Highcharts URLs)
- **Input**: Structured data from Step 3 + customer/account info
- **Output**: `{{output_folder_path}}/output-quick/reports/{Customer}_Security_Dashboard.html`
- **Validate**: File created, contains Highcharts charts + data tables

Dashboard must include:
1. KPI cards (Total Checks, Pass Rate %, Critical Findings, High Findings, Accounts Assessed)
2. Security Score gauge (solid-gauge showing pass rate %)
3. Findings by Severity chart (donut: Critical/High/Medium/Low)
4. Findings by Service chart (top 10 services bar chart, color-coded by severity)
5. Top Failed Checks table (check_title, service, severity, count, risk description)
6. Compliance Framework Coverage (per-framework pass rate if available)
7. Remediation Priority cards (Critical → High → Medium, with specific actions, CLI commands, and TF snippets from Prowler data)
8. Phased Remediation Roadmap (Immediate: Critical, Week 1-2: High, Month 1: Medium, Ongoing: Low)
9. AWS Shared Responsibility Model reminder
10. Footer with data sources, scan date, account IDs

**AWS logo (HTML):** Use the EXACT official AWS wordmark+smile SVG below — inline with `width="80" height="48"`, viewBox="0 0 304 182", NO style attribute on the SVG element. This is the same SVG used by the cost optimization and resiliency dashboards:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 304 182" width="80" height="48">
  <path fill="#FFFFFF" d="M86.4 66.4c0 3.7.4 6.7 1.1 8.9.8 2.2 1.8 4.6 3.2 7.2.5.8.7 1.6.7 2.3 0 1-.6 2-1.9 3l-6.3 4.2c-.9.6-1.8.9-2.6.9-1 0-2-.5-3-1.4-1.4-1.5-2.6-3.1-3.6-4.7-1-1.7-2-3.6-3.1-5.9-7.8 9.2-17.6 13.8-29.4 13.8-8.4 0-15.1-2.4-20-7.2-4.9-4.8-7.4-11.2-7.4-19.2 0-8.5 3-15.4 9.1-20.6 6.1-5.2 14.2-7.8 24.5-7.8 3.4 0 6.9.3 10.6.8 3.7.5 7.5 1.3 11.5 2.2v-7.3c0-7.6-1.6-12.9-4.7-16-3.2-3.1-8.6-4.6-16.3-4.6-3.5 0-7.1.4-10.8 1.3-3.7.9-7.3 2-10.8 3.4-1.6.7-2.8 1.1-3.5 1.3-.7.2-1.2.3-1.6.3-1.4 0-2.1-1-2.1-3.1v-4.9c0-1.6.2-2.8.7-3.5.5-.7 1.4-1.4 2.8-2.1 3.5-1.8 7.7-3.3 12.6-4.5 4.9-1.2 10.1-1.8 15.6-1.8 12.2 0 21.1 2.8 26.8 8.3 5.6 5.6 8.5 14 8.5 25.3v33.5h-.6zM45.8 81.6c3.3 0 6.7-.6 10.3-1.8 3.6-1.2 6.8-3.4 9.5-6.4 1.6-1.9 2.8-4 3.4-6.4.6-2.4 1-5.3 1-8.7v-4.2c-2.9-.7-6-1.3-9.2-1.7-3.2-.4-6.3-.6-9.4-.6-6.7 0-11.6 1.3-14.9 4-3.3 2.7-4.9 6.5-4.9 11.5 0 4.7 1.2 8.2 3.7 10.6 2.4 2.5 5.9 3.7 10.5 3.7zm80.3 10.8c-1.8 0-3-.3-3.8-1-.8-.6-1.5-2-2.1-3.9L96.7 10.2c-.6-2-.9-3.3-.9-4 0-1.6.8-2.5 2.4-2.5h9.8c1.9 0 3.2.3 3.9 1 .8.6 1.4 2 2 3.9l16.8 66.2 15.6-66.2c.5-2 1.1-3.3 1.9-3.9.8-.6 2.2-1 4-1h8c1.9 0 3.2.3 4 1 .8.6 1.5 2 1.9 3.9l15.8 67 17.3-67c.6-2 1.3-3.3 2-3.9.8-.6 2.1-1 3.9-1h9.3c1.6 0 2.5.8 2.5 2.5 0 .5-.1 1-.2 1.6-.1.6-.3 1.4-.7 2.5l-24.1 77.3c-.6 2-1.3 3.3-2.1 3.9-.8.6-2.1 1-3.8 1h-8.6c-1.9 0-3.2-.3-4-1-.8-.7-1.5-2-1.9-4L156 23l-15.4 64.4c-.5 2-1.1 3.3-1.9 4-.8.7-2.2 1-4 1h-8.6zm128.5 2.7c-5.2 0-10.4-.6-15.4-1.8-5-1.2-8.9-2.5-11.5-4-1.6-.9-2.7-1.9-3.1-2.8-.4-.9-.6-1.9-.6-2.8v-5.1c0-2.1.8-3.1 2.3-3.1.6 0 1.2.1 1.8.3.6.2 1.5.6 2.5 1 3.4 1.5 7.1 2.7 11 3.5 4 .8 7.9 1.2 11.9 1.2 6.3 0 11.2-1.1 14.6-3.3 3.4-2.2 5.2-5.4 5.2-9.5 0-2.8-.9-5.1-2.7-7-1.8-1.9-5.2-3.6-10.1-5.2l-14.5-4.5c-7.3-2.3-12.7-5.7-16-10.2-3.3-4.4-5-9.3-5-14.5 0-4.2.9-7.9 2.7-11.1 1.8-3.2 4.2-6 7.2-8.2 3-2.3 6.4-4 10.4-5.2 4-1.2 8.2-1.7 12.6-1.7 2.2 0 4.5.1 6.7.4 2.3.3 4.4.7 6.5 1.1 2 .5 3.9 1 5.7 1.6 1.8.6 3.2 1.2 4.2 1.8 1.4.8 2.4 1.6 3 2.5.6.8.9 1.9.9 3.3v4.7c0 2.1-.8 3.2-2.3 3.2-.8 0-2.1-.4-3.8-1.2-5.7-2.6-12.1-3.9-19.2-3.9-5.7 0-10.2.9-13.3 2.8-3.1 1.9-4.7 4.8-4.7 8.9 0 2.8 1 5.2 3 7.1 2 1.9 5.7 3.8 11 5.5l14.2 4.5c7.2 2.3 12.4 5.5 15.5 9.6 3.1 4.1 4.6 8.8 4.6 14 0 4.3-.9 8.2-2.6 11.6-1.8 3.4-4.2 6.4-7.3 8.8-3.1 2.5-6.8 4.3-11.1 5.6-4.5 1.4-9.2 2.1-14.3 2.1z"/>
  <path fill="#FF9900" d="M273.5 143.7c-32.9 24.3-80.7 37.2-121.8 37.2-57.6 0-109.5-21.3-148.7-56.7-3.1-2.8-.3-6.6 3.4-4.4 42.4 24.6 94.7 39.5 148.8 39.5 36.5 0 76.6-7.6 113.5-23.2 5.6-2.3 10.2 3.7 4.8 7.6z"/>
  <path fill="#FF9900" d="M287.2 128.1c-4.2-5.4-27.8-2.6-38.5-1.3-3.2.4-3.7-2.4-.8-4.5 18.8-13.2 49.7-9.4 53.3-5 3.6 4.5-1 35.4-18.6 50.2-2.7 2.3-5.3 1.1-4.1-1.9 4-9.9 12.9-32.2 8.7-37.5z"/>
</svg>
```
**CRITICAL**: Use CDN Highcharts URLs (`https://cdn.jsdelivr.net/npm/highcharts@12.1.2/`) — NOT `/vendor/highcharts/` paths.

### Step 5: Generate PPTX Deck
- **Mode**: `agentic`
- **MANDATORY**: This step is NOT optional — always generate the PPTX deck as part of the workflow. Do NOT skip it due to time or complexity.
- **If running as background task**: Ensure sufficient timeout (120s+) for the full multi-layer pptxgenjs build.
- **Tool**: `run_python` (matplotlib for charts) + `run_javascript` (pptxgenjs)
- **Input**: Structured data from Step 3 + customer info
- **Output**: `{{output_folder_path}}/output-quick/reports/{Customer}_Security_Assessment_Deck.pptx`
- **Validate**: PPTX file created with 10-12 slides

**Step 5a: Generate chart PNGs with matplotlib:**
- Severity distribution donut (Critical/High/Medium/Low with counts)
- Top 10 services failure bar chart
- Security score gauge
- Compliance framework coverage bar chart

**Step 5b: Build PPTX with pptxgenjs (11 slides):**
1. Title — "AWS Security Assessment", customer name, "Confidential", AWS logo
2. Executive Summary — KPI boxes (Score %, Critical, High, Medium, Low) + key insights
3. Severity Distribution — embedded chart + risk summary
4. Findings by Service — embedded chart + top 5 services with descriptions
5. Critical & High Findings Detail — top 10 critical/high with risk + remediation
6. Remediation: Immediate Actions — emoji icon cards for Critical findings with CLI commands
7. Remediation: Short-Term Actions — icon cards for High severity findings
8. Compliance Framework Coverage — per-framework pass rates + gaps
9. Implementation Roadmap — 4 phase boxes (Immediate → Week 1-2 → Month 1 → Ongoing)
10. AWS Best Practices & Next Steps — Security Pillar checklist
11. Thank You / Closing — AWS logo

**Consistent on every slide:** AWS logo top-right, header "Customer — AWS Security Assessment", slide number.

**AWS Logo in PPTX (CRITICAL — must match cost optimization & resiliency decks):**
- Save the official AWS SVG (viewBox="0 0 304 182", white wordmark + orange smile) to workspace as `artifacts/aws_logo/aws_logo.svg`
- On EVERY content slide (white bg): `slide.addImage({ path: awsLogoDarkSvg, x: 8.90, y: 0.15, w: 0.70, h: 0.42 })`
- On title/closing slides (dark bg): `slide.addImage({ path: awsLogoWhiteSvg, x: 8.80, y: 0.20, w: 0.80, h: 0.48 })`
- pptxgenjs auto-generates a PNG fallback (1,594 bytes) alongside the SVG (2,733 bytes) — this is expected
- Do NOT use text "aws" as a placeholder — always embed the actual SVG image file
- Use TWO SVG files: `aws_logo_white.svg` (fill=#FFFFFF for dark backgrounds) and `aws_logo_dark.svg` (fill=#232F3E for white backgrounds). The orange smile paths (#FF9900) are the same in both.

### Step 6: Present Recommendations & Ask for IaC Selection
- **Mode**: `agentic`
- **Input**: Top failed security checks from Step 3
- **Output**: User's selection, IaC format, and Kiro preference
- **Validate**: User provides selection

Present decision cards:

**Card 1 — IaC Format & Delegation:**
```
<decisions>
<decision question="IaC format for all remediation scripts?">
<option>CloudFormation (YAML)</option>
<option>Terraform (HCL)</option>
</decision>
<decision question="Use Kiro for parallel generation?">
<option>Yes — delegate to Kiro (parallel, faster)</option>
<option>No — build natively in Quick (sequential, no dependency)</option>
</decision>
</decisions>
```

**Card 2 — Remediation Selection (multi-select):**
Present top security findings that can be automated:
- S3 Block Public Access + encryption
- IAM MFA enforcement
- Security Group restriction (no 0.0.0.0/0)
- EBS/RDS encryption at rest
- CloudTrail multi-region enablement
- VPC Flow Logs enablement
- Lambda VPC placement
- Access logging (S3, ALB)
- KMS key rotation
- Root account access key removal

All scripts in ONE format (CF or TF) — no mixed output.

### Step 7: Generate IaC Scripts
- **Mode**: `agentic`
- **Tool**: `file_write` (native) OR `send_message_to_acp_agent` (Kiro delegation)
- **Input**: Selected remediations from Step 6
- **Output**: IaC files in `{{output_folder_path}}/output-quick/iac/`

**IMPORTANT**: Prowler output already contains remediation code (REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_CLI, REMEDIATION_CODE_NATIVEIAC). Use these as starting points but enhance them into complete, production-ready templates with proper parameters, IAM roles, tags, and outputs.

**If native:** Generate via `file_write` with all IaC Quality Guidelines applied.
**If Kiro:** Dispatch via `send_message_to_acp_agent` with `wait_for_completion=false` for 3+ scripts.

### Step 8: Generate README
- **Mode**: `deterministic`
- **Tool**: `file_write`
- **Output**: `{{output_folder_path}}/output-quick/{Customer}_README.md`

README structure:
1. Overview — accounts assessed, scan date, security score, critical findings count
2. Prerequisites — AWS CLI, IAM permissions, Terraform, cfn-lint
3. Findings Summary by Severity + Service
4. Compliance Framework Coverage
5. For each IaC script: description, parameters, deploy command, rollback, validation
6. Post-deployment security validation checklist
7. Re-assessment guidance (re-run Prowler)

### Step 9: Generate Remediation Plan (PDF)
- **Mode**: `agentic`
- **Tool**: `run_python` (reportlab)
- **Output**: `{{output_folder_path}}/output-quick/{Customer}_Security_Remediation_Plan.pdf`

Plan structure:
1. Title page
2. Table of Contents
3. Executive Summary — security score, critical count, top risks
4. Findings Summary Table (check, service, severity, count, compliance)
5. Phase 1: Immediate (Day 1-3) — Critical findings: MFA, public access, exposed secrets
6. Phase 2: Short-Term (Week 1-2) — High: encryption, logging, SG restrictions
7. Phase 3: Medium-Term (Month 1) — Medium: best practices, compliance gaps
8. Phase 4: Ongoing — Low + governance: periodic scans, Config rules, GuardDuty
9. Risk Matrix (use Paragraph objects for wrapping)
10. Compliance Gap Analysis — per-framework pass rates + remediation priority
11. Success Metrics — Security score target, mean-time-to-remediate, compliance %
12. Appendix: IaC script reference

**PDF Branding:** AWS header/footer on every page via onPage callback.

### Step 10: Open Deliverables & Summarize
- **Mode**: `deterministic`
- **Tool**: `open_in_session_tab`
- Open HTML dashboard + PPTX deck. Present summary with qw-file:// links.

## Output

```
{{output_folder_path}}/
└── output-quick/                                        # Single top-level deliverables container
    ├── reports/
    │   ├── {Customer}_Security_Dashboard.html           # Interactive Highcharts dashboard
    │   └── {Customer}_Security_Assessment_Deck.pptx     # AWS-branded executive deck (11 slides)
    ├── {Customer}_README.md                             # Usage guide
    ├── {Customer}_Security_Remediation_Plan.pdf         # Phased plan (AWS branded)
    └── iac/
        ├── {Customer}_s3_security.yaml                  # S3 block public access + encryption
        ├── {Customer}_iam_mfa_enforcement.yaml          # IAM MFA policy
        ├── {Customer}_security_groups.yaml              # Restricted SG rules
        ├── {Customer}_encryption_at_rest.yaml           # EBS/RDS encryption
        ├── {Customer}_cloudtrail_logging.yaml           # Multi-region CloudTrail
        ├── {Customer}_vpc_flow_logs.yaml                # VPC Flow Logs
        └── ... (per user selection)
```

**File naming:** ALL output files prefixed with customer name.

## IaC Quality Guidelines

All generated CloudFormation and Terraform scripts MUST adhere to these standards:

### 1. IAM & Security
- Create dedicated IAM roles/instance profiles per resource (no shared roles)
- Apply least-privilege policies — only permissions the resource actually needs
- Enable encryption at rest and in transit by default
- Use `StorageEncrypted: true`, `HttpTokens: required` (IMDSv2), `PubliclyAccessible: false`

### 2. Native Resources Only
- Use native CF/TF resource types — NEVER use `null_resource` + `local-exec` hacks

### 3. Parameters Drive Everything
- ALL configurable values must be parameters/variables
- Include sensible defaults, use AllowedValues/validation blocks

### 4. Safety Defaults
- CF: `DeletionPolicy: Retain` for security resources (CloudTrail, Config, logs)
- Default to safest option (encryption=true, public_access=false, mfa=required)

### 5. Accurate Naming
- Stack names: `{customer}-{purpose}`, Resource IDs: PascalCase

### 6. README + Parameter Input Files
- Generate parameters.json (CF) or terraform.tfvars.example (TF)

### 7. Pre-flight Validation
- cfn-lint / terraform validate instructions

### 8. Tagging & Observability
- Tag ALL resources, include CloudWatch alarms, enable logging

### 9. Completeness Checklist
- Parameters, tags, outputs, alarms, rollback instructions, deploy commands

### 10. Outputs Section
- Export key IDs/ARNs for cross-stack referencing

### 11. Conditions for Optional Resources
- Use CF Conditions or TF count/for_each for toggles

### 12. State Management (Terraform)
- Document S3+DynamoDB backend, include backend.tf.example

### 13. Drift Detection Guidance
- Include drift detection commands in README

### 14. Explicit Rollback Instructions
- Per-script, document rollback order

### 15. Cost Estimation Notes
- Note billable items (CloudTrail, VPC Flow Logs, Config rules)

### 16. Dependency Ordering
- DependsOn / depends_on for multi-resource stacks

### 17. Secrets Handling
- NEVER hardcode credentials; use Secrets Manager / SSM

### 18. Multi-Account & Enterprise Considerations
- StackSets for org-wide security controls, assume-role for cross-account

## Lessons Learned

### Do
- Parse Prowler CSVs with semicolon delimiter (`;`) — NOT comma
- Use the main CSV (OCSF format) for severity, risk, and remediation fields
- Use compliance/ subfolder CSVs for framework-specific coverage analysis
- Leverage REMEDIATION_CODE_TERRAFORM and REMEDIATION_CODE_CLI from Prowler as starting points
- Group findings by: severity first, then service, then check_id
- Calculate security score as: (PASS / total) * 100
- Always present Critical findings first in all deliverables
- Prefix ALL output files with customer name
- Use CDN Highcharts (not /vendor/)
- AWS logo SVG: always include `width="80" height="48"` attributes
- Use Paragraph objects in reportlab Table cells for text wrapping
- Ask IaC format (all CF or all TF) — no mixed output
- Make Kiro optional — skill works natively

### Don't
- Don't assume comma-delimited CSVs — Prowler uses semicolons
- Don't skip the PPTX deck — it is mandatory
- Don't use text "aws" as logo placeholder in PPTX — always embed the actual SVG file via slide.addImage()
- Don't use a simplified/custom SVG for the logo — use the official AWS wordmark (viewBox="0 0 304 182") with 3 paths (white text + 2 orange smile paths)
- Don't use `LAYOUT_WIDE` (13.33"×7.5") for pptxgenjs — ALWAYS use `pres.layout = 'LAYOUT_16x9'` (10"×5.625") to match cost optimization and resiliency decks
- Don't use the WHITE logo SVG (fill="#FFFFFF") on white-background slides — use TWO logo variants: white (fill="#FFFFFF") for dark-bg slides (title/closing) and dark (fill="#232F3E") for white-bg content slides. The orange smile paths stay the same (#FF9900) in both.
- Don't use /vendor/highcharts/ paths
- Don't produce mixed CF + TF output
- Don't assume Kiro is available
- Don't show real account IDs in customer-facing decks (anonymize if requested)
- Don't embed SVG without explicit width/height
- Don't ignore the REMEDIATION_CODE_* fields — they contain valuable starting code
- Don't read all rows into memory for very large CSVs (100K+ rows) — use chunked reading or pandas

### Common Failures
- **Semicolon delimiter**: Prowler CSVs use `;` not `,`. Using wrong delimiter produces single-column data.
- **Large files**: Some Prowler outputs have 10K+ rows. Use pandas or chunked reading.
- **Multiple accounts**: Files may cover multiple AWS accounts. Group and report per-account.
- **Missing remediation code**: Not all checks have REMEDIATION_CODE_TERRAFORM. Fall back to REMEDIATION_RECOMMENDATION_TEXT.

### When to Ask the User
- Input/output folder paths
- IaC format (CF or TF) — always ask
- Whether to delegate to Kiro — always ask
- Which remediations to generate IaC for (multi-select)
- Customer name if not determinable from files
- Whether to anonymize account IDs in customer-facing outputs
