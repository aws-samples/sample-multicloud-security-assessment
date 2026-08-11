---
name: cloud-security-assessment
display_name: Cloud Security Assessment (Multi-Cloud, Prowler)
description: "Analyze Prowler security scan outputs from any cloud (AWS, Azure, GCP, OCI) — including CSV, OCSF JSON, Security Hub JSON, and HTML reports — and generate a complete set of customer-facing deliverables: an interactive HTML dashboard, a PowerPoint deck, a phased remediation plan (PDF), and Terraform remediation modules. Activate when the user says 'cloud security assessment', 'analyze prowler output', 'security assessment', 'prowler dashboard', or provides a folder of Prowler scan files."
icon: "🔒"
trigger: cloud security assessment, analyze prowler output, prowler assessment, security posture assessment, prowler dashboard
inputs:
  - name: input_folder_path
    description: "Path to folder containing Prowler scan files from any cloud (CSV, OCSF JSON, HTML) and/or Security Hub JSON exports. Skill will prompt if not provided."
    type: path
    required: true
  - name: output_folder_path
    description: "Path to folder where deliverables will be saved. If omitted, defaults to a per-provider assessment-summary-<provider>/ folder beside the input (holding reports/, README, remediation plan PDF, and iac/)."
    type: path
    required: false
tools: [run_python, file_write, open_in_session_tab, file_copy, file_read, run_javascript, file_edit, folder_create, file_move, folder_list]
depends-on: [canvas_pptx, html_design, highcharts]
---

## Overview

This skill analyzes **Prowler** security scan outputs from **any supported cloud — AWS, Azure, GCP, or OCI** (and Kubernetes/M365 where present) — and generates comprehensive customer deliverables: an interactive HTML security dashboard, a **neutrally-branded** PowerPoint presentation, **Terraform** remediation scripts, and a phased remediation plan (PDF). It auto-detects the cloud provider(s) and the account/scope from the scan data, extracts findings by severity and service, maps compliance frameworks, and produces artifacts suitable for sharing directly with a customer.

**Multi-cloud by design.** Prowler emits a consistent output schema across providers (CSV, OCSF JSON, HTML). The same key columns/fields (`PROVIDER`, `STATUS`, `SEVERITY`, `CHECK_ID`, `CHECK_TITLE`, `SERVICE_NAME`, `RESOURCE_UID`, `RISK`, `REMEDIATION_*`, `COMPLIANCE`) are present regardless of cloud. This skill MUST be **provider-aware**: read the `PROVIDER` field, and adapt service groupings, remediation examples, terminology, and IaC to the detected cloud(s). Do NOT hard-code AWS-only assumptions.

> **Disclaimer — review generated IaC before deploying.** The Terraform this skill produces is auto-generated from Prowler's remediation fields and touches sensitive controls (identity/IAM, network rules, logging, encryption/key stores). Treat it as a starting point: review, run `terraform plan`, and validate against your environment and change-management process before applying. It is not guaranteed to be production-ready as-is.

### Provider awareness reference

Detect the provider from the Prowler `PROVIDER` field (values like `aws`, `azure`, `gcp`, `oci`, `kubernetes`, `m365`). A single input folder MAY contain scans from multiple providers — handle each, and label deliverables per provider. Use these mappings when generating service groupings, examples, and terminology:

| Concept | AWS | Azure | GCP | OCI |
|---|---|---|---|---|
| Account scope | Account ID | Subscription / Tenant ID | Project / Org ID | Tenancy / Compartment OCID |
| Object storage | S3 | Blob Storage | Cloud Storage (GCS) | Object Storage |
| Compute | EC2 | Virtual Machines | Compute Engine | Compute |
| Identity | IAM | Entra ID / IAM | Cloud IAM | IAM |
| Managed SQL | RDS | Azure SQL | Cloud SQL | Autonomous DB / DB Systems |
| Serverless | Lambda | Functions | Cloud Functions | Functions |
| Key management | KMS | Key Vault | Cloud KMS | Vault / KMS |
| Logging/Audit | CloudTrail / CloudWatch | Monitor / Activity Log | Cloud Logging / Audit Logs | Audit / Logging |
| Networking | VPC / Security Groups | VNet / NSG | VPC / Firewall Rules | VCN / Security Lists |
| Threat detection | GuardDuty | Defender for Cloud | Security Command Center | Cloud Guard |

**Terminology:** Use the neutral term **"account/subscription/project/tenancy"** or simply **"scope"** in customer-facing text unless a single provider is detected, in which case use that provider's correct term.

## Workflow

### Step 1: Gather Inputs, Output Path & Required Choices
- **Mode**: `agentic`
- **Input**: User message (may contain paths) or conversation context
- **Output**: Validated `{{input_folder_path}}` and `{{output_folder_path}}`, plus the **required** anonymization choice (see below)
- **Validate**: Both paths exist and input folder contains at least one readable file (.csv, .json, .html, .xlsx)
- **On failure**: Prompt user: "What folder contains the Prowler scan files?" and "Where should I save the deliverables?"

**Input folder may be nested.** The Prowler files often live in a subfolder such as `<cloud>/output/` (with `<cloud>/output/compliance/` for framework CSVs). Point the input at whatever folder contains (or contains-below) the scan files — scanning is recursive.

**Output folder — user's choice, with a smart per-provider default.** If the user does not specify an output location, default to an **`assessment-summary-<provider>`** folder (the provider is auto-detected from the scan data — e.g. `assessment-summary-aws`, `assessment-summary-azure`, `assessment-summary-gcp`). It is placed in: the PARENT of the input folder when the input folder is named `output` (e.g. `.../aws/output` → `.../aws/assessment-summary-aws/`), otherwise the input folder itself (e.g. `.../aws` → `.../aws/assessment-summary-aws/`). The `-<provider>` suffix keeps per-provider runs in separate folders — run the tool once per provider, even for multi-cloud customers. Always let the user override with an explicit path. Do NOT write deliverables inside the Prowler scan `output/` folder.

**REQUIRED pre-generation choice — account/scope anonymization.** Before generating ANY artifact, you MUST ask and record this choice (do not treat it as optional or defer it):

```
<decision question="Anonymize cloud account/subscription/project/tenancy identifiers in all customer-facing deliverables?">
<option description="Replace every real identifier with generic labels (Account A / Subscription B / Project C ...) consistently across dashboard, deck, PDF, README, and IaC">Yes — anonymize all identifiers</option>
<option description="Show the real identifiers in all deliverables">No — show real identifiers</option>
</decision>
```

Record the choice as `anonymize = true|false` and a stable mapping `{real_id -> masked_label}`. This mapping MUST be applied and verified in every downstream step (see Step 3a and the Step 10 verification gate).

Create the output folder structure ({{output_folder_path}} = the user's chosen output dir, or the smart per-provider default `assessment-summary-<provider>/` folder):
```
{{output_folder_path}}/          # e.g. <cloud>/assessment-summary-<provider>/ by default
├── reports/                     # HTML dashboard + PPTX deck
├── {Customer}_README.md
├── {Customer}_Security_Remediation_Plan.pdf
└── iac/                         # Terraform remediation scripts
```

### Step 2: Scan & Identify Assessment Files
- **Mode**: `deterministic`
- **Tool**: `folder_list` (+ `run_python` for recursive listing)
- **Input**: `{{input_folder_path}}`
- **Output**: List of all files categorized by type; provider(s) identified; accounts/scopes identified; frameworks found
- **Validate**: At least one security data file found
- **On failure**: Report "No Prowler / security assessment files found."

**Important:** Do NOT assume specific filenames or a single cloud. Scan all files present. Look for:
- Prowler main CSVs (semicolon-delimited; columns include PROVIDER, STATUS, SEVERITY, CHECK_ID, SERVICE_NAME, REMEDIATION_*)
- Prowler compliance CSVs (in compliance/ subfolder, framework-specific)
- Prowler **OCSF JSON** outputs (`*.ocsf.json`) — full findings in normalized schema
- Prowler **HTML** reports
- **Security Hub JSON** exports (AWS) and equivalent posture exports
- Any Excel/PDF security reports

**Provider auto-detection:** Read the `PROVIDER` field/column from the main output (CSV or OCSF JSON). Identify all distinct providers present. Auto-detect account/scope identifiers from the data (e.g. AWS `ACCOUNT_UID`, Azure subscription/tenant, GCP project, OCI tenancy/compartment) and from filenames as a fallback (e.g. `prowler-output-123456789012-...` → account `123456789012`). Customer name: ask user if not determinable.

### Step 3: Extract & Analyze Security Data
- **Mode**: `deterministic`
- **Tool**: `run_python` (csv, json, pandas)
- **Input**: List of assessment files from Step 2
- **Output**: Structured data with: provider(s), total_checks, pass_count, fail_count, findings_by_severity (critical/high/medium/low), findings_by_service, top_failed_checks, compliance_frameworks, scopes_assessed, security_score, detailed_findings (each with: provider, check_id, check_title, status, severity, service, resource_id, risk, remediation_text, remediation_cli, remediation_iac, compliance_mapping)

Prefer the **richest available source** per scan. Read at least one of the following for each provider; do not rely on CSV alone:

**A) Prowler main CSV (primary when present):**
- Delimiter: semicolon (`;`)
- Key columns: PROVIDER, STATUS, SEVERITY, CHECK_ID, CHECK_TITLE, SERVICE_NAME, RESOURCE_UID, RISK, REMEDIATION_RECOMMENDATION_TEXT, REMEDIATION_CODE_CLI, REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_NATIVEIAC, COMPLIANCE, CATEGORIES
- Filter: focus on STATUS=FAIL findings; group by: severity, service, check_id

**B) Prowler OCSF JSON (`*.ocsf.json`) — use when CSV is absent or to enrich:**
- Array of finding objects in OCSF schema. Parse with `json.load`.
- Map fields: `status_code`/`status` → STATUS; `severity` → SEVERITY; `finding_info.title`/`finding_info.uid` → CHECK_TITLE/CHECK_ID; `resources[].uid`/`resources[].type` → resource id/type; `cloud.provider` → PROVIDER; `remediation.desc`/`remediation.references` → remediation; `unmapped`/`compliance` → framework mapping.
- Normalize to the same structured schema as the CSV path so downstream steps are source-agnostic.

**C) Security Hub JSON (AWS) or equivalent posture export — use when present:**
- Array of findings (ASFF for AWS Security Hub). Map: `Severity.Label` → SEVERITY; `Title`/`GeneratorId` → CHECK_TITLE/CHECK_ID; `Resources[].Id` → resource id; `ProductFields`/`Compliance.Status` → status/compliance; `Remediation.Recommendation.Text/Url` → remediation.

**D) Prowler HTML report — use as a fallback/supplement:**
- Parse the findings table(s) from the HTML (pandas `read_html` or manual parse) to recover STATUS/SEVERITY/CHECK/SERVICE when no CSV/JSON is available.

**E) Prowler compliance CSVs (framework coverage):**
- Delimiter: semicolon (`;`); key columns: STATUS, CHECKID, REQUIREMENTS_ID, REQUIREMENTS_DESCRIPTION, REQUIREMENTS_ATTRIBUTES_SERVICE, REQUIREMENTS_ATTRIBUTES_SECTION, FRAMEWORK. Use for per-framework pass-rate reporting. Frameworks vary by cloud (e.g. CIS AWS/Azure/GCP/OCI benchmarks, Azure Security Benchmark, etc.).
- **Two denominators — do not conflate them.** One CSV row is requirement x resource x region x scope, so a plain row count is a *check* count, not the framework's size, and it multiplies when several scopes are assessed (e.g. MITRE ATT&CK: ~45 requirements but 23,000+ rows across two accounts). Report check-level pass/fail/total (a valid scope-weighted rate) **and** a requirement-level count de-duplicated by REQUIREMENTS_ID, where a requirement passes only if no scope reported FAIL for it. Label them distinctly ("Total Checks" vs "Requirements Met") — never present a summed row count as framework coverage.

**Compute security score:** (pass_count / (pass_count + fail_count)) * 100, reported overall and per provider/scope. Non-actionable statuses (MANUAL/INFO/MUTED) are excluded from the denominator so they don't artificially deflate the score.

- **Validate**: Data contains at least findings with severity levels
- **On failure**: Report which files failed and continue with available data

### Step 3a: Apply Anonymization Mapping (if enabled)
- **Mode**: `deterministic`
- **Tool**: `run_python`
- **Input**: Structured data from Step 3 + the `anonymize` choice and `{real_id -> masked_label}` mapping from Step 1
- **Output**: A single canonical dataset where, if `anonymize=true`, EVERY occurrence of a real account/subscription/project/tenancy identifier (and any embedded resource ARNs/URIs that reveal them) is replaced with the stable masked label
- **How**: Build the mapping from all distinct scope identifiers discovered in Step 2/3. Apply it to: scope lists, per-scope tables, `resource_id`/`RESOURCE_UID` fields, any identifiers inside `risk`/`remediation` text, and file-name prefixes. Persist the real->label mapping to an operator-only sidecar (`anon_map.json` in your working area) for the Step 10 verification gate. This sidecar is NOT part of the customer deliverables. The shipped `analysis.json` and all generated artifacts must contain ONLY the generic labels (e.g. `Scope A`) — never the real identifiers, and never the reverse label->real mapping.
- **Rule**: All later steps consume this canonical dataset ONLY — they must never re-read raw identifiers from source files.

### Step 4: Generate HTML Dashboard
- **Mode**: `agentic`
- **Tool**: `file_write` (load html_design + highcharts skills first; use CDN Highcharts URLs)
- **Input**: Canonical dataset from Step 3/3a + customer info
- **Output**: `{{output_folder_path}}/reports/{Customer}_Security_Dashboard.html`
- **Validate**: File created, contains Highcharts charts + data tables; if `anonymize=true`, contains NO real identifiers (see Step 10 gate)

Dashboard must include:
1. KPI cards (Total Checks, Pass Rate %, Critical Findings, High Findings, Scopes Assessed — where "scope" = accounts/subscriptions/projects/tenancies)
2. Security Score gauge (solid-gauge showing pass rate %)
3. Findings by Severity chart (donut: Critical/High/Medium/Low, plus Other when non-zero)
4. Findings by Service chart (top 10 services bar chart) — use the DETECTED provider's service names
5. **Findings by Cloud Provider** (when >1 provider present): a breakdown chart by provider
6. Top Failed Checks table (check_title, service, severity, count, risk description)
7. Compliance Framework Coverage (per-framework pass rate if available; frameworks appropriate to each cloud)
8. Remediation Priority cards (Critical → High → Medium, with provider-appropriate actions and Terraform snippets from Prowler data)
9. Phased Remediation Roadmap (Immediate: Critical, Week 1-2: High, Month 1: Medium, Ongoing: Low)
10. **Cloud Shared Responsibility Model** reminder — provider-appropriate wording (AWS Shared Responsibility Model; Azure shared responsibility; Google shared responsibility; OCI shared security model). If multiple providers, state it generically.
11. Footer with data sources, scan date, and — **only if `anonymize=false`** — the scope identifiers. If `anonymize=true`, show masked labels only.

**Branding: NEUTRAL — no cloud logo.** Do NOT embed any cloud-provider logo. Use a clean, neutral header: a dark slate band (e.g. `#1F2937`) with the report title and customer name, and a subtle accent color. This keeps deliverables safe for single-cloud or mixed multi-cloud customer distribution.

**CRITICAL**: Use CDN Highcharts URLs (`https://cdn.jsdelivr.net/npm/highcharts@12.1.2/`) — pin the version so the dashboard renders consistently and offline-of-your-app.

### Step 5: Generate PPTX Deck
- **Mode**: `agentic`
- **MANDATORY**: This step is NOT optional — always generate the PPTX deck as part of the workflow. Do NOT skip it due to time or complexity.
- **Tool**: `run_python` (matplotlib for charts) + `run_javascript` (pptxgenjs)
- **Input**: Canonical dataset from Step 3/3a + customer info
- **Output**: `{{output_folder_path}}/reports/{Customer}_Security_Assessment_Deck.pptx`
- **Validate**: PPTX file created with 11 slides (see Step 5b); if `anonymize=true`, NO real identifiers present

**Step 5a: Generate chart PNGs with matplotlib:**
- Severity distribution donut (Critical/High/Medium/Low with counts, plus an "Other"
  slice for findings whose severity is missing/unrecognized — include it only when
  non-zero, so the donut always reconciles with the total failed-check count)
- Top 10 services failure bar chart (detected provider's services)
- Security score gauge
- Compliance framework coverage bar chart
- Findings by provider (only if >1 provider)

**Step 5b: Build PPTX with pptxgenjs (11 slides):**
1. Title — "Cloud Security Assessment", customer name, provider(s) assessed, "Confidential" (neutral — no cloud logo)
2. Executive Summary — KPI boxes (Score %, Critical, High, Medium, Low, plus Other when non-zero) + key insights
3. Severity Distribution — embedded chart + risk summary
4. Findings by Service — embedded chart + top 5 services with descriptions (provider-appropriate)
5. Critical & High Findings Detail — top 10 critical/high with risk + remediation
6. Remediation: Immediate Actions — icon cards for Critical findings with CLI/Terraform snippets
7. Remediation: Short-Term Actions — icon cards for High severity findings
8. Compliance Framework Coverage — per-framework pass rates + gaps
9. Implementation Roadmap — 4 phase boxes (Immediate → Week 1-2 → Month 1 → Ongoing)
10. Cloud Security Best Practices & Next Steps — provider-appropriate security best-practice checklist
11. Thank You / Closing (neutral)

**Consistent on every slide:** neutral header "Customer — Cloud Security Assessment" + slide number. Use `pres.layout = 'LAYOUT_16x9'` (10"×5.625").

**Branding: NEUTRAL — no cloud logo in the PPTX.** Do NOT embed any cloud logo. Use a neutral dark-slate title bar and accent color only.

### Step 6: Present Recommendations & Ask for IaC Selection
- **Mode**: `agentic`
- **Input**: Top failed security checks from Step 3 (provider-aware)
- **Output**: User's remediation selection
- **Validate**: User provides selection

**IaC format is Terraform for all clouds** — Terraform works across AWS, Azure, GCP, and OCI and keeps output consistent for multi-cloud, so no per-scan format question is needed.

**Remediation Selection (multi-select) — present provider-appropriate options** based on the detected cloud(s) and the top failed checks. Examples by provider:
- **AWS**: Object storage public-access + encryption (S3), IAM MFA enforcement, Security Group restriction (no 0.0.0.0/0), EBS/RDS encryption, CloudTrail multi-region, VPC Flow Logs, KMS key rotation
- **Azure**: Storage account secure-transfer + public access, Entra ID MFA/conditional access, NSG restriction, Disk/SQL encryption, Activity Log + diagnostic settings, Key Vault soft-delete/purge protection
- **GCP**: GCS uniform bucket-level access + public access prevention, IAM least-privilege, Firewall rule restriction, CMEK encryption, Cloud Audit Logs, KMS key rotation
- **OCI**: Object Storage visibility + encryption, IAM policy hardening, Security List restriction, Block Volume/DB encryption, Audit/Logging, Vault key rotation

All scripts in **Terraform (HCL)** — one consistent language across clouds. Use the correct provider block(s) (`aws`, `azurerm`, `google`, `oci`).

### Step 7: Generate IaC Scripts (Terraform)
- **Mode**: `agentic`
- **Tool**: `file_write`
- **Input**: Selected remediations from Step 6
- **Output**: Terraform files in `{{output_folder_path}}/iac/`

**IMPORTANT**: Prowler output already contains remediation code (REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_CLI, REMEDIATION_CODE_NATIVEIAC). Use `REMEDIATION_CODE_TERRAFORM` as the starting point but enhance it into complete modules with proper variables, providers, tags/labels, and outputs. Use the correct Terraform provider for the target cloud.

**Reminder:** Generated Terraform touches sensitive controls (identity, network, logging, encryption). Include the review-before-deploy disclaimer in the module README and require `terraform plan` review before `apply`.

### Step 8: Generate README
- **Mode**: `deterministic`
- **Tool**: `file_write`
- **Output**: `{{output_folder_path}}/{Customer}_README.md`

README structure:
1. Overview — provider(s) & scopes assessed, scan date, security score, critical findings count
2. Prerequisites — Terraform, provider CLI(s) (aws/az/gcloud/oci), provider credentials, `terraform validate`/`tflint`
3. Findings Summary by Severity + Service (+ by provider if multi-cloud)
4. Compliance Framework Coverage
5. For each Terraform module: description, variables, `terraform init/plan/apply`, rollback (`terraform destroy`), validation
6. **Review-before-deploy disclaimer** for the generated IaC
7. Post-deployment security validation checklist (provider-appropriate)
8. Re-assessment guidance (re-run Prowler for the relevant provider)

### Step 9: Generate Remediation Plan (PDF)
- **Mode**: `agentic`
- **Tool**: `run_python` (reportlab)
- **Output**: `{{output_folder_path}}/{Customer}_Security_Remediation_Plan.pdf`

Plan structure:
1. Title page (neutral branding)
2. Table of Contents
3. Executive Summary — security score, critical count, top risks, provider(s)
4. Findings Summary Table (provider, check, service, severity, count, compliance)
5. Phase 1: Immediate (Day 1-3) — Critical findings: MFA/identity, public exposure, exposed secrets
6. Phase 2: Short-Term (Week 1-2) — High: encryption, logging, network restrictions
7. Phase 3: Medium-Term (Month 1) — Medium: best practices, compliance gaps
8. Phase 4: Ongoing — Low + governance: periodic scans, policy-as-code, threat detection
9. Risk Matrix (use Paragraph objects for wrapping)
10. Compliance Gap Analysis — per-framework pass rates + remediation priority
11. Success Metrics — Security score target, mean-time-to-remediate, compliance %
12. Appendix: Terraform module reference

**Embed the chart PNGs** generated in Step 5a (severity donut, top services, score gauge, compliance coverage) into the relevant sections — do NOT produce a text-only PDF.

**PDF Branding:** NEUTRAL header/footer on every page via onPage callback (dark-slate band + title; no cloud logo).

### Step 10: Verify Anonymization, Open Deliverables & Summarize
- **Mode**: `deterministic`
- **Tool**: `run_python` (verification) + `open_in_session_tab`

**Anonymization verification gate (if `anonymize=true`):** Before presenting results, scan every generated artifact for leaked identifiers:
- Load the persisted `anon_map.json` (operator-side only — it holds the real->label mapping and is NEVER shipped to the customer). For each real identifier, grep the text content of the HTML, README, PDF (extracted text), the PPTX (unzip and scan slide XML), every Terraform file in `iac/`, **and the intermediate `analysis.json`** (the data file the generators consume). Do NOT store the reverse (label->real) mapping in `analysis.json` — keep only the generic labels there; the real->label mapping belongs solely in `anon_map.json`.
- If ANY real identifier is found, fix the source data/mapping and regenerate the affected artifact(s). Do not present until the scan is clean.
- Report the verification result to the user (e.g. "Anonymization verified across all artifacts — 0 leaked identifiers").

Then open the HTML dashboard + PPTX deck and present a summary with links.

## Output

```
{{output_folder_path}}/                                   # user's choice, or default <cloud>/assessment-summary-<provider>/
├── reports/
│   ├── {Customer}_Security_Dashboard.html               # Interactive Highcharts dashboard (neutral branding)
│   └── {Customer}_Security_Assessment_Deck.pptx         # Neutral executive deck (11 slides)
├── {Customer}_README.md                                 # Usage guide
├── {Customer}_Security_Remediation_Plan.pdf             # Phased plan (neutral branding, charts embedded)
└── iac/
    ├── providers.tf                                     # Shared provider + terraform block
    ├── variables.tf                                     # All variable declarations (shared)
    ├── locals.tf                                        # Shared tags/labels
    ├── terraform.tfvars.example                         # One example tfvars for all modules
    ├── {Customer}_<provider>_<remediation>.tf           # Resource-only module (provider-appropriate)
    └── ... (per user selection)
```

**File naming:** ALL output files prefixed with customer name. If `anonymize=true`, ensure the prefix and file contents contain no real identifiers.

## IaC Quality Guidelines

All generated **Terraform** modules MUST adhere to these standards (apply the equivalent for the target provider — `aws`, `azurerm`, `google`, `oci`):

### 1. Identity & Security
- Create dedicated roles/service principals/service accounts per resource (no shared identities)
- Apply least-privilege policies — only permissions the resource actually needs
- Enable encryption at rest and in transit by default (e.g. AWS `StorageEncrypted`; Azure `enable_https_traffic_only`; GCP CMEK; OCI encryption)
- Disable public access by default (e.g. S3 public access block; Azure storage public access; GCP public access prevention; OCI private visibility)

### 2. Native Resources Only
- Use native Terraform provider resources — NEVER use `null_resource` + `local-exec` hacks

### 3. Variables Drive Everything
- ALL configurable values must be Terraform variables with types, descriptions, and sensible defaults; use validation blocks

### 4. Safety Defaults
- Use `prevent_destroy` / lifecycle rules for security-critical resources (audit logs, key stores)
- Default to the safest option (encryption=true, public_access=false, mfa=required)

### 5. Accurate Naming
- Resource names: `{customer}-{purpose}`; consistent, lowercase where the provider requires

### 6. README + Variable Input Files
- Generate ONE shared `terraform.tfvars.example` covering all modules (variables declared once in `variables.tf`)

### 7. Pre-flight Validation
- `terraform init`, `terraform validate`, `tflint` instructions in README

### 8. Tagging/Labeling & Observability
- Tag/label ALL resources (Environment, ManagedBy=Terraform, Purpose=SecurityRemediation); enable resource-level logging/alarms

### 9. Completeness Checklist
- Variables, tags/labels, outputs, rollback instructions, apply/plan commands

### 10. Outputs Section
- Export key resource IDs/ARNs/self-links/OCIDs for cross-module referencing

### 11. Conditions for Optional Resources
- Use `count` / `for_each` for toggles

### 12. State Management (Terraform)
- Document a remote backend appropriate to the cloud (AWS S3+DynamoDB; Azure Storage; GCS; OCI Object Storage); include `backend.tf.example`

### 13. Drift Detection Guidance
- Include `terraform plan`-based drift detection commands in README

### 14. Explicit Rollback Instructions
- Per-module, document `terraform destroy` order and any manual steps

### 15. Cost Estimation Notes
- Note billable items (audit logging, flow logs, key stores, threat detection)

### 16. Dependency Ordering
- `depends_on` for multi-resource modules

### 17. Secrets Handling
- NEVER hardcode credentials; use the provider's secret store (Secrets Manager/SSM, Key Vault, Secret Manager, OCI Vault) and Terraform variables marked `sensitive = true`

### 18. Multi-Account / Multi-Cloud & Enterprise Considerations
- Support multiple scopes via provider aliases and `for_each`; document assume-role / service-principal / workload-identity patterns per cloud

### 19. Review Before Deploy
- Every module README MUST state that the IaC is auto-generated, touches sensitive controls, and must be reviewed and `terraform plan`-checked before `apply`.

## Lessons Learned

### Do
- Detect the `PROVIDER` field first and drive ALL provider-specific content (services, examples, terminology, IaC provider) from it
- Prefer the richest source per scan: main CSV, else OCSF JSON, else Security Hub JSON, else HTML — and normalize them all to one schema
- Parse Prowler CSVs with semicolon delimiter (`;`) — NOT comma
- Parse OCSF JSON with `json.load` and map to the same normalized schema as the CSV path
- Use compliance/ subfolder CSVs for framework-specific coverage analysis (frameworks vary by cloud)
- Leverage `REMEDIATION_CODE_TERRAFORM` from Prowler as the Terraform starting point
- Group findings by: severity first, then service, then check_id
- Calculate security score as: (pass_count / (pass_count + fail_count)) * 100 — overall and per provider/scope, with MANUAL/INFO/MUTED excluded from the denominator
- Always present Critical findings first in all deliverables
- Make anonymization a REQUIRED up-front choice; apply the mapping to the canonical dataset (Step 3a) and VERIFY across every artifact (Step 10 gate)
- Use NEUTRAL branding (no cloud logo) on the dashboard, deck, and PDF
- Embed the chart PNGs into the PDF (not text-only)
- Include the review-before-deploy disclaimer for all generated IaC
- Prefix ALL output files with customer name
- Pin the Highcharts CDN version
- Use Paragraph objects in reportlab Table cells for text wrapping
- IaC is Terraform for all clouds — use the correct provider block

### Don't
- Don't advertise AWS-only outputs — this skill is multi-cloud (AWS/Azure/GCP/OCI)
- Don't hard-code AWS service names, examples, or Shared Responsibility wording when the scan is another cloud
- Don't embed any cloud logo — branding is neutral
- Don't rely on CSV alone — OCSF JSON, Security Hub JSON, and HTML are valid inputs and must be parseable
- Don't treat anonymization as an unimplemented reminder — it is a required choice, applied AND verified
- Don't show real account/subscription/project/tenancy identifiers when `anonymize=true`
- Don't publish real-looking identifiers in examples — use obvious placeholders (e.g. account `123456789012`)
- Don't produce a text-only PDF — embed the charts
- Don't assume comma-delimited CSVs — Prowler uses semicolons
- Don't skip the PPTX deck — it is mandatory
- Don't use `LAYOUT_WIDE` (13.33"×7.5") for pptxgenjs — ALWAYS use `pres.layout = 'LAYOUT_16x9'` (10"×5.625")
- Don't produce mixed IaC languages — Terraform only
- Don't read all rows into memory for very large CSVs (100K+ rows) — use chunked reading or pandas

### Common Failures
- **Provider assumptions**: Defaulting to AWS terminology on an Azure/GCP/OCI scan. Always branch on `PROVIDER`.
- **CSV-only parsing**: Some scans ship only OCSF JSON or HTML. Implement all input paths.
- **Semicolon delimiter**: Prowler CSVs use `;` not `,`. Wrong delimiter produces single-column data.
- **Anonymization leaks**: Real IDs hiding in resource ARNs/URIs, PPTX slide XML, or IaC. The Step 10 gate must scan all artifacts, including unzipped PPTX XML and .tf files.
- **Large files**: Some Prowler outputs have 10K+ rows. Use pandas or chunked reading.
- **Multiple providers/scopes in one folder**: Group and report per provider and per scope.
- **Missing remediation code**: Not all checks have `REMEDIATION_CODE_TERRAFORM`. Fall back to `REMEDIATION_RECOMMENDATION_TEXT`.

### When to Ask the User
- Input/output folder paths
- **Anonymize identifiers? — REQUIRED, up front (before generating anything)**
- Which remediations to generate Terraform for (multi-select, provider-appropriate)
- Customer name if not determinable from files
