# Cloud Security Assessment (Multi-Cloud, Prowler) — Amazon Quick Skill

An Amazon Quick skill that analyzes **Prowler security scan outputs from any cloud — AWS, Azure, GCP, or OCI** — and generates a complete set of customer-ready deliverables:

- 📊 **Interactive HTML dashboard** — KPI cards, security-score gauge, severity/service charts (Highcharts), findings tables, remediation cards, and a phased roadmap
- 📑 **PowerPoint deck** (11 slides, neutral branding) — executive summary, findings, remediation, roadmap
- 📄 **Phased remediation plan** (PDF, with charts embedded)
- 🛠️ **Terraform remediation modules** — one consistent IaC language across all clouds
- 📘 **README** tying the deliverables together

> **Neutral branding.** Deliverables carry no cloud-provider logo, so they are safe to share for single-cloud or mixed multi-cloud engagements.

> ⚠️ **Review generated IaC before deploying.** The Terraform this skill produces is auto-generated from Prowler's remediation fields and touches sensitive controls (identity, network rules, logging, encryption/key stores). Review it, run `terraform plan`, and validate against your environment before `apply`. It is a starting point, not guaranteed production-ready.

## Multi-cloud support

Prowler emits a consistent output schema across providers, so this skill is **provider-aware**. It reads the `PROVIDER` field and adapts service names, examples, terminology, compliance frameworks, and Terraform providers to the detected cloud(s). A single input folder may contain scans from more than one cloud.

| Concept | AWS | Azure | GCP | OCI |
|---|---|---|---|---|
| Scope | Account | Subscription / Tenant | Project / Org | Tenancy / Compartment |
| Object storage | S3 | Blob Storage | Cloud Storage | Object Storage |
| Identity | IAM | Entra ID | Cloud IAM | IAM |
| Key management | KMS | Key Vault | Cloud KMS | Vault / KMS |
| Threat detection | GuardDuty | Defender for Cloud | Security Command Center | Cloud Guard |

## Supported input formats

The skill parses whichever of these are present, preferring the richest source per scan:

- **Prowler main CSV** (semicolon-delimited)
- **Prowler OCSF JSON** (`*.ocsf.json`)
- **Security Hub JSON** exports (AWS ASFF) and equivalent posture exports
- **Prowler HTML** reports
- **Prowler compliance CSVs** (per-framework coverage)

## What it does

Given a folder of Prowler output, the skill:

1. Scans and identifies assessment files, and auto-detects the cloud provider(s) and account/scope identifiers
2. Parses findings from CSV / OCSF JSON / Security Hub JSON / HTML into one normalized schema — severity, service, compliance mapping, remediation code
3. Computes a security score `(pass / total) × 100`, overall and per provider/scope
4. Optionally **anonymizes** account/subscription/project/tenancy identifiers (a required up-front choice), applied and verified across every artifact
5. Generates the dashboard, deck, Terraform IaC, README, and PDF

## Requirements

This is a skill for **Amazon Quick**. To use it you need the Amazon Quick app, which loads skills from a local skills directory. If you don't use Amazon Quick, the workflow described in `SKILL.md` is still a useful, tool-agnostic recipe for turning Prowler output into an assessment package.

To deploy the generated IaC you will also need:

- **Terraform**
- The relevant provider CLI (`aws`, `az`, `gcloud`, or `oci`) and credentials

## Install

Copy the skill folder into your Amazon Quick skills directory (the location is shown in the app's settings), then reload skills / restart the app:

```bash
cp -R quick-skill  <your-amazon-quick-skills-directory>/cloud-security-assessment
```

The destination folder name must match the `name:` field in the `SKILL.md` frontmatter (`cloud-security-assessment`), which is how Amazon Quick registers the skill.

## Usage

Trigger the skill with any of:

- "cloud security assessment"
- "analyze prowler output"
- "prowler assessment"
- "security posture assessment"

…or just point it at a folder of Prowler files. The skill will ask for:

- Input folder (Prowler output; may be nested, e.g. `<cloud>/output/`) and output folder (defaults to a per-provider `assessment-summary-<provider>/` folder if omitted)
- **Whether to anonymize account/subscription/project/tenancy identifiers** (required, asked up front)
- Customer name (auto-detected from the scan data where possible)
- Which remediations to generate Terraform for (provider-appropriate, multi-select)

IaC is always **Terraform** — one consistent language across all clouds.

## Output structure

```
<output_folder>/                                  # your choice, or default <cloud>/assessment-summary-<provider>/
├── reports/
│   ├── {Customer}_Security_Dashboard.html
│   └── {Customer}_Security_Assessment_Deck.pptx
├── {Customer}_README.md
├── {Customer}_Security_Remediation_Plan.pdf
└── iac/
    ├── providers.tf                       # shared provider + terraform block
    ├── variables.tf                       # all variable declarations (shared)
    ├── locals.tf                          # shared tags/labels
    ├── terraform.tfvars.example           # one example tfvars for all modules
    └── {Customer}_<provider>_<remediation>.tf   # resource-only module(s)
```

**Default output folder:** if you don't specify one, a per-provider `assessment-summary-<provider>` folder is created (provider auto-detected — e.g. `assessment-summary-aws`) beside the input. Run once per provider.

## License

MIT-0. See the repository `LICENSE` file.
