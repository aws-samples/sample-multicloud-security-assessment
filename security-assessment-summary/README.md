# Security Assessment Summary

Analyze **Prowler** security scan output from any supported cloud (AWS, Azure, GCP, OCI) and generate a complete set of customer-ready deliverables — all from a single command or conversation.

## Deliverables

| Output | Description |
|--------|-------------|
| **HTML Dashboard** | Interactive Highcharts dashboard with KPI cards, security-score gauge, severity/service charts, findings tables, and phased remediation roadmap |
| **PowerPoint Deck** | 11-slide executive presentation (16:9, neutral branding) |
| **PDF Remediation Plan** | Phased plan: Immediate → Short-term → Medium-term → Ongoing |
| **Terraform Scripts** | Provider-appropriate `.tf` modules (`aws` / `azurerm` / `google` / `oci`) |
| **README** | Customer-facing guide tying all deliverables together |

## Choose Your Variant

This tool is available in three variants. Pick the one that best fits your workflow:

| Variant | Best For | How to Run |
|---------|----------|------------|
| [**Kiro Agent**](kiro-agent/README.md) | Interactive, conversational workflow using Kiro CLI | `kiro chat` with the agent definition |
| [**Python Scripts**](python-script/README.md) | Standalone CLI pipeline — no AI runtime needed | Run scripts directly with `python3` and `node` |
| [**Amazon Quick Skill**](quick-skill/README.md) | Amazon Q Developer / Quick skill integration | Install as a Quick skill |

All three variants target the same deliverables — an interactive HTML dashboard, an executive PPTX deck, a phased remediation-plan PDF, Terraform modules, and a README. They differ in **execution model**:

- **Python Scripts** is the single source of truth — a standalone, self-contained CLI pipeline. **Kiro Agent** is a thin conversational wrapper: it bundles no scripts of its own and invokes the `python-script/scripts/` code via relative paths, so it produces identical output with zero duplication. (Because of this, the Kiro Agent variant requires the `python-script/` folder to be present alongside it.)
- The **Amazon Quick Skill** ships **no bundled scripts** — its `SKILL.md` instructs the AI assistant to generate the equivalent logic at run time. It targets the same deliverables and format, but because the code is LLM-generated per run, output is functionally equivalent rather than byte-for-byte identical, and it requires the Amazon Quick runtime.

Each variant is self-contained: pick one based on your workflow and run it independently.

## Multi-Cloud Support

The pipeline is **provider-aware** — it reads Prowler's `PROVIDER` field and automatically adapts:
- Service names and terminology (account / subscription / project / tenancy)
- Compliance framework mappings
- Terraform provider blocks (`aws` / `azurerm` / `google` / `oci`)
- Remediation recommendations

A single input folder may contain scans from more than one cloud.

## Supported Input Formats

- Prowler main CSV (semicolon-delimited)
- Prowler OCSF JSON (`*.ocsf.json`)
- Security Hub / ASFF JSON (AWS)
- Prowler HTML reports
- Prowler compliance CSVs (per-framework coverage)

## Requirements

- **Python 3.9+** with packages: `matplotlib`, `numpy`, `reportlab`
- **Node.js 18+** with package: `pptxgenjs`
- For Terraform deployment: **Terraform CLI** + relevant provider CLI (`aws` / `az` / `gcloud` / `oci`)

```bash
pip3 install matplotlib numpy reportlab
# pptxgenjs lives with the shared scripts; all three variants use this one install.
cd python-script/scripts && npm install
```

## Quick Start

1. Run a Prowler scan against your cloud environment (or use existing scan output)
2. Point any variant at the Prowler output folder
3. Receive the full deliverable set in an output directory

See the individual variant READMEs linked above for detailed usage instructions.

## Sample Deliverables

See what the tool produces — these are real outputs from an anonymized AWS assessment:

| Sample | Description |
|--------|-------------|
| [Security Dashboard (HTML)](samples/Sample_Security_Dashboard.html) | Interactive dashboard with KPI cards, security-score gauge, severity/service charts, findings tables, and phased remediation roadmap |
| [Remediation Plan (PDF)](samples/Sample_Security_Remediation_Plan.pdf) | Phased remediation plan with executive summary, risk matrix, compliance gap analysis, and Terraform appendix |

> **Note**: These samples were generated from a real scan with account identifiers anonymized. Download and open locally — the HTML dashboard requires a browser, and the PDF can be viewed in any PDF reader.

## Key Features

- **Anonymization**: Optionally mask account/subscription/project identifiers across all deliverables
- **Neutral branding**: No cloud-provider logos — safe for single-cloud or mixed multi-cloud engagements
- **Terraform review disclaimer**: All generated IaC includes a prominent disclaimer reminding users to review and `terraform plan` before `apply`
- **Compliance frameworks**: Automatic detection and reporting across CIS, SOC2, PCI, HIPAA, ISO27001, NIST, MITRE ATT&CK, and more

> ⚠️ **Review generated IaC before deploying.** The Terraform modules are auto-generated from Prowler's remediation data and touch sensitive controls (identity, network, logging, encryption/key stores). Run `terraform plan` and validate against your environment before `apply`.
