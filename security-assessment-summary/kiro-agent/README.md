# Cloud Security Assessment - Kiro Agent

> **Requires the sibling `python-script/` folder.** This Kiro agent is a thin
> conversational wrapper that runs the shared scripts in `../python-script/scripts/`.
> Download/clone both folders together (or the whole repo).

A Kiro CLI agent that analyzes multi-cloud **Prowler security assessment outputs**
(AWS, Azure, GCP, OCI) and generates comprehensive **customer-facing deliverables**.

## Deliverables

| Output | Description |
|--------|-------------|
| HTML Dashboard | Interactive Highcharts dashboard - KPIs, gauges, charts, per-provider breakdown |
| PPTX Deck | Executive presentation (16:9, neutral branding) |
| PDF Remediation Plan | Phased plan: Immediate -> Short-term -> Medium-term -> Ongoing |
| Terraform Scripts | Provider-appropriate `.tf` (aws / azurerm / google / oci) |
| README | Customer-facing guide tying all deliverables together |

## Requirements

- **Python 3.9+** with packages: `matplotlib`, `numpy`, `reportlab`
- **Node.js 18+** with package: `pptxgenjs`
- **Kiro CLI** installed and configured

### Install Python dependencies

```bash
pip3 install matplotlib numpy reportlab
```

### Install Node dependencies

```bash
cd ../python-script/scripts
npm install
```

## Supported Input Formats

Auto-detected and normalized to a single schema. Prowler emits the **same findings in multiple formats**, so a **single richest source** is used (priority: CSV → OCSF JSON → Security Hub JSON → HTML) to avoid double-counting; compliance CSVs are read separately.

- **Prowler CSV** (semicolon `;` delimited)
- **Prowler OCSF JSON** (provider from `cloud.provider`)
- **Security Hub / ASFF JSON**
- **Prowler HTML** reports

## Usage

From Kiro CLI, load this agent and provide a Prowler output folder:

```
kiro chat --agent kiro-agent/agent.md
```

Then trigger the workflow with any of:
- "cloud security assessment"
- "run security assessment"
- "analyze prowler output in /path/to/folder"

The agent will ask for:
1. **Input folder** - where your Prowler CSV/JSON/HTML files are
2. **Output folder** - where to save deliverables (your choice). If omitted, a default `assessment-summary-<provider>` folder is used (provider auto-detected, e.g. `assessment-summary-aws`): parent of the input folder when the input is named `output` (e.g. `aws/output` -> `aws/assessment-summary-aws/`), else the input folder itself. Run once per provider. Override with `--output-dir`.
3. **Customer/organization name** - detected from files if possible
4. **Which remediations** to generate Terraform for

## Output Structure

```
<output_dir>/
├── analysis.json                              # Intermediate analysis data
├── charts/                                    # Chart PNGs for PPTX
├── reports/
│   ├── <Customer>_Security_Dashboard.html
│   └── <Customer>_Security_Assessment_Deck.pptx
├── <Customer>_README.md
├── <Customer>_Security_Remediation_Plan.pdf
└── iac/
    └── <Customer>_<provider>_<capability>.tf
```

## Scripts (shared from `../python-script/scripts/`)

> This agent is a **thin wrapper** — it does not bundle its own scripts. The runnable
> code lives in the sibling `python-script/scripts/` folder (single source of truth),
> which must be present alongside `kiro-agent/`. The agent invokes it via relative paths.

| Script | Purpose | Language |
|--------|---------|----------|
| `analyze_security_data.py` | Parse multi-cloud/multi-format Prowler output, compute scores, output analysis.json | Python |
| `generate_dashboard.py` | Interactive HTML dashboard with Highcharts | Python |
| `generate_charts.py` | Chart PNGs (matplotlib) for PPTX embedding | Python |
| `generate_pptx.js` | Executive PowerPoint deck (16:9) | Node.js |
| `generate_pdf.py` | Phased remediation plan PDF (reportlab) | Python |
| `generate_iac.py` | Terraform templates (aws / azurerm / google / oci) | Python |
| `generate_readme.py` | Customer README with deploy instructions | Python |

## Manual Usage (without the Kiro agent)

You can run the scripts directly:

```bash
# 1. Analyze Prowler output
python3 ../python-script/scripts/analyze_security_data.py ./prowler-output ./output/analysis.json --customer "Acme Corp"
# Add --anonymize to mask account/subscription/project/tenancy IDs (Scope A, Scope B, ...) everywhere:
# python3 ../python-script/scripts/analyze_security_data.py ./prowler-output ./output/analysis.json --customer "Acme Corp" --anonymize

# 2. Generate HTML dashboard
python3 ../python-script/scripts/generate_dashboard.py ./output/analysis.json "./output/reports/Acme Corp_Security_Dashboard.html"

# 3. Generate chart PNGs
python3 ../python-script/scripts/generate_charts.py ./output/analysis.json ./output/charts/

# 4. Generate PPTX deck
cd ../python-script/scripts && node generate_pptx.js ../output/analysis.json ../output/charts/ "../output/reports/Acme Corp_Security_Assessment_Deck.pptx" && cd ..

# 5. Generate Terraform (provider auto-detected; override with --provider)
#    These capability names resolve on every provider. Provider-specific extras
#    (e.g. flow_logs, which is AWS only) are skipped with an error on other clouds.
python3 ../python-script/scripts/generate_iac.py ./output/analysis.json "object_storage_public_access,identity_mfa,audit_logging,key_management" ./output/iac/

# 6. Generate README
python3 ../python-script/scripts/generate_readme.py ./output/analysis.json "./output/Acme Corp_README.md"

# 7. Generate PDF
python3 ../python-script/scripts/generate_pdf.py ./output/analysis.json "./output/Acme Corp_Security_Remediation_Plan.pdf"
```

## Terraform Review Disclaimer

> **IMPORTANT - Review before applying.** The generated Terraform is
> **auto-generated** and touches **sensitive controls** (identity, network,
> logging, encryption). It is a **starting point, not a turnkey deployment**.
> Review every resource, adapt parameters to your environment, run
> `terraform init && terraform validate`, then run **`terraform plan`** and
> inspect the full change set **before** running **`terraform apply`**.

## Key Notes

- Prowler CSVs use **semicolons (`;`)** as delimiters - not commas
- PPTX uses `LAYOUT_16x9` (10" x 5.625")
- Neutral branding: dark-slate header (#1F2937), no cloud vendor logos
- IaC is **Terraform only** (aws / azurerm / google / oci)
- Provider-aware: detects AWS / Azure / GCP / OCI and adds a per-provider breakdown
- All output files are prefixed with the customer name
- All deliverables go under a single top-level `output/` directory

## License

Released under the **MIT-0** license.

---

*Built for Kiro CLI.*