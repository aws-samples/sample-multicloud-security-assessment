# Cloud Security Assessment — Python Scripts

A standalone, runnable pipeline that turns **Prowler** security scan output (from AWS, Azure, GCP, or OCI) into a full set of deliverables: an interactive HTML dashboard, an 11-slide PowerPoint deck, a phased remediation plan (PDF), and Terraform remediation modules.

No proprietary runtime required — just Python and Node.

> ⚠️ **Review generated IaC before deploying.** The Terraform modules are auto-generated from Prowler's remediation data and touch sensitive controls (identity, network, logging, encryption/key stores). Review each module, run `terraform plan`, and validate against your environment before `terraform apply`.

## Multi-cloud

The pipeline is **provider-aware** — it reads Prowler's `PROVIDER` field and adapts service names, terminology (account / subscription / project / tenancy), compliance frameworks, and Terraform provider blocks (`aws` / `azurerm` / `google` / `oci`) to the detected cloud(s). A single input folder may contain scans from more than one cloud.

## Supported inputs

Prowler main CSV (semicolon-delimited), Prowler OCSF JSON (`*.ocsf.json`), Security Hub JSON (AWS ASFF), Prowler HTML reports, and Prowler compliance CSVs.

Prowler emits the **same findings in multiple formats**, so the analyzer parses a **single richest source** in priority order — CSV → OCSF JSON → Security Hub JSON → HTML — to avoid double-counting. Compliance CSVs are read separately for per-framework coverage.

## Requirements

- **Python 3.9+** with: `matplotlib`, `numpy`, `reportlab`
- **Node.js 18+** with: `pptxgenjs`
- To deploy the generated IaC: **Terraform** + the relevant provider CLI (`aws` / `az` / `gcloud` / `oci`)

```bash
pip3 install matplotlib numpy reportlab
cd scripts && npm install
```

## Scripts

| Script | Purpose | Language |
|--------|---------|----------|
| `analyze_security_data.py` | Scan + parse Prowler output (CSV/OCSF/ASFF/HTML), provider-aware, → `analysis.json` | Python |
| `generate_charts.py` | Chart PNGs (matplotlib) for the deck/PDF | Python |
| `generate_dashboard.py` | Interactive HTML dashboard (Highcharts, neutral branding) | Python |
| `generate_pptx.js` | 11-slide PowerPoint deck (neutral branding) | Node.js |
| `generate_pdf.py` | Phased remediation plan PDF (charts embedded) | Python |
| `generate_iac.py` | Terraform remediation modules (provider-aware) | Python |
| `generate_readme.py` | Customer README with deploy instructions | Python |

## Usage

```bash
IN=./prowler-output
OUT=./output
CUST="Acme Corp"

# 1. Analyze
python3 scripts/analyze_security_data.py "$IN" "$OUT/analysis.json" --customer "$CUST"
# Output folder is your choice. If you OMIT the analysis.json path and --output-dir,
# a default "assessment-summary-<provider>" folder is created (provider auto-detected
# from the scan data): parent of the input folder when the input is named "output"
# (aws/output -> aws/assessment-summary-aws/), else the input folder itself
# (aws -> aws/assessment-summary-aws/). Run once per provider. Override with --output-dir.
#   python3 scripts/analyze_security_data.py "$IN" --customer "$CUST"            # default output
#   python3 scripts/analyze_security_data.py "$IN" --output-dir "$OUT" --customer "$CUST"
# (add --anonymize to replace real account/subscription/project/tenancy IDs
#  with generic labels — Scope A, Scope B, ... — across every downstream artifact)

# 2. Charts
python3 scripts/generate_charts.py "$OUT/analysis.json" "$OUT/charts/"

# 3. Dashboard
python3 scripts/generate_dashboard.py "$OUT/analysis.json" "$OUT/reports/${CUST}_Security_Dashboard.html"

# 4. Deck
cd scripts && node generate_pptx.js "../$OUT/analysis.json" "../$OUT/charts/" "../$OUT/reports/${CUST}_Security_Assessment_Deck.pptx" && cd ..

# 5. Terraform IaC (provider auto-detected from analysis.json; override with --provider)
python3 scripts/generate_iac.py "$OUT/analysis.json" "s3_public_access,iam_mfa,audit_logging" "$OUT/iac/"

# 6. README
python3 scripts/generate_readme.py "$OUT/analysis.json" "$OUT/${CUST}_README.md"

# 7. PDF (charts embedded)
python3 scripts/generate_pdf.py "$OUT/analysis.json" "$OUT/${CUST}_Security_Remediation_Plan.pdf" --charts "$OUT/charts/"
```

## Output structure

`output/` below is illustrative; by default the folder is `<cloud>/assessment-summary-<provider>/`.

```
output/
├── analysis.json
├── charts/
├── reports/
│   ├── <Customer>_Security_Dashboard.html
│   └── <Customer>_Security_Assessment_Deck.pptx
├── <Customer>_README.md
├── <Customer>_Security_Remediation_Plan.pdf
└── iac/
    ├── providers.tf                       # shared provider + terraform block
        ├── variables.tf                       # all variable declarations (shared)
        ├── locals.tf                          # shared tags/labels
        ├── terraform.tfvars.example           # one example tfvars for all modules
        └── <Customer>_<provider>_<remediation>.tf   # resource-only module(s)
```

## License

MIT-0. See the repository `LICENSE` file.
