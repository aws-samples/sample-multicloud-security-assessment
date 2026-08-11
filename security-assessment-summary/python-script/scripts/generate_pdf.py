#!/usr/bin/env python3
"""
generate_pdf.py — Generate a phased security remediation plan PDF (neutral branding, multi-cloud).

Embeds the chart PNGs produced by generate_charts.py when available.

Usage:
    python3 generate_pdf.py <analysis_json> <output_pdf_path> [--charts <charts_dir>]
"""

import argparse
import json
import os
import sys
from providers import PROVIDER_LABELS as PROVIDER_LABEL, PROVIDER_SCOPE_TERM as SCOPE_TERM

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    )
    from reportlab.lib.enums import TA_CENTER
except ImportError:
    print("ERROR: reportlab is required. Install with: pip3 install reportlab", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Neutral palette (no cloud-provider branding)
# ---------------------------------------------------------------------------
SLATE_DARK = colors.HexColor("#1F2937")
ACCENT = colors.HexColor("#3B82F6")
CRITICAL_RED = colors.HexColor("#D32F2F")
HIGH_ORANGE = colors.HexColor("#F57C00")
MEDIUM_YELLOW = colors.HexColor("#FBC02D")
LOW_GREEN = colors.HexColor("#388E3C")
LIGHT_GRAY = colors.HexColor("#F4F6F9")

def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _scope_term(providers):
    terms = {SCOPE_TERM.get(p, "scope") for p in providers}
    return terms.pop() if len(terms) == 1 else "scope"


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(2)
    canvas.line(0.5 * inch, 10.5 * inch, 8.0 * inch, 10.5 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.gray)
    canvas.drawString(0.75 * inch, 0.4 * inch, "Cloud Security Remediation Plan — Confidential")
    canvas.drawRightString(7.75 * inch, 0.4 * inch, f"Page {doc.page}")
    canvas.restoreState()


def _chart(charts_dir, name, width=5.5 * inch):
    """Return a reportlab Image flowable if the chart PNG exists, else None.

    `name` may be a single base name or a tuple of alias base names; the first
    matching file wins (covers both sev_donut/severity_donut style names).
    """
    if not charts_dir:
        return None
    names = name if isinstance(name, (tuple, list)) else (name,)
    candidates = []
    for n in names:
        candidates.extend([n, n + ".png"])
    for fn in candidates:
        p = os.path.join(charts_dir, fn)
        if os.path.exists(p):
            try:
                img = Image(p)
                ratio = img.imageHeight / float(img.imageWidth)
                img.drawWidth = width
                img.drawHeight = width * ratio
                return img
            except Exception:
                return None
    return None


def build_pdf(data: dict, output_path: str, charts_dir: str = ""):
    meta = data.get("metadata", {})
    customer = meta.get("customer", "Customer")
    scan_date = meta.get("scan_date", "")
    providers = (data.get("metadata", {}).get("providers")
                 or list(data.get("summary", {}).get("findings_by_provider", {}).keys())
                 or data.get("providers")
                 or [])
    provider_labels = [PROVIDER_LABEL.get(p, p.upper()) for p in providers]
    scopes = meta.get("scopes_assessed", meta.get("accounts_assessed", [])) or []
    scope_term = _scope_term(providers)
    summary = data["summary"]
    severity = summary["findings_by_severity"]
    score = summary["security_score"]
    top_checks = data["top_failed_checks"][:20]
    compliance = data.get("compliance_coverage", {})

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.9 * inch, bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=14, textColor=ACCENT, spaceAfter=24))
    styles.add(ParagraphStyle("SectionHead", parent=styles["Heading1"], fontSize=16, textColor=SLATE_DARK, spaceBefore=18, spaceAfter=10))
    styles.add(ParagraphStyle("SubHead", parent=styles["Heading2"], fontSize=13, textColor=SLATE_DARK, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle("BodyWrap", parent=styles["Normal"], fontSize=10, leading=13, spaceAfter=6))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=9, leading=11, textColor=colors.gray))
    styles.add(ParagraphStyle("CenterTitle", parent=styles["Title"], fontSize=28, textColor=SLATE_DARK, alignment=TA_CENTER))

    E = []

    # Title
    E.append(Spacer(1, 2 * inch))
    E.append(Paragraph("Cloud Security", styles["CenterTitle"]))
    E.append(Paragraph("Remediation Plan", styles["CenterTitle"]))
    E.append(Spacer(1, 0.5 * inch))
    E.append(Paragraph(customer, styles["Subtitle"]))
    E.append(Paragraph(f"Assessment Date: {scan_date}", styles["BodyWrap"]))
    E.append(Paragraph(f"Cloud Provider(s): {', '.join(provider_labels)}", styles["BodyWrap"]))
    E.append(Paragraph(f"{scope_term.capitalize()}(s): {', '.join(scopes) if scopes else 'N/A'}", styles["BodyWrap"]))
    E.append(Paragraph("Confidential — For Customer Use Only", styles["Small"]))
    E.append(PageBreak())

    # Executive Summary + score gauge chart
    E.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
    E.append(Paragraph(
        f"This remediation plan addresses findings from a security assessment of {len(scopes)} "
        f"{scope_term}(s) on {', '.join(provider_labels)}, conducted on {scan_date}. The assessment "
        f"evaluated {summary['total_checks']:,} security checks, achieving an overall security score "
        f"of <b>{score}%</b>.", styles["BodyWrap"]))
    E.append(Spacer(1, 0.15 * inch))
    gauge = _chart(charts_dir, "score_gauge", width=3.2 * inch)
    if gauge:
        E.append(gauge)
    E.append(Spacer(1, 0.15 * inch))
    kpi = [["Metric", "Value"],
           ["Security Score", f"{score}%"],
           ["Total Checks", f"{summary['total_checks']:,}"],
           ["Pass", f"{summary['pass_count']:,}"],
           ["Fail", f"{summary['fail_count']:,}"],
           ["Critical", str(severity["critical"])],
           ["High", str(severity["high"])],
           ["Medium", str(severity["medium"])],
           ["Low", str(severity["low"])]]
    if severity.get("other"):
        kpi.append(["Other", str(severity["other"])])
    t = Table(kpi, colWidths=[3 * inch, 2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SLATE_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
    ]))
    E.append(t)
    E.append(PageBreak())

    # Findings Summary + severity + service charts
    E.append(Paragraph("2. Findings Summary", styles["SectionHead"]))
    for cname, cap in ((("severity_donut", "sev_donut"), "Findings by Severity"),
                       (("service_bar", "svc_bar"), "Top Services by Failed Checks")):
        img = _chart(charts_dir, cname)
        if img:
            E.append(Paragraph(cap, styles["SubHead"]))
            E.append(img)
            E.append(Spacer(1, 0.15 * inch))

    if len(providers) > 1:
        prov_img = _chart(charts_dir, "provider_bar")
        if prov_img:
            E.append(Paragraph("Findings by Cloud Provider", styles["SubHead"]))
            E.append(prov_img)
            E.append(Spacer(1, 0.15 * inch))

    E.append(Paragraph("Top Failed Security Checks", styles["SubHead"]))
    table_data = [["#", "Check", "Service", "Severity", "Count"]]
    for i, check in enumerate(top_checks[:15], 1):
        table_data.append([
            str(i),
            Paragraph(str(check.get("check_title", ""))[:55], styles["BodyWrap"]),
            str(check.get("service", "")),
            str(check.get("severity", "")),
            str(check.get("count", 0)),
        ])
    t = Table(table_data, colWidths=[0.4 * inch, 3.2 * inch, 1.3 * inch, 0.9 * inch, 0.6 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SLATE_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
    ]))
    E.append(t)
    E.append(PageBreak())

    def phase(title, blurb, sev_label, checks, emoji, limit):
        E.append(Paragraph(title, styles["SectionHead"]))
        E.append(Paragraph(blurb, styles["BodyWrap"]))
        picks = [c for c in checks if str(c.get("severity", "")).lower() == sev_label]
        if picks:
            for c in picks[:limit]:
                E.append(Paragraph(f"<b>{emoji} {c.get('check_title','')}</b>", styles["SubHead"]))
                E.append(Paragraph(f"Service: {c.get('service','N/A')} | Count: {c.get('count',0)}", styles["Small"]))
                E.append(Paragraph(c.get("remediation_text") or "Refer to the provider's documentation for remediation steps.", styles["BodyWrap"]))
                E.append(Spacer(1, 0.12 * inch))
        else:
            E.append(Paragraph("No findings at this severity.", styles["BodyWrap"]))
        E.append(PageBreak())

    phase("3. Phase 1: Immediate Actions (Day 1-3)",
          "Address all Critical findings immediately — highest risk to the environment.",
          "critical", top_checks, "🚨", 8)
    phase("4. Phase 2: Short-Term Actions (Week 1-2)",
          "Address High severity findings within the first two weeks.",
          "high", top_checks, "⚠️", 8)
    phase("5. Phase 3: Medium-Term Actions (Month 1)",
          "Address Medium severity findings within the first month.",
          "medium", top_checks, "📋", 6)

    # Phase 4 — provider-generic governance
    E.append(Paragraph("6. Phase 4: Ongoing Governance", styles["SectionHead"]))
    # Provider-appropriate service names — only reference the cloud(s) actually assessed.
    _compliance_svc = {
        "aws": "AWS Config", "azure": "Azure Policy",
        "gcp": "GCP Organization Policy", "oci": "OCI Cloud Guard",
    }
    _threat_svc = {
        "aws": "GuardDuty", "azure": "Defender for Cloud",
        "gcp": "Security Command Center", "oci": "OCI Cloud Guard",
    }
    _comp = " / ".join(dict.fromkeys(_compliance_svc.get(p, p) for p in providers)) or "the provider's policy service"
    _threat = " / ".join(dict.fromkeys(_threat_svc.get(p, p) for p in providers)) or "the provider's threat-detection service"
    for item in [
        "Schedule periodic Prowler re-assessments (monthly or quarterly)",
        f"Enable continuous compliance monitoring ({_comp})",
        f"Enable native threat detection ({_threat})",
        "Centralize findings management for the assessed environment",
        "Establish a security review cadence with stakeholders",
        "Automate remediation with policy-as-code",
        "Rotate credentials/keys on a regular schedule",
        "Monitor audit logs for unauthorized activity",
    ]:
        E.append(Paragraph(f"• {item}", styles["BodyWrap"]))
    E.append(PageBreak())

    # Risk Matrix
    E.append(Paragraph("7. Risk Matrix", styles["SectionHead"]))
    risk = [
        ["Severity", "Count", "Impact", "Urgency", "Action"],
        ["Critical", str(severity["critical"]), Paragraph("Data breach, scope compromise", styles["BodyWrap"]), "Immediate", "Day 1-3"],
        ["High", str(severity["high"]), Paragraph("Unauthorized access, data exposure", styles["BodyWrap"]), "High", "Week 1-2"],
        ["Medium", str(severity["medium"]), Paragraph("Compliance gaps, misconfigurations", styles["BodyWrap"]), "Medium", "Month 1"],
        ["Low", str(severity["low"]), Paragraph("Best-practice deviations", styles["BodyWrap"]), "Low", "Ongoing"],
    ]
    if severity.get("other"):
        risk.append(["Other", str(severity["other"]),
                     Paragraph("Unclassified severity — triage manually", styles["BodyWrap"]),
                     "Triage", "Ongoing"])
    t = Table(risk, colWidths=[0.8 * inch, 0.6 * inch, 2.3 * inch, 0.9 * inch, 0.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SLATE_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    E.append(t)
    E.append(PageBreak())

    # Compliance
    E.append(Paragraph("8. Compliance Gap Analysis", styles["SectionHead"]))
    if compliance:
        # "Checks" totals sum every check row across all assessed scopes; "Reqs Met"
        # de-duplicates by requirement ID so it reflects the framework's real size.
        comp = [["Framework", "Checks", "Pass", "Fail", "Pass Rate", "Reqs Met"]]
        for fw, info in list(compliance.items())[:10]:
            _req = (f"{info.get('requirements_passed', 0)}/{info['requirements_total']}"
                    if info.get("requirements_total") else "—")
            comp.append([fw, str(info["total"]), str(info["pass"]), str(info["fail"]),
                         f"{info['pass_rate']}%", _req])
        t = Table(comp, colWidths=[2.2 * inch, 0.9 * inch, 0.7 * inch, 0.7 * inch, 0.9 * inch, 0.8 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SLATE_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
        ]))
        E.append(t)
    else:
        E.append(Paragraph("No compliance framework data available from this assessment.", styles["BodyWrap"]))
    E.append(PageBreak())

    # Success Metrics
    E.append(Paragraph("9. Success Metrics", styles["SectionHead"]))
    for m in [
        f"Security Score Target: ≥ 90% (current: {score}%)",
        "Critical findings: 0 within 3 days",
        "High findings: 0 within 2 weeks",
        "Mean-time-to-remediate (MTTR): < 48 hours for Critical",
        "Compliance pass rate: ≥ 85% across all frameworks",
        "Re-assessment frequency: Monthly",
    ]:
        E.append(Paragraph(f"• {m}", styles["BodyWrap"]))
    E.append(PageBreak())

    # Appendix
    E.append(Paragraph("10. Appendix: Terraform Module Reference", styles["SectionHead"]))
    E.append(Paragraph(
        "Terraform remediation modules are provided in the iac/ directory. Each module targets a "
        "specific security control and includes variables, deployment commands, rollback instructions, "
        "and validation steps. Refer to the README for full details.", styles["BodyWrap"]))
    E.append(Spacer(1, 0.2 * inch))
    E.append(Paragraph(
        "⚠️ The Terraform modules are auto-generated and touch sensitive controls (identity, network, "
        "logging, encryption). Review each module and run <b>terraform plan</b> before <b>apply</b>.",
        styles["BodyWrap"]))

    doc.build(E, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"✅ PDF remediation plan generated → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate PDF security remediation plan (neutral, multi-cloud)")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_pdf", help="Path for output PDF file")
    parser.add_argument("--charts", default="", help="Directory containing chart PNGs to embed")
    args = parser.parse_args()
    data = load_analysis(args.analysis_json)
    build_pdf(data, args.output_pdf, args.charts)


if __name__ == "__main__":
    main()
