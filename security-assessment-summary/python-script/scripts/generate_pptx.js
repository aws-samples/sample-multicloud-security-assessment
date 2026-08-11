#!/usr/bin/env node
/**
 * generate_pptx.js — Generate an 11-slide, neutrally-branded cloud security assessment deck.
 *
 * Multi-cloud (AWS / Azure / GCP / OCI), provider-aware, no cloud-provider logo.
 *
 * Usage:
 *   node generate_pptx.js <analysis_json> <charts_dir> <output_pptx_path>
 *
 * Requires: pptxgenjs (npm install pptxgenjs)
 */

const fs = require("fs");
const path = require("path");

let PptxGenJS;
try {
  PptxGenJS = require("pptxgenjs");
} catch (e) {
  console.error("ERROR: pptxgenjs not installed. Run: npm install pptxgenjs");
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length < 3) {
  console.error("Usage: node generate_pptx.js <analysis.json> <charts_dir> <output.pptx>");
  process.exit(1);
}

const [analysisPath, chartsDir, outputPath] = args;
const data = JSON.parse(fs.readFileSync(analysisPath, "utf-8"));
const customer = (data.metadata && data.metadata.customer) || "Customer";
const scanDate = (data.metadata && data.metadata.scan_date) || new Date().toISOString().slice(0, 10);
const summary = data.summary;
const severity = summary.findings_by_severity;
const topChecks = data.top_failed_checks || [];
const compliance = data.compliance_coverage || {};

const PROVIDER_LABEL = { aws: "AWS", azure: "Azure", gcp: "GCP", oci: "OCI", kubernetes: "Kubernetes", unknown: "Unknown" };
const providers = ((data.metadata && data.metadata.providers && data.metadata.providers.length)
  ? data.metadata.providers
  : (data.summary && data.summary.findings_by_provider ? Object.keys(data.summary.findings_by_provider) : []));
const providerLabels = providers.map((p) => PROVIDER_LABEL[p] || p.toUpperCase()).join(", ");
const multiProvider = providers.length > 1;

// Chart paths (support both new and legacy names)
function chartPath(...names) {
  for (const n of names) {
    const p = path.join(chartsDir, n);
    if (fs.existsSync(p)) return p;
  }
  return null;
}
const severityChart = chartPath("sev_donut.png", "severity_donut.png");
const serviceChart = chartPath("svc_bar.png", "service_bar.png");
const scoreChart = chartPath("score_gauge.png");
const complianceChart = chartPath("compliance_bar.png");
const providerChart = chartPath("provider_bar.png");

// ---------------------------------------------------------------------------
// Neutral palette — no cloud-provider branding
// ---------------------------------------------------------------------------
const pres = new PptxGenJS();
pres.layout = "LAYOUT_16x9"; // 10" x 5.625"
pres.author = "Cloud Security Assessment";
pres.subject = `${customer} Cloud Security Assessment`;

const SLATE = "1F2937";   // neutral dark header
const ACCENT = "3B82F6";  // neutral blue accent
const WHITE = "FFFFFF";
const LIGHT_GRAY = "F4F6F9";

// Neutral header band (replaces cloud logo).
function addHeaderBand(slide, title, num) {
  slide.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: 10, h: 0.7, fill: { color: LIGHT_GRAY }, line: { color: "E3E8EE", width: 0.5 } });
  slide.addText(title, { x: 0.5, y: 0.12, w: 7.6, h: 0.46, fontSize: 18, bold: true, color: SLATE, valign: "middle" });
  slide.addText(`${customer} — Cloud Security Assessment`, { x: 0.5, y: 0.5, w: 8, h: 0.16, fontSize: 7, color: "8A94A0" });
  if (num) slide.addText(String(num), { x: 9.3, y: 5.2, w: 0.5, h: 0.3, fontSize: 9, color: "999999", align: "right" });
}

// ---------------------------------------------------------------------------
// Slide 1: Title (neutral)
// ---------------------------------------------------------------------------
let slide = pres.addSlide();
slide.background = { color: SLATE };
slide.addText("Cloud Security Assessment", { x: 0.8, y: 1.5, w: 8.4, h: 0.8, fontSize: 32, bold: true, color: WHITE });
slide.addText(customer, { x: 0.8, y: 2.4, w: 8.4, h: 0.6, fontSize: 22, color: ACCENT });
slide.addText(`${providerLabels}  |  ${scanDate}  |  Confidential`, { x: 0.8, y: 3.2, w: 8.4, h: 0.4, fontSize: 14, color: "AAAAAA" });
slide.addText("Powered by Prowler", { x: 0.8, y: 4.8, w: 4, h: 0.3, fontSize: 11, color: "777777" });

// ---------------------------------------------------------------------------
// Slide 2: Executive Summary
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Executive Summary", 2);
const kpis = [
  { label: "Security Score", value: `${summary.security_score}%`, color: "2E7D32" },
  { label: "Critical", value: String(severity.critical), color: "D32F2F" },
  { label: "High", value: String(severity.high), color: "F57C00" },
  { label: "Medium", value: String(severity.medium), color: "B8860B" },
  { label: "Low", value: String(severity.low), color: "388E3C" },
];
// Unclassified-severity findings only earn a card when present, so the row stays 5-up
// for the common case and reconciles with the donut when it isn't.
if (severity.other) kpis.push({ label: "Other", value: String(severity.other), color: "9E9E9E" });
const kpiW = kpis.length > 5 ? 1.4 : 1.7;
const kpiGap = kpis.length > 5 ? 1.55 : 1.9;
kpis.forEach((kpi, i) => {
  const x = 0.5 + i * kpiGap;
  slide.addShape(pres.ShapeType.roundRect, { x, y: 0.9, w: kpiW, h: 1.2, fill: { color: LIGHT_GRAY }, line: { color: "DDDDDD", width: 1 } });
  slide.addText(kpi.value, { x, y: 1.0, w: kpiW, h: 0.7, fontSize: 24, bold: true, color: kpi.color, align: "center", valign: "middle" });
  slide.addText(kpi.label, { x, y: 1.6, w: kpiW, h: 0.4, fontSize: 10, color: "666666", align: "center" });
});
// analyze_security_data.py caps findings_by_service at most_common(20);
// only claim "N+" when the scan actually hit that cap.
const SERVICE_CAP = 20;
const serviceCount = Object.keys(summary.findings_by_service).length;
const serviceCountLabel = serviceCount >= SERVICE_CAP ? `${serviceCount}+` : String(serviceCount);
const insights = [
  `Total of ${summary.total_checks.toLocaleString()} security checks performed across ${providerLabels}`,
  `${severity.critical + severity.high} Critical/High findings require immediate attention`,
  `${serviceCountLabel} cloud services with security findings`,
];
insights.forEach((text, i) => {
  slide.addText(`• ${text}`, { x: 0.7, y: 2.5 + i * 0.4, w: 8.7, h: 0.35, fontSize: 12, color: SLATE });
});

// ---------------------------------------------------------------------------
// Slide 3: Severity Distribution
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Findings by Severity", 3);
if (severityChart) slide.addImage({ path: severityChart, x: 0.5, y: 0.9, w: 4.5, h: 4.2 });
slide.addText("Risk Summary", { x: 5.5, y: 1.0, w: 4, h: 0.4, fontSize: 14, bold: true, color: SLATE });
const riskLines = [
  `• ${severity.critical} Critical findings — immediate action required`,
  `• ${severity.high} High findings — address within 1-2 weeks`,
  `• ${severity.medium} Medium findings — plan within 1 month`,
  `• ${severity.low} Low findings — ongoing improvement`,
];
if (severity.other) riskLines.push(`• ${severity.other} Other findings — unclassified severity, triage manually`);
slide.addText(riskLines.join("\n"), { x: 5.5, y: 1.5, w: 4, h: 2.5, fontSize: 11, color: "444444", valign: "top" });

// ---------------------------------------------------------------------------
// Slide 4: Findings by Service
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Findings by Cloud Service", 4);
if (serviceChart) slide.addImage({ path: serviceChart, x: 0.3, y: 0.9, w: 5.5, h: 4.2 });
const topServices = Object.entries(summary.findings_by_service).slice(0, 5);
topServices.forEach(([svc, count], i) => {
  slide.addText(`${svc}: ${count} findings`, { x: 6.0, y: 1.2 + i * 0.5, w: 3.5, h: 0.4, fontSize: 11, color: "444444" });
});

// ---------------------------------------------------------------------------
// Slide 5: Critical & High Findings Detail
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Critical & High Findings", 5);
const critHigh = topChecks.filter((c) => ["critical", "high"].includes(String(c.severity).toLowerCase())).slice(0, 8);
const tableRows = [["Check", "Service", "Severity", "Count"]];
critHigh.forEach((c) => {
  tableRows.push([String(c.check_title).slice(0, 45), c.service, c.severity, String(c.count)]);
});
slide.addTable(tableRows, {
  x: 0.4, y: 0.9, w: 9.2, fontSize: 9,
  border: { type: "solid", color: "DDDDDD", pt: 0.5 },
  colW: [4.5, 2.0, 1.2, 0.8], rowH: [0.35],
  autoPage: false, color: "333333",
});

// ---------------------------------------------------------------------------
// Slide 6: Remediation — Immediate Actions
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Remediation: Immediate Actions (Critical)", 6);
const criticals = topChecks.filter((c) => String(c.severity).toLowerCase() === "critical").slice(0, 4);
criticals.forEach((c, i) => {
  const y = 0.9 + i * 1.1;
  slide.addShape(pres.ShapeType.roundRect, { x: 0.4, y, w: 9.2, h: 0.95, fill: { color: "FFF5F5" }, line: { color: "D32F2F", width: 1 } });
  slide.addText(`🚨 ${String(c.check_title).slice(0, 60)}`, { x: 0.6, y, w: 8.8, h: 0.4, fontSize: 11, bold: true, color: SLATE });
  const rem = c.remediation_text ? String(c.remediation_text).slice(0, 100) : "Refer to the provider's documentation";
  slide.addText(rem, { x: 0.6, y: y + 0.4, w: 8.8, h: 0.45, fontSize: 9, color: "555555" });
});

// ---------------------------------------------------------------------------
// Slide 7: Remediation — Short-Term Actions
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Remediation: Short-Term Actions (High)", 7);
const highs = topChecks.filter((c) => String(c.severity).toLowerCase() === "high").slice(0, 4);
highs.forEach((c, i) => {
  const y = 0.9 + i * 1.1;
  slide.addShape(pres.ShapeType.roundRect, { x: 0.4, y, w: 9.2, h: 0.95, fill: { color: "FFF8E1" }, line: { color: "F57C00", width: 1 } });
  slide.addText(`⚠️ ${String(c.check_title).slice(0, 60)}`, { x: 0.6, y, w: 8.8, h: 0.4, fontSize: 11, bold: true, color: SLATE });
  const rem = c.remediation_text ? String(c.remediation_text).slice(0, 100) : "Refer to the provider's documentation";
  slide.addText(rem, { x: 0.6, y: y + 0.4, w: 8.8, h: 0.45, fontSize: 9, color: "555555" });
});

// ---------------------------------------------------------------------------
// Slide 8: Compliance Framework Coverage
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Compliance Framework Coverage", 8);
if (complianceChart) slide.addImage({ path: complianceChart, x: 0.5, y: 0.9, w: 6, h: 4.0 });
else if (providerChart && multiProvider) slide.addImage({ path: providerChart, x: 0.5, y: 0.9, w: 6, h: 4.0 });
const fwList = Object.entries(compliance).slice(0, 5);
fwList.forEach(([fw, info], i) => {
  slide.addText(`${fw}: ${info.pass_rate}%`, { x: 7.0, y: 1.2 + i * 0.5, w: 2.5, h: 0.4, fontSize: 11, color: "444444" });
});

// ---------------------------------------------------------------------------
// Slide 9: Implementation Roadmap
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Implementation Roadmap", 9);
const phases = [
  { title: "Phase 1: Immediate", time: "Day 1-3", desc: "Critical: identity/MFA, public access, secrets", color: "D32F2F" },
  { title: "Phase 2: Short-Term", time: "Week 1-2", desc: "High: encryption, logging, network rules", color: "F57C00" },
  { title: "Phase 3: Medium-Term", time: "Month 1", desc: "Medium: best practices, compliance", color: "B8860B" },
  { title: "Phase 4: Ongoing", time: "Continuous", desc: "Low + governance, monitoring", color: "388E3C" },
];
phases.forEach((p, i) => {
  const x = 0.4 + i * 2.4;
  slide.addShape(pres.ShapeType.roundRect, { x, y: 1.0, w: 2.2, h: 3.5, fill: { color: LIGHT_GRAY }, line: { color: p.color, width: 2 } });
  slide.addText(p.time, { x, y: 1.1, w: 2.2, h: 0.4, fontSize: 10, bold: true, color: p.color, align: "center" });
  slide.addText(p.title, { x, y: 1.6, w: 2.2, h: 0.5, fontSize: 11, bold: true, color: SLATE, align: "center" });
  slide.addText(p.desc, { x: x + 0.1, y: 2.3, w: 2.0, h: 1.5, fontSize: 9, color: "555555", align: "center", valign: "top" });
});

// ---------------------------------------------------------------------------
// Slide 10: Cloud Security Best Practices & Next Steps (provider-generic)
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBand(slide, "Cloud Security Best Practices & Next Steps", 10);
// Provider-appropriate service names — only reference the cloud(s) actually assessed.
const _COMPLIANCE_SVC = { aws: "AWS Config", azure: "Azure Policy", gcp: "GCP Organization Policy", oci: "OCI Cloud Guard" };
const _THREAT_SVC = { aws: "GuardDuty", azure: "Defender for Cloud", gcp: "Security Command Center", oci: "OCI Cloud Guard" };
const _compSvc = [...new Set(providers.map((p) => _COMPLIANCE_SVC[p] || p))].join(" / ") || "the provider's policy service";
const _threatSvc = [...new Set(providers.map((p) => _THREAT_SVC[p] || p))].join(" / ") || "the provider's threat-detection service";
const bestPractices = [
  "✅ Enforce MFA / strong identity for all users and privileged accounts",
  "✅ Encrypt data at rest and in transit across all services",
  "✅ Enable audit/activity logging across all regions and scopes",
  "✅ Restrict network rules — no unrestricted (0.0.0.0/0) ingress",
  "✅ Enable network flow logging for visibility",
  `✅ Implement continuous compliance monitoring (${_compSvc})`,
  `✅ Enable native threat detection (${_threatSvc})`,
  "✅ Schedule periodic Prowler re-assessments",
];
bestPractices.forEach((bp, i) => {
  slide.addText(bp, { x: 0.7, y: 0.95 + i * 0.5, w: 8.7, h: 0.4, fontSize: 12, color: SLATE });
});

// ---------------------------------------------------------------------------
// Slide 11: Closing (neutral)
// ---------------------------------------------------------------------------
slide = pres.addSlide();
slide.background = { color: SLATE };
slide.addText("Thank You", { x: 0.8, y: 2.0, w: 8.4, h: 0.8, fontSize: 36, bold: true, color: WHITE, align: "center" });
slide.addText(customer, { x: 0.8, y: 2.9, w: 8.4, h: 0.5, fontSize: 18, color: ACCENT, align: "center" });
slide.addText("Questions on findings or remediation? Let's discuss next steps.", { x: 0.8, y: 3.8, w: 8.4, h: 0.4, fontSize: 12, color: "AAAAAA", align: "center" });

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------
const outDir = path.dirname(outputPath);
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

pres.writeFile({ fileName: outputPath })
  .then(() => console.log(`✅ PPTX deck generated → ${outputPath}`))
  .catch((err) => { console.error("ERROR generating PPTX:", err); process.exit(1); });
