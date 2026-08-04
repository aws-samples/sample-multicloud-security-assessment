#!/usr/bin/env node
/**
 * generate_pptx.js - Generate a multi-cloud security assessment PowerPoint deck.
 *
 * Provider-neutral: uses "scope" terminology and a neutral dark-slate header
 * with title text only (no cloud vendor logos). Adds a per-provider slide when
 * multiple providers are present.
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

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
if (args.length < 3) {
  console.error("Usage: node generate_pptx.js <analysis.json> <charts_dir> <output.pptx>");
  process.exit(1);
}

const [analysisPath, chartsDir, outputPath] = args;
const data = JSON.parse(fs.readFileSync(analysisPath, "utf-8"));
const meta = data.metadata || {};
const customer = meta.customer || "Customer";
const scanDate = meta.scan_date || new Date().toISOString().slice(0, 10);
const providerLabels = meta.provider_labels || [];
const providersStr = providerLabels.length ? providerLabels.join(", ") : "Multi-Cloud";
const summary = data.summary;
const severity = summary.findings_by_severity;
const byProvider = summary.findings_by_provider || {};
const topChecks = data.top_failed_checks || [];
const compliance = data.compliance_coverage || {};

// Chart paths
const severityChart = path.join(chartsDir, "severity_donut.png");
const serviceChart = path.join(chartsDir, "service_bar.png");
const scoreChart = path.join(chartsDir, "score_gauge.png");
const complianceChart = path.join(chartsDir, "compliance_bar.png");
const providerChart = path.join(chartsDir, "provider_bar.png");

// ---------------------------------------------------------------------------
// Build Deck
// ---------------------------------------------------------------------------
const pres = new PptxGenJS();
pres.layout = "LAYOUT_16x9"; // 10" x 5.625"
pres.author = "Cloud Security Assessment";
pres.subject = `${customer} Security Assessment`;

// Neutral palette (no cloud vendor branding)
const DARK_BG = "1F2937";    // neutral dark slate
const ACCENT = "3B82F6";     // neutral blue accent
const WHITE = "FFFFFF";
const LIGHT_GRAY = "F4F6F9";

// Neutral header bar for content slides (dark-slate band + title text).
function addHeaderBar(slide, title, titleColor) {
  slide.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: 10, h: 0.75, fill: { color: DARK_BG } });
  slide.addText(title, { x: 0.5, y: 0.12, w: 9, h: 0.5, fontSize: 18, bold: true, color: titleColor || WHITE });
}

function addSlideNumber(slide, num) {
  slide.addText(String(num), { x: 9.3, y: 5.2, w: 0.5, h: 0.3, fontSize: 9, color: "999999", align: "right" });
}

// ---------------------------------------------------------------------------
// Slide 1: Title
// ---------------------------------------------------------------------------
let slide = pres.addSlide();
slide.background = { color: DARK_BG };
slide.addText("Cloud Security Assessment", { x: 0.8, y: 1.5, w: 8.4, h: 0.8, fontSize: 32, bold: true, color: WHITE });
slide.addText(customer, { x: 0.8, y: 2.4, w: 8.4, h: 0.6, fontSize: 22, color: ACCENT });
slide.addText(`${providersStr}`, { x: 0.8, y: 3.05, w: 8.4, h: 0.4, fontSize: 14, color: "CBD5E1" });
slide.addText(`${scanDate} | Confidential`, { x: 0.8, y: 3.5, w: 8.4, h: 0.4, fontSize: 14, color: "AAAAAA" });
slide.addText("Powered by Prowler", { x: 0.8, y: 4.8, w: 4, h: 0.3, fontSize: 11, color: "777777" });

// ---------------------------------------------------------------------------
// Slide 2: Executive Summary
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, `${customer} - Executive Summary`);
addSlideNumber(slide, 2);

const kpis = [
  { label: "Security Score", value: `${summary.security_score}%`, color: "2E7D32" },
  { label: "Critical", value: String(severity.critical), color: "D32F2F" },
  { label: "High", value: String(severity.high), color: "F57C00" },
  { label: "Medium", value: String(severity.medium), color: "FBC02D" },
  { label: "Low", value: String(severity.low), color: "388E3C" },
];

kpis.forEach((kpi, i) => {
  const x = 0.5 + i * 1.9;
  slide.addShape(pres.ShapeType.roundRect, { x, y: 1.1, w: 1.7, h: 1.2, fill: { color: LIGHT_GRAY }, line: { color: "DDDDDD", width: 1 } });
  slide.addText(kpi.value, { x, y: 1.2, w: 1.7, h: 0.7, fontSize: 24, bold: true, color: kpi.color, align: "center", valign: "middle" });
  slide.addText(kpi.label, { x, y: 1.8, w: 1.7, h: 0.4, fontSize: 10, color: "666666", align: "center" });
});

const insights = [
  `Total of ${summary.total_checks.toLocaleString()} security checks performed`,
  `${severity.critical + severity.high} Critical/High findings require immediate attention`,
  `${Object.keys(summary.findings_by_service).length} services with security findings across ${providersStr}`,
];
insights.forEach((text, i) => {
  slide.addText(`- ${text}`, { x: 0.7, y: 2.7 + i * 0.4, w: 8.5, h: 0.35, fontSize: 12, color: DARK_BG });
});

// ---------------------------------------------------------------------------
// Slide 3: Severity Distribution
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Findings by Severity");
addSlideNumber(slide, 3);
if (fs.existsSync(severityChart)) {
  slide.addImage({ path: severityChart, x: 0.5, y: 1.0, w: 4.5, h: 4.0 });
}
slide.addText("Risk Summary", { x: 5.5, y: 1.1, w: 4, h: 0.4, fontSize: 14, bold: true, color: DARK_BG });
slide.addText(`- ${severity.critical} Critical findings - immediate action required\n- ${severity.high} High findings - address within 1-2 weeks\n- ${severity.medium} Medium findings - plan within 1 month\n- ${severity.low} Low findings - ongoing improvement`, { x: 5.5, y: 1.6, w: 4, h: 2.5, fontSize: 11, color: "444444", valign: "top" });

// ---------------------------------------------------------------------------
// Slide 4: Findings by Service
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Findings by Service");
addSlideNumber(slide, 4);
if (fs.existsSync(serviceChart)) {
  slide.addImage({ path: serviceChart, x: 0.3, y: 0.9, w: 5.5, h: 4.2 });
}
const topServices = Object.entries(summary.findings_by_service).slice(0, 5);
topServices.forEach(([svc, count], i) => {
  slide.addText(`${svc}: ${count} findings`, { x: 6.0, y: 1.3 + i * 0.5, w: 3.5, h: 0.4, fontSize: 11, color: "444444" });
});

// ---------------------------------------------------------------------------
// Slide 5: Critical & High Findings Detail
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Critical & High Findings");
addSlideNumber(slide, 5);

const critHigh = topChecks.filter(c => ["Critical", "High"].includes(c.severity)).slice(0, 8);
const tableRows = [["Check", "Provider", "Service", "Severity", "Count"]];
critHigh.forEach(c => {
  const prov = (c.provider && c.provider !== "unknown") ? String(c.provider).toUpperCase() : "";
  tableRows.push([String(c.check_title || "").slice(0, 40), prov, c.service, c.severity, String(c.count)]);
});
slide.addTable(tableRows, {
  x: 0.4, y: 0.95, w: 9.2,
  fontSize: 9,
  border: { type: "solid", color: "DDDDDD", pt: 0.5 },
  colW: [3.8, 1.4, 2.0, 1.2, 0.8],
  rowH: [0.35],
  autoPage: false,
  headerRow: true,
  color: "333333",
});

// ---------------------------------------------------------------------------
// Slide 6: Remediation - Immediate Actions
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Remediation: Immediate Actions (Critical)", "FFB4B4");
addSlideNumber(slide, 6);

const criticals = topChecks.filter(c => c.severity === "Critical").slice(0, 4);
criticals.forEach((c, i) => {
  const y = 1.0 + i * 1.05;
  slide.addShape(pres.ShapeType.roundRect, { x: 0.4, y, w: 9.2, h: 0.9, fill: { color: "FFF5F5" }, line: { color: "D32F2F", width: 1 } });
  slide.addText(`${c.check_title.slice(0, 60)}`, { x: 0.6, y, w: 8.8, h: 0.4, fontSize: 11, bold: true, color: DARK_BG });
  const rem = c.remediation_text ? c.remediation_text.slice(0, 100) : "Refer to the relevant cloud provider documentation";
  slide.addText(rem, { x: 0.6, y: y + 0.4, w: 8.8, h: 0.45, fontSize: 9, color: "555555" });
});

// ---------------------------------------------------------------------------
// Slide 7: Remediation - Short-Term Actions
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Remediation: Short-Term Actions (High)", "FFDca0");
addSlideNumber(slide, 7);

const highs = topChecks.filter(c => c.severity === "High").slice(0, 4);
highs.forEach((c, i) => {
  const y = 1.0 + i * 1.05;
  slide.addShape(pres.ShapeType.roundRect, { x: 0.4, y, w: 9.2, h: 0.9, fill: { color: "FFF8E1" }, line: { color: "F57C00", width: 1 } });
  slide.addText(`${c.check_title.slice(0, 60)}`, { x: 0.6, y, w: 8.8, h: 0.4, fontSize: 11, bold: true, color: DARK_BG });
  const rem = c.remediation_text ? c.remediation_text.slice(0, 100) : "Refer to the relevant cloud provider documentation";
  slide.addText(rem, { x: 0.6, y: y + 0.4, w: 8.8, h: 0.45, fontSize: 9, color: "555555" });
});

// ---------------------------------------------------------------------------
// Slide 8: Compliance Framework Coverage
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Compliance Framework Coverage");
addSlideNumber(slide, 8);
if (fs.existsSync(complianceChart)) {
  slide.addImage({ path: complianceChart, x: 0.5, y: 1.0, w: 6, h: 3.8 });
}
const fwList = Object.entries(compliance).slice(0, 5);
fwList.forEach(([fw, info], i) => {
  slide.addText(`${fw}: ${info.pass_rate}%`, { x: 7.0, y: 1.3 + i * 0.5, w: 2.5, h: 0.4, fontSize: 11, color: "444444" });
});

// ---------------------------------------------------------------------------
// Slide 9: Per-Provider Breakdown (only when multiple providers) OR Roadmap
// ---------------------------------------------------------------------------
const providerKeys = Object.keys(byProvider);
if (providerKeys.length > 1) {
  slide = pres.addSlide();
  addHeaderBar(slide, "Per-Provider Breakdown");
  addSlideNumber(slide, 9);
  if (fs.existsSync(providerChart)) {
    slide.addImage({ path: providerChart, x: 0.4, y: 0.95, w: 5.4, h: 4.0 });
  }
  const provRows = [["Provider", "Score", "Crit", "High"]];
  providerKeys.forEach(pkey => {
    const info = byProvider[pkey];
    provRows.push([info.label, `${info.security_score}%`,
      String(info.findings_by_severity.critical), String(info.findings_by_severity.high)]);
  });
  slide.addTable(provRows, {
    x: 6.0, y: 1.1, w: 3.6, fontSize: 10,
    border: { type: "solid", color: "DDDDDD", pt: 0.5 },
    colW: [1.5, 0.9, 0.6, 0.6], rowH: [0.4], headerRow: true, color: "333333",
  });
}

// ---------------------------------------------------------------------------
// Slide 10: Implementation Roadmap
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Implementation Roadmap");
addSlideNumber(slide, 10);

const phases = [
  { title: "Phase 1: Immediate", time: "Day 1-3", desc: "Critical: strong auth, public access, secrets", color: "D32F2F" },
  { title: "Phase 2: Short-Term", time: "Week 1-2", desc: "High: Encryption, logging, network rules", color: "F57C00" },
  { title: "Phase 3: Medium-Term", time: "Month 1", desc: "Medium: Best practices, compliance", color: "FBC02D" },
  { title: "Phase 4: Ongoing", time: "Continuous", desc: "Low + governance, monitoring", color: "388E3C" },
];
phases.forEach((p, i) => {
  const x = 0.4 + i * 2.4;
  slide.addShape(pres.ShapeType.roundRect, { x, y: 1.1, w: 2.2, h: 3.5, fill: { color: LIGHT_GRAY }, line: { color: p.color, width: 2 } });
  slide.addText(p.time, { x, y: 1.2, w: 2.2, h: 0.4, fontSize: 10, bold: true, color: p.color, align: "center" });
  slide.addText(p.title, { x, y: 1.7, w: 2.2, h: 0.5, fontSize: 11, bold: true, color: DARK_BG, align: "center" });
  slide.addText(p.desc, { x: x + 0.1, y: 2.4, w: 2.0, h: 1.5, fontSize: 9, color: "555555", align: "center", valign: "top" });
});

// ---------------------------------------------------------------------------
// Slide 11: Best Practices & Next Steps
// ---------------------------------------------------------------------------
slide = pres.addSlide();
addHeaderBar(slide, "Cloud Security Best Practices & Next Steps");
addSlideNumber(slide, 11);

const bestPractices = [
  "Enforce MFA / strong authentication on all identities and privileged accounts",
  "Encrypt data at rest (disks, databases, object storage) and in transit",
  "Enable audit/activity logging across all regions and scopes with validation",
  "Restrict network ingress rules - no 0.0.0.0/0 on sensitive ports",
  "Enable network flow logs for visibility",
  "Implement policy-as-code for continuous compliance",
  "Enable cloud-native threat detection",
  "Schedule periodic Prowler re-assessments",
];
bestPractices.forEach((bp, i) => {
  slide.addText(`- ${bp}`, { x: 0.7, y: 1.0 + i * 0.5, w: 8.5, h: 0.4, fontSize: 12, color: DARK_BG });
});

// ---------------------------------------------------------------------------
// Slide 12: Closing
// ---------------------------------------------------------------------------
slide = pres.addSlide();
slide.background = { color: DARK_BG };
slide.addText("Thank You", { x: 0.8, y: 2.0, w: 8.4, h: 0.8, fontSize: 36, bold: true, color: WHITE, align: "center" });
slide.addText(customer, { x: 0.8, y: 2.9, w: 8.4, h: 0.5, fontSize: 18, color: ACCENT, align: "center" });
slide.addText("For questions, contact your security team", { x: 0.8, y: 3.8, w: 8.4, h: 0.4, fontSize: 12, color: "AAAAAA", align: "center" });

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------
const outDir = path.dirname(outputPath);
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

pres.writeFile({ fileName: outputPath })
  .then(() => {
    console.log(`PPTX deck generated -> ${outputPath}`);
  })
  .catch((err) => {
    console.error("ERROR generating PPTX:", err);
    process.exit(1);
  });
