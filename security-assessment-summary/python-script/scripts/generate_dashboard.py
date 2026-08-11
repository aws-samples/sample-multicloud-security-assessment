#!/usr/bin/env python3
"""
generate_dashboard.py - Generate an interactive multi-cloud HTML security
dashboard with Highcharts.

Provider-neutral: uses "scope" terminology (account/subscription/project/tenancy)
and adds a per-provider breakdown when multiple clouds are present. No cloud
vendor logos are embedded; the header is a neutral dark-slate bar with title text.

Usage:
    python3 generate_dashboard.py <analysis_json> <output_html_path>
"""

import argparse
import html
import json
import os
import sys


HEADER_BG = "#1F2937"   # neutral dark slate
ACCENT = "#3B82F6"      # neutral blue accent


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def generate_html(data: dict, output_path: str):
    meta = data["metadata"]
    customer = html.escape(str(meta["customer"]))  # escaped: used raw in title/header
    scan_date = meta["scan_date"]
    scopes = meta.get("scopes_assessed", [])
    scope_term = meta.get("scope_term", "scope")
    provider_labels = meta.get("provider_labels", [])
    summary = data["summary"]
    score = summary["security_score"]
    severity = summary["findings_by_severity"]
    by_service = summary["findings_by_service"]
    by_provider = summary.get("findings_by_provider", {})
    top_checks = data["top_failed_checks"][:15]
    compliance = data.get("compliance_coverage", {})

    html_parts = []
    html_parts.append(_head(customer, scan_date, provider_labels))
    html_parts.append(_kpi_section(summary, scopes, scope_term))
    html_parts.append(_charts_section(score, severity, by_service))
    html_parts.append(_provider_section(by_provider))
    html_parts.append(_top_checks_table(top_checks))
    html_parts.append(_compliance_section(compliance))
    html_parts.append(_remediation_section(top_checks))
    html_parts.append(_roadmap_section())
    html_parts.append(_footer(scan_date, scopes, scope_term, provider_labels))

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html_parts))

    print(f"Dashboard generated -> {output_path}")


# ---------------------------------------------------------------------------
# HTML Sections
# ---------------------------------------------------------------------------

def _head(customer: str, scan_date: str, provider_labels: list) -> str:
    providers_str = ", ".join(provider_labels) if provider_labels else "Multi-Cloud"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{customer} - Cloud Security Assessment Dashboard</title>
<!-- Highcharts is pinned to 12.1.2 with Subresource Integrity (SRI) hashes below.
     IMPORTANT: if you change the Highcharts version, you MUST regenerate the SRI
     integrity="sha384-..." hashes for the new files, or browsers will block the
     scripts and the charts will silently fail to load. Generate with, e.g.:
       curl -s <cdn-url> | openssl dgst -sha384 -binary | openssl base64 -A -->
<script src="https://cdn.jsdelivr.net/npm/highcharts@12.1.2/highcharts.js" integrity="sha384-tpQ9Jct0yKJo0Tk30P5SpTR7A2N1o3qcjTSeB9GUe3AOkiCuVEKjS1hHjHfzCLVg" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdn.jsdelivr.net/npm/highcharts@12.1.2/highcharts-more.js" integrity="sha384-7e9YekYbVeibelTksZ5pSClelAtxcfYvP7oSqqUd+Ll9OpL6myRftg6xNqrPWQ+Y" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdn.jsdelivr.net/npm/highcharts@12.1.2/modules/solid-gauge.js" integrity="sha384-3DyUReexxlqPxS326njEso2Hzm6Fp8ycxh6cbh6f3mHMKBnp7iaDd5RhvauY3JAu" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f6f9; color: #1F2937; }}
.header {{ background: {HEADER_BG}; color: #fff; padding: 24px 40px; }}
.header h1 {{ font-size: 22px; font-weight: 600; }}
.header .meta {{ font-size: 13px; opacity: 0.85; margin-top: 4px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px 40px; }}
.kpi-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.kpi-card {{ background: #fff; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.kpi-card .value {{ font-size: 32px; font-weight: 700; margin: 8px 0 4px; }}
.kpi-card .label {{ font-size: 13px; color: #666; }}
.kpi-card.critical .value {{ color: #d32f2f; }}
.kpi-card.high .value {{ color: #f57c00; }}
.kpi-card.score .value {{ color: #2e7d32; }}
.charts-row {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; margin-bottom: 32px; }}
.chart-box {{ background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.chart-box h3 {{ font-size: 15px; margin-bottom: 12px; color: #1F2937; }}
.section {{ margin-bottom: 32px; }}
.section h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid {ACCENT}; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
th {{ background: {HEADER_BG}; color: #fff; padding: 12px 16px; text-align: left; font-size: 13px; }}
td {{ padding: 10px 16px; border-bottom: 1px solid #eee; font-size: 13px; }}
tr:hover td {{ background: #fafafa; }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; }}
.severity-critical {{ background: #d32f2f; }}
.severity-high {{ background: #f57c00; }}
.severity-medium {{ background: #fbc02d; color: #333; }}
.severity-low {{ background: #388e3c; }}
.provider-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; background: {ACCENT}; }}
.remediation-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }}
.rem-card {{ background: #fff; border-radius: 8px; padding: 16px; border-left: 4px solid #d32f2f; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.rem-card.high {{ border-left-color: #f57c00; }}
.rem-card.medium {{ border-left-color: #fbc02d; }}
.rem-card h4 {{ font-size: 14px; margin-bottom: 6px; }}
.rem-card p {{ font-size: 12px; color: #555; }}
.roadmap {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
.phase-box {{ background: #fff; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.phase-box h4 {{ font-size: 13px; color: #1F2937; margin-bottom: 8px; }}
.phase-box .timeline {{ font-size: 11px; color: {ACCENT}; font-weight: 600; margin-bottom: 6px; }}
.phase-box p {{ font-size: 12px; color: #555; }}
.compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }}
.compliance-card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
.compliance-card h4 {{ font-size: 13px; margin-bottom: 8px; }}
.compliance-card .bar {{ height: 8px; background: #eee; border-radius: 4px; overflow: hidden; }}
.compliance-card .bar-fill {{ height: 100%; border-radius: 4px; }}
.provider-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
.provider-card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); border-top: 4px solid {ACCENT}; }}
.provider-card h4 {{ font-size: 15px; margin-bottom: 8px; }}
.provider-card .pmetric {{ font-size: 12px; color: #555; margin: 3px 0; }}
.footer {{ background: {HEADER_BG}; color: #fff; padding: 20px 40px; margin-top: 40px; font-size: 12px; opacity: 0.95; }}
@media (max-width: 900px) {{
  .charts-row {{ grid-template-columns: 1fr; }}
  .roadmap {{ grid-template-columns: 1fr 1fr; }}
}}
</style>
</head>
<body>
<div class="header">
  <h1>{customer} - Cloud Security Assessment</h1>
  <div class="meta">Generated: {scan_date} &nbsp;|&nbsp; Providers: {providers_str} &nbsp;|&nbsp; Source: Prowler</div>
</div>
<div class="container">
"""


def _kpi_section(summary: dict, scopes: list, scope_term: str) -> str:
    score = summary["security_score"]
    sev = summary["findings_by_severity"]
    total = summary["total_checks"]
    scope_label = f"{scope_term.capitalize()}s Assessed"
    return f"""
<div class="kpi-row">
  <div class="kpi-card"><div class="label">Total Checks</div><div class="value">{total:,}</div></div>
  <div class="kpi-card score"><div class="label">Security Score</div><div class="value">{score}%</div></div>
  <div class="kpi-card critical"><div class="label">Critical Findings</div><div class="value">{sev['critical']}</div></div>
  <div class="kpi-card high"><div class="label">High Findings</div><div class="value">{sev['high']}</div></div>
  <div class="kpi-card"><div class="label">{scope_label}</div><div class="value">{len(scopes)}</div></div>
</div>
"""


def _safe_json_for_script(obj) -> str:
    """Serialize obj to JSON safe for embedding inside an HTML <script> block.

    json.dumps does not escape '</' or '<!--', so a crafted string like
    '</script><script>alert(1)</script>' can break out of the script context.
    Replacing '<' and '>' with their Unicode escape sequences neutralizes this
    without affecting JSON semantics (JSON parsers decode \\uXXXX transparently).
    """
    raw = json.dumps(obj)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e")


def _charts_section(score: float, severity: dict, by_service: dict) -> str:
    services = list(by_service.keys())[:10]
    service_vals = [by_service[s] for s in services]
    services_json = _safe_json_for_script(services)
    service_vals_json = _safe_json_for_script(service_vals)

    return f"""
<div class="charts-row">
  <div class="chart-box">
    <h3>Security Score</h3>
    <div id="gauge-chart" style="height:250px;"></div>
  </div>
  <div class="chart-box">
    <h3>Findings by Severity</h3>
    <div id="severity-chart" style="height:250px;"></div>
  </div>
  <div class="chart-box">
    <h3>Top Services with Failures</h3>
    <div id="service-chart" style="height:250px;"></div>
  </div>
</div>
<script>
Highcharts.chart('gauge-chart', {{
  chart: {{ type: 'solidgauge' }},
  title: null,
  pane: {{
    center: ['50%', '70%'], size: '120%',
    startAngle: -90, endAngle: 90,
    background: {{ backgroundColor: '#EEE', innerRadius: '60%', outerRadius: '100%', shape: 'arc' }}
  }},
  yAxis: {{ min: 0, max: 100, stops: [[0.3, '#DF5353'], [0.6, '#DDDF0D'], [0.9, '#55BF3B']], lineWidth: 0, tickWidth: 0, minorTickInterval: null, labels: {{ y: 16 }} }},
  series: [{{ name: 'Score', data: [{score}], dataLabels: {{ format: '<div style="text-align:center"><span style="font-size:28px">{{y}}%</span></div>' }} }}],
  credits: {{ enabled: false }}
}});
Highcharts.chart('severity-chart', {{
  chart: {{ type: 'pie' }},
  title: null,
  plotOptions: {{ pie: {{ innerSize: '55%', dataLabels: {{ format: '{{point.name}}: {{point.y}}' }} }} }},
  series: [{{ name: 'Findings', data: [
    {{ name: 'Critical', y: {severity['critical']}, color: '#d32f2f' }},
    {{ name: 'High', y: {severity['high']}, color: '#f57c00' }},
    {{ name: 'Medium', y: {severity['medium']}, color: '#fbc02d' }},
    {{ name: 'Low', y: {severity['low']}, color: '#388e3c' }},
    {{ name: 'Other', y: {severity.get('other', 0)}, color: '#9e9e9e' }}
  ] }}],
  credits: {{ enabled: false }}
}});
Highcharts.chart('service-chart', {{
  chart: {{ type: 'bar' }},
  title: null,
  xAxis: {{ categories: {services_json}, labels: {{ style: {{ fontSize: '11px' }} }} }},
  yAxis: {{ title: {{ text: 'Failed Checks' }} }},
  series: [{{ name: 'Failures', data: {service_vals_json}, color: '{ACCENT}' }}],
  legend: {{ enabled: false }},
  credits: {{ enabled: false }}
}});
</script>
"""


def _provider_section(by_provider: dict) -> str:
    # Only render a per-provider breakdown when multiple providers are present.
    if not by_provider or len(by_provider) <= 1:
        return ""
    cards = ""
    for pkey, info in by_provider.items():
        sev = info["findings_by_severity"]
        scope_term = info.get("scope_term", "scope")
        cards += f"""<div class="provider-card">
  <h4><span class="provider-badge">{html.escape(str(info['label']))}</span></h4>
  <div class="pmetric"><strong>Security Score:</strong> {info['security_score']}%</div>
  <div class="pmetric"><strong>Total Checks:</strong> {info['total_checks']:,} (Pass {info['pass_count']:,} / Fail {info['fail_count']:,})</div>
  <div class="pmetric"><strong>Critical:</strong> {sev['critical']} &nbsp; <strong>High:</strong> {sev['high']} &nbsp; <strong>Medium:</strong> {sev['medium']} &nbsp; <strong>Low:</strong> {sev['low']}</div>
  <div class="pmetric"><strong>{scope_term.capitalize()}s:</strong> {len(info.get('scopes', []))}</div>
</div>\n"""
    return f"""
<div class="section">
  <h2>Per-Provider Breakdown</h2>
  <div class="provider-grid">{cards}</div>
</div>
"""


def _top_checks_table(top_checks: list) -> str:
    rows = ""
    for check in top_checks[:15]:
        sev = check.get("severity", "").lower()
        badge_class = f"severity-{sev}" if sev in ("critical", "high", "medium", "low") else ""
        provider = check.get("provider", "")
        prov_label = provider.upper() if provider and provider != "unknown" else ""
        # html.escape() every Prowler-derived string to prevent HTML/JS injection
        # from crafted check titles, service names, or resource-derived risk text.
        _title = html.escape(str(check.get('check_title', ''))[:60])
        _service = html.escape(str(check.get('service', '')))
        _severity = html.escape(str(check.get('severity', '')))
        _risk = html.escape(str(check.get('risk', ''))[:80])
        _prov = html.escape(prov_label)
        rows += f"""<tr>
  <td>{_title}</td>
  <td>{_prov}</td>
  <td>{_service}</td>
  <td><span class="severity-badge {badge_class}">{_severity}</span></td>
  <td>{check.get('count', 0)}</td>
  <td>{_risk}</td>
</tr>\n"""

    return f"""
<div class="section">
  <h2>Top Failed Security Checks</h2>
  <table>
    <thead><tr><th>Check</th><th>Provider</th><th>Service</th><th>Severity</th><th>Count</th><th>Risk</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
"""


def _compliance_section(compliance: dict) -> str:
    if not compliance:
        return ""
    cards = ""
    for fw, info in compliance.items():
        rate = info.get("pass_rate", 0)
        color = "#388e3c" if rate >= 80 else "#f57c00" if rate >= 50 else "#d32f2f"
        cards += f"""<div class="compliance-card">
  <h4>{html.escape(str(fw))}</h4>
  <div style="font-size:12px;color:#666;margin-bottom:6px;">Pass: {info['pass']} / {info['total']} ({rate}%)</div>
  <div class="bar"><div class="bar-fill" style="width:{rate}%;background:{color};"></div></div>
</div>\n"""

    return f"""
<div class="section">
  <h2>Compliance Framework Coverage</h2>
  <div class="compliance-grid">{cards}</div>
</div>
"""


def _remediation_section(top_checks: list) -> str:
    cards = ""
    for check in top_checks[:9]:
        sev = check.get("severity", "").lower()
        card_class = sev if sev in ("critical", "high", "medium") else ""
        rem_text = check.get("remediation_text", "")[:120] or "See the relevant cloud provider documentation for remediation steps."
        # Escape all Prowler-derived strings to prevent HTML/JS injection.
        _c_title = html.escape(str(check.get('check_title', ''))[:50])
        _c_service = html.escape(str(check.get('service', '')))
        _c_sev = html.escape(str(check.get('severity', '')))
        _rem = html.escape(str(rem_text))
        cards += f"""<div class="rem-card {card_class}">
  <h4>{_c_title}</h4>
  <p><strong>{_c_service}</strong> - {_c_sev}</p>
  <p>{_rem}</p>
</div>\n"""

    return f"""
<div class="section">
  <h2>Remediation Priorities</h2>
  <div class="remediation-cards">{cards}</div>
</div>
"""


def _roadmap_section() -> str:
    return """
<div class="section">
  <h2>Phased Remediation Roadmap</h2>
  <div class="roadmap">
    <div class="phase-box">
      <div class="timeline">Day 1-3</div>
      <h4>Immediate</h4>
      <p>Critical: MFA/strong auth, public access, exposed secrets, privileged keys</p>
    </div>
    <div class="phase-box">
      <div class="timeline">Week 1-2</div>
      <h4>Short-Term</h4>
      <p>High: Encryption, logging, network rules, identity policies</p>
    </div>
    <div class="phase-box">
      <div class="timeline">Month 1</div>
      <h4>Medium-Term</h4>
      <p>Medium: Best practices, compliance gaps, monitoring</p>
    </div>
    <div class="phase-box">
      <div class="timeline">Ongoing</div>
      <h4>Continuous</h4>
      <p>Low + Governance: Periodic scans, policy-as-code, threat detection</p>
    </div>
  </div>
</div>
"""


def _footer(scan_date: str, scopes: list, scope_term: str, provider_labels: list) -> str:
    scope_str = html.escape(", ".join(scopes)) if scopes else "N/A"
    providers_str = html.escape(", ".join(provider_labels)) if provider_labels else "Multi-Cloud"
    return f"""
</div><!-- end container -->
<div class="footer">
  <p><strong>Shared Responsibility:</strong> Cloud security is a shared responsibility between the cloud provider and the customer. The provider secures the underlying cloud infrastructure; the customer secures their workloads, data, identities, and configurations in the cloud.</p>
  <p style="margin-top:8px;">Data source: Prowler Security Assessment | Providers: {providers_str} | Scan date: {scan_date} | {scope_term.capitalize()}s: {scope_str}</p>
</div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML security dashboard")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_html", help="Path for output HTML file")
    args = parser.parse_args()

    data = load_analysis(args.analysis_json)
    generate_html(data, args.output_html)


if __name__ == "__main__":
    main()
