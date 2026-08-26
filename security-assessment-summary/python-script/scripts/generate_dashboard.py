#!/usr/bin/env python3
"""
generate_dashboard.py - Generate an interactive multi-cloud HTML security
dashboard with Chart.js and Bootstrap 5.

Provider-neutral: uses "scope" terminology (account/subscription/project/tenancy)
and adapts when multiple clouds are present.

Usage:
    python3 generate_dashboard.py <analysis_json> <output_html_path>
"""

import argparse
import html
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Severity weights for score calculation (weighted penalty approach)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "informational": 1,
    "info": 1,
    "other": 1,
}


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _safe_json(obj) -> str:
    """Serialize to JSON safe for embedding in HTML <script> blocks."""
    raw = json.dumps(obj, default=str)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _esc(val) -> str:
    """HTML-escape a value."""
    return html.escape(str(val))


def _risk_class(score: float) -> str:
    if score >= 70:
        return "risk-high"
    elif score >= 40:
        return "risk-medium"
    return "risk-low"


def _score_class(score: float) -> str:
    if score >= 70:
        return "score-high"
    elif score >= 40:
        return "score-medium"
    return "score-low"


def _severity_badge_color(sev: str) -> str:
    s = sev.lower()
    if s == "critical":
        return "#dc3545"
    elif s == "high":
        return "#fd7e14"
    elif s == "medium":
        return "#ffc107"
    elif s == "low":
        return "#28a745"
    return "#6c757d"


def _severity_bg_class(sev: str) -> str:
    s = sev.lower()
    if s == "critical":
        return "bg-danger"
    elif s == "high":
        return "bg-warning"
    elif s == "medium":
        return "bg-info"
    elif s == "low":
        return "bg-success"
    return "bg-secondary"


def _compute_risk_score(findings: list) -> float:
    """Compute risk score for a group of findings (0-100 scale)."""
    if not findings:
        return 0.0
    total = len(findings)
    max_possible = total * SEVERITY_WEIGHTS.get("critical", 10)
    if max_possible == 0:
        return 0.0
    weighted_failed = 0.0
    for f in findings:
        status = f.get("status", "").upper()
        if status == "FAIL" or status == "FAILED":
            sev = f.get("severity", "other").lower()
            weighted_failed += SEVERITY_WEIGHTS.get(sev, 1)
    return round((weighted_failed / max_possible) * 100, 1)


def _compute_security_score(findings: list) -> float:
    """Compute overall security score using weighted penalty approach."""
    if not findings:
        return 100.0
    total = len(findings)
    max_possible = total * SEVERITY_WEIGHTS.get("critical", 10)
    if max_possible == 0:
        return 100.0
    weighted_penalty = 0.0
    for f in findings:
        status = f.get("status", "").upper()
        if status == "FAIL" or status == "FAILED":
            sev = f.get("severity", "other").lower()
            weighted_penalty += SEVERITY_WEIGHTS.get(sev, 1)
    score = 100 - (weighted_penalty / max_possible * 100)
    return round(max(0, min(100, score)), 1)


def _compute_per_account_stats(detailed_findings: list) -> list:
    """Group findings by account_uid and compute stats."""
    by_account = defaultdict(list)
    for f in detailed_findings:
        acct = f.get("account_uid", f.get("account_id", "unknown"))
        by_account[acct].append(f)

    results = []
    for acct_id, findings in by_account.items():
        total = len(findings)
        failed = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED"))
        passed = total - failed
        pass_rate = round((passed / total * 100), 1) if total > 0 else 0.0
        critical = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "high")
        risk_score = _compute_risk_score(findings)
        # Try to get an account name from the findings
        account_name = None
        for f in findings:
            n = f.get("account_name", f.get("account_tag", ""))
            if n and n != acct_id:
                account_name = n
                break
        results.append({
            "account_id": acct_id,
            "account_name": account_name or acct_id,
            "total": total,
            "failed": failed,
            "pass_rate": pass_rate,
            "critical": critical,
            "high": high,
            "risk_score": risk_score,
        })
    results.sort(key=lambda x: x["critical"], reverse=True)
    return results


def _compute_per_service_stats(detailed_findings: list) -> list:
    """Group findings by service and compute stats."""
    by_service = defaultdict(list)
    for f in detailed_findings:
        svc = f.get("service", "unknown")
        by_service[svc].append(f)

    results = []
    for svc, findings in by_service.items():
        total = len(findings)
        failed = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED"))
        failure_rate = round((failed / total * 100), 1) if total > 0 else 0.0
        critical = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "high")
        risk_score = _compute_risk_score(findings)
        results.append({
            "service": svc,
            "total": total,
            "failed": failed,
            "failure_rate": failure_rate,
            "critical": critical,
            "high": high,
            "risk_score": risk_score,
        })
    results.sort(key=lambda x: x["critical"], reverse=True)
    return results


def _compute_per_region_stats(detailed_findings: list) -> list:
    """Group findings by region and compute stats."""
    by_region = defaultdict(list)
    for f in detailed_findings:
        region = f.get("region", "global")
        by_region[region].append(f)

    results = []
    for region, findings in by_region.items():
        total = len(findings)
        failed = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED"))
        critical = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "high")
        medium = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "medium")
        low = sum(1 for f in findings if f.get("status", "").upper() in ("FAIL", "FAILED") and f.get("severity", "").lower() == "low")
        risk_score = _compute_risk_score(findings)
        results.append({
            "region": region,
            "total": total,
            "failed": failed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "risk_score": risk_score,
        })
    results.sort(key=lambda x: x["failed"], reverse=True)
    return results


def _build_roadmap(top_checks: list) -> dict:
    """Build a phased roadmap from top_failed_checks."""
    immediate = []
    short_term = []
    long_term = []

    for check in top_checks:
        sev = check.get("severity", "medium").lower()
        count = check.get("fail_count", check.get("count", 1))
        title = check.get("check_title", check.get("title", ""))
        service = check.get("service", "")
        check_id = check.get("check_id", "")
        remediation = check.get("remediation_text", "")

        # Estimate effort based on severity and resource count
        if sev == "critical":
            effort = round(0.2 + (count * 0.05), 1)
            effort = min(effort, 2.0)
        elif sev == "high":
            effort = round(0.5 + (count * 0.03), 1)
            effort = min(effort, 4.0)
        elif sev == "medium":
            effort = round(1.0 + (count * 0.01), 1)
            effort = min(effort, 4.0)
        else:
            effort = round(1.0 + (count * 0.005), 1)
            effort = min(effort, 3.0)

        # Generate description
        if remediation:
            desc = remediation[:80]
        elif sev == "critical" and ("mfa" in title.lower() or "root" in title.lower()):
            desc = f"Enable MFA for {count} account(s)/user(s)"
        elif "public" in title.lower() or "access" in title.lower():
            desc = f"Restrict public access for {count} {service} resource(s)"
        else:
            desc = f"Address security configuration for {count} {service} resource(s)"

        item = {
            "title": title,
            "service": service,
            "severity": sev.capitalize(),
            "affected_resources": count,
            "effort_weeks": effort,
            "check_id": check_id,
            "description": desc,
        }

        # Categorize into phases
        if sev == "critical" or (sev == "high" and count > 5):
            immediate.append(item)
        elif sev == "high" or (sev == "medium" and count > 50):
            short_term.append(item)
        else:
            long_term.append(item)

    imm_effort = round(sum(i["effort_weeks"] for i in immediate), 1)
    short_effort = round(sum(i["effort_weeks"] for i in short_term), 1)
    long_effort = round(sum(i["effort_weeks"] for i in long_term), 1)

    return {
        "immediate": {
            "count": len(immediate),
            "items": immediate[:10],
            "effort_weeks": imm_effort,
            "timeline": "1-2 weeks",
            "description": "Critical and high-severity issues requiring immediate attention",
        },
        "short_term": {
            "count": len(short_term),
            "items": short_term[:10],
            "effort_weeks": short_effort,
            "timeline": "1-2 months",
            "description": "Important security improvements with moderate complexity",
        },
        "long_term": {
            "count": len(long_term),
            "items": long_term[:10],
            "effort_weeks": long_effort,
            "timeline": "3-6 months",
            "description": "Strategic security enhancements and architectural improvements",
        },
        "summary": {
            "total_issues": len(immediate) + len(short_term) + len(long_term),
            "total_effort_weeks": round(imm_effort + short_effort + long_effort, 1),
            "critical_count": sum(1 for i in immediate if i["severity"].lower() == "critical"),
            "high_count": sum(1 for i in immediate + short_term if i["severity"].lower() == "high"),
        },
    }


def generate_html(data: dict, output_path: str):
    """Main generation function."""
    meta = data.get("metadata", {})
    customer = _esc(meta.get("customer", "Security Assessment"))
    scan_date = meta.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    providers = meta.get("providers", meta.get("provider_labels", []))
    scope_term = meta.get("scope_term", "account")

    summary = data.get("summary", {})
    severity = summary.get("findings_by_severity", {})
    total_checks = summary.get("total_checks", 0)
    pass_count = summary.get("pass_count", 0)
    fail_count = summary.get("fail_count", 0)
    by_service = summary.get("findings_by_service", {})

    # Use detailed_findings for per-account/service/region computation
    detailed_findings = data.get("detailed_findings", [])
    top_checks = data.get("top_failed_checks", [])
    compliance = data.get("compliance_frameworks", data.get("compliance_coverage", {}))

    # Scopes assessed
    scopes = summary.get("scopes_assessed", meta.get("scopes_assessed", []))
    num_accounts = len(scopes) if scopes else 1

    # Compute stats
    account_stats = _compute_per_account_stats(detailed_findings) if detailed_findings else []
    service_stats = _compute_per_service_stats(detailed_findings) if detailed_findings else []
    region_stats = _compute_per_region_stats(detailed_findings) if detailed_findings else []

    # Security score (prefer pre-computed, fallback to computation)
    security_score = summary.get("security_score", 0)
    if not security_score and detailed_findings:
        security_score = _compute_security_score(detailed_findings)

    # Build roadmap
    roadmap = _build_roadmap(top_checks)

    # Provider info
    provider_str = ", ".join(providers) if providers else "Multi-Cloud"
    scope_label = f"{scope_term.capitalize()}s Assessed" if scope_term else "Accounts Assessed"

    # Severity counts
    critical = severity.get("critical", 0)
    high = severity.get("high", 0)
    medium = severity.get("medium", 0)
    low = severity.get("low", 0)
    info_count = severity.get("informational", severity.get("info", severity.get("other", 0)))

    # Prepare chart data
    severity_chart_data = _build_severity_chart(severity)
    account_chart_data = _build_account_chart(account_stats)
    service_chart_data = _build_service_chart(service_stats[:10])
    checks_chart_data = _build_checks_chart(top_checks[:10])
    regions_chart_data = _build_regions_chart(region_stats[:15])
    roadmap_chart_data = _build_roadmap_chart(roadmap)

    # Build HTML
    parts = []
    parts.append(_html_head(customer, scan_date))
    parts.append(_html_navbar())
    parts.append(_html_sidebar())
    parts.append(_html_main_start())
    parts.append(_html_overview(customer, scan_date, num_accounts, security_score, provider_str, scope_term))
    parts.append(_html_global_filter())
    parts.append(_html_kpi_cards(critical, high, total_checks, num_accounts, scope_label))
    parts.append(_html_charts_section())
    parts.append(_html_regions_section(region_stats[:15]))
    parts.append(_html_details_section(account_stats, service_stats))
    parts.append(_html_compliance_section(compliance))
    # --- Section 1: Summary / Aggregate View (upfront) ---
    # --- Section 2: Charts & Analysis ---
    # --- Section 3: Detailed Findings ---
    # --- Section 4: Remediation (at the end, per reviewer feedback) ---
    parts.append(_html_roadmap_section(roadmap))
    parts.append(_html_insights_section(critical, high, security_score, account_stats))
    parts.append(_html_methodology_section())
    parts.append(_html_main_end())
    parts.append(_html_scripts(
        severity_chart_data, account_chart_data, service_chart_data,
        checks_chart_data, regions_chart_data, roadmap_chart_data, roadmap
    ))
    parts.append("</body>\n</html>")

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))

    print(f"Dashboard generated -> {output_path}")


# ---------------------------------------------------------------------------
# Chart Data Builders
# ---------------------------------------------------------------------------

def _build_severity_chart(severity: dict) -> dict:
    labels = []
    data_vals = []
    colors = []
    mapping = [
        ("Critical", severity.get("critical", 0), "#dc3545"),
        ("High", severity.get("high", 0), "#fd7e14"),
        ("Medium", severity.get("medium", 0), "#ffc107"),
        ("Low", severity.get("low", 0), "#28a745"),
    ]
    for label, val, color in mapping:
        if val > 0:
            labels.append(label)
            data_vals.append(val)
            colors.append(color)
    return {
        "type": "pie",
        "data": {
            "labels": labels,
            "datasets": [{"data": data_vals, "backgroundColor": colors, "borderWidth": 2, "borderColor": "#fff"}]
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "plugins": {"legend": {"position": "bottom"}, "tooltip": {"mode": "nearest", "intersect": True}}
        }
    }


def _build_account_chart(account_stats: list) -> dict:
    if not account_stats:
        return {}
    # Use account names as labels, show stacked severities
    # We need per-severity breakdown per account from detailed data
    labels = [a["account_name"][:25] for a in account_stats[:12]]
    critical_data = [a["critical"] for a in account_stats[:12]]
    high_data = [a["high"] for a in account_stats[:12]]
    # Estimate medium/low from failed - critical - high
    medium_data = [max(0, a["failed"] - a["critical"] - a["high"]) for a in account_stats[:12]]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {"label": "Critical", "data": critical_data, "backgroundColor": "#dc3545", "stack": "failures"},
                {"label": "High", "data": high_data, "backgroundColor": "#fd7e14", "stack": "failures"},
                {"label": "Medium/Low", "data": medium_data, "backgroundColor": "#ffc107", "stack": "failures"},
            ]
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "scales": {
                "x": {"stacked": True, "ticks": {"maxRotation": 45}},
                "y": {"stacked": True, "beginAtZero": True}
            },
            "plugins": {"legend": {"position": "top"}, "tooltip": {"mode": "index", "intersect": False}}
        }
    }


def _build_service_chart(service_stats: list) -> dict:
    if not service_stats:
        return {}
    labels = [s["service"] for s in service_stats]
    risk_scores = [s["risk_score"] for s in service_stats]
    failed_counts = [s["failed"] for s in service_stats]

    # Color bars by risk level
    bar_colors = []
    for score in risk_scores:
        if score >= 70:
            bar_colors.append("#dc3545")
        elif score >= 40:
            bar_colors.append("#fd7e14")
        else:
            bar_colors.append("#ffc107")

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": "Risk Score",
                    "data": risk_scores,
                    "backgroundColor": bar_colors,
                    "borderWidth": 1,
                    "yAxisID": "y"
                },
                {
                    "label": "Failed Findings",
                    "data": failed_counts,
                    "backgroundColor": "rgba(54, 162, 235, 0.6)",
                    "borderColor": "rgba(54, 162, 235, 1)",
                    "borderWidth": 1,
                    "type": "line",
                    "yAxisID": "y1",
                    "tension": 0.4
                }
            ]
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "interaction": {"mode": "index", "intersect": False},
            "scales": {
                "x": {"display": True, "title": {"display": True, "text": "Services"}, "ticks": {"maxRotation": 45, "minRotation": 45}},
                "y": {"type": "linear", "display": True, "position": "left", "title": {"display": True, "text": "Risk Score (0-100)"}, "beginAtZero": True, "max": 100},
                "y1": {"type": "linear", "display": True, "position": "right", "title": {"display": True, "text": "Failed Findings Count"}, "beginAtZero": True, "grid": {"drawOnChartArea": False}}
            },
            "plugins": {"legend": {"position": "top"}, "tooltip": {"mode": "index", "intersect": False}}
        }
    }


def _build_checks_chart(top_checks: list) -> dict:
    if not top_checks:
        return {}
    labels = []
    data_vals = []
    colors = []
    full_titles = []
    severities = []
    check_ids = []
    services = []

    for check in top_checks:
        title = check.get("check_title", check.get("title", ""))
        labels.append(title[:55] + "..." if len(title) > 55 else title)
        full_titles.append(title)
        data_vals.append(check.get("fail_count", check.get("count", 0)))
        sev = check.get("severity", "medium").lower()
        colors.append(_severity_badge_color(sev))
        severities.append(sev.capitalize())
        check_ids.append(check.get("check_id", ""))
        services.append(check.get("service", ""))

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [{
                "label": "Failure Count",
                "data": data_vals,
                "backgroundColor": colors,
                "borderWidth": 1,
                "fullTitles": full_titles,
                "checkIds": check_ids,
                "services": services,
                "severities": severities
            }]
        },
        "options": {
            "indexAxis": "y",
            "responsive": True,
            "maintainAspectRatio": False,
            "layout": {"padding": {"left": 20, "right": 20, "top": 10, "bottom": 10}},
            "scales": {
                "x": {"beginAtZero": True, "title": {"display": True, "text": "Number of Failures"}},
                "y": {"title": {"display": True, "text": "Security Checks"}, "ticks": {"maxRotation": 0, "font": {"size": 11}}}
            },
            "plugins": {"legend": {"display": False}, "tooltip": {"mode": "nearest", "intersect": True}}
        }
    }


def _build_regions_chart(region_stats: list) -> dict:
    if not region_stats:
        return {}
    labels = [r["region"] for r in region_stats]
    critical_data = [r["critical"] for r in region_stats]
    high_data = [r["high"] for r in region_stats]
    medium_data = [r["medium"] for r in region_stats]
    low_data = [r["low"] for r in region_stats]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {"label": "Critical", "data": critical_data, "backgroundColor": "#dc3545", "borderColor": "#dc3545", "borderWidth": 1, "stack": "failures"},
                {"label": "High", "data": high_data, "backgroundColor": "#fd7e14", "borderColor": "#fd7e14", "borderWidth": 1, "stack": "failures"},
                {"label": "Medium", "data": medium_data, "backgroundColor": "#ffc107", "borderColor": "#ffc107", "borderWidth": 1, "stack": "failures"},
                {"label": "Low", "data": low_data, "backgroundColor": "#28a745", "borderColor": "#28a745", "borderWidth": 1, "stack": "failures"},
            ]
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "interaction": {"mode": "index", "intersect": False},
            "scales": {
                "x": {"display": True, "stacked": True, "title": {"display": True, "text": "Regions"}, "ticks": {"maxRotation": 45, "minRotation": 45}},
                "y": {"type": "linear", "display": True, "stacked": True, "position": "left", "title": {"display": True, "text": "Number of Failed Findings"}, "beginAtZero": True}
            },
            "plugins": {"legend": {"position": "top"}, "tooltip": {"mode": "index", "intersect": False}}
        }
    }


def _build_roadmap_chart(roadmap: dict) -> dict:
    imm = roadmap["immediate"]
    short = roadmap["short_term"]
    long = roadmap["long_term"]

    return {
        "type": "bar",
        "data": {
            "labels": ["Immediate\\n(1-2 weeks)", "Short Term\\n(1-2 months)", "Long Term\\n(3-6 months)"],
            "datasets": [
                {
                    "label": "Number of Issues",
                    "data": [imm["count"], short["count"], long["count"]],
                    "backgroundColor": ["#dc354580", "#fd7e1480", "#28a74580"],
                    "borderColor": ["#c82333", "#e0a800", "#1e7e34"],
                    "borderWidth": 2,
                    "yAxisID": "y"
                },
                {
                    "label": "Effort (Weeks)",
                    "data": [imm["effort_weeks"], short["effort_weeks"], long["effort_weeks"]],
                    "backgroundColor": "rgba(54, 162, 235, 0.6)",
                    "borderColor": "rgba(54, 162, 235, 1)",
                    "borderWidth": 2,
                    "type": "line",
                    "yAxisID": "y1",
                    "tension": 0.4,
                    "pointRadius": 6,
                    "pointHoverRadius": 8
                }
            ]
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "interaction": {"mode": "index", "intersect": False},
            "scales": {
                "x": {"display": True, "title": {"display": True, "text": "Implementation Timeline"}, "ticks": {"maxRotation": 0, "minRotation": 0}},
                "y": {"type": "linear", "display": True, "position": "left", "title": {"display": True, "text": "Number of Issues"}, "beginAtZero": True},
                "y1": {"type": "linear", "display": True, "position": "right", "title": {"display": True, "text": "Effort Required (Weeks)"}, "beginAtZero": True, "grid": {"drawOnChartArea": False}}
            },
            "plugins": {"legend": {"position": "top"}, "tooltip": {"mode": "index", "intersect": False}}
        }
    }


# ---------------------------------------------------------------------------
# HTML Section Builders
# ---------------------------------------------------------------------------

def _html_head(customer: str, scan_date: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CSPM Security Insights Dashboard for {customer}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js" integrity="sha384-9MhbyIRcBVQiiC7FSd7T38oJNj2Zh+EfxS7/vjhBi4OOT78NlHSnzM31EZRWR1LZ" crossorigin="anonymous"></script>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet" integrity="sha384-3B6NwesSXE7YJlcLI9RpRqGf2p/EgVH8BgoKTaUrmKNDkHPStTQ3EyoYjCGXaOTS" crossorigin="anonymous">
<style>
body {{
    background-color: #f8f9fa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}}
.dashboard-header {{
    background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
    color: white;
    padding: 2rem;
    border-radius: 10px;
    margin-bottom: 2rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}}
.dashboard-header h1 {{
    color: white !important;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
    margin-bottom: 0.5rem;
}}
.dashboard-header .lead {{
    color: rgba(255, 255, 255, 0.9) !important;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
    margin-bottom: 1rem;
}}
.dashboard-header .generation-time {{
    color: rgba(255, 255, 255, 0.8) !important;
    font-size: 0.9rem;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
}}
.summary-card {{
    border: none;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s;
}}
.summary-card:hover {{
    transform: translateY(-2px);
}}
.security-score {{
    font-size: 1.2rem;
}}
.score-label {{
    color: white !important;
    font-weight: 500;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
    margin-right: 0.5rem;
}}
.score-value {{
    font-weight: bold;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}}
.score-high {{
    background-color: #d4edda;
    color: #155724;
    border: 2px solid #c3e6cb;
}}
.score-medium {{
    background-color: #fff3cd;
    color: #856404;
    border: 2px solid #ffeaa7;
}}
.score-low {{
    background-color: #f8d7da;
    color: #721c24;
    border: 2px solid #f5c6cb;
}}
.risk-score {{
    font-weight: bold;
    padding: 0.25rem 0.5rem;
    border-radius: 15px;
}}
.risk-high {{
    background-color: #f8d7da;
    color: #721c24;
}}
.risk-medium {{
    background-color: #fff3cd;
    color: #856404;
}}
.risk-low {{
    background-color: #d4edda;
    color: #155724;
}}
.card {{
    border: none;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    margin-bottom: 1rem;
}}
.card-header {{
    background-color: #f8f9fa;
    border-bottom: 1px solid #dee2e6;
    font-weight: 600;
}}
.table th {{
    border-top: none;
    font-weight: 600;
    background-color: #f8f9fa;
}}
.main-content {{
    margin-top: 70px;
    transition: margin-left 0.3s ease;
}}
.sidebar {{
    position: fixed;
    top: 56px;
    left: -300px;
    width: 300px;
    height: calc(100vh - 56px);
    background: #fff;
    box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
    transition: left 0.3s ease;
    z-index: 1040;
    overflow-y: auto;
}}
.sidebar.show {{
    left: 0;
}}
.sidebar-header {{
    padding: 1rem;
    border-bottom: 1px solid #dee2e6;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.sidebar-content {{
    padding: 1rem;
}}
.nav-section {{
    margin-bottom: 2rem;
}}
.nav-section h6 {{
    color: #6c757d;
    font-size: 0.875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.75rem;
}}
.sidebar .nav-link {{
    color: #495057;
    padding: 0.5rem 0.75rem;
    border-radius: 0.375rem;
    transition: all 0.2s ease;
    font-size: 0.875rem;
}}
.sidebar .nav-link:hover {{
    background-color: #f8f9fa;
    color: #007bff;
    text-decoration: none;
}}
.sidebar .nav-link i {{
    width: 20px;
    margin-right: 0.5rem;
}}
.sidebar-overlay {{
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    z-index: 1030;
    display: none;
}}
.sidebar-overlay.show {{
    display: block;
}}
html {{
    scroll-behavior: smooth;
}}
.row[id] {{
    scroll-margin-top: 80px;
}}
@media (max-width: 768px) {{
    .main-content {{
        margin-top: 60px;
    }}
    .sidebar {{
        top: 60px;
        height: calc(100vh - 60px);
    }}
}}
@media print {{
    .navbar, .sidebar, .sidebar-overlay, .btn {{
        display: none !important;
    }}
    .main-content {{
        margin-top: 0 !important;
        margin-left: 0 !important;
    }}
    body {{
        background: white !important;
        color: black !important;
        font-size: 12pt;
        line-height: 1.4;
    }}
    .dashboard-header {{
        background: #2c3e50 !important;
        color: white !important;
        padding: 1rem !important;
        margin-bottom: 1rem !important;
        page-break-inside: avoid;
    }}
    .card {{
        border: 1px solid #ddd !important;
        box-shadow: none !important;
        margin-bottom: 1rem !important;
        page-break-inside: avoid;
    }}
    .card-header {{
        background: #f8f9fa !important;
        border-bottom: 1px solid #ddd !important;
        font-weight: bold;
    }}
    .table {{
        font-size: 10pt;
    }}
    .table th, .table td {{
        padding: 0.25rem !important;
        border: 1px solid #ddd !important;
    }}
    .form-control, .form-select, .alert {{
        display: none !important;
    }}
    canvas {{
        max-width: 100% !important;
        height: auto !important;
    }}
    .row[id] {{
        page-break-before: auto;
        page-break-after: auto;
        page-break-inside: avoid;
    }}
    .badge, .risk-score, .score-value {{
        border: 1px solid #333 !important;
        background: white !important;
        color: black !important;
    }}
    .card:has(.form-control), .card:has(.form-select) {{
        display: none !important;
    }}
    .container-fluid {{
        padding: 0 !important;
    }}
    .row {{
        margin: 0 !important;
    }}
    .col-md-6, .col-md-4, .col-md-3, .col-12 {{
        padding: 0.25rem !important;
    }}
}}
</style>
</head>
<body>
"""


def _html_navbar() -> str:
    return """
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <div class="container-fluid">
        <button class="btn btn-outline-light btn-sm me-3" onclick="toggleSidebar()">
            <i class="fas fa-bars"></i> Menu
        </button>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link" href="#overview">\U0001f4ca Overview</a></li>
                <li class="nav-item"><a class="nav-link" href="#charts">\U0001f4c8 Charts</a></li>
                <li class="nav-item"><a class="nav-link" href="#regions">\U0001f30d Regions</a></li>
                <li class="nav-item"><a class="nav-link" href="#details">\U0001f4cb Details</a></li>
                <li class="nav-item"><a class="nav-link" href="#compliance">\u2705 Compliance</a></li>
                <li class="nav-item"><a class="nav-link" href="#insights">\U0001f4a1 Insights</a></li>
                <li class="nav-item"><a class="nav-link" href="#roadmap">\U0001f6e3\ufe0f Roadmap</a></li>
                <li class="nav-item"><a class="nav-link" href="#methodology">\U0001f522 Methodology</a></li>
            </ul>
        </div>
    </div>
</nav>
"""


def _html_sidebar() -> str:
    return """
<div class="sidebar" id="sidebar">
    <div class="sidebar-header">
        <h5>Navigation</h5>
        <button class="btn btn-sm btn-outline-secondary" onclick="toggleSidebar()">
            <i class="fas fa-times"></i>
        </button>
    </div>
    <div class="sidebar-content">
        <div class="nav-section">
            <h6>\U0001f4ca Dashboard Sections</h6>
            <ul class="nav flex-column">
                <li class="nav-item"><a class="nav-link" href="#overview" onclick="scrollToSection('overview')"><i class="fas fa-tachometer-alt"></i> Overview &amp; Summary</a></li>
                <li class="nav-item"><a class="nav-link" href="#charts" onclick="scrollToSection('charts')"><i class="fas fa-chart-pie"></i> Security Charts</a></li>
                <li class="nav-item"><a class="nav-link" href="#regions" onclick="scrollToSection('regions')"><i class="fas fa-globe"></i> Regional Analysis</a></li>
                <li class="nav-item"><a class="nav-link" href="#details" onclick="scrollToSection('details')"><i class="fas fa-table"></i> Detailed Analysis</a></li>
                <li class="nav-item"><a class="nav-link" href="#compliance" onclick="scrollToSection('compliance')"><i class="fas fa-check-circle"></i> Compliance Status</a></li>
                <li class="nav-item"><a class="nav-link" href="#roadmap" onclick="scrollToSection('roadmap')"><i class="fas fa-road"></i> Improvement Roadmap</a></li>
                <li class="nav-item"><a class="nav-link" href="#insights" onclick="scrollToSection('insights')"><i class="fas fa-lightbulb"></i> Recommendations</a></li>
                <li class="nav-item"><a class="nav-link" href="#methodology" onclick="scrollToSection('methodology')"><i class="fas fa-calculator"></i> Score Methodology</a></li>
            </ul>
        </div>
    </div>
</div>
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
"""


def _html_main_start() -> str:
    return """
<div class="main-content">
    <div class="container-fluid">
"""


def _html_main_end() -> str:
    return """
    </div>
</div>
"""


def _html_overview(customer: str, scan_date: str, num_accounts: int,
                   security_score: float, provider_str: str, scope_term: str) -> str:
    score_cls = _score_class(security_score)
    scope_word = scope_term if scope_term else "account"
    return f"""
<div class="row mb-4" id="overview">
    <div class="col-12">
        <div class="dashboard-header">
            <h1 class="display-4">CSPM Security Insights Dashboard for {customer}</h1>
            <p class="lead">Security Insights from the Prowler Scans for {customer} across {num_accounts} {_esc(provider_str)} {scope_word}s</p>
            <div class="d-flex justify-content-between align-items-center flex-wrap">
                <span class="generation-time">Generated: {_esc(scan_date)}</span>
                <div class="security-score d-flex align-items-center">
                    <span class="score-label">Overall Security Score:</span>
                    <span class="score-value {score_cls}">{security_score}%</span>
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_global_filter() -> str:
    return """
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5>\U0001f50d Global Filter</h5>
            </div>
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-md-4">
                        <label for="statusFilter" class="form-label">Filter by Finding Status:</label>
                        <select id="statusFilter" class="form-select" onchange="applyStatusFilter()">
                            <option value="all">All Findings</option>
                            <option value="Failed">Failed Only</option>
                            <option value="Passed">Passed Only</option>
                            <option value="Manual">Manual Only</option>
                        </select>
                    </div>
                    <div class="col-md-8">
                        <div class="alert alert-info mb-0" id="filterInfo">
                            <small><strong>Current View:</strong> Showing all findings across all statuses</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_kpi_cards(critical: int, high: int, total: int, num_accounts: int, scope_label: str) -> str:
    return f"""
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card summary-card">
            <div class="card-body text-center">
                <h3 class="card-title text-danger" id="criticalCount">{critical}</h3>
                <p class="card-text">Critical Findings</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card summary-card">
            <div class="card-body text-center">
                <h3 class="card-title text-warning" id="highCount">{high}</h3>
                <p class="card-text">High Findings</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card summary-card">
            <div class="card-body text-center">
                <h3 class="card-title text-info" id="totalCount">{total}</h3>
                <p class="card-text" id="totalLabel">Total Findings</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card summary-card">
            <div class="card-body text-center">
                <h3 class="card-title text-success" id="accountCount">{num_accounts}</h3>
                <p class="card-text">{_esc(scope_label)}</p>
            </div>
        </div>
    </div>
</div>
"""


def _html_charts_section() -> str:
    return """
<div class="row mb-4" id="charts">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header"><h5>Severity Distribution</h5></div>
            <div class="card-body"><canvas id="severityChart" height="300"></canvas></div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header"><h5>Account Security Comparison</h5></div>
            <div class="card-body"><canvas id="accountChart" height="300"></canvas></div>
        </div>
    </div>
</div>
<div class="row mb-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header"><h5>Service Risk Analysis</h5></div>
            <div class="card-body"><canvas id="serviceChart" height="300"></canvas></div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header"><h5>Top Failing Checks (by Failure Count)</h5></div>
            <div class="card-body"><canvas id="checksChart" height="400"></canvas></div>
        </div>
    </div>
</div>
"""


def _html_regions_section(region_stats: list) -> str:
    # Build the region summary table
    rows_html = ""
    for r in region_stats[:10]:
        rc = _risk_class(r["risk_score"])
        rows_html += f"""
                <tr>
                    <td><small><strong>{_esc(r['region'])}</strong></small></td>
                    <td class="text-center"><small>{r['total']}</small></td>
                    <td class="text-center"><small>{r['failed']}</small></td>
                    <td class="text-center"><small><span class="badge bg-danger">{r['critical']}</span></small></td>
                    <td class="text-center"><small><span class="badge bg-warning">{r['high']}</span></small></td>
                    <td class="text-center"><small><span class="risk-score {rc}">{r['risk_score']}</span></small></td>
                </tr>"""

    if not region_stats:
        return '<div class="row mb-4" id="regions"></div>'

    return f"""
<div class="row mb-4" id="regions">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>\U0001f30d Regional Distribution of Findings</h5></div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <canvas id="regionsChart" height="300"></canvas>
                    </div>
                    <div class="col-md-4">
                        <h6>Top Regions by Findings</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th><small>Region</small></th>
                                        <th class="text-center"><small>Total</small></th>
                                        <th class="text-center"><small>Failed</small></th>
                                        <th class="text-center"><small>Critical</small></th>
                                        <th class="text-center"><small>High</small></th>
                                        <th class="text-center"><small>Risk</small></th>
                                    </tr>
                                </thead>
                                <tbody>{rows_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_details_section(account_stats: list, service_stats: list) -> str:
    # Build account table rows
    account_rows = ""
    for a in account_stats:
        rc = _risk_class(a["risk_score"])
        account_rows += f"""
                        <tr class="account-row" data-account-name="{_esc(a['account_name'].lower())}" data-account-id="{_esc(a['account_id'])}" data-risk-score="{a['risk_score']}" data-pass-rate="{a['pass_rate']}">
                            <td>{_esc(a['account_name'])}</td>
                            <td><code>{_esc(a['account_id'])}</code></td>
                            <td>{a['total']}</td>
                            <td>{a['failed']}</td>
                            <td>{a['pass_rate']}%</td>
                            <td><span class="badge bg-danger">{a['critical']}</span></td>
                            <td><span class="badge bg-warning">{a['high']}</span></td>
                            <td><span class="risk-score {rc}">{a['risk_score']}</span></td>
                        </tr>"""

    # Build service table rows
    service_rows = ""
    for s in service_stats:
        rc = _risk_class(s["risk_score"])
        service_rows += f"""
                        <tr class="service-row" data-service-name="{_esc(s['service'].lower())}" data-critical-failures="{s['critical']}" data-high-failures="{s['high']}" data-risk-score="{s['risk_score']}" data-failure-rate="{s['failure_rate']}">
                            <td>{_esc(s['service'])}</td>
                            <td>{s['total']}</td>
                            <td>{s['failed']}</td>
                            <td>{s['failure_rate']}%</td>
                            <td><span class="badge bg-danger">{s['critical']}</span></td>
                            <td><span class="badge bg-warning">{s['high']}</span></td>
                            <td><span class="risk-score {rc}">{s['risk_score']}</span></td>
                        </tr>"""

    return f"""
<div class="row mb-4" id="details">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>Account Security Details</h5></div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-md-4">
                        <label for="accountNameFilter" class="form-label">Filter by Account Name:</label>
                        <input type="text" id="accountNameFilter" class="form-control" placeholder="Enter account name..." onkeyup="filterAccountTable()">
                    </div>
                    <div class="col-md-4">
                        <label for="accountNumberFilter" class="form-label">Filter by Account Number:</label>
                        <input type="text" id="accountNumberFilter" class="form-control" placeholder="Enter account number..." onkeyup="filterAccountTable()">
                    </div>
                    <div class="col-md-4 d-flex align-items-end">
                        <button type="button" class="btn btn-outline-secondary" onclick="clearAccountFilters()">\U0001f5d1\ufe0f Clear Filters</button>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped" id="accountTable">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Account Number</th>
                                <th>Total Findings</th>
                                <th>Failed</th>
                                <th>Pass Rate</th>
                                <th>Critical</th>
                                <th>High</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="accountTableBody">{account_rows}
                        </tbody>
                    </table>
                </div>
                <div class="row mt-2">
                    <div class="col-md-6">
                        <div id="accountTableInfo" class="text-muted"></div>
                    </div>
                    <div class="col-md-6">
                        <nav aria-label="Account table pagination">
                            <ul class="pagination pagination-sm justify-content-end" id="accountPagination"></ul>
                        </nav>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>Service Vulnerability Analysis</h5></div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label for="serviceNameFilter" class="form-label">Filter by Service Name:</label>
                        <input type="text" id="serviceNameFilter" class="form-control" placeholder="Enter service name..." onkeyup="filterServiceTable()">
                    </div>
                    <div class="col-md-6 d-flex align-items-end">
                        <button type="button" class="btn btn-outline-secondary me-2" onclick="clearServiceFilters()">\U0001f5d1\ufe0f Clear Filters</button>
                        <div class="text-muted small"><i>Sorted by Critical Failures (highest first)</i></div>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped" id="serviceTable">
                        <thead>
                            <tr>
                                <th>Service</th>
                                <th>Total Findings</th>
                                <th>Failed</th>
                                <th>Failure Rate</th>
                                <th>Critical \u2193</th>
                                <th>High</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="serviceTableBody">{service_rows}
                        </tbody>
                    </table>
                </div>
                <div class="row mt-2">
                    <div class="col-md-6">
                        <div id="serviceTableInfo" class="text-muted"></div>
                    </div>
                    <div class="col-md-6">
                        <nav aria-label="Service table pagination">
                            <ul class="pagination pagination-sm justify-content-end" id="servicePagination"></ul>
                        </nav>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_compliance_section(compliance: dict) -> str:
    if not compliance:
        return '<div class="row mb-4" id="compliance"></div>'

    cards_html = ""
    for fw, info in compliance.items():
        if isinstance(info, dict):
            total = info.get("total", 0)
            passed = info.get("pass", info.get("passed", 0))
            rate = info.get("pass_rate", round((passed / total * 100), 1) if total > 0 else 0)
            color = "#28a745" if rate >= 80 else "#fd7e14" if rate >= 50 else "#dc3545"
            cards_html += f"""
                <div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h6>{_esc(fw)}</h6>
                            <div class="small text-muted mb-2">Checks passed: {passed} / {total} ({rate}%)</div>
                            <div class="progress" style="height: 8px;">
                                <div class="progress-bar" style="width: {rate}%; background-color: {color};"></div>
                            </div>
                        </div>
                    </div>
                </div>"""

    return f"""
<div class="row mb-4" id="compliance">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>\u2705 Compliance Framework Coverage</h5></div>
            <div class="card-body">
                <div class="row">{cards_html}
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_insights_section(critical: int, high: int, security_score: float,
                           account_stats: list) -> str:
    alerts_html = ""

    # Critical alert
    if critical > 0:
        alerts_html += f"""
            <div class="alert alert-danger" role="alert">
                <h6 class="alert-heading">\U0001f6a8 Critical Security Issues Detected</h6>
                <p class="mb-2">{critical} critical security findings require immediate attention.</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Prioritize remediation of critical findings to reduce security risk.</p>
            </div>"""

    # Underperforming accounts
    weak_accounts = [a for a in account_stats if a["pass_rate"] < 60]
    if weak_accounts:
        worst = min(weak_accounts, key=lambda x: x["pass_rate"])
        alerts_html += f"""
            <div class="alert alert-warning" role="alert">
                <h6 class="alert-heading">\u26a0\ufe0f Account Security Concerns</h6>
                <p class="mb-2">Account '{_esc(worst['account_name'])}' has a {worst['pass_rate']}% pass rate.</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Review and strengthen security controls for underperforming accounts.</p>
            </div>"""

    # Positive posture
    if security_score >= 70:
        alerts_html += f"""
            <div class="alert alert-success" role="alert">
                <h6 class="alert-heading">\u2705 Strong Security Posture</h6>
                <p class="mb-2">Overall security score of {security_score}% indicates good security practices.</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Maintain current security standards and monitor for new threats.</p>
            </div>"""
    elif security_score >= 40:
        alerts_html += f"""
            <div class="alert alert-warning" role="alert">
                <h6 class="alert-heading">\u26a0\ufe0f Moderate Security Posture</h6>
                <p class="mb-2">Overall security score of {security_score}% indicates room for improvement.</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Focus on critical and high-severity findings to improve your security posture.</p>
            </div>"""
    else:
        alerts_html += f"""
            <div class="alert alert-danger" role="alert">
                <h6 class="alert-heading">\U0001f6a8 Weak Security Posture</h6>
                <p class="mb-2">Overall security score of {security_score}% requires significant improvement.</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Immediately address critical findings and develop a comprehensive security improvement plan.</p>
            </div>"""

    return f"""
<div class="row mb-4" id="insights">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>\U0001f50d Security Insights &amp; Recommendations</h5></div>
            <div class="card-body">{alerts_html}
            </div>
        </div>
    </div>
</div>
"""


def _html_roadmap_section(roadmap: dict) -> str:
    summary = roadmap["summary"]
    imm = roadmap["immediate"]
    short = roadmap["short_term"]
    long = roadmap["long_term"]

    # Build phase cards
    def _phase_items_html(items: list, border_class: str) -> str:
        result = ""
        for item in items:
            sev_lower = item["severity"].lower()
            sev_bg = _severity_bg_class(sev_lower)
            border_sev = "border-danger" if sev_lower == "critical" else "border-warning" if sev_lower == "high" else "border-success"
            title_short = _esc(item["title"][:50]) + "..." if len(item["title"]) > 50 else _esc(item["title"])
            result += f"""
                            <div class="roadmap-item mb-2 p-2 border-start border-3 {border_sev}">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div class="flex-grow-1">
                                        <small class="fw-bold">{title_short}</small>
                                        <div class="text-muted" style="font-size: 0.75rem;">{_esc(item['service'])} \u2022 {item['affected_resources']} resource(s)</div>
                                        <div class="text-muted" style="font-size: 0.75rem;">{_esc(item['description'][:60])}</div>
                                    </div>
                                    <div class="text-end">
                                        <span class="badge {sev_bg}">{_esc(item['severity'])}</span>
                                        <div class="text-muted" style="font-size: 0.7rem;">{item['effort_weeks']}w</div>
                                    </div>
                                </div>
                            </div>"""
        return result

    imm_items = _phase_items_html(imm["items"], "border-danger")
    short_items = _phase_items_html(short["items"], "border-warning")
    long_items = _phase_items_html(long["items"], "border-success")

    return f"""
<div class="row mb-4" id="roadmap">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5>\U0001f6e3\ufe0f Security Improvement Roadmap</h5>
                <p class="mb-0 text-muted">Strategic plan to address {summary['total_issues']} security findings</p>
            </div>
            <div class="card-body">
                <div class="row mb-4">
                    <div class="col-md-8">
                        <canvas id="roadmapChart" height="300"></canvas>
                    </div>
                    <div class="col-md-4">
                        <div class="roadmap-summary">
                            <h6>\U0001f4ca Roadmap Summary</h6>
                            <div class="mb-3">
                                <div class="d-flex justify-content-between"><span>Total Issues:</span><strong>{summary['total_issues']}</strong></div>
                                <div class="d-flex justify-content-between"><span>Total Effort:</span><strong>{summary['total_effort_weeks']} weeks</strong></div>
                                <div class="d-flex justify-content-between"><span>Critical Issues:</span><strong class="text-danger">{summary['critical_count']}</strong></div>
                                <div class="d-flex justify-content-between"><span>High Priority:</span><strong class="text-warning">{summary['high_count']}</strong></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card border-danger">
                            <div class="card-header bg-danger text-white">
                                <h6 class="mb-0">\U0001f6a8 Immediate ({imm['timeline']})</h6>
                            </div>
                            <div class="card-body">
                                <div class="mb-2"><strong>{imm['count']} issues</strong> \u2022 <span class="text-muted">{imm['effort_weeks']} weeks effort</span></div>
                                <p class="small text-muted mb-3">{_esc(imm['description'])}</p>
                                {imm_items}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card border-warning">
                            <div class="card-header bg-warning text-dark">
                                <h6 class="mb-0">\u26a0\ufe0f Short Term ({short['timeline']})</h6>
                            </div>
                            <div class="card-body">
                                <div class="mb-2"><strong>{short['count']} issues</strong> \u2022 <span class="text-muted">{short['effort_weeks']} weeks effort</span></div>
                                <p class="small text-muted mb-3">{_esc(short['description'])}</p>
                                {short_items}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card border-success">
                            <div class="card-header bg-success text-white">
                                <h6 class="mb-0">\U0001f4c8 Long Term ({long['timeline']})</h6>
                            </div>
                            <div class="card-body">
                                <div class="mb-2"><strong>{long['count']} issues</strong> \u2022 <span class="text-muted">{long['effort_weeks']} weeks effort</span></div>
                                <p class="small text-muted mb-3">{_esc(long['description'])}</p>
                                {long_items}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""


def _html_methodology_section() -> str:
    return """
<div class="row mb-4" id="methodology">
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h5>\U0001f4ca Score Calculation Methodology</h5></div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-primary">\U0001f6e1\ufe0f Overall Security Score</h6>
                        <p class="text-muted">The Overall Security Score represents the percentage of security controls that are properly configured across all accounts.</p>
                        <div class="bg-light p-3 rounded mb-3">
                            <h6 class="mb-2">Calculation Formula:</h6>
                            <code class="d-block mb-2">Security Score = 100 - (Weighted Penalty / Max Possible Penalty \u00d7 100)</code>
                            <h6 class="mb-2 mt-3">Severity Weights:</h6>
                            <ul class="list-unstyled">
                                <li><span class="badge bg-danger me-2">Critical</span> Weight: 10</li>
                                <li><span class="badge bg-warning me-2">High</span> Weight: 7</li>
                                <li><span class="badge bg-info me-2">Medium</span> Weight: 4</li>
                                <li><span class="badge bg-success me-2">Low</span> Weight: 2</li>
                                <li><span class="badge bg-secondary me-2">Info</span> Weight: 1</li>
                            </ul>
                        </div>
                        <div class="alert alert-info">
                            <small><strong>Example:</strong> If you have 1 Critical failure (10 points) out of 100 total findings, the penalty would be 10/1000 = 1%, resulting in a 99% security score.</small>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">\u26a0\ufe0f Risk Score (Per Account/Service)</h6>
                        <p class="text-muted">Risk Scores are calculated for individual accounts and services based on their failed security findings.</p>
                        <div class="bg-light p-3 rounded mb-3">
                            <h6 class="mb-2">Calculation Formula:</h6>
                            <code class="d-block mb-2">Risk Score = (Weighted Failed Findings / Max Possible \u00d7 100)</code>
                            <h6 class="mb-2 mt-3">Risk Score Interpretation:</h6>
                            <ul class="list-unstyled">
                                <li><span class="risk-score risk-high me-2">70-100</span> High Risk</li>
                                <li><span class="risk-score risk-medium me-2">40-69</span> Medium Risk</li>
                                <li><span class="risk-score risk-low me-2">0-39</span> Low Risk</li>
                            </ul>
                        </div>
                        <div class="alert alert-warning">
                            <small><strong>Note:</strong> Risk Scores focus only on failed findings, while the Overall Security Score considers all findings. A low Risk Score is desirable (fewer weighted failures).</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

def _html_scripts(severity_data: dict, account_data: dict, service_data: dict,
                  checks_data: dict, regions_data: dict, roadmap_data: dict,
                  roadmap: dict) -> str:
    """Generate the <script> block with all Chart.js initialization and interactivity."""

    charts_init = ""

    def _chart_block(canvas_id: str, config: dict) -> str:
        if not config:
            return ""
        return f"""
    try {{
        const {canvas_id}Ctx = document.getElementById('{canvas_id}');
        if ({canvas_id}Ctx) {{
            const chartConfig = {_safe_json(config)};
            chartInstances['{canvas_id}'] = new Chart({canvas_id}Ctx, chartConfig);
            originalChartData['{canvas_id}'] = {{
                labels: [...chartConfig.data.labels],
                datasets: chartConfig.data.datasets.map(dataset => ({{
                    ...dataset,
                    data: [...dataset.data]
                }}))
            }};
        }}
    }} catch (error) {{
        console.error('Error initializing {canvas_id}:', error);
    }}
"""

    charts_init += _chart_block("severityChart", severity_data)
    charts_init += _chart_block("accountChart", account_data)
    charts_init += _chart_block("serviceChart", service_data)

    # Checks chart with custom tooltip
    if checks_data:
        charts_init += f"""
    try {{
        const checksChartCtx = document.getElementById('checksChart');
        if (checksChartCtx) {{
            const chartConfig = {_safe_json(checks_data)};
            if (chartConfig.options && chartConfig.options.plugins && chartConfig.options.plugins.tooltip) {{
                chartConfig.options.plugins.tooltip.callbacks = {{
                    title: function(context) {{
                        const dataset = context[0].dataset;
                        const index = context[0].dataIndex;
                        return dataset.fullTitles ? dataset.fullTitles[index] : context[0].label;
                    }},
                    label: function(context) {{
                        const dataset = context.dataset;
                        const index = context.dataIndex;
                        const labels = [];
                        labels.push('Failures: ' + context.parsed.x);
                        if (dataset.severities && dataset.severities[index]) {{
                            labels.push('Severity: ' + dataset.severities[index]);
                        }}
                        if (dataset.checkIds && dataset.checkIds[index]) {{
                            labels.push('Check ID: ' + dataset.checkIds[index]);
                        }}
                        if (dataset.services && dataset.services[index]) {{
                            labels.push('Service: ' + dataset.services[index]);
                        }}
                        return labels;
                    }}
                }};
            }}
            chartInstances['checksChart'] = new Chart(checksChartCtx, chartConfig);
            originalChartData['checksChart'] = {{
                labels: [...chartConfig.data.labels],
                datasets: chartConfig.data.datasets.map(dataset => ({{
                    ...dataset,
                    data: [...dataset.data]
                }}))
            }};
        }}
    }} catch (error) {{
        console.error('Error initializing checksChart:', error);
    }}
"""

    charts_init += _chart_block("regionsChart", regions_data)
    charts_init += _chart_block("roadmapChart", roadmap_data)

    return f"""
<script>
// Global data storage for filtering
let originalData = {{}};
let currentFilter = 'all';
let chartInstances = {{}};
let originalChartData = {{}};

// Initialize original data for filtering
function initializeFilterData() {{
    originalData = {{
        critical: parseInt(document.getElementById('criticalCount').textContent),
        high: parseInt(document.getElementById('highCount').textContent),
        total: parseInt(document.getElementById('totalCount').textContent),
        accounts: parseInt(document.getElementById('accountCount').textContent)
    }};
}}

// Apply status filter
function applyStatusFilter() {{
    const filter = document.getElementById('statusFilter').value;
    currentFilter = filter;
    const filterInfo = document.getElementById('filterInfo');

    if (filter === 'all') {{
        document.getElementById('criticalCount').textContent = originalData.critical;
        document.getElementById('highCount').textContent = originalData.high;
        document.getElementById('totalCount').textContent = originalData.total;
        document.getElementById('totalLabel').textContent = 'Total Findings';
        filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing all findings across all statuses</small>';
        filterInfo.className = 'alert alert-info mb-0';
    }} else if (filter === 'Failed') {{
        document.getElementById('criticalCount').textContent = originalData.critical;
        document.getElementById('highCount').textContent = originalData.high;
        document.getElementById('totalCount').textContent = originalData.critical + originalData.high;
        document.getElementById('totalLabel').textContent = 'Failed Findings';
        filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-danger">FAILED</span> findings</small>';
        filterInfo.className = 'alert alert-danger mb-0';
    }} else if (filter === 'Passed') {{
        const passedFindings = originalData.total - (originalData.critical + originalData.high);
        document.getElementById('criticalCount').textContent = '0';
        document.getElementById('highCount').textContent = '0';
        document.getElementById('totalCount').textContent = passedFindings;
        document.getElementById('totalLabel').textContent = 'Passed Findings';
        filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-success">PASSED</span> findings</small>';
        filterInfo.className = 'alert alert-success mb-0';
    }} else if (filter === 'Manual') {{
        document.getElementById('criticalCount').textContent = '0';
        document.getElementById('highCount').textContent = '0';
        document.getElementById('totalCount').textContent = '0';
        document.getElementById('totalLabel').textContent = 'Manual Findings';
        filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-warning">MANUAL</span> findings</small>';
        filterInfo.className = 'alert alert-warning mb-0';
    }}

    updateSeverityChart(filter);
    updateAccountChart(filter);
}}

// Update severity chart based on filter
function updateSeverityChart(filter) {{
    const chart = chartInstances['severityChart'];
    if (!chart || !originalChartData['severityChart']) return;
    const origData = originalChartData['severityChart'];
    let newData = [...origData.datasets[0].data];
    let newLabels = [...origData.labels];

    if (filter === 'Failed') {{
        const mediumIndex = newLabels.indexOf('Medium');
        const lowIndex = newLabels.indexOf('Low');
        if (mediumIndex !== -1) newData[mediumIndex] = 0;
        if (lowIndex !== -1) newData[lowIndex] = 0;
    }} else if (filter === 'Passed') {{
        const criticalIndex = newLabels.indexOf('Critical');
        const highIndex = newLabels.indexOf('High');
        if (criticalIndex !== -1) newData[criticalIndex] = 0;
        if (highIndex !== -1) newData[highIndex] = 0;
    }} else if (filter === 'Manual') {{
        newData = newData.map(() => 0);
    }}

    chart.data.datasets[0].data = newData;
    chart.update();
}}

// Update account chart based on filter
function updateAccountChart(filter) {{
    const chart = chartInstances['accountChart'];
    if (!chart || !originalChartData['accountChart']) return;
    const origData = originalChartData['accountChart'];

    if (filter === 'all') {{
        chart.data.datasets.forEach((dataset, index) => {{
            dataset.data = [...origData.datasets[index].data];
        }});
    }} else if (filter === 'Failed') {{
        chart.data.datasets.forEach((dataset, index) => {{
            if (dataset.label === 'Critical' || dataset.label === 'High') {{
                dataset.data = [...origData.datasets[index].data];
            }} else {{
                dataset.data = origData.datasets[index].data.map(() => 0);
            }}
        }});
    }} else if (filter === 'Passed') {{
        chart.data.datasets.forEach((dataset, index) => {{
            if (dataset.label === 'Medium/Low' || dataset.label === 'Low') {{
                dataset.data = [...origData.datasets[index].data];
            }} else {{
                dataset.data = origData.datasets[index].data.map(() => 0);
            }}
        }});
    }} else if (filter === 'Manual') {{
        chart.data.datasets.forEach((dataset, index) => {{
            dataset.data = origData.datasets[index].data.map(() => 0);
        }});
    }}

    chart.update();
}}

// Account table filtering and pagination
let currentAccountPage = 1;
let accountsPerPage = 5;
let filteredAccountRows = [];

function filterAccountTable() {{
    const nameFilter = document.getElementById('accountNameFilter').value.toLowerCase();
    const numberFilter = document.getElementById('accountNumberFilter').value.toLowerCase();
    const allRows = document.querySelectorAll('.account-row');

    filteredAccountRows = Array.from(allRows).filter(row => {{
        const accountName = row.getAttribute('data-account-name');
        const accountId = row.getAttribute('data-account-id').toLowerCase();
        const nameMatch = !nameFilter || accountName.includes(nameFilter);
        const numberMatch = !numberFilter || accountId.includes(numberFilter);
        return nameMatch && numberMatch;
    }});

    currentAccountPage = 1;
    displayAccountPage();
    updateAccountPagination();
}}

function displayAccountPage() {{
    const allRows = document.querySelectorAll('.account-row');
    allRows.forEach(row => row.style.display = 'none');
    const startIndex = (currentAccountPage - 1) * accountsPerPage;
    const endIndex = startIndex + accountsPerPage;
    filteredAccountRows.slice(startIndex, endIndex).forEach(row => {{
        row.style.display = '';
    }});
    updateAccountTableInfo();
}}

function updateAccountPagination() {{
    const totalPages = Math.ceil(filteredAccountRows.length / accountsPerPage);
    const pagination = document.getElementById('accountPagination');
    if (totalPages <= 1) {{ pagination.innerHTML = ''; return; }}
    let html = '';
    if (currentAccountPage > 1) {{
        html += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${{currentAccountPage - 1}}); return false;">Previous</a></li>`;
    }} else {{
        html += `<li class="page-item disabled"><span class="page-link">Previous</span></li>`;
    }}
    const maxVisible = 5;
    let startPage = Math.max(1, currentAccountPage - Math.floor(maxVisible / 2));
    let endPage = Math.min(totalPages, startPage + maxVisible - 1);
    if (endPage - startPage + 1 < maxVisible) startPage = Math.max(1, endPage - maxVisible + 1);
    for (let i = startPage; i <= endPage; i++) {{
        if (i === currentAccountPage) {{
            html += `<li class="page-item active"><span class="page-link">${{i}}</span></li>`;
        }} else {{
            html += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${{i}}); return false;">${{i}}</a></li>`;
        }}
    }}
    if (currentAccountPage < totalPages) {{
        html += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${{currentAccountPage + 1}}); return false;">Next</a></li>`;
    }} else {{
        html += `<li class="page-item disabled"><span class="page-link">Next</span></li>`;
    }}
    pagination.innerHTML = html;
}}

function changeAccountPage(page) {{
    currentAccountPage = page;
    displayAccountPage();
    updateAccountPagination();
}}

function updateAccountTableInfo() {{
    const total = filteredAccountRows.length;
    const startIndex = (currentAccountPage - 1) * accountsPerPage + 1;
    const endIndex = Math.min(currentAccountPage * accountsPerPage, total);
    const info = document.getElementById('accountTableInfo');
    if (total === 0) {{
        info.textContent = 'No accounts found matching the filter criteria.';
    }} else {{
        info.textContent = `Showing ${{startIndex}}-${{endIndex}} of ${{total}} accounts`;
    }}
}}

function clearAccountFilters() {{
    document.getElementById('accountNameFilter').value = '';
    document.getElementById('accountNumberFilter').value = '';
    filterAccountTable();
}}

function initializeAccountTable() {{
    const allRows = document.querySelectorAll('.account-row');
    filteredAccountRows = Array.from(allRows);
    displayAccountPage();
    updateAccountPagination();
}}

// Service table filtering and pagination
let currentServicePage = 1;
let servicesPerPage = 5;
let filteredServiceRows = [];

function filterServiceTable() {{
    const nameFilter = document.getElementById('serviceNameFilter').value.toLowerCase();
    const allRows = document.querySelectorAll('.service-row');

    filteredServiceRows = Array.from(allRows).filter(row => {{
        const serviceName = row.getAttribute('data-service-name');
        return !nameFilter || serviceName.includes(nameFilter);
    }});

    currentServicePage = 1;
    displayServicePage();
    updateServicePagination();
}}

function displayServicePage() {{
    const allRows = document.querySelectorAll('.service-row');
    allRows.forEach(row => row.style.display = 'none');
    const startIndex = (currentServicePage - 1) * servicesPerPage;
    const endIndex = startIndex + servicesPerPage;
    filteredServiceRows.slice(startIndex, endIndex).forEach(row => {{
        row.style.display = '';
    }});
    updateServiceTableInfo();
}}

function updateServicePagination() {{
    const totalPages = Math.ceil(filteredServiceRows.length / servicesPerPage);
    const pagination = document.getElementById('servicePagination');
    if (totalPages <= 1) {{ pagination.innerHTML = ''; return; }}
    let html = '';
    if (currentServicePage > 1) {{
        html += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${{currentServicePage - 1}}); return false;">Previous</a></li>`;
    }} else {{
        html += `<li class="page-item disabled"><span class="page-link">Previous</span></li>`;
    }}
    const maxVisible = 5;
    let startPage = Math.max(1, currentServicePage - Math.floor(maxVisible / 2));
    let endPage = Math.min(totalPages, startPage + maxVisible - 1);
    if (endPage - startPage + 1 < maxVisible) startPage = Math.max(1, endPage - maxVisible + 1);
    for (let i = startPage; i <= endPage; i++) {{
        if (i === currentServicePage) {{
            html += `<li class="page-item active"><span class="page-link">${{i}}</span></li>`;
        }} else {{
            html += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${{i}}); return false;">${{i}}</a></li>`;
        }}
    }}
    if (currentServicePage < totalPages) {{
        html += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${{currentServicePage + 1}}); return false;">Next</a></li>`;
    }} else {{
        html += `<li class="page-item disabled"><span class="page-link">Next</span></li>`;
    }}
    pagination.innerHTML = html;
}}

function changeServicePage(page) {{
    currentServicePage = page;
    displayServicePage();
    updateServicePagination();
}}

function updateServiceTableInfo() {{
    const total = filteredServiceRows.length;
    const startIndex = (currentServicePage - 1) * servicesPerPage + 1;
    const endIndex = Math.min(currentServicePage * servicesPerPage, total);
    const info = document.getElementById('serviceTableInfo');
    if (total === 0) {{
        info.textContent = 'No services found matching the filter criteria.';
    }} else {{
        info.textContent = `Showing ${{startIndex}}-${{endIndex}} of ${{total}} services`;
    }}
}}

function clearServiceFilters() {{
    document.getElementById('serviceNameFilter').value = '';
    filterServiceTable();
}}

function initializeServiceTable() {{
    const allRows = document.querySelectorAll('.service-row');
    filteredServiceRows = Array.from(allRows);
    displayServicePage();
    updateServicePagination();
}}

// Navigation
function toggleSidebar() {{
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    sidebar.classList.toggle('show');
    overlay.classList.toggle('show');
}}

function scrollToSection(sectionId) {{
    const element = document.getElementById(sectionId);
    if (element) {{
        element.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        if (window.innerWidth <= 768) {{
            toggleSidebar();
        }}
    }}
}}

// Close sidebar when clicking outside on mobile
document.addEventListener('click', function(event) {{
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = event.target.closest('[onclick*="toggleSidebar"]');
    if (!sidebar.contains(event.target) && !sidebarToggle && sidebar.classList.contains('show')) {{
        toggleSidebar();
    }}
}});

window.addEventListener('resize', function() {{
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (window.innerWidth > 768 && sidebar.classList.contains('show')) {{
        sidebar.classList.remove('show');
        overlay.classList.remove('show');
    }}
}});

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {{
    initializeFilterData();
    initializeAccountTable();
    initializeServiceTable();
}});

// Initialize charts
{charts_init}
</script>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate HTML security dashboard (Chart.js + Bootstrap 5)")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_html", help="Path for output HTML file")
    args = parser.parse_args()

    data = load_analysis(args.analysis_json)
    generate_html(data, args.output_html)


if __name__ == "__main__":
    main()
