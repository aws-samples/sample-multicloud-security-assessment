#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
generate_charts.py - Generate chart PNG images for embedding in the PPTX deck.

Provider-neutral: charts describe severity, service, score, compliance, and an
optional per-provider breakdown when multiple clouds are present.

Usage:
    python3 generate_charts.py <analysis_json> <output_charts_dir>
"""

import argparse
import json
import os
import sys
import safe_io

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
except ImportError:
    print("ERROR: matplotlib is required. Install with: pip3 install matplotlib", file=sys.stderr)
    sys.exit(1)


def _plain(label) -> str:
    """Render a scan-derived label literally. Matplotlib treats paired ``$...$`` as
    mathtext, so a crafted service/framework name could inject math markup or raise
    on invalid syntax and abort chart generation; escaping ``$`` keeps it plain text."""
    return str(label).replace("$", r"\$")


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# Output folder the charts are contained under (see safe_io.containment_root); set by
# main(). None falls back to the chart's own folder.
OUTPUT_ROOT = None


def save_chart(output_path: str):
    """Write the active Matplotlib figure without following a planted output link."""
    output_root = OUTPUT_ROOT or os.path.dirname(os.path.abspath(output_path)) or "."
    with safe_io.open_write_nofollow(output_path, binary=True, root=output_root) as fh:
        plt.savefig(fh, dpi=150, bbox_inches="tight", transparent=True)


def generate_severity_donut(severity: dict, output_path: str):
    """Donut chart showing findings by severity."""
    labels = ["Critical", "High", "Medium", "Low", "Other"]
    values = [severity.get("critical", 0), severity.get("high", 0),
              severity.get("medium", 0), severity.get("low", 0),
              severity.get("other", 0)]
    colors = ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c", "#9e9e9e"]

    non_zero = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
    if not non_zero:
        non_zero = [("No Findings", 1, "#cccccc")]

    fig, ax = plt.subplots(1, 1, figsize=(5, 5))
    ax.pie(
        [x[1] for x in non_zero],
        labels=[f"{x[0]} ({x[1]})" for x in non_zero],
        colors=[x[2] for x in non_zero],
        autopct="%1.0f%%",
        startangle=90,
        pctdistance=0.8,
        wedgeprops={"width": 0.4}
    )
    ax.set_title("Findings by Severity", fontsize=14, fontweight="bold", pad=16)
    plt.tight_layout()
    save_chart(output_path)
    plt.close()
    print(f"  + Severity donut -> {output_path}")


def generate_service_bar(by_service: dict, output_path: str):
    """Horizontal bar chart showing top 10 services with failures."""
    services = list(by_service.keys())[:10]
    values = [by_service[s] for s in services]

    fig, ax = plt.subplots(1, 1, figsize=(7, 5))
    bars = ax.barh([_plain(s) for s in services[::-1]], values[::-1], color="#f57c00", edgecolor="none")
    ax.set_xlabel("Failed Checks", fontsize=11)
    ax.set_title("Top Services with Security Failures", fontsize=14, fontweight="bold", pad=12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=10)

    plt.tight_layout()
    save_chart(output_path)
    plt.close()
    print(f"  + Service bar chart -> {output_path}")


def generate_score_gauge(score: float, output_path: str):
    """Gauge-style chart showing security score percentage."""
    fig, ax = plt.subplots(1, 1, figsize=(4, 3))

    theta1, theta2 = 0, 180
    arc_bg = mpatches.Arc((0.5, 0), 0.8, 0.8, angle=0, theta1=theta1, theta2=theta2,
                          color="#eeeeee", linewidth=20)
    ax.add_patch(arc_bg)

    score_angle = score / 100 * 180
    color = "#388e3c" if score >= 70 else "#f57c00" if score >= 50 else "#d32f2f"
    arc_score = mpatches.Arc((0.5, 0), 0.8, 0.8, angle=0, theta1=theta1,
                             theta2=theta1 + score_angle, color=color, linewidth=20)
    ax.add_patch(arc_score)

    ax.text(0.5, 0.05, f"{score}%", ha="center", va="center", fontsize=28, fontweight="bold", color=color)
    ax.text(0.5, -0.15, "Security Score", ha="center", va="center", fontsize=12, color="#666")

    ax.set_xlim(0, 1)
    ax.set_ylim(-0.3, 0.6)
    ax.set_aspect("equal")
    ax.axis("off")
    plt.tight_layout()
    save_chart(output_path)
    plt.close()
    print(f"  + Score gauge -> {output_path}")


def generate_compliance_bar(compliance: dict, output_path: str):
    """Bar chart showing per-framework compliance pass rates."""
    if not compliance:
        fig, ax = plt.subplots(1, 1, figsize=(6, 4))
        ax.text(0.5, 0.5, "No compliance data available", ha="center", va="center", fontsize=14)
        ax.axis("off")
        save_chart(output_path)
        plt.close()
        print(f"  + Compliance chart (empty) -> {output_path}")
        return

    frameworks = list(compliance.keys())[:8]
    rates = [compliance[fw]["pass_rate"] for fw in frameworks]
    colors = ["#388e3c" if r >= 80 else "#f57c00" if r >= 50 else "#d32f2f" for r in rates]

    fig, ax = plt.subplots(1, 1, figsize=(7, 4))
    bars = ax.barh([_plain(f) for f in frameworks[::-1]], rates[::-1], color=colors[::-1], edgecolor="none")
    ax.set_xlabel("Pass Rate (%)", fontsize=11)
    ax.set_xlim(0, 100)
    ax.set_title("Compliance Framework Coverage", fontsize=14, fontweight="bold", pad=12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, rate in zip(bars, rates[::-1]):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{rate}%", va="center", fontsize=10)

    plt.tight_layout()
    save_chart(output_path)
    plt.close()
    print(f"  + Compliance chart -> {output_path}")


def generate_provider_bar(by_provider: dict, output_path: str):
    """Stacked bar chart of failed findings per provider (only when >1 provider)."""
    providers = [p for p in by_provider.keys()]
    if len(providers) <= 1:
        return  # Single-cloud: per-provider chart adds no value.

    labels = [by_provider[p]["label"] for p in providers]
    def _sev(key):
        return [by_provider[p]["findings_by_severity"].get(key, 0) for p in providers]

    series = [(_sev("critical"), "#d32f2f", "Critical"), (_sev("high"), "#f57c00", "High"),
              (_sev("medium"), "#fbc02d", "Medium"), (_sev("low"), "#388e3c", "Low"),
              (_sev("other"), "#9e9e9e", "Other")]

    fig, ax = plt.subplots(1, 1, figsize=(7, 4))
    import numpy as np
    idx = np.arange(len(labels))
    bottom = np.zeros(len(labels))
    for vals, color, name in series:
        if not any(vals):
            continue  # Skip empty severity bands so the legend stays readable.
        ax.bar(idx, vals, bottom=bottom, color=color, label=name)
        bottom += np.array(vals)

    ax.set_xticks(idx)
    ax.set_xticklabels([_plain(label) for label in labels])
    ax.set_ylabel("Failed Checks", fontsize=11)
    ax.set_title("Findings by Cloud Provider", fontsize=14, fontweight="bold", pad=12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=9)

    plt.tight_layout()
    save_chart(output_path)
    plt.close()
    print(f"  + Provider breakdown chart -> {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate chart PNGs for PPTX deck")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("output_dir", help="Directory to save chart PNGs")
    args = parser.parse_args()

    data = load_analysis(args.analysis_json)
    if os.path.lexists(args.output_dir) and os.path.islink(args.output_dir):
        print(f"ERROR: refusing to write charts to a symlinked directory: {args.output_dir}",
              file=sys.stderr)
        sys.exit(1)
    global OUTPUT_ROOT
    OUTPUT_ROOT = (safe_io.containment_root(args.output_dir, os.path.dirname(args.analysis_json))
                   or args.output_dir)
    safe_io.ensure_dir_within(args.output_dir, OUTPUT_ROOT, mode=0o700)

    summary = data["summary"]
    print("Generating charts for PPTX deck...")
    generate_severity_donut(summary["findings_by_severity"], os.path.join(args.output_dir, "severity_donut.png"))
    generate_service_bar(summary["findings_by_service"], os.path.join(args.output_dir, "service_bar.png"))
    generate_score_gauge(summary["security_score"], os.path.join(args.output_dir, "score_gauge.png"))
    generate_compliance_bar(data.get("compliance_coverage", {}), os.path.join(args.output_dir, "compliance_bar.png"))
    generate_provider_bar(summary.get("findings_by_provider", {}), os.path.join(args.output_dir, "provider_bar.png"))
    print("All charts generated.")


if __name__ == "__main__":
    main()
