#!/usr/bin/env python3
"""
analyze_security_data.py - Scan, parse, and analyze multi-cloud Prowler security
assessment outputs (AWS, Azure, GCP, OCI).

Combines file scanning and data analysis. Outputs a structured JSON file used by
all downstream generators.

Supported input formats (auto-detected, normalized to a single schema):
    - Prowler CSV (semicolon ';' delimited)
    - Prowler OCSF JSON
    - Security Hub / ASFF JSON (AWS Security Finding Format)
    - Prowler HTML reports

Usage:
    python3 analyze_security_data.py <input_folder> <output_json_path> [--customer <name>]
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from providers import PROVIDER_LABELS, PROVIDER_SCOPE_TERM

# Prowler REMEDIATION_CODE_* / RISK / DESCRIPTION fields can exceed Python's default
# CSV field limit (131,072 chars). Without this, csv.reader raises "field larger than
# field limit" and an entire file's findings would be silently dropped. Bump to the
# platform max (with a fallback for platforms where sys.maxsize overflows a C long).
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    # Some 32-bit / Windows builds reject sys.maxsize; fall back to the largest
    # value that is universally accepted.
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# Collects human-readable parse warnings so they can be surfaced in the output JSON
# (not just printed to stderr) — a downstream consumer can see if any file failed.
_PARSE_WARNINGS = []


# ---------------------------------------------------------------------------
# Provider awareness
# ---------------------------------------------------------------------------

# Normalized provider keys and human-friendly labels.
# Per-provider name for the top-level isolation boundary ("scope").
def normalize_provider(raw: str) -> str:
    """Map an arbitrary provider string to a normalized key."""
    if not raw:
        return "unknown"
    r = str(raw).strip().lower()
    if r.startswith("aws") or "amazon" in r:
        return "aws"
    if r.startswith("azure") or "microsoft" in r or "entra" in r:
        return "azure"
    if r.startswith("gcp") or "google" in r:
        return "gcp"
    if r.startswith("oci") or "oracle" in r:
        return "oci"
    if "kubernetes" in r or r == "k8s":
        return "kubernetes"
    return "unknown"


def scope_term_for_providers(providers: list) -> str:
    """Return a scope noun appropriate for the detected provider set."""
    terms = {PROVIDER_SCOPE_TERM.get(p, "scope") for p in providers}
    if len(terms) == 1:
        return terms.pop()
    # Mixed providers -> neutral umbrella term.
    return "account/subscription/project/tenancy"


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

PROWLER_MAIN_COLUMNS = {
    "STATUS", "SEVERITY", "CHECK_ID", "CHECK_TITLE", "SERVICE_NAME",
    "RESOURCE_UID", "RISK", "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_CODE_CLI", "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_NATIVEIAC", "COMPLIANCE", "CATEGORIES", "PROVIDER",
}

PROWLER_COMPLIANCE_COLUMNS = {
    "STATUS", "CHECKID", "REQUIREMENTS_ID", "REQUIREMENTS_DESCRIPTION",
    "REQUIREMENTS_ATTRIBUTES_SERVICE", "REQUIREMENTS_ATTRIBUTES_SECTION", "FRAMEWORK",
}


def detect_scope_ids(folder_path: str) -> list:
    """Extract likely cloud scope IDs (accounts/subscriptions/projects/tenancies)
    from filenames. Provider-neutral: matches 12-digit AWS account IDs, GUIDs
    (Azure subscriptions), and generic project/tenancy identifiers in filenames."""
    scope_ids = set()
    # 12-digit numeric IDs (AWS accounts, some GCP project numbers)
    numeric = re.compile(r"\b(\d{12})\b")
    # GUID-style IDs (Azure subscriptions, OCI OCIDs are longer/handled separately)
    guid = re.compile(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b")
    for f in Path(folder_path).rglob("*"):
        if not f.is_file():
            continue
        for m in numeric.findall(f.name):
            scope_ids.add(m)
        for m in guid.findall(f.name):
            scope_ids.add(m)
    return sorted(scope_ids)


def _is_compliance_json(filepath: Path) -> bool:
    """True if a .json is a per-framework compliance export rather than a main
    OCSF findings file. Detected by a compliance/ path or a framework-suffixed stem
    (the main per-scan file is exactly prowler-output-<id>-<ts>.ocsf.json — no extra
    _<framework> segment before the extension)."""
    name = filepath.name
    if "compliance" in str(filepath).lower():
        return True
    stem = name
    for ext in (".ocsf.json", ".json"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    # Main scan stems look like: prowler-output-<scope>-<14-digit-timestamp>
    # A compliance file appends _<framework> after the timestamp.
    m = re.search(r"-(\d{14})(.+)$", stem)
    if m and m.group(2):  # extra text after the timestamp -> framework-specific
        return True
    return False


def identify_files(folder_path: str) -> dict:
    """Categorize files in the input folder by type."""
    result = {
        "prowler_main_csv": [],
        "prowler_compliance_csv": [],
        "prowler_html": [],
        "prowler_json": [],
        "security_hub_json": [],
        "other": [],
    }

    for f in Path(folder_path).rglob("*"):
        if not f.is_file():
            continue
        name_lower = f.name.lower()

        if name_lower.endswith(".csv"):
            category = _classify_csv(f)
            if category == "main":
                result["prowler_main_csv"].append(str(f))
            elif category == "compliance":
                result["prowler_compliance_csv"].append(str(f))
            else:
                result["other"].append(str(f))
        elif name_lower.endswith(".html") or name_lower.endswith(".htm"):
            result["prowler_html"].append(str(f))
        elif name_lower.endswith(".json"):
            # A .json is a MAIN OCSF findings export only if it is the plain per-scan
            # file (prowler-output-<id>-<ts>.ocsf.json). Prowler also emits per-FRAMEWORK
            # OCSF/JSON compliance files (…_<framework>.ocsf.json) and places compliance
            # outputs under a compliance/ folder — those must NOT be treated as main
            # findings (doing so double-counts and injects an 'unknown' provider bucket).
            if _is_compliance_json(f):
                # Per-framework OCSF/JSON compliance exports are redundant with the
                # semicolon-delimited compliance CSVs (which the coverage parser reads).
                # Route them to 'other' so they are neither counted as main findings nor
                # fed to the CSV compliance parser (which would mis-split the JSON).
                result["other"].append(str(f))
            else:
                category = _classify_json(f)
                if category == "security_hub":
                    result["security_hub_json"].append(str(f))
                else:
                    result["prowler_json"].append(str(f))
        else:
            result["other"].append(str(f))

    return result


def _classify_csv(filepath: Path) -> str:
    """Classify a CSV as prowler main, compliance, or other."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            first_line = fh.readline().strip()
        headers = set(h.strip().upper() for h in first_line.split(";"))
        # Check compliance FIRST: compliance exports carry REQUIREMENTS_* / FRAMEWORK /
        # CHECKID (no underscore) columns that main findings files never have. Note
        # that compliance files ALSO contain a STATUS column, so testing "main" first
        # would misclassify every compliance file as main.
        if headers & {"REQUIREMENTS_ID", "FRAMEWORK", "CHECKID"}:
            return "compliance"
        # Main findings files are identified by columns unique to them (CHECK_ID and
        # SERVICE_NAME use underscores; compliance uses CHECKID without one).
        if headers & {"CHECK_ID", "SEVERITY", "SERVICE_NAME"}:
            return "main"
        # Fallback: files under a compliance/ folder are compliance exports.
        if "compliance" in str(filepath).lower():
            return "compliance"
    except Exception:
        pass
    return "other"


def _classify_json(filepath: Path) -> str:
    """Classify a JSON as Security Hub / ASFF export or Prowler OCSF."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            start = fh.read(2000)
        # ASFF / Security Hub markers
        if ('"ProductArn"' in start or '"AwsSecurityFinding"' in start
                or '"SchemaVersion"' in start and '"Compliance"' in start):
            return "security_hub"
        if '"Findings"' in start and '"AwsAccountId"' in start:
            return "security_hub"
    except Exception:
        pass
    return "prowler"


# ---------------------------------------------------------------------------
# Normalized finding schema
# ---------------------------------------------------------------------------
# Every parser below emits dicts with these normalized (UPPERCASE) keys so that
# analysis is provider- and format-agnostic:
#   PROVIDER, STATUS, SEVERITY, CHECK_ID, CHECK_TITLE, SERVICE_NAME,
#   RESOURCE_UID, RISK, REMEDIATION_RECOMMENDATION_TEXT, REMEDIATION_CODE_CLI,
#   REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_NATIVEIAC, COMPLIANCE,
#   CATEGORIES, SCOPE_ID

NORMALIZED_KEYS = [
    "PROVIDER", "STATUS", "SEVERITY", "CHECK_ID", "CHECK_TITLE", "SERVICE_NAME",
    "RESOURCE_UID", "RISK", "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_CODE_CLI", "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_NATIVEIAC", "COMPLIANCE", "CATEGORIES", "SCOPE_ID",
]


def _blank_finding() -> dict:
    return {k: "" for k in NORMALIZED_KEYS}


# ---------------------------------------------------------------------------
# CSV parsing (Prowler, semicolon-delimited)
# ---------------------------------------------------------------------------

def parse_prowler_main_csv(filepath: str) -> list:
    """Parse a Prowler main CSV (semicolon-delimited) into normalized findings."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter=";")
            for row in reader:
                norm = {k.strip().upper(): (v.strip() if v else "")
                        for k, v in row.items() if k}
                f = _blank_finding()
                for k in NORMALIZED_KEYS:
                    if k in norm:
                        f[k] = norm[k]
                # Provider column may be named PROVIDER or CLOUD_PROVIDER.
                f["PROVIDER"] = normalize_provider(
                    norm.get("PROVIDER") or norm.get("CLOUD_PROVIDER") or "")
                # Scope id can come from ACCOUNT_UID/SUBSCRIPTION/PROJECT/TENANCY columns.
                f["SCOPE_ID"] = (norm.get("ACCOUNT_UID") or norm.get("ACCOUNT_ID")
                                 or norm.get("SUBSCRIPTION_ID") or norm.get("PROJECT_ID")
                                 or norm.get("TENANCY_ID") or norm.get("SCOPE_ID") or "")
                findings.append(f)
    except Exception as e:
        print(f"  [WARN] Failed to parse {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse {filepath}: {e}")
    return findings


def parse_prowler_compliance_csv(filepath: str) -> list:
    """Parse a Prowler compliance CSV (semicolon-delimited)."""
    records = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter=";")
            for row in reader:
                normalized = {k.strip().upper(): v.strip() if v else ""
                              for k, v in row.items() if k}
                records.append(normalized)
    except Exception as e:
        print(f"  [WARN] Failed to parse compliance CSV {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse compliance CSV {filepath}: {e}")
    return records


# ---------------------------------------------------------------------------
# OCSF JSON parsing (Prowler native JSON output)
# ---------------------------------------------------------------------------

def parse_ocsf_json(filepath: str) -> list:
    """Parse a Prowler OCSF JSON file into normalized findings.

    OCSF findings carry provider under cloud.provider and severity as a string.
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"  [WARN] Failed to parse OCSF JSON {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse OCSF JSON {filepath}: {e}")
        return findings

    if isinstance(data, dict):
        data = data.get("findings") or data.get("Findings") or [data]

    for item in data:
        if not isinstance(item, dict):
            continue
        f = _blank_finding()
        cloud = item.get("cloud", {}) if isinstance(item.get("cloud"), dict) else {}
        f["PROVIDER"] = normalize_provider(cloud.get("provider", ""))

        account = cloud.get("account", {}) if isinstance(cloud.get("account"), dict) else {}
        f["SCOPE_ID"] = str(account.get("uid", "") or account.get("name", ""))

        # status_code: PASS / FAIL
        f["STATUS"] = str(item.get("status_code", item.get("status", ""))).upper()

        # severity string
        f["SEVERITY"] = str(item.get("severity", "")).capitalize()

        finding_info = item.get("finding_info", {}) if isinstance(item.get("finding_info"), dict) else {}
        f["CHECK_ID"] = str(item.get("check_id")
                            or finding_info.get("uid", "")
                            or item.get("metadata", {}).get("event_code", ""))
        f["CHECK_TITLE"] = str(finding_info.get("title", "") or item.get("message", ""))

        # resource
        resources = item.get("resources", [])
        if resources and isinstance(resources, list) and isinstance(resources[0], dict):
            res = resources[0]
            f["SERVICE_NAME"] = str(res.get("group", {}).get("name", "")
                                    if isinstance(res.get("group"), dict)
                                    else res.get("type", ""))
            f["RESOURCE_UID"] = str(res.get("uid", ""))

        # remediation
        remediation = item.get("remediation", {}) if isinstance(item.get("remediation"), dict) else {}
        f["REMEDIATION_RECOMMENDATION_TEXT"] = str(remediation.get("desc", ""))
        refs = remediation.get("references", [])
        if isinstance(refs, list):
            for ref in refs:
                ref_s = str(ref)
                if "terraform" in ref_s.lower():
                    f["REMEDIATION_CODE_TERRAFORM"] = ref_s
                elif ref_s.lower().startswith(("aws ", "az ", "gcloud ", "oci ")):
                    f["REMEDIATION_CODE_CLI"] = ref_s

        f["RISK"] = str(item.get("risk_details", "") or finding_info.get("desc", ""))

        # unmapped structures -> unmapped
        unmapped = item.get("unmapped", {}) if isinstance(item.get("unmapped"), dict) else {}
        if not f["SERVICE_NAME"]:
            f["SERVICE_NAME"] = str(unmapped.get("service_name", "") or "Unknown")

        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Security Hub / ASFF JSON parsing
# ---------------------------------------------------------------------------

def parse_security_hub_json(filepath: str) -> list:
    """Parse a Security Hub / ASFF JSON export into normalized findings.

    ASFF findings are always AWS. Structure: {"Findings": [ {...ASFF...} ]} or a
    bare list of ASFF finding objects.
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"  [WARN] Failed to parse Security Hub JSON {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse Security Hub JSON {filepath}: {e}")
        return findings

    if isinstance(data, dict):
        data = data.get("Findings") or data.get("findings") or [data]

    for item in data:
        if not isinstance(item, dict):
            continue
        f = _blank_finding()
        f["PROVIDER"] = "aws"  # ASFF is an AWS format
        f["SCOPE_ID"] = str(item.get("AwsAccountId", ""))

        # Compliance.Status -> PASSED / FAILED
        compliance = item.get("Compliance", {}) if isinstance(item.get("Compliance"), dict) else {}
        raw_status = str(compliance.get("Status", "")).upper()
        f["STATUS"] = "PASS" if raw_status in ("PASSED", "PASS") else (
            "FAIL" if raw_status in ("FAILED", "FAIL", "WARNING") else raw_status)

        sev = item.get("Severity", {}) if isinstance(item.get("Severity"), dict) else {}
        f["SEVERITY"] = str(sev.get("Label", "")).capitalize()

        f["CHECK_ID"] = str(item.get("GeneratorId", "") or item.get("Id", ""))
        f["CHECK_TITLE"] = str(item.get("Title", ""))
        f["RISK"] = str(item.get("Description", ""))

        remediation = item.get("Remediation", {}) if isinstance(item.get("Remediation"), dict) else {}
        rec = remediation.get("Recommendation", {}) if isinstance(remediation.get("Recommendation"), dict) else {}
        f["REMEDIATION_RECOMMENDATION_TEXT"] = str(rec.get("Text", ""))

        # Resource + service
        resources = item.get("Resources", [])
        if resources and isinstance(resources, list) and isinstance(resources[0], dict):
            res = resources[0]
            f["RESOURCE_UID"] = str(res.get("Id", ""))
            res_type = str(res.get("Type", ""))
            # AwsS3Bucket -> S3
            svc = res_type.replace("Aws", "").split("::")[0] if res_type else ""
            f["SERVICE_NAME"] = svc or "Unknown"

        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# HTML parsing (Prowler HTML report)
# ---------------------------------------------------------------------------

class _ProwlerHTMLTableParser(HTMLParser):
    """Minimal parser that extracts rows from the findings table in a Prowler
    HTML report. Falls back gracefully if the structure is unfamiliar."""

    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_row = False
        self.in_cell = False
        self.current_row = []
        self.current_cell = []
        self.rows = []
        self.headers = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.in_table = True
        elif tag == "tr" and self.in_table:
            self.in_row = True
            self.current_row = []
        elif tag in ("td", "th") and self.in_row:
            self.in_cell = True
            self.current_cell = []

    def handle_endtag(self, tag):
        if tag == "table":
            self.in_table = False
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if self.current_row:
                self.rows.append(self.current_row)
        elif tag in ("td", "th") and self.in_cell:
            self.in_cell = False
            self.current_row.append(" ".join(self.current_cell).strip())

    def handle_data(self, data):
        if self.in_cell:
            text = data.strip()
            if text:
                self.current_cell.append(text)


def parse_prowler_html(filepath: str) -> list:
    """Parse a Prowler HTML report into normalized findings (best-effort).

    HTML reports vary; this maps recognizable column headers to the normalized
    schema. Provider is inferred from column content or defaults to unknown.
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            html = fh.read()
    except Exception as e:
        print(f"  [WARN] Failed to read HTML {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to read HTML {filepath}: {e}")
        return findings

    parser = _ProwlerHTMLTableParser()
    try:
        parser.feed(html)
    except Exception as e:
        print(f"  [WARN] Failed to parse HTML {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse HTML {filepath}: {e}")
        return findings

    rows = parser.rows
    if not rows:
        return findings

    # First row is assumed to be the header.
    header = [h.strip().upper().replace(" ", "_") for h in rows[0]]

    def col(row, *names):
        for n in names:
            if n in header:
                idx = header.index(n)
                if idx < len(row):
                    return row[idx]
        return ""

    for row in rows[1:]:
        if len(row) < 2:
            continue
        f = _blank_finding()
        f["PROVIDER"] = normalize_provider(col(row, "PROVIDER", "CLOUD"))
        f["STATUS"] = col(row, "STATUS", "RESULT").upper()
        f["SEVERITY"] = col(row, "SEVERITY").capitalize()
        f["CHECK_ID"] = col(row, "CHECK_ID", "CHECKID")
        f["CHECK_TITLE"] = col(row, "CHECK_TITLE", "TITLE", "CHECK")
        f["SERVICE_NAME"] = col(row, "SERVICE_NAME", "SERVICE") or "Unknown"
        f["RESOURCE_UID"] = col(row, "RESOURCE_UID", "RESOURCE_ID", "RESOURCE")
        f["RISK"] = col(row, "RISK")
        f["REMEDIATION_RECOMMENDATION_TEXT"] = col(row, "REMEDIATION",
                                                    "REMEDIATION_RECOMMENDATION_TEXT")
        f["SCOPE_ID"] = col(row, "ACCOUNT_ID", "ACCOUNT_UID", "SUBSCRIPTION",
                            "PROJECT_ID", "TENANCY")
        if f["STATUS"] or f["CHECK_ID"]:
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_findings(all_findings: list) -> dict:
    """Compute aggregate statistics from normalized findings, provider-aware."""
    total = len(all_findings)
    pass_count = sum(1 for f in all_findings if f.get("STATUS", "").upper().startswith("PASS"))
    fail_count = sum(1 for f in all_findings if f.get("STATUS", "").upper().startswith("FAIL"))

    # Score = PASS / (PASS + FAIL). Excludes non-actionable statuses (MANUAL/INFO/MUTED)
    # from the denominator so they don't artificially deflate the score. total_checks
    # (reported separately) still reflects every check that ran.
    scored = pass_count + fail_count
    security_score = round((pass_count / scored) * 100, 1) if scored > 0 else 0.0

    failed = [f for f in all_findings if f.get("STATUS", "").upper().startswith("FAIL")]

    # Providers present
    provider_keys = sorted({f.get("PROVIDER", "unknown") or "unknown" for f in all_findings})

    severity_counter = Counter(f.get("SEVERITY", "unknown").capitalize() for f in failed)
    findings_by_severity = {
        "critical": severity_counter.get("Critical", 0),
        "high": severity_counter.get("High", 0),
        "medium": severity_counter.get("Medium", 0),
        "low": severity_counter.get("Low", 0),
        "other": sum(v for k, v in severity_counter.items()
                     if k not in ("Critical", "High", "Medium", "Low")),
    }

    service_counter = Counter(f.get("SERVICE_NAME", "Unknown") or "Unknown" for f in failed)
    findings_by_service = dict(service_counter.most_common(20))

    # Per-provider breakdown
    findings_by_provider = {}
    for pkey in provider_keys:
        p_all = [f for f in all_findings if (f.get("PROVIDER") or "unknown") == pkey]
        p_failed = [f for f in p_all if f.get("STATUS", "").upper().startswith("FAIL")]
        p_pass = sum(1 for f in p_all if f.get("STATUS", "").upper().startswith("PASS"))
        p_sev = Counter(f.get("SEVERITY", "unknown").capitalize() for f in p_failed)
        p_svc = Counter(f.get("SERVICE_NAME", "Unknown") or "Unknown" for f in p_failed)
        p_scopes = sorted({f.get("SCOPE_ID", "") for f in p_all if f.get("SCOPE_ID")})
        findings_by_provider[pkey] = {
            "label": PROVIDER_LABELS.get(pkey, pkey.upper()),
            "scope_term": PROVIDER_SCOPE_TERM.get(pkey, "scope"),
            "total_checks": len(p_all),
            "pass_count": p_pass,
            "fail_count": len(p_failed),
            "security_score": round((p_pass / (p_pass + len(p_failed))) * 100, 1) if (p_pass + len(p_failed)) > 0 else 0.0,
            "findings_by_severity": {
                "critical": p_sev.get("Critical", 0),
                "high": p_sev.get("High", 0),
                "medium": p_sev.get("Medium", 0),
                "low": p_sev.get("Low", 0),
                "other": sum(v for k, v in p_sev.items()
                             if k not in ("Critical", "High", "Medium", "Low")),
            },
            "findings_by_service": dict(p_svc.most_common(10)),
            "scopes": p_scopes,
        }

    # Top failed checks
    check_counter = Counter()
    check_details = {}
    for f in failed:
        check_id = f.get("CHECK_ID", "unknown")
        check_counter[check_id] += 1
        if check_id not in check_details:
            check_details[check_id] = {
                "check_id": check_id,
                "check_title": f.get("CHECK_TITLE", ""),
                "severity": f.get("SEVERITY", "").capitalize(),
                "service": f.get("SERVICE_NAME", ""),
                "provider": f.get("PROVIDER", "unknown"),
                "risk": f.get("RISK", ""),
                "remediation_text": f.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
                "remediation_cli": f.get("REMEDIATION_CODE_CLI", ""),
                "remediation_terraform": f.get("REMEDIATION_CODE_TERRAFORM", ""),
                "remediation_nativeiac": f.get("REMEDIATION_CODE_NATIVEIAC", ""),
            }

    top_failed_checks = []
    for check_id, count in check_counter.most_common(25):
        entry = dict(check_details[check_id])
        entry["count"] = count
        top_failed_checks.append(entry)

    # Detailed findings (deduplicated by check_id + resource)
    detailed_findings = []
    seen = set()
    for f in failed:
        resource_uid = f.get("RESOURCE_UID", "")
        check_id = f.get("CHECK_ID", "")
        # Only deduplicate when RESOURCE_UID is non-empty. When it's blank (common
        # for OCSF/HTML/Security Hub findings), each finding row is unique and
        # collapsing them would under-report the number of affected resources.
        if resource_uid:
            key = (check_id, resource_uid)
            if key in seen:
                continue
            seen.add(key)
        detailed_findings.append({
            "provider": f.get("PROVIDER", "unknown"),
            "check_id": f.get("CHECK_ID", ""),
            "check_title": f.get("CHECK_TITLE", ""),
            "status": f.get("STATUS", ""),
            "severity": f.get("SEVERITY", "").capitalize(),
            "service": f.get("SERVICE_NAME", ""),
            "resource_id": f.get("RESOURCE_UID", ""),
            "scope_id": f.get("SCOPE_ID", ""),
            "risk": f.get("RISK", ""),
            "remediation_text": f.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
            "remediation_cli": f.get("REMEDIATION_CODE_CLI", ""),
            "remediation_terraform": f.get("REMEDIATION_CODE_TERRAFORM", ""),
            "remediation_nativeiac": f.get("REMEDIATION_CODE_NATIVEIAC", ""),
            "compliance": f.get("COMPLIANCE", ""),
            "categories": f.get("CATEGORIES", ""),
        })

    return {
        "total_checks": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "security_score": security_score,
        "providers": provider_keys,
        "findings_by_severity": findings_by_severity,
        "findings_by_service": findings_by_service,
        "findings_by_provider": findings_by_provider,
        "top_failed_checks": top_failed_checks,
        "detailed_findings": detailed_findings[:500],
        "detailed_findings_truncated": len(detailed_findings) > 500,
        "detailed_findings_total": len(detailed_findings),
    }


def analyze_compliance(compliance_records: list) -> dict:
    """Analyze compliance CSV records to produce per-framework coverage."""
    frameworks = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    for rec in compliance_records:
        fw = rec.get("FRAMEWORK", "Unknown")
        frameworks[fw]["total"] += 1
        status = rec.get("STATUS", "").upper()
        if status.startswith("PASS"):
            frameworks[fw]["pass"] += 1
        elif status.startswith("FAIL"):
            frameworks[fw]["fail"] += 1

    result = {}
    for fw, counts in frameworks.items():
        total = counts["total"]
        pass_rate = round((counts["pass"] / total) * 100, 1) if total > 0 else 0.0
        result[fw] = {
            "total": total,
            "pass": counts["pass"],
            "fail": counts["fail"],
            "pass_rate": pass_rate,
        }
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Anonymization (optional)
# ---------------------------------------------------------------------------

def build_scope_mask(scope_ids: list) -> dict:
    """Build a stable {real_id -> generic_label} map for the given scope ids.

    Labels are assigned deterministically (sorted order): Scope A, Scope B, ...
    so the same input always yields the same mapping.
    """
    mapping = {}
    for i, sid in enumerate(sorted(s for s in scope_ids if s)):
        # A, B, ... Z, AA, AB, ...
        label = ""
        n = i
        while True:
            label = chr(ord("A") + (n % 26)) + label
            n = n // 26 - 1
            if n < 0:
                break
        mapping[str(sid)] = f"Scope {label}"
    return mapping


def _mask_str(value: str, mapping: dict) -> str:
    """Replace every real identifier occurrence inside a string (covers ids
    embedded in ARNs / resource URIs / free text).

    Hardening against partial/overlapping masks:
      * Process identifiers LONGEST-FIRST so that if one id is a substring of
        another (e.g. "12345" vs "12345678"), the longer one is masked first and
        the shorter one can't corrupt it.
      * Use a boundary-aware regex so an id is only replaced when it is NOT part
        of a larger alphanumeric token. Boundaries treat non-[A-Za-z0-9] as
        separators, so ids embedded in ARNs/URIs/paths (delimited by :/.-_ etc.)
        are still masked, but an id that is merely a digit-substring of a longer
        number/token is left intact.
    """
    out = str(value)
    # Longest id first; skip empties.
    for real in sorted((r for r in mapping if r), key=len, reverse=True):
        label = mapping[real]
        if real in out:
            # (?<![A-Za-z0-9]) real (?![A-Za-z0-9]) — surrounded by non-alphanumerics
            # (or string edges), so it won't match inside a larger token.
            out = re.sub(r"(?<![A-Za-z0-9])" + re.escape(real) + r"(?![A-Za-z0-9])",
                         label, out)
    return out


def apply_anonymization(obj, mapping: dict):
    """Recursively mask every real identifier in a nested dict/list/str structure.
    Also masks dict KEYS (e.g. per-scope tables keyed by real id)."""
    if not mapping:
        return obj
    if isinstance(obj, dict):
        return {
            _mask_str(k, mapping) if isinstance(k, str) else k: apply_anonymization(v, mapping)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [apply_anonymization(v, mapping) for v in obj]
    if isinstance(obj, str):
        return _mask_str(obj, mapping)
    return obj


def verify_anonymization(obj, mapping: dict) -> list:
    """Return a list of real identifiers still present anywhere in obj (should be empty)."""
    blob = json.dumps(obj, default=str)
    return [real for real in mapping if real and real in blob]


def peek_provider(files: dict) -> str:
    """Cheaply determine the cloud provider BEFORE full analysis, so the default
    output folder can be named per provider. Reads only the header/first record of
    the first available main CSV or OCSF JSON. Returns a normalized provider key
    (aws/azure/gcp/oci/...) or "" if it cannot be determined.

    NOTE: Each run is expected to cover a single provider. If a folder happens to
    mix providers, this returns the first detected — run the tool once per provider.
    """
    # Try main CSV first (PROVIDER column).
    for csv_path in files.get("prowler_main_csv", []):
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as fh:
                header = fh.readline().strip().split(";")
                first = fh.readline().strip().split(";")
            cols = [h.strip().upper() for h in header]
            if "PROVIDER" in cols:
                val = first[cols.index("PROVIDER")] if len(first) > cols.index("PROVIDER") else ""
                p = normalize_provider(val)
                if p != "unknown":
                    return p
        except Exception:
            pass
    # Fall back to OCSF JSON (cloud.provider).
    for json_path in files.get("prowler_json", []):
        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                start = fh.read(4000)
            m = re.search(r'"provider"\s*:\s*"([^"]+)"', start)
            if m:
                p = normalize_provider(m.group(1))
                if p != "unknown":
                    return p
        except Exception:
            pass
    # Security Hub / ASFF is AWS.
    if files.get("security_hub_json"):
        return "aws"
    return ""


def resolve_default_output_dir(input_folder: str, user_output_dir: str = None,
                               provider: str = "") -> str:
    """Resolve the deliverables output directory.

    - If the user provides an explicit output dir, use it (abspath).
    - Otherwise use the SMART DEFAULT: '<base>/assessment-summary-<provider>', where
      <base> is the PARENT of the input folder when the input folder is named 'output'
      (e.g. .../aws/output -> .../aws/assessment-summary-aws), and the INPUT FOLDER
      ITSELF otherwise (e.g. .../aws -> .../aws/assessment-summary-aws). The
      '-<provider>' suffix keeps per-provider runs in separate folders; if the
      provider is unknown, the bare 'assessment-summary' name is used.
    """
    if user_output_dir:
        return os.path.abspath(user_output_dir)
    input_folder = os.path.abspath(input_folder)
    if os.path.basename(input_folder).lower() == "output":
        base = os.path.dirname(input_folder)
    else:
        base = input_folder
    name = f"assessment-summary-{provider}" if provider else "assessment-summary"
    return os.path.join(base, name)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze multi-cloud Prowler security assessment outputs")
    parser.add_argument("input_folder", help="Path to folder containing security assessment files")
    parser.add_argument("output_json", nargs="?", default=None,
                        help="Path to write analysis JSON output. If omitted, a default "
                             "'assessment-summary/analysis.json' folder is created (see --output-dir).")
    parser.add_argument("--output-dir", default=None,
                        help="Directory for all deliverables. If omitted, defaults to "
                             "'<default>/assessment-summary' where <default> is the parent of the "
                             "input folder when the input folder is named 'output', otherwise the "
                             "input folder itself.")
    parser.add_argument("--customer", default="", help="Customer/organization name")
    parser.add_argument("--anonymize", action="store_true",
                        help="Replace real account/subscription/project/tenancy identifiers "
                             "with generic labels (Scope A, Scope B, ...) across all output.")
    args = parser.parse_args()

    input_folder = os.path.abspath(args.input_folder)

    if not os.path.isdir(input_folder):
        print(f"ERROR: Input folder does not exist: {input_folder}", file=sys.stderr)
        sys.exit(1)

    # Peek the provider (cheap) so the default output folder can be named per provider.
    _peek_files = identify_files(input_folder)
    _provider = peek_provider(_peek_files)

    # Resolve the output directory (user choice, else smart per-provider default).
    output_dir = resolve_default_output_dir(input_folder, args.output_dir, _provider)
    # If an explicit analysis.json path was given, honor it; otherwise place it in output_dir.
    if args.output_json:
        output_json = os.path.abspath(args.output_json)
    else:
        output_json = os.path.join(output_dir, "analysis.json")

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    print(f"       Detected provider (for default folder): {_provider or 'unknown'}")
    print(f"       Output directory: {output_dir}")

    print(f"[1/4] Scanning files in: {input_folder}")
    files = identify_files(input_folder)
    scope_ids = detect_scope_ids(input_folder)

    file_count = sum(len(v) for v in files.values())
    print(f"       Found {file_count} files, {len(scope_ids)} scope id(s): {scope_ids}")
    print(f"       Main CSVs: {len(files['prowler_main_csv'])}")
    print(f"       Compliance CSVs: {len(files['prowler_compliance_csv'])}")
    print(f"       OCSF JSON: {len(files['prowler_json'])}")
    print(f"       Security Hub / ASFF JSON: {len(files['security_hub_json'])}")
    print(f"       HTML reports: {len(files['prowler_html'])}")

    has_input = (files["prowler_main_csv"] or files["prowler_json"]
                 or files["security_hub_json"] or files["prowler_html"])
    if not has_input:
        print("ERROR: No supported security assessment files found "
              "(CSV / OCSF JSON / Security Hub JSON / HTML).", file=sys.stderr)
        sys.exit(1)

    # Parse findings from the SINGLE richest available source (in priority order):
    # CSV -> OCSF JSON -> Security Hub JSON -> HTML. Prowler emits the SAME findings
    # in multiple formats simultaneously, so parsing more than one source would
    # double-count. We therefore pick ONE source and stop.
    # Group scan files by scan identity, then parse ONE format per scan. Prowler writes
    # every format of a single scan under the SAME filename stem
    # (prowler-output-<id>-<ts>.csv / .ocsf.json / .html), so the stem identifies a scan.
    # Within each scan we pick a single richest source (CSV > OCSF JSON > Security Hub > HTML)
    # to avoid double-counting the same findings across formats. Because we process EVERY
    # scan group, distinct scans — including different providers in one folder (e.g. an AWS
    # CSV alongside a GCP OCSF JSON) — are all retained.
    print("[2/4] Parsing findings (one source per scan group; distinct scans all kept)...")

    def _scan_stem(path):
        b = os.path.basename(path)
        for ext in (".ocsf.json", ".csv", ".html", ".json"):
            if b.lower().endswith(ext):
                return b[: -len(ext)]
        return os.path.splitext(b)[0]

    # Build scan groups: stem -> {format: [paths]}
    groups = {}
    for fmt, paths in (("csv", files["prowler_main_csv"]), ("ocsf", files["prowler_json"]),
                       ("securityhub", files["security_hub_json"]), ("html", files["prowler_html"])):
        for p in paths:
            groups.setdefault(_scan_stem(p), {}).setdefault(fmt, []).append(p)

    all_findings = []
    _parsers = {"csv": parse_prowler_main_csv, "ocsf": parse_ocsf_json,
                "securityhub": parse_security_hub_json, "html": parse_prowler_html}
    _labels = {"csv": "CSV", "ocsf": "OCSF JSON", "securityhub": "Security Hub JSON", "html": "HTML"}
    for stem in sorted(groups):
        fmts = groups[stem]
        # richest source priority
        chosen_fmt = next((f for f in ("csv", "ocsf", "securityhub", "html") if f in fmts), None)
        if not chosen_fmt:
            continue
        others = [f for f in fmts if f != chosen_fmt]
        note = f" (ignored duplicate formats: {', '.join(_labels[o] for o in others)})" if others else ""
        for path in fmts[chosen_fmt]:
            recs = _parsers[chosen_fmt](path)
            all_findings.extend(recs)
            print(f"       [{_labels[chosen_fmt]}] {os.path.basename(path)} -> {len(recs)} records{note}")

    provs = sorted({(f.get("PROVIDER") or "unknown").lower() for f in all_findings})
    print(f"       {len(all_findings)} findings across {len(groups)} scan group(s); provider(s): {', '.join(provs) or 'none'}")

    print("[3/4] Parsing compliance CSVs...")
    all_compliance = []
    for csv_path in files["prowler_compliance_csv"]:
        print(f"       Parsing: {os.path.basename(csv_path)}")
        records = parse_prowler_compliance_csv(csv_path)
        all_compliance.extend(records)
        print(f"         -> {len(records)} records")

    print("[4/4] Analyzing findings...")
    analysis = analyze_findings(all_findings)
    compliance_coverage = analyze_compliance(all_compliance)

    providers = analysis["providers"]
    provider_labels = [PROVIDER_LABELS.get(p, p.upper()) for p in providers]
    scope_term = scope_term_for_providers(providers)

    # Prefer scope ids discovered inside the findings; fall back to filename detection.
    scope_ids_in_data = sorted({
        s for prov in analysis["findings_by_provider"].values() for s in prov["scopes"]
    })
    effective_scopes = scope_ids_in_data or scope_ids

    customer = args.customer or "Customer"
    output = {
        "metadata": {
            "customer": customer,
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "providers": providers,
            "provider_labels": provider_labels,
            "scope_term": scope_term,
            "scopes_assessed": effective_scopes,
            "input_folder": input_folder,
            "files_processed": {k: len(v) for k, v in files.items()},
        },
        "summary": {
            "total_checks": analysis["total_checks"],
            "pass_count": analysis["pass_count"],
            "fail_count": analysis["fail_count"],
            "security_score": analysis["security_score"],
            "findings_by_severity": analysis["findings_by_severity"],
            "findings_by_service": analysis["findings_by_service"],
            "findings_by_provider": analysis["findings_by_provider"],
        },
        "top_failed_checks": analysis["top_failed_checks"],
        "compliance_coverage": compliance_coverage,
        "detailed_findings": analysis["detailed_findings"],
    }

    # Optional anonymization: mask every scope identifier across the ENTIRE output
    # (metadata, per-scope tables, resource ids, and ids embedded in ARNs/URIs/text).
    if args.anonymize:
        mask = build_scope_mask(effective_scopes)
        output = apply_anonymization(output, mask)
        output["metadata"]["anonymized"] = True
        # Redact the input_folder path — it can leak operator identity or customer
        # names via directory paths (e.g. /Users/jdoe/clients/AcmeCorp/output).
        output["metadata"]["input_folder"] = "<redacted>"
        # Store ONLY the generic labels in the shipped analysis.json — never the real
        # identifiers. (A previous version stored {label: real_id} here, which leaked the
        # real account/subscription/project/tenancy IDs into the customer-facing file.)
        # The real->label mapping is written ONLY to the operator-side anon_map.json sidecar.
        output["metadata"]["scope_labels"] = sorted(mask.values())
        # Write the reverse mapping to a SEPARATE operator sidecar (NOT shipped to the
        # customer) next to the output, for the operator's own de-anonymization/verification.
        sidecar = os.path.join(os.path.dirname(output_json), "anon_map.json")
        # Write the real->label mapping with owner-only (0o600) permissions — on shared
        # systems this prevents other users from reading the exact de-anonymization map.
        _fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as mf:
            json.dump({"real_to_label": mask}, mf, indent=2)
        # Verify the shipped output (analysis.json content) contains NO real identifiers.
        leaks = verify_anonymization(output, mask)
        if leaks:
            print(f"   WARNING: anonymization incomplete, {len(leaks)} identifier(s) still present: {leaks}",
                  file=sys.stderr)
        else:
            print(f"   Anonymization applied and verified: {len(mask)} scope id(s) masked, 0 leaks.")

    # Surface any parse warnings collected during this run into the output metadata,
    # so incomplete results are visible to downstream consumers (not just on stderr).
    if _PARSE_WARNINGS:
        output["metadata"]["parse_warnings"] = list(_PARSE_WARNINGS)

    with open(output_json, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, default=str)

    print(f"\nAnalysis complete -> {output_json}")
    print(f"   Providers: {', '.join(provider_labels) if provider_labels else 'Unknown'}")
    print(f"   Security Score: {analysis['security_score']}%")
    print(f"   Total Checks: {analysis['total_checks']}")
    print(f"   Failed: {analysis['fail_count']} (Critical: {analysis['findings_by_severity']['critical']}, "
          f"High: {analysis['findings_by_severity']['high']}, "
          f"Medium: {analysis['findings_by_severity']['medium']}, "
          f"Low: {analysis['findings_by_severity']['low']})")
    if compliance_coverage:
        print(f"   Compliance Frameworks: {', '.join(compliance_coverage.keys())}")


if __name__ == "__main__":
    main()
