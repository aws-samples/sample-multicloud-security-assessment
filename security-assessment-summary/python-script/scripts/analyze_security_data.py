#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

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
import stat
import sys
from collections import Counter, defaultdict
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from providers import PROVIDER_LABELS, PROVIDER_SCOPE_TERM
import safe_io

# ---------------------------------------------------------------------------
# Parser resource limits
# ---------------------------------------------------------------------------
# Prowler REMEDIATION_CODE_* / RISK / DESCRIPTION fields can exceed Python's default
# CSV field limit (131,072 chars). We raise the limit so a legitimately large field
# doesn't drop a file's findings — but to a BOUNDED value, not sys.maxsize, so a
# hostile input can't drive unbounded memory use (DoS). The caps below also bound the
# per-file size we are willing to read.
MAX_FIELD_BYTES = 16 * 1024 * 1024          # 16 MiB per CSV field (generous for Prowler)
MAX_FILE_BYTES = 512 * 1024 * 1024          # 512 MiB per CSV/HTML input file
MAX_JSON_FILE_BYTES = 256 * 1024 * 1024     # 256 MiB per JSON file (fully loaded into memory)
MAX_HTML_FILE_BYTES = 32 * 1024 * 1024      # 32 MiB per HTML file (fully loaded into memory)
MAX_CSV_HEADER_BYTES = 64 * 1024             # 64 KiB cap before CSV classification

# Aggregate (whole-job) limits — bound total work so a hostile input tree can't exhaust
# memory/time even when every individual file is under the per-file caps above.
MAX_TOTAL_FILES = 10_000                     # max files discovered/categorized in one run
MAX_TOTAL_INPUT_PATHS = 50_000               # max files + directories visited in one run
MAX_RECURSION_DEPTH = 32                     # max directory depth below the input root
MAX_TOTAL_RECORDS = 5_000_000               # max normalized findings aggregated per run
# Per-file cap matches the aggregate cap: org-wide Prowler exports routinely hold several
# hundred thousand rows, and silently analyzing a fraction would skew every score.
MAX_RECORDS_PER_FILE = MAX_TOTAL_RECORDS

try:
    csv.field_size_limit(MAX_FIELD_BYTES)
except OverflowError:
    # Some 32-bit / Windows builds reject large values; fall back to the C-long max.
    csv.field_size_limit(min(MAX_FIELD_BYTES, 2**31 - 1))


def _file_too_large(filepath, limit_bytes: int) -> bool:
    """Return True (and log) if filepath exceeds limit_bytes. Fail safe: on stat error,
    treat as not-too-large so a transient error doesn't silently drop a file."""
    try:
        size = os.path.getsize(filepath)
    except OSError:
        return False
    if size > limit_bytes:
        print(f"  [WARN] Skipping {filepath}: {size} bytes exceeds limit "
              f"({limit_bytes} bytes).", file=sys.stderr)
        # A deliberate limit, not a parse failure: record it as a partial-results notice
        # (non-fatal) rather than a parse warning (which aborts the run).
        _LIMIT_NOTICES.append("oversized input file skipped")
        return True
    return False


# Collects errors from selected inputs so main() can reject incomplete analyses.
_PARSE_WARNINGS = []

# Collects deliberate safety-limit hits (oversized file skipped, file/record caps reached).
# These are NOT parse failures: the run continues, prints a PARTIAL RESULTS warning, and
# records a path-free summary in metadata.input_limits_applied so deliverables show it.
_LIMIT_NOTICES = []


def _open_input_file(filepath, binary: bool = False):
    """Open an ordinary input file without following a final symlink.

    The descriptor is validated after open so a CSV discovered as a regular file
    cannot be swapped to a FIFO, device, or final-component symlink before parsing.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(filepath, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"refusing non-regular input file: {filepath}")
        mode = "rb" if binary else "r"
        kwargs = {} if binary else {"encoding": "utf-8", "errors": "replace"}
        return os.fdopen(fd, mode, **kwargs)
    except Exception:
        os.close(fd)
        raise


def _record_limit_reached(records: list, filepath: str, kind: str) -> bool:
    """Return True after recording one non-fatal partial-results limit notice."""
    if len(records) < MAX_RECORDS_PER_FILE:
        return False
    print(f"  [WARN] Reached {MAX_RECORDS_PER_FILE}-record limit for {filepath}; "
          "remaining records are ignored.", file=sys.stderr)
    _LIMIT_NOTICES.append(f"{kind} exceeded {MAX_RECORDS_PER_FILE}-record per-file limit")
    return True


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


def _is_within(path: Path, parent: Path) -> bool:
    """Return whether *path* is contained by *parent* after resolving both."""
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _has_tool_artifacts(folder: Path) -> bool:
    """True if ``folder`` holds an artifact only this tool writes. analysis.json alone is
    not enough: a run may write it elsewhere (custom output_json) while the dashboard and
    Terraform still land in the folder. Generic names (e.g. ``*_README.md``) are NOT a
    signature: a customer folder holding one would be silently dropped as output."""
    try:
        if (folder / "analysis.json").is_file():
            return True
        if (folder / "iac" / ".cloud-sec-assessment-manifest.json").is_file():
            return True
        return any((folder / "reports").glob("*_Security_Dashboard.html"))
    except OSError:
        return False


def _is_generated_output_file(filepath: Path, input_root: Path) -> bool:
    """True for files inside an assessment-summary* folder THIS TOOL created — one that
    holds its artifacts (see :func:`_has_tool_artifacts`). A customer folder that merely
    shares the name (e.g. ``assessment-summary-q3/`` with real scan files) is still read
    as input."""
    try:
        root = input_root.resolve()
        relative_parts = filepath.resolve().relative_to(root).parts[:-1]
    except (OSError, ValueError):
        return False
    current = root
    for part in relative_parts:
        current = current / part
        if ((part == "assessment-summary" or part.startswith("assessment-summary-"))
                and _has_tool_artifacts(current)):
            return True
    return False


def _should_skip_file(filepath: Path, excluded_roots: list, input_root: Path,
                      exclude_generated_outputs: bool,
                      excluded_files: list = None) -> bool:
    # These are this tool's own JSON artifacts, including when an earlier run
    # placed them outside the current deliverables directory.
    if filepath.name in {"analysis.json", "anon_map.json"} or (
            filepath.name.startswith("anon_map_") and filepath.name.endswith(".json")):
        return True
    if any(filepath.resolve() == excluded.resolve()
           for excluded in (excluded_files or [])):
        return True
    if any(_is_within(filepath, root) for root in excluded_roots):
        return True
    return exclude_generated_outputs and _is_generated_output_file(filepath, input_root)


def detect_scope_ids(folder_path: str, excluded_roots: list = None,
                     files: dict = None) -> list:
    """Extract likely cloud scope IDs (accounts/subscriptions/projects/tenancies)
    from filenames already accepted by the bounded input discovery. Provider-neutral:
    matches 12-digit AWS account IDs, GUIDs (Azure subscriptions), and generic
    project/tenancy identifiers in filenames."""
    scope_ids = set()
    # 12-digit numeric IDs (AWS accounts, some GCP project numbers)
    numeric = re.compile(r"\b(\d{12})\b")
    # GUID-style IDs (Azure subscriptions, OCI OCIDs are longer/handled separately)
    guid = re.compile(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b")
    if files is None:
        files = identify_files(
            folder_path,
            excluded_roots=excluded_roots,
            exclude_generated_outputs=True,
        )
    for category_paths in files.values():
        for filepath in category_paths:
            filename = Path(filepath).name
            for m in numeric.findall(filename):
                scope_ids.add(m)
            for m in guid.findall(filename):
                scope_ids.add(m)
    return sorted(scope_ids)


def _is_compliance_json(filepath: Path) -> bool:
    """True if a .json is a per-framework compliance export rather than a main
    OCSF findings file. Detected by a compliance/ immediate parent directory or a
    framework-suffixed stem (the main per-scan file is exactly
    prowler-output-<id>-<ts>.ocsf.json — no extra _<framework> segment before the
    extension). Only checks the filename and immediate parent to avoid false positives
    when the full path contains 'compliance' (e.g. Acme-Compliance-2026/)."""
    name = filepath.name
    if name.lower().endswith(".asff.json"):
        return False
    # Check only the immediate parent directory, not the full path
    parent_name = filepath.parent.name.lower()
    if parent_name == "compliance":
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


def identify_files(folder_path: str, excluded_roots: list = None,
                   exclude_generated_outputs: bool = False,
                   excluded_files: list = None) -> dict:
    """Categorize files in the input folder by type.

    ``excluded_roots`` and ``excluded_files`` prevent generated deliverables from
    being re-read as input.
    ``exclude_generated_outputs`` additionally ignores prior default output folders
    while detecting the provider for a new default output path.
    """
    result = {
        "prowler_main_csv": [],
        "prowler_compliance_csv": [],
        "prowler_html": [],
        "prowler_json": [],
        "security_hub_json": [],
        "other": [],
    }

    input_root = Path(folder_path)
    excluded_roots = [Path(root) for root in (excluded_roots or [])]
    excluded_files = [Path(file_path) for file_path in (excluded_files or [])]
    # Resolve the input root once so we can confirm every discovered file stays inside
    # it. rglob + is_file() follow symlinks, so without this a symlink planted in a
    # shared input directory could point at /etc/passwd or another customer's data and
    # turn this tool into a confused-deputy reader.
    try:
        input_root_resolved = input_root.resolve()
    except OSError:
        input_root_resolved = input_root
    _files_seen = 0
    _paths_seen = 0
    pending_dirs = [input_root]
    # Stream directory entries rather than using rglob/os.walk: both construct an
    # unbounded list for a wide directory before a limit can be applied.
    while pending_dirs:
        current_dir = pending_dirs.pop()
        try:
            entries = os.scandir(current_dir)
        except OSError as exc:
            print(f"  [WARN] Cannot scan {current_dir}: {exc}", file=sys.stderr)
            _LIMIT_NOTICES.append("unreadable input folder skipped")
            continue
        with entries:
            for entry in entries:
                _paths_seen += 1
                if _paths_seen > MAX_TOTAL_INPUT_PATHS:
                    print(f"  [WARN] Reached input-path limit ({MAX_TOTAL_INPUT_PATHS}); "
                          "ignoring remaining paths. Narrow the input folder or split the run.",
                          file=sys.stderr)
                    _LIMIT_NOTICES.append(
                        f"input exceeded {MAX_TOTAL_INPUT_PATHS}-path limit; remaining paths ignored")
                    return result

                f = Path(entry.path)
                try:
                    if entry.is_symlink():
                        print(f"  [WARN] Skipping symlinked path (not followed): {f}",
                              file=sys.stderr)
                        _LIMIT_NOTICES.append("symlinked input path not followed")
                        continue
                    f_resolved = f.resolve()
                    f_resolved.relative_to(input_root_resolved)
                    depth = len(f.relative_to(input_root).parts)
                except (OSError, ValueError):
                    print(f"  [WARN] Skipping path outside input root: {f}", file=sys.stderr)
                    _LIMIT_NOTICES.append("input path outside the input folder skipped")
                    continue
                if depth > MAX_RECURSION_DEPTH:
                    print(f"  [WARN] Skipping path deeper than {MAX_RECURSION_DEPTH} levels: {f}",
                          file=sys.stderr)
                    _LIMIT_NOTICES.append(
                        f"input deeper than {MAX_RECURSION_DEPTH} folder levels skipped")
                    continue
                if entry.is_dir(follow_symlinks=False):
                    # Prune output folders here, once, so their files neither use up the
                    # path budget nor cost a per-file resolve/ancestor check.
                    if any(_is_within(f, root) for root in excluded_roots):
                        continue
                    if (exclude_generated_outputs
                            and (f.name == "assessment-summary"
                                 or f.name.startswith("assessment-summary-"))
                            and _has_tool_artifacts(f)):
                        # Visible, not a partial-results notice: re-runs prune their own
                        # output folder every time.
                        print(f"  [INFO] Skipping generated output folder: {f}",
                              file=sys.stderr)
                        continue
                    pending_dirs.append(f)
                    continue
                # Only ordinary files are inputs. Do not open FIFOs, devices, or
                # sockets: they can block indefinitely or have side effects.
                if not entry.is_file(follow_symlinks=False):
                    continue
                if _should_skip_file(f, excluded_roots, input_root,
                                     exclude_generated_outputs, excluded_files):
                    continue
                _files_seen += 1
                if _files_seen > MAX_TOTAL_FILES:
                    print(f"  [WARN] Reached file limit ({MAX_TOTAL_FILES}); ignoring additional "
                          "input files. Narrow the input folder or split the run.", file=sys.stderr)
                    _LIMIT_NOTICES.append(
                        f"input exceeded {MAX_TOTAL_FILES}-file limit; extra files ignored")
                    return result
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
                        category = ("security_hub" if name_lower.endswith(".asff.json")
                                    else _classify_json(f))
                        if category == "security_hub":
                            result["security_hub_json"].append(str(f))
                        else:
                            result["prowler_json"].append(str(f))
                else:
                    result["other"].append(str(f))

    return result


def _classify_csv(filepath: Path) -> str:
    """Classify a CSV as prowler main, compliance, or other."""
    if _file_too_large(filepath, MAX_FILE_BYTES):
        return "other"
    try:
        with _open_input_file(filepath, binary=True) as fh:
            first_line = fh.readline(MAX_CSV_HEADER_BYTES + 1)
        if len(first_line) > MAX_CSV_HEADER_BYTES:
            print(f"  [WARN] Skipping CSV with header exceeding {MAX_CSV_HEADER_BYTES} "
                  f"bytes: {filepath}", file=sys.stderr)
            _LIMIT_NOTICES.append("CSV header exceeds classification limit; input skipped")
            return "other"
        first_line = first_line.decode("utf-8", errors="replace").strip()
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
        # Fallback: files directly inside a compliance/ folder are compliance exports.
        # Only the immediate parent is checked (matching _is_compliance_json) so a
        # customer folder like Acme-Compliance-2026/ doesn't misclassify every CSV.
        if filepath.parent.name.lower() == "compliance":
            return "compliance"
    except Exception as e:
        # An unreadable CSV may be a Prowler findings file we can't see: treat it as a
        # parse failure (fatal) rather than silently classifying it as "other".
        print(f"  [WARN] Could not read CSV {filepath}: {e}", file=sys.stderr)
        _PARSE_WARNINGS.append(f"Could not read CSV {filepath}: {e}")
    return "other"


def _classify_json(filepath: Path) -> str:
    """Classify a JSON as Security Hub / ASFF export or Prowler OCSF."""
    try:
        with _open_input_file(filepath) as fh:
            start = fh.read(2000)
        # ASFF / Security Hub markers
        if ('"ProductArn"' in start or '"AwsSecurityFinding"' in start
                or '"SchemaVersion"' in start and '"Compliance"' in start):
            return "security_hub"
        if '"Findings"' in start and '"AwsAccountId"' in start:
            return "security_hub"
    except Exception as e:
        # Unreadable/malformed JSON preview: fall back to "prowler" (the default OCSF
        # format) so one bad file does not abort the run; log why for debugging.
        print(f"  [DEBUG] Could not classify JSON {filepath}: {e}", file=sys.stderr)
    return "prowler"


# ---------------------------------------------------------------------------
# Normalized finding schema
# ---------------------------------------------------------------------------
# Every parser below emits dicts with these normalized (UPPERCASE) keys so that
# analysis is provider- and format-agnostic:
#   PROVIDER, STATUS, SEVERITY, CHECK_ID, CHECK_TITLE, SERVICE_NAME,
#   RESOURCE_UID, RISK, REMEDIATION_RECOMMENDATION_TEXT, REMEDIATION_CODE_CLI,
#   REMEDIATION_CODE_TERRAFORM, REMEDIATION_CODE_NATIVEIAC, COMPLIANCE,
#   CATEGORIES, SCOPE_ID, REGION

NORMALIZED_KEYS = [
    "PROVIDER", "STATUS", "SEVERITY", "CHECK_ID", "CHECK_TITLE", "SERVICE_NAME",
    "RESOURCE_UID", "RISK", "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_CODE_CLI", "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_NATIVEIAC", "COMPLIANCE", "CATEGORIES", "SCOPE_ID", "REGION",
]


def _blank_finding() -> dict:
    return {k: "" for k in NORMALIZED_KEYS}


# ---------------------------------------------------------------------------
# CSV parsing (Prowler, semicolon-delimited)
# ---------------------------------------------------------------------------

def parse_prowler_main_csv(filepath: str) -> list:
    """Parse a Prowler main CSV (semicolon-delimited) into normalized findings."""
    findings = []
    if _file_too_large(filepath, MAX_FILE_BYTES):
        return findings
    try:
        with _open_input_file(filepath) as fh:
            reader = csv.DictReader(fh, delimiter=";")
            for row in reader:
                if _record_limit_reached(findings, filepath, "CSV findings"):
                    break
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
                f["REGION"] = (norm.get("REGION") or norm.get("AWS_REGION")
                               or norm.get("LOCATION") or "")
                findings.append(f)
    except Exception as e:
        print(f"  [WARN] Failed to parse {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse {filepath}: {e}")
    return findings


def parse_prowler_compliance_csv(filepath: str) -> list:
    """Parse a Prowler compliance CSV (semicolon-delimited)."""
    records = []
    if _file_too_large(filepath, MAX_FILE_BYTES):
        return records
    try:
        with _open_input_file(filepath) as fh:
            reader = csv.DictReader(fh, delimiter=";")
            for row in reader:
                if _record_limit_reached(records, filepath, "CSV compliance records"):
                    break
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
    if _file_too_large(filepath, MAX_JSON_FILE_BYTES):
        return findings
    try:
        with _open_input_file(filepath) as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"  [WARN] Failed to parse OCSF JSON {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse OCSF JSON {filepath}: {e}")
        return findings

    if isinstance(data, dict):
        data = data.get("findings") or data.get("Findings") or [data]

    for item in data:
        if _record_limit_reached(findings, filepath, "OCSF findings"):
            break
        if not isinstance(item, dict):
            continue
        f = _blank_finding()
        cloud = item.get("cloud", {}) if isinstance(item.get("cloud"), dict) else {}
        f["PROVIDER"] = normalize_provider(cloud.get("provider", ""))

        account = cloud.get("account", {}) if isinstance(cloud.get("account"), dict) else {}
        f["SCOPE_ID"] = str(account.get("uid", "") or account.get("name", ""))
        f["REGION"] = str(cloud.get("region", "") or item.get("region", ""))

        # status_code: PASS / FAIL
        f["STATUS"] = str(item.get("status_code", item.get("status", ""))).upper()

        # severity string
        f["SEVERITY"] = str(item.get("severity", "")).capitalize()

        finding_info = item.get("finding_info", {}) if isinstance(item.get("finding_info"), dict) else {}
        metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
        f["CHECK_ID"] = str(item.get("check_id")
                            or metadata.get("event_code", "")
                            or finding_info.get("uid", ""))
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
    if _file_too_large(filepath, MAX_JSON_FILE_BYTES):
        return findings
    try:
        with _open_input_file(filepath) as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"  [WARN] Failed to parse Security Hub JSON {filepath}: {e}", file=sys.stderr); _PARSE_WARNINGS.append(f"Failed to parse Security Hub JSON {filepath}: {e}")
        return findings

    if isinstance(data, dict):
        data = data.get("Findings") or data.get("findings") or [data]

    for item in data:
        if _record_limit_reached(findings, filepath, "Security Hub findings"):
            break
        if not isinstance(item, dict):
            continue
        f = _blank_finding()
        f["PROVIDER"] = "aws"  # ASFF is an AWS format
        f["SCOPE_ID"] = str(item.get("AwsAccountId", ""))
        f["REGION"] = str(item.get("Region", "") or item.get("AwsRegion", ""))

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
    if _file_too_large(filepath, MAX_HTML_FILE_BYTES):
        return findings
    try:
        with _open_input_file(filepath) as fh:
            html = fh.read(MAX_HTML_FILE_BYTES + 1)
        if len(html) > MAX_HTML_FILE_BYTES:
            _LIMIT_NOTICES.append("HTML input exceeds read limit; input skipped")
            return findings
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
        if _record_limit_reached(findings, filepath, "HTML findings"):
            break
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
        f["REGION"] = col(row, "REGION", "AWS_REGION", "LOCATION")
        if f["STATUS"] or f["CHECK_ID"]:
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}


def _dashboard_finding(finding: dict) -> dict:
    """Serialize the complete, compact data set used for dashboard metrics.

    Detailed findings remain a capped remediation list. Dashboard calculations need
    every status, however, so they use this non-sensitive aggregation input instead.
    """
    return {
        "provider": finding.get("PROVIDER", "unknown"),
        "status": finding.get("STATUS", ""),
        "severity": finding.get("SEVERITY", "").capitalize(),
        "service": finding.get("SERVICE_NAME", "") or "Unknown",
        "scope_id": finding.get("SCOPE_ID", ""),
        "region": finding.get("REGION", "") or "global",
    }


def analyze_findings(all_findings: list) -> dict:
    """Compute aggregate statistics from normalized findings, provider-aware."""
    total = len(all_findings)
    pass_count = sum(1 for f in all_findings if f.get("STATUS", "").upper().startswith("PASS"))
    fail_count = sum(1 for f in all_findings if f.get("STATUS", "").upper().startswith("FAIL"))

    # Security Score — weighted penalty model:
    #   Score = 100 - (weighted_penalty / max_possible_penalty × 100)
    # Severity weights: Critical=10, High=7, Medium=4, Low=2, Info=1.
    # Only FAIL findings contribute to the penalty. MANUAL/INFO/MUTED excluded.
    scored = pass_count + fail_count
    failed_findings = [f for f in all_findings if f.get("STATUS", "").upper().startswith("FAIL")]
    max_possible = scored * SEVERITY_WEIGHTS["critical"] if scored > 0 else 1
    weighted_penalty = sum(
        SEVERITY_WEIGHTS.get(f.get("SEVERITY", "other").lower(), 1)
        for f in failed_findings
    )
    security_score = round(100 - (weighted_penalty / max_possible * 100), 1) if scored > 0 else 0.0

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
            "security_score": round(
                100 - (sum(
                    SEVERITY_WEIGHTS.get(f.get("SEVERITY", "other").lower(), 1)
                    for f in p_failed
                ) / ((p_pass + len(p_failed)) * SEVERITY_WEIGHTS["critical"]) * 100), 1
            ) if (p_pass + len(p_failed)) > 0 else 0.0,
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

    # Retain top failed checks for every severity so later remediation phases
    # are still represented when Critical findings dominate the ranking.
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
    # Sort by severity (Critical first) then by count descending, so all criticals
    # appear before lower-severity checks regardless of occurrence count.
    _severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranked = sorted(check_counter.items(),
                    key=lambda item: (_severity_rank.get(
                        check_details[item[0]].get("severity", "").capitalize(), 99),
                        -item[1]))
    per_severity_count = Counter()
    for check_id, count in ranked:
        severity = check_details[check_id].get("severity", "").capitalize()
        bucket = _severity_rank.get(severity, 99)
        if per_severity_count[bucket] >= 25:
            continue
        per_severity_count[bucket] += 1
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
            "region": f.get("REGION", "") or "global",
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
        "dashboard_findings": [_dashboard_finding(f) for f in all_findings],
        "detailed_findings": detailed_findings[:500],
        "detailed_findings_truncated": len(detailed_findings) > 500,
        "detailed_findings_total": len(detailed_findings),
    }


def analyze_compliance(compliance_records: list) -> dict:
    """Analyze compliance CSV records to produce per-framework coverage.

    Two different denominators are reported, because they answer different questions:

    * check-level (``total``/``pass``/``fail``/``pass_rate``) counts every CSV row,
      i.e. requirement x resource x region x scope. When several scopes are assessed
      these sum, so ``total`` is a check count and NOT the size of the framework.
      ``pass_rate`` remains a valid scope-weighted rate.
    * requirement-level (``requirements_*``) de-duplicates by REQUIREMENTS_ID so the
      denominator is the framework's actual requirement count regardless of how many
      scopes were scanned. A requirement counts as passing only when every
      observed row explicitly reports PASS or PASSED.
    """
    frameworks = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    # requirement id -> True only while every observed row explicitly passes
    req_status = defaultdict(dict)
    scopes = defaultdict(set)
    for rec in compliance_records:
        # FRAMEWORK is shared across benchmark versions (e.g. CIS); NAME
        # identifies the versioned benchmark in Prowler's compliance export.
        fw = rec.get("NAME") or rec.get("FRAMEWORK") or "Unknown"
        frameworks[fw]["total"] += 1
        raw_status = str(rec.get("STATUS") or "").strip().upper()
        status = {"PASSED": "PASS", "FAILED": "FAIL"}.get(raw_status, raw_status)
        if status == "PASS":
            frameworks[fw]["pass"] += 1
        elif status == "FAIL":
            frameworks[fw]["fail"] += 1
        scope = rec.get("ACCOUNTID") or rec.get("SUBSCRIPTIONID") or rec.get("PROJECTID")
        if scope:
            scopes[fw].add(scope)
        req_id = rec.get("REQUIREMENTS_ID")
        if req_id:
            req_status[fw][req_id] = (
                req_status[fw].get(req_id, True) and status == "PASS"
            )

    result = {}
    for fw, counts in frameworks.items():
        total = counts["total"]
        pass_rate = round((counts["pass"] / total) * 100, 1) if total > 0 else 0.0
        reqs = req_status.get(fw, {})
        req_total = len(reqs)
        req_passed = sum(1 for ok in reqs.values() if ok)
        req_rate = round((req_passed / req_total) * 100, 1) if req_total > 0 else 0.0
        result[fw] = {
            "total": total,
            "pass": counts["pass"],
            "fail": counts["fail"],
            "pass_rate": pass_rate,
            "requirements_total": req_total,
            "requirements_passed": req_passed,
            "requirements_pass_rate": req_rate,
            "scopes_counted": len(scopes.get(fw, ())),
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


# Cloud scope identifiers that can appear INSIDE resource IDs even when the scope column
# holds something else (e.g. Azure ACCOUNT_UID is the tenant, while RESOURCE_UID carries
# /subscriptions/<guid>/...; ARNs can name other accounts).
_EMBEDDED_ID_PATTERNS = [
    re.compile(r"arn:aws[a-zA-Z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12})(?=:|/)"),
    re.compile(r"/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", re.IGNORECASE),
    re.compile(r"(ocid1\.(?:tenancy|compartment)\.[a-z0-9]+\.[a-z0-9-]*\.[a-z0-9]+)"),
]
# GCP project IDs in resource-path form ("projects/<id>/..."), matched in GCP findings only.
_GCP_PROJECT_PATTERN = re.compile(r"(?:^|[/\s\"'])projects/([a-z][a-z0-9-]{4,28}[a-z0-9])(?=/|$|\")")


_GCP_URL_LOOKBACK = 2048


def _gcp_project_ids(text: str) -> set:
    """GCP project IDs in resource-path form (projects/<id>/...). Real IDs almost always
    contain a digit or hyphen; requiring one avoids masking words like 'locations'.
    Matches inside non-googleapis.com URLs are ignored: documentation links such as
    .../gcloud/reference/projects/add-iam-policy-binding are not project IDs."""
    found = set()
    for m in _GCP_PROJECT_PATTERN.finditer(text):
        project = m.group(1)
        if not any(c.isdigit() or c == "-" for c in project):
            continue
        # Bounded look-back: an unbounded rfind rescans the whole text for every match
        # (quadratic on large blobs). A token longer than the window is treated as
        # not-a-URL, which errs toward masking.
        window_start = max(0, m.start(1) - _GCP_URL_LOOKBACK)
        window = text[window_start:m.start(1)]
        prefix = window[max(window.rfind(ch) for ch in " \t\r\n\"'") + 1:]
        if "://" in prefix:
            # API selfLinks (https://compute.googleapis.com/.../projects/<id>/...) DO name
            # a project; any other URL is documentation.
            host = prefix.split("://", 1)[1].split("/", 1)[0].lower()
            if not host.endswith("googleapis.com"):
                continue
        found.add(project)
    return found



def extract_embedded_scope_ids(findings: list) -> set:
    """Scope identifiers embedded anywhere in findings' text fields. The generic
    projects/<id> form is only trusted in GCP findings: elsewhere it is far more likely
    to be a path fragment than a scope."""
    found = set()
    for f in findings:
        is_gcp = f.get("PROVIDER") == "gcp"
        for value in f.values():
            if not isinstance(value, str) or not value:
                continue
            for pattern in _EMBEDDED_ID_PATTERNS:
                found.update(pattern.findall(value))
            if is_gcp:
                found.update(_gcp_project_ids(value))
    return found


def verify_anonymization(obj, mapping: dict, check_gcp: bool = True) -> list:
    """Return real identifiers still present anywhere in obj (should be empty): every
    known id, plus any provider-shaped id (ARN account, Azure subscription, OCI
    tenancy/compartment) that was never in the mapping."""
    blob = json.dumps(obj, default=str)
    leaks = [real for real in mapping if real and real in blob]
    labels = set(mapping.values())
    for pattern in _EMBEDDED_ID_PATTERNS:
        leaks.extend(m for m in pattern.findall(blob) if m not in labels and m not in leaks)
    if check_gcp:
        leaks.extend(m for m in _gcp_project_ids(blob) if m not in labels and m not in leaks)
    return leaks


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
            with _open_input_file(csv_path) as fh:
                header = fh.readline().strip().split(";")
                first = fh.readline().strip().split(";")
            cols = [h.strip().upper() for h in header]
            if "PROVIDER" in cols:
                val = first[cols.index("PROVIDER")] if len(first) > cols.index("PROVIDER") else ""
                p = normalize_provider(val)
                if p != "unknown":
                    return p
        except Exception as e:
            # Can't read this CSV's header for a quick provider peek — try the next
            # candidate file rather than failing; log why for debugging.
            print(f"  [DEBUG] Provider peek failed for CSV {csv_path}: {e}", file=sys.stderr)
            continue
    # Fall back to OCSF JSON (cloud.provider).
    for json_path in files.get("prowler_json", []):
        try:
            with _open_input_file(json_path) as fh:
                start = fh.read(4000)
            m = re.search(r'"provider"\s*:\s*"([^"]+)"', start)
            if m:
                p = normalize_provider(m.group(1))
                if p != "unknown":
                    return p
        except Exception as e:
            # Can't read this JSON's preview for a provider peek — try the next
            # candidate file rather than failing; log why for debugging.
            print(f"  [DEBUG] Provider peek failed for JSON {json_path}: {e}", file=sys.stderr)
            continue
    # Security Hub / ASFF is AWS.
    if files.get("security_hub_json"):
        return "aws"
    return ""


def _refuse_symlinked_output(path: str, input_folder: str) -> None:
    """Exit if an output folder that lives inside (or beside) the untrusted input tree is,
    or contains, a symlink. A customer archive can ship ``assessment-summary-aws`` (or its
    ``reports/``, ``iac/``, ``charts/``) as a symlink to redirect every deliverable write."""
    path = os.path.abspath(path)
    anchor = os.path.abspath(input_folder)
    if os.path.basename(anchor).lower() == "output":
        anchor = os.path.dirname(anchor)
    if path != anchor and not path.startswith(anchor + os.sep):
        return  # operator-chosen location outside the input tree
    current = anchor
    rel = os.path.relpath(path, anchor)
    for part in ([] if rel == "." else rel.split(os.sep)):
        current = os.path.join(current, part)
        if os.path.islink(current):
            print(f"ERROR: output folder component is a symlink: {current}. "
                  "Refusing to write deliverables through it (use --output-dir).",
                  file=sys.stderr)
            sys.exit(1)
    for sub in ("reports", "iac", "charts"):
        if os.path.islink(os.path.join(path, sub)):
            print(f"ERROR: {os.path.join(path, sub)} is a symlink. Refusing to write "
                  "deliverables through it (use --output-dir).", file=sys.stderr)
            sys.exit(1)


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
    parser.add_argument("--debug-metadata", action="store_true",
                        help="Operator-only: include the full absolute input-folder path in "
                             "the analysis metadata. OFF by default so the customer-facing "
                             "analysis.json does not leak host-specific/operator paths.")
    parser.add_argument("--anon-map-dir", default=None,
                        help="Operator-only directory for the de-anonymization key "
                             "(anon_map). Defaults to ~/.cloud-security-assessment/anon-maps/. "
                             "The key is NEVER written into the deliverables folder, and each "
                             "run gets a provider+timestamp-stamped filename so runs don't "
                             "overwrite each other.")
    args = parser.parse_args()
    _PARSE_WARNINGS.clear()
    _LIMIT_NOTICES.clear()

    input_folder = os.path.abspath(args.input_folder)

    if not os.path.isdir(input_folder):
        print(f"ERROR: Input folder does not exist: {input_folder}", file=sys.stderr)
        sys.exit(1)

    # Peek the provider (cheap) so the default output folder can be named per provider.
    _peek_files = identify_files(input_folder, exclude_generated_outputs=True)
    _provider = peek_provider(_peek_files)
    # The peek pass may hit limits for paths the real pass excludes; only the final
    # discovery below decides which notices are reported.
    _LIMIT_NOTICES.clear()
    _PARSE_WARNINGS.clear()

    # Resolve the output directory (user choice, else smart per-provider default).
    output_dir = resolve_default_output_dir(input_folder, args.output_dir, _provider)
    # If an explicit analysis.json path was given, honor it; otherwise place it in output_dir.
    if args.output_json:
        output_json = os.path.abspath(args.output_json)
    else:
        output_json = os.path.join(output_dir, "analysis.json")

    _output_json_dir = os.path.dirname(output_json)
    _refuse_symlinked_output(output_dir, input_folder)
    _refuse_symlinked_output(_output_json_dir, input_folder)
    print(f"       Detected provider (for default folder): {_provider or 'unknown'}")
    print(f"       Output directory: {output_dir}")

    print(f"[1/4] Scanning files in: {input_folder}")
    # An output directory nested in the input tree must never become an input source
    # on a repeat run. This also excludes an explicitly selected analysis.json path.
    input_root = Path(input_folder)
    excluded_roots = [
        path for path in (Path(output_dir), Path(_output_json_dir))
        if _is_within(path, input_root) and path.resolve() != input_root.resolve()
    ]
    files = identify_files(input_folder, excluded_roots=excluded_roots,
                           exclude_generated_outputs=True,
                           excluded_files=[Path(output_json)])
    scope_ids = detect_scope_ids(input_folder, excluded_roots=excluded_roots,
                                 files=files)

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
        """Key on path relative to input folder so same-named files in different
        subdirectories are treated as separate scans (not collapsed or suppressed)."""
        rel = os.path.relpath(path, input_folder)
        b = os.path.basename(rel)
        for ext in (".ocsf.json", ".asff.json", ".csv", ".html", ".json"):
            if b.lower().endswith(ext):
                return os.path.join(os.path.dirname(rel), b[: -len(ext)])
        return os.path.join(os.path.dirname(rel), os.path.splitext(b)[0])

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
            # Bound aggregate memory: stop accumulating once the total-record cap is hit
            # so a hostile set of individually-valid files can't exhaust memory in sum.
            if len(all_findings) > MAX_TOTAL_RECORDS:
                print(f"  [WARN] Reached record limit ({MAX_TOTAL_RECORDS}); truncating "
                      "aggregated findings. Results are partial.", file=sys.stderr)
                _LIMIT_NOTICES.append(
                    f"aggregated findings exceeded {MAX_TOTAL_RECORDS}-record limit; truncated")
                del all_findings[MAX_TOTAL_RECORDS:]
                break
        else:
            continue
        break

    provs = sorted({(f.get("PROVIDER") or "unknown").lower() for f in all_findings})
    print(f"       {len(all_findings)} findings across {len(groups)} scan group(s); provider(s): {', '.join(provs) or 'none'}")

    print("[3/4] Parsing compliance CSVs...")
    all_compliance = []
    for csv_path in files["prowler_compliance_csv"]:
        print(f"       Parsing: {os.path.basename(csv_path)}")
        records = parse_prowler_compliance_csv(csv_path)
        all_compliance.extend(records)
        print(f"         -> {len(records)} records")
        # Bound aggregate compliance memory the same way as findings.
        if len(all_compliance) > MAX_TOTAL_RECORDS:
            print(f"  [WARN] Reached compliance record limit ({MAX_TOTAL_RECORDS}); "
                  "truncating. Compliance coverage is partial.", file=sys.stderr)
            _LIMIT_NOTICES.append(
                f"compliance records exceeded {MAX_TOTAL_RECORDS}-record limit; truncated")
            del all_compliance[MAX_TOTAL_RECORDS:]
            break

    if _PARSE_WARNINGS:
        print(f"ERROR: {len(_PARSE_WARNINGS)} selected input file(s) could not be "
              "fully parsed; analysis was not written.", file=sys.stderr)
        sys.exit(1)
    if _LIMIT_NOTICES:
        print(f"  [WARN] PARTIAL RESULTS: {len(_LIMIT_NOTICES)} safety limit(s) applied "
              f"({'; '.join(sorted(set(_LIMIT_NOTICES)))}). Recorded in "
              "metadata.input_limits_applied.", file=sys.stderr)

    if _output_json_dir:
        os.makedirs(_output_json_dir, exist_ok=True)

    print("[4/4] Analyzing findings...")
    analysis = analyze_findings(all_findings)
    compliance_coverage = analyze_compliance(all_compliance)

    providers = analysis["providers"]
    provider_labels = [PROVIDER_LABELS.get(p, p.upper()) for p in providers]
    scope_term = scope_term_for_providers(providers)

    # Prefer scope ids discovered inside the findings; fall back to filename detection.
    # Use UNION (not OR) so that accounts appearing only in filenames are still masked.
    scope_ids_in_data = sorted({
        s for prov in analysis["findings_by_provider"].values() for s in prov["scopes"]
    })
    effective_scopes = sorted(set(scope_ids_in_data) | set(scope_ids))

    customer = args.customer or "Customer"
    output = {
        "metadata": {
            "customer": customer,
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "providers": providers,
            "provider_labels": provider_labels,
            "scope_term": scope_term,
            "scopes_assessed": effective_scopes,
            # Do NOT leak the operator's absolute input path into the customer-facing
            # analysis.json by default — it can reveal host usernames, client names, and
            # directory layout. Store only the basename unless the operator explicitly
            # opts in with --debug-metadata. (The --anonymize path redacts this fully.)
            "input_folder": (input_folder if args.debug_metadata
                             else os.path.basename(os.path.normpath(input_folder))),
            "files_processed": {k: len(v) for k, v in files.items()},
            # Path-free summary of safety limits hit (empty when results are complete).
            "input_limits_applied": sorted(set(_LIMIT_NOTICES)),
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
        # Complete compact input for dashboard account/service/region metrics. This
        # intentionally includes PASS, FAIL, and manual statuses and is never capped.
        "dashboard_findings": analysis["dashboard_findings"],
        "detailed_findings": analysis["detailed_findings"],
        # detailed_findings is capped at 500 rows; carry the flag + true count through so
        # consumers can say "showing 500 of N" instead of implying the list is complete.
        "detailed_findings_truncated": analysis["detailed_findings_truncated"],
        "detailed_findings_total": analysis["detailed_findings_total"],
    }

    # Optional anonymization: mask every scope identifier across the ENTIRE output
    # (metadata, per-scope tables, resource ids, and ids embedded in ARNs/URIs/text).
    if args.anonymize:
        mask = build_scope_mask(sorted(set(effective_scopes)
                                       | extract_embedded_scope_ids(all_findings)))
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
        leaks = verify_anonymization(
            output, mask, check_gcp=any(f.get("PROVIDER") == "gcp" for f in all_findings))
        if leaks:
            print(f"ERROR: anonymization incomplete; {len(leaks)} identifier(s) "
                  "remain in the analysis. No output was written.", file=sys.stderr)
            sys.exit(1)
        # Write the real->label mapping to an OPERATOR-ONLY location, never inside the
        # deliverables tree (sharing that folder must not hand over the de-anonymization
        # key). Default to ~/.cloud-security-assessment/anon-maps/; override with
        # --anon-map-dir. Each run gets a provider+timestamp-stamped filename so a second
        # provider run does not overwrite the first run's key.
        _default_anon_map_dir = os.path.join(os.path.expanduser("~"),
                                             ".cloud-security-assessment", "anon-maps")
        _anon_map_dir = args.anon_map_dir or _default_anon_map_dir
        _anon_real = os.path.realpath(_anon_map_dir)
        for _tree in (output_dir, _output_json_dir, input_folder):
            _tree_real = os.path.realpath(_tree)
            if _anon_real == _tree_real or _anon_real.startswith(_tree_real + os.sep):
                print(f"ERROR: --anon-map-dir {_anon_map_dir} is inside {_tree}; the "
                      "de-anonymization key must live outside the input and deliverables "
                      "folders. No output was written.", file=sys.stderr)
                sys.exit(1)
        _anon_dir_existed = os.path.isdir(_anon_map_dir)
        try:
            os.makedirs(_anon_map_dir, mode=0o700, exist_ok=True)
            # Only tighten permissions on a directory this tool owns: one it just created,
            # or its own default location. Never chmod an existing operator-supplied
            # directory (it may be shared) — the 0o600 key file below is protected anyway.
            if not _anon_dir_existed or os.path.abspath(_anon_map_dir) == _default_anon_map_dir:
                os.chmod(_anon_map_dir, 0o700)
            elif os.stat(_anon_map_dir).st_mode & 0o077:
                print(f"  [WARN] --anon-map-dir {_anon_map_dir} is accessible to other "
                      "users; permissions left unchanged. The key file itself is "
                      "owner-only (0600), but consider a private directory.", file=sys.stderr)
        except OSError as e:
            print(f"ERROR: cannot create operator anon-map directory {_anon_map_dir}: {e}",
                  file=sys.stderr)
            sys.exit(1)
        _prov_tag = (providers[0] if providers else "unknown")
        _stamp = datetime.now().strftime("%Y%m%dT%H%M%S_%f")
        sidecar = os.path.join(_anon_map_dir, f"anon_map_{_prov_tag}_{_stamp}_{os.getpid()}.json")
        # Write the real->label mapping with owner-only (0o600) permissions — on shared
        # systems this prevents other users from reading the exact de-anonymization map.
        # O_NOFOLLOW: refuse to follow a symlink at the sidecar path, so an attacker who
        # pre-plants a symlink there cannot redirect this (truncating) write elsewhere.
        _open_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        try:
            _fd = os.open(sidecar, _open_flags, 0o600)
        except OSError as e:
            print(f"ERROR: refusing to write anonymization sidecar at {sidecar}: {e} "
                  "(a symlink or unwritable path may be present). No sidecar written.",
                  file=sys.stderr)
            sys.exit(1)
        # The mode arg to os.open only applies when CREATING the file. If the file already
        # existed (e.g. world-readable from a prior run or another tool), tighten it to
        # owner-only now so the de-anonymization map can't be read by other users.
        try:
            os.fchmod(_fd, 0o600)
        except OSError:
            pass  # best-effort on platforms/filesystems without fchmod
        with os.fdopen(_fd, "w", encoding="utf-8") as mf:
            json.dump({"real_to_label": mask}, mf, indent=2)
        print(f"   De-anonymization key (operator-only, NOT a deliverable): {sidecar}")
        print(f"   Anonymization: {len(mask)} scope id(s) (account/subscription/project/"
              f"tenancy) masked and verified absent from all output.")
        print("   NOTE: only scope identifiers are masked. Principal names, emails, "
              "resource names, IPs, and other identifiers in free text are NOT masked — "
              "review deliverables before sharing.")

    with safe_io.open_write_nofollow(output_json,
                                     root=(os.path.dirname(output_json) or ".")) as fh:
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
