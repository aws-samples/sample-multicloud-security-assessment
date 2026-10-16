# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Security-hardening regressions: input-path redaction, symlink containment,
oversized-file limits, sidecar no-follow, and README escaping.

These cover the security-critical paths added to defend against info leakage,
confused-deputy reads, symlink-redirected writes, parser DoS, and Markdown/HTML
injection in generated deliverables.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
PPTX_SCRIPT = SCRIPTS_DIR / "generate_pptx.js"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer
import generate_readme
import generate_dashboard
import generate_pdf


MAIN_CSV = (
    "STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;PROVIDER\n"
    "PASS;Info;pass-check;S3;111122223333;aws\n"
    "FAIL;High;fail-check;S3;111122223333;aws\n"
)


def run_analyzer(input_dir, output_path, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "analyze_security_data.py"),
         str(input_dir), str(output_path), *map(str, args)],
        capture_output=True, text=True,
    )


class InputPathRedactionTests(unittest.TestCase):
    def test_absolute_input_path_not_leaked_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            # A directory name that would be sensitive if leaked.
            input_dir = root / "clients" / "SecretCustomer" / "output"
            input_dir.mkdir(parents=True)
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            output = root / "analysis.json"

            result = run_analyzer(input_dir, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            folder = data["metadata"]["input_folder"]
            # Must not contain the absolute path or the sensitive parent components.
            self.assertNotIn(str(input_dir), folder)
            self.assertNotIn("SecretCustomer", folder)
            self.assertNotIn(os.sep, folder)
            self.assertEqual(folder, "output")

    def test_debug_metadata_opts_in_to_full_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            output = root / "analysis.json"

            result = run_analyzer(input_dir, output, "--debug-metadata")
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["input_folder"],
                             os.path.abspath(str(input_dir)))


class SymlinkContainmentTests(unittest.TestCase):
    def test_symlinked_file_in_input_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            # A secret file OUTSIDE the input tree, exposed via a symlink inside it.
            secret = root / "secret.csv"
            secret.write_text(
                "STATUS;SEVERITY;CHECK_ID;SERVICE_NAME;ACCOUNT_UID;PROVIDER\n"
                "FAIL;Critical;leaked;Secret;999999999999;aws\n",
                encoding="utf-8",
            )
            link = input_dir / "linked.csv"
            try:
                link.symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            files = analyzer.identify_files(str(input_dir))
            all_found = [p for cat in files.values() for p in cat]
            # The real file is included; the symlink to outside content is not.
            self.assertTrue(any(p.endswith("main.csv") for p in all_found))
            self.assertFalse(any("linked.csv" in p for p in all_found))
            self.assertFalse(any("secret.csv" in p for p in all_found))


class ResourceLimitTests(unittest.TestCase):
    def test_oversized_csv_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "big.csv"
            path.write_text(MAIN_CSV, encoding="utf-8")
            # Force the limit tiny so the small file counts as oversized.
            original = analyzer.MAX_FILE_BYTES
            analyzer.MAX_FILE_BYTES = 1
            try:
                self.assertTrue(analyzer._file_too_large(str(path), analyzer.MAX_FILE_BYTES))
                self.assertEqual(analyzer.parse_prowler_main_csv(str(path)), [])
            finally:
                analyzer.MAX_FILE_BYTES = original

    def test_field_size_limit_is_bounded_not_maxsize(self):
        import csv
        # The limit must be a bounded value, not sys.maxsize (DoS guard).
        self.assertLessEqual(csv.field_size_limit(), analyzer.MAX_FIELD_BYTES)
        self.assertLess(analyzer.MAX_FIELD_BYTES, sys.maxsize)

    def test_csv_classification_checks_size_before_reading_header(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "big.csv"
            path.write_text(MAIN_CSV, encoding="utf-8")
            original = analyzer.MAX_FILE_BYTES
            try:
                analyzer.MAX_FILE_BYTES = 1
                self.assertEqual(analyzer._classify_csv(path), "other")
            finally:
                analyzer.MAX_FILE_BYTES = original

    def test_csv_classification_bounds_header_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "long-header.csv"
            path.write_bytes(b"STATUS;SEVERITY;" + b"x" * 64)
            original = analyzer.MAX_CSV_HEADER_BYTES
            try:
                analyzer.MAX_CSV_HEADER_BYTES = 16
                self.assertEqual(analyzer._classify_csv(path), "other")
            finally:
                analyzer.MAX_CSV_HEADER_BYTES = original


class SidecarNoFollowTests(unittest.TestCase):
    def test_sidecar_written_to_operator_dir_not_deliverables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "aws" / "output"
            input_dir.mkdir(parents=True)
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            out_dir = root / "aws" / "deliverables"
            out_dir.mkdir(parents=True)
            output = out_dir / "analysis.json"
            keydir = root / "operator_keys"

            result = run_analyzer(input_dir, output, "--anonymize",
                                  "--anon-map-dir", str(keydir))
            self.assertEqual(result.returncode, 0, result.stderr)
            # Key is written to the operator dir with a run-stamped name...
            keys = list(keydir.glob("anon_map_*.json"))
            self.assertEqual(len(keys), 1)
            # ...and NOT into the customer scan tree or deliverables folder.
            self.assertFalse((root / "aws" / "anon_map.json").exists())
            self.assertFalse(list(out_dir.glob("anon_map*.json")))
            self.assertFalse(list(input_dir.glob("anon_map*.json")))


class ReadmeEscapingTests(unittest.TestCase):
    def _render(self, data):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "README.md"
            generate_readme.generate_readme(data, str(out))
            return out.read_text(encoding="utf-8")

    def _base_data(self, customer="Acme", service="S3"):
        return {
            "metadata": {"customer": customer, "scan_date": "2026-10-08",
                         "providers": ["aws"], "scopes_assessed": ["111122223333"]},
            "summary": {
                "total_checks": 10, "pass_count": 5, "security_score": 50,
                "findings_by_severity": {"critical": 1, "high": 2, "medium": 3, "low": 4},
                "findings_by_service": {service: 3},
            },
            "compliance_coverage": {},
        }

    def test_pipe_in_service_name_is_escaped(self):
        md = self._render(self._base_data(service="S3 | EC2"))
        # A raw pipe would split the table cell; it must be backslash-escaped.
        self.assertIn("S3 \\| EC2", md)

    def test_html_in_customer_is_escaped(self):
        md = self._render(self._base_data(customer="<script>alert(1)</script>"))
        self.assertNotIn("<script>", md)
        self.assertIn("&lt;script&gt;", md)


class OutputSymlinkTests(unittest.TestCase):
    def test_analysis_json_write_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            # Plant a symlink at the analysis.json output path.
            evil = root / "evil_out.json"
            evil.write_text("UNTOUCHED", encoding="utf-8")
            out = root / "analysis.json"
            try:
                out.symlink_to(evil)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            result = run_analyzer(input_dir, out)
            # Must fail rather than follow the symlink and clobber evil_out.json.
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(evil.read_text(encoding="utf-8"), "UNTOUCHED")

    def test_open_write_nofollow_rejects_symlink(self):
        import safe_io
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.txt"
            target.write_text("UNTOUCHED", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.open_write_nofollow(str(link))
            self.assertEqual(target.read_text(encoding="utf-8"), "UNTOUCHED")

    def test_assert_within_root_blocks_escape(self):
        import safe_io
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "out"
            root.mkdir()
            # A sibling path that is NOT under root must be rejected.
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.assert_within_root(str(Path(temp_dir) / "elsewhere" / "x.txt"), str(root))
            # A path under root is allowed.
            safe_io.assert_within_root(str(root / "ok.txt"), str(root))


class AggregateLimitTests(unittest.TestCase):
    def test_total_file_limit_truncates_discovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            input_dir.mkdir()
            for i in range(6):
                (input_dir / f"f{i}.csv").write_text(MAIN_CSV, encoding="utf-8")
            original = analyzer.MAX_TOTAL_FILES
            analyzer.MAX_TOTAL_FILES = 3
            try:
                files = analyzer.identify_files(str(input_dir))
                total = sum(len(v) for v in files.values())
                self.assertLessEqual(total, 3)
            finally:
                analyzer.MAX_TOTAL_FILES = original

    def test_recursion_depth_limit_skips_deep_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            deep = input_dir / "a" / "b" / "c" / "d"
            deep.mkdir(parents=True)
            (input_dir / "shallow.csv").write_text(MAIN_CSV, encoding="utf-8")
            (deep / "deep.csv").write_text(MAIN_CSV, encoding="utf-8")
            original = analyzer.MAX_RECURSION_DEPTH
            analyzer.MAX_RECURSION_DEPTH = 2
            try:
                files = analyzer.identify_files(str(input_dir))
                found = [p for cat in files.values() for p in cat]
                self.assertTrue(any("shallow.csv" in p for p in found))
                self.assertFalse(any("deep.csv" in p for p in found))
            finally:
                analyzer.MAX_RECURSION_DEPTH = original

    def test_scope_id_detection_uses_discovery_limits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            deep = input_dir / "a" / "b" / "c" / "d"
            deep.mkdir(parents=True)
            (input_dir / "111122223333.csv").write_text(MAIN_CSV, encoding="utf-8")
            (deep / "999988887777.csv").write_text(MAIN_CSV, encoding="utf-8")
            original = analyzer.MAX_RECURSION_DEPTH
            try:
                analyzer.MAX_RECURSION_DEPTH = 2
                scope_ids = analyzer.detect_scope_ids(str(input_dir))
                self.assertIn("111122223333", scope_ids)
                self.assertNotIn("999988887777", scope_ids)
            finally:
                analyzer.MAX_RECURSION_DEPTH = original

    def test_discovery_prunes_over_depth_directories_before_descending(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            deep = input_dir / "a" / "b" / "c" / "d"
            deep.mkdir(parents=True)
            (deep / "deep.csv").write_text(MAIN_CSV, encoding="utf-8")
            original_depth = analyzer.MAX_RECURSION_DEPTH
            real_scandir = analyzer.os.scandir
            scanned_dirs = []

            def tracking_scandir(path):
                scanned_dirs.append(Path(path))
                return real_scandir(path)

            try:
                analyzer.MAX_RECURSION_DEPTH = 2
                with mock.patch.object(analyzer.os, "scandir", side_effect=tracking_scandir):
                    analyzer.identify_files(str(input_dir))
            finally:
                analyzer.MAX_RECURSION_DEPTH = original_depth

            self.assertNotIn(input_dir / "a" / "b" / "c", scanned_dirs)

    def test_discovery_skips_fifo_without_opening_it(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFOs are not supported on this platform")
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "scan"
            input_dir.mkdir()
            fifo = input_dir / "stalled.csv"
            os.mkfifo(fifo)
            files = analyzer.identify_files(str(input_dir))
            self.assertNotIn(str(fifo), files["prowler_main_csv"])
            self.assertNotIn(str(fifo), files["other"])

    def test_aggregate_limits_are_bounded(self):
        self.assertLess(analyzer.MAX_TOTAL_FILES, 10 ** 9)
        self.assertLess(analyzer.MAX_RECURSION_DEPTH, 10 ** 6)
        self.assertLess(analyzer.MAX_TOTAL_RECORDS, sys.maxsize)


class AgentDocShellSafetyTests(unittest.TestCase):
    """The agent doc must not teach the vulnerable inline single-quote pattern."""

    def test_agent_doc_has_no_inline_customer_assignment(self):
        agent_md = (Path(__file__).resolve().parents[2]
                    / "kiro-agent" / "agent.md").read_text(encoding="utf-8")
        # The old, vulnerable pattern assigned the raw placeholder inline.
        self.assertNotIn("CUSTOMER='<Customer>'", agent_md)
        # The hardened guidance references an env-provided value and a safe slug.
        self.assertIn("CUSTOMER_NAME", agent_md)
        self.assertIn("CUST_SLUG", agent_md)


class ParentSymlinkContainmentTests(unittest.TestCase):
    def test_open_write_nofollow_rejects_parent_outside_root(self):
        import safe_io
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "intended"
            root.mkdir()
            outside = Path(temp_dir) / "outside"
            outside.mkdir()
            # Target lives under 'outside' but we claim 'intended' as the root — the
            # resolved parent is not under the resolved root, so it must be refused.
            target = outside / "artifact.txt"
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.open_write_nofollow(str(target), root=str(root))
            self.assertEqual(list(outside.iterdir()), [])

    def test_open_write_nofollow_refuses_symlinked_final_file(self):
        import safe_io
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evil = root / "evil.txt"
            evil.write_text("UNTOUCHED", encoding="utf-8")
            link = root / "artifact.txt"
            try:
                link.symlink_to(evil)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")
            # O_NOFOLLOW must refuse to follow the symlinked final component.
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                safe_io.open_write_nofollow(str(link), root=str(root))
            self.assertEqual(evil.read_text(encoding="utf-8"), "UNTOUCHED")

    def test_open_write_nofollow_allows_normal_parent(self):
        import safe_io
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "out"
            target = out / "artifact.txt"
            with safe_io.open_write_nofollow(str(target), root=str(out)) as fh:
                fh.write("ok")
            self.assertEqual(target.read_text(encoding="utf-8"), "ok")


class PptxOutputSymlinkTests(unittest.TestCase):
    @staticmethod
    def _analysis():
        return {
            "metadata": {"customer": "Acme", "scan_date": "2026-10-09",
                         "providers": ["aws"]},
            "summary": {
                "security_score": 50,
                "total_checks": 0,
                "findings_by_severity": {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0,
                },
                "findings_by_service": {},
            },
            "top_failed_checks": [],
            "compliance_coverage": {},
        }

    def _run_pptx(self, analysis, charts, output):
        return subprocess.run(
            ["node", str(PPTX_SCRIPT), str(analysis), str(charts), str(output)],
            capture_output=True, text=True,
        )

    def test_pptx_write_refuses_final_symlink(self):
        if not shutil.which("node") or not (SCRIPTS_DIR / "node_modules" / "pptxgenjs").exists():
            self.skipTest("Node.js and pptxgenjs are required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            victim = root / "victim.pptx"
            victim.write_bytes(b"UNTOUCHED")
            output = root / "deck.pptx"
            try:
                output.symlink_to(victim)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            result = self._run_pptx(analysis, root, output)

            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertEqual(victim.read_bytes(), b"UNTOUCHED")

    def test_pptx_write_refuses_symlinked_reports_directory(self):
        if not shutil.which("node") or not (SCRIPTS_DIR / "node_modules" / "pptxgenjs").exists():
            self.skipTest("Node.js and pptxgenjs are required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            reports = root / "reports"
            try:
                reports.symlink_to(elsewhere, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            result = self._run_pptx(analysis, root, reports / "deck.pptx")

            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse((elsewhere / "deck.pptx").exists())

    def test_pptx_write_refuses_nested_reports_symlink(self):
        if not shutil.which("node") or not (SCRIPTS_DIR / "node_modules" / "pptxgenjs").exists():
            self.skipTest("Node.js and pptxgenjs are required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            reports = root / "deliverables" / "reports"
            reports.parent.mkdir()
            try:
                reports.symlink_to(elsewhere, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            result = self._run_pptx(analysis, root, reports / "nested" / "deck.pptx")

            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse((elsewhere / "nested" / "deck.pptx").exists())

    def test_pptx_write_follows_symlinked_deliverables_root(self):
        # Like safe_io.py: the operator-chosen root may be a symlink (macOS /tmp,
        # ~/work -> /Volumes/...); only components BELOW it must be real directories.
        if not shutil.which("node") or not (SCRIPTS_DIR / "node_modules" / "pptxgenjs").exists():
            self.skipTest("Node.js and pptxgenjs are required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            deliverables = root / "deliverables"
            try:
                deliverables.symlink_to(elsewhere, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            result = self._run_pptx(analysis, root,
                                    deliverables / "reports" / "deck.pptx")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((elsewhere / "reports" / "deck.pptx").is_file())

    def test_pptx_write_preserves_normal_output_and_suffix_behavior(self):
        if not shutil.which("node") or not (SCRIPTS_DIR / "node_modules" / "pptxgenjs").exists():
            self.skipTest("Node.js and pptxgenjs are required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            output = root / "deck"

            result = self._run_pptx(analysis, root, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "deck.pptx").exists())


class SidecarPermissionTests(unittest.TestCase):
    def test_operator_keydir_and_key_are_owner_only(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits only")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "aws" / "output"
            input_dir.mkdir(parents=True)
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            output = root / "aws" / "deliverables" / "analysis.json"
            keydir = root / "operator_keys"
            # A keydir the tool creates itself is owner-only.
            result = run_analyzer(input_dir, output, "--anonymize",
                                  "--anon-map-dir", str(keydir))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(oct(keydir.stat().st_mode & 0o777), oct(0o700))
            keys = list(keydir.glob("anon_map_*.json"))
            self.assertEqual(len(keys), 1)
            self.assertEqual(oct(keys[0].stat().st_mode & 0o777), oct(0o600))

    def test_existing_operator_keydir_permissions_are_not_changed(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits only")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "aws" / "output"
            input_dir.mkdir(parents=True)
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            output = root / "aws" / "deliverables" / "analysis.json"
            # A pre-existing (possibly shared) directory must be left as-is, with a warning;
            # only the key file itself is forced to 0o600.
            shared = root / "shared_keys"
            shared.mkdir()
            os.chmod(shared, 0o755)

            result = run_analyzer(input_dir, output, "--anonymize",
                                  "--anon-map-dir", str(shared))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(oct(shared.stat().st_mode & 0o777), oct(0o755))
            self.assertIn("permissions left unchanged", result.stderr)
            keys = list(shared.glob("anon_map_*.json"))
            self.assertEqual(len(keys), 1)
            self.assertEqual(oct(keys[0].stat().st_mode & 0o777), oct(0o600))


class ComplianceCapTests(unittest.TestCase):
    def test_compliance_records_are_capped(self):
        # Direct unit check: the cap constant is applied to compliance aggregation.
        # (A full-volume integration test would be prohibitively large; we assert the
        # cap exists and is bounded, mirroring the findings cap.)
        self.assertLess(analyzer.MAX_TOTAL_RECORDS, sys.maxsize)
        self.assertGreater(analyzer.MAX_TOTAL_RECORDS, 0)


class DashboardCspTests(unittest.TestCase):
    def _analysis(self):
        return {
            "metadata": {"customer": "Acme", "scan_date": "2026-10-08",
                         "providers": ["aws"], "provider_labels": ["AWS"],
                         "scope_term": "account", "scopes_assessed": ["111122223333"]},
            "summary": {"total_checks": 1, "pass_count": 0, "fail_count": 1,
                        "security_score": 0,
                        "findings_by_severity": {"critical": 1, "high": 0, "medium": 0,
                                                 "low": 0, "other": 0},
                        "findings_by_service": {"S3": 1},
                        "findings_by_provider": {}},
            "dashboard_findings": [], "detailed_findings": [],
            "detailed_findings_truncated": False, "detailed_findings_total": 0,
            "compliance_coverage": {}, "regions": {},
        }

    def test_dashboard_has_csp_limited_to_pinned_cdns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            analysis = Path(temp_dir) / "analysis.json"
            analysis.write_text(json.dumps(self._analysis()), encoding="utf-8")
            out = Path(temp_dir) / "d.html"
            result = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "generate_dashboard.py"),
                 str(analysis), str(out)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            html = out.read_text(encoding="utf-8")
            self.assertIn('http-equiv="Content-Security-Policy"', html)
            self.assertIn("default-src 'none'", html)
            self.assertIn("https://cdn.jsdelivr.net", html)
            self.assertIn("object-src 'none'", html)


class PdfTruncationTests(unittest.TestCase):
    def test_long_fields_do_not_break_pdf(self):
        # Produce a real analysis.json via the analyzer from a CSV with huge title +
        # remediation fields, then confirm the PDF step completes (truncation applied).
        with tempfile.TemporaryDirectory() as temp_dir:
            scan = Path(temp_dir) / "scan"
            scan.mkdir()
            big_title = "T" * 400
            big_rem = "R" * 40000
            (scan / "main.csv").write_text(
                "STATUS;SEVERITY;CHECK_ID;CHECK_TITLE;SERVICE_NAME;ACCOUNT_UID;PROVIDER;"
                "REMEDIATION_RECOMMENDATION_TEXT\n"
                f"FAIL;Critical;c1;{big_title};S3;111122223333;aws;{big_rem}\n",
                encoding="utf-8")
            analysis = Path(temp_dir) / "analysis.json"
            r1 = run_analyzer(scan, analysis)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            out = Path(temp_dir) / "plan.pdf"
            r2 = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "generate_pdf.py"), str(analysis), str(out)],
                capture_output=True, text=True)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertTrue(out.exists() and out.stat().st_size > 0)

    def test_safe_truncates_with_ellipsis(self):
        out = generate_pdf._safe("A" * 100, max_len=10)
        self.assertTrue(out.endswith("…"))
        self.assertLessEqual(len(out), 10)


class ReviewFixAnalyzerAndOutputTests(unittest.TestCase):
    """Regressions for the 2026-10-09 review (limits, containment, README, dashboard)."""

    def test_oversized_file_is_partial_not_fatal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            (input_dir / "huge.csv").write_text(MAIN_CSV + "PASS;Low;x;S3;1;aws\n" * 50,
                                                encoding="utf-8")
            output = root / "analysis.json"
            # Run in-process so the size cap can be lowered for the test.
            original = analyzer.MAX_FILE_BYTES
            analyzer.MAX_FILE_BYTES = len(MAIN_CSV) + 10
            argv = sys.argv
            sys.argv = ["analyze_security_data.py", str(input_dir), str(output)]
            try:
                analyzer.main()
            finally:
                analyzer.MAX_FILE_BYTES = original
                sys.argv = argv
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["input_limits_applied"],
                             ["oversized input file skipped"])

    def test_file_count_limit_is_partial_not_fatal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_dir = root / "scan"
            input_dir.mkdir()
            (input_dir / "main.csv").write_text(MAIN_CSV, encoding="utf-8")
            for i in range(4):
                (input_dir / f"more{i}.csv").write_text(MAIN_CSV, encoding="utf-8")
            output = root / "analysis.json"
            original = analyzer.MAX_TOTAL_FILES
            analyzer.MAX_TOTAL_FILES = 2
            argv = sys.argv
            sys.argv = ["analyze_security_data.py", str(input_dir), str(output)]
            try:
                analyzer.main()
            finally:
                analyzer.MAX_TOTAL_FILES = original
                sys.argv = argv
            self.assertTrue(output.exists())
            limits = json.loads(output.read_text(encoding="utf-8"))["metadata"]["input_limits_applied"]
            self.assertEqual(len(limits), 1)
            self.assertIn("file limit", limits[0])

    def test_symlinked_reports_subfolder_is_contained(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            out = root / "deliverables"
            out.mkdir()
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            (out / "reports").symlink_to(elsewhere, target_is_directory=True)
            data = {"metadata": {}, "summary": {"total_checks": 0, "pass_count": 0,
                    "fail_count": 0, "findings_by_severity": {}, "findings_by_service": {}}}
            analysis = out / "analysis.json"
            analysis.write_text(json.dumps(data), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "generate_dashboard.py"), str(analysis),
                 str(out / "reports" / "dash.html")], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(elsewhere.iterdir()), [])

    def test_containment_root_only_for_paths_inside_anchor(self):
        import safe_io
        self.assertEqual(safe_io.containment_root("/a/out/reports/x.html", "/a/out"), "/a/out")
        self.assertIsNone(safe_io.containment_root("/b/x.html", "/a/out"))

    def test_readme_file_names_are_plain_slugs(self):
        data = {
            "metadata": {"customer": "AT&T_Corp", "providers": ["aws"], "scan_date": "2026-10-09"},
            "summary": {"total_checks": 1, "security_score": 50,
                        "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                        "findings_by_service": {}},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "AT_T_Corp_README.md"
            generate_readme.generate_readme(data, str(out))
            text = out.read_text(encoding="utf-8")
            self.assertIn("`reports/AT_T_Corp_Security_Dashboard.html`", text)
            self.assertIn("`AT_T_Corp_README.md`", text)
            self.assertNotIn("\\_", text.split("### Deliverables")[1].split("##")[0])
            self.assertIn("AT&amp;T\\_Corp", text)  # display name still escaped


if __name__ == "__main__":
    unittest.main()
