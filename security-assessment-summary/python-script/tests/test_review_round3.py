# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Regressions for the 2026-10-14 review of c62c76b: a planted IaC manifest must not
vouch for non-regular entries, limits must not silently truncate ordinary exports,
earlier output folders must be skipped without analysis.json, and output writes must
not hang on FIFOs or create directories outside the output root."""

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_security_data as analyzer
import generate_dashboard
import safe_io
from test_review_round2 import gen


class PlantedManifestTests(unittest.TestCase):
    def _plant(self, out, names):
        out.mkdir(parents=True, exist_ok=True)
        (out / ".cloud-sec-assessment-manifest.json").write_text(
            json.dumps({"generated": names, "sha256": {}}), encoding="utf-8")

    def test_manifest_listed_terraform_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iac"
            self._plant(out, [".terraform"])
            (out / ".terraform").mkdir()
            r, _ = gen(d, "aws", "kms_rotation", out)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(".terraform", r.stderr)
            r, _ = gen(d, "aws", "kms_rotation", out, "--force")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((out / ".terraform").exists())

    def test_manifest_listed_symlinked_tf_is_refused(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        with tempfile.TemporaryDirectory() as d:
            hostile = Path(d) / "hostile.tf"
            hostile.write_text('data "external" "x" { program = ["sh"] }\n', encoding="utf-8")
            out = Path(d) / "iac"
            self._plant(out, ["x.tf"])
            (out / "x.tf").symlink_to(hostile)
            r, _ = gen(d, "aws", "kms_rotation", out)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("x.tf", r.stderr)
            r, _ = gen(d, "aws", "kms_rotation", out, "--force")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(os.path.lexists(out / "x.tf"))
            self.assertTrue(hostile.exists())


class AnalyzerLimitTests(unittest.TestCase):
    def test_limits_do_not_truncate_ordinary_exports(self):
        self.assertGreaterEqual(analyzer.MAX_RECORDS_PER_FILE, 1_000_000)
        self.assertGreaterEqual(analyzer.MAX_JSON_FILE_BYTES, 256 * 1024 * 1024)

    def test_output_folder_without_analysis_json_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reports = root / "assessment-summary-aws" / "reports"
            reports.mkdir(parents=True)
            dash = reports / "Acme_Security_Dashboard.html"
            dash.write_text("<html></html>", encoding="utf-8")
            self.assertTrue(analyzer._is_generated_output_file(dash, root))
            customer = root / "assessment-summary-q3" / "main.csv"
            customer.parent.mkdir()
            customer.write_text("x", encoding="utf-8")
            self.assertFalse(analyzer._is_generated_output_file(customer, root))


class SafeIoFollowupTests(unittest.TestCase):
    def test_fifo_at_output_path_does_not_block(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFOs")
        with tempfile.TemporaryDirectory() as d:
            fifo = Path(d) / "out.html"
            os.mkfifo(fifo)
            errors = []

            def attempt():
                try:
                    safe_io.open_write_nofollow(str(fifo), root=d).close()
                except safe_io.UnsafeOutputPathError as exc:
                    errors.append(exc)

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive(), "open blocked on a FIFO")
            self.assertEqual(len(errors), 1)

    def test_dashboard_creates_nothing_through_symlinked_subfolder(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "out"
            root.mkdir()
            elsewhere = Path(d) / "elsewhere"
            elsewhere.mkdir()
            (root / "reports").symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaises(safe_io.UnsafeOutputPathError):
                generate_dashboard.generate_html({}, str(root / "reports" / "sub" / "x.html"),
                                                 output_root=str(root))
            self.assertFalse((elsewhere / "sub").exists())


if __name__ == "__main__":
    unittest.main()
