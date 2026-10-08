"""PDF regression coverage for markup-looking assessment data."""

import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from struct import pack

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import generate_pdf


def _write_png(path, width, height):
    """Write a solid-color chart fixture without an image-library test dependency."""
    def chunk(kind, data):
        return pack(">I", len(data)) + kind + data + pack(">I", zlib.crc32(kind + data))

    pixels = (b"\0" + b"\x44\x88\xcc" * width) * height
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )


class PdfSafetyTests(unittest.TestCase):
    def test_markup_looking_data_generates_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "plan.pdf"
            title = "Check <img src='missing.png'> & <b>review</b>"
            remediation = 'Keep <b>literal</b> & verify <img src="absent.png">'
            data = {
                "metadata": {
                    "customer": "Acme <b>",
                    "scan_date": "2026-10-07 <scan>",
                    "providers": ["custom<b>"],
                    "scopes_assessed": ["scope <one> & two"],
                },
                "summary": {
                    "findings_by_severity": {
                        "critical": 1, "high": 0, "medium": 0, "low": 0,
                    },
                    "security_score": 50,
                    "total_checks": 1,
                    "pass_count": 0,
                    "fail_count": 1,
                },
                "top_failed_checks": [{
                    "check_title": title,
                    "service": "Service <b>raw</b>",
                    "severity": "critical",
                    "count": 1,
                    "remediation_text": remediation,
                }],
                "compliance_coverage": {
                    "Framework <b>literal</b>": {
                        "total": 1, "pass": 0, "fail": 1,
                        "pass_rate": 0, "requirements_total": 0,
                    },
                },
            }

            generate_pdf.build_pdf(data, str(output_path))
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))
            if PdfReader is None:
                return
            text = "\n".join(page.extract_text() for page in PdfReader(output_path).pages)

        self.assertIn("Acme <b>", text)
        self.assertIn("2026-10-07 <scan>", text)
        self.assertIn("CUSTOM<B>", text)
        self.assertIn("scope <one> & two", text)
        self.assertIn(title, text)
        self.assertIn("Service <b>raw</b>", text)
        self.assertIn(remediation, text)
        self.assertIn("Framework <b>literal</b>", text)

    def test_service_chart_stays_with_its_caption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            charts_dir = Path(temp_dir) / "charts"
            charts_dir.mkdir()
            _write_png(charts_dir / "severity_donut.png", 100, 100)
            _write_png(charts_dir / "service_bar.png", 101, 100)
            output_path = Path(temp_dir) / "plan.pdf"
            data = {
                "metadata": {"customer": "Acme", "providers": ["aws"]},
                "summary": {
                    "findings_by_severity": {
                        "critical": 0, "high": 0, "medium": 0, "low": 0,
                    },
                    "security_score": 100,
                    "total_checks": 0,
                    "pass_count": 0,
                    "fail_count": 0,
                },
                "top_failed_checks": [],
            }

            generate_pdf.build_pdf(data, str(output_path), str(charts_dir))
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))
            if PdfReader is None:
                return

            caption_pages = [
                page for page in PdfReader(output_path).pages
                if "Top Services by Failed Checks" in page.extract_text()
            ]
            self.assertEqual(len(caption_pages), 1)
            resources = caption_pages[0]["/Resources"].get_object()
            images = resources["/XObject"].get_object().values()
            image_widths = [
                int(image.get_object()["/Width"]) for image in images
                if image.get_object().get("/Subtype") == "/Image"
            ]
            self.assertIn(101, image_widths)


if __name__ == "__main__":
    unittest.main()
