"""Tests export PDF (src/render_pdf.py) — roadmap P2 'Export PDF'."""
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import render_pdf  # noqa: E402

CVES = [
    {"id": "CVE-2026-110936", "cvss": 9.8, "severity": "CRITICAL", "kev": True, "epss": 0.42, "risk": 6.23,
     "relevant": True, "description": "Siemens Software Center — faille critique OT."},
    {"id": "CVE-2026-63350", "cvss": 9.6, "severity": "CRITICAL", "kev": False, "epss": 0.01, "risk": 5.1,
     "relevant": True, "description": "SIMATIC S7 —description longue " * 12},
    {"id": "CVE-2026-99999", "cvss": None, "severity": "MEDIUM", "kev": False, "epss": None, "risk": None,
     "relevant": False, "description": ""},
]
KEV = [{"cveID": "CVE-2026-110936", "vendorProject": "Siemens", "product": "Software Center",
        "dateAdded": "2026-10-20", "knownRansomwareCampaignUse": "Known"}]
ADVISORIES = [{"code": "ICSA-26-295-03", "title": "Siemens SIMATIC", "published": "2026-10-22T14:00:00",
               "link": "https://www.cisa.gov/x", "summary": "Avis ICS Siemens."}]
META = {"generated_at": "2026-10-31T23:07:57+00:00", "window_days": 14,
        "counts": {"cves": 3, "advisories": 1, "kev": 1}}
ARTICLES = [{"title": "À la une", "kicker": "Analyse", "body": "## Titre\nTexte **gras** et [lien](https://x.example)."}]
HISTORY = [{"date": f"2026-10-{d:02d}", "total": d % 3, "critical": 0, "kev": 0, "kev_added": d % 2}
           for d in range(2, 32)]


@unittest.skipIf(render_pdf.FPDF is None, "fpdf2 non installé")
class TestRenderPdf(unittest.TestCase):
    def test_pdf_valide(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "issue-test.pdf")
            render_pdf.render_pdf("31 octobre 2026", CVES, ADVISORIES, KEV, META, ARTICLES, out, history=HISTORY)
            data = open(out, "rb").read()
            self.assertTrue(data.startswith(b"%PDF-"), "en-tête PDF manquant")
            self.assertIn(b"%%EOF", data[-64:], "fin PDF manquante")
            self.assertGreater(len(data), 5000, "PDF trop petit")
            pages = len(re.findall(rb"/Type\s*/Page[^s]", data))
            self.assertGreaterEqual(pages, 1, "aucune page")

    def test_pdf_sans_history(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "issue-test.pdf")
            render_pdf.render_pdf("31 octobre 2026", CVES[:1], [], [], META, [], out, history=None)
            self.assertTrue(open(out, "rb").read(5) == b"%PDF-")

    def test_strip_md(self):
        self.assertEqual(render_pdf.strip_md("## A\n**b** [t](https://u) `c`"), "A\nb t (https://u) c")

    def test_latest_issue_pdf(self):
        # out/ réel : un PDF doit exister après run_all (ou génération manuelle)
        res = render_pdf and __import__("server", fromlist=["latest_issue_pdf"]).latest_issue_pdf()
        if os.path.exists(os.path.join(render_pdf.OUT, "issue-2026-10-31.pdf")):
            self.assertIsNotNone(res)
            self.assertTrue(res[0].startswith(b"%PDF-"))
            self.assertTrue(res[1].endswith(".pdf"))


if __name__ == "__main__":
    unittest.main()
