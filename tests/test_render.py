#!/usr/bin/env python3
"""Tests unitaires du rendu (ECC tdd-workflow) — focus sécurité XSS + conversion markdown."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import render


class TestSafeUrl(unittest.TestCase):
    def test_allowed_schemes(self):
        self.assertEqual(render.safe_url("https://www.cisa.gov/x"), "https://www.cisa.gov/x")
        self.assertEqual(render.safe_url("HTTPS://EXAMPLE.COM"), "HTTPS://EXAMPLE.COM")
        self.assertEqual(render.safe_url("mailto:a@b.c"), "mailto:a@b.c")

    def test_dangerous_schemes_blocked(self):
        for bad in ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>", "vbscript:x", "", None]:
            self.assertEqual(render.safe_url(bad), "#", msg=bad)


class TestMdToHtml(unittest.TestCase):
    def test_formatting(self):
        out = render.md_to_html("# Titre\n\nDu **gras** et *italique* et `code`.\n\n- item 1\n- item 2")
        self.assertIn("<h3>Titre</h3>", out)  # niveau # -> h3 dans le gabarit article
        self.assertIn("<strong>gras</strong>", out)
        self.assertIn("<em>italique</em>", out)
        self.assertIn("<code>code</code>", out)
        self.assertIn("<li>item 1</li>", out)

    def test_link_http_ok(self):
        out = render.md_to_html("[CISA](https://www.cisa.gov)")
        self.assertIn('href="https://www.cisa.gov"', out)

    def test_link_javascript_neutralise(self):
        out = render.md_to_html("[clic](javascript:alert(document.cookie))")
        self.assertIn('href="#"', out)
        self.assertNotIn("javascript:", out)

    def test_html_injection_neutralisee(self):
        out = render.md_to_html("<script>alert(1)</script>")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)


class TestBlocks(unittest.TestCase):
    def test_cve_block_xss_description(self):
        c = {
            "id": "CVE-2026-X", "cvss": 9.8, "severity": "CRITICAL", "kev": True,
            "published": "2026-10-20T00:00:00.000",
            "description": '"><img src=x onerror=alert(1)> broken',
            "cwes": ["CWE-79"], "refs": ["javascript:alert(1)"],
        }
        out = render.cve_block(c)
        self.assertNotIn("<img", out)
        self.assertNotIn("javascript:", out)
        self.assertIn("★KEV", out)
        self.assertIn("&lt;img", out)

    def test_advisory_block_xss_titre(self):
        a = {"code": "ICSA-26-999-01", "title": "<script>alert(1)</script> Evil",
             "link": "javascript:alert(1)", "published": "Thu, 22 Oct 2026", "summary": "<b>bad</b>"}
        out = render.advisory_block(a)
        self.assertNotIn("<script>", out)
        self.assertNotIn("javascript:", out)
        self.assertIn('href="#"', out)

    def test_sev_badge(self):
        self.assertIn("#b91c1c", render.sev_badge(9.8, "CRITICAL"))
        self.assertIn("9.8", render.sev_badge(9.8, "CRITICAL"))
        self.assertIn("n/a", render.sev_badge(None, None))


class TestRenderHtmlEndToEnd(unittest.TestCase):
    def test_full_document_sans_injection(self):
        meta = {"generated_at": "2026-10-31T22:00:00+00:00", "window_days": 14,
                "counts": {"cves": 1, "cisa_advisories": 1, "kev_ot": 1}}
        cves = [{"id": "CVE-2026-X", "cvss": 9.8, "severity": "CRITICAL", "kev": True,
                 "published": "2026-10-20", "description": "<script>alert(1)</script>",
                 "cwes": [], "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-X"]}]
        advisories = [{"code": "ICSA-26-302-01", "title": "<script>x</script>", "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01", "published": "Mon, 26 Oct 2026", "summary": "ok"}]
        kev = [{"cveID": "CVE-2026-110936", "vendorProject": "Siemens", "product": "Software Center",
                "vulnerabilityName": "KEV", "dateAdded": "2026-10-19", "dueDate": "2026-11-09",
                "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch", "shortDescription": ""}]
        articles = [{"title": "<script>alert(2)</script> Titre", "kicker": "K", "section": "S",
                     "lead": True, "body_html": "<p>corps</p>", "body_md": ""}]
        doc = render.render_html("31 octobre 2026", cves, advisories, kev, meta, articles)
        self.assertNotIn("<script>", doc)
        self.assertIn("OT Watch", doc)
        self.assertIn("31 octobre 2026", doc)
        self.assertIn("CVE-2026-X", doc)
        self.assertIn("ICSA-26-302-01", doc)
        # aucune ressource externe embarquée
        self.assertNotIn("<img", doc)
        self.assertNotIn("@import", doc)


class TestEditorialParsing(unittest.TestCase):
    def test_parse_real_editorial(self):
        arts = render.parse_editorial()
        self.assertGreaterEqual(len(arts), 5)
        self.assertTrue(any(a["lead"] for a in arts))
        for a in arts:
            self.assertTrue(a["title"])
            self.assertNotIn("<script>", a["body_html"])


if __name__ == "__main__":
    unittest.main()
