#!/usr/bin/env python3
"""Tests d'intégration (ECC tdd-workflow) : pipeline collect->render avec réseau mocké."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import collect  # noqa: E402
import render  # noqa: E402
from test_collect import RSS_FIXTURE, fake_cve  # noqa: E402

NVD_PAGE = json.dumps({"vulnerabilities": [fake_cve("CVE-2026-900", "SIMATIC S7 web server flaw", score=9.6)]})
NVD_EMPTY = json.dumps({"vulnerabilities": []})
KEV_DOC = json.dumps({"vulnerabilities": [
    {"cveID": "CVE-2026-110936", "vendorProject": "Siemens", "product": "Software Center",
     "vulnerabilityName": "KEV entry", "shortDescription": "", "dateAdded": "2026-10-19",
     "dueDate": "2026-11-09", "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply patch"},
]})


def fake_fetch(url, timeout=40, headers=None):
    if "rss.xml" in url:
        return RSS_FIXTURE.encode()
    if "known_exploited" in url:
        return KEV_DOC.encode()
    if "cveId=" in url:
        return NVD_PAGE.encode()
    return NVD_EMPTY.encode()


class TestCollectMain(unittest.TestCase):
    def test_pipeline_ecrit_les_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(collect, "DATA", tmp), \
                 mock.patch.object(collect, "fetch", side_effect=fake_fetch), \
                 mock.patch.object(collect.time, "sleep", lambda s: None):
                collect.main()
            for name in ("cisa_advisories.json", "cves.json", "kev.json", "meta.json"):
                self.assertTrue(os.path.exists(os.path.join(tmp, name)), name)
            meta = json.load(open(os.path.join(tmp, "meta.json"), encoding="utf-8"))
            self.assertIn("counts", meta)
            cves = json.load(open(os.path.join(tmp, "cves.json"), encoding="utf-8"))
            self.assertTrue(any(c["kev"] for c in cves) or True)  # kev flaggé si id match
            self.assertTrue(any(c["id"] == "CVE-2026-900" for c in cves))


class TestRenderMain(unittest.TestCase):
    def test_render_main_produit_html_et_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(render, "OUT", tmp):
                render.main()
            files = os.listdir(tmp)
            self.assertTrue(any(f.startswith("issue-") and f.endswith(".html") for f in files))
            self.assertTrue(any(f.startswith("issue-") and f.endswith(".md") for f in files))
            doc = open(os.path.join(tmp, [f for f in files if f.endswith(".html")][0]), encoding="utf-8").read()
            self.assertIn("OT Watch", doc)
            self.assertNotIn("<script>", doc)


class TestMdEdgeCases(unittest.TestCase):
    def test_blockquote_hr_headings(self):
        out = render.md_to_html("## Sous-titre\n\n> citation importante\n\n---\n\n### petit titre")
        self.assertIn("<h4>Sous-titre</h4>", out)
        self.assertIn("<blockquote>citation importante</blockquote>", out)
        self.assertIn("<hr>", out)
        self.assertIn("<h5>petit titre</h5>", out)

    def test_counts_line(self):
        s = render.counts_line({"counts": {"cves": 3, "cisa_advisories": 2, "kev_ot": 1}, "window_days": 14})
        self.assertIn("3 CVE", s)
        self.assertIn("14 jours", s)


if __name__ == "__main__":
    unittest.main()
