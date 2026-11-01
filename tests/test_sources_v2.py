"""Tests sources additionnelles 2026 : flux CISA ICS dédié, GitHub GHSA, OTX (clé env optionnelle)."""
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import collect  # noqa: E402

RSS_ICS = """<?xml version="1.0"?><rss version="2.0"><channel><title>ICS Advisories</title>
<item><title>Siemens SIMATIC flaw</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-999-01</link>
<pubDate>Tue, 27 Oct 26 12:00:00 +0000</pubDate><description>&lt;p&gt;RCE via Modbus.&lt;/p&gt;</description></item>
<item><title>AA26-999A supply chain</title><link>https://www.cisa.gov/news-events/alerts/aa26-999a</link>
<pubDate>Tue, 27 Oct 26 13:00:00 +0000</pubDate><description>AA alert</description></item>
<item><title>Old ICS</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-20-001-01</link>
<pubDate>Mon, 01 Jan 24 12:00:00 +0000</pubDate><description>too old</description></item>
</channel></rss>"""

GHSA_PAGE = json.dumps([
    {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-424242", "summary": "Modicon RCE"},
    {"ghsa_id": "GHSA-dddd-eeee-ffff", "cve_id": "CVE-2026-424242", "summary": "doublon"},
    {"ghsa_id": "GHSA-gggg-hhhh-iiii", "cve_id": None, "summary": "sans CVE"},
])


def fake_fetch(url, timeout=40, headers=None, save_raw=False):
    if "ics-advisories.xml" in url or "rss.xml" in url:
        return RSS_ICS.encode()
    if "api.github.com/advisories" in url:
        return GHSA_PAGE.encode()
    raise AssertionError(url)


class TestCisaIcsFeed(unittest.TestCase):
    def test_parse_filtre_et_code(self):
        with mock.patch.object(collect, "fetch", side_effect=fake_fetch):
            items = collect.parse_rss_items(RSS_ICS.encode(), 14)
        codes = [i["code"] for i in items]
        self.assertIn("ICSA-26-999-01", codes)
        self.assertIn("AA26-999A", codes)
        self.assertNotIn("ICSA-20-001-01", codes)  # hors fenêtre
        self.assertTrue(all(i["summary"] and "<" not in i["summary"] for i in items))

    def test_collect_cisa_dedup_2_flux(self):
        def fetch2(url, timeout=60, headers=None, save_raw=False):
            return RSS_ICS.encode()  # même contenu sur les 2 flux -> dédup
        with mock.patch.object(collect, "fetch", side_effect=fetch2):
            out = collect.collect_cisa(14)
        self.assertEqual(len(out), 2)  # 2 items valides, pas de doublon


class TestGhsa(unittest.TestCase):
    def test_extraction_cve_dedup(self):
        with mock.patch.object(collect, "fetch", side_effect=fake_fetch), \
             mock.patch.object(collect.time, "sleep", lambda s: None):
            old = collect.CFG["sources"].get("ghsa_queries", [])
            collect.CFG["sources"]["ghsa_queries"] = ["Modicon"]
            try:
                ids = collect.collect_ghsa_cves()
            finally:
                collect.CFG["sources"]["ghsa_queries"] = old
        self.assertEqual(ids, ["CVE-2026-424242"])


class TestOtx(unittest.TestCase):
    def test_sans_cle_ignore(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(collect.collect_otx_cves(), [])

    def test_avec_cle_extrait_cve(self):
        payload = json.dumps({"results": [{"name": "ICS malware", "description": "targets CVE-2026-777777 and CVE-2026-777777"}]})
        with mock.patch.dict(os.environ, {"OTWATCH_OTX_API_KEY": "x"}), \
             mock.patch.object(collect, "fetch", return_value=payload.encode()), \
             mock.patch.object(collect.time, "sleep", lambda s: None):
            old = collect.CFG["sources"].get("otx_queries", [])
            collect.CFG["sources"]["otx_queries"] = ["ICS"]
            try:
                ids = collect.collect_otx_cves()
            finally:
                collect.CFG["sources"]["otx_queries"] = old
        self.assertEqual(ids, ["CVE-2026-777777"])


if __name__ == "__main__":
    unittest.main()
