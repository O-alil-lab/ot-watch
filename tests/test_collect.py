#!/usr/bin/env python3
"""Tests unitaires du collecteur (ECC tdd-workflow) — stdlib unittest, aucun dependency."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import collect

RSS_FIXTURE = """<?xml version="1.0"?>
<rss version="2.0"><channel>
<item><title>Siemens SIMATIC S7 PLCs Web Server</title>
<link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-14</link>
<pubDate>Thu, 22 Oct 2026 20:00:00 +0000</pubDate>
<description><![CDATA[<p>CVSS 9.6 web server flaws</p>]]></description></item>
<item><title>Some IT-only advisory</title>
<link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-999a</link>
<pubDate>Thu, 22 Oct 2026 20:00:00 +0000</pubDate>
<description>not ICS</description></item>
<item><title>Old Siemens advisory</title>
<link>https://www.cisa.gov/news-events/ics-advisories/icsa-20-001-01</link>
<pubDate>Mon, 04 Jan 2021 20:00:00 +0000</pubDate>
<description>too old</description></item>
</channel></rss>"""


def fake_cve(cid, desc, cpes=None, score=9.8, sev="CRITICAL"):
    return {
        "cve": {
            "id": cid,
            "published": "2026-10-20T00:00:00.000",
            "lastModified": "2026-10-21T00:00:00.000",
            "descriptions": [{"lang": "en", "value": desc}],
            "configurations": [
                {"nodes": [{"cpeMatch": [{"cpeName": c} for c in (cpes or [])]}]}
            ],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": "CVSS:3.1/AV:N"}}]},
            "weaknesses": [{"description": [{"description": "CWE-79"}]}],
            "references": [{"url": "https://example.com/ref"}],
        }
    }


class TestCisaParsing(unittest.TestCase):
    def test_only_ics_items_kept_and_code_extracted(self):
        with mock.patch.object(collect, "fetch", return_value=RSS_FIXTURE.encode()):
            items = collect.collect_cisa(window_days=14)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["code"], "ICSA-26-295-14")
        self.assertIn("icsa-26-295-14", items[0]["link"])
        self.assertNotIn("<p>", items[0]["summary"])  # HTML nettoyé

    def test_old_items_filtered_by_window(self):
        with mock.patch.object(collect, "fetch", return_value=RSS_FIXTURE.encode()):
            items = collect.collect_cisa(window_days=14)
        self.assertFalse(any("2021" in i["published"] for i in items))


class TestVendorFilter(unittest.TestCase):
    def setUp(self):
        self.vendor_re = collect.re.compile(collect.CFG["vendor_regex"], collect.re.I)

    def test_plc_with_ot_context_kept(self):
        rec = collect._cve_record(fake_cve("CVE-2026-1", "PLC authentication bypass on industrial control network")["cve"], self.vendor_re)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["cvss"], 9.8)
        self.assertEqual(rec["cwes"], ["CWE-79"])

    def test_travel_plc_faux_positif_rejete(self):
        rec = collect._cve_record(fake_cve("CVE-2002-1", "Datalex PLC BookIt! Consumer stores usernames and passwords in plaintext in a cookie")["cve"], self.vendor_re)
        self.assertIsNone(rec)

    def test_strong_vendor_kept_without_context(self):
        rec = collect._cve_record(fake_cve("CVE-2026-2", "A flaw in SIMATIC web server")["cve"], self.vendor_re)
        self.assertIsNotNone(rec)

    def test_cpe_industriel_kept(self):
        rec = collect._cve_record(fake_cve("CVE-2026-3", "Affected devices...", cpes=["cpe:2.3:h:siemens:simatic_s7-1500:-:*:*:*:*:*:*:*"])["cve"], self.vendor_re)
        self.assertIsNotNone(rec)

    def test_irrelevant_rejete(self):
        rec = collect._cve_record(fake_cve("CVE-2026-4", "A heap overflow in some media library")["cve"], self.vendor_re)
        self.assertIsNone(rec)


class TestKevFilter(unittest.TestCase):
    def test_ot_kev_kept_graphics_faux_positif_rejete(self):
        kev = {"vulnerabilities": [
            {"cveID": "CVE-2026-A", "vendorProject": "Siemens", "product": "SIMATIC CP 1543-1",
             "vulnerabilityName": "Improper Privilege Management", "shortDescription": "", "dateAdded": "2026-01-01"},
            {"cveID": "CVE-2026-B", "vendorProject": "Apple", "product": "Multiple Products",
             "vulnerabilityName": "Graphics Component Memory Corruption", "shortDescription": "", "dateAdded": "2026-01-01"},
        ]}
        with mock.patch.object(collect, "fetch", return_value=json.dumps(kev).encode()):
            out = collect.collect_kev()
        ids = [k["cveID"] for k in out]
        self.assertIn("CVE-2026-A", ids)
        self.assertNotIn("CVE-2026-B", ids)  # 'Graphics' ne doit pas matcher 'ics'


if __name__ == "__main__":
    unittest.main()
