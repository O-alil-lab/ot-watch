#!/usr/bin/env python3
"""Tests v2 du collecteur : EPSS, score de risque, requête CPE."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import collect  # noqa: E402


class TestEpssRisk(unittest.TestCase):
    def test_enrich_epss_et_risque(self):
        cves = [
            {"id": "CVE-2026-A", "cvss": 9.8, "kev": True},
            {"id": "CVE-2026-B", "cvss": 5.0, "kev": False},
        ]
        epss_doc = json.dumps({"status": "OK", "data": [
            {"cve": "CVE-2026-A", "epss": "0.900", "percentile": "0.99"},
            {"cve": "CVE-2026-B", "epss": "0.010", "percentile": "0.10"},
        ]})

        def fake_fetch(url, timeout=40, headers=None):
            if "first.org" in url:
                self.assertIn("cve=CVE-2026-A", url)  # lot par cve=
                return epss_doc.encode()
            raise AssertionError("unexpected url " + url)

        with mock.patch.object(collect, "fetch", side_effect=fake_fetch), \
             mock.patch.object(collect.time, "sleep", lambda s: None):
            out = collect.sort_by_risk(collect.enrich_epss(cves))
        self.assertAlmostEqual(out[0]["epss"], 0.9)
        self.assertGreater(out[0]["risk"], out[1]["risk"])  # KEV+EPSS haut devant
        # vérification formule : 10*(0.5*0.98 + 0.3*0.9 + 0.2*1) = 9.6
        self.assertAlmostEqual(out[0]["risk"], 9.6, places=2)

    def test_epss_indisponible_ne_casse_pas(self):
        cves = [{"id": "CVE-2026-A", "cvss": 9.0, "kev": False}]

        def boom(url, timeout=40, headers=None):
            raise OSError("offline")

        with mock.patch.object(collect, "fetch", side_effect=boom), \
             mock.patch.object(collect.time, "sleep", lambda s: None):
            out = collect.enrich_epss(cves)
        self.assertIsNone(out[0]["epss"])
        self.assertAlmostEqual(out[0]["risk"], 10 * 0.5 * 0.9, places=2)  # cvss seul


class TestCpeQuery(unittest.TestCase):
    def test_cpe_vendors_present_dans_config(self):
        self.assertIn("siemens", collect.CFG["nvd_cpe_vendors"])
        self.assertTrue(collect.CFG.get("use_epss"))


if __name__ == "__main__":
    unittest.main()
