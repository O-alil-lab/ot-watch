#!/usr/bin/env python3
"""Tests de la validation qualité des données (ECC data-quality gates)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import validate  # noqa: E402


def cve(cid="CVE-2026-63350", cvss=9.4, desc="PLC flaw", pub="2026-10-22T00:00:00.000"):
    return {"id": cid, "cvss": cvss, "description": desc, "published": pub}


class TestValidateAll(unittest.TestCase):
    def test_payload_valide_ok(self):
        r = validate.validate_all({
            "cves": [cve()],
            "advisories": [{"code": "ICSA-26-302-01", "title": "X", "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01"}],
            "kev": [{"cveID": "CVE-2026-110936"}],
        })
        self.assertTrue(r["ok"])
        self.assertEqual(r["counts"]["cves"], 1)

    def test_id_cve_invalide(self):
        r = validate.validate_all({"cves": [cve(cid="CVE-99-1")], "advisories": [], "kev": []})
        self.assertFalse(r["ok"])
        self.assertTrue(any("invalide" in i for i in r["issues"]))

    def test_cvss_hors_bornes(self):
        r = validate.validate_all({"cves": [cve(cvss=11.5)], "advisories": [], "kev": []})
        self.assertFalse(r["ok"])

    def test_description_vide(self):
        r = validate.validate_all({"cves": [cve(desc="")], "advisories": [], "kev": []})
        self.assertFalse(r["ok"])

    def test_lien_non_https_rejete(self):
        r = validate.validate_all({"cves": [], "advisories": [{"code": "X", "title": "t", "link": "javascript:alert(1)"}], "kev": []})
        self.assertFalse(r["ok"])


class TestVolumeCheck(unittest.TestCase):
    def test_chute_brutale_detectee(self):
        issues = validate.volume_check({"cves": 100}, {"cves": 50})
        self.assertTrue(issues)

    def test_volume_stable_ok(self):
        self.assertEqual(validate.volume_check({"cves": 100}, {"cves": 90}), [])

    def test_premiere_collecte_ok(self):
        self.assertEqual(validate.volume_check(None, {"cves": 5}), [])


if __name__ == "__main__":
    unittest.main()
