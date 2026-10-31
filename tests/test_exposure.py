#!/usr/bin/env python3
"""Tests du profil d'exposition (⭐ mes actifs OT) et du tri par priorité."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import collect  # noqa: E402


class TestExposure(unittest.TestCase):
    def test_relevant_si_keyword_actif(self):
        cves = [
            {"id": "CVE-2026-1", "description": "Flaw in SIMATIC S7-1500 web server", "cvss": 7.0},
            {"id": "CVE-2026-2", "description": "Heap overflow in some media library", "cvss": 9.9},
        ]
        out = collect.apply_exposure(cves)
        by_id = {c["id"]: c for c in out}
        self.assertTrue(by_id["CVE-2026-1"]["relevant"])   # SIMATIC = dans le profil
        self.assertFalse(by_id["CVE-2026-2"]["relevant"])  # non OT

    def test_tri_priorite_relevant_dabord_puis_risque(self):
        cves = [
            {"id": "A", "relevant": False, "risk": 9.9},
            {"id": "B", "relevant": True, "risk": 5.0},
            {"id": "C", "relevant": True, "risk": 7.0},
        ]
        out = collect.sort_by_priority(cves)
        self.assertEqual([c["id"] for c in out], ["C", "B", "A"])

    def test_config_exposure_present(self):
        self.assertIn("exposure", collect.CFG)
        self.assertIn("siemens", " ".join(collect.CFG["exposure"]["keywords"]).lower())


if __name__ == "__main__":
    unittest.main()
