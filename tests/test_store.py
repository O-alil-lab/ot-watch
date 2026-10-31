#!/usr/bin/env python3
"""Tests du store SQLite : idempotence + détection des nouveautés."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import store  # noqa: E402


class TestStore(unittest.TestCase):
    def test_diff_nouveautes_et_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "test.db")
            payload1 = {"cves": [{"id": "CVE-2026-1", "cvss": 9.8, "severity": "CRITICAL", "kev": True,
                                  "epss": 0.9, "risk": 9.9, "published": "2026-10-30", "description": "a", "refs": []}],
                        "advisories": [{"code": "ICSA-26-1", "title": "t", "link": "https://x", "published": "d", "summary": "s"}],
                        "kev": [{"cveID": "CVE-2026-1", "vendorProject": "Siemens", "product": "P", "dateAdded": "2026-10-01", "dueDate": "2026-11-01", "knownRansomwareCampaignUse": "Known"}]}
            d1 = store.store_run(payload1, validation={"ok": True, "counts": {"cves": 1, "advisories": 1, "kev": 1}}, db_path=db)
            self.assertEqual(d1["new_cves"], ["CVE-2026-1"])
            self.assertEqual(d1["new_advisories"], ["ICSA-26-1"])

            # 2e collecte : même CVE + une nouvelle -> seul le diff nouveau est retourné
            payload2 = {"cves": payload1["cves"] + [{"id": "CVE-2026-2", "cvss": 7.5, "severity": "HIGH", "kev": False, "published": "2026-10-31", "description": "b", "refs": []}],
                        "advisories": payload1["advisories"], "kev": payload1["kev"]}
            d2 = store.store_run(payload2, validation={"ok": True, "counts": {"cves": 2, "advisories": 1, "kev": 1}}, db_path=db)
            self.assertEqual(d2["new_cves"], ["CVE-2026-2"])
            self.assertEqual(d2["new_advisories"], [])

            # 3e collecte identique -> aucun nouveauté (idempotent)
            d3 = store.store_run(payload2, validation={"ok": True, "counts": {"cves": 2, "advisories": 1, "kev": 1}}, db_path=db)
            self.assertEqual(d3["new_cves"], [])

            hist = store.history(db_path=db)
            self.assertEqual(sum(h["count"] for h in hist), 2)  # 2 CVE au total dans l'historique


if __name__ == "__main__":
    unittest.main()
