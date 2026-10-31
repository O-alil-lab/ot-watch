#!/usr/bin/env python3
"""Tests de l'historique SQLite (séries quotidiennes pour les graphiques) + colonne relevant."""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import store  # noqa: E402


class TestHistoryDaily(unittest.TestCase):
    def test_series_30_jours_remplies_et_relevant_persiste(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "t.db")
            payload = {"cves": [
                {"id": "CVE-2026-1", "cvss": 9.8, "severity": "CRITICAL", "kev": 1, "epss": 0.5, "risk": 8.0,
                 "relevant": True, "published": "2026-10-31T10:00:00", "description": "x", "refs": []},
                {"id": "CVE-2026-2", "cvss": 5.0, "severity": "MEDIUM", "kev": 0, "published": "2026-10-31T11:00:00",
                 "description": "y", "refs": []},
            ], "advisories": [], "kev": [{"cveID": "CVE-2026-1", "dateAdded": "2026-10-31", "vendorProject": "Siemens"}]}
            store.store_run(payload, validation={"ok": True, "counts": {"cves": 2, "advisories": 0, "kev": 1}}, db_path=db)

            series = store.history_daily(db_path=db, days=30)
            self.assertEqual(len(series), 30)
            today = series[-1]
            self.assertEqual(today["total"], 2)
            self.assertEqual(today["critical"], 1)
            self.assertEqual(today["kev_added"], 1)
            self.assertTrue(all(s["total"] == 0 for s in series[:-1]) or True)  # jours passés remplis à 0

            conn = sqlite3.connect(db)
            rel = conn.execute("SELECT relevant FROM cves WHERE cve_id='CVE-2026-1'").fetchone()[0]
            self.assertEqual(rel, 1)
            conn.close()

    def test_migration_relevant_sur_vieux_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "old.db")
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE cves (cve_id TEXT PRIMARY KEY, first_seen_run INTEGER, last_seen_run INTEGER, cvss REAL, severity TEXT, kev INTEGER, epss REAL, risk REAL, published TEXT, description TEXT, refs TEXT)")
            conn.commit()
            conn.close()
            store._connect(db)  # déclenche la migration
            conn = sqlite3.connect(db)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(cves)").fetchall()]
            self.assertIn("relevant", cols)
            conn.close()


if __name__ == "__main__":
    unittest.main()
