"""Tests pack P2 : connecteur MISP, inventaire actifs + SBOM CycloneDX, replay raw, backups/DR, i18n AR."""
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import assets as assets_mod  # noqa: E402
import misp_export  # noqa: E402
import replay  # noqa: E402
import render_ar  # noqa: E402
import render_en  # noqa: E402

CVES = [
    {"id": "CVE-2026-110936", "cvss": 8.4, "severity": "HIGH", "kev": True, "epss": 0.4, "risk": 6.23,
     "relevant": True, "ssvc": "act", "attack_ics": ["T0885"], "description": "Siemens Software Center DLL hijacking"},
    {"id": "CVE-2026-63350", "cvss": 9.6, "severity": "CRITICAL", "kev": False, "epss": 0.01, "risk": 5.1,
     "relevant": True, "ssvc": "act", "attack_ics": [], "description": "Schneider Modicon M340 program download"},
]
ADVISORIES = [{"code": "ICSA-26-295-03", "title": "Siemens SIMATIC", "link": "https://www.cisa.gov/x", "published": "2026-10-22", "summary": "s"}]
META = {"generated_at": "2026-10-31T23:00:00+00:00", "window_days": 14, "counts": {"cves": 2}}
ASSETS_CFG = {"assets": [
    {"asset_id": "plc-s7", "name": "Siemens S7-1500", "vendor": "Siemens", "product": "SIMATIC S7-1500", "purdue_level": "L1", "criticality": "high"},
    {"asset_id": "plc-m340", "name": "Modicon M340", "vendor": "Schneider", "product": "Modicon M340", "purdue_level": "L1", "criticality": "high"},
]}


class TestMisp(unittest.TestCase):
    def test_event_structure(self):
        ev = misp_export.build_misp_event(CVES, ADVISORIES, META, "2026-10-31")["Event"]
        self.assertIn("OT Watch", ev["info"])
        tags = [t["name"] for t in ev["Tag"]]
        self.assertIn("TLP:WHITE", tags)
        cve_attrs = [a for a in ev["Attribute"] if a["type"] == "cve"]
        self.assertEqual(len(cve_attrs), 2)
        self.assertTrue(cve_attrs[0]["to_ids"])  # KEV -> to_ids
        self.assertIn("SSVC=act", cve_attrs[0]["comment"])
        links = [a for a in ev["Attribute"] if a["type"] == "link"]
        self.assertEqual(len(links), 1)

    def test_push_dry_run_et_reel(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(misp_export, "DATA", td), mock.patch.object(misp_export, "OUT", td), \
             mock.patch.dict(os.environ, {}, clear=True):
            with open(os.path.join(td, "meta.json"), "w", encoding="utf-8") as fh:
                json.dump(META, fh)
            with open(os.path.join(td, "cves.json"), "w", encoding="utf-8") as fh:
                json.dump(CVES, fh)
            with open(os.path.join(td, "cisa_advisories.json"), "w", encoding="utf-8") as fh:
                json.dump(ADVISORIES, fh)
            misp_export.main()  # dry-run
            self.assertTrue(os.path.exists(os.path.join(td, "issue-2026-10-31.misp.json")))
            # push réel mocké
            payload = json.dumps({"Event": {"id": "42"}}).encode()
            resp = mock.Mock(read=lambda: payload)
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            with mock.patch.dict(os.environ, {"OTWATCH_MISP_URL": "https://misp.local", "OTWATCH_MISP_AUTHKEY": "k"}),                  mock.patch("urllib.request.urlopen", return_value=resp):
                eid = misp_export.push_to_misp({"Event": {}}, "https://misp.local", "k")
                self.assertEqual(eid, "42")


class TestAssets(unittest.TestCase):
    def test_match_et_sbom(self):
        with tempfile.TemporaryDirectory() as td:
            sbom = {"bomFormat": "CycloneDX", "components": [
                {"name": "open62541", "version": "1.5.0", "supplier": {"name": "open62541"}}]}
            with open(os.path.join(td, "sbom.cdx.json"), "w", encoding="utf-8") as fh:
                json.dump(sbom, fh)
            assets = assets_mod.load_assets(ASSETS_CFG, td)
            ids = {a["asset_id"] for a in assets}
            self.assertIn("plc-s7", ids)
            self.assertTrue(any(a["source"] == "sbom" for a in assets))  # composant SBOM importé
            cves = assets_mod.match_assets([dict(c) for c in CVES], assets)
            by_id = {c["id"]: c.get("asset_impact") for c in cves}
            self.assertIn("plc-s7", by_id["CVE-2026-110936"])     # Siemens
            self.assertIn("plc-m340", by_id["CVE-2026-63350"])     # Modicon

    def test_impacted_map(self):
        cves = [{"id": "CVE-1", "asset_impact": ["a", "b"]}, {"id": "CVE-2", "asset_impact": ["a"]}]
        self.assertEqual(assets_mod.impacted_map(cves), {"a": ["CVE-1", "CVE-2"], "b": ["CVE-1"]})

    def test_score_ot(self):
        cfg = {"ot_scoring": {"kev_bonus": 1.0, "ssvc_act_bonus": 1.0, "cap": 10.0}}
        assets = assets_mod.load_assets(ASSETS_CFG)
        by_id = {a["asset_id"]: a for a in assets}
        # CVE Siemens (L1 x high = 1.0x1.2 = 1.2) + KEV +1 + SSVC act +1 -> min(10, 6.23x1.2+2)
        c = assets_mod.score_ot(dict(CVES[0]), by_id, cfg)
        c["asset_impact"] = ["plc-s7"]
        c = assets_mod.score_ot(c, by_id, cfg)
        self.assertAlmostEqual(c["ot_score"], min(10.0, round(6.23 * 1.2 + 1.0 + 1.0, 2)), places=2)
        self.assertEqual(c["ot_score_detail"]["asset_factor"], 1.2)
        self.assertEqual(c["ot_score_detail"]["kev_bonus"], 1.0)
        # safety : +0.3 sur le facteur
        by_id["plc-s7"]["safety"] = True
        c2 = assets_mod.score_ot({"id": "CVE-X", "risk": 5.0, "asset_impact": ["plc-s7"]}, by_id, cfg)
        self.assertAlmostEqual(c2["ot_score_detail"]["asset_factor"], 1.5, places=2)
        # aucun actif impacté -> ot_score None
        c3 = assets_mod.score_ot({"id": "CVE-Y", "risk": 5.0}, by_id, cfg)
        self.assertIsNone(c3["ot_score"])
        # plafond à 10
        c4 = assets_mod.score_ot({"id": "CVE-Z", "risk": 9.9, "kev": True, "ssvc": "act", "asset_impact": ["plc-s7"]}, by_id, cfg)
        self.assertEqual(c4["ot_score"], 10.0)

    def test_score_ot_all_et_store_colonne(self):
        import store
        assets = assets_mod.load_assets(ASSETS_CFG)
        cves = [dict(c) for c in CVES]
        cves = assets_mod.match_assets(cves, assets)
        cves, n = assets_mod.score_ot_all(cves, assets, {"ot_scoring": {}})
        self.assertEqual(n, 2)
        self.assertTrue(all(c.get("ot_score") is not None for c in cves))
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "t.db")
            store.store_run({"cves": cves, "advisories": [], "kev": []}, validation={"counts": {"cves": 2}, "ok": True}, db_path=db)
            import sqlite3
            conn = sqlite3.connect(db)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(cves)")]
            self.assertIn("ot_score", cols)
            row = conn.execute("SELECT cve_id, ot_score, assets FROM cves WHERE cve_id=?", (CVES[0]["id"],)).fetchone()
            self.assertIsNotNone(row[1])
            self.assertIn("plc-s7", row[2])


class TestReplay(unittest.TestCase):
    def test_replay_sans_reseau(self):
        with tempfile.TemporaryDirectory() as td:
            raw = os.path.join(td, "raw", "20261031T000000Z")
            os.makedirs(raw)
            kev = {"vulnerabilities": [{"cveID": "CVE-2026-110936", "vendorProject": "Siemens", "product": "Software Center",
                                        "vulnerabilityName": "x", "shortDescription": "SCADA PLC"}]}
            nvd = {"vulnerabilities": [{"cve": {"id": "CVE-2026-110936", "descriptions": [{"lang": "en", "value": "Siemens SIMATIC PLC flaw"}],
                                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.4, "baseSeverity": "HIGH", "vectorString": "NETWORK"}}]},
                                                "references": []}}]}
            entries = [
                {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "file": "kev.aaa", "bytes": 1},
                {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PLC", "file": "nvd.bbb", "bytes": 1},
            ]
            with open(os.path.join(raw, "kev.aaa"), "w") as fh:
                json.dump(kev, fh)
            with open(os.path.join(raw, "nvd.bbb"), "w") as fh:
                json.dump(nvd, fh)
            with open(os.path.join(raw, "manifest.json"), "w") as fh:
                json.dump(entries, fh)
            res = replay.replay(raw)
            self.assertIn("CVE-2026-110936", res["cve_ids"])
            self.assertEqual(res["kev_count"], 1)
            self.assertEqual(len(res["sources"]), 2)


class TestBackupRestore(unittest.TestCase):
    def test_backup_restore(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "data")
            os.makedirs(os.path.join(src, "raw", "run1"))
            with open(os.path.join(src, "otwatch.db"), "w") as fh:
                fh.write("SQLITE")
            with open(os.path.join(src, "raw", "run1", "x.json"), "w") as fh:
                fh.write("{}")
            bak = os.path.join(td, "backups")
            r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "backup.sh"), src, bak],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            tars = [f for f in os.listdir(bak) if f.endswith(".tar.gz") and f != "latest.tar.gz"]
            self.assertEqual(len(tars), 1)
            dest = os.path.join(td, "data2")
            r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "restore.sh"),
                                os.path.join(bak, tars[0]), dest], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(dest, "otwatch.db")))
            with tarfile.open(os.path.join(bak, tars[0])) as tf:
                self.assertTrue(any(n.endswith("otwatch.db") for n in tf.getnames()))


class TestI18nAr(unittest.TestCase):
    def test_edition_ar(self):
        doc = render_ar.render_ar_html("2026-10-31", CVES, ADVISORIES, [], META)
        self.assertIn('lang="ar"', doc)
        self.assertIn('dir="rtl"', doc)
        self.assertIn("CVE-2026-110936", doc)
        self.assertIn("نشرة OT Watch", doc)  # arabe présent
        md = render_ar.render_ar_md("2026-10-31", CVES, ADVISORIES, [], META)
        self.assertIn("CVE-2026-63350", md)
        self.assertIn("★KEV", md)

    def test_ar_bidi_isolation(self):
        """v1.17 : les IDs CVE, scores et dates latins sont isolés (bidi) en contexte RTL."""
        doc = render_ar.render_ar_html("2026-10-31", CVES, ADVISORIES, [], META)
        self.assertIn("<bdi><b>CVE-2026-110936</b></bdi>", doc)
        self.assertIn('dir="ltr"', doc)
        self.assertIn("Noto Naskh Arabic", doc)  # pile de polices arabe système
        self.assertIn('<span dir="ltr">2026-10-31</span>', doc)  # date isolée

    def test_worker_ar_no_typo(self):
        """v1.17 : la faute « edition » du worker est corrigée en « إصدار »."""
        with open(os.path.join(ROOT, "workers", "otwatch_worker.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("ال edition", src)
        self.assertIn("إصدار", src)
        self.assertIn("_render_min_en", src)
        self.assertIn('"/issue.en"', src)


class TestI18nEn(unittest.TestCase):
    def test_edition_en(self):
        doc = render_en.render_en_html("2026-10-31", CVES, ADVISORIES, [], META)
        self.assertIn('lang="en"', doc)
        self.assertIn('dir="ltr"', doc)
        self.assertIn("CVE-2026-110936", doc)
        self.assertIn("Cybersecurity Newsletter", doc)
        self.assertIn("OT-exposed", doc)
        self.assertIn("/issue.ar", doc)  # lien vers l'édition arabe
        md = render_en.render_en_md("2026-10-31", CVES, ADVISORIES, [], META)
        self.assertIn("CVE-2026-63350", md)
        self.assertIn("★KEV", md)

    def test_run_all_generates_en(self):
        with open(os.path.join(ROOT, "run_all.sh"), encoding="utf-8") as fh:
            self.assertIn("render_en.py", fh.read())

    def test_server_route_en(self):
        with open(os.path.join(ROOT, "server.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('"/issue.en"', src)
        self.assertIn("latest_issue_en", src)


class TestInventairePrive(unittest.TestCase):
    """Le vrai inventaire vit dans un fichier ignoré par git, jamais dans config.json (dépôt public)."""

    def test_fichier_prive_prioritaire(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            priv = os.path.join(td, "config.assets.local.json")
            with open(priv, "w", encoding="utf-8") as fh:
                json.dump({"assets": [{"asset_id": "prive-1", "name": "PLC réel", "vendor": "Siemens",
                                       "product": "SIMATIC S7-1500"}]}, fh)
            ids = [a["asset_id"] for a in assets_mod.load_assets(ASSETS_CFG, td, private_file=priv)]
            self.assertEqual(ids, ["prive-1"])
            ids = [a["asset_id"] for a in assets_mod.load_assets(ASSETS_CFG, td,
                                                                 private_file=os.path.join(td, "absent.json"))]
            self.assertIn("plc-s7", ids)  # repli sur les exemples

    def test_fichier_prive_ignore_par_git_et_exemples_fictifs(self):
        with open(os.path.join(ROOT, ".gitignore"), encoding="utf-8") as fh:
            self.assertIn("config.assets.local.json", fh.read())
        with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        self.assertTrue(all(a["name"].startswith("Exemple fictif") for a in cfg["assets"]))


if __name__ == "__main__":
    unittest.main()
