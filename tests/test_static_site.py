"""Site statique GitHub Pages (scripts/build_static.py + workflow pages.yml)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fixtures import fixture_data_dir  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location("build_static", os.path.join(ROOT, "scripts", "build_static.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBuildStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bs = _load()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.site = os.path.join(cls.tmp.name, "site")
        orig = (cls.bs.server.DATA, cls.bs.server.OUT)
        try:
            cls.written = cls.bs.build(cls.site, data_dir=fixture_data_dir(), issues_dir=os.path.join(ROOT, "out"))
        finally:
            cls.bs.server.DATA, cls.bs.server.OUT = orig

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_fichiers_publies(self):
        for name in ("index.html", "api/data.json", "api/history.json", ".nojekyll", "feed.xml",
                     "issue.html", "issue.ar.html", "issue.en.html", "issue.pdf", "robots.txt", "sitemap.xml"):
            self.assertTrue(os.path.exists(os.path.join(self.site, name)), name)

    def test_chemins_relatifs_pour_sous_dossier_pages(self):
        with open(os.path.join(self.site, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("fetch('api/data.json'", html)
        self.assertNotIn("fetch('/api/", html)
        self.assertNotIn('href="/', html)
        self.assertNotIn("/taxii2", html)
        self.assertIn("if (false) {", html)  # SSE désactivé : pas de serveur
        self.assertNotIn('id="subForm"', html)  # abonnement = serveur uniquement
        self.assertIn('href="feed.xml"', html)
        self.assertNotIn("version serveur", html)
        # re-collecte via le Worker Cloudflare (jamais de jeton côté navigateur)
        self.assertIn("await refreshViaWorker();return;", html)
        self.assertIn("ot-watch-cron.alilououssama.workers.dev", html)
        self.assertIn('id="nextRun"', html)
        self.assertNotIn("github_pat_", html)
        self.assertNotIn("GITHUB_TOKEN", html)
        self.assertIn('href="issue.en.html"', html)

    def test_donnees_snapshot(self):
        with open(os.path.join(self.site, "api", "data.json"), encoding="utf-8") as fh:
            d = json.load(fh)
        self.assertTrue(d["static"])
        self.assertFalse(d["collecting"])
        self.assertEqual(d["auto_interval_seconds"], 6 * 3600)
        self.assertGreater(len(d["cves"]), 0)

    def test_flux_rss(self):
        with open(os.path.join(self.site, "feed.xml"), encoding="utf-8") as fh:
            rss = fh.read()
        self.assertIn('<rss version="2.0">', rss)
        self.assertIn('<?xml-stylesheet type="text/xsl" href="feed.xsl"?>', rss)
        self.assertTrue(os.path.exists(os.path.join(self.site, "feed.xsl")))
        self.assertIn("<item>", rss)

    def _read(self, name):
        with open(os.path.join(self.site, name), encoding="utf-8") as fh:
            return fh.read()

    def test_aucun_inventaire_ni_profil_actifs_publie(self):
        """Grand public : ni inventaire OT, ni lien CVE -> actifs, ni score OT, ni « Mes actifs »."""
        import public_edition
        ids = public_edition.private_asset_ids(fixture_data_dir())
        self.assertTrue(ids)  # le jeu figé contient bien un inventaire : le test a du sens
        for name in self.written:
            if name.endswith(".pdf"):
                continue
            txt = self._read(name)
            for needle in [*ids, "asset_impact", "ot_score_detail", "firmware\": ", "Mes actifs OT"]:
                self.assertNotIn(needle, txt, f"{needle} publié dans {name}")
        d = json.loads(self._read("api/data.json"))
        self.assertNotIn("assets", d)
        for c in d["cves"]:
            for k in ("relevant", "asset_impact", "ot_score", "ot_score_detail"):
                self.assertNotIn(k, c)

    def test_aucun_detail_interne_publie(self):
        d = json.loads(self._read("api/data.json"))
        for k in ("last_error", "last_run", "collect_runs", "agents", "netwatch", "quality", "server_time"):
            self.assertNotIn(k, d)
        self.assertNotIn("validation", d["meta"])
        self.assertNotIn("quality", d["meta"])
        html = self._read("index.html")
        for needle in ("github.com/O-alil-lab", "openapi", "/taxii2", "SQLite", "research/findings", "anti-XSS"):
            self.assertNotIn(needle, html)
        self.assertFalse(os.path.exists(os.path.join(self.site, "openapi.json")))

    def test_securite_et_mobile(self):
        html = self._read("index.html")
        self.assertIn('http-equiv="Content-Security-Policy"', html)
        self.assertIn("object-src 'none'", html)
        self.assertIn('name="referrer" content="no-referrer"', html)
        self.assertIn("@media (max-width:640px)", html)
        # styles publics après la feuille du dashboard (sinon écrasés)
        self.assertGreater(html.index("#liveBadge{display:none!important}"), html.index(":root{"))

    def test_editions_liens_relatifs(self):
        for name in ("issue.html", "issue.ar.html", "issue.en.html"):
            self.assertNotIn('href="/', self._read(name), name)

    def test_motif_disparu_detecte(self):
        with self.assertRaises(ValueError):
            self.bs.static_dashboard("<html><body>rien</body></html>")


class TestPagesWorkflow(unittest.TestCase):
    def test_workflow(self):
        with open(os.path.join(ROOT, ".github", "workflows", "pages.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        self.assertEqual(wf["permissions"]["pages"], "write")
        self.assertEqual(wf["permissions"]["id-token"], "write")
        self.assertIn("schedule", wf[True])  # 'on' est lu comme True par PyYAML
        steps = " ".join(str(s) for s in wf["jobs"]["build"]["steps"])
        self.assertIn("build_static.py", steps)
        self.assertIn("Garde-fou", steps)
        self.assertEqual(wf["jobs"]["deploy"]["needs"], "build")
        keep = wf["jobs"]["keepalive"]
        self.assertEqual(keep["permissions"], {"actions": "write"})
        self.assertIn("/enable", keep["steps"][0]["run"])


if __name__ == "__main__":
    unittest.main()
