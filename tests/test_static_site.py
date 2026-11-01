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
        for name in ("index.html", "api/data.json", "api/history.json", ".nojekyll", "openapi.json"):
            self.assertTrue(os.path.exists(os.path.join(self.site, name)), name)

    def test_chemins_relatifs_pour_sous_dossier_pages(self):
        with open(os.path.join(self.site, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("fetch('api/data.json'", html)
        self.assertNotIn("fetch('/api/", html)
        self.assertNotIn('href="/', html)
        self.assertNotIn("/taxii2", html)
        self.assertIn("if (false) {", html)  # SSE désactivé : pas de serveur

    def test_donnees_snapshot(self):
        with open(os.path.join(self.site, "api", "data.json"), encoding="utf-8") as fh:
            d = json.load(fh)
        self.assertTrue(d["static"])
        self.assertFalse(d["collecting"])
        self.assertEqual(d["auto_interval_seconds"], 6 * 3600)
        self.assertGreater(len(d["cves"]), 0)

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


if __name__ == "__main__":
    unittest.main()
