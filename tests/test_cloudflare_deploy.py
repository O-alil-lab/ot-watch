"""Tests déploiement Cloudflare free tier : wrangler.toml, worker Python, doc, workflow CI."""
import json
import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W = os.path.join(ROOT, "workers")


class TestWrangler(unittest.TestCase):
    def test_wrangler_toml(self):
        # wrangler.toml est du TOML ; on valide via tomllib
        import tomllib
        with open(os.path.join(W, "wrangler.toml"), "rb") as fh:
            cfg = tomllib.load(fh)
        self.assertEqual(cfg["main"], "otwatch_worker.py")
        self.assertIn("python_workers", cfg["compatibility_flags"])
        self.assertTrue(any("cron" in c or "/" in c for c in cfg["triggers"]["crons"]))
        d1 = cfg["d1_databases"][0]
        self.assertEqual(d1["binding"], "DB")
        self.assertEqual(cfg["kv_namespaces"][0]["binding"], "KV")
        self.assertEqual(cfg["r2_buckets"][0]["binding"], "R2")

    def test_worker_py_compiles(self):
        import py_compile
        py_compile.compile(os.path.join(W, "otwatch_worker.py"), doraise=True)

    def test_worker_routes_couvrent_openapi(self):
        with open(os.path.join(W, "otwatch_worker.py"), encoding="utf-8") as fh:
            src = fh.read()
        for route in ("/api/data", "/api/history", "/api/assets", "/api/netwatch", "/api/meta",
                      "/metrics", "/issue", "/issue.ar", "/issue.pdf", "/stix", "/misp",
                      "/openapi.json", "/taxii2", "/api/stream", "/api/refresh"):
            self.assertIn(f'"{route}"', src, route)
        self.assertIn("async def scheduled", src)   # cron collecte
        self.assertIn("text/event-stream", src)      # SSE

    def test_migration_schema_identique_store(self):
        with open(os.path.join(W, "migrations", "0001_init.sql"), encoding="utf-8") as fh:
            mig = fh.read()
        with open(os.path.join(ROOT, "src", "store.py"), encoding="utf-8") as fh:
            store = fh.read()
        for table in ("runs", "cves", "advisories", "assets", "kev"):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", mig)
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", store)


class TestCloudflareDocs(unittest.TestCase):
    def test_doc_et_workflow(self):
        p = os.path.join(ROOT, "docs", "deploy", "CLOUDFLARE-FREE-TIER-2026-11-01.md")
        self.assertTrue(os.path.exists(p))
        with open(p, encoding="utf-8") as fh:
            txt = fh.read()
        for kw in ("100 000", "10 ms", "D1", "R2", "KV", "GA", "cron", "15 min"):
            self.assertIn(kw, txt)
        with open(os.path.join(ROOT, ".github", "workflows", "deploy-cloudflare.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        self.assertIn("CLOUDFLARE_API_TOKEN", json.dumps(wf))
        self.assertIn("wrangler deploy", json.dumps(wf))

    def test_deploy_script_guard(self):
        import subprocess
        r = subprocess.run(["bash", os.path.join(W, "deploy.sh")], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"]})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("CLOUDFLARE_API_TOKEN", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
