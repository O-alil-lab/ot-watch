"""Tests câblage DevOps gratuit : workflow GHCR, script github-setup, import Linear, ADR."""
import json
import os
import subprocess
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys_path_added = False


class TestDockerWorkflow(unittest.TestCase):
    def test_workflow_ghcr_valide(self):
        with open(os.path.join(ROOT, ".github", "workflows", "docker.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        self.assertIn("jobs", wf)
        job = wf["jobs"]["build-push"]
        self.assertEqual(wf["permissions"]["packages"], "write")
        self.assertEqual(wf["permissions"]["contents"], "read")
        steps = json.dumps(job["steps"])
        self.assertIn("ghcr.io", steps)
        self.assertIn("secrets.GITHUB_TOKEN", steps)      # aucun PAT requis
        self.assertIn("docker/build-push-action", steps)
        self.assertIn("docker/login-action", steps)
        self.assertIn("trivy", json.dumps(wf["jobs"]["scan"]["steps"]).lower())

    def test_dockerfile_present(self):
        with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
            df = fh.read()
        self.assertIn("FROM python:3.13-slim", df)
        self.assertIn("USER otwatch", df)                 # non-root
        self.assertIn("HEALTHCHECK", df)


class TestGithubSetup(unittest.TestCase):
    SCRIPT = os.path.join(ROOT, "scripts", "github-setup.sh")

    def test_refuse_sans_repo(self):
        r = subprocess.run(["bash", self.SCRIPT], capture_output=True, text=True,
                           env={**os.environ, "GITHUB_REPO": ""})
        self.assertEqual(r.returncode, 2)
        self.assertIn("GITHUB_REPO", r.stderr)

    def test_refuse_repo_malforme(self):
        r = subprocess.run(["bash", self.SCRIPT], capture_output=True, text=True,
                           env={**os.environ, "GITHUB_REPO": "pas-de-slash"})
        self.assertEqual(r.returncode, 2)


class TestLinearImport(unittest.TestCase):
    def test_parse_et_dry_run(self):
        import sys
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import linear_import
        items = linear_import.parse_items()
        self.assertGreater(len(items), 5)
        self.assertTrue(any(i["prio"] == "P0" for i in items))
        self.assertTrue(any(i["done"] for i in items))     # ✅ présents dans le plan
        mut = linear_import.mutation(items[0], "TEAM_X")
        self.assertIn("issueCreate", mut["query"])
        self.assertEqual(mut["variables"]["input"]["teamId"], "TEAM_X")
        # dry-run CLI : aucune clé requise, exit 0
        r = subprocess.run(["python3", os.path.join(ROOT, "scripts", "linear_import.py")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("dry-run", r.stdout)


class TestAdr(unittest.TestCase):
    def test_adr_present(self):
        p = os.path.join(ROOT, "docs", "adr", "ADR-2026-11-01-remote-github-linear-ghcr.md")
        self.assertTrue(os.path.exists(p))
        with open(p, encoding="utf-8") as fh:
            txt = fh.read()
        for kw in ("GHCR", "Linear", "GITHUB_TOKEN", "packages: write", "2 000"):
            self.assertIn(kw, txt)


if __name__ == "__main__":
    unittest.main()
