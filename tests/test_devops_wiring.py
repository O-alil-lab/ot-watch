"""Tests du câblage DevOps v1.15 : workflow GHCR, script de setup GitHub, import Linear, ADR."""
import importlib.util
import io
import os
import subprocess
import unittest
from contextlib import redirect_stdout

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_linear():
    spec = importlib.util.spec_from_file_location("linear_import", os.path.join(ROOT, "scripts", "linear_import.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDockerWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, ".github", "workflows", "docker.yml"), encoding="utf-8") as fh:
            cls.wf = yaml.safe_load(fh)

    def test_jobs_separes_et_permissions_minimales(self):
        jobs = self.wf["jobs"]
        self.assertEqual(jobs["scan"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["push"]["permissions"].get("packages"), "write")
        self.assertEqual(jobs["push"]["needs"], "scan")
        self.assertEqual(self.wf["permissions"], {"contents": "read"})

    def test_ghcr_via_github_token(self):
        steps = self.wf["jobs"]["push"]["steps"]
        login = next(s for s in steps if str(s.get("uses", "")).startswith("docker/login-action"))
        self.assertEqual(login["with"]["registry"], "ghcr.io")
        self.assertIn("secrets.GITHUB_TOKEN", login["with"]["password"])

    def test_trivy_version_saine_et_isolee(self):
        scan_uses = [s.get("uses", "") for s in self.wf["jobs"]["scan"]["steps"]]
        push_uses = [s.get("uses", "") for s in self.wf["jobs"]["push"]["steps"]]
        trivy = [u for u in scan_uses if u.startswith("aquasecurity/trivy-action@")]
        self.assertEqual(len(trivy), 1)
        ver = trivy[0].split("@", 1)[1]
        # <= v0.34.2 compromis (CVE-2026-33634) ; accepter v0.35.0+ ou un SHA de 40 caractères
        if len(ver) != 40:
            major_minor = tuple(int(x) for x in ver.lstrip("v").split(".")[:2])
            self.assertGreaterEqual(major_minor, (0, 35))
        self.assertFalse(any("trivy" in u for u in push_uses))

    def test_pas_de_push_sur_pr(self):
        self.assertIn("pull_request", self.wf["jobs"]["push"]["if"])


class TestDockerfile(unittest.TestCase):
    def test_non_root_et_healthcheck(self):
        with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
            df = fh.read()
        self.assertIn("USER otwatch", df)
        self.assertIn("HEALTHCHECK", df)


class TestGithubSetup(unittest.TestCase):
    SCRIPT = os.path.join(ROOT, "scripts", "github-setup.sh")

    def _run(self, repo):
        env = {**os.environ, "GITHUB_REPO": repo, "DRY_RUN": "1"}
        return subprocess.run(["bash", self.SCRIPT], capture_output=True, text=True, env=env)

    def test_refuse_sans_variable(self):
        r = self._run("")
        self.assertEqual(r.returncode, 1)
        self.assertIn("GITHUB_REPO", r.stderr)

    def test_refuse_valeur_invalide(self):
        r = self._run("pas un repo; rm -rf x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("invalide", r.stderr)


class TestLinearImport(unittest.TestCase):
    SAMPLE = (
        "## 1. Sources — P0\n"
        "- **P0 · NVD par CPE** : utiliser le dictionnaire CPE.\n"
        "- **P1 · Santé par source** : badge.\n"
        "texte libre ignoré\n"
        "## 2. Divers\n"
        "- **P2 · Archives** : page d'archives.\n"
    )

    def setUp(self):
        self.li = _load_linear()

    def test_parse_priorites(self):
        items = self.li.parse_roadmap(self.SAMPLE)
        self.assertEqual([i["priority"] for i in items], [1, 2, 3])
        self.assertEqual(items[0]["title"], "[P0] NVD par CPE")
        self.assertIn("Sources", items[0]["description"])

    def test_dry_run_sans_reseau_ni_cle(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.li.main([], environ={})
        self.assertEqual(rc, 0)
        self.assertIn("[dry-run]", buf.getvalue())

    def test_apply_exige_les_variables(self):
        rc = self.li.main(["--apply"], environ={})
        self.assertEqual(rc, 1)

    def test_plafond_free(self):
        rc = self.li.main(["--max", "1"], environ={})
        self.assertEqual(rc, 1)


class TestAdr(unittest.TestCase):
    def test_adr_present_et_source(self):
        path = os.path.join(ROOT, "docs", "adr", "ADR-2026-11-01-remote-github-linear-ghcr.md")
        with open(path, encoding="utf-8") as fh:
            txt = fh.read()
        for k in ("GHCR", "Linear", "CVE-2026-33634", "## Sources"):
            self.assertIn(k, txt)


class TestServerEnvBinding(unittest.TestCase):
    def test_host_port_lus_depuis_env(self):
        with open(os.path.join(ROOT, "server.py"), encoding="utf-8") as fh:
            srv = fh.read()
        for var in ('"OTWATCH_HOST"', '"OTWATCH_PORT"', '"PORT"'):
            self.assertIn(var, srv)


if __name__ == "__main__":
    unittest.main()
