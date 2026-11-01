"""Tests pipeline agents IA éditoriaux (agents/) : analyste RAG, rédacteur, fact-checker 3 niveaux,
illustrateur SVG data-driven, gate HITL de publication."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agents import factcheck, images, pipeline, rag, writer  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fixtures import fixture_data_dir  # noqa: E402

DATA = fixture_data_dir()  # jeu figé, indépendant de data/ et du réseau
DB = os.path.join(DATA, "otwatch.db")


@unittest.skipUnless(os.path.exists(os.path.join(DATA, "cves.json")), "data/ requis")
class TestAnalystRag(unittest.TestCase):
    def setUp(self):
        self.brief = rag.build_brief(DATA, DB)

    def test_brief_structure(self):
        b = self.brief
        self.assertTrue(b["top_cves"])
        self.assertEqual(len(b["trends"]["history"]), 30)
        top = b["top_cves"][0]
        self.assertTrue(top["id"].startswith("CVE-"))
        self.assertTrue(any("nvd.nist.gov" in u for u in top["citations"]))

    def test_brief_citations_kev(self):
        kev_cves = [c for c in self.brief["top_cves"] if c["kev"]]
        for c in kev_cves:
            self.assertTrue(any("cisa.gov" in u and "known-exploited" in u for u in c["citations"]))


class TestWriter(unittest.TestCase):
    def setUp(self):
        self.brief = rag.build_brief(DATA, DB)
        self.article = writer.write_article(self.brief)

    def test_article_structure(self):
        self.assertIn("title:", self.article)
        self.assertIn("---", self.article)
        self.assertRegex(self.article, r"CVE-\d{4}-\d{4,7}")

    def test_disclosure_ai_act(self):
        self.assertIn("revue éditoriale humaine", self.article)
        self.assertIn("art. 50", self.article)

    def test_ot_impact_section_data_grounded(self):
        """v1.17 : chaque CVE prioritaire a une section 'impact OT' calculée depuis le brief."""
        self.assertIn("Pourquoi cela compte pour l'OT", self.article)
        top = self.brief["top_cves"][0]
        if top.get("ot_score") is not None:
            self.assertIn(f"score OT {top['ot_score']:.1f}/10", self.article)
        if top.get("asset_impact"):
            self.assertIn(", ".join(top["asset_impact"]), self.article)

    def test_article_en(self):
        """v1.17 : édition anglaise (lang='en'), dir ltr implicite, mêmes données."""
        art = writer.write_article(self.brief, lang="en")
        self.assertIn("OT/ICS Threat Watch", art)
        self.assertIn("Why this matters for OT", art)
        self.assertIn("EU AI Act, art. 50", art)
        self.assertRegex(art, r"CVE-\d{4}-\d{4,7}")
        rep = factcheck.check_draft(art, self.brief, DATA)
        self.assertTrue(rep["ok"], rep["failed"])

    def test_brief_ot_fields(self):
        """v1.17 : le brief RAG expose ot_score / ot_score_detail / asset_impact."""
        top = self.brief["top_cves"][0]
        self.assertIn("ot_score", top)
        self.assertIn("ot_score_detail", top)
        self.assertIn("asset_impact", top)
        self.assertIn("new_kev_facts", self.brief)


class TestFactcheck(unittest.TestCase):
    def setUp(self):
        self.brief = rag.build_brief(DATA, DB)
        self.article = writer.write_article(self.brief)

    def test_clean_draft_ok(self):
        rep = factcheck.check_draft(self.article, self.brief, DATA)
        self.assertTrue(rep["ok"], rep["failed"])
        self.assertGreater(rep["checked"], 0)
        self.assertTrue(any("humaine" in h["reason"] for h in rep["human_review"]))

    def test_fabricated_cve_flagged(self):
        bad = self.article.replace(self.brief["top_cves"][0]["id"], "CVE-9999-99999")
        rep = factcheck.check_draft(bad, self.brief, DATA)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("CVE-9999-99999" in f["claim"] for f in rep["failed"]))

    def test_fake_kev_flagged(self):
        c = self.brief["top_cves"][-1]["id"]
        bad = self.article + f"\n- {c} ★ KEV confirmée\n"
        rep = factcheck.check_draft(bad, self.brief, DATA)
        if c.upper() not in {k.get("cveID", "").upper() for k in factcheck.load_json(DATA, "kev.json", [])}:
            self.assertFalse(rep["ok"])

    def test_bad_citation_host_flagged(self):
        bad = self.article + "\nVoir https://evil.example.com/poc\n"
        rep = factcheck.check_draft(bad, self.brief, DATA)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("evil.example.com" in f["claim"] for f in rep["failed"]))


class TestImages(unittest.TestCase):
    def test_svgs_data_driven(self):
        brief = rag.build_brief(DATA, DB)
        with tempfile.TemporaryDirectory() as td:
            imgs = images.generate_svgs(brief, td)
            self.assertGreaterEqual(len(imgs), 2)
            for im in imgs:
                with open(os.path.join(td, im["file"]), encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("<svg", content)
                self.assertIn("provenance", content)
                self.assertFalse(im["ai_generated"])


class TestPipelineGate(unittest.TestCase):
    def test_draft_then_hitl_publish(self):
        with tempfile.TemporaryDirectory() as td:
            drafts = os.path.join(td, "drafts")
            edito = os.path.join(td, "editorial")
            ddir, rep = pipeline.run_draft(date="2026-11-01", data_dir=DATA, db_path=DB, drafts_dir=drafts)
            self.assertTrue(os.path.exists(os.path.join(ddir, "brief.json")))
            self.assertTrue(os.path.exists(os.path.join(ddir, "article.md")))
            self.assertTrue(os.path.exists(os.path.join(ddir, "factcheck.json")))
            # publish refusé sans .approved (HITL)
            with self.assertRaises(SystemExit):
                pipeline.publish("draft-2026-11-01", "", drafts_dir=drafts, editorial_dir=edito)
            # approuvé -> publie dans editorial/
            with open(os.path.join(drafts, "draft-2026-11-01.approved"), "w", encoding="utf-8") as fh:
                fh.write("A. Reviewer")
            dest = pipeline.publish("draft-2026-11-01", "A. Reviewer", drafts_dir=drafts, editorial_dir=edito)
            self.assertTrue(os.path.exists(dest))
            self.assertIn("auto-2026-11-01.md", dest)

    def test_publish_blocked_on_factcheck_ko(self):
        with tempfile.TemporaryDirectory() as td:
            drafts = os.path.join(td, "drafts")
            edito = os.path.join(td, "editorial")
            ddir, _ = pipeline.run_draft(date="2026-11-02", data_dir=DATA, db_path=DB, drafts_dir=drafts)
            # corrompre le factcheck
            with open(os.path.join(ddir, "factcheck.json"), encoding="utf-8") as fh:
                fc = json.load(fh)
            fc["ok"] = False
            fc["failed"] = [{"claim": "CVE-9999-99999", "reason": "hallucination"}]
            with open(os.path.join(ddir, "factcheck.json"), "w", encoding="utf-8") as fh:
                json.dump(fc, fh)
            with open(os.path.join(drafts, "draft-2026-11-02.approved"), "w", encoding="utf-8") as fh:
                fh.write("A. Reviewer")
            with self.assertRaises(SystemExit):
                pipeline.publish("draft-2026-11-02", "A. Reviewer", drafts_dir=drafts, editorial_dir=edito)


if __name__ == "__main__":
    unittest.main()
