#!/usr/bin/env python3
"""Tests v1.18 growth : RSS, sitemap/robots, subscribe (RGPD, dédup), stats, page integrate,
injection SEO hreflang/OG sur les éditions servies, routes live, FUNDING.yml + docs."""
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import growth  # noqa: E402
import server  # noqa: E402


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fixtures import fixture_data_dir  # noqa: E402

_GROWTH_DATA = None


def setUpModule():
    """Jeu de données figé pour tout le module : aucun besoin de data/ local ni de réseau."""
    global _GROWTH_DATA
    _GROWTH_DATA = (growth.DATA,)
    growth.DATA = fixture_data_dir()


def tearDownModule():
    growth.DATA = _GROWTH_DATA[0]

class TestGrowthUnit(unittest.TestCase):
    def test_rss_valide(self):
        feed = growth.rss_feed("https://otwatch.example")
        root = ET.fromstring(feed)  # lève si XML invalide
        self.assertEqual(root.tag, "rss")
        items = root.findall("./channel/item")
        self.assertTrue(items)
        titles = " ".join(i.findtext("title") for i in items)
        self.assertIn("CVE-", titles)

    def test_sitemap_et_robots(self):
        sm = growth.sitemap("https://otwatch.example")
        root = ET.fromstring(sm)
        locs = [u.findtext("{http://www.sitemaps.org/schemas/sitemap/0.9}loc") for u in root]
        self.assertIn("https://otwatch.example/issue.en", locs)
        self.assertIn("https://otwatch.example/feed.xml", locs)
        rb = growth.robots("https://otwatch.example")
        self.assertIn("Sitemap: https://otwatch.example/sitemap.xml", rb)
        self.assertIn("Disallow: /api/refresh", rb)

    def test_subscribe_dedup_et_validation(self):
        with tempfile.TemporaryDirectory() as td:
            f = os.path.join(td, "subs.json")
            ok, msg = growth.subscribe(email="Sec@Example.com ", subs_file=f)
            self.assertTrue(ok, msg)
            ok2, _ = growth.subscribe(email="sec@example.com", subs_file=f)  # même e-mail, casse différente
            self.assertTrue(ok2)
            self.assertEqual(growth.subscriber_count(f), 1)  # dédupliqué
            ok3, _ = growth.subscribe(email="pas-un-email", subs_file=f)
            self.assertFalse(ok3)
            ok4, _ = growth.subscribe(webhook="http://insecure.example", subs_file=f)  # http refusé
            self.assertFalse(ok4)
            ok5, _ = growth.subscribe(webhook="https://soc.example/hook", subs_file=f)
            self.assertTrue(ok5)
            self.assertEqual(growth.subscriber_count(f), 2)
            self.assertTrue(growth.unsubscribe("sec@example.com", subs_file=f))
            self.assertEqual(growth.subscriber_count(f), 1)

    def test_seo_head_hreflang(self):
        block = growth.seo_head("https://x", "en", "/issue.en", "T", "D", "2026-11-01")
        self.assertIn('hreflang="fr"', block)
        self.assertIn('hreflang="ar"', block)
        self.assertIn('hreflang="en"', block)
        self.assertIn('rel="canonical"', block)
        self.assertIn("og:title", block)
        self.assertIn("application/ld+json", block)

    def test_stats_payload(self):
        s = growth.stats_payload()
        for k in ("cves_now", "kev_now", "subscribers", "runs_30d", "assets"):
            self.assertIn(k, s)
        self.assertGreaterEqual(s["cves_now"], 1)

    def test_integrate_page(self):
        doc = growth.integrate_html("https://x")
        self.assertIn("/taxii2/collections", doc)
        self.assertIn("/subscribe", doc)
        self.assertIn("ISAGCA", doc)

    def test_funding_et_docs(self):
        for p in ("FUNDING.yml", "docs/MONETIZATION.md", "docs/COMMUNITY.md"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, p)), p)
        with open(os.path.join(ROOT, "FUNDING.yml"), encoding="utf-8") as fh:
            self.assertIn("MONETIZATION.md", fh.read())


class TestGrowthLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # éditions isolées : copie de out/ + édition EN générée depuis le jeu figé (pas d'artefact local requis)
        import shutil
        import tempfile
        from unittest import mock

        import render_en
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        cls._tmp = tempfile.TemporaryDirectory()
        out = os.path.join(cls._tmp.name, "out")
        shutil.copytree(os.path.join(server.ROOT, "out"), out)
        data = growth.DATA
        load = lambda n: json.load(open(os.path.join(data, n), encoding="utf-8"))  # noqa: E731
        with open(os.path.join(out, "issue-2026-10-31.en.html"), "w", encoding="utf-8") as fh:
            fh.write(render_en.render_en_html("2026-10-31", load("cves.json"), load("cisa_advisories.json"),
                                              load("kev.json"), load("meta.json")))
        cls._patches = [mock.patch.object(server, "OUT", out), mock.patch.object(server, "DATA", data)]
        for p in cls._patches:
            p.start()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for p in cls._patches:
            p.stop()
        cls._tmp.cleanup()

    def req(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": ctype} if body is not None else {}
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        ctype_r = r.getheader("Content-Type")
        c.close()
        return r.status, data, ctype_r

    def test_feed_sitemap_robots(self):
        code, body, ct = self.req("GET", "/feed.xml")
        self.assertEqual(code, 200)
        self.assertIn("rss", ct)
        self.assertIn(b"CVE-", body)
        code, body, _ = self.req("GET", "/sitemap.xml")
        self.assertEqual(code, 200)
        self.assertIn(b"/issue.en", body)
        code, body, _ = self.req("GET", "/robots.txt")
        self.assertEqual(code, 200)
        self.assertIn(b"Sitemap:", body)

    def test_integrate_stats(self):
        code, body, _ = self.req("GET", "/integrate")
        self.assertEqual(code, 200)
        self.assertIn(b"TAXII", body)
        code, body, _ = self.req("GET", "/stats")
        self.assertEqual(code, 200)
        self.assertIn("abonn", body.decode("utf-8"))

    def test_subscribe_live(self):
        with tempfile.TemporaryDirectory() as td:
            old = growth._subs_file
            growth._subs_file = lambda: os.path.join(td, "subs.json")
            try:
                payload = json.dumps({"email": "live-test@example.com"}).encode()
                code, body, _ = self.req("POST", "/subscribe", body=payload)
                self.assertEqual(code, 200, body)
                self.assertTrue(json.loads(body)["ok"])
                code, body, _ = self.req("POST", "/subscribe", body=json.dumps({"email": "bad"}).encode())
                self.assertEqual(code, 400)
                code, body, _ = self.req("GET", "/api/subscribers")
                self.assertEqual(json.loads(body)["subscribers"], 1)
            finally:
                growth._subs_file = old

    def test_issue_en_seo_injecte(self):
        code, body, _ = self.req("GET", "/issue.en")
        self.assertEqual(code, 200)
        txt = body.decode("utf-8")
        self.assertIn('hreflang="en"', txt)
        self.assertIn('hreflang="ar"', txt)
        self.assertIn('og:title', txt)
        self.assertIn('rel="canonical"', txt)

    def test_dashboard_boutons_growth(self):
        code, body, _ = self.req("GET", "/")
        self.assertEqual(code, 200)
        for b in (b"/feed.xml", b"/integrate", b"/stats", b"subForm"):
            self.assertIn(b, body)


if __name__ == "__main__":
    unittest.main()
