#!/usr/bin/env python3
"""Tests du serveur live (ECC verification-loop) : démarre le serveur sur port éphémère, requêtes réelles."""
import http.client
import json
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
import server  # noqa: E402


class TestLiveServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def test_dashboard_html(self):
        code, body = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"OT Watch", body)
        self.assertIn(b"/api/data", body)  # le front appelle la vraie API

    def test_api_data_contient_vraies_donnees(self):
        code, body = self.req("GET", "/api/data")
        self.assertEqual(code, 200)
        d = json.loads(body)
        for k in ("meta", "cves", "advisories", "kev", "articles", "server_time", "collecting"):
            self.assertIn(k, d)
        # données réelles collectées (pas de démo) : la meta porte un timestamp réel
        self.assertTrue(d["meta"].get("generated_at"))
        self.assertGreater(len(d["cves"]), 0)
        self.assertGreater(len(d["articles"]), 0)

    def test_api_meta(self):
        code, body = self.req("GET", "/api/meta")
        self.assertEqual(code, 200)
        d = json.loads(body)
        self.assertIn("auto_interval_seconds", d)

    def test_refresh_declenche_collecte(self):
        import time
        with mock.patch.object(server, "run_collect", return_value=True) as m:
            code, body = self.req("POST", "/api/refresh")
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)["status"], "started")  # réponse immédiate
            for _ in range(40):
                if m.called:
                    break
                time.sleep(0.05)
            m.assert_called_once()  # la collecte tourne bien en arrière-plan

    def test_404(self):
        code, _ = self.req("GET", "/nope")
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
