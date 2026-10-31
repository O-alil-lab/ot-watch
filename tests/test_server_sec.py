#!/usr/bin/env python3
"""Tests sécurité du serveur live : en-têtes, /metrics, auth token, rate-limit."""
import http.client
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
import server  # noqa: E402


class TestServerSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        hdrs = dict(r.getheaders())
        c.close()
        return r.status, hdrs, body

    def test_security_headers(self):
        code, hdrs, _ = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertEqual(hdrs.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(hdrs.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", hdrs.get("Content-Security-Policy", ""))
        self.assertEqual(hdrs.get("Referrer-Policy"), "no-referrer")

    def test_metrics_prometheus(self):
        code, hdrs, body = self.req("GET", "/metrics")
        self.assertEqual(code, 200)
        txt = body.decode()
        self.assertIn("otwatch_up 1", txt)
        self.assertIn("otwatch_cves_total", txt)
        self.assertIn("otwatch_stale", txt)
        self.assertIn("otwatch_data_freshness_seconds", txt)

    def test_refresh_sans_token_quand_env_set(self):
        with mock.patch.dict(os.environ, {"OTWATCH_ADMIN_TOKEN": "secret123"}):
            code, _, _ = self.req("POST", "/api/refresh")
            self.assertEqual(code, 401)
            code, _, body = self.req("POST", "/api/refresh", headers={"Authorization": "Bearer secret123"})
            self.assertIn(code, (200, 429))  # 200 si kolekce démarre, 429 si rate-limit

    def test_refresh_rate_limit(self):
        server._state["last_refresh_start"] = time.time()  # simule un refresh récent
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OTWATCH_ADMIN_TOKEN", None)
            code, _, body = self.req("POST", "/api/refresh")
            self.assertEqual(code, 429)
            self.assertIn("rate_limited", body.decode())
        server._state["last_refresh_start"] = 0.0

    def test_api_history(self):
        code, _, body = self.req("GET", "/api/history")
        self.assertEqual(code, 200)
        h = json.loads(body)["history"]
        self.assertEqual(len(h), 30)
        self.assertIn("total", h[0])
        self.assertIn("critical", h[0])
        self.assertIn("kev_added", h[0])

    def test_api_data_a_relevant(self):
        code, _, body = self.req("GET", "/api/data")
        d = json.loads(body)
        self.assertTrue(all("relevant" in c for c in d["cves"]) or d["cves"] == [])

    def test_api_meta_contient_stale(self):
        code, _, body = self.req("GET", "/api/meta")
        d = json.loads(body)
        self.assertIn("stale", d)
        self.assertIn("freshness_seconds", d)


if __name__ == "__main__":
    unittest.main()
