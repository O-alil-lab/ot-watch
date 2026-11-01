"""Routes de lecture du serveur sur le jeu figé : chaque export répond, avec le bon type de contenu."""
import http.client
import json
import os
import sys
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402
from _fixtures import fixture_data_dir  # noqa: E402


class TestServerRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._data = mock.patch.object(server, "DATA", fixture_data_dir())
        cls._data.start()
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._data.stop()

    def get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, r.getheader("Content-Type") or "", body

    def test_edition_html(self):
        st, ct, body = self.get("/issue")
        self.assertEqual(st, 200)
        self.assertIn("text/html", ct)
        self.assertIn(b"CVE-", body)

    def test_exports_non_generes_404_explicite(self):
        """AR, MISP et netwatch n'existent qu'après collecte : 404 JSON avec message, pas de crash."""
        for path in ("/issue.ar", "/misp", "/api/netwatch"):
            st, _, body = self.get(path)
            self.assertEqual(st, 404, path)
            self.assertIn("error", json.loads(body), path)

    def test_edition_pdf(self):
        st, ct, body = self.get("/issue.pdf")
        self.assertEqual(st, 200)
        self.assertIn("application/pdf", ct)
        self.assertTrue(body.startswith(b"%PDF"))

    def test_stix_bundle(self):
        st, _, body = self.get("/stix")
        self.assertEqual(st, 200)
        b = json.loads(body)
        self.assertEqual(b["type"], "bundle")
        self.assertTrue(any(o["type"] == "vulnerability" for o in b["objects"]))

    def test_assets_openapi_index(self):
        for path in ("/api/assets", "/openapi.json", "/index.html"):
            st, _, body = self.get(path)
            self.assertEqual(st, 200, path)
            self.assertTrue(body, path)
        spec = json.loads(self.get("/openapi.json")[2])
        self.assertEqual(spec["openapi"], "3.1.0")

    def test_taxii_via_serveur(self):
        st, ct, body = self.get("/taxii2/collections")
        self.assertEqual(st, 200)
        self.assertIn("application/taxii+json", ct)
        self.assertEqual(json.loads(body)["collections"][0]["id"], "otwatch-ot-cves")


if __name__ == "__main__":
    unittest.main()
