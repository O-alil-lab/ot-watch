"""Tests serveur TAXII 2.1 read-only (src/taxii.py) : discovery, collections, objects, manifest,
added_after, 405 POST, auth Bearer optionnelle."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import stix  # noqa: E402
import taxii  # noqa: E402

CVES = [
    {"id": "CVE-2026-110936", "cvss": 8.4, "severity": "HIGH", "kev": True, "epss": 0.4, "risk": 6.23,
     "relevant": True, "ssvc": "act", "attack_ics": ["T0885"], "vector": "NETWORK",
     "published": "2026-10-20T00:00:00.000Z", "lastModified": "2026-10-30T00:00:00.000Z",
     "description": "Siemens.", "refs": []},
    {"id": "CVE-2026-63350", "cvss": 9.6, "severity": "CRITICAL", "kev": False, "epss": 0.01, "risk": 5.1,
     "relevant": True, "ssvc": "act", "attack_ics": [], "vector": "NETWORK",
     "published": "2026-09-01T00:00:00.000Z", "lastModified": "2026-09-02T00:00:00.000Z",
     "description": "Ancien.", "refs": []},
]


class TestTaxii(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = stix.build_bundle(CVES, [], {"generated_at": "2026-10-31T23:00:00+00:00", "window_days": 14}, "2026-10-31")

    def test_discovery(self):
        st, body, ct = taxii.handle("/taxii2/")
        self.assertEqual(st, 200)
        self.assertIn("application/taxii+json", ct)
        d = json.loads(body)
        self.assertIn("2.1", d["versions"])
        self.assertEqual(d["default"], "/taxii2/")

    def test_collections_readonly(self):
        st, body, _ = taxii.handle("/taxii2/collections")
        cols = json.loads(body)["collections"]
        self.assertEqual(cols[0]["id"], taxii.COLLECTION_ID)
        self.assertTrue(cols[0]["can_read"])
        self.assertFalse(cols[0]["can_write"])

    def test_objects_envelope(self):
        env = taxii.objects_envelope(self.bundle)
        self.assertFalse(env["more"])
        types = {o["type"] for o in env["objects"]}
        self.assertIn("vulnerability", types)
        self.assertIn("report", types)

    def test_added_after_filter(self):
        env = taxii.objects_envelope(self.bundle, added_after="2026-10-01T00:00:00.000Z")
        ids = [o.get("name", o["id"]) for o in env["objects"]]
        self.assertIn("CVE-2026-110936", ids)
        self.assertNotIn("CVE-2026-63350", ids)  # modifié en septembre -> exclu

    def test_manifest_versions(self):
        m = taxii.manifest(self.bundle)["manifest"]
        self.assertTrue(all(e["id"] and e["version"] and e["media_type"] == "application/stix+json" for e in m))
        v = taxii.versions(self.bundle)
        self.assertIn("2026-10-30T00:00:00.000Z", v)

    def test_method_not_allowed(self):
        st, _, ct = taxii.handle("/taxii2/collections/x/objects", method="POST")
        self.assertEqual(st, 405)
        self.assertIn("application/taxii+json", ct)

    def test_token_auth(self):
        env = {"OTWATCH_TAXII_TOKEN": "tok123"}
        st, _, _ = taxii.handle("/taxii2/", headers={}, environ=env)
        self.assertEqual(st, 401)
        st, _, _ = taxii.handle("/taxii2/", headers={"Authorization": "Bearer tok123"}, environ=env)
        self.assertEqual(st, 200)
        st, _, _ = taxii.handle("/taxii2/", headers={}, environ={})
        self.assertEqual(st, 200)  # sans token -> ouvert (TLP:WHITE)

    def test_404_unknown(self):
        st, _, _ = taxii.handle("/taxii2/collections/nope/objects")
        self.assertEqual(st, 404)

    def test_sans_dossier_out(self):
        """Clone neuf / CI : out/ absent -> discovery 200, objects 404 propre (pas d'exception)."""
        self.assertIsNone(taxii.load_latest_bundle("/chemin/inexistant/out"))
        orig = taxii.OUT
        try:
            taxii.load_latest_bundle.__defaults__ = ("/chemin/inexistant/out",)
            st, _, _ = taxii.handle("/taxii2/")
            self.assertEqual(st, 200)
            st, _, _ = taxii.handle(f"/taxii2/collections/{taxii.COLLECTION_ID}/objects")
            self.assertEqual(st, 404)
        finally:
            taxii.load_latest_bundle.__defaults__ = (orig,)


if __name__ == "__main__":
    unittest.main()
