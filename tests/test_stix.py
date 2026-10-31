"""Tests export STIX 2.1 (src/stix.py) — bundle OASIS valide, IDs déterministes, refs MITRE/NVD/KEV."""
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import stix  # noqa: E402

CVES = [
    {"id": "CVE-2026-110936", "cvss": 8.4, "severity": "HIGH", "kev": True, "epss": 0.42, "risk": 6.23,
     "relevant": True, "ssvc": "act", "attack_ics": ["T0885"], "vector": "NETWORK",
     "published": "2026-10-20T00:00:00.000Z", "lastModified": "2026-10-25T00:00:00.000Z",
     "description": "Siemens Software Center — DLL hijacking.", "refs": ["https://cert-portal.siemens.com/x.html"]},
    {"id": "CVE-2026-63350", "cvss": 9.6, "severity": "CRITICAL", "kev": False, "epss": 0.01, "risk": 5.1,
     "relevant": True, "ssvc": "act", "attack_ics": ["T0843"], "vector": "NETWORK",
     "published": "2026-10-22T14:17:37.190Z", "lastModified": "2026-10-23T00:00:00.000Z",
     "description": "Program download to PLC.", "refs": []},
]
ADVISORIES = [{"code": "ICSA-26-295-03", "title": "Siemens SIMATIC", "published": "2026-10-22T14:00:00",
               "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-03", "summary": "Avis ICS."}]
META = {"generated_at": "2026-10-31T23:07:57+00:00", "window_days": 14}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class TestStixBundle(unittest.TestCase):
    def setUp(self):
        self.bundle = stix.build_bundle(CVES, ADVISORIES, META, "2026-10-31")

    def test_bundle_structure(self):
        b = self.bundle
        self.assertEqual(b["type"], "bundle")
        self.assertTrue(UUID_RE.match(b["id"].split("--")[1]))
        types = [o["type"] for o in b["objects"]]
        self.assertIn("marking-definition", types)
        self.assertEqual(types.count("vulnerability"), 2)
        self.assertEqual(types.count("course-of-action"), 1)
        self.assertEqual(types.count("report"), 1)

    def test_vulnerability_sdo(self):
        v = next(o for o in self.bundle["objects"] if o["type"] == "vulnerability" and o["name"] == "CVE-2026-110936")
        self.assertEqual(v["spec_version"], "2.1")
        self.assertTrue(UUID_RE.match(v["id"].split("--")[1]))
        self.assertEqual(v["created"], "2026-10-20T00:00:00.000Z")
        srcs = {e["source_name"]: e.get("external_id") for e in v["external_references"]}
        self.assertEqual(srcs["NVD"], "CVE-2026-110936")
        self.assertEqual(srcs["CISA KEV"], "CVE-2026-110936")
        self.assertEqual(srcs["mitre-attack"], "T0885")
        self.assertIn("https://attack.mitre.org/techniques/T0885/", v["external_references"][2]["url"])
        self.assertEqual(v["x_otwatch_ssvc"], "act")
        self.assertEqual(v["x_otwatch_attack_ics"], ["T0885"])
        self.assertEqual(v["x_otwatch_relevant"], True)
        self.assertTrue(v["object_marking_refs"])

    def test_tlp_white(self):
        m = next(o for o in self.bundle["objects"] if o["type"] == "marking-definition")
        self.assertEqual(m["definition"], {"tlp": "white"})
        self.assertEqual(m["definition_type"], "tlp")

    def test_report_refs(self):
        r = next(o for o in self.bundle["objects"] if o["type"] == "report")
        self.assertEqual(len(r["object_refs"]), 3)  # 2 vuln + 1 COA
        self.assertIn("threat-report", r["report_types"])

    def test_ids_deterministes(self):
        b2 = stix.build_bundle(CVES, ADVISORIES, META, "2026-10-31")
        self.assertEqual(self.bundle["id"], b2["id"])
        v1 = next(o for o in self.bundle["objects"] if o["type"] == "vulnerability")
        v2 = next(o for o in b2["objects"] if o["type"] == "vulnerability")
        self.assertEqual(v1["id"], v2["id"])

    def test_json_serialisable(self):
        json.dumps(self.bundle, ensure_ascii=False)

    def test_latest_issue_stix(self):
        import server  # noqa: E402
        if os.path.exists(os.path.join(stix.OUT, "issue-2026-10-31.stix.json")):
            res = server.latest_issue_stix()
            self.assertIsNotNone(res)
            self.assertEqual(res[0][:1], b"{")
            self.assertTrue(res[1].endswith(".stix.json"))


if __name__ == "__main__":
    unittest.main()
