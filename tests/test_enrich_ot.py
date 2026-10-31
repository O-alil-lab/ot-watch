"""Tests enrichissement OT : mapping ATT&CK for ICS + décision SSVC (src/enrich_ot.py)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import enrich_ot  # noqa: E402

ATTACK_CFG = {
    "T0843": {"label": "Program Download", "keywords": ["program download", "block download"]},
    "T0885": {"label": "Commonly Used Port", "keywords": ["modbus", "port 502"]},
    "T0880": {"label": "Loss of Safety", "keywords": ["safety instrumented", "emergency shutdown"]},
}
SSVC_CFG = {"epss_poc": 0.1, "automatable_cvss": 9.0, "total_impact_cvss": 9.0,
            "poc_keywords": ["proof of concept", "poc"]}


class TestAttackIcs(unittest.TestCase):
    def test_mapping_techniques(self):
        self.assertEqual(enrich_ot.map_attack_ics("Attackers can perform a program download to the PLC", ATTACK_CFG), ["T0843"])
        self.assertEqual(enrich_ot.map_attack_ics("Exploitable over Modbus on port 502", ATTACK_CFG), ["T0885"])
        self.assertEqual(enrich_ot.map_attack_ics("Nothing relevant here", ATTACK_CFG), [])
        self.assertEqual(enrich_ot.map_attack_ics("Block download then Modbus", ATTACK_CFG), ["T0843", "T0885"])

    def test_enrich_champs(self):
        cves = [{"id": "CVE-2026-1", "description": "program download to PLC", "cvss": 9.8,
                 "vector": "NETWORK", "kev": True, "relevant": True}]
        out, n_tech, n_act = enrich_ot.enrich(cves, {"attack_ics": ATTACK_CFG, "ssvc": SSVC_CFG})
        self.assertEqual(out[0]["attack_ics"], ["T0843"])
        self.assertEqual(out[0]["ssvc"], "act")
        self.assertEqual(n_tech, 1)
        self.assertEqual(n_act, 1)


class TestSsvc(unittest.TestCase):
    def test_kev_act(self):
        d = enrich_ot.ssvc_decision({"kev": True, "cvss": 5.0, "epss": 0.0, "vector": "LOCAL"}, SSVC_CFG)
        self.assertEqual(d["decision"], "act")
        self.assertEqual(d["exploitation"], "active")

    def test_automatable_total_act(self):
        d = enrich_ot.ssvc_decision({"kev": False, "cvss": 9.8, "vector": "NETWORK", "epss": 0.0}, SSVC_CFG)
        self.assertEqual(d["decision"], "act")
        self.assertEqual(d["automatable"], "yes")
        self.assertEqual(d["technical_impact"], "total")

    def test_poc_attend(self):
        d = enrich_ot.ssvc_decision({"kev": False, "cvss": 7.5, "vector": "NETWORK", "epss": 0.5}, SSVC_CFG)
        self.assertEqual(d["decision"], "attend")
        self.assertEqual(d["exploitation"], "poc")

    def test_poc_keyword_attend(self):
        d = enrich_ot.ssvc_decision({"kev": False, "cvss": 6.0, "vector": "LOCAL", "epss": 0.0,
                                     "description": "A proof of concept is available"}, SSVC_CFG)
        self.assertEqual(d["exploitation"], "poc")
        self.assertEqual(d["decision"], "attend")

    def test_relevant_track_star(self):
        d = enrich_ot.ssvc_decision({"kev": False, "cvss": 4.0, "vector": "LOCAL", "epss": 0.0, "relevant": True}, SSVC_CFG)
        self.assertEqual(d["decision"], "track*")
        self.assertEqual(d["mission"], "high")

    def test_low_track(self):
        d = enrich_ot.ssvc_decision({"kev": False, "cvss": 3.0, "vector": "LOCAL", "epss": 0.0}, SSVC_CFG)
        self.assertEqual(d["decision"], "track")


if __name__ == "__main__":
    unittest.main()
