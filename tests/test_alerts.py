#!/usr/bin/env python3
"""Tests du module d'alerting (build_alert, dry-run JSONL, webhook mocké)."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import alerts  # noqa: E402

META = {
    "generated_at": "2026-10-31T23:00:00+00:00",
    "counts": {"cves": 22, "advisories": 5, "kev_ot": 13},
    "diff": {"new_cves": ["CVE-2026-A", "CVE-2026-B"], "new_advisories": ["ICSA-26-1"], "new_kev": ["CVE-2026-A"]},
}
CVES = [
    {"id": "CVE-2026-A", "severity": "CRITICAL", "kev": True, "cvss": 9.8, "risk": 9.6, "epss": 0.9, "description": "x"},
    {"id": "CVE-2026-B", "severity": "LOW", "kev": False, "cvss": 3.0, "risk": 1.5, "epss": 0.001, "description": "y"},
]


class TestBuildAlert(unittest.TestCase):
    def test_alerte_si_cve_critique_ou_kev(self):
        a = alerts.build_alert(META, CVES)
        self.assertIsNotNone(a)
        self.assertEqual([c["id"] for c in a["new_critical"]], ["CVE-2026-A"])  # B est LOW -> exclue
        self.assertEqual(a["new_kev"], ["CVE-2026-A"])

    def test_pas_alerte_si_rien_de_critique(self):
        meta = {"diff": {"new_cves": ["CVE-2026-B"], "new_kev": []}}
        self.assertIsNone(alerts.build_alert(meta, CVES))

    def test_alerte_si_nouveau_kev_seul(self):
        meta = {"diff": {"new_cves": [], "new_kev": ["CVE-2026-Z"]}}
        a = alerts.build_alert(meta, CVES)
        self.assertIsNotNone(a)
        self.assertEqual(a["new_kev"], ["CVE-2026-Z"])


class TestSendAlert(unittest.TestCase):
    def test_dry_run_log_jsonl_sans_destination(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(alerts, "LOGS", tmp), \
             mock.patch.dict(os.environ, {}, clear=True):
            a = alerts.build_alert(META, CVES)
            res = alerts.send_alert(a)
            self.assertTrue(res["dry_run"])
            self.assertIsNone(res["webhook"])
            lines = open(os.path.join(tmp, "alerts.jsonl"), encoding="utf-8").read().strip().split("\n")
            self.assertEqual(json.loads(lines[-1])["type"], "otwatch_alert")

    def test_webhook_appele_quand_configure(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(alerts, "LOGS", tmp), \
             mock.patch.dict(os.environ, {"OTWATCH_WEBHOOK_URL": "https://hooks.example.com/x"}), \
             mock.patch.object(alerts, "_post_json", return_value=200) as post:
            a = alerts.build_alert(META, CVES)
            res = alerts.send_alert(a)
            self.assertFalse(res["dry_run"])
            self.assertEqual(res["webhook"], 200)
            post.assert_called_once()
            url, payload = post.call_args[0]
            self.assertEqual(url, "https://hooks.example.com/x")
            self.assertEqual(payload["type"], "otwatch_alert")

    def test_slack_payload_text(self):
        a = alerts.build_alert(META, CVES)
        txt = alerts.format_slack(a)
        self.assertIn("CVE-2026-A", txt)
        self.assertIn("★KEV", txt)


if __name__ == "__main__":
    unittest.main()
