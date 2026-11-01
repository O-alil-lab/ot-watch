"""Tests des destinations d'alerte (webhook, Slack, SMTP/SMTPS) — sans réseau, via mocks."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import alerts  # noqa: E402

ALERT = {
    "type": "otwatch_alert", "generated_at": "2026-11-01T00:00:00+00:00",
    "new_critical": [{"id": "CVE-2026-1", "cvss": 9.8, "risk": 9.1, "epss": 0.5, "kev": True,
                      "severity": "CRITICAL", "published": None, "description": "PLC RCE"}],
    "new_kev": ["CVE-2026-1"], "new_advisories": [], "counts": {},
}


class _Resp:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p_logs = mock.patch.object(alerts, "LOGS", self.tmp.name)
        self.p_logs.start()

    def tearDown(self):
        self.p_logs.stop()
        self.tmp.cleanup()

    def test_build_alert_cve_absente_ignoree(self):
        meta = {"diff": {"new_cves": ["CVE-INCONNUE"], "new_kev": []}}
        self.assertIsNone(alerts.build_alert(meta, []))

    def test_post_json_envoie_du_json(self):
        with mock.patch("urllib.request.urlopen", return_value=_Resp()) as uo:
            st = alerts._post_json("https://hooks.example/x", {"a": 1})
        self.assertEqual(st, 202)
        req = uo.call_args[0][0]
        self.assertEqual(json.loads(req.data), {"a": 1})
        self.assertEqual(req.get_header("Content-type"), "application/json")

    def test_webhook_et_slack(self):
        env = {"OTWATCH_WEBHOOK_URL": "https://hooks.example/w", "OTWATCH_SLACK_WEBHOOK": "https://hooks.example/s"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(alerts, "_post_json", return_value=200) as pj:
            res = alerts.send_alert(ALERT)
        self.assertFalse(res["dry_run"])
        self.assertEqual((res["webhook"], res["slack"]), (200, 200))
        slack_payload = pj.call_args_list[1][0][1]
        self.assertIn("CVE-2026-1", slack_payload["text"])
        with open(os.path.join(self.tmp.name, "alerts.jsonl"), encoding="utf-8") as fh:
            self.assertEqual(json.loads(fh.readline())["type"], "otwatch_alert")

    def test_smtp_starttls_avec_login(self):
        env = {"OTWATCH_SMTP_HOST": "smtp.example", "OTWATCH_SMTP_TO": "soc@example", "OTWATCH_SMTP_USER": "u",
               "OTWATCH_SMTP_PASS": "p"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("smtplib.SMTP") as smtp:
            res = alerts.send_alert(ALERT)
        self.assertEqual(res["email"], 250)
        s = smtp.return_value.__enter__.return_value
        s.starttls.assert_called_once()
        s.login.assert_called_once_with("u", "p")
        msg = s.send_message.call_args[0][0]
        self.assertIn("1 nouvelle(s)", msg["Subject"])
        self.assertNotIn("*", msg.get_content())

    def test_smtps(self):
        env = {"OTWATCH_SMTP_HOST": "smtp.example", "OTWATCH_SMTP_TO": "soc@example", "OTWATCH_SMTP_SSL": "1",
               "OTWATCH_SMTP_PORT": "465"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("smtplib.SMTP_SSL") as ssl:
            self.assertEqual(alerts._send_email(ALERT), 250)
        ssl.assert_called_once_with("smtp.example", 465, timeout=20)
        ssl.return_value.__enter__.return_value.login.assert_not_called()

    def test_smtp_sans_destinataire(self):
        with mock.patch.dict(os.environ, {"OTWATCH_SMTP_HOST": "smtp.example"}, clear=True):
            self.assertIsNone(alerts._send_email(ALERT))

    def test_dispatch_erreur_non_bloquante(self):
        meta = {"diff": {"new_cves": ["CVE-2026-1"], "new_kev": []}}
        cves = [{"id": "CVE-2026-1", "severity": "CRITICAL"}]
        with mock.patch.object(alerts, "send_alert", side_effect=OSError("réseau")), \
             mock.patch("builtins.print") as pr:
            alerts.dispatch(meta, cves)  # ne doit pas lever
        self.assertIn("non bloquante", pr.call_args[0][0])

    def test_dispatch_succes(self):
        meta = {"diff": {"new_cves": ["CVE-2026-1"], "new_kev": []}}
        cves = [{"id": "CVE-2026-1", "severity": "CRITICAL"}]
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("builtins.print") as pr:
            alerts.dispatch(meta, cves)
        self.assertIn("alerte envoyée", pr.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
