"""Tests collecte passive (P1 runbook) : parsing Zeek conn.log -> actifs OT découverts + anomalies."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import netwatch  # noqa: E402

CONN_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-11-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]
1762041600.000000\tCabc123\t10.10.3.10\t51234\t10.10.1.5\t502\ttcp\tmodbus\t1.0\t120\t240\tSF\tT\tT\t0\tShADadFf\t10\t400\t8\t380\t-
1762041601.000000\tCabc124\t10.10.3.10\t51235\t10.10.1.5\t502\ttcp\tmodbus\t0.5\t60\t120\tSF\tT\tT\t0\tShADadFf\t5\t200\t4\t190\t-
1762041602.000000\tCabc125\t10.10.3.11\t49152\t10.10.1.8\t102\ttcp\ts7comm\t2.0\t300\t900\tSF\tT\tT\t0\tShADadFf\t12\t600\t20\t1100\t-
1762041603.000000\tCudp1\t10.10.3.10\t0\t10.10.1.5\t502\tudp\t-\t0\t0\t0\tS0\tT\tT\t0\t-\t0\t0\t0\t0\t-
1762041604.000000\tCabc126\t10.10.3.12\t50000\t10.10.1.9\t4840\ttcp\topcua\t5.0\t1000\t2000\tSF\tT\tT\t0\tShADadFf\t30\t1600\t40\t2600\t-
1762041605.000000\tCabc127\t10.10.3.10\t51236\t192.168.1.50\t443\ttcp\tssl\t3.0\t500\t5000\tSF\tT\tT\t0\tShADadFf\t20\t900\t60\t5600\t-
#close\t2026-11-01-01-00-00
"""


class TestNetwatch(unittest.TestCase):
    def _write_log(self, td, content=CONN_LOG):
        p = os.path.join(td, "conn.log")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_parse_conn_log(self):
        with tempfile.TemporaryDirectory() as td:
            rows = netwatch.parse_conn_log(self._write_log(td))
            self.assertEqual(len(rows), 6)  # 6 lignes de données (hors commentaires)
            self.assertEqual(rows[0]["id.resp_h"], "10.10.1.5")
            self.assertEqual(rows[0]["id.resp_p"], "502")

    def test_summarize_decouverte_actifs_OT(self):
        with tempfile.TemporaryDirectory() as td:
            rows = netwatch.parse_conn_log(self._write_log(td))
            rep = netwatch.summarize(rows, {})
            ips = {a["ip"] for a in rep["assets_discovered"]}
            self.assertEqual(ips, {"10.10.1.5", "10.10.1.8", "10.10.1.9"})  # 443 exclu (pas un port OT)
            s7 = next(a for a in rep["assets_discovered"] if a["ip"] == "10.10.1.8")
            self.assertEqual(s7["services"][0]["proto"], "S7comm (ISO-on-TCP)")
            self.assertEqual(s7["services"][0]["conns"], 1)
            modbus = next(a for a in rep["assets_discovered"] if a["ip"] == "10.10.1.5")
            self.assertEqual(modbus["services"][0]["conns"], 3)  # 2 flux TCP + 1 UDP sur le port 502
            self.assertEqual(rep["stats"]["hosts_OT"], 3)
            self.assertIn(502, rep["stats"]["ports_OT"])
            # sans baseline : tous les hôtes sont des anomalies
            self.assertTrue(any(a["type"] == "nouvel_hote_OT" for a in rep["anomalies"]))

    def test_baseline_supprime_anomalies_connues(self):
        with tempfile.TemporaryDirectory() as td:
            rows = netwatch.parse_conn_log(self._write_log(td))
            base = netwatch.summarize(rows, {})
            rep2 = netwatch.summarize(rows, {}, baseline=base)
            self.assertEqual(rep2["anomalies"], [])
            # nouveau flux : baseline partielle
            base_flows = {"flows": [f for f in base["flows"] if not (f["resp_h"] == "10.10.1.5" and f["resp_p"] == 502)],
                          "assets_discovered": base["assets_discovered"]}
            rep3 = netwatch.summarize(rows, {}, baseline=base_flows)
            self.assertTrue(any(a["type"] == "nouveau_flux_OT" and a["resp_p"] == 502 for a in rep3["anomalies"]))

    def test_run_ecrit_json(self):
        with tempfile.TemporaryDirectory() as td:
            log = self._write_log(td)
            out = os.path.join(td, "netwatch.json")
            rep = netwatch.run(log, out_path=out, cfg={})
            self.assertTrue(os.path.exists(out))
            loaded = json.load(open(out, encoding="utf-8"))
            self.assertEqual(loaded["stats"]["hosts_OT"], rep["stats"]["hosts_OT"])
            self.assertEqual(loaded["sources"], [log])

    def test_ports_ot_surchargeables(self):
        rows = [{"id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.9", "id.resp_p": "9999",
                 "proto": "tcp", "orig_bytes": "10", "resp_bytes": "20"}]
        rep = netwatch.summarize(rows, {"ot_ports": {"9999": {"proto": "Custom OT", "vendor_hint": "X"}}})
        self.assertEqual(len(rep["assets_discovered"]), 1)
        self.assertEqual(rep["assets_discovered"][0]["services"][0]["proto"], "Custom OT")
        # port non OT -> ignoré
        rep2 = netwatch.summarize(rows, {})
        self.assertEqual(rep2["assets_discovered"], [])


if __name__ == "__main__":
    unittest.main()
