#!/usr/bin/env python3
"""Test du push SSE : un client connecté reçoit l'événement broadcast en temps réel."""
import json
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
import server  # noqa: E402


class TestSSE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_sse_connected_puis_broadcast_recu(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        sock.sendall(b"GET /api/stream HTTP/1.1\r\nHost: x\r\n\r\n")
        f = sock.makefile("rb")
        # lire l'en-tête HTTP
        status = f.readline().decode()
        self.assertIn("200", status)
        headers = {}
        while True:
            line = f.readline().decode().strip()
            if not line:
                break
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        self.assertIn("text/event-stream", headers.get("content-type", ""))
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")

        first = f.readline().decode()  # data: {"type":"connected"}
        self.assertIn('"connected"', first)
        f.readline()  # ligne vide

        # broadcast -> le client doit recevoir l'event immédiatement
        server.broadcast({"type": "collected", "diff": {"new_cves": ["CVE-2026-TEST"]}, "counts": {"cves": 1}})
        line = f.readline().decode()
        self.assertTrue(line.startswith("data: "))
        ev = json.loads(line[6:])
        self.assertEqual(ev["type"], "collected")
        self.assertEqual(ev["diff"]["new_cves"], ["CVE-2026-TEST"])
        sock.close()


if __name__ == "__main__":
    unittest.main()
