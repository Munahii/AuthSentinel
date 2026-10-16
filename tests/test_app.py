"""Dashboard API tests; no third-party dependencies."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import Handler


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.root = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_demo_api_has_all_three_patterns(self):
        with urlopen(self.root + "/api/sample", timeout=5) as response:
            payload = json.load(response)
        self.assertGreater(payload["summary"]["total"], 200)
        self.assertEqual(
            {record["detection"] for record in payload["findings"]},
            {"Brute Force", "Password Spraying", "Success After Failures"},
        )

    def test_custom_csv(self):
        body = b"timestamp,ip_address,username,status\n2026-01-01T12:00:00Z,203.0.113.1,test,success\n"
        req = Request(self.root + "/api/analyze", data=body, method="POST", headers={"Content-Type": "text/csv"})
        with urlopen(req, timeout=5) as response:
            payload = json.load(response)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["findings"], 0)

    def test_missing_csv_column_is_rejected(self):
        body = b"timestamp,ip_address,username\n2026-01-01T12:00:00Z,203.0.113.1,test\n"
        req = Request(self.root + "/api/analyze", data=body, method="POST", headers={"Content-Type": "text/csv"})
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 422)

    def test_html_dashboard_is_served(self):
        with urlopen(self.root, timeout=5) as response:
            self.assertIn(b"AuthSentinel", response.read())
            self.assertIn("text/html", response.headers["Content-Type"])


if __name__ == "__main__":
    unittest.main()
