"""Tests for the SunLicense client against a local HTTP server (standard library only).

Run: python -m unittest discover -s tests
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sunlicense import SunLicense, __version__  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    """Answers like api.sunlicense.com behind Cloudflare: the default urllib User-Agent is
    refused at the edge (error 1010, plain text) before the API sees the request."""

    seen = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        _Handler.seen.append({"headers": dict(self.headers), "body": body})
        if self.headers.get("User-Agent", "").startswith("Python-urllib"):
            return self._send(403, "text/plain", b"error code: 1010")
        if self.headers.get("Authorization") != "Bearer good-token":
            return self._send(401, "application/json", b'{"title":"Unauthorized","status":401}')
        valid = body.get("license") == "GOOD-KEY"
        payload = {"valid": valid, "code": "VALID" if valid else "NOT_FOUND"}
        return self._send(200 if valid else 404, "application/json", json.dumps(payload).encode())

    def _send(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base_url = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _Handler.seen.clear()

    def test_valid_key_passes_the_edge_with_our_user_agent(self):
        client = SunLicense(base_url=self.base_url, token="good-token")
        result = client.validate("GOOD-KEY", host="pc-1")
        self.assertTrue(result.valid)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.data["code"], "VALID")
        sent = _Handler.seen[0]
        self.assertEqual(sent["headers"]["User-Agent"], "sunlicense-python/" + __version__)
        self.assertEqual(sent["headers"]["Accept"], "application/json")
        self.assertEqual(sent["body"], {"license": "GOOD-KEY", "host": "pc-1"})

    def test_rejected_key_returns_the_parsed_body(self):
        result = SunLicense(base_url=self.base_url, token="good-token").validate("BAD-KEY")
        self.assertFalse(result.valid)
        self.assertEqual(result.status, 404)
        self.assertEqual(result.data["code"], "NOT_FOUND")

    def test_non_json_error_body_is_returned_as_text(self):
        client = SunLicense(base_url=self.base_url, token="good-token")
        client._user_agent = "Python-urllib/3.12"  # what 0.0.1 sent
        result = client.validate("GOOD-KEY")
        self.assertFalse(result.valid)
        self.assertEqual(result.status, 403)
        self.assertEqual(result.data, "error code: 1010")

    def test_result_still_unpacks_into_three_fields(self):
        valid, status, data = SunLicense(base_url=self.base_url, token="good-token").validate("GOOD-KEY")
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
