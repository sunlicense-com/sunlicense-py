"""Tests for built-in product analytics (standard library only).

Run: python -m unittest discover -s tests
"""

import getpass
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sunlicense import SunLicense, SunLicenseAnalytics  # noqa: E402
from sunlicense.analytics import SDK_NAME, SDK_VERSION, collect, first_delay, next_delay  # noqa: E402

# SunLicense's conformance fixtures (spec 185 section 4.8,
# analytics-service/src/test/resources/conformance/reports.json): copy the file again when it changes.
with open(os.path.join(os.path.dirname(__file__), "fixtures", "conformance-reports.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)


class Recorder:
    """A transport that records requests and answers with ``status`` (and Retry-After)."""

    def __init__(self, status=204, retry_after=None):
        self.status, self.retry_after, self.seen = status, retry_after, []

    def __call__(self, url, headers, body):
        self.seen.append({"url": url, "headers": headers, "body": json.loads(body.decode("utf-8"))})
        return self.status, self.retry_after


def no_env(_name):
    return None


def make(**options):
    options.setdefault("_env", no_env)
    options.setdefault("data_directory", tempfile.mkdtemp())
    return SunLicenseAnalytics(**options)


class ConformanceTest(unittest.TestCase):
    def test_sends_the_request_side_of_every_fixture(self):
        for case in FIXTURES["cases"]:
            with self.subTest(case["name"]):
                r = case["report"]
                system = dict(r.get("metrics", {}))
                product_version = system.pop("productVersion", None)
                directory = tempfile.mkdtemp()
                if "installId" in r:
                    with open(os.path.join(directory, ".sunlicense-install-id"), "w") as f:
                        f.write(r["installId"])
                transport = Recorder()
                analytics = SunLicenseAnalytics(
                    base_url="https://api.example.test/",
                    api_key="slk_test" if case["licensed"] else None,
                    license_key=r.get("licenseKey"),
                    fingerprint=r.get("fingerprint"),
                    product_analytics_id=r.get("productAnalyticsId"),
                    data_directory=directory,
                    product_version=product_version,
                    _collect=lambda system=system: dict(system),
                    _env=no_env,
                    _transport=transport,
                )
                self.assertEqual(analytics.send_now(), 204)
                sent = transport.seen[0]
                self.assertEqual(sent["url"], "https://api.example.test/api/v2/analytics/report")
                expected = dict(r, schema=1, sdk={"name": SDK_NAME, "version": SDK_VERSION})
                self.assertEqual(sent["body"], expected)
                self.assertEqual(sent["headers"].get("Authorization"), "Bearer slk_test" if case["licensed"] else None)
                self.assertRegex(sent["headers"]["User-Agent"], r"^sunlicense-python/\d+\.\d+\.\d+ analytics$")


class AnalyticsTest(unittest.TestCase):
    def test_collects_raw_built_in_metrics_and_nothing_personal(self):
        transport = Recorder()
        make(product_analytics_id="pa_test", product_version="v1.2.3", _transport=transport).send_now()
        body = transport.seen[0]["body"]
        metrics = body["metrics"]
        self.assertEqual(metrics["productVersion"], "v1.2.3")
        self.assertEqual(metrics["runtime"], "python")
        self.assertTrue(metrics["runtimeVersion"].startswith("%d.%d" % sys.version_info[:2]))
        self.assertEqual(metrics["platform"], "standalone")
        self.assertGreaterEqual(metrics["cores"], 1)
        self.assertTrue(metrics["os"] and metrics["arch"])
        text = json.dumps(body)
        for personal in (socket.gethostname(), getpass.getuser(), os.getcwd(), os.path.expanduser("~")):
            self.assertNotIn(personal, text)

    def test_platform_override(self):
        m = collect(("MyEngine", "4.2"))
        self.assertEqual((m["platform"], m["platformVersion"]), ("myengine", "4.2"))

    def test_client_helpers(self):
        client = SunLicense(base_url="https://api.example.test/", token="slk_x")
        a = client.analytics("K", "f", enabled=False)
        self.assertEqual(a._endpoint, "https://api.example.test/api/v2/analytics/report")
        self.assertEqual(a._api_key, "slk_x")
        self.assertFalse(a.is_enabled())
        a.close()
        free = SunLicense.analytics_for("pa_abc", enabled=False)
        self.assertEqual(free._product_analytics_id, "pa_abc")
        free.close()

    def test_opt_out_sends_nothing(self):
        def raises():
            raise RuntimeError("config gone")

        cases = [
            {"enabled": False},
            {"enabled": lambda: False},
            {"enabled": raises},
            {"_env": lambda n: "off" if n == "SUNLICENSE_ANALYTICS" else None},
            {"_env": lambda n: " FALSE " if n == "SUNLICENSE_ANALYTICS" else None},
            {"_env": lambda n: "0" if n == "SUNLICENSE_ANALYTICS" else None},
        ]
        for extra in cases:
            transport = Recorder()
            a = make(product_analytics_id="pa_x", _transport=transport, **extra)
            self.assertFalse(a.is_enabled())
            self.assertEqual(a.send_now(), 0)
            self.assertEqual(transport.seen, [])
        state = {"on": False}
        transport = Recorder()
        a = make(product_analytics_id="pa_x", enabled=lambda: state["on"], _transport=transport)
        self.assertEqual(a.send_now(), 0)
        state["on"] = True
        self.assertEqual(a.send_now(), 204)

    def test_identity(self):
        transport = Recorder()
        self.assertEqual(make(_transport=transport).send_now(), 0)
        self.assertEqual(make(api_key="slk", fingerprint="f", _transport=transport).send_now(), 0)
        state = {"key": None}
        later = make(api_key="slk", fingerprint="f", license_key=lambda: state["key"], _transport=transport)
        self.assertEqual(later.send_now(), 0)
        state["key"] = " AX8P-4Q2M "
        self.assertEqual(later.send_now(), 204)
        self.assertEqual(transport.seen[0]["body"]["licenseKey"], "AX8P-4Q2M")
        self.assertNotIn("installId", transport.seen[0]["body"])

    def test_never_raises(self):
        def boom(*_args):
            raise OSError("network down")

        def bad_version():
            raise ValueError("x")

        self.assertEqual(make(product_analytics_id="pa_x", product_version=bad_version, _transport=boom).send_now(), -1)
        SunLicenseAnalytics.start(base_url=None, nonsense=True).close()  # bad options: a disabled reporter

    def test_schedule(self):
        class Low:
            def randint(self, a, b):
                return a

        class High:
            def randint(self, a, b):
                return b

        self.assertEqual(first_delay(Low()), 60)
        self.assertEqual(first_delay(High()), 30 * 60)
        self.assertEqual(next_delay(204, "86400"), 1800)
        self.assertEqual(next_delay(-1, None), 1800)
        self.assertEqual(next_delay(429, "120"), 120)
        self.assertEqual(next_delay(429, "5"), 60)
        self.assertEqual(next_delay(403, "999999"), 86400)
        self.assertEqual(next_delay(503, "Wed, 21 Oct 2026 07:28:00 GMT"), 1800)

    def test_install_id_is_kept(self):
        directory = tempfile.mkdtemp()
        transport = Recorder()
        make(product_analytics_id="pa_x", data_directory=directory, _transport=transport).send_now()
        make(product_analytics_id="pa_x", data_directory=directory, _transport=transport).send_now()
        with open(os.path.join(directory, ".sunlicense-install-id")) as f:
            stored = f.read()
        self.assertRegex(stored, r"^[A-Za-z0-9_-]{8,64}$")
        self.assertEqual([s["body"]["installId"] for s in transport.seen], [stored, stored])

    def test_big_report_keeps_built_ins(self):
        transport = Recorder()
        a = make(product_analytics_id="pa_x", _transport=transport)

        class Big:
            def write(self, report):
                report["features"] = {"feature-%d" % i: i + 1 for i in range(2000)}

        class Broken:
            def write(self, report):
                raise RuntimeError("broken section")

        a._add(Big())._add(Broken())
        self.assertEqual(a.send_now(), 204)
        self.assertNotIn("features", transport.seen[0]["body"])
        self.assertIn("metrics", transport.seen[0]["body"])

    def test_background_report_to_a_real_server(self):
        bodies = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                bodies.append((self.path, json.loads(self.rfile.read(length))))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            a = SunLicenseAnalytics.start(
                base_url="http://127.0.0.1:%d" % server.server_address[1],
                product_analytics_id="pa_bg",
                data_directory=tempfile.mkdtemp(),
                _env=no_env,
                _first_delay=0.01,
            )
            for _ in range(200):
                if bodies:
                    break
                time.sleep(0.02)
            a.close()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(bodies), 1)
        self.assertEqual(bodies[0][0], "/api/v2/analytics/report")
        self.assertEqual(bodies[0][1]["productAnalyticsId"], "pa_bg")
        self.assertTrue(a._thread.daemon)


if __name__ == "__main__":
    unittest.main()


class UsageTest(unittest.TestCase):
    def test_features_are_kept_until_stored(self):
        transport = Recorder(503, "60")
        a = make(product_analytics_id="pa_x", _transport=transport)
        a.feature("auto-sell").feature("Auto-Sell", 2).feature("web-editor")
        a.feature("bad name!").feature("x", 0).feature("y", 1.5).feature(42).feature("z", True)
        self.assertEqual(a.send_now(), 503)
        self.assertEqual(transport.seen[0]["body"]["features"], {"auto-sell": 3, "web-editor": 1})
        a.feature("auto-sell")
        transport.status = 204
        self.assertEqual(a.send_now(), 204)
        self.assertEqual(transport.seen[1]["body"]["features"], {"auto-sell": 4, "web-editor": 1})
        a.send_now()
        self.assertNotIn("features", transport.seen[2]["body"])
        off = make(product_analytics_id="pa_x", enabled=False, _transport=transport)
        off.feature("auto-sell")
        self.assertEqual(off._features, {})

    def test_at_most_50_features_per_report(self):
        transport = Recorder()
        a = make(product_analytics_id="pa_x", _transport=transport)
        for i in range(60):
            a.feature("f%d" % i)
        a.send_now()
        a.send_now()
        self.assertEqual([len(s["body"]["features"]) for s in transport.seen], [50, 10])

    def test_every_chart_type(self):
        def raises():
            raise RuntimeError("x")

        transport = Recorder()
        a = (
            make(product_analytics_id="pa_x", _transport=transport)
            .simple_pie("storage", lambda: "mysql")
            .advanced_pie("modules", lambda: {"shop": 2, "auctions": 1, "zero": 0})
            .drilldown_pie("java", lambda: {"Java 21": {"21.0.4": 1}, "empty": {}})
            .single_line("players", lambda: 42)
            .multi_line("worlds", lambda: {"overworld": 30, "nether": -2})
            .simple_bar("commands", lambda: {"sell": 12})
            .advanced_bar("tiers", lambda: {"gold": [1, 2, 3], "bad": [1, "x"]})
            .simple_pie("nothing", lambda: None)
            .simple_pie("empty", lambda: "  ")
            .single_line("huge", lambda: 2 * 10 ** 9)
            .simple_pie("throws", raises)
            .simple_pie("Bad Id", lambda: "x")
            .simple_pie("removed", lambda: "x")
            .remove_chart("removed")
        )
        self.assertEqual(a.send_now(), 204)
        self.assertEqual(transport.seen[0]["body"]["charts"], [
            {"id": "storage", "type": "simple_pie", "data": {"value": "mysql"}},
            {"id": "modules", "type": "advanced_pie", "data": {"values": {"shop": 2, "auctions": 1}}},
            {"id": "java", "type": "drilldown_pie", "data": {"values": {"Java 21": {"21.0.4": 1}}}},
            {"id": "players", "type": "single_line", "data": {"value": 42}},
            {"id": "worlds", "type": "multi_line", "data": {"values": {"overworld": 30, "nether": -2}}},
            {"id": "commands", "type": "simple_bar", "data": {"values": {"sell": 12}}},
            {"id": "tiers", "type": "advanced_bar", "data": {"values": {"gold": [1, 2, 3]}}},
        ])

    def test_same_id_replaces_and_30_charts_at_most(self):
        transport = Recorder()
        a = make(product_analytics_id="pa_x", _transport=transport)
        a.simple_pie("storage", lambda: "mysql").simple_pie("STORAGE", lambda: "sqlite")
        for i in range(40):
            a.single_line("c%d" % i, lambda i=i: i)
        a.send_now()
        charts = transport.seen[0]["body"]["charts"]
        self.assertEqual(len(charts), 30)
        self.assertEqual(charts[0], {"id": "storage", "type": "simple_pie", "data": {"value": "sqlite"}})
