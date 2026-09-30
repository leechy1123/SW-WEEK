"""외부 네트워크 없이 실제 로컬 서버를 실행하는 기능·경계 테스트."""
import http.client
import json
import threading
import unittest
from unittest.mock import patch

import app
import lab
from scanner import ScanError, evaluate, scan, validate_target


class ProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.create_server(0)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, payload=None, extra_headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {"Content-Type": "application/json"}
        headers.update(extra_headers or {})
        body = json.dumps(payload).encode() if payload is not None else None
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            conn.close()

    def test_actual_before_after_http_responses(self):
        with patch.multiple(lab, REPAIR_ACCESS=False, REPAIR_DEBUG=False, REPAIR_SQL=False):
            result = scan(self.base + "/lab/vulnerable", self.port, compare=True)
        self.assertEqual(result["request_count"], 16)
        self.assertEqual([c["state"] for c in result["before"]["checks"]], ["vulnerable"] * 3)
        self.assertEqual([c["state"] for c in result["after"]["checks"]], ["pass"] * 3)
        self.assertTrue(all(c["normal_ok"] for c in result["after"]["checks"]))
        self.assertEqual(result["before"]["checks"][0]["evidence"][1]["body"]["post"]["owner"], "bob")

    def test_repair_flags_change_live_behavior(self):
        for flag, repaired_index in [("REPAIR_ACCESS", 0), ("REPAIR_DEBUG", 1), ("REPAIR_SQL", 2)]:
            values = {"REPAIR_ACCESS": False, "REPAIR_DEBUG": False, "REPAIR_SQL": False, flag: True}
            with patch.multiple(lab, **values):
                result = scan(self.base + "/lab/vulnerable", self.port)
            expected = ["vulnerable"] * 3
            expected[repaired_index] = "pass"
            self.assertEqual([c["state"] for c in result["checks"]], expected)

    def test_both_users_and_unauthenticated_access(self):
        for user, own, other in [("demo-alice", "1", "2"), ("demo-bob", "2", "1")]:
            self.assertEqual(lab.read_post("fixed", own, user)[0], 200)
            self.assertEqual(lab.read_post("fixed", other, user)[0], 403)
        for session in ["", "forged", "alice"]:
            self.assertEqual(lab.read_post("fixed", "1", session)[0], 401)

    def test_bad_post_and_search_inputs(self):
        self.assertEqual(lab.read_post("fixed", "missing", "demo-alice")[0], 404)
        self.assertEqual(lab.search_products("fixed", "x" * 101)[0], 400)
        self.assertEqual(lab.search_products("fixed", "O'Reilly")[1], {"products": []})
        for word in ["노트", "연필", "지우개"]:
            self.assertEqual(len(lab.search_products("fixed", word)[1]["products"]), 1)

    def test_only_exact_local_lab_targets(self):
        invalid = ["https://example.com", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                   self.base + "/lab/fixed?next=https://example.com", self.base + "/lab/fixed#x",
                   self.base + "/lab/../fixed", self.base + "/lab/fixed/search", "http://localhost:" + str(self.port) + "/lab/fixed",
                   "http://127.0.0.1:1/lab/fixed", f"http://user:pass@127.0.0.1:{self.port}/lab/fixed",
                   self.base + "/lab/fixed\r\nX:1", self.base + "/lab/%66ixed", None, ""]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ScanError):
                validate_target(value, self.port)
        self.assertEqual(validate_target(self.base + "/lab/fixed/", self.port), "fixed")

    def test_no_network_call_for_rejected_target(self):
        with patch("scanner.http.client.HTTPConnection") as connection:
            with self.assertRaises(ScanError):
                scan("https://example.com", self.port)
            connection.assert_not_called()

    def test_broken_normal_function_cannot_pass(self):
        report = scan(self.base + "/lab/fixed", self.port)
        for finding in report["checks"]:
            cases = finding["evidence"]
            cases[0] = {"status": 500, "body": {"message": "broken"}}
            state, _, normal_ok = evaluate(finding["id"], cases)
            self.assertEqual(state, "unknown")
            self.assertFalse(normal_ok)

    def test_transport_failure_is_not_pass(self):
        with patch("scanner.http.client.HTTPConnection.request", side_effect=OSError("offline")):
            with self.assertRaises(ScanError):
                scan(self.base + "/lab/fixed", self.port)
        with patch("scanner.request_case", side_effect=ScanError("서버 응답 실패")):
            status, body, _ = self.request("POST", "/api/scan", {"url": self.base + "/lab/fixed", "authorized": True})
        self.assertEqual(status, 400)
        self.assertNotIn("checks", json.loads(body))

    def test_api_requires_consent_and_json(self):
        status, _, _ = self.request("POST", "/api/scan", {"url": self.base + "/lab/fixed"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/scan", {"authorized": "true"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/scan", {"authorized": True}, {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/scan", ["unexpected"])
        self.assertEqual(status, 400)

    def test_host_origin_and_cross_site_rejected(self):
        for headers in [{"Host": "attacker.example"}, {"Origin": "https://attacker.example"}, {"Sec-Fetch-Site": "cross-site"}]:
            status, _, _ = self.request("GET", "/api/config", extra_headers=headers)
            self.assertEqual(status, 403)

    def test_api_returns_report_and_lock_rejects_parallel_scan(self):
        payload = {"url": self.base + "/lab/fixed", "authorized": True}
        status, body, _ = self.request("POST", "/api/scan", payload)
        self.assertEqual(status, 200)
        self.assertEqual([c["state"] for c in json.loads(body)["checks"]], ["pass"] * 3)
        with app.SCAN_LOCK:
            status, _, _ = self.request("POST", "/api/scan", payload)
        self.assertEqual(status, 429)

    def test_static_allowlist_and_security_headers(self):
        for path in ["/", "/style.css", "/app.js", "/lab.js", "/lab/vulnerable", "/lab/fixed"]:
            status, body, headers = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        for path in ["/../app.py", "/app.py", "/lab/vulnerable/unknown"]:
            self.assertEqual(self.request("GET", path)[0], 404)


if __name__ == "__main__":
    unittest.main()
