import unittest
from app import app, analyze_url


class CyberGuardTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_safe_https_url(self):
        result = analyze_url("https://www.wikipedia.org/wiki/Cybersecurity")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["status"], "No Obvious Warning Signs")
        self.assertEqual(result["reasons"], [])

    def test_needs_verification_url(self):
        result = analyze_url("http://portal-login.example.com/account")
        self.assertGreaterEqual(result["score"], 20)
        self.assertLess(result["score"], 50)
        self.assertEqual(result["status"], "Needs Verification")

    def test_suspicious_phishing_url(self):
        result = analyze_url(
            "http://192.168.1.45/secure-bank/login/verify-password?next=http://bit.ly/3demo"
        )
        self.assertGreaterEqual(result["score"], 50)
        self.assertEqual(result["status"], "Suspicious")

    def test_shortener_and_symbols(self):
        result = analyze_url("https://bit.ly/demo@phish")
        self.assertGreaterEqual(result["score"], 40)

    def test_scan_endpoint_validation(self):
        res_empty = self.client.post("/scan", json={"url": ""})
        self.assertEqual(res_empty.status_code, 400)

        res_bad_scheme = self.client.post("/scan", json={"url": "not-a-url"})
        self.assertEqual(res_bad_scheme.status_code, 400)

        res_too_long = self.client.post("/scan", json={"url": "https://example.com/" + "a" * 2050})
        self.assertEqual(res_too_long.status_code, 400)

    def test_home_and_scan_success(self):
        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 200)

        res_scan = self.client.post("/scan", json={"url": "https://example.com"})
        self.assertEqual(res_scan.status_code, 200)
        payload = res_scan.get_json()
        self.assertEqual(payload["status"], "No Obvious Warning Signs")


if __name__ == "__main__":
    unittest.main()
