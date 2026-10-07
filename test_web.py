"""HTTP-level coverage for the browser dashboard and its local-only assets."""
import unittest

from fastapi.testclient import TestClient

from app import app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_dashboard_is_served_with_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Agent Signal", response.text)
        self.assertIn('id="run-assessment"', response.text)
        self.assertIn("Registered agents", response.text)
        self.assertIn("Verify a report signature", response.text)
        self.assertIn("The private key stays in this browser", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("default-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_dashboard_alias_and_assets_are_available(self):
        alias = self.client.get("/dashboard")
        self.assertEqual(alias.status_code, 200)
        for asset in ("dashboard.css", "dashboard.js"):
            with self.subTest(asset=asset):
                response = self.client.get(f"/assets/{asset}")
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.content)

    def test_browser_flow_uses_existing_api_and_does_not_persist_secrets(self):
        script = self.client.get("/assets/dashboard.js").text
        for required in (
            "/v1/agents", "/v1/agents/register", "/v1/identity/challenge", "/v1/identity/verify",
            "/v1/score", "/v1/score/report/signed", "/v1/reports/verify",
            "/v1/agents/rotate-key",
            "subtle.importKey", "subtle.sign", "Requester supplied",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("sessionStorage", script)
        self.assertNotIn("console.log", script)
        self.assertNotIn(".innerHTML", script)

    def test_dashboard_assets_have_no_third_party_dependencies(self):
        page = self.client.get("/").text
        script = self.client.get("/assets/dashboard.js").text
        styles = self.client.get("/assets/dashboard.css").text
        self.assertNotIn("https://", page)
        self.assertNotIn("https://", script)
        self.assertNotIn("https://", styles)
        self.assertNotIn("@import", styles)
        self.assertIn("[hidden]", styles)
        self.assertIn("display: none !important", styles)

    def test_unknown_dashboard_asset_returns_safe_api_error(self):
        response = self.client.get("/assets/agent_public_keys.json")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
