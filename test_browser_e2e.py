"""Real Chromium test for registration, signed assessment, and key revocation."""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parent
REGISTRATION_TOKEN = "browser-e2e-registration-token-0123456789"


class BrowserJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True)
        except Exception as error:
            if "bootstrap_check_in" in str(error) and "Permission denied (1100)" in str(error):
                cls.playwright.stop()
                raise unittest.SkipTest(
                    "This macOS task sandbox cannot launch Chromium; the browser journey remains enabled for CI runners."
                ) from None
            cls.playwright.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agent-signal-browser-")
        self.data_dir = Path(self.temp.name)
        self.agent_id = "browser-demo-agent"
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.private_raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.private_key_path = self.data_dir / "test-agent.pem"
        self.private_key_path.write_bytes(self.private_pem)
        self.private_key_path.chmod(0o600)
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.registry_path = self.data_dir / "public-keys.json"
        self.registry_path.write_text(json.dumps({
            self.agent_id: base64.b64encode(public_bytes).decode("ascii"),
        }), encoding="utf-8")
        self.db_path = self.data_dir / "agents.sqlite3"
        self.report_signing_key_path = self.data_dir / "report-signing-key.pem"
        report_signing_key = Ed25519PrivateKey.generate()
        self.report_signing_key_path.write_bytes(report_signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        self.report_signing_key_path.chmod(0o600)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.server_log = self.data_dir / "server.log"
        self.log_handle = self.server_log.open("w", encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "REGISTRATION_TOKEN": REGISTRATION_TOKEN,
            "AGENTS_DB_FILE": str(self.db_path),
            "AGENT_PUBLIC_KEYS_FILE": str(self.registry_path),
            "REPORT_SIGNING_PRIVATE_KEY_FILE": str(self.report_signing_key_path),
            "API_RATE_LIMIT_MAX_REQUESTS": "60",
        })
        self.server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=ROOT,
            env=env,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_ready()
        self.context = self.browser.new_context()
        self.page = self.context.new_page()

    def tearDown(self):
        if hasattr(self, "context"):
            self.context.close()
        if hasattr(self, "server"):
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        if hasattr(self, "log_handle"):
            self.log_handle.close()
        self.temp.cleanup()

    def _wait_until_ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.log_handle.flush()
                self.fail(f"Local API exited during browser test setup; see {self.server_log}")
            try:
                with urlopen(f"{self.base_url}/v1/health", timeout=1) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.2)
        self.fail(f"Local API did not become healthy; see {self.server_log}")

    def _api_status(self, path, api_key):
        request = Request(f"{self.base_url}{path}", headers={"X-API-Key": api_key})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status
        except HTTPError as error:
            return error.code

    def test_real_browser_registration_signed_report_and_revocation(self):
        responses = {}
        transmitted_bodies = []
        requested_urls = []

        def capture_response(response):
            if response.url.endswith("/v1/agents/register"):
                responses["registration"] = response.json()
            elif response.url.endswith("/v1/agents/rotate-key"):
                responses["rotation"] = response.json()
            elif response.url.endswith("/v1/score/report/signed"):
                responses["signed_report"] = response.json()

        self.page.on("response", capture_response)
        self.page.on("request", lambda request: transmitted_bodies.append(request.post_data or ""))
        self.page.on("request", lambda request: requested_urls.append(request.url))
        self.page.goto(self.base_url, wait_until="networkidle")
        self.page.get_by_text("Local API connected", exact=True).wait_for()

        # Workspace access powers the real, registration-token-protected directory.
        self.page.locator("#workspace-token").fill("incorrect-browser-e2e-token")
        self.page.get_by_role("button", name="Connect").click()
        self.page.get_by_text("Authentication failed. Check the local token or agent API key.", exact=True).wait_for()
        self.assertNotIn("Traceback", self.page.locator("body").inner_text())
        self.page.locator("#workspace-token").fill(REGISTRATION_TOKEN)
        self.page.get_by_role("button", name="Connect").click()
        self.page.get_by_text("Workspace connected. The registration token is held in this tab only.", exact=True).wait_for()

        self.page.locator("#agent-id").fill(self.agent_id)
        self.page.locator("#private-key").set_input_files(str(self.private_key_path))
        self.page.get_by_role("button", name="Run assessment").click()
        self.page.wait_for_function(
            "() => document.getElementById('detail-score').textContent === '95'",
            timeout=15000,
        )

        self.assertEqual(self.page.locator("#detail-rating").inner_text(), "High score")
        self.assertIn("All three evidence checks passed", self.page.locator("#detail-summary").inner_text())
        self.assertIn("not checked against external systems", self.page.locator(".trust-note").inner_text())
        self.assertIn("does not check actual permissions", self.page.locator("#assessment").inner_text())
        self.assertIn("does not receive audit history", self.page.locator("#assessment").inner_text())
        self.assertIn("Requester supplied", self.page.locator("#detail-factors").inner_text())
        self.assertIn("Signature verified", self.page.locator("#detail-factors").inner_text())
        self.assertIn(self.agent_id, self.page.locator("#agents-list").inner_text())
        self.assertIn("95 / 100", self.page.locator("#agents-list").inner_text())
        self.assertIn("Report", self.page.locator("#detail-report-id").inner_text())
        self.assertTrue(self.page.get_by_role("button", name="Rotate and revoke old key").is_visible())
        self.assertTrue(self.page.get_by_role("button", name="Save current API key").is_visible())
        for route in (
            "/v1/agents", "/v1/agents/register", "/v1/identity/challenge", "/v1/identity/verify",
            "/v1/score", "/v1/score/report/signed", "/v1/reports/signing-key", "/v1/agents/",
        ):
            self.assertTrue(any(route in url for url in requested_urls), f"browser did not request {route}")

        registered_key = responses["registration"]["api_key"]
        page_text = self.page.locator("body").inner_text()
        self.assertNotIn(registered_key, page_text)
        self.assertNotIn(REGISTRATION_TOKEN, page_text)
        signed_report = responses["signed_report"]
        self.assertEqual(signed_report["report"]["overall_score"], 95)
        self.assertIn(signed_report["signature"], self.page.locator("#signed-report-json").inner_text())
        private_key_markers = (
            self.private_pem.decode("ascii"),
            base64.b64encode(self.private_pem).decode("ascii"),
            base64.b64encode(self.private_raw).decode("ascii"),
        )
        self.assertFalse(
            any(marker in body for marker in private_key_markers for body in transmitted_bodies),
            "private key material was included in an API request body",
        )
        browser_storage = self.page.evaluate("""() => ({
            local: Object.keys(localStorage),
            session: Object.keys(sessionStorage),
        })""")
        self.assertEqual(browser_storage, {"local": [], "session": []})

        # Verify a real server-signed report, then prove a modified score is rejected.
        self.page.get_by_role("button", name="Verify signature").click()
        self.page.get_by_text("Signature verified · Report signature verified with the local Agent Signal signing key.", exact=False).wait_for()
        tampered_report = json.loads(self.page.locator("#report-input").input_value())
        tampered_report["report"]["overall_score"] = 94
        self.page.locator("#report-input").fill(json.dumps(tampered_report))
        self.page.get_by_role("button", name="Verify report").click()
        self.page.get_by_text("Signature invalid", exact=False).wait_for()
        self.page.locator("#report-input").fill(json.dumps(signed_report))
        self.page.get_by_role("button", name="Verify report").click()
        self.page.get_by_text("Signature verified", exact=False).wait_for()

        self.page.on("dialog", lambda dialog: dialog.accept())
        self.page.get_by_role("button", name="Rotate and revoke old key").click()
        self.page.get_by_text("Old credential revoked (HTTP 401 confirmed). The replacement is active in this tab; save it if you need access later.", exact=True).wait_for()
        rotated_key = responses["rotation"]["api_key"]
        self.assertNotEqual(registered_key, rotated_key)
        self.assertEqual(self._api_status(f"/v1/score?agent_id={self.agent_id}", registered_key), 401)
        self.assertEqual(self._api_status(f"/v1/score?agent_id={self.agent_id}", rotated_key), 200)
        self.assertNotIn(rotated_key, self.page.locator("body").inner_text())


if __name__ == "__main__":
    unittest.main()
