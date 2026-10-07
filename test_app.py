"""API-level tests for scoring and cryptographic evidence."""
import base64
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import agent_registry
import app as app_module
import security
import report_signing
from app import app
from rate_limit import PerKeyRateLimiter
from security import canonical_audit_payload, canonical_permissions_payload

DEFAULT_AUDIT = object()


class TrustAPITests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.original_rate_limiter = app_module.RATE_LIMITER
        self.original_registration_token = app_module.REGISTRATION_TOKEN
        app_module.RATE_LIMITER = PerKeyRateLimiter()
        app_module.REGISTRATION_TOKEN = "test-registration-token-0123456789abcdef"
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_report_signing_key_file = report_signing.SIGNING_KEY_FILE
        report_signing.SIGNING_KEY_FILE = Path(self.temporary_directory.name) / "report-signing-key.pem"
        report_private_key = Ed25519PrivateKey.generate()
        report_signing.SIGNING_KEY_FILE.write_bytes(report_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        report_signing.SIGNING_KEY_FILE.chmod(0o600)
        self.original_registry = agent_registry.REGISTRY
        agent_registry.REGISTRY = agent_registry.AgentRegistry(Path(self.temporary_directory.name) / "agents.sqlite3")
        security.CHALLENGES.clear()
        security.CONSUMED_CHALLENGES.clear()
        security.IDENTITY_PROOFS.clear()
        self.agent_id = "agent-test"
        self.api_key = agent_registry.REGISTRY.register(self.agent_id)
        self.private_key = Ed25519PrivateKey.generate()
        self.wrong_key = Ed25519PrivateKey.generate()
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        security.PUBLIC_KEYS[self.agent_id] = base64.b64encode(public_bytes).decode("ascii")

    def tearDown(self):
        security.PUBLIC_KEYS.pop(self.agent_id, None)
        security.CHALLENGES.clear()
        security.CONSUMED_CHALLENGES.clear()
        security.IDENTITY_PROOFS.clear()
        agent_registry.REGISTRY = self.original_registry
        app_module.RATE_LIMITER = self.original_rate_limiter
        app_module.REGISTRATION_TOKEN = self.original_registration_token
        report_signing.SIGNING_KEY_FILE = self.original_report_signing_key_file
        self.temporary_directory.cleanup()

    def signed_manifest(self, actions=None, key=None):
        actions = actions or ["read:profile", "write:notes"]
        key = key or self.private_key
        signature = key.sign(canonical_permissions_payload(self.agent_id, actions))
        return {"allowed_actions": actions, "signature": base64.b64encode(signature).decode("ascii")}

    def signed_audit(self, digest=None, created_at=None, key=None):
        digest = digest or "a" * 64
        created_at = created_at or datetime.now(timezone.utc)
        key = key or self.private_key
        signature = key.sign(canonical_audit_payload(self.agent_id, digest, created_at))
        return {
            "digest": digest,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def score(self, manifest=None, audit=DEFAULT_AUDIT, incident_count=0):
        if audit is DEFAULT_AUDIT:
            audit = self.signed_audit()
        payload = {"agent_id": self.agent_id, "audit_log": audit, "incident_count": incident_count}
        if manifest is not None:
            payload["permission_manifest"] = manifest
        return self.client.post("/score", json=payload, headers={"X-API-Key": self.api_key})

    def start_challenge(self):
        response = self.client.post("/identity/challenge", json={"agent_id": self.agent_id}, headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        return response.json()

    def verify_challenge(self, challenge, key=None):
        key = key or self.private_key
        signature = key.sign(challenge["challenge"].encode("utf-8"))
        return self.client.post("/identity/verify", json={
            "agent_id": self.agent_id,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        }, headers={"X-API-Key": self.api_key})

    def test_valid_permissions_manifest_signature_awards_points(self):
        response = self.score(manifest=self.signed_manifest())
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["score"], 80)
        permission = data["evidence_results"]["permission_declared"]
        self.assertTrue(permission["valid"])
        self.assertEqual(permission["verification"], "cryptographic")

    def test_tampered_manifest_gets_no_permission_points(self):
        manifest = self.signed_manifest(["read:profile"])
        manifest["allowed_actions"].append("admin:all")
        data = self.score(manifest=manifest).json()
        self.assertEqual(data["score"], 65)
        self.assertFalse(data["evidence_results"]["permission_declared"]["valid"])
        self.assertIn("signature is invalid", data["evidence_results"]["permission_declared"]["reason"])

    def test_wrong_key_signature_gets_no_permission_points(self):
        data = self.score(manifest=self.signed_manifest(key=self.wrong_key)).json()
        self.assertEqual(data["score"], 65)
        permission = data["evidence_results"]["permission_declared"]
        self.assertFalse(permission["valid"])
        self.assertEqual(permission["verification"], "cryptographic")

    def test_missing_signature_gets_no_permission_points(self):
        for signature in (None, ""):
            with self.subTest(signature=signature):
                manifest = {"allowed_actions": ["read:profile"]}
                if signature is not None:
                    manifest["signature"] = signature
                response = self.score(manifest=manifest)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data["score"], 65)
                permission = data["evidence_results"]["permission_declared"]
                self.assertFalse(permission["valid"])
                self.assertIn("signature is missing", permission["reason"])

    def test_missing_permissions_manifest_gets_no_points(self):
        data = self.score().json()
        self.assertFalse(data["evidence_results"]["permission_declared"]["valid"])
        self.assertIn("manifest is missing", data["evidence_results"]["permission_declared"]["reason"])

    def test_valid_identity_challenge_awards_identity_points(self):
        challenge = self.start_challenge()
        self.assertGreater(len(challenge["challenge"]), 30)
        result = self.verify_challenge(challenge)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()["verified"])
        scored = self.score(manifest=self.signed_manifest()).json()
        self.assertEqual(scored["score"], 95)
        identity = scored["evidence_results"]["identity_verified"]
        self.assertTrue(identity["valid"])
        self.assertEqual(identity["verification"], "cryptographic")

    def test_identity_endpoints_require_the_registered_agents_api_key(self):
        self.assertEqual(self.client.post("/v1/identity/challenge", json={"agent_id": self.agent_id}).status_code, 401)
        unauthorized_verify = self.client.post("/v1/identity/verify", json={
            "agent_id": self.agent_id,
            "challenge_id": "not-a-real-challenge",
            "signature": "invalid",
        })
        self.assertEqual(unauthorized_verify.status_code, 401)

    def test_wrong_identity_signature_does_not_award_identity_points(self):
        challenge = self.start_challenge()
        self.assertEqual(self.verify_challenge(challenge, self.wrong_key).status_code, 401)
        scored = self.score(manifest=self.signed_manifest()).json()
        self.assertEqual(scored["score"], 80)
        self.assertFalse(scored["evidence_results"]["identity_verified"]["valid"])

    def test_invalid_signature_does_not_consume_identity_challenge(self):
        challenge = self.start_challenge()
        self.assertEqual(self.verify_challenge(challenge, self.wrong_key).status_code, 401)
        self.assertEqual(self.verify_challenge(challenge).status_code, 200)
        self.assertEqual(self.verify_challenge(challenge).status_code, 409)

    def test_expired_identity_challenge_is_rejected(self):
        challenge = self.start_challenge()
        security.CHALLENGES[challenge["challenge_id"]].expires_at = security.now_utc() - timedelta(seconds=1)
        response = self.verify_challenge(challenge)
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json()["detail"], "Challenge has expired.")

    def test_identity_challenge_cannot_be_replayed(self):
        challenge = self.start_challenge()
        self.assertEqual(self.verify_challenge(challenge).status_code, 200)
        self.assertEqual(self.verify_challenge(challenge).status_code, 409)

    def test_cross_agent_cannot_consume_another_agents_challenge(self):
        challenge = self.start_challenge()
        signature = self.private_key.sign(challenge["challenge"].encode("utf-8"))
        wrong_agent_key = agent_registry.REGISTRY.register("different-agent")
        wrong_agent = self.client.post("/identity/verify", json={
            "agent_id": "different-agent",
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        }, headers={"X-API-Key": wrong_agent_key})
        self.assertEqual(wrong_agent.status_code, 400)
        self.assertEqual(self.verify_challenge(challenge).status_code, 200)

    def test_unknown_agent_cannot_start_identity_challenge(self):
        security.PUBLIC_KEYS.pop(self.agent_id)
        response = self.client.post("/identity/challenge", json={"agent_id": self.agent_id})
        self.assertEqual(response.status_code, 404)

    def test_valid_audit_signature_awards_points(self):
        response = self.score(manifest=self.signed_manifest(), audit=self.signed_audit())
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["score"], 80)
        audit = data["evidence_results"]["audit_log"]
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["verification"], "cryptographic")

    def test_tampered_audit_digest_gets_no_audit_points(self):
        proof = self.signed_audit(digest="a" * 64)
        proof["digest"] = "b" * 64
        data = self.score(manifest=self.signed_manifest(), audit=proof).json()
        self.assertEqual(data["score"], 65)
        audit = data["evidence_results"]["audit_log"]
        self.assertFalse(audit["valid"])
        self.assertIn("signature is invalid", audit["reason"])

    def test_missing_audit_proof_gets_no_audit_points(self):
        data = self.score(manifest=self.signed_manifest(), audit=None).json()
        self.assertEqual(data["score"], 65)
        audit = data["evidence_results"]["audit_log"]
        self.assertFalse(audit["valid"])
        self.assertIn("proof is missing", audit["reason"])

    def test_expired_audit_proof_gets_no_audit_points(self):
        old_timestamp = datetime.now(timezone.utc) - timedelta(seconds=security.AUDIT_PROOF_MAX_AGE_SECONDS + 1)
        proof = self.signed_audit(created_at=old_timestamp)
        data = self.score(manifest=self.signed_manifest(), audit=proof).json()
        self.assertEqual(data["score"], 65)
        audit = data["evidence_results"]["audit_log"]
        self.assertFalse(audit["valid"])
        self.assertIn("proof has expired", audit["reason"])

    def test_missing_audit_signature_gets_no_audit_points(self):
        proof = self.signed_audit()
        proof.pop("signature")
        data = self.score(manifest=self.signed_manifest(), audit=proof).json()
        self.assertEqual(data["score"], 65)
        self.assertIn("signature is missing", data["evidence_results"]["audit_log"]["reason"])

    def test_invalid_audit_digest_is_rejected_by_model(self):
        proof = self.signed_audit()
        proof["digest"] = "not-a-digest"
        response = self.score(manifest=self.signed_manifest(), audit=proof)
        self.assertEqual(response.status_code, 200)
        audit = response.json()["evidence_results"]["audit_log"]
        self.assertFalse(audit["valid"])
        self.assertIn("64-character SHA-256", audit["reason"])

    def test_report_shape_and_end_to_end_verified_score(self):
        challenge = self.start_challenge()
        self.assertEqual(self.verify_challenge(challenge).status_code, 200)
        payload = {
            "agent_id": self.agent_id,
            "permission_manifest": self.signed_manifest(),
            "audit_log": self.signed_audit(),
            "incident_count": 1,
        }
        response = self.client.post("/score/report", json=payload, headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(set(report), {
            "agent_id", "overall_score", "rating", "base_score", "factor_scores",
            "evidence_results", "reasons", "checked_at",
        })
        self.assertEqual((report["overall_score"], report["rating"], report["base_score"]), (85, "high_score", 50))
        factors = {item["factor"]: item for item in report["factor_scores"]}
        self.assertEqual(set(factors), {"identity_verified", "permission_declared", "audit_log", "incidents"})
        self.assertEqual(
            {name: factors[name]["points"] for name in ("identity_verified", "permission_declared", "audit_log", "incidents")},
            {"identity_verified": 15, "permission_declared": 15, "audit_log": 15, "incidents": -10},
        )
        self.assertTrue(all(factors[name]["status"] == "verified" for name in ("identity_verified", "permission_declared", "audit_log")))
        self.assertEqual(report["evidence_results"]["audit_log"]["verification"], "cryptographic")
        self.assertIn("1 incident reduced the score by 10 points.", report["reasons"])

    def test_report_end_to_end_missing_evidence(self):
        response = self.client.post("/score/report", json={"agent_id": self.agent_id, "incident_count": 0}, headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual((report["overall_score"], report["rating"]), (50, "review"))
        factors = {item["factor"]: item for item in report["factor_scores"]}
        for name in ("identity_verified", "permission_declared", "audit_log"):
            self.assertEqual(factors[name]["points"], 0)
            self.assertEqual(factors[name]["status"], "failed")
            self.assertFalse(report["evidence_results"][name]["valid"])
            self.assertTrue(report["evidence_results"][name]["reason"])
        self.assertEqual(len(report["reasons"]), 3)

    def test_signed_report_verification_registry_listing_and_persistence(self):
        challenge = self.start_challenge()
        self.assertEqual(self.verify_challenge(challenge).status_code, 200)
        evidence = {
            "agent_id": self.agent_id,
            "permission_manifest": self.signed_manifest(),
            "audit_log": self.signed_audit(),
            "incident_count": 0,
        }
        signed_response = self.client.post(
            "/v1/score/report/signed", json=evidence, headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(signed_response.status_code, 200, signed_response.text)
        envelope = signed_response.json()
        self.assertEqual(envelope["algorithm"], "Ed25519")
        self.assertEqual(envelope["report"]["overall_score"], 95)

        verification = self.client.post("/v1/reports/verify", json=envelope)
        self.assertEqual(verification.status_code, 200)
        self.assertTrue(verification.json()["valid"])
        self.assertEqual(verification.json()["report_id"], envelope["report_id"])

        tampered = {**envelope, "report": {**envelope["report"], "overall_score": 94}}
        invalid = self.client.post("/v1/reports/verify", json=tampered)
        self.assertEqual(invalid.status_code, 200)
        self.assertFalse(invalid.json()["valid"])
        self.assertIn("signature is invalid", invalid.json()["reason"])

        self.assertEqual(self.client.get("/v1/agents").status_code, 401)
        admin_headers = {"X-Registration-Token": app_module.REGISTRATION_TOKEN}
        listing = self.client.get("/v1/agents", headers=admin_headers)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()["agents"]), 1)
        self.assertEqual(listing.json()["agents"][0]["score"], 95)
        self.assertEqual(listing.json()["agents"][0]["status"], "active")
        self.assertNotIn(self.api_key, listing.text)
        details = self.client.get(f"/v1/agents/{self.agent_id}", headers=admin_headers)
        self.assertEqual(details.status_code, 200)
        self.assertEqual(details.json()["signed_report"]["report_id"], envelope["report_id"])

        reloaded = agent_registry.AgentRegistry(Path(self.temporary_directory.name) / "agents.sqlite3")
        persisted = reloaded.get_agent(self.agent_id)
        self.assertEqual(persisted["signed_report"]["signature"], envelope["signature"])

        rotated = self.client.post(
            "/v1/agents/rotate-key", json={"agent_id": self.agent_id}, headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(self.client.get(f"/v1/score?agent_id={self.agent_id}", headers={"X-API-Key": self.api_key}).status_code, 401)

    def test_report_clamps_extreme_incident_penalty_and_explains_it(self):
        response = self.client.post("/score/report", json={
            "agent_id": self.agent_id,
            "incident_count": 100,
        }, headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["overall_score"], 0)
        self.assertIn("Raw score -950 was clamped to 0.", report["reasons"])
        incidents = next(item for item in report["factor_scores"] if item["factor"] == "incidents")
        self.assertEqual(incidents["points"], -1000)

    def test_registration_persists_only_hash_and_key_works_for_scoring(self):
        response = self.client.post("/agents/register", json={"agent_id": "registration-e2e"}, headers={"X-Registration-Token": app_module.REGISTRATION_TOKEN})
        self.assertEqual(response.status_code, 201)
        registration = response.json()
        api_key = registration["api_key"]
        self.assertEqual(registration["agent_id"], "registration-e2e")
        self.assertTrue(agent_registry.REGISTRY.verify("registration-e2e", api_key))

        registry_file = Path(self.temporary_directory.name) / "agents.sqlite3"
        with sqlite3.connect(registry_file) as connection:
            stored_hash = connection.execute("SELECT key_hash FROM agents WHERE agent_id = ?", ("registration-e2e",)).fetchone()[0]
        self.assertNotEqual(stored_hash, api_key)
        self.assertEqual(stored_hash, agent_registry.AgentRegistry._hash(api_key))
        reloaded_registry = agent_registry.AgentRegistry(registry_file)
        self.assertTrue(reloaded_registry.verify("registration-e2e", api_key))
        self.assertEqual(registry_file.stat().st_mode & 0o777, 0o600)

        score_response = self.client.post(
            "/score/report",
            json={"agent_id": "registration-e2e", "incident_count": 0},
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(score_response.status_code, 200)
        self.assertEqual(score_response.json()["overall_score"], 50)
        self.assertEqual(self.client.post("/agents/register", json={"agent_id": "registration-e2e"}, headers={"X-Registration-Token": app_module.REGISTRATION_TOKEN}).status_code, 409)

    def test_registration_requires_bootstrap_token_and_is_rate_limited(self):
        self.assertEqual(self.client.post("/v1/agents/register", json={"agent_id": "no-token"}).status_code, 401)
        app_module.REGISTRATION_TOKEN = "short"
        weak = self.client.post("/v1/agents/register", json={"agent_id": "weak-token"}, headers={"X-Registration-Token": "short"})
        self.assertEqual(weak.status_code, 503)
        app_module.REGISTRATION_TOKEN = None
        disabled = self.client.post("/v1/agents/register", json={"agent_id": "disabled"}, headers={"X-Registration-Token": "test-registration-token-0123456789abcdef"})
        self.assertEqual(disabled.status_code, 503)
        app_module.REGISTRATION_TOKEN = "test-registration-token-0123456789abcdef"
        app_module.RATE_LIMITER = PerKeyRateLimiter(max_requests=1, window_seconds=60)
        first = self.client.post("/v1/agents/register", json={"agent_id": "first-bootstrap"}, headers={"X-Registration-Token": app_module.REGISTRATION_TOKEN})
        second = self.client.post("/v1/agents/register", json={"agent_id": "second-bootstrap"}, headers={"X-Registration-Token": app_module.REGISTRATION_TOKEN})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 429)

    def test_rotation_persists_across_registry_restart(self):
        replacement = agent_registry.REGISTRY.rotate(self.agent_id, self.api_key)
        restarted = agent_registry.AgentRegistry(Path(self.temporary_directory.name) / "agents.sqlite3")
        self.assertFalse(restarted.verify(self.agent_id, self.api_key))
        self.assertTrue(restarted.verify(self.agent_id, replacement))

    def test_legacy_json_hashes_migrate_into_sqlite(self):
        import json
        legacy_path = Path(self.temporary_directory.name) / "legacy-agents.json"
        database_path = Path(self.temporary_directory.name) / "migrated.sqlite3"
        legacy_key = "legacy-test-api-key"
        legacy_path.write_text(json.dumps({"legacy-agent": agent_registry.AgentRegistry._hash(legacy_key)}), encoding="utf-8")
        self.assertEqual(agent_registry.migrate_legacy_json(legacy_path, database_path), 1)
        migrated = agent_registry.AgentRegistry(database_path)
        self.assertTrue(migrated.verify("legacy-agent", legacy_key))
        self.assertFalse(legacy_path.exists())
        self.assertTrue(Path(str(legacy_path) + ".migrated").exists())
        replacement = migrated.rotate("legacy-agent", legacy_key)
        self.assertFalse(migrated.verify("legacy-agent", legacy_key))
        for database_file in Path(self.temporary_directory.name).glob("migrated.sqlite3*"):
            if database_file.name != "migrated.sqlite3.legacy-imported":
                database_file.unlink()
        Path(str(database_path) + ".legacy-imported").unlink()
        self.assertEqual(agent_registry.migrate_legacy_json(legacy_path, database_path), 0)
        after_database_loss = agent_registry.AgentRegistry(database_path)
        self.assertFalse(after_database_loss.verify("legacy-agent", legacy_key))
        self.assertFalse(after_database_loss.verify("legacy-agent", replacement))

    def test_sqlite_compare_and_swap_allows_only_one_concurrent_rotation(self):
        import concurrent.futures
        registries = [agent_registry.AgentRegistry(Path(self.temporary_directory.name) / "agents.sqlite3") for _ in range(2)]
        def rotate(registry):
            try:
                return registry.rotate(self.agent_id, self.api_key)
            except agent_registry.InvalidAgentKey:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(rotate, registries))
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_oversized_body_and_extreme_incident_count_are_rejected(self):
        oversized = self.client.post("/v1/score", content=b" " * (app_module.MAX_REQUEST_BODY_BYTES + 1), headers={"X-API-Key": self.api_key})
        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(oversized.json()["error"]["code"], "request_too_large")
        too_many = self.client.post("/v1/score", json={"agent_id": self.agent_id, "incident_count": 1_000_001}, headers={"X-API-Key": self.api_key})
        self.assertEqual(too_many.status_code, 422)
        malformed = self.client.post("/v1/score", content=b"{bad json", headers={"Content-Type": "application/json", "X-API-Key": self.api_key})
        self.assertEqual(malformed.status_code, 422)

    def test_errors_use_stable_developer_friendly_envelope(self):
        unauthorized = self.client.get("/v1/score?agent_id=agent-test")
        self.assertEqual(unauthorized.json()["error"]["code"], "unauthorized")
        invalid = self.client.post("/v1/score", json={"agent_id": "agent-test"}, headers={"X-API-Key": self.api_key})
        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(invalid.json()["error"]["code"], "invalid_request")
        self.assertTrue(invalid.json()["error"]["details"])
        missing = self.client.get("/no-such-route")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["error"]["code"], "not_found")

    def test_key_rotation_cannot_reset_rate_limit_budget(self):
        app_module.RATE_LIMITER = PerKeyRateLimiter(max_requests=2, window_seconds=60)
        self.assertEqual(self.client.post("/v1/score", json={"agent_id": self.agent_id, "incident_count": 0}, headers={"X-API-Key": self.api_key}).status_code, 200)
        rotated = self.client.post("/v1/agents/rotate-key", json={"agent_id": self.agent_id}, headers={"X-API-Key": self.api_key})
        self.assertEqual(rotated.status_code, 200)
        replacement = rotated.json()["api_key"]
        denied = self.client.post("/v1/score", json={"agent_id": self.agent_id, "incident_count": 0}, headers={"X-API-Key": replacement})
        self.assertEqual(denied.status_code, 429)

    def test_audit_timestamp_future_skew_boundary_and_beyond(self):
        base = datetime.now(timezone.utc)
        allowed = self.signed_audit(created_at=base + timedelta(seconds=security.AUDIT_PROOF_FUTURE_SKEW_SECONDS - 1))
        accepted = self.score(manifest=self.signed_manifest(), audit=allowed).json()
        self.assertTrue(accepted["evidence_results"]["audit_log"]["valid"])
        beyond = self.signed_audit(created_at=base + timedelta(seconds=security.AUDIT_PROOF_FUTURE_SKEW_SECONDS + 5))
        rejected = self.score(manifest=self.signed_manifest(), audit=beyond).json()
        self.assertFalse(rejected["evidence_results"]["audit_log"]["valid"])
        self.assertIn("in the future", rejected["evidence_results"]["audit_log"]["reason"])

    def test_audit_timestamp_exact_future_and_expiry_boundaries(self):
        fixed_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch.object(security, "now_utc", return_value=fixed_now):
            at_future_limit = self.signed_audit(created_at=fixed_now + timedelta(seconds=security.AUDIT_PROOF_FUTURE_SKEW_SECONDS))
            at_age_limit = self.signed_audit(created_at=fixed_now - timedelta(seconds=security.AUDIT_PROOF_MAX_AGE_SECONDS))
            future_result = self.score(manifest=self.signed_manifest(), audit=at_future_limit).json()
            age_result = self.score(manifest=self.signed_manifest(), audit=at_age_limit).json()
        self.assertTrue(future_result["evidence_results"]["audit_log"]["valid"])
        self.assertTrue(age_result["evidence_results"]["audit_log"]["valid"])

    def test_api_key_is_required_and_bound_to_agent_on_both_post_score_routes(self):
        payload = {"agent_id": self.agent_id, "incident_count": 0}
        for route in ("/score", "/score/report"):
            with self.subTest(route=route):
                self.assertEqual(self.client.post(route, json=payload).status_code, 401)
                self.assertEqual(self.client.post(route, json=payload, headers={"X-API-Key": "wrong-key"}).status_code, 401)
                self.assertEqual(self.client.post(route, json=payload, headers={"X-API-Key": self.api_key}).status_code, 200)

    def test_another_agents_api_key_cannot_score_this_agent(self):
        other_agent_key = agent_registry.REGISTRY.register("other-agent")
        payload = {"agent_id": self.agent_id, "incident_count": 0}
        for route in ("/score", "/score/report"):
            with self.subTest(route=route):
                response = self.client.post(route, json=payload, headers={"X-API-Key": other_agent_key})
                self.assertEqual(response.status_code, 401)

    def test_get_score_also_requires_agent_api_key(self):
        self.assertEqual(self.client.get("/score?agent_id=agent-test").status_code, 401)
        response = self.client.get("/score?agent_id=agent-test", headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["agent_id"], self.agent_id)

    def test_v1_health_and_versioned_score_routes(self):
        health = self.client.get("/v1/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok", "api_version": "v1"})
        self.assertEqual(self.client.get("/v1/status").json(), health.json())
        payload = {"agent_id": self.agent_id, "incident_count": 0}
        self.assertEqual(self.client.post("/v1/score", json=payload, headers={"X-API-Key": self.api_key}).status_code, 200)
        self.assertEqual(self.client.post("/v1/score/report", json=payload, headers={"X-API-Key": self.api_key}).status_code, 200)

    def test_health_fails_when_registry_is_not_ready(self):
        with patch.object(agent_registry.REGISTRY, "health_check", return_value=False):
            response = self.client.get("/v1/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "temporarily_unavailable")

    def test_key_rotation_invalidates_old_key_and_accepts_new_key(self):
        rotated = self.client.post(
            "/v1/agents/rotate-key",
            json={"agent_id": self.agent_id},
            headers={"X-API-Key": self.api_key},
        )
        self.assertEqual(rotated.status_code, 200)
        new_key = rotated.json()["api_key"]
        self.assertNotEqual(new_key, self.api_key)
        payload = {"agent_id": self.agent_id, "incident_count": 0}
        self.assertEqual(self.client.post("/v1/score", json=payload, headers={"X-API-Key": self.api_key}).status_code, 401)
        self.assertEqual(self.client.post("/v1/score", json=payload, headers={"X-API-Key": new_key}).status_code, 200)
        self.assertEqual(self.client.post(
            "/v1/agents/rotate-key", json={"agent_id": self.agent_id},
            headers={"X-API-Key": self.api_key},
        ).status_code, 401)

    def test_complete_v1_lifecycle_registration_to_revocation(self):
        """Exercise the documented developer journey through the public API."""
        agent_id = "outside-dev-journey"
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        security.PUBLIC_KEYS[agent_id] = base64.b64encode(public_bytes).decode("ascii")
        try:
            registration = self.client.post(
                "/v1/agents/register", json={"agent_id": agent_id},
                headers={"X-Registration-Token": app_module.REGISTRATION_TOKEN},
            )
            self.assertEqual(registration.status_code, 201)
            api_key = registration.json()["api_key"]
            headers = {"X-API-Key": api_key}

            self.assertEqual(self.client.get(f"/v1/score?agent_id={agent_id}").status_code, 401)
            health = self.client.get("/v1/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json(), {"status": "ok", "api_version": "v1"})

            challenge_response = self.client.post(
                "/v1/identity/challenge", json={"agent_id": agent_id}, headers=headers,
            )
            self.assertEqual(challenge_response.status_code, 200)
            challenge = challenge_response.json()
            signature = base64.b64encode(private_key.sign(challenge["challenge"].encode("utf-8"))).decode("ascii")
            wrong_signature = base64.b64encode(self.wrong_key.sign(challenge["challenge"].encode("utf-8"))).decode("ascii")
            invalid = self.client.post("/v1/identity/verify", json={
                "agent_id": agent_id, "challenge_id": challenge["challenge_id"], "signature": wrong_signature,
            }, headers=headers)
            self.assertEqual(invalid.status_code, 401)
            verified = self.client.post("/v1/identity/verify", json={
                "agent_id": agent_id, "challenge_id": challenge["challenge_id"], "signature": signature,
            }, headers=headers)
            self.assertEqual(verified.status_code, 200)
            self.assertTrue(verified.json()["verified"])
            replay = self.client.post("/v1/identity/verify", json={
                "agent_id": agent_id, "challenge_id": challenge["challenge_id"], "signature": signature,
            }, headers=headers)
            self.assertEqual(replay.status_code, 409)

            actions = ["read:profile", "write:notes"]
            manifest = {
                "allowed_actions": actions,
                "signature": base64.b64encode(private_key.sign(canonical_permissions_payload(agent_id, actions))).decode("ascii"),
            }
            created_at = datetime.now(timezone.utc)
            digest = "c" * 64
            audit = {
                "digest": digest,
                "created_at": created_at.isoformat().replace("+00:00", "Z"),
                "signature": base64.b64encode(private_key.sign(canonical_audit_payload(agent_id, digest, created_at))).decode("ascii"),
            }
            evidence = {"agent_id": agent_id, "permission_manifest": manifest, "audit_log": audit, "incident_count": 0}
            scored = self.client.post("/v1/score", json=evidence, headers=headers)
            self.assertEqual(scored.status_code, 200)
            self.assertEqual(scored.json()["score"], 95)
            self.assertEqual(scored.json()["rating"], "high_score")
            self.assertTrue(all(result["valid"] for result in scored.json()["evidence_results"].values()))

            report_response = self.client.post("/v1/score/report", json=evidence, headers=headers)
            self.assertEqual(report_response.status_code, 200)
            report = report_response.json()
            self.assertEqual(report["overall_score"], 95)
            self.assertTrue(report["reasons"])
            self.assertTrue(all(
                item["status"] == "verified"
                for item in report["factor_scores"]
                if item["factor"] != "incidents"
            ))
            fetched = self.client.get(f"/v1/score?agent_id={agent_id}", headers=headers)
            self.assertEqual(fetched.status_code, 200)
            self.assertEqual(fetched.json()["score"], 65)
            self.assertTrue(fetched.json()["reason"])

            malformed = self.client.post("/v1/score", content=b"{bad json", headers={**headers, "Content-Type": "application/json"})
            self.assertEqual(malformed.status_code, 422)
            self.assertEqual(malformed.json()["error"]["code"], "invalid_request")
            other_agent_key = agent_registry.REGISTRY.register("journey-other-agent")
            cross_agent = self.client.post("/v1/score", json=evidence, headers={"X-API-Key": other_agent_key})
            self.assertEqual(cross_agent.status_code, 401)

            rotated = self.client.post("/v1/agents/rotate-key", json={"agent_id": agent_id}, headers=headers)
            self.assertEqual(rotated.status_code, 200)
            replacement_key = rotated.json()["api_key"]
            self.assertEqual(self.client.get(f"/v1/score?agent_id={agent_id}", headers=headers).status_code, 401)
            replacement_score = self.client.get(
                f"/v1/score?agent_id={agent_id}", headers={"X-API-Key": replacement_key},
            )
            self.assertEqual(replacement_score.status_code, 200)
        finally:
            security.PUBLIC_KEYS.pop(agent_id, None)

    def test_rate_limit_is_per_key_and_returns_retry_after(self):
        app_module.RATE_LIMITER = PerKeyRateLimiter(max_requests=2, window_seconds=60)
        payload = {"agent_id": self.agent_id, "incident_count": 0}
        for _ in range(2):
            self.assertEqual(self.client.post("/v1/score", json=payload, headers={"X-API-Key": self.api_key}).status_code, 200)
        limited = self.client.post("/v1/score", json=payload, headers={"X-API-Key": self.api_key})
        self.assertEqual(limited.status_code, 429)
        self.assertGreaterEqual(int(limited.headers["Retry-After"]), 1)

        other_key = agent_registry.REGISTRY.register("independent-rate-key")
        independent = self.client.post(
            "/v1/score",
            json={"agent_id": "independent-rate-key", "incident_count": 0},
            headers={"X-API-Key": other_key},
        )
        self.assertEqual(independent.status_code, 200)

    def test_rate_limiter_resets_at_next_fixed_window(self):
        now = [100.0]
        limiter = PerKeyRateLimiter(max_requests=1, window_seconds=10, clock=lambda: now[0])
        self.assertEqual(limiter.check("key-hash"), 0)
        self.assertEqual(limiter.check("key-hash"), 10)
        now[0] = 110.0
        self.assertEqual(limiter.check("key-hash"), 0)

    def test_rating_bands_clamping_and_input_validation(self):
        from scoring import rating_for_score
        self.assertEqual(rating_for_score(80), "high_score")
        self.assertEqual(rating_for_score(79), "review")
        self.assertEqual(rating_for_score(50), "review")
        self.assertEqual(rating_for_score(49), "low_score")
        self.assertEqual(self.score(manifest=None, audit=None, incident_count=100).json()["score"], 0)
        self.assertEqual(self.score(manifest=self.signed_manifest(), incident_count=-1).status_code, 422)


if __name__ == "__main__":
    unittest.main()
