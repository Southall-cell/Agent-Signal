#!/usr/bin/env python3
"""Register a local agent, sign evidence, submit it, and print its trust report."""
import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security import canonical_audit_payload, canonical_permissions_payload, utc_text  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("API_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--agent-id", default="demo-agent")
    parser.add_argument("--private-key", type=Path, default=ROOT / ".dev" / "demo-agent.pem")
    args = parser.parse_args()

    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    secret_path = ROOT / ".dev" / f"{args.agent_id}.api-key"
    registration_env = ROOT / ".dev" / "registration.env"
    registration_token = registration_env.read_text(encoding="utf-8").strip().partition("=")[2]
    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=10) as client:
        if secret_path.exists():
            api_key = secret_path.read_text(encoding="utf-8").strip()
            check = client.get("/v1/score", params={"agent_id": args.agent_id}, headers={"X-API-Key": api_key})
            if check.status_code == 401:
                raise SystemExit(f"Saved key is no longer valid. Reset the local dev state and retry (see API.md).")
            check.raise_for_status()
        else:
            registration = client.post(
                "/v1/agents/register",
                json={"agent_id": args.agent_id},
                headers={"X-Registration-Token": registration_token},
            )
            if registration.status_code == 409:
                raise SystemExit("Agent is already registered but no local key file exists. Reset local dev state and retry (see API.md).")
            registration.raise_for_status()
            api_key = registration.json()["api_key"]
            descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
                secret_file.write(api_key + "\n")

        agent_headers = {"X-API-Key": api_key}
        challenge_response = client.post("/v1/identity/challenge", json={"agent_id": args.agent_id}, headers=agent_headers)
        challenge_response.raise_for_status()
        challenge = challenge_response.json()
        signature = base64.b64encode(private_key.sign(challenge["challenge"].encode("utf-8"))).decode("ascii")
        verified = client.post("/v1/identity/verify", json={
            "agent_id": args.agent_id,
            "challenge_id": challenge["challenge_id"],
            "signature": signature,
        }, headers=agent_headers)
        verified.raise_for_status()

        actions = ["read:profile", "write:notes"]
        permission_manifest = {
            "allowed_actions": actions,
            "signature": base64.b64encode(private_key.sign(canonical_permissions_payload(args.agent_id, actions))).decode("ascii"),
        }
        created_at = datetime.now(timezone.utc)
        digest = hashlib.sha256(b"local developer example audit event").hexdigest()
        audit_log = {
            "digest": digest,
            "created_at": utc_text(created_at),
            "signature": base64.b64encode(private_key.sign(canonical_audit_payload(args.agent_id, digest, created_at))).decode("ascii"),
        }
        evidence = {
            "agent_id": args.agent_id,
            "permission_manifest": permission_manifest,
            "audit_log": audit_log,
            "incident_count": 0,
        }
        score = client.post("/v1/score", json=evidence, headers={"X-API-Key": api_key})
        score.raise_for_status()
        report = client.post("/v1/score/report", json=evidence, headers={"X-API-Key": api_key})
        report.raise_for_status()
        print(json.dumps(report.json(), indent=2))


if __name__ == "__main__":
    main()
