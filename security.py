"""Local Ed25519 key lookup, challenge state, and signature verification."""
import base64
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from models import AuditLogProof, EvidenceResult, PermissionsManifest

CHALLENGE_TTL_SECONDS = 60
IDENTITY_PROOF_TTL_SECONDS = 300
AUDIT_PROOF_MAX_AGE_SECONDS = 300
AUDIT_PROOF_FUTURE_SKEW_SECONDS = 30
PUBLIC_KEYS_FILE = Path(os.environ.get("AGENT_PUBLIC_KEYS_FILE", Path(__file__).with_name("agent_public_keys.json")))


def load_public_keys() -> Dict[str, str]:
    """Read a local map of agent IDs to base64-encoded raw Ed25519 public keys."""
    if not PUBLIC_KEYS_FILE.exists():
        return {}
    with PUBLIC_KEYS_FILE.open(encoding="utf-8") as key_file:
        loaded = json.load(key_file)
    if not isinstance(loaded, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in loaded.items()):
        raise RuntimeError("Public key registry must map agent IDs to base64 Ed25519 public keys.")
    return loaded


PUBLIC_KEYS: Dict[str, str] = load_public_keys()


@dataclass
class ChallengeRecord:
    agent_id: str
    challenge: str
    expires_at: datetime
    used: bool = False


CHALLENGES: Dict[str, ChallengeRecord] = {}
IDENTITY_PROOFS: Dict[str, datetime] = {}
CONSUMED_CHALLENGES = set()
_CHALLENGE_LOCK = threading.RLock()
MAX_PENDING_CHALLENGES = 10000


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def make_challenge(agent_id: str) -> tuple[str, ChallengeRecord]:
    """Create and store a unique, short-lived challenge for a registered agent."""
    challenge_id = secrets.token_urlsafe(18)
    challenge = secrets.token_urlsafe(32)
    record = ChallengeRecord(agent_id, challenge, now_utc() + timedelta(seconds=CHALLENGE_TTL_SECONDS))
    with _CHALLENGE_LOCK:
        now = now_utc()
        for old_id, old_record in list(CHALLENGES.items()):
            if old_record.used or old_record.expires_at <= now:
                CHALLENGES.pop(old_id, None)
                CONSUMED_CHALLENGES.discard(old_id)
        if len(CHALLENGES) >= MAX_PENDING_CHALLENGES:
            raise OverflowError("Too many pending identity challenges.")
        CHALLENGES[challenge_id] = record
    return challenge_id, record


def verify_and_consume_challenge(challenge_id: str, agent_id: str, signature_text: str):
    """Verify under the challenge lock; invalid signatures do not burn the challenge."""
    with _CHALLENGE_LOCK:
        record = CHALLENGES.get(challenge_id)
        if record is None:
            return ("consumed" if challenge_id in CONSUMED_CHALLENGES else "missing"), None
        if record.agent_id != agent_id:
            return "wrong_agent", None
        if now_utc() >= record.expires_at:
            CHALLENGES.pop(challenge_id, None)
            CONSUMED_CHALLENGES.add(challenge_id)
            return "expired", None
        try:
            verify_identity_signature(agent_id, record.challenge, signature_text)
        except (ValueError, InvalidSignature):
            return "invalid_signature", None
        CHALLENGES.pop(challenge_id, None)
        CONSUMED_CHALLENGES.add(challenge_id)
        if len(CONSUMED_CHALLENGES) > MAX_PENDING_CHALLENGES:
            CONSUMED_CHALLENGES.pop()
        verified_at = now_utc()
        IDENTITY_PROOFS[agent_id] = verified_at + timedelta(seconds=IDENTITY_PROOF_TTL_SECONDS)
        return "verified", verified_at


def canonical_permissions_payload(agent_id: str, allowed_actions: list[str]) -> bytes:
    """Return the exact UTF-8 bytes agents must sign for a permissions manifest."""
    signed_content = {
        "context": "agent-permissions-v1",
        "agent_id": agent_id,
        "allowed_actions": allowed_actions,
    }
    return json.dumps(signed_content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_audit_payload(agent_id: str, digest: str, created_at: datetime) -> bytes:
    """Return the bytes an agent signs for its SHA-256 audit digest."""
    signed_content = {
        "context": "agent-audit-digest-v1",
        "agent_id": agent_id,
        "algorithm": "sha256",
        "digest": digest.lower(),
        "created_at": utc_text(created_at),
    }
    return json.dumps(signed_content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _registered_public_key(agent_id: str) -> Ed25519PublicKey:
    encoded = PUBLIC_KEYS.get(agent_id)
    if encoded is None:
        raise ValueError("No public key is registered for this agent.")
    raw_key = base64.b64decode(encoded, validate=True)
    return Ed25519PublicKey.from_public_bytes(raw_key)


def verify_permissions_manifest(agent_id: str, manifest: Optional[PermissionsManifest]) -> EvidenceResult:
    if manifest is None:
        return EvidenceResult(valid=False, verification="cryptographic", reason="Signed permissions manifest is missing.")
    if not manifest.signature:
        return EvidenceResult(valid=False, verification="cryptographic", reason="Permissions manifest signature is missing.")
    if agent_id not in PUBLIC_KEYS:
        return EvidenceResult(valid=False, verification="cryptographic", reason="No public key is registered for this agent.")
    try:
        signature = base64.b64decode(manifest.signature, validate=True)
        public_key = _registered_public_key(agent_id)
        public_key.verify(signature, canonical_permissions_payload(agent_id, manifest.allowed_actions))
    except (ValueError, InvalidSignature):
        return EvidenceResult(valid=False, verification="cryptographic", reason="Permissions manifest signature is invalid.")
    return EvidenceResult(valid=True, verification="cryptographic", reason="Permissions manifest signature verified.")


def verify_audit_proof(agent_id: str, proof: Optional[AuditLogProof]) -> EvidenceResult:
    if proof is None:
        return EvidenceResult(valid=False, verification="cryptographic", reason="Signed audit log proof is missing.")
    if not proof.signature:
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log signature is missing.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", proof.digest):
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log digest must be a 64-character SHA-256 hex value.")
    if proof.created_at.tzinfo is None or proof.created_at.utcoffset() is None:
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log timestamp must include a UTC offset.")

    now = now_utc()
    created_at = proof.created_at.astimezone(timezone.utc)
    if created_at > now + timedelta(seconds=AUDIT_PROOF_FUTURE_SKEW_SECONDS):
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log proof timestamp is in the future.")
    if now - created_at > timedelta(seconds=AUDIT_PROOF_MAX_AGE_SECONDS):
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log proof has expired.")
    if agent_id not in PUBLIC_KEYS:
        return EvidenceResult(valid=False, verification="cryptographic", reason="No public key is registered for this agent.")

    try:
        signature = base64.b64decode(proof.signature, validate=True)
        public_key = _registered_public_key(agent_id)
        public_key.verify(signature, canonical_audit_payload(agent_id, proof.digest, created_at))
    except (ValueError, InvalidSignature):
        return EvidenceResult(valid=False, verification="cryptographic", reason="Audit log signature is invalid.")
    return EvidenceResult(valid=True, verification="cryptographic", reason="SHA-256 audit log digest signature verified.")


def current_identity_result(agent_id: str) -> EvidenceResult:
    with _CHALLENGE_LOCK:
        proof_expiry = IDENTITY_PROOFS.get(agent_id)
        if proof_expiry is not None and proof_expiry > now_utc():
            return EvidenceResult(valid=True, verification="cryptographic", reason="Ed25519 challenge signature verified.")
        IDENTITY_PROOFS.pop(agent_id, None)
    return EvidenceResult(valid=False, verification="cryptographic", reason="No unexpired challenge signature has been verified.")


def verify_identity_signature(agent_id: str, challenge: str, signature_text: str) -> bool:
    signature = base64.b64decode(signature_text, validate=True)
    public_key = _registered_public_key(agent_id)
    public_key.verify(signature, challenge.encode("utf-8"))
    return True
