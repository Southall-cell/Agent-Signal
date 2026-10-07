"""Local Ed25519 signing and verification for Agent Signal report envelopes."""
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from models import SignedTrustReport, TrustReportResponse


DEFAULT_SIGNING_KEY = Path(__file__).with_name(".dev") / "report-signing-key.pem"
SIGNING_KEY_FILE = Path(os.environ.get("REPORT_SIGNING_PRIVATE_KEY_FILE", DEFAULT_SIGNING_KEY))
REPORT_CONTEXT = "agent-signal-trust-report-v1"


class ReportSigningUnavailable(Exception):
    """Raised when the local report signing key is absent or unsafe."""


def _private_key() -> Ed25519PrivateKey:
    try:
        mode = stat.S_IMODE(SIGNING_KEY_FILE.stat().st_mode)
        if mode & 0o077:
            raise ReportSigningUnavailable("The report signing key must be readable only by its owner.")
        loaded = serialization.load_pem_private_key(SIGNING_KEY_FILE.read_bytes(), password=None)
    except ReportSigningUnavailable:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ReportSigningUnavailable("The local report signing key is unavailable or invalid.") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ReportSigningUnavailable("The local report signing key must be Ed25519.")
    return loaded


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key_id(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(_public_key_bytes(public_key)).hexdigest()[:32]


def public_key_info() -> tuple[str, str]:
    public_key = _private_key().public_key()
    return _key_id(public_key), base64.b64encode(_public_key_bytes(public_key)).decode("ascii")


def _signed_bytes(report_id: str, signing_key_id: str, report: dict) -> bytes:
    payload = {
        "context": REPORT_CONTEXT,
        "report_id": report_id,
        "algorithm": "Ed25519",
        "signing_key_id": signing_key_id,
        "report": report,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_report(report_id: str, report: TrustReportResponse) -> SignedTrustReport:
    private_key = _private_key()
    public_key = private_key.public_key()
    key_id = _key_id(public_key)
    report_data = report.model_dump(mode="json")
    signature = private_key.sign(_signed_bytes(report_id, key_id, report_data))
    return SignedTrustReport(
        report_id=report_id,
        algorithm="Ed25519",
        signing_key_id=key_id,
        report=report,
        signature=base64.b64encode(signature).decode("ascii"),
    )


def verify_report(envelope: SignedTrustReport) -> tuple[bool, str]:
    try:
        public_key = _private_key().public_key()
        if envelope.signing_key_id != _key_id(public_key):
            return False, "Report was signed by an unknown or superseded local signing key."
        signature = base64.b64decode(envelope.signature, validate=True)
        public_key.verify(
            signature,
            _signed_bytes(
                envelope.report_id,
                envelope.signing_key_id,
                envelope.report.model_dump(mode="json"),
            ),
        )
    except InvalidSignature:
        return False, "Report signature is invalid; the report may have been changed."
    except (ValueError, ReportSigningUnavailable):
        return False, "Report signature could not be verified with the current local signing key."
    return True, "Report signature verified with the local Agent Signal signing key."
