"""Create a locally signed, time-bounded SHA-256 audit digest proof."""
import argparse
import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from security import canonical_audit_payload, utc_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--digest", required=True, help="64-character SHA-256 hex digest")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.digest):
        parser.error("--digest must be a 64-character SHA-256 hex value")

    created_at = datetime.now(timezone.utc)
    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    signature = private_key.sign(canonical_audit_payload(args.agent_id, args.digest, created_at))
    print(json.dumps({
        "agent_id": args.agent_id,
        "audit_log": {
            "digest": args.digest,
            "created_at": utc_text(created_at),
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }, indent=2))


if __name__ == "__main__":
    main()
