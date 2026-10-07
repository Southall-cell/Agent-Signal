"""Sign allowed actions using a local Ed25519 private key."""
import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from security import canonical_permissions_payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--action", required=True, action="append", dest="actions", help="allowed action; repeat as needed")
    args = parser.parse_args()

    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    signature = private_key.sign(canonical_permissions_payload(args.agent_id, args.actions))
    print(json.dumps({
        "agent_id": args.agent_id,
        "permission_manifest": {
            "allowed_actions": args.actions,
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }, indent=2))


if __name__ == "__main__":
    main()
