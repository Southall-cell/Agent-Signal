"""Generate an Ed25519 agent key and register only its public key locally."""
import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--private-key-out", required=True, type=Path)
    parser.add_argument("--registry", type=Path, default=Path(__file__).with_name("agent_public_keys.json"))
    parser.add_argument("--force", action="store_true", help="replace an existing private key or agent registration")
    args = parser.parse_args()

    registry = json.loads(args.registry.read_text(encoding="utf-8")) if args.registry.exists() else {}
    if (args.private_key_out.exists() or args.agent_id in registry) and not args.force:
        parser.error("key path or agent ID already exists; use --force to replace it")

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    args.private_key_out.parent.mkdir(parents=True, exist_ok=True)
    private_fd = os.open(args.private_key_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(private_fd, "wb") as private_file:
        private_file.write(private_pem)
    os.chmod(args.private_key_out, 0o600)

    registry[args.agent_id] = base64.b64encode(public_raw).decode("ascii")
    args.registry.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    print(f"Private key saved to {args.private_key_out}")
    print(f"Public key registered for {args.agent_id} in {args.registry}")


if __name__ == "__main__":
    main()
