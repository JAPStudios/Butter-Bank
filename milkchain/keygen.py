"""Generate an Ed25519 validator keypair without overwriting existing files."""
import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keypair(path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes_raw().hex() + "\n"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(seed)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    public_key = private_key.public_key().public_bytes_raw().hex()
    return public_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new private-key file (created with mode 0600)")
    args = parser.parse_args()
    public_key = generate_keypair(args.output)
    print("Validator public key:", public_key)
    print("Private key saved with owner-only permissions:", args.output)


if __name__ == "__main__":
    main()
