#!/usr/bin/env python3
"""Create and inspect Ed25519 wallets for Emberchain."""
import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def read_wallet(path):
    """Load a wallet and verify that its public key matches its private key."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"private_key", "public_key"}:
        raise ValueError("wallet file must contain private_key and public_key")

    try:
        private = bytes.fromhex(data["private_key"])
        public = bytes.fromhex(data["public_key"])
    except (TypeError, ValueError):
        raise ValueError("wallet keys must be hexadecimal") from None

    if len(private) != 32 or len(public) != 32:
        raise ValueError("wallet keys must each be 32 bytes")

    key = Ed25519PrivateKey.from_private_bytes(private)
    derived_public = public_hex(key)
    if derived_public != public.hex():
        raise ValueError("wallet public key does not match its private key")
    return key, derived_public


def create_wallet(path):
    """Create a new wallet file without overwriting an existing path."""
    target = Path(path)
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public = public_hex(key)
    payload = json.dumps(
        {"private_key": private, "public_key": public},
        indent=2,
    ) + "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(target), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(payload)
        try:
            target.chmod(0o600)
        except OSError:
            # The creation mode remains the best available protection on
            # platforms that do not support changing permissions afterward.
            pass
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return public


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("file")

    address_parser = subparsers.add_parser("address")
    address_parser.add_argument("file")

    args = parser.parse_args()
    if args.cmd == "create":
        try:
            public = create_wallet(args.file)
        except FileExistsError:
            parser.error("refusing to overwrite an existing wallet file")
        except OSError as error:
            parser.error(f"cannot create wallet file: {error}")
        print("Public address:", public)
        print("Keep the wallet file secret; anyone with its private key can spend funds.")
    else:
        _, public = read_wallet(args.file)
        print(public)


if __name__ == "__main__":
    main()
