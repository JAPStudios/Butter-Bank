#!/usr/bin/env python3
"""Create and inspect owner-protected Ed25519 wallets for Biscuits."""
import argparse
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def read_wallet(path):
    """Read a wallet without following symlinks or accepting group/world access."""
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("wallet file must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ValueError("wallet file cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("wallet file must be a regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("wallet file must have permissions 0600")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            data = json.load(stream)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(data, dict) or set(data) != {"private_key", "public_key"}:
        raise ValueError("wallet file must contain private_key and public_key")
    try:
        private = bytes.fromhex(data["private_key"])
        public = bytes.fromhex(data["public_key"])
    except (TypeError, ValueError):
        raise ValueError("wallet keys must be hexadecimal")
    if len(private) != 32 or len(public) != 32:
        raise ValueError("wallet keys must each be 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(private)
    if public_hex(key) != public.hex():
        raise ValueError("wallet public key does not match its private key")
    return key, public.hex()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    create = sub.add_parser("create")
    create.add_argument("file")
    address = sub.add_parser("address")
    address.add_argument("file")
    args = parser.parse_args()
    if args.cmd == "create":
        target = Path(args.file)
        if target.exists() or target.is_symlink():
            raise SystemExit("Refusing to overwrite an existing wallet file.")
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        public = public_hex(key)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(target), flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(
                {"private_key": private, "public_key": public}, indent=2
            ) + "\n")
        try:
            target.chmod(0o600)
        except OSError:
            pass
        print("Public address:", public)
        print("Keep the wallet file secret; anyone with its private key can spend funds.")
    else:
        _, public = read_wallet(args.file)
        print(public)


if __name__ == "__main__":
    main()
