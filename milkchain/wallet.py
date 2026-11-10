#!/usr/bin/env python3
"""Create and inspect encrypted Ed25519 wallets for Biscuits."""
import argparse
import base64
import getpass
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 2
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
NONCE_BYTES = 12


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _derive_key(passphrase, salt):
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError("wallet passphrase must contain at least 12 characters")
    return Scrypt(
        salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    ).derive(passphrase.encode("utf-8"))


def _wallet_payload(key, passphrase):
    private_bytes = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = public_hex(key)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    aad = f"butter-bank-wallet-v{FORMAT_VERSION}:{public}".encode("ascii")
    ciphertext = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, private_bytes, aad)
    return {
        "version": FORMAT_VERSION,
        "kdf": "scrypt",
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "public_key": public,
    }


def _prompt_new_passphrase():
    first = getpass.getpass("Create wallet passphrase (minimum 12 characters): ")
    second = getpass.getpass("Confirm wallet passphrase: ")
    if len(first) < 12:
        raise ValueError("wallet passphrase must contain at least 12 characters")
    if first != second:
        raise ValueError("wallet passphrases do not match")
    return first


def _prompt_passphrase():
    return getpass.getpass("Wallet passphrase: ")


def _decode_wallet(data, passphrase):
    required = {"version", "kdf", "cipher", "salt", "nonce", "ciphertext", "public_key"}
    if set(data) != required or data.get("version") != FORMAT_VERSION:
        raise ValueError("unsupported encrypted wallet format")
    if data.get("kdf") != "scrypt" or data.get("cipher") != "AES-256-GCM":
        raise ValueError("unsupported wallet encryption parameters")
    public = data.get("public_key")
    if not isinstance(public, str) or len(public) != 64:
        raise ValueError("wallet public key must be 32-byte hexadecimal")
    try:
        public_bytes = bytes.fromhex(public)
        salt = base64.b64decode(data["salt"], validate=True)
        nonce = base64.b64decode(data["nonce"], validate=True)
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
    except (TypeError, ValueError):
        raise ValueError("wallet encryption fields are malformed")
    if len(public_bytes) != 32 or len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES or len(ciphertext) != 48:
        raise ValueError("wallet encryption fields have invalid lengths")
    aad = f"butter-bank-wallet-v{FORMAT_VERSION}:{public}".encode("ascii")
    try:
        private = AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("wallet passphrase is incorrect or wallet data was altered") from exc
    key = Ed25519PrivateKey.from_private_bytes(private)
    if public_hex(key) != public.lower():
        raise ValueError("wallet public key does not match its private key")
    return key, public.lower()


def read_wallet(path, passphrase=None):
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

    if not isinstance(data, dict):
        raise ValueError("wallet file must contain a JSON object")
    if set(data) == {"private_key", "public_key"}:
        # Preserve compatibility with existing wallets, but make the risk explicit.
        print(
            "Warning: this legacy wallet stores its private key without encryption. "
            "Run 'wallet.py encrypt FILE' to protect it.",
            file=sys.stderr,
        )
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

    if passphrase is None:
        passphrase = _prompt_passphrase()
    return _decode_wallet(data, passphrase)


def write_new_wallet(path, key, passphrase):
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise FileExistsError("refusing to overwrite an existing wallet file")
    payload = json.dumps(_wallet_payload(key, passphrase), sort_keys=True, indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(target), flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    if hasattr(os, "fchmod"):
        os.chmod(target, 0o600)
    return public_hex(key)


def encrypt_legacy_wallet(path, passphrase):
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("wallet file must be a regular non-symlink file")
    metadata = target.stat()
    key, public = read_wallet(target, passphrase)
    payload = json.dumps(_wallet_payload(key, passphrase), sort_keys=True, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        current = target.stat()
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RuntimeError("wallet file changed during encryption; refusing to replace it")
        os.replace(temporary, target)
        try:
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return public


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    create = sub.add_parser("create")
    create.add_argument("file")
    address = sub.add_parser("address")
    address.add_argument("file")
    encrypt = sub.add_parser("encrypt")
    encrypt.add_argument("file")
    args = parser.parse_args()

    if args.cmd == "create":
        passphrase = _prompt_new_passphrase()
        key = Ed25519PrivateKey.generate()
        public = write_new_wallet(args.file, key, passphrase)
        print("Public address:", public)
        print("The private key is encrypted with a passphrase-derived AES-256-GCM key.")
        print("Keep the passphrase separate from the wallet file; it cannot be recovered.")
    elif args.cmd == "address":
        _, public = read_wallet(args.file)
        print(public)
    else:
        passphrase = _prompt_new_passphrase()
        public = encrypt_legacy_wallet(args.file, passphrase)
        print("Encrypted wallet:", public)


if __name__ == "__main__":
    main()
