import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wallet import public_hex, read_wallet


class WalletFileTests(unittest.TestCase):
    def write_wallet(self, path):
        key = Ed25519PrivateKey.generate()
        path.write_text(json.dumps({
            "private_key": key.private_bytes_raw().hex(),
            "public_key": public_hex(key),
        }))
        path.chmod(0o600)
        return key

    def test_reads_valid_owner_only_wallet(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.json"
            expected = self.write_wallet(path)
            actual, address = read_wallet(path)
            self.assertEqual(actual.private_bytes_raw(), expected.private_bytes_raw())
            self.assertEqual(address, public_hex(expected))

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_rejects_group_or_world_readable_wallet(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.json"
            self.write_wallet(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "permissions 0600"):
                read_wallet(path)

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_rejects_wallet_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real.json"
            link = Path(directory) / "linked.json"
            self.write_wallet(real)
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                read_wallet(link)

    def test_rejects_mismatched_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.json"
            self.write_wallet(path)
            data = json.loads(path.read_text())
            data["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            path.write_text(json.dumps(data))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "does not match"):
                read_wallet(path)


if __name__ == "__main__":
    unittest.main()
