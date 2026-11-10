import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wallet import encrypt_legacy_wallet, public_hex, read_wallet, write_new_wallet


class EncryptedWalletTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "biscuits.wallet"
        self.passphrase = "correct horse battery staple"

    def test_new_wallet_encrypts_private_key_and_round_trips(self):
        key = Ed25519PrivateKey.generate()
        public = write_new_wallet(self.path, key, self.passphrase)
        stored = self.path.read_text(encoding="utf-8")
        self.assertNotIn(key.private_bytes_raw().hex(), stored)
        self.assertEqual(public, public_hex(key))
        loaded, loaded_public = read_wallet(self.path, self.passphrase)
        self.assertEqual(loaded.private_bytes_raw(), key.private_bytes_raw())
        self.assertEqual(loaded_public, public)
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_wrong_passphrase_and_tampered_ciphertext_are_rejected(self):
        key = Ed25519PrivateKey.generate()
        write_new_wallet(self.path, key, self.passphrase)
        with self.assertRaisesRegex(ValueError, "passphrase is incorrect"):
            read_wallet(self.path, "an incorrect passphrase")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        ciphertext = data["ciphertext"]
        data["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        self.path.write_text(json.dumps(data), encoding="utf-8")
        if os.name != "nt":
            self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            read_wallet(self.path, self.passphrase)

    def test_legacy_wallet_can_be_encrypted_in_place(self):
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes_raw().hex()
        public = public_hex(key)
        self.path.write_text(
            json.dumps({"private_key": private, "public_key": public}),
            encoding="utf-8",
        )
        if os.name != "nt":
            self.path.chmod(0o600)
        migrated_public = encrypt_legacy_wallet(self.path, self.passphrase)
        self.assertEqual(migrated_public, public)
        stored = self.path.read_text(encoding="utf-8")
        self.assertNotIn(private, stored)
        loaded, loaded_public = read_wallet(self.path, self.passphrase)
        self.assertEqual(loaded_public, public)
        self.assertEqual(loaded.private_bytes_raw().hex(), private)

    def test_create_refuses_to_overwrite_existing_wallet(self):
        key = Ed25519PrivateKey.generate()
        write_new_wallet(self.path, key, self.passphrase)
        with self.assertRaises(FileExistsError):
            write_new_wallet(self.path, Ed25519PrivateKey.generate(), self.passphrase)


if __name__ == "__main__":
    unittest.main()
