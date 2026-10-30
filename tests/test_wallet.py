import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from wallet import create_wallet, read_wallet


class WalletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test-wallet.json"

    def test_create_writes_valid_json_with_real_newline(self):
        public = create_wallet(self.path)

        raw = self.path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\\n", raw)
        data = json.loads(raw)
        self.assertEqual(data["public_key"], public)

        key, loaded_public = read_wallet(self.path)
        self.assertEqual(loaded_public, public)
        self.assertEqual(
            key.public_key().public_bytes_raw().hex(),
            public,
        )

    def test_wallet_file_is_created_with_private_permissions(self):
        create_wallet(self.path)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_create_refuses_to_overwrite_existing_file(self):
        self.path.write_text("keep this file", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            create_wallet(self.path)
        self.assertEqual(self.path.read_text(encoding="utf-8"), "keep this file")

    def test_read_rejects_extra_fields(self):
        self.path.write_text(
            json.dumps({"private_key": "00", "public_key": "00", "extra": True}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "must contain"):
            read_wallet(self.path)

    def test_read_rejects_mismatched_public_key(self):
        create_wallet(self.path)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data["public_key"] = "00" * 32
        self.path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match"):
            read_wallet(self.path)


if __name__ == "__main__":
    unittest.main()
