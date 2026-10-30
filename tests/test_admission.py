import unittest
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keygen import generate_keypair

from admission import (
    admission_signing_bytes,
    issuer_set_hash,
    sign_admission,
    validator_set_from_certificates,
    verify_admission_certificate,
)


class AdmissionCertificateTests(unittest.TestCase):
    def setUp(self):
        self.issuer_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.issuers = [key.public_key().public_bytes_raw().hex() for key in self.issuer_keys]
        self.validators = [
            Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            for _ in range(4)
        ]
        self.validator = self.validators[0]
        self.chain_id = "biscuits-testnet"
        self.issuer_hash = issuer_set_hash(self.issuers)

    def certificate(self, count=3, validator_key=None):
        validator_key = validator_key or self.validator
        signatures = [
            sign_admission(key, self.chain_id, validator_key, 10, 20, self.issuer_hash)
            for key in self.issuer_keys[:count]
        ]
        return {
            "chain_id": self.chain_id,
            "validator_public_key": validator_key,
            "issued_epoch": 10,
            "expires_epoch": 20,
            "issuer_set_hash": self.issuer_hash,
            "signatures": signatures,
        }

    def test_threshold_admission_and_equal_voting_power(self):
        certificate = self.certificate()
        self.assertTrue(verify_admission_certificate(certificate, self.issuers,
                                                     self.chain_id, 15))
        validators = validator_set_from_certificates(
            [self.certificate(validator_key=key) for key in self.validators],
            self.issuers, self.chain_id, 15
        )
        self.assertEqual(len(validators), 4)
        self.assertEqual({item["voting_power"] for item in validators}, {1})

    def test_rejects_insufficient_signatures_and_expired_certificates(self):
        self.assertFalse(verify_admission_certificate(
            self.certificate(2), self.issuers, self.chain_id, 15
        ))
        self.assertFalse(verify_admission_certificate(
            self.certificate(), self.issuers, self.chain_id, 21
        ))

    def test_rejects_duplicate_issuers_and_validator_keys(self):
        certificate = self.certificate()
        certificate["signatures"].append(certificate["signatures"][0])
        self.assertFalse(verify_admission_certificate(
            certificate, self.issuers, self.chain_id, 15
        ))
        with self.assertRaises(ValueError):
            validator_set_from_certificates(
                [self.certificate(), self.certificate()],
                self.issuers, self.chain_id, 15
            )
        with self.assertRaises(ValueError):
            issuer_set_hash([
                self.issuers[0], self.issuers[0].upper(),
                self.issuers[1], self.issuers[2]
            ])
        case_duplicate = self.certificate(validator_key=self.validator.upper())
        with self.assertRaises(ValueError):
            validator_set_from_certificates(
                [self.certificate(), case_duplicate],
                self.issuers, self.chain_id, 15
            )

    def test_keygen_creates_owner_only_key_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validator.key"
            public = generate_keypair(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))
            self.assertEqual(private.public_key().public_bytes_raw().hex(), public)
            with self.assertRaises(FileExistsError):
                generate_keypair(path)


if __name__ == "__main__":
    unittest.main()
