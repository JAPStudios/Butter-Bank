import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        self.validator = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        self.chain_id = "biscuits-testnet"
        self.issuer_hash = issuer_set_hash(self.issuers)

    def certificate(self, count=3):
        signatures = [
            sign_admission(key, self.chain_id, self.validator, 10, 20, self.issuer_hash)
            for key in self.issuer_keys[:count]
        ]
        return {
            "chain_id": self.chain_id,
            "validator_public_key": self.validator,
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
            [certificate], self.issuers, self.chain_id, 15
        )
        self.assertEqual(validators, [{"public_key": self.validator, "voting_power": 1}])

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


if __name__ == "__main__":
    unittest.main()
