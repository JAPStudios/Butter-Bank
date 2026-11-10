import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from consensus import validator_set_hash
from validator_transitions import (
    make_transition_certificate,
    verify_transition_certificate,
    verify_transition_history,
    validator_set_at_height,
)


class ValidatorTransitionTests(unittest.TestCase):
    def setUp(self):
        self.chain_id = "biscuits-transition-tests"
        self.old_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.new_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.old_set = [
            {"public_key": key.public_key().public_bytes_raw().hex(), "voting_power": 1}
            for key in self.old_keys
        ]
        self.new_set = [
            {"public_key": key.public_key().public_bytes_raw().hex(), "voting_power": 1}
            for key in self.new_keys
        ]

    def certificate(self, keys=None, height=10, old=None, new=None):
        return make_transition_certificate(
            self.old_keys[:3] if keys is None else keys,
            self.chain_id, height,
            self.old_set if old is None else old,
            self.new_set if new is None else new,
        )

    def test_transition_requires_strictly_more_than_two_thirds_old_voting_power(self):
        certificate = self.certificate()
        self.assertTrue(verify_transition_certificate(certificate, self.old_set, self.chain_id))
        insufficient = self.certificate(keys=self.old_keys[:2])
        self.assertFalse(verify_transition_certificate(insufficient, self.old_set, self.chain_id))

    def test_transition_binds_chain_height_previous_set_and_next_set(self):
        certificate = self.certificate()
        for field, value in (
            ("chain_id", "another-chain"),
            ("activation_height", 11),
            ("previous_set_hash", "00" * 32),
            ("next_set_hash", "ff" * 32),
        ):
            changed = copy.deepcopy(certificate)
            changed[field] = value
            self.assertFalse(verify_transition_certificate(changed, self.old_set, self.chain_id))

    def test_transition_rejects_duplicate_signer_and_invalid_signature(self):
        certificate = self.certificate()
        duplicate = copy.deepcopy(certificate)
        duplicate["signatures"].append(copy.deepcopy(duplicate["signatures"][0]))
        self.assertFalse(verify_transition_certificate(duplicate, self.old_set, self.chain_id))
        corrupted = copy.deepcopy(certificate)
        corrupted["signatures"][0]["signature"] = "00" * 64
        self.assertFalse(verify_transition_certificate(corrupted, self.old_set, self.chain_id))

    def test_transition_rejects_unknown_signer_and_wrong_previous_set(self):
        certificate = self.certificate()
        other_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        other_set = [
            {"public_key": key.public_key().public_bytes_raw().hex(), "voting_power": 1}
            for key in other_keys
        ]
        self.assertFalse(verify_transition_certificate(certificate, other_set, self.chain_id))

    def test_history_requires_each_transition_to_be_signed_by_current_set(self):
        first = self.certificate(height=10)
        second = make_transition_certificate(
            self.new_keys[:3], self.chain_id, 20, self.new_set, self.old_set
        )
        self.assertTrue(verify_transition_history([first, second], self.old_set, self.chain_id))
        self.assertFalse(verify_transition_history([second, first], self.old_set, self.chain_id))
        forged_second = make_transition_certificate(
            self.old_keys[:3], self.chain_id, 20, self.new_set, self.old_set
        )
        self.assertFalse(verify_transition_history([first, forged_second], self.old_set, self.chain_id))

    def test_history_rejects_repeated_or_non_increasing_activation_heights(self):
        first = self.certificate(height=10)
        repeated = make_transition_certificate(
            self.new_keys[:3], self.chain_id, 10, self.new_set, self.old_set
        )
        self.assertFalse(verify_transition_history([first, repeated], self.old_set, self.chain_id))


    def test_validator_set_changes_exactly_at_its_activation_height(self):
        first = self.certificate(height=10)
        second = make_transition_certificate(
            self.new_keys[:3], self.chain_id, 20, self.new_set, self.old_set
        )
        old_sorted = sorted(self.old_set, key=lambda item: item["public_key"])
        new_sorted = sorted(self.new_set, key=lambda item: item["public_key"])
        self.assertEqual(validator_set_at_height([], self.old_set, self.chain_id, 9), old_sorted)
        self.assertEqual(validator_set_at_height([first], self.old_set, self.chain_id, 9), old_sorted)
        self.assertEqual(validator_set_at_height([first], self.old_set, self.chain_id, 10), new_sorted)
        self.assertEqual(validator_set_at_height([first, second], self.old_set, self.chain_id, 19), new_sorted)
        self.assertEqual(validator_set_at_height([first, second], self.old_set, self.chain_id, 20), old_sorted)

    def test_validator_set_resolution_fails_closed_on_invalid_history(self):
        first = self.certificate(height=10)
        bad = copy.deepcopy(first)
        bad["signatures"][0]["signature"] = "00" * 64
        with self.assertRaisesRegex(ValueError, "history is invalid"):
            validator_set_at_height([bad], self.old_set, self.chain_id, 10)

    def test_transition_rejects_small_next_set(self):
        small = self.new_set[:3]
        with self.assertRaises(ValueError):
            self.certificate(new=small)


if __name__ == "__main__":
    unittest.main()
