import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from consensus import (
    make_proposal,
    make_vote,
    select_proposer,
    validator_set_hash,
    verify_commit_certificate,
    verify_proposal,
    verify_vote,
)


def validator(power=1):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw().hex()
    return key, {"public_key": public, "voting_power": power}


class BFTPrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.keys_and_records = [validator(power) for power in (2, 1, 1, 1)]
        self.validators = [record for _, record in self.keys_and_records]
        self.chain_id = "biscuits-testnet"
        self.block_hash = "ab" * 32
        self.set_hash = validator_set_hash(self.validators)

    def test_validator_set_rejects_duplicate_keys_and_zero_power(self):
        duplicate = [self.validators[0], self.validators[0]]
        with self.assertRaises(ValueError):
            validator_set_hash(duplicate)
        invalid = [{"public_key": self.validators[0]["public_key"], "voting_power": 0}]
        with self.assertRaises(ValueError):
            validator_set_hash(invalid)

    def test_proposal_signature_and_validator_membership(self):
        proposal = make_proposal(
            self.keys_and_records[0][0], self.chain_id, 1, 0,
            self.block_hash, self.set_hash,
        )
        self.assertTrue(verify_proposal(proposal, self.validators, self.chain_id))
        tampered = dict(proposal, block_hash="cd" * 32)
        self.assertFalse(verify_proposal(tampered, self.validators, self.chain_id))
        self.assertFalse(verify_proposal(proposal, self.validators, "other-chain"))

    def test_votes_are_domain_separated_and_signed(self):
        vote = make_vote(
            self.keys_and_records[0][0], self.chain_id, 1, 0,
            "precommit", self.block_hash, self.set_hash,
        )
        self.assertTrue(verify_vote(vote, self.validators, self.chain_id))
        self.assertFalse(verify_vote(dict(vote, step="prevote"), self.validators, self.chain_id))

    def test_commit_requires_strictly_more_than_two_thirds_power(self):
        votes = [
            make_vote(key, self.chain_id, 1, 0, "precommit", self.block_hash, self.set_hash)
            for key, _ in self.keys_and_records[:3]
        ]
        # 4/5 voting power is greater than two thirds.
        self.assertTrue(verify_commit_certificate(
            votes, self.validators, self.chain_id, 1, 0, self.block_hash
        ))
        # 2/5 voting power is insufficient.
        self.assertFalse(verify_commit_certificate(
            votes[:1], self.validators, self.chain_id, 1, 0, self.block_hash
        ))

    def test_commit_rejects_duplicate_validator_votes(self):
        vote = make_vote(
            self.keys_and_records[0][0], self.chain_id, 1, 0,
            "precommit", self.block_hash, self.set_hash,
        )
        self.assertFalse(verify_commit_certificate(
            [vote, vote], self.validators, self.chain_id, 1, 0, self.block_hash
        ))

    def test_proposer_selection_is_deterministic_and_validated(self):
        first = select_proposer(self.validators, 12, 3)
        self.assertEqual(first, select_proposer(self.validators, 12, 3))
        self.assertIn(first, {v["public_key"] for v in self.validators})
        with self.assertRaises(ValueError):
            select_proposer(self.validators, 0, 0)


if __name__ == "__main__":
    unittest.main()
