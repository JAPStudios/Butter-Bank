import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from milkchain.consensus import BFTChain, ConsensusError, canonical, public_key_hex, sign_vote


def keypair():
    private = Ed25519PrivateKey.generate()
    public = public_key_hex(private)
    return private, public


class MilkchainBFTTests(unittest.TestCase):
    def setUp(self):
        self.keys = [keypair() for _ in range(4)]
        self.validators = [
            {"public_key": public, "power": 1}
            for _, public in self.keys
        ]
        self.sender_key, self.sender = keypair()
        _, self.recipient = keypair()
        self.chain = BFTChain(
            "milkchain-test",
            self.validators,
            {self.sender: 1000},
        )

    def certificates(self, proposal, indexes=(0, 1, 2)):
        prevotes = [
            sign_vote(self.keys[i][0], self.chain.chain_id, proposal["height"],
                      proposal["round"], "prevote", proposal["hash"])
            for i in indexes
        ]
        precommits = [
            sign_vote(self.keys[i][0], self.chain.chain_id, proposal["height"],
                      proposal["round"], "precommit", proposal["hash"])
            for i in indexes
        ]
        return prevotes, precommits

    def transaction(self, amount=125, nonce=1):
        payload = {
            "chain_id": self.chain.chain_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": amount,
            "nonce": nonce,
        }
        return {
            **payload,
            "signature": self.sender_key.sign(canonical(payload)).hex(),
        }

    def test_three_of_four_validators_commit_block_and_transfer(self):
        tx = self.transaction()
        proposal = self.chain.make_proposal([tx], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        block = self.chain.commit(proposal, prevotes, precommits)
        self.assertEqual(block["height"], 1)
        balances, nonces = self.chain.state()
        self.assertEqual(balances[self.sender], 875)
        self.assertEqual(balances[self.recipient], 125)
        self.assertEqual(nonces[self.sender], 1)

    def test_two_of_four_cannot_commit(self):
        proposal = self.chain.make_proposal([], timestamp=1)
        prevotes, precommits = self.certificates(proposal, (0, 1))
        with self.assertRaisesRegex(ConsensusError, "insufficient prevote"):
            self.chain.commit(proposal, prevotes, precommits)

    def test_votes_cannot_be_replayed_for_another_block(self):
        proposal = self.chain.make_proposal([], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        other = self.chain.make_proposal([], timestamp=1, round_number=1)
        with self.assertRaises(ConsensusError):
            self.chain.commit(other, prevotes, precommits)

    def test_duplicate_validator_vote_is_rejected(self):
        proposal = self.chain.make_proposal([], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        prevotes.append(prevotes[0])
        with self.assertRaisesRegex(ConsensusError, "duplicate"):
            self.chain.commit(proposal, prevotes, precommits)

    def test_invalid_transaction_signature_is_rejected(self):
        tx = self.transaction()
        tx["amount"] = 126
        proposal = self.chain.make_proposal([tx], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        with self.assertRaisesRegex(ConsensusError, "invalid transaction"):
            self.chain.commit(proposal, prevotes, precommits)

    def test_chain_validation_and_restart(self):
        proposal = self.chain.make_proposal([self.transaction()], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        self.chain.commit(proposal, prevotes, precommits)
        self.assertTrue(self.chain.validate_chain(self.chain.blocks))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "milkchain.json"
            persisted = BFTChain("milkchain-test", self.validators,
                                 {self.sender: 1000}, path)
            persisted.commit(proposal, prevotes, precommits)
            restored = BFTChain("milkchain-test", self.validators,
                                {self.sender: 1000}, path)
            self.assertEqual(restored.blocks, persisted.blocks)
            self.assertEqual(restored.height, 1)

    def test_altered_commit_certificate_invalidates_chain(self):
        proposal = self.chain.make_proposal([], timestamp=1)
        prevotes, precommits = self.certificates(proposal)
        self.chain.commit(proposal, prevotes, precommits)
        corrupted = [dict(block) for block in self.chain.blocks]
        corrupted[1] = dict(corrupted[1])
        corrupted[1]["precommits"] = corrupted[1]["precommits"][:2]
        self.assertFalse(self.chain.validate_chain(corrupted))


if __name__ == "__main__":
    unittest.main()
