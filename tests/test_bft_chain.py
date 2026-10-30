import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admission import issuer_set_hash, sign_admission
from bft_chain import BFTChain
from consensus import make_vote, validator_set_hash


class BFTChainTests(unittest.TestCase):
    def setUp(self):
        self.issuers = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.issuer_public = [key.public_key().public_bytes_raw().hex()
                              for key in self.issuers]
        self.validator_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.chain_id = "biscuits-bft-chain-test"
        self.issuer_hash = issuer_set_hash(self.issuer_public)
        self.certificates = []
        for key in self.validator_keys:
            validator_public = key.public_key().public_bytes_raw().hex()
            signatures = [
                sign_admission(issuer, self.chain_id, validator_public, 1, 100,
                               self.issuer_hash)
                for issuer in self.issuers[:3]
            ]
            self.certificates.append({
                "chain_id": self.chain_id,
                "validator_public_key": validator_public,
                "issued_epoch": 1,
                "expires_epoch": 100,
                "issuer_set_hash": self.issuer_hash,
                "signatures": signatures,
            })
        self.cfg = {
            "chain_id": self.chain_id,
            "consensus": "bft",
            "difficulty": 1,
            "block_reward": 25,
            "genesis_allocations": {},
            "admission_issuers": self.issuer_public,
            "admission_certificates": self.certificates,
            "admission_epoch": 10,
            "peers": [],
        }

    def test_bft_chain_finalizes_and_persists_without_mining(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain = BFTChain(self.cfg, path)
            proposer = chain.validators[0]["public_key"]
            block = chain.build_proposal(proposer)
            self.assertEqual(chain.validate_proposal_block(block), block["hash"])
            self.assertIsNone(chain.mine(proposer)[0])
            set_hash = validator_set_hash(chain.validators)
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id,
                          1, 0, "precommit", block["hash"], set_hash)
                for item in chain.validators[:3]
            ]
            ok, message = chain.accept_finalized_block(block, 0, votes)
            self.assertTrue(ok, message)
            self.assertEqual(len(chain.blocks), 2)
            reopened = BFTChain(self.cfg, path)
            self.assertEqual(reopened.blocks, chain.blocks)
            self.assertTrue(reopened.valid_chain(reopened.blocks))

    def test_bft_chain_rejects_insufficient_commit_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            block = chain.build_proposal(chain.validators[0]["public_key"])
            key = self.validator_keys[0]
            set_hash = validator_set_hash(chain.validators)
            vote = make_vote(key, self.chain_id, 1, 0, "precommit",
                             block["hash"], set_hash)
            ok, _ = chain.accept_finalized_block(block, 0, [vote])
            self.assertFalse(ok)
            self.assertEqual(len(chain.blocks), 1)

    def test_bft_chain_refuses_conflicting_finalized_history(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            self.assertFalse(chain.replace([chain.genesis_block(), {}])[0])


if __name__ == "__main__":
    unittest.main()
