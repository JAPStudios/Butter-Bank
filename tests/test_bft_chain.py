import tempfile
import unittest
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admission import issuer_set_hash, sign_admission
from bft_chain import BFTChain
from consensus import make_proposal, select_proposer
from consensus_network import ConsensusHTTPServer
from engine import ConsensusEngine
from signer import ConsensusSigner
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

    def test_four_node_network_reaches_bft_finality(self):
        with tempfile.TemporaryDirectory() as directory:
            chains = []
            servers = []
            threads = []
            for index, key in enumerate(self.validator_keys):
                chain = BFTChain(self.cfg, Path(directory) / f"chain-{index}.json")
                signer = ConsensusSigner(
                    key, self.chain_id, chain.validators,
                    Path(directory) / f"signer-{index}.json"
                )
                engine = ConsensusEngine(signer, chain.validate_proposal_block)

                def persist(result, target=chain):
                    ok, message = target.accept_finalized_block(
                        result["block"], result["round"], result["commit_votes"]
                    )
                    if not ok:
                        raise RuntimeError(message)

                server = ConsensusHTTPServer(
                    engine, host="127.0.0.1", port=0, on_finalized=persist
                )
                chains.append(chain)
                servers.append(server)
            urls = [
                "http://127.0.0.1:" + str(server.server.server_address[1])
                for server in servers
            ]
            for index, server in enumerate(servers):
                server.peers = [url for peer_index, url in enumerate(urls)
                                if peer_index != index]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            try:
                selected = select_proposer(chains[0].validators, 1, 0)
                proposer_index = next(
                    i for i, key in enumerate(self.validator_keys)
                    if key.public_key().public_bytes_raw().hex() == selected
                )
                proposer_key = self.validator_keys[proposer_index]
                block = chains[proposer_index].build_proposal(selected)
                proposal = make_proposal(
                    proposer_key, self.chain_id, 1, 0, block["hash"],
                    validator_set_hash(chains[0].validators)
                )
                servers[proposer_index].publish_proposal(proposal, block)
                deadline = time.time() + 10
                while time.time() < deadline and any(len(chain.blocks) != 2 for chain in chains):
                    time.sleep(0.05)
                self.assertTrue(all(len(chain.blocks) == 2 for chain in chains),
                                "all four validators should finalize the same block")
                self.assertEqual(len({chain.blocks[-1]["hash"] for chain in chains}), 1)
            finally:
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
