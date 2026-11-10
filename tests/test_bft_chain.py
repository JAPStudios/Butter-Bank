import os
import tempfile
import unittest
import threading
import json
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admission import issuer_set_hash, sign_admission
from bft_chain import BFTChain
from node import bhash, signing_bytes, synchronize_peer
from consensus import make_proposal, make_round_change, select_proposer
from consensus_network import ConsensusHTTPServer
from engine import ConsensusEngine
from signer import ConsensusSigner
from bft_node import (
    BFTAPI, load_validator_key, build_validator_activation,
    validator_state_path,
)
from keygen import generate_keypair
from consensus import make_vote, validator_set_hash
from validator_transitions import make_transition_certificate


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
            "block_reward": 0,
            "genesis_allocations": {},
            "admission_issuers": self.issuer_public,
            "admission_certificates": self.certificates,
            "admission_epoch": 10,
            "peers": [],
        }

    def test_bft_chain_rejects_a_malformed_genesis_parent_without_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "malformed-parent.json")
            proposer = select_proposer(chain.validators, 1, 0)
            block = chain.build_proposal(proposer)
            votes = [
                make_vote(key, self.chain_id, 1, 0, "precommit", block["hash"],
                          validator_set_hash(chain.validators))
                for key in self.validator_keys[:3]
            ]
            block["commit_round"] = 0
            block["commit_certificate"] = votes
            self.assertFalse(chain.valid_chain(["malformed-genesis", block]))

    def test_bft_chain_disables_issuance_until_supply_rules_are_defined(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = dict(self.cfg, block_reward=1)
            with self.assertRaisesRegex(ValueError, "supply and issuance rules"):
                BFTChain(cfg, Path(directory) / "chain.json")

    def test_bft_chain_rejects_user_transaction_fees(self):
        with tempfile.TemporaryDirectory() as directory:
            sender_key = Ed25519PrivateKey.generate()
            recipient_key = Ed25519PrivateKey.generate()
            sender = sender_key.public_key().public_bytes_raw().hex()
            recipient = recipient_key.public_key().public_bytes_raw().hex()
            cfg = dict(self.cfg, genesis_allocations={sender: 1000})
            chain = BFTChain(cfg, Path(directory) / "fee-policy-chain.json")
            transaction = {
                "chain_id": self.chain_id,
                "sender": sender,
                "recipient": recipient,
                "amount": 10,
                "fee": 1,
                "nonce": 1,
            }
            transaction["signature"] = sender_key.sign(signing_bytes(transaction)).hex()
            accepted, message = chain.add_tx(transaction)
            self.assertFalse(accepted)
            self.assertIn("fees are disabled", message)
            self.assertEqual(chain.pool, [])

            transaction["fee"] = 0
            transaction["signature"] = sender_key.sign(signing_bytes(transaction)).hex()
            accepted, message = chain.add_tx(transaction)
            self.assertTrue(accepted, message)
            self.assertEqual(chain.pool, [transaction])

            # Historical blocks containing a user-paid fee must also fail
            # validation, even when their coinbase claims the fee.
            invalid_block = {
                "height": 1,
                "previous_hash": chain.blocks[0]["hash"],
                "timestamp": chain.blocks[0]["timestamp"],
                "transactions": [
                    {"type": "coinbase", "recipient": chain.validators[0]["public_key"], "amount": 1},
                    dict(transaction, fee=1),
                ],
                "nonce": 0,
            }
            invalid_block["transactions"][1]["signature"] = sender_key.sign(
                signing_bytes(invalid_block["transactions"][1])
            ).hex()
            invalid_block["hash"] = bhash(invalid_block)
            self.assertFalse(
                chain.valid_chain(chain.blocks + [invalid_block], require_certificates=False)
            )

    def test_bft_chain_finalizes_and_persists_without_mining(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain = BFTChain(self.cfg, path)
            proposer = select_proposer(chain.validators, len(chain.blocks), 0)
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
            self.assertTrue(chain.accept_finalized_block(block, 0, votes)[0])
            self.assertEqual(len(chain.blocks), 2)
            reopened = BFTChain(self.cfg, path)
            self.assertEqual(reopened.blocks, chain.blocks)
            self.assertTrue(reopened.valid_chain(reopened.blocks))

    def test_committed_transition_changes_validator_set_at_activation_height(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transition-chain.json"
            chain = BFTChain(self.cfg, path)
            next_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            next_set = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in next_keys
            ]
            certificate = make_transition_certificate(
                self.validator_keys[:3], self.chain_id, 2,
                chain.initial_validators, next_set,
            )

            old_proposer = select_proposer(chain.validators, 1, 0)
            first = chain.build_proposal(
                old_proposer, validator_transition=certificate
            )
            old_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            old_votes = [
                make_vote(old_by_public[item["public_key"]], self.chain_id,
                          1, 0, "precommit", first["hash"],
                          validator_set_hash(chain.initial_validators))
                for item in chain.initial_validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(first, 0, old_votes)
            self.assertTrue(accepted, message)
            self.assertEqual(
                chain.validators,
                sorted(next_set, key=lambda item: item["public_key"]),
            )

            next_proposer = select_proposer(chain.validators, 2, 0)
            second = chain.build_proposal(next_proposer)
            next_by_public = {
                key.public_key().public_bytes_raw().hex(): key for key in next_keys
            }
            next_votes = [
                make_vote(next_by_public[item["public_key"]], self.chain_id,
                          2, 0, "precommit", second["hash"],
                          validator_set_hash(next_set))
                for item in chain.validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(second, 0, next_votes)
            self.assertTrue(accepted, message)

            reopened = BFTChain(self.cfg, path)
            self.assertEqual(reopened.validators, chain.validators)
            self.assertTrue(reopened.valid_chain(reopened.blocks))

            tampered = json.loads(json.dumps(reopened.blocks))
            tampered[1]["validator_transition"]["activation_height"] = 3
            self.assertFalse(reopened.valid_chain(tampered))

    def test_transition_certificate_cannot_be_added_after_its_activation_height(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "late-transition.json")
            old_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            first_proposer = select_proposer(chain.validators, 1, 0)
            first = chain.build_proposal(first_proposer)
            first_votes = [
                make_vote(old_by_public[item["public_key"]], self.chain_id,
                          1, 0, "precommit", first["hash"],
                          validator_set_hash(chain.initial_validators))
                for item in chain.initial_validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(first, 0, first_votes)
            self.assertTrue(accepted, message)

            next_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            next_set = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in next_keys
            ]
            certificate = make_transition_certificate(
                self.validator_keys[:3], self.chain_id, 2,
                chain.initial_validators, next_set,
            )
            proposer = select_proposer(chain.validators, 2, 0)
            block = chain.build_proposal(proposer, validator_transition=certificate)
            self.assertIsNone(chain.validate_proposal_block(block))

    def test_node_recovers_only_the_active_validator_signing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "activation-chain.json")
            next_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            next_set = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in next_keys
            ]
            certificate = make_transition_certificate(
                self.validator_keys[:3], self.chain_id, 2,
                chain.initial_validators, next_set,
            )
            proposer = select_proposer(chain.validators, 1, 0)
            block = chain.build_proposal(proposer, validator_transition=certificate)
            votes = [
                make_vote(key, self.chain_id, 1, 0, "precommit", block["hash"],
                          validator_set_hash(chain.initial_validators))
                for key in self.validator_keys[:3]
            ]
            accepted, message = chain.accept_finalized_block(block, 0, votes)
            self.assertTrue(accepted, message)

            base = Path(directory) / "validator-state.json"
            active = build_validator_activation(next_keys[0], chain, base)
            self.assertIsNotNone(active["signer"])
            self.assertEqual(active["signer"].height, len(chain.blocks))
            self.assertEqual(
                active["signer"].validators_hash, chain.validators_hash
            )
            self.assertNotEqual(validator_state_path(base, chain), base)
            active["signer"].close()

            removed = build_validator_activation(self.validator_keys[0], chain, base)
            self.assertIsNone(removed["signer"])

    def test_peer_sync_accepts_a_longer_chain_with_a_verified_new_validator_set(self):
        with tempfile.TemporaryDirectory() as directory:
            source = BFTChain(self.cfg, Path(directory) / "source.json")
            target = BFTChain(self.cfg, Path(directory) / "target.json")
            next_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            next_set = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in next_keys
            ]
            certificate = make_transition_certificate(
                self.validator_keys[:3], self.chain_id, 2,
                source.initial_validators, next_set,
            )
            proposer = select_proposer(source.validators, 1, 0)
            block = source.build_proposal(proposer, validator_transition=certificate)
            votes = [
                make_vote(key, self.chain_id, 1, 0, "precommit", block["hash"],
                          validator_set_hash(source.initial_validators))
                for key in self.validator_keys[:3]
            ]
            accepted, message = source.accept_finalized_block(block, 0, votes)
            self.assertTrue(accepted, message)

            status = {
                "chain_id": source.id,
                "genesis_hash": source.blocks[0]["hash"],
                "difficulty": source.diff,
                "block_reward": source.reward,
                "consensus": "bft",
                "validator_set_hash": source.validators_hash,
                "height": len(source.blocks) - 1,
            }

            def fake_get(url):
                if url.endswith("/status"):
                    return status
                if "/chain?" in url:
                    return {"start": 0, "chain": source.blocks}
                raise AssertionError(url)

            with patch("node.get", side_effect=fake_get):
                self.assertTrue(synchronize_peer(target, "http://127.0.0.1:8333"))
            self.assertEqual(target.blocks, source.blocks)
            self.assertEqual(target.validators, source.validators)

    def test_bft_chain_rejects_reward_redirection_away_from_selected_proposer(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            proposer = select_proposer(chain.validators, 1, 0)
            proposer_key = next(
                key for key in self.validator_keys
                if key.public_key().public_bytes_raw().hex() == proposer
            )
            block = chain.build_proposal(proposer)
            other = next(item["public_key"] for item in chain.validators
                         if item["public_key"] != proposer)
            block["transactions"][0]["recipient"] = other
            block["hash"] = bhash(block)
            signer = ConsensusSigner(
                proposer_key, self.chain_id, chain.validators,
                Path(directory) / "signer.json"
            )
            engine = ConsensusEngine(signer, chain.validate_proposal_block)
            proposal = make_proposal(
                proposer_key, self.chain_id, 1, 0, block["hash"],
                chain.validators_hash
            )
            self.assertFalse(engine.receive_proposal(proposal, block))
            signer.close()

    def test_bft_chain_rejects_insufficient_commit_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            block = chain.build_proposal(select_proposer(chain.validators, len(chain.blocks), 0))
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

    def test_bft_chain_rejects_inherited_uncoordinated_block_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            block = chain.build_proposal(select_proposer(chain.validators, len(chain.blocks), 0))
            ok, message = chain.accept_block(block)
            self.assertFalse(ok)
            self.assertIn("consensus finality", message)
            self.assertEqual(len(chain.blocks), 1)

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
                        result["block"], result["round"], result["commit_votes"],
                        result.get("valid_round"), result.get("valid_round_certificate"),
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

    def test_four_locked_validators_recover_through_valid_round_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            chains, signers, servers, threads = [], [], [], []
            validators = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in self.validator_keys
            ]
            set_hash = validator_set_hash(validators)
            old_hash = "ab" * 32
            old_certificate = [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          old_hash, set_hash)
                for key in self.validator_keys[:3]
            ]
            round_changes = []
            for index, key in enumerate(self.validator_keys):
                chain = BFTChain(self.cfg, Path(directory) / f"recovery-chain-{index}.json")
                signer = ConsensusSigner(
                    key, self.chain_id, chain.validators,
                    Path(directory) / f"recovery-signer-{index}.json"
                )
                signer.lock_from_prevotes(old_certificate, 0, old_hash)
                round_changes.append(signer.sign_round_change(2))
                chains.append(chain)
                signers.append(signer)
            round_change_certificate = round_changes[:3]
            for signer in signers:
                self.assertEqual(signer.advance_round(round_change_certificate), 2)

            for index, chain in enumerate(chains):
                engine = ConsensusEngine(signers[index], chain.validate_proposal_block)

                def persist(result, target=chain):
                    ok, message = target.accept_finalized_block(
                        result["block"], result["round"], result["commit_votes"],
                        result.get("valid_round"), result.get("valid_round_certificate"),
                    )
                    if not ok:
                        raise RuntimeError(message)

                servers.append(ConsensusHTTPServer(
                    engine, host="127.0.0.1", port=0, on_finalized=persist
                ))
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
                selected = select_proposer(chains[0].validators, 1, 2)
                proposer_index = next(
                    index for index, key in enumerate(self.validator_keys)
                    if key.public_key().public_bytes_raw().hex() == selected
                )
                block = chains[proposer_index].build_proposal(selected, round_number=2)
                valid_round_certificate = [
                    make_vote(key, self.chain_id, 1, 1, "prevote",
                              block["hash"], set_hash)
                    for key in self.validator_keys[:3]
                ]
                proposal = make_proposal(
                    self.validator_keys[proposer_index], self.chain_id, 1, 2,
                    block["hash"], set_hash, 1, valid_round_certificate,
                )
                servers[proposer_index].publish_proposal(proposal, block)
                deadline = time.time() + 10
                while time.time() < deadline and any(len(chain.blocks) != 2 for chain in chains):
                    time.sleep(0.05)
                self.assertTrue(
                    all(len(chain.blocks) == 2 for chain in chains),
                    "all four locked validators should recover and finalize the same block",
                )
                self.assertEqual(len({chain.blocks[-1]["hash"] for chain in chains}), 1)
                self.assertTrue(all(signer.height == 2 for signer in signers))
                self.assertTrue(all(signer.locked_block_hash is None for signer in signers))
                self.assertEqual(chains[0].blocks[-1]["valid_round"], 1)
                tampered_chain = list(chains[0].blocks)
                tampered_tip = dict(tampered_chain[-1])
                tampered_tip["valid_round_certificate"] = [
                    dict(vote) for vote in tampered_tip["valid_round_certificate"]
                ]
                tampered_tip["valid_round_certificate"][0]["signature"] = "00" * 64
                tampered_chain[-1] = tampered_tip
                self.assertFalse(chains[0].valid_chain(tampered_chain))
                offline = ConsensusSigner(
                    self.validator_keys[0], self.chain_id, chains[0].validators,
                    Path(directory) / "offline-recovery-signer.json",
                )
                offline.lock_from_prevotes(old_certificate, 0, old_hash)
                offline.catch_up(chains[0].blocks[1:])
                self.assertEqual(offline.height, 2)
                self.assertIsNone(offline.locked_block_hash)
                offline.close()
            finally:
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)
                for signer in signers:
                    signer.close()

    def test_offline_signer_catches_up_from_verified_commit_certificates(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            signer = ConsensusSigner(
                self.validator_keys[0], self.chain_id, chain.validators,
                Path(directory) / "offline-signer.json", initial_height=1
            )
            block = chain.build_proposal(select_proposer(chain.validators, len(chain.blocks), 0))
            set_hash = validator_set_hash(chain.validators)
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id, 1, 0,
                          "precommit", block["hash"], set_hash)
                for item in chain.validators[:3]
            ]
            self.assertTrue(chain.accept_finalized_block(block, 0, votes)[0])
            signer.catch_up(chain.blocks[1:])
            self.assertEqual(signer.height, 2)

    def test_signer_catch_up_rolls_back_memory_after_persistence_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            signer_path = Path(directory) / "offline-signer.json"
            signer = ConsensusSigner(
                self.validator_keys[0], self.chain_id, chain.validators,
                signer_path, initial_height=1
            )
            block = chain.build_proposal(select_proposer(chain.validators, 1, 0))
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id, 1, 0,
                          "precommit", block["hash"], chain.validators_hash)
                for item in chain.validators[:3]
            ]
            self.assertTrue(chain.accept_finalized_block(block, 0, votes)[0])
            original_save = signer._save
            signer._save = lambda: (_ for _ in ()).throw(
                OSError("simulated signer-state disk failure")
            )
            with self.assertRaisesRegex(OSError, "simulated signer-state"):
                signer.catch_up(chain.blocks[1:])
            self.assertEqual(signer.height, 1)
            self.assertEqual(json.loads(signer_path.read_text())["height"], 1)
            signer._save = original_save
            signer.catch_up(chain.blocks[1:])
            self.assertEqual(signer.height, 2)
            signer.close()

    def test_offline_signer_refuses_catch_up_over_conflicting_local_vote(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            signer = ConsensusSigner(
                self.validator_keys[0], self.chain_id, chain.validators,
                Path(directory) / "offline-signer.json", initial_height=1
            )
            set_hash = validator_set_hash(chain.validators)
            conflicting_hash = "ff" * 32
            conflicting_prevotes = [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          conflicting_hash, set_hash)
                for key in self.validator_keys[:3]
            ]
            signer.lock_from_prevotes(conflicting_prevotes, 0, conflicting_hash)
            signer.sign_vote(0, "precommit", conflicting_hash)
            block = chain.build_proposal(select_proposer(chain.validators, len(chain.blocks), 0))
            set_hash = validator_set_hash(chain.validators)
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id, 1, 0,
                          "precommit", block["hash"], set_hash)
                for item in chain.validators[:3]
            ]
            self.assertTrue(chain.accept_finalized_block(block, 0, votes)[0])
            with self.assertRaises(ValueError):
                signer.catch_up(chain.blocks[1:])

    def test_bft_node_loads_owner_only_validator_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validator.key"
            expected_public = generate_keypair(path)
            loaded = load_validator_key(path)
            self.assertEqual(loaded.public_key().public_bytes_raw().hex(), expected_public)

    def test_failed_bft_persistence_rolls_back_in_memory_state(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            block = chain.build_proposal(select_proposer(chain.validators, len(chain.blocks), 0))
            set_hash = validator_set_hash(chain.validators)
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id, 1, 0,
                          "precommit", block["hash"], set_hash)
                for item in chain.validators[:3]
            ]
            original_save = chain.save
            chain.save = lambda: (_ for _ in ()).throw(OSError("simulated disk failure"))
            with self.assertRaises(OSError):
                chain.accept_finalized_block(block, 0, votes)
            self.assertEqual(len(chain.blocks), 1)
            chain.save = original_save

    def test_bft_finality_rejects_longer_conflicting_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            left = BFTChain(self.cfg, Path(directory) / "left.json")
            right = BFTChain(self.cfg, Path(directory) / "right.json")
            set_hash = validator_set_hash(left.validators)
            keys_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }

            def commit_next(chain, proposer):
                block = chain.build_proposal(proposer)
                votes = [
                    make_vote(keys_by_public[item["public_key"]], self.chain_id,
                              block["height"], 0, "precommit", block["hash"], set_hash)
                    for item in chain.validators[:3]
                ]
                self.assertTrue(chain.accept_finalized_block(block, 0, votes)[0])
                return block

            selected = select_proposer(left.validators, len(left.blocks), 0)
            left_first = commit_next(left, selected)
            right_block = right.build_proposal(selected)
            right_block["timestamp"] += 1
            right_block["hash"] = bhash(right_block)
            right_votes = [
                make_vote(keys_by_public[item["public_key"]], self.chain_id,
                          right_block["height"], 0, "precommit", right_block["hash"], set_hash)
                for item in right.validators[:3]
            ]
            self.assertTrue(right.accept_finalized_block(right_block, 0, right_votes)[0])
            right_first = right_block
            self.assertNotEqual(left_first["hash"], right_first["hash"])
            commit_next(right, select_proposer(right.validators, len(right.blocks), 0))
            self.assertEqual(len(right.blocks), 3)
            ok, message = left.replace(right.blocks)
            self.assertFalse(ok)
            self.assertIn("conflicts with locally finalized history", message)

    def test_bft_chain_rejects_remote_plain_http_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = dict(self.cfg, peers=["http://example.com:8333"])
            with self.assertRaises(ValueError):
                BFTChain(cfg, Path(directory) / "chain.json")

    def test_bft_node_propose_api_only_allows_selected_proposer(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            selected = select_proposer(chain.validators, 1, 0)
            selected_key = next(
                key for key in self.validator_keys
                if key.public_key().public_bytes_raw().hex() == selected
            )
            signer = ConsensusSigner(
                selected_key, self.chain_id, chain.validators,
                Path(directory) / "signer.json"
            )
            engine = ConsensusEngine(signer, chain.validate_proposal_block)
            consensus_server = ConsensusHTTPServer(engine, host="127.0.0.1", port=0)
            BFTAPI.chain = chain
            BFTAPI.peers = chain.peers
            BFTAPI.consensus_server = consensus_server
            BFTAPI.consensus_key = selected_key
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), BFTAPI)
            thread = threading.Thread(target=api_server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:" + str(api_server.server_address[1]) + "/propose"
                request = urllib.request.Request(
                    url, data=json.dumps({}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST"
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    result = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                self.assertTrue(result["ok"])
                self.assertEqual(result["proposal"]["proposer"], selected)
                self.assertIn("1:0:prevote", signer.state["signed"])
            finally:
                api_server.shutdown()
                api_server.server_close()
                thread.join(timeout=2)
                consensus_server.server.server_close()
                signer.close()
                BFTAPI.consensus_server = None
                BFTAPI.consensus_key = None
                BFTAPI.chain = None
                BFTAPI.peers = []

    def test_bft_propose_api_relays_valid_round_recovery_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            selected = select_proposer(chain.validators, 1, 2)
            selected_key = next(
                key for key in self.validator_keys
                if key.public_key().public_bytes_raw().hex() == selected
            )
            signer = ConsensusSigner(
                selected_key, self.chain_id, chain.validators,
                Path(directory) / "signer.json"
            )
            old_hash = "ab" * 32
            old_certificate = [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          old_hash, chain.validators_hash)
                for key in self.validator_keys[:3]
            ]
            signer.lock_from_prevotes(old_certificate, 0, old_hash)
            local_round_change = signer.sign_round_change(2)
            other_keys = [
                key for key in self.validator_keys
                if key.public_key().public_bytes_raw().hex() != selected
            ][:2]
            round_change_certificate = [
                local_round_change,
                *[
                    make_round_change(
                        key, self.chain_id, 1, 2, chain.validators_hash
                    )
                    for key in other_keys
                ],
            ]
            signer.advance_round(round_change_certificate)
            engine = ConsensusEngine(signer, chain.validate_proposal_block)
            consensus_server = ConsensusHTTPServer(engine, host="127.0.0.1", port=0)
            BFTAPI.chain = chain
            BFTAPI.peers = chain.peers
            BFTAPI.consensus_server = consensus_server
            BFTAPI.consensus_key = selected_key
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), BFTAPI)
            thread = threading.Thread(target=api_server.serve_forever, daemon=True)
            thread.start()
            try:
                block = chain.build_proposal(selected, round_number=2)
                valid_round_certificate = [
                    make_vote(key, self.chain_id, 1, 1, "prevote",
                              block["hash"], chain.validators_hash)
                    for key in self.validator_keys[:3]
                ]
                url = "http://127.0.0.1:" + str(api_server.server_address[1]) + "/propose"
                request = urllib.request.Request(
                    url,
                    data=json.dumps({
                        "block": block,
                        "valid_round": 1,
                        "valid_round_certificate": valid_round_certificate,
                    }).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    result = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                self.assertTrue(result["ok"])
                self.assertEqual(result["proposal"]["valid_round"], 1)
                self.assertEqual(result["proposal"]["valid_round_certificate"],
                                 valid_round_certificate)
                self.assertEqual(signer.state["signed"]["1:2:prevote"]["block_hash"],
                                 block["hash"])
            finally:
                api_server.shutdown()
                api_server.server_close()
                thread.join(timeout=2)
                consensus_server.server.server_close()
                signer.close()
                BFTAPI.consensus_server = None
                BFTAPI.consensus_key = None
                BFTAPI.chain = None
                BFTAPI.peers = []

    def test_three_of_four_online_validators_reach_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            proposer = select_proposer(
                [{"public_key": key.public_key().public_bytes_raw().hex(),
                  "voting_power": 1} for key in self.validator_keys],
                1, 0
            )
            proposer_index = next(
                i for i, key in enumerate(self.validator_keys)
                if key.public_key().public_bytes_raw().hex() == proposer
            )
            active_indices = [i for i in range(4) if i != (proposer_index + 1) % 4]
            chains, servers, threads = [], [], []
            for index in active_indices:
                chain = BFTChain(self.cfg, Path(directory) / f"online-chain-{index}.json")
                signer = ConsensusSigner(
                    self.validator_keys[index], self.chain_id, chain.validators,
                    Path(directory) / f"online-signer-{index}.json"
                )
                engine = ConsensusEngine(signer, chain.validate_proposal_block)

                def persist(result, target=chain):
                    ok, message = target.accept_finalized_block(
                        result["block"], result["round"], result["commit_votes"],
                        result.get("valid_round"), result.get("valid_round_certificate"),
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
                active_proposer_position = active_indices.index(proposer_index)
                block = chains[active_proposer_position].build_proposal(proposer)
                proposal = make_proposal(
                    self.validator_keys[proposer_index], self.chain_id, 1, 0,
                    block["hash"], validator_set_hash(chains[0].validators)
                )
                servers[active_proposer_position].publish_proposal(proposal, block)
                deadline = time.time() + 10
                while time.time() < deadline and any(len(chain.blocks) != 2 for chain in chains):
                    time.sleep(0.05)
                self.assertTrue(
                    all(len(chain.blocks) == 2 for chain in chains),
                    "three honest validators must form a >2/3 quorum with one offline validator"
                )
                self.assertEqual(len({chain.blocks[-1]["hash"] for chain in chains}), 1)
            finally:
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)

    @unittest.skipIf(os.name == "nt", "POSIX file-mode and symlink semantics")
    def test_bft_node_rejects_symlinked_validator_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real.key"
            link = Path(directory) / "linked.key"
            generate_keypair(real)
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                load_validator_key(link)

    def test_two_of_four_partition_cannot_finalize(self):
        with tempfile.TemporaryDirectory() as directory:
            proposer = select_proposer(
                [{"public_key": key.public_key().public_bytes_raw().hex(),
                  "voting_power": 1} for key in self.validator_keys],
                1, 0
            )
            proposer_index = next(
                i for i, key in enumerate(self.validator_keys)
                if key.public_key().public_bytes_raw().hex() == proposer
            )
            active_indices = [proposer_index, (proposer_index + 1) % 4]
            chains, servers, threads = [], [], []
            for index in active_indices:
                chain = BFTChain(self.cfg, Path(directory) / f"partition-chain-{index}.json")
                signer = ConsensusSigner(
                    self.validator_keys[index], self.chain_id, chain.validators,
                    Path(directory) / f"partition-signer-{index}.json"
                )
                engine = ConsensusEngine(signer, chain.validate_proposal_block)

                def persist(result, target=chain):
                    ok, message = target.accept_finalized_block(
                        result["block"], result["round"], result["commit_votes"],
                        result.get("valid_round"), result.get("valid_round_certificate"),
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
                block = chains[0].build_proposal(proposer)
                proposal = make_proposal(
                    self.validator_keys[proposer_index], self.chain_id, 1, 0,
                    block["hash"], validator_set_hash(chains[0].validators)
                )
                servers[0].publish_proposal(proposal, block)
                time.sleep(0.5)
                self.assertTrue(all(len(chain.blocks) == 1 for chain in chains))
            finally:
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_bft_chain_rejects_symlinked_chain_data_file(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real-chain.json"
            link = Path(directory) / "linked-chain.json"
            BFTChain(self.cfg, real)
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                BFTChain(self.cfg, link)


    def test_multiple_committed_transitions_rotate_quorum_at_each_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "multi-epoch-chain.json"
            chain = BFTChain(self.cfg, path)
            set_two_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            set_two = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in set_two_keys
            ]
            first_transition = make_transition_certificate(
                self.validator_keys[:3], self.chain_id, 2,
                chain.initial_validators, set_two,
            )
            first_proposer = select_proposer(chain.validators, 1, 0)
            first_block = chain.build_proposal(
                first_proposer, validator_transition=first_transition
            )
            old_keys = {
                key.public_key().public_bytes_raw().hex(): key
                for key in self.validator_keys
            }
            first_votes = [
                make_vote(old_keys[item["public_key"]], self.chain_id, 1, 0,
                          "precommit", first_block["hash"],
                          validator_set_hash(chain.initial_validators))
                for item in chain.initial_validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(
                first_block, 0, first_votes
            )
            self.assertTrue(accepted, message)
            self.assertEqual(
                chain.validators, sorted(set_two, key=lambda item: item["public_key"])
            )

            set_three_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            set_three = [
                {"public_key": key.public_key().public_bytes_raw().hex(),
                 "voting_power": 1}
                for key in set_three_keys
            ]
            second_transition = make_transition_certificate(
                set_two_keys[:3], self.chain_id, 3, set_two, set_three
            )
            second_proposer = select_proposer(chain.validators, 2, 0)
            second_block = chain.build_proposal(
                second_proposer, validator_transition=second_transition
            )
            # A certificate from the retired set cannot finalize the next height.
            stale_votes = [
                make_vote(key, self.chain_id, 2, 0, "precommit",
                          second_block["hash"], validator_set_hash(chain.initial_validators))
                for key in self.validator_keys[:3]
            ]
            accepted, _ = chain.accept_finalized_block(second_block, 0, stale_votes)
            self.assertFalse(accepted)

            set_two_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in set_two_keys
            }
            second_votes = [
                make_vote(set_two_by_public[item["public_key"]], self.chain_id,
                          2, 0, "precommit", second_block["hash"],
                          validator_set_hash(set_two))
                for item in chain.validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(
                second_block, 0, second_votes
            )
            self.assertTrue(accepted, message)
            self.assertEqual(
                chain.validators,
                sorted(set_three, key=lambda item: item["public_key"]),
            )

            third_proposer = select_proposer(chain.validators, 3, 0)
            third_block = chain.build_proposal(third_proposer)
            set_three_by_public = {
                key.public_key().public_bytes_raw().hex(): key
                for key in set_three_keys
            }
            third_votes = [
                make_vote(set_three_by_public[item["public_key"]], self.chain_id,
                          3, 0, "precommit", third_block["hash"],
                          validator_set_hash(set_three))
                for item in chain.validators[:3]
            ]
            accepted, message = chain.accept_finalized_block(
                third_block, 0, third_votes
            )
            self.assertTrue(accepted, message)

            reopened = BFTChain(self.cfg, path)
            self.assertEqual(reopened.blocks, chain.blocks)
            self.assertEqual(
                reopened.validators,
                sorted(set_three, key=lambda item: item["public_key"]),
            )
            self.assertTrue(reopened.valid_chain(reopened.blocks))


if __name__ == "__main__":
    unittest.main()
