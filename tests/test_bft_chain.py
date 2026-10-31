import os
import tempfile
import unittest
import threading
import json
import urllib.request
from http.server import ThreadingHTTPServer
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admission import issuer_set_hash, sign_admission
from bft_chain import BFTChain
from node import bhash
from consensus import make_proposal, make_round_change, select_proposer
from consensus_network import ConsensusHTTPServer
from engine import ConsensusEngine
from signer import ConsensusSigner
from bft_node import BFTAPI, load_validator_key
from keygen import generate_keypair
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

    def test_bft_chain_rejects_reward_redirection_away_from_selected_proposer(self):
        with tempfile.TemporaryDirectory() as directory:
            chain = BFTChain(self.cfg, Path(directory) / "chain.json")
            proposer = select_proposer(chain.validators, 1, 0)
            block = chain.build_proposal(proposer)
            other = next(item["public_key"] for item in chain.validators
                         if item["public_key"] != proposer)
            block["transactions"][0]["recipient"] = other
            block["hash"] = bhash(block)
            self.assertIsNone(chain.validate_proposal_block(block))

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
            block = chain.build_proposal(chain.validators[0]["public_key"])
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
            block = chain.build_proposal(chain.validators[0]["public_key"])
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
            block = chain.build_proposal(chain.validators[0]["public_key"])
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
            block = chain.build_proposal(chain.validators[0]["public_key"])
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


if __name__ == "__main__":
    unittest.main()
