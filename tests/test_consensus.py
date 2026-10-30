import os
import unittest
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import urllib.request
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from consensus import (
    make_proposal,
    make_vote,
    make_round_change,
    select_proposer,
    validator_set_hash,
    verify_commit_certificate,
    verify_proposal,
    verify_vote,
    verify_round_change,
    verify_round_change_certificate,
)
from signer import ConsensusSigner
from engine import ConsensusEngine
from consensus_network import ConsensusHTTPServer


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
        case_duplicate = [
            {"public_key": self.validators[0]["public_key"].lower(), "voting_power": 1},
            {"public_key": self.validators[0]["public_key"].upper(), "voting_power": 1},
        ]
        with self.assertRaises(ValueError):
            validator_set_hash(case_duplicate)
        invalid = [{"public_key": self.validators[0]["public_key"], "voting_power": 0}]
        with self.assertRaises(ValueError):
            validator_set_hash(invalid)

    def test_proposal_signature_and_validator_membership(self):
        proposer = select_proposer(self.validators, 1, 0)
        proposer_key = next(key for key, record in self.keys_and_records
                            if record["public_key"] == proposer)
        proposal = make_proposal(
            proposer_key, self.chain_id, 1, 0,
            self.block_hash, self.set_hash,
        )
        self.assertTrue(verify_proposal(proposal, self.validators, self.chain_id))
        tampered = dict(proposal, block_hash="cd" * 32)
        self.assertFalse(verify_proposal(tampered, self.validators, self.chain_id))
        self.assertFalse(verify_proposal(
            dict(proposal, block_hash=proposal["block_hash"].upper()),
            self.validators, self.chain_id
        ))
        self.assertFalse(verify_proposal(
            dict(proposal, signature=proposal["signature"].upper()),
            self.validators, self.chain_id
        ))
        self.assertFalse(verify_proposal(proposal, self.validators, "other-chain"))

    def test_votes_are_domain_separated_and_signed(self):
        vote = make_vote(
            self.keys_and_records[0][0], self.chain_id, 1, 0,
            "precommit", self.block_hash, self.set_hash,
        )
        self.assertTrue(verify_vote(vote, self.validators, self.chain_id))
        self.assertFalse(verify_vote(dict(vote, step="prevote"), self.validators, self.chain_id))
        self.assertFalse(verify_vote(
            dict(vote, block_hash=vote["block_hash"].upper()),
            self.validators, self.chain_id
        ))


    def test_round_change_certificate_requires_authenticated_supermajority(self):
        messages = [
            make_round_change(key, self.chain_id, 1, 1, self.set_hash)
            for key, _ in self.keys_and_records[:3]
        ]
        self.assertTrue(verify_round_change(messages[0], self.validators, self.chain_id))
        self.assertTrue(verify_round_change_certificate(
            messages, self.validators, self.chain_id, 1, 1
        ))
        self.assertFalse(verify_round_change_certificate(
            messages[:1], self.validators, self.chain_id, 1, 1
        ))
        self.assertFalse(verify_round_change_certificate(
            messages + [messages[0]], self.validators, self.chain_id, 1, 1
        ))
        self.assertFalse(verify_round_change_certificate(
            messages, self.validators, self.chain_id, 1, 2
        ))
        altered = dict(messages[0], round=2)
        self.assertFalse(verify_round_change(altered, self.validators, self.chain_id))


    def test_engine_advances_only_after_persisted_round_change_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "round-change-state.json"
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators, path
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            local = engine.request_round_change(1)
            self.assertIsNone(engine.receive_round_change(
                make_round_change(self.keys_and_records[1][0], self.chain_id, 1, 1, self.set_hash)
            ))
            result = engine.receive_round_change(
                make_round_change(self.keys_and_records[2][0], self.chain_id, 1, 1, self.set_hash)
            )
            self.assertEqual(result["round"], 1)
            self.assertEqual(engine.round, 1)
            signer.close()
            reopened = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators, path
            )
            self.assertEqual(reopened.current_round, 1)
            self.assertEqual(reopened.state["signed_round_changes"]["1"], local)
            reopened.close()

    def test_locked_signer_cannot_sign_or_accept_round_change_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "locked-round-state.json"
            )
            prevotes = [
                make_vote(key, self.chain_id, 1, 0, "prevote", self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            signer.lock_from_prevotes(prevotes, 0, self.block_hash)
            with self.assertRaises(RuntimeError):
                signer.sign_round_change(1)
            certificate = [
                make_round_change(key, self.chain_id, 1, 1, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            with self.assertRaises(RuntimeError):
                signer.advance_round(certificate)
            signer.close()

    def test_round_change_is_chain_and_validator_set_bound(self):
        message = make_round_change(
            self.keys_and_records[0][0], self.chain_id, 1, 2, self.set_hash
        )
        self.assertFalse(verify_round_change(message, self.validators, "other-chain"))
        changed_set = self.validators[:-1]
        self.assertFalse(verify_round_change(message, changed_set, self.chain_id))

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
        self.assertFalse(verify_commit_certificate(
            votes, self.validators, self.chain_id, True, 0, self.block_hash
        ))
        self.assertFalse(verify_commit_certificate(
            votes, self.validators, self.chain_id, 1, False, self.block_hash
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

    def test_signer_persists_votes_and_refuses_double_signing(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'validator-state.json'
            signer = ConsensusSigner(key, self.chain_id, self.validators, path)
            vote = signer.sign_vote(0, 'prevote', self.block_hash)
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                ConsensusSigner(key, self.chain_id, self.validators, path)
            signer.close()
            reopened = ConsensusSigner(key, self.chain_id, self.validators, path)
            self.assertEqual(vote, reopened.sign_vote(0, 'prevote', self.block_hash))
            with self.assertRaises(ValueError):
                reopened.sign_vote(0, 'prevote', 'cd' * 32)
            reopened.close()

    def test_signer_requires_prevote_quorum_lock_before_precommit(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(key, self.chain_id, self.validators, Path(directory) / 'state.json')
            with self.assertRaises(ValueError):
                signer.sign_vote(0, 'precommit', self.block_hash)
            prevotes = [make_vote(k, self.chain_id, 1, 0, 'prevote', self.block_hash, self.set_hash) for k, _ in self.keys_and_records[:3]]
            signer.lock_from_prevotes(prevotes, 0, self.block_hash)
            self.assertTrue(verify_vote(signer.sign_vote(0, 'precommit', self.block_hash), self.validators, self.chain_id))
            with self.assertRaises(ValueError):
                signer.sign_vote(1, 'prevote', 'cd' * 32)

    def test_proposal_rejects_non_designated_validator(self):
        selected = select_proposer(self.validators, 1, 0)
        wrong = next(k for k, record in self.keys_and_records if record['public_key'] != selected)
        proposal = make_proposal(wrong, self.chain_id, 1, 0, self.block_hash, self.set_hash)
        self.assertFalse(verify_proposal(proposal, self.validators, self.chain_id))

    def test_engine_finalizes_only_after_prevotes_and_precommits_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            local_key = self.keys_and_records[0][0]
            signer = ConsensusSigner(local_key, self.chain_id, self.validators,
                                     Path(directory) / "engine-state.json")
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            proposer_key = next(
                key for key, record in self.keys_and_records
                if record["public_key"] == select_proposer(self.validators, 1, 0)
            )
            block = {"hash": self.block_hash, "payload": "valid-test-block"}
            proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                     self.block_hash, self.set_hash)
            self.assertTrue(engine.receive_proposal(proposal, block))
            local_prevote = engine.prevote(self.block_hash)
            prevotes = [local_prevote] + [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ]
            precommit = None
            for vote in prevotes:
                action = engine.receive_vote(vote)
                if action is not None:
                    precommit = action
            self.assertIsNotNone(precommit)
            self.assertTrue(verify_vote(precommit, self.validators, self.chain_id))
            precommits = [
                make_vote(key, self.chain_id, 1, 0, "precommit",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ] + [precommit]
            finalized = None
            for vote in precommits:
                action = engine.receive_vote(vote)
                if action is not None:
                    finalized = action
            self.assertIsNotNone(finalized)
            self.assertEqual(finalized["block"], block)
            self.assertEqual(signer.height, 2)

    def test_engine_rejects_invalid_block_and_halts_locked_round_change(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "engine-state.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            proposer_key = next(
                key for key, record in self.keys_and_records
                if record["public_key"] == select_proposer(self.validators, 1, 0)
            )
            proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                     self.block_hash, self.set_hash)
            self.assertFalse(engine.receive_proposal(proposal, {"hash": "cd" * 32}))
            certificate = [
                make_round_change(key, self.chain_id, 1, 1, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            self.assertEqual(engine.advance_round(certificate), 1)
            locked_prevotes = [
                make_vote(key, self.chain_id, 1, 1, "prevote",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            signer.lock_from_prevotes(locked_prevotes, 1, self.block_hash)
            with self.assertRaises(RuntimeError):
                engine.advance_round()

    def test_http_transport_accepts_signed_proposal_and_vote(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(self.keys_and_records[0][0], self.chain_id,
                                     self.validators, Path(directory) / "network-state.json")
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            server = ConsensusHTTPServer(engine, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = "http://127.0.0.1:" + str(server.server.server_address[1])
            try:
                proposer_key = next(
                    key for key, record in self.keys_and_records
                    if record["public_key"] == select_proposer(self.validators, 1, 0)
                )
                block = {"hash": self.block_hash}
                proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                         self.block_hash, self.set_hash)
                payload = json.dumps({"proposal": proposal, "block": block}).encode()
                request = urllib.request.Request(
                    url + "/consensus/proposal", data=payload,
                    headers={"Content-Type": "application/json"}, method="POST"
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                vote = make_vote(self.keys_and_records[1][0], self.chain_id, 1, 0,
                                 "prevote", self.block_hash, self.set_hash)
                payload = json.dumps({"vote": vote}).encode()
                request = urllib.request.Request(
                    url + "/consensus/vote", data=payload,
                    headers={"Content-Type": "application/json"}, method="POST"
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                self.assertIn(("0", "prevote"), {
                    (str(key[0]), key[1]) for key in engine.votes
                })
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_http_transport_round_change_requires_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "round-change-network-state.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            server = ConsensusHTTPServer(engine, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = "http://127.0.0.1:" + str(server.server.server_address[1])
            try:
                server.publish_round_change(1)
                for key, _ in self.keys_and_records[1:3]:
                    round_change = make_round_change(
                        key, self.chain_id, 1, 1, self.set_hash
                    )
                    payload = json.dumps({"round_change": round_change}).encode()
                    request = urllib.request.Request(
                        url + "/consensus/round-change", data=payload,
                        headers={"Content-Type": "application/json"}, method="POST"
                    )
                    with urllib.request.urlopen(request, timeout=2) as response:
                        self.assertEqual(response.status, 200)
                self.assertEqual(engine.round, 1)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_transport_rejects_remote_plain_http_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(self.keys_and_records[0][0], self.chain_id,
                                     self.validators, Path(directory) / "network-state.json")
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            with self.assertRaises(ValueError):
                ConsensusHTTPServer(engine, peers=["http://example.com:8334"])

    def test_commit_certificate_finalizes_validator_without_local_prevote_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "signer.json"
            )
            votes = [
                make_vote(key, self.chain_id, 1, 0, "precommit",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            signer.finalize(votes, 0, self.block_hash)
            self.assertEqual(signer.height, 2)

    def test_engine_persists_block_callback_before_advancing_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "signer.json"
            )
            observed_heights = []
            engine = ConsensusEngine(
                signer, lambda block: block.get("hash"),
                on_finalized=lambda result: observed_heights.append(signer.height)
            )
            proposer_key = next(
                key for key, record in self.keys_and_records
                if record["public_key"] == select_proposer(self.validators, 1, 0)
            )
            block = {"hash": self.block_hash}
            proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                     self.block_hash, self.set_hash)
            self.assertTrue(engine.receive_proposal(proposal, block))
            local_prevote = engine.prevote(self.block_hash)
            prevotes = [local_prevote] + [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ]
            precommit = None
            for vote in prevotes:
                action = engine.receive_vote(vote)
                if action is not None:
                    precommit = action
            precommits = [precommit] + [
                make_vote(key, self.chain_id, 1, 0, "precommit",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ]
            for vote in precommits:
                engine.receive_vote(vote)
            self.assertEqual(observed_heights, [1])
            self.assertEqual(signer.height, 2)

    def test_round_number_survives_restart_and_prevents_regression(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            signer = ConsensusSigner(key, self.chain_id, self.validators, path)
            certificate = [
                make_round_change(key, self.chain_id, 1, 1, self.set_hash)
                for key, _ in self.keys_and_records[:3]
            ]
            self.assertEqual(signer.advance_round(certificate), 1)
            signer.close()
            reopened = ConsensusSigner(key, self.chain_id, self.validators, path)
            engine = ConsensusEngine(reopened, lambda block: block.get("hash"))
            self.assertEqual(engine.round, 1)
            with self.assertRaises(ValueError):
                reopened.sign_vote(0, "prevote", self.block_hash)
            reopened.sign_vote(1, "prevote", self.block_hash)
            reopened.close()

    def test_commit_retries_after_transient_chain_persistence_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "signer.json"
            )
            calls = []
            def persist(result):
                calls.append(result["block_hash"])
                if len(calls) == 1:
                    raise OSError("temporary disk failure")
            engine = ConsensusEngine(
                signer, lambda block: block.get("hash"), on_finalized=persist
            )
            proposer_key = next(
                key for key, record in self.keys_and_records
                if record["public_key"] == select_proposer(self.validators, 1, 0)
            )
            block = {"hash": self.block_hash}
            proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                     self.block_hash, self.set_hash)
            self.assertTrue(engine.receive_proposal(proposal, block))
            local_prevote = engine.prevote(self.block_hash)
            prevotes = [local_prevote] + [
                make_vote(key, self.chain_id, 1, 0, "prevote",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ]
            precommit = None
            for vote in prevotes:
                action = engine.receive_vote(vote)
                if action is not None:
                    precommit = action
            precommits = [precommit] + [
                make_vote(key, self.chain_id, 1, 0, "precommit",
                          self.block_hash, self.set_hash)
                for key, _ in self.keys_and_records[1:3]
            ]
            for vote in precommits:
                engine.receive_vote(vote)
            self.assertEqual(signer.height, 1)
            self.assertIsNotNone(engine.retry_pending_finalization())
            self.assertEqual(signer.height, 2)
            self.assertEqual(len(calls), 2)

    def test_concurrent_signing_returns_one_persisted_vote(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(key, self.chain_id, self.validators,
                                     Path(directory) / "state.json")
            with ThreadPoolExecutor(max_workers=8) as executor:
                votes = list(executor.map(
                    lambda _: signer.sign_vote(0, "prevote", self.block_hash),
                    range(32)
                ))
            self.assertTrue(all(vote == votes[0] for vote in votes))
            signer.close()
            reopened = ConsensusSigner(key, self.chain_id, self.validators,
                                       Path(directory) / "state.json")
            self.assertEqual(reopened.sign_vote(0, "prevote", self.block_hash), votes[0])
            reopened.close()

    def test_concurrent_duplicate_network_votes_count_once(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "state.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            proposer_key = next(
                key for key, record in self.keys_and_records
                if record["public_key"] == select_proposer(self.validators, 1, 0)
            )
            block = {"hash": self.block_hash}
            proposal = make_proposal(proposer_key, self.chain_id, 1, 0,
                                     self.block_hash, self.set_hash)
            self.assertTrue(engine.receive_proposal(proposal, block))
            vote = make_vote(self.keys_and_records[1][0], self.chain_id, 1, 0,
                             "prevote", self.block_hash, self.set_hash)
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda _: engine.receive_vote(vote), range(32)))
            self.assertEqual(len(engine.votes[(0, "prevote")]), 1)

    def test_consensus_transport_requires_tls_on_public_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "signer.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            with self.assertRaises(ValueError):
                ConsensusHTTPServer(engine, host="0.0.0.0", port=0)

    @unittest.skipIf(os.name == "nt", "POSIX file-mode and symlink semantics")
    def test_signer_rejects_group_readable_state_file(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            signer = ConsensusSigner(key, self.chain_id, self.validators, path)
            signer.close()
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "permissions 0600"):
                ConsensusSigner(key, self.chain_id, self.validators, path)

    @unittest.skipIf(os.name == "nt", "POSIX file-mode and symlink semantics")
    def test_signer_rejects_state_file_symlink(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real-state.json"
            link = Path(directory) / "linked-state.json"
            signer = ConsensusSigner(key, self.chain_id, self.validators, real)
            signer.close()
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                ConsensusSigner(key, self.chain_id, self.validators, link)

    def test_signer_exclusive_process_lock_is_released_on_close(self):
        key, _ = self.keys_and_records[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            first = ConsensusSigner(key, self.chain_id, self.validators, path)
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                ConsensusSigner(key, self.chain_id, self.validators, path)
            first.close()
            with self.assertRaisesRegex(RuntimeError, "signer is closed"):
                first.sign_vote(0, "prevote", self.block_hash)
            second = ConsensusSigner(key, self.chain_id, self.validators, path)
            second.close()

    def test_engine_counts_at_most_one_vote_per_validator_per_round_step(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "state.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            first = make_vote(
                self.keys_and_records[1][0], self.chain_id, 1, 0,
                "prevote", self.block_hash, self.set_hash
            )
            conflicting = make_vote(
                self.keys_and_records[1][0], self.chain_id, 1, 0,
                "prevote", "ab" * 32, self.set_hash
            )
            self.assertIsNone(engine.receive_vote(first))
            self.assertIsNone(engine.receive_vote(conflicting))
            self.assertEqual(len(engine.votes[(0, "prevote")]), 1)
            self.assertEqual(
                engine.votes[(0, "prevote")][first["validator"]]["block_hash"],
                self.block_hash
            )

    def test_engine_ignores_stale_future_and_wrong_chain_votes(self):
        with tempfile.TemporaryDirectory() as directory:
            signer = ConsensusSigner(
                self.keys_and_records[0][0], self.chain_id, self.validators,
                Path(directory) / "state.json"
            )
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            stale = make_vote(
                self.keys_and_records[1][0], self.chain_id, 1, 0,
                "prevote", self.block_hash, self.set_hash
            )
            stale["height"] = 0
            self.assertIsNone(engine.receive_vote(stale))
            for height, round_number, chain_id in (
                (2, 0, self.chain_id), (1, 1, self.chain_id),
                (1, 0, "other-chain")
            ):
                vote = make_vote(
                    self.keys_and_records[1][0], chain_id, height, round_number,
                    "prevote", self.block_hash, self.set_hash
                )
                self.assertIsNone(engine.receive_vote(vote))
            self.assertEqual(sum(len(votes) for votes in engine.votes.values()), 0)


if __name__ == "__main__":
    unittest.main()
