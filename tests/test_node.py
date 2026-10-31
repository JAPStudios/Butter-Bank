import io
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from email.message import Message
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from node import API, Chain, bhash, canon, signing_bytes, synchronize_peer


def wallet():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return key, private.hex(), public.hex()


class ChainValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "chain.json"
        self.cfg = {
            "chain_id": "unit-test-chain",
            "difficulty": 1,
            "block_reward": 50,
            "genesis_allocations": {},
        }
        self.chain = Chain(self.cfg, self.path)

    def test_rejects_invalid_configuration(self):
        for changes in (
            {"difficulty": True},
            {"difficulty": 0},
            {"block_reward": -1},
            {"genesis_allocations": {"not-a-key": 1}},
        ):
            cfg = dict(self.cfg)
            cfg.update(changes)
            with self.assertRaises(ValueError):
                Chain(cfg, Path(self.temp.name) / ("bad-" + str(len(changes)) + ".json"))

    def test_mined_block_validates_and_persists(self):
        _, _, address = wallet()
        block, message = self.chain.mine(address)
        self.assertEqual(message, "mined")
        self.assertTrue(self.chain.valid_chain(self.chain.blocks))
        restored = Chain(self.cfg, self.path)
        self.assertEqual(restored.blocks, self.chain.blocks)
        self.assertEqual(restored.state()[0][address], 50)

    def test_rejects_tampered_block_and_non_integer_timestamp(self):
        _, _, address = wallet()
        self.chain.mine(address)
        tampered = [dict(b) for b in self.chain.blocks]
        tampered[1]["timestamp"] = str(tampered[1]["timestamp"])
        self.assertFalse(self.chain.valid_chain(tampered))
        tampered = [dict(b) for b in self.chain.blocks]
        tampered[1]["transactions"] = []
        self.assertFalse(self.chain.valid_chain(tampered))

    def test_signed_transaction_and_pool_survive_restart(self):
        key, _, sender = wallet()
        _, _, recipient = wallet()
        self.cfg["genesis_allocations"] = {sender: 1000}
        self.path = Path(self.temp.name) / "funded-chain.json"
        self.chain = Chain(self.cfg, self.path)
        tx = {
            "chain_id": self.cfg["chain_id"],
            "sender": sender,
            "recipient": recipient,
            "amount": 100,
            "fee": 2,
            "nonce": 1,
        }
        tx["signature"] = key.sign(signing_bytes(tx)).hex()
        ok, message = self.chain.add_tx(tx)
        self.assertTrue(ok, message)
        restored = Chain(self.cfg, self.path)
        self.assertEqual(restored.pool, [tx])

    def test_configured_peers_persist_across_restart(self):
        self.cfg["peers"] = ["http://127.0.0.1:8334"]
        self.chain = Chain(self.cfg, self.path)
        restored = Chain(self.cfg, self.path)
        self.assertEqual(restored.peers, ["http://127.0.0.1:8334"])

    def test_rejects_malformed_peer_configuration(self):
        cfg = dict(self.cfg)
        cfg["peers"] = "http://127.0.0.1:8333"
        with self.assertRaises(ValueError):
            Chain(cfg, Path(self.temp.name) / "bad-peers.json")

    def test_block_cannot_spend_its_own_coinbase_reward(self):
        miner_key, _, miner = wallet()
        _, _, recipient = wallet()
        tx = {
            "chain_id": self.cfg["chain_id"],
            "sender": miner,
            "recipient": recipient,
            "amount": 50,
            "fee": 0,
            "nonce": 1,
        }
        tx["signature"] = miner_key.sign(signing_bytes(tx)).hex()
        block = {
            "height": 1,
            "previous_hash": self.chain.blocks[0]["hash"],
            "timestamp": 1,
            "transactions": [
                {"type": "coinbase", "recipient": miner, "amount": 50},
                tx,
            ],
            "nonce": 0,
        }
        while True:
            block["hash"] = bhash(block)
            if block["hash"].startswith("0" * self.cfg["difficulty"]):
                break
            block["nonce"] += 1

        # The miner has no funds before this block. Its reward must not be
        # spendable by a transaction included in the same block.
        self.assertFalse(self.chain.valid_chain([self.chain.blocks[0], block]))

    def test_sync_revalidates_pending_transactions(self):
        _, _, miner = wallet()
        self.chain.mine(miner)
        candidate = list(self.chain.blocks)
        _, _, second_miner = wallet()
        remote = Chain(self.cfg, Path(self.temp.name) / "remote.json")
        remote.mine(second_miner)
        remote.mine(second_miner)
        self.assertTrue(self.chain.replace(remote.blocks)[0])
        self.assertEqual(len(self.chain.blocks), 3)



    def test_chain_work_uses_proof_of_work_target(self):
        from node import block_work, chain_work

        self.assertEqual(block_work(1), 16)
        self.assertEqual(block_work(2), 256)
        _, _, miner = wallet()
        self.chain.mine(miner)
        self.assertEqual(chain_work(self.chain.blocks, self.chain.diff), 16)

    def test_reorganization_returns_orphaned_transactions_to_mempool(self):
        sender_key, _, sender = wallet()
        _, _, recipient = wallet()
        self.cfg["genesis_allocations"] = {sender: 1000}
        self.path = Path(self.temp.name) / "reorg-local.json"
        self.chain = Chain(self.cfg, self.path)
        tx = {
            "chain_id": self.cfg["chain_id"],
            "sender": sender,
            "recipient": recipient,
            "amount": 125,
            "fee": 3,
            "nonce": 1,
        }
        tx["signature"] = sender_key.sign(signing_bytes(tx)).hex()
        self.assertTrue(self.chain.add_tx(tx)[0])
        local_block, message = self.chain.mine(sender)
        self.assertEqual(message, "mined")
        self.assertIn(tx, local_block["transactions"])

        remote = Chain(self.cfg, Path(self.temp.name) / "reorg-remote.json")
        _, _, remote_miner = wallet()
        remote.mine(remote_miner)
        remote.mine(remote_miner)
        self.assertTrue(self.chain.replace(remote.blocks)[0])
        self.assertEqual(self.chain.blocks, remote.blocks)
        self.assertIn(tx, self.chain.pool)
        balances, nonces = self.chain.state()
        self.assertEqual(balances[sender], 1000)
        self.assertEqual(nonces[sender], 0)

    def test_peer_sync_fetches_and_adopts_longer_chain(self):
        _, _, miner = wallet()
        remote = Chain(self.cfg, Path(self.temp.name) / "remote-periodic.json")
        remote.mine(miner)
        API.chain = remote
        API.peers = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), API)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)

        peer = f"http://127.0.0.1:{server.server_port}"
        self.assertTrue(synchronize_peer(self.chain, peer))
        self.assertEqual(self.chain.blocks, remote.blocks)

    def test_peer_sync_rejects_different_network(self):
        other_cfg = dict(self.cfg, chain_id="different-chain")
        remote = Chain(other_cfg, Path(self.temp.name) / "other-network.json")
        API.chain = remote
        API.peers = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), API)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)

        peer = f"http://127.0.0.1:{server.server_port}"
        self.assertFalse(synchronize_peer(self.chain, peer))
        self.assertEqual(len(self.chain.blocks), 1)

    def test_receive_chain_endpoint_synchronizes_a_longer_fork(self):
        _, _, first_miner = wallet()
        _, _, second_miner = wallet()
        remote = Chain(self.cfg, Path(self.temp.name) / "remote-sync.json")
        remote.mine(first_miner)
        remote.mine(second_miner)

        API.chain = self.chain
        API.peers = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), API)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)

        payload = json.dumps({"chain": remote.blocks}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/receive-chain",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            result = json.loads(response.read())
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.chain.blocks, remote.blocks)


class RequestBodyValidationTests(unittest.TestCase):
    def make_handler(self, body, *lengths, transfer_encoding=None):
        handler = API.__new__(API)
        handler.headers = Message()
        for length in lengths:
            handler.headers.add_header('Content-Length', length)
        if transfer_encoding is not None:
            handler.headers.add_header('Transfer-Encoding', transfer_encoding)
        handler.rfile = io.BytesIO(body)
        return handler

    def test_accepts_complete_json_object(self):
        body = b'{"transaction":{}}'
        self.assertEqual(self.make_handler(body, str(len(body))).body(),
                         {'transaction': {}})

    def test_rejects_missing_or_duplicate_content_length(self):
        for lengths in ((), ('2', '2')):
            with self.subTest(lengths=lengths):
                with self.assertRaisesRegex(ValueError, 'exactly one Content-Length'):
                    self.make_handler(b'{}', *lengths).body()

    def test_rejects_transfer_encoding(self):
        with self.assertRaisesRegex(ValueError, 'Transfer-Encoding'):
            self.make_handler(b'{}', '2', transfer_encoding='chunked').body()

    def test_rejects_non_decimal_and_out_of_range_lengths(self):
        for length in ('+2', ' 2', '2, 2', '٢', '0', '1000001'):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    self.make_handler(b'{}', length).body()

    def test_rejects_truncated_body_and_non_object_json(self):
        with self.assertRaisesRegex(ValueError, 'incomplete request body'):
            self.make_handler(b'{}', '3').body()
        with self.assertRaisesRegex(ValueError, 'JSON request body must be an object'):
            self.make_handler(b'[]', '2').body()

if __name__ == "__main__":
    unittest.main()
