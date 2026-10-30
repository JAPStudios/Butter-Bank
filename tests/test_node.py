import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from node import Chain, bhash, canon, signing_bytes


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


if __name__ == "__main__":
    unittest.main()
