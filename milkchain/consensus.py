"""Milkchain's deterministic, Ed25519-authenticated BFT ledger core.

This module implements a Tendermint-inspired two-vote commit rule:
a block is committed only when validator voting power representing at
least two thirds of the configured power has prevoted and precommitted
for the same block in the same round.

Networking, validator discovery, dynamic validator-set changes, and
production key custody are deliberately separate concerns.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def sign_vote(private_key: Ed25519PrivateKey, chain_id: str, height: int,
              round_number: int, step: str, block_hash: str) -> dict[str, Any]:
    if step not in ("prevote", "precommit"):
        raise ValueError("step must be prevote or precommit")
    payload = {
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "step": step,
        "block_hash": block_hash,
    }
    return {
        "validator": public_key_hex(private_key),
        **payload,
        "signature": private_key.sign(canonical(payload)).hex(),
    }


class ConsensusError(ValueError):
    """Raised when a proposal, vote, or commit certificate is invalid."""


class BFTChain:
    """Persistent account-based ledger with weighted Byzantine commit certificates."""

    def __init__(self, chain_id: str, validators: list[dict[str, Any]],
                 genesis_allocations: dict[str, int] | None = None,
                 data_path: str | Path | None = None):
        if not isinstance(chain_id, str) or not chain_id.strip():
            raise ValueError("chain_id must be a non-empty string")
        if not isinstance(validators, list) or not validators:
            raise ValueError("at least one validator is required")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in validators:
            if not isinstance(item, dict) or set(item) != {"public_key", "power"}:
                raise ValueError("each validator requires public_key and power")
            key, power = item["public_key"], item["power"]
            if not self._is_hex(key, 32) or key in seen:
                raise ValueError("validator public keys must be unique 32-byte hex values")
            if not isinstance(power, int) or isinstance(power, bool) or power <= 0:
                raise ValueError("validator power must be a positive integer")
            seen.add(key)
            normalized.append({"public_key": key, "power": power})
        allocations = genesis_allocations or {}
        if not isinstance(allocations, dict):
            raise ValueError("genesis_allocations must be an object")
        for address, amount in allocations.items():
            if not self._is_hex(address, 32):
                raise ValueError("genesis allocation addresses must be 32-byte hex values")
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                raise ValueError("genesis allocation amounts must be non-negative integers")

        self.chain_id = chain_id
        self.validators = sorted(normalized, key=lambda x: x["public_key"])
        self.validator_power = {v["public_key"]: v["power"] for v in self.validators}
        self.total_power = sum(self.validator_power.values())
        self.data_path = Path(data_path) if data_path is not None else None
        self.blocks: list[dict[str, Any]] = [self._genesis(allocations)]
        if self.data_path and self.data_path.exists():
            stored = json.loads(self.data_path.read_text(encoding="utf-8"))
            if not isinstance(stored, dict) or stored.get("chain_id") != self.chain_id:
                raise ValueError("stored ledger belongs to another chain")
            candidate = stored.get("blocks")
            if not self.validate_chain(candidate):
                raise ValueError("stored ledger failed full validation")
            self.blocks = candidate
        elif self.data_path:
            self.save()

    @staticmethod
    def _is_hex(value: Any, size: int) -> bool:
        if not isinstance(value, str) or len(value) != size * 2:
            return False
        try:
            return len(bytes.fromhex(value)) == size
        except ValueError:
            return False

    def _genesis(self, allocations: dict[str, int]) -> dict[str, Any]:
        header = {
            "chain_id": self.chain_id,
            "height": 0,
            "round": 0,
            "previous_hash": "0" * 64,
            "timestamp": 0,
            "transactions": [],
        }
        return {
            **header,
            "hash": digest(header),
            "prevotes": [],
            "precommits": [],
            "genesis_allocations": dict(sorted(allocations.items())),
            "validators": self.validators,
        }

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    @property
    def tip(self) -> str:
        return self.blocks[-1]["hash"]

    def state(self, blocks: list[dict[str, Any]] | None = None) -> tuple[dict[str, int], dict[str, int]]:
        ledger = self.blocks if blocks is None else blocks
        balances = dict(ledger[0]["genesis_allocations"])
        nonces: dict[str, int] = {address: 0 for address in balances}
        for block in ledger[1:]:
            for tx in block["transactions"]:
                sender, recipient = tx["sender"], tx["recipient"]
                balances[sender] -= tx["amount"]
                balances[recipient] = balances.get(recipient, 0) + tx["amount"]
                nonces[sender] = tx["nonce"]
                nonces.setdefault(recipient, 0)
        return balances, nonces

    def transaction_payload(self, tx: dict[str, Any]) -> dict[str, Any]:
        return {k: tx[k] for k in ("chain_id", "sender", "recipient", "amount", "nonce")}

    def validate_transaction(self, tx: Any, balances: dict[str, int],
                             nonces: dict[str, int]) -> bool:
        fields = {"chain_id", "sender", "recipient", "amount", "nonce", "signature"}
        if not isinstance(tx, dict) or set(tx) != fields:
            return False
        if tx["chain_id"] != self.chain_id:
            return False
        if not self._is_hex(tx["sender"], 32) or not self._is_hex(tx["recipient"], 32):
            return False
        for field in ("amount", "nonce"):
            if not isinstance(tx[field], int) or isinstance(tx[field], bool) or tx[field] <= 0:
                return False
        if tx["nonce"] != nonces.get(tx["sender"], 0) + 1:
            return False
        if balances.get(tx["sender"], 0) < tx["amount"]:
            return False
        if not self._is_hex(tx["signature"], 64):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["sender"])).verify(
                bytes.fromhex(tx["signature"]), canonical(self.transaction_payload(tx))
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    def make_proposal(self, transactions: list[dict[str, Any]],
                      timestamp: int | None = None, round_number: int = 0) -> dict[str, Any]:
        if not isinstance(transactions, list):
            raise ValueError("transactions must be a list")
        if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
            raise ValueError("round must be a non-negative integer")
        block_time = int(time.time()) if timestamp is None else timestamp
        if not isinstance(block_time, int) or isinstance(block_time, bool) or block_time < self.blocks[-1]["timestamp"]:
            raise ValueError("timestamp must be an integer no earlier than the previous block")
        header = {
            "chain_id": self.chain_id,
            "height": self.height + 1,
            "round": round_number,
            "previous_hash": self.tip,
            "timestamp": block_time,
            "transactions": transactions,
        }
        return {**header, "hash": digest(header)}

    def _vote_power(self, votes: Any, step: str, block: dict[str, Any]) -> int:
        if not isinstance(votes, list):
            raise ConsensusError(f"{step} certificate must be a list")
        seen: set[str] = set()
        power = 0
        expected = {
            "chain_id": self.chain_id,
            "height": block["height"],
            "round": block["round"],
            "step": step,
            "block_hash": block["hash"],
        }
        for vote in votes:
            if not isinstance(vote, dict) or set(vote) != {
                "validator", "chain_id", "height", "round", "step", "block_hash", "signature"
            }:
                raise ConsensusError("malformed vote")
            validator = vote["validator"]
            if validator in seen:
                raise ConsensusError("duplicate validator vote")
            if validator not in self.validator_power:
                raise ConsensusError("vote from a non-validator")
            payload = {k: vote[k] for k in expected}
            if payload != expected:
                raise ConsensusError("vote does not match this chain, height, round, step, and block")
            if not self._is_hex(vote["signature"], 64):
                raise ConsensusError("invalid vote signature encoding")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(validator)).verify(
                    bytes.fromhex(vote["signature"]), canonical(payload)
                )
            except (InvalidSignature, ValueError):
                raise ConsensusError("invalid validator signature")
            seen.add(validator)
            power += self.validator_power[validator]
        return power

    def commit(self, proposal: dict[str, Any], prevotes: list[dict[str, Any]],
               precommits: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(proposal, dict):
            raise ConsensusError("proposal must be an object")
        required = {"chain_id", "height", "round", "previous_hash", "timestamp", "transactions", "hash"}
        if set(proposal) != required:
            raise ConsensusError("proposal has incorrect fields")
        header = {k: proposal[k] for k in required if k != "hash"}
        if proposal["hash"] != digest(header):
            raise ConsensusError("proposal hash mismatch")
        if proposal["chain_id"] != self.chain_id or proposal["height"] != self.height + 1:
            raise ConsensusError("proposal is for the wrong chain or height")
        if proposal["previous_hash"] != self.tip:
            raise ConsensusError("proposal does not extend the current tip")
        if not isinstance(proposal["round"], int) or isinstance(proposal["round"], bool) or proposal["round"] < 0:
            raise ConsensusError("invalid proposal round")
        if not isinstance(proposal["timestamp"], int) or isinstance(proposal["timestamp"], bool) or proposal["timestamp"] < self.blocks[-1]["timestamp"]:
            raise ConsensusError("invalid proposal timestamp")
        if not isinstance(proposal["transactions"], list):
            raise ConsensusError("proposal transactions must be a list")

        balances, nonces = self.state()
        for tx in proposal["transactions"]:
            if not self.validate_transaction(tx, balances, nonces):
                raise ConsensusError("proposal contains an invalid transaction")
            balances[tx["sender"]] -= tx["amount"]
            balances[tx["recipient"]] = balances.get(tx["recipient"], 0) + tx["amount"]
            nonces[tx["sender"]] = tx["nonce"]
            nonces.setdefault(tx["recipient"], 0)

        threshold = (2 * self.total_power + 2) // 3
        if self._vote_power(prevotes, "prevote", proposal) < threshold:
            raise ConsensusError("insufficient prevote voting power")
        if self._vote_power(precommits, "precommit", proposal) < threshold:
            raise ConsensusError("insufficient precommit voting power")

        committed = {**proposal, "prevotes": prevotes, "precommits": precommits}
        self.blocks.append(committed)
        self.save()
        return committed

    def validate_chain(self, blocks: Any) -> bool:
        try:
            if not isinstance(blocks, list) or not blocks or blocks[0] != self._genesis(blocks[0].get("genesis_allocations", {})):
                return False
            if blocks[0].get("validators") != self.validators:
                return False
            balances, nonces = self.state(blocks[:1])
            for index, block in enumerate(blocks[1:], 1):
                required = {"chain_id", "height", "round", "previous_hash", "timestamp",
                            "transactions", "hash", "prevotes", "precommits"}
                if not isinstance(block, dict) or set(block) != required:
                    return False
                proposal = {k: block[k] for k in ("chain_id", "height", "round", "previous_hash", "timestamp", "transactions", "hash")}
                header = {k: proposal[k] for k in ("chain_id", "height", "round", "previous_hash", "timestamp", "transactions")}
                if block["hash"] != digest(header) or block["chain_id"] != self.chain_id:
                    return False
                if block["height"] != index or block["previous_hash"] != blocks[index - 1]["hash"]:
                    return False
                if not isinstance(block["round"], int) or isinstance(block["round"], bool) or block["round"] < 0:
                    return False
                if not isinstance(block["timestamp"], int) or isinstance(block["timestamp"], bool) or block["timestamp"] < blocks[index - 1]["timestamp"]:
                    return False
                if not isinstance(block["transactions"], list):
                    return False
                for tx in block["transactions"]:
                    if not self.validate_transaction(tx, balances, nonces):
                        return False
                    balances[tx["sender"]] -= tx["amount"]
                    balances[tx["recipient"]] = balances.get(tx["recipient"], 0) + tx["amount"]
                    nonces[tx["sender"]] = tx["nonce"]
                    nonces.setdefault(tx["recipient"], 0)
                threshold = (2 * self.total_power + 2) // 3
                if self._vote_power(block["prevotes"], "prevote", proposal) < threshold:
                    return False
                if self._vote_power(block["precommits"], "precommit", proposal) < threshold:
                    return False
            return True
        except (KeyError, TypeError, ValueError, ConsensusError, AttributeError):
            return False

    def save(self) -> None:
        if self.data_path is None:
            return
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical({"chain_id": self.chain_id, "blocks": self.blocks})
        fd, temporary = tempfile.mkstemp(prefix=self.data_path.name + ".", dir=self.data_path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.data_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
