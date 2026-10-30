"""Stake-free BFT consensus primitives for Biscuits.

This module verifies validator signatures, proposal commitments and >2/3
commit certificates. It deliberately does not implement validator admission,
network transport, persistent consensus locks, or a complete round state
machine; those are required before production deployment.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

STEPS = frozenset({"prevote", "precommit"})


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _is_hex(value: object, size: int) -> bool:
    if not isinstance(value, str) or len(value) != size * 2:
        return False
    try:
        return len(bytes.fromhex(value)) == size
    except ValueError:
        return False


def normalize_validator_set(validators: Sequence[Mapping[str, object]]) -> dict[str, int]:
    """Validate and normalize a validator set keyed by Ed25519 public key hex."""
    if not isinstance(validators, Sequence) or isinstance(validators, (str, bytes)):
        raise ValueError("validators must be a sequence")
    result: dict[str, int] = {}
    for item in validators:
        if not isinstance(item, Mapping) or set(item) != {"public_key", "voting_power"}:
            raise ValueError("each validator requires public_key and voting_power")
        key = item["public_key"]
        power = item["voting_power"]
        if not _is_hex(key, 32):
            raise ValueError("validator public_key must be 32-byte hex")
        key = key.lower()
        if not isinstance(power, int) or isinstance(power, bool) or power <= 0:
            raise ValueError("validator voting_power must be a positive integer")
        if key in result:
            raise ValueError("duplicate validator public key")
        result[key] = power
    if not result:
        raise ValueError("validator set cannot be empty")
    return dict(sorted(result.items()))


def validator_set_hash(validators: Sequence[Mapping[str, object]]) -> str:
    normalized = normalize_validator_set(validators)
    entries = [
        {"public_key": key, "voting_power": power}
        for key, power in normalized.items()
    ]
    return hashlib.sha256(canonical_json(entries)).hexdigest()


def select_proposer(
    validators: Sequence[Mapping[str, object]], height: int, round_number: int
) -> str:
    """Select a deterministic weighted proposer for a height and round."""
    normalized = normalize_validator_set(validators)
    if not isinstance(height, int) or isinstance(height, bool) or height < 1:
        raise ValueError("height must be a positive integer")
    if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
        raise ValueError("round_number must be a non-negative integer")
    total = sum(normalized.values())
    seed = hashlib.sha256(f"biscuits-proposer:{height}:{round_number}".encode()).digest()
    slot = int.from_bytes(seed, "big") % total
    for key, power in normalized.items():
        if slot < power:
            return key
        slot -= power
    raise AssertionError("weighted proposer selection failed")


def proposal_signing_bytes(
    chain_id: str, height: int, round_number: int, block_hash: str, validators_hash: str
) -> bytes:
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise ValueError("chain_id must be non-empty")
    if not isinstance(height, int) or isinstance(height, bool) or height < 1:
        raise ValueError("height must be positive")
    if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0:
        raise ValueError("round_number must be non-negative")
    if not _is_hex(block_hash, 32) or not _is_hex(validators_hash, 32):
        raise ValueError("block_hash and validators_hash must be 32-byte hex")
    return canonical_json({
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "block_hash": block_hash.lower(),
        "validator_set_hash": validators_hash.lower(),
        "message": "biscuits/bft/proposal/v1",
    })


def make_proposal(
    private_key: Ed25519PrivateKey,
    chain_id: str,
    height: int,
    round_number: int,
    block_hash: str,
    validators_hash: str,
) -> dict[str, object]:
    public_key = private_key.public_key().public_bytes_raw().hex()
    message = proposal_signing_bytes(
        chain_id, height, round_number, block_hash, validators_hash
    )
    return {
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "block_hash": block_hash.lower(),
        "validator_set_hash": validators_hash.lower(),
        "proposer": public_key,
        "signature": private_key.sign(message).hex(),
    }


def verify_proposal(
    proposal: Mapping[str, object],
    validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
) -> bool:
    try:
        if set(proposal) != {
            "chain_id", "height", "round", "block_hash",
            "validator_set_hash", "proposer", "signature",
        }:
            return False
        normalized = normalize_validator_set(validators)
        proposer = proposal["proposer"]
        if proposer not in normalized or proposal["chain_id"] != expected_chain_id:
            return False
        if not _is_hex(proposer, 32):
            return False
        expected_set_hash = validator_set_hash(validators)
        if proposal["validator_set_hash"] != expected_set_hash:
            return False
        if proposer != select_proposer(validators, proposal["height"], proposal["round"]):
            return False
        message = proposal_signing_bytes(
            expected_chain_id, proposal["height"], proposal["round"],
            proposal["block_hash"], expected_set_hash,
        )
        if not _is_hex(proposal["signature"], 64):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(proposer)).verify(
            bytes.fromhex(proposal["signature"]), message
        )
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False


def vote_signing_bytes(
    chain_id: str, height: int, round_number: int, step: str,
    block_hash: str, validators_hash: str,
) -> bytes:
    if step not in STEPS:
        raise ValueError("step must be prevote or precommit")
    # Reuse proposal field validation and domain-separate vote messages.
    proposal = proposal_signing_bytes(
        chain_id, height, round_number, block_hash, validators_hash
    )
    data = json.loads(proposal)
    data["message"] = f"biscuits/bft/{step}/v1"
    return canonical_json(data)


def make_vote(
    private_key: Ed25519PrivateKey, chain_id: str, height: int,
    round_number: int, step: str, block_hash: str, validators_hash: str,
) -> dict[str, object]:
    public_key = private_key.public_key().public_bytes_raw().hex()
    message = vote_signing_bytes(
        chain_id, height, round_number, step, block_hash, validators_hash
    )
    return {
        "chain_id": chain_id, "height": height, "round": round_number,
        "step": step, "block_hash": block_hash.lower(),
        "validator_set_hash": validators_hash.lower(),
        "validator": public_key, "signature": private_key.sign(message).hex(),
    }


def verify_vote(
    vote: Mapping[str, object], validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
) -> bool:
    try:
        if set(vote) != {
            "chain_id", "height", "round", "step", "block_hash",
            "validator_set_hash", "validator", "signature",
        }:
            return False
        normalized = normalize_validator_set(validators)
        key = vote["validator"]
        if key not in normalized or vote["chain_id"] != expected_chain_id:
            return False
        if vote["validator_set_hash"] != validator_set_hash(validators):
            return False
        message = vote_signing_bytes(
            expected_chain_id, vote["height"], vote["round"], vote["step"],
            vote["block_hash"], vote["validator_set_hash"],
        )
        if not _is_hex(vote["signature"], 64):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(vote["signature"]), message
        )
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False


def verify_commit_certificate(
    votes: Sequence[Mapping[str, object]],
    validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
    height: int,
    round_number: int,
    block_hash: str,
) -> bool:
    """Require unique valid precommit votes representing strictly >2/3 power."""
    try:
        normalized = normalize_validator_set(validators)
        expected_set_hash = validator_set_hash(validators)
        seen: set[str] = set()
        signed_power = 0
        for vote in votes:
            if not verify_vote(vote, validators, expected_chain_id):
                return False
            if (
                vote["height"] != height or vote["round"] != round_number
                or vote["step"] != "precommit"
                or vote["block_hash"] != block_hash.lower()
                or vote["validator_set_hash"] != expected_set_hash
            ):
                return False
            key = vote["validator"]
            if key in seen:
                return False
            seen.add(key)
            signed_power += normalized[key]
        total_power = sum(normalized.values())
        return signed_power * 3 > total_power * 2
    except (ValueError, TypeError, KeyError):
        return False
