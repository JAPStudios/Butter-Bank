"""Stake-free BFT consensus primitives for Biscuits.

This module defines canonical, domain-separated Ed25519 messages and verifies
validator sets, proposals, votes, round-change certificates, and commit
certificates. Persistent signing state, coordination, admission, and transport
are implemented in their dedicated modules. The complete production protocol
still requires formally specified safe locked-round recovery and validation.
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
# A 32-bit round counter is ample for any practical deployment and keeps
# untrusted consensus messages and persisted counters strictly bounded.
MAX_ROUND = (1 << 32) - 1


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
    if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 0 or round_number > MAX_ROUND:
        raise ValueError("round_number must be a 32-bit non-negative integer")
    total = sum(normalized.values())
    seed = hashlib.sha256(f"biscuits-proposer:{height}:{round_number}".encode()).digest()
    slot = int.from_bytes(seed, "big") % total
    for key, power in normalized.items():
        if slot < power:
            return key
        slot -= power
    raise AssertionError("weighted proposer selection failed")


def proposal_signing_bytes(
    chain_id: str, height: int, round_number: int, block_hash: str,
    validators_hash: str, valid_round: int | None = None,
    valid_round_certificate: Sequence[Mapping[str, object]] = (),
) -> bytes:
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise ValueError("chain_id must be non-empty")
    if not isinstance(height, int) or isinstance(height, bool) or height < 1:
        raise ValueError("height must be positive")
    if (not isinstance(round_number, int) or isinstance(round_number, bool)
            or round_number < 0 or round_number > MAX_ROUND):
        raise ValueError("round_number must be a 32-bit non-negative integer")
    if not _is_hex(block_hash, 32) or not _is_hex(validators_hash, 32):
        raise ValueError("block_hash and validators_hash must be 32-byte hex")
    if valid_round is not None and (
        not isinstance(valid_round, int) or isinstance(valid_round, bool)
        or valid_round < 0 or valid_round >= round_number
    ):
        raise ValueError("valid_round must be earlier than the proposal round")
    if not isinstance(valid_round_certificate, Sequence) or isinstance(valid_round_certificate, (str, bytes)):
        raise ValueError("valid_round_certificate must be a sequence")
    if (valid_round is None) != (len(valid_round_certificate) == 0):
        raise ValueError("valid-round metadata and certificate must be supplied together")
    return canonical_json({
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "block_hash": block_hash.lower(),
        "validator_set_hash": validators_hash.lower(),
        "valid_round": valid_round,
        "valid_round_certificate": list(valid_round_certificate),
        "message": "biscuits/bft/proposal/v2",
    })


def make_proposal(
    private_key: Ed25519PrivateKey,
    chain_id: str,
    height: int,
    round_number: int,
    block_hash: str,
    validators_hash: str,
    valid_round: int | None = None,
    valid_round_certificate: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    public_key = private_key.public_key().public_bytes_raw().hex()
    message = proposal_signing_bytes(
        chain_id, height, round_number, block_hash, validators_hash,
        valid_round, valid_round_certificate,
    )
    return {
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "block_hash": block_hash.lower(),
        "validator_set_hash": validators_hash.lower(),
        "valid_round": valid_round,
        "valid_round_certificate": list(valid_round_certificate),
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
            "validator_set_hash", "valid_round", "valid_round_certificate",
            "proposer", "signature",
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
        if (not isinstance(proposal["block_hash"], str)
                or proposal["block_hash"] != proposal["block_hash"].lower()):
            return False
        valid_round = proposal["valid_round"]
        certificate = proposal["valid_round_certificate"]
        if valid_round is None:
            if certificate != []:
                return False
        else:
            if (not isinstance(valid_round, int) or isinstance(valid_round, bool)
                    or valid_round < 0 or valid_round >= proposal["round"]
                    or not verify_prevote_certificate(
                        certificate, validators, expected_chain_id,
                        proposal["height"], valid_round, proposal["block_hash"],
                    )):
                return False
        if proposer != select_proposer(validators, proposal["height"], proposal["round"]):
            return False
        message = proposal_signing_bytes(
            expected_chain_id, proposal["height"], proposal["round"],
            proposal["block_hash"], expected_set_hash, valid_round, certificate,
        )
        if (not _is_hex(proposal["signature"], 64)
                or proposal["signature"] != proposal["signature"].lower()):
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
        if (not isinstance(vote["block_hash"], str)
                or vote["block_hash"] != vote["block_hash"].lower()):
            return False
        message = vote_signing_bytes(
            expected_chain_id, vote["height"], vote["round"], vote["step"],
            vote["block_hash"], vote["validator_set_hash"],
        )
        if (not _is_hex(vote["signature"], 64)
                or vote["signature"] != vote["signature"].lower()):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(vote["signature"]), message
        )
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False



def round_change_signing_bytes(chain_id: str, height: int, round_number: int,
                               validators_hash: str) -> bytes:
    """Canonical signed request to enter a later consensus round.

    This message is only a timeout/round-change signal. It carries no authority
    to discard a lock or to vote for a different block.
    """
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise ValueError("chain_id must be non-empty")
    if not isinstance(height, int) or isinstance(height, bool) or height < 1:
        raise ValueError("height must be positive")
    if (not isinstance(round_number, int) or isinstance(round_number, bool)
            or round_number < 1 or round_number > MAX_ROUND):
        raise ValueError("round_number must be a positive 32-bit integer")
    if not _is_hex(validators_hash, 32):
        raise ValueError("validators_hash must be 32-byte hex")
    return canonical_json({
        "message": "biscuits/bft/round-change/v1",
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "validator_set_hash": validators_hash.lower(),
    })


def make_round_change(private_key: Ed25519PrivateKey, chain_id: str,
                      height: int, round_number: int,
                      validators_hash: str) -> dict[str, object]:
    """Create an authenticated request to move to round_number."""
    public_key = private_key.public_key().public_bytes_raw().hex()
    message = round_change_signing_bytes(
        chain_id, height, round_number, validators_hash
    )
    return {
        "chain_id": chain_id,
        "height": height,
        "round": round_number,
        "validator_set_hash": validators_hash.lower(),
        "validator": public_key,
        "signature": private_key.sign(message).hex(),
    }


def verify_round_change(message: Mapping[str, object],
                        validators: Sequence[Mapping[str, object]],
                        expected_chain_id: str) -> bool:
    """Verify a round-change signal; it does not itself advance local state."""
    try:
        if set(message) != {
            "chain_id", "height", "round", "validator_set_hash",
            "validator", "signature",
        }:
            return False
        normalized = normalize_validator_set(validators)
        key = message["validator"]
        if key not in normalized or message["chain_id"] != expected_chain_id:
            return False
        expected_hash = validator_set_hash(validators)
        if message["validator_set_hash"] != expected_hash:
            return False
        if (not _is_hex(key, 32) or not _is_hex(message["signature"], 64)
                or message["signature"] != message["signature"].lower()):
            return False
        payload = round_change_signing_bytes(
            expected_chain_id, message["height"], message["round"], expected_hash
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(message["signature"]), payload
        )
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False


def verify_round_change_certificate(messages: Sequence[Mapping[str, object]],
                                    validators: Sequence[Mapping[str, object]],
                                    expected_chain_id: str, height: int,
                                    round_number: int) -> bool:
    """Require unique authenticated signals with strictly >2/3 voting power."""
    try:
        if (not isinstance(height, int) or isinstance(height, bool) or height < 1
                or not isinstance(round_number, int) or isinstance(round_number, bool)
                or round_number < 1 or round_number > MAX_ROUND
                or not isinstance(messages, Sequence)
                or isinstance(messages, (str, bytes))):
            return False
        normalized = normalize_validator_set(validators)
        seen = set()
        power = 0
        for message in messages:
            if (not verify_round_change(message, validators, expected_chain_id)
                    or message["height"] != height
                    or message["round"] != round_number):
                return False
            key = message["validator"]
            if key in seen:
                return False
            seen.add(key)
            power += normalized[key]
        return power * 3 > sum(normalized.values()) * 2
    except (ValueError, TypeError, KeyError):
        return False



def verify_prevote_certificate(
    votes: Sequence[Mapping[str, object]],
    validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
    height: int,
    round_number: int,
    block_hash: str,
) -> bool:
    """Verify a unique >2/3 prevote certificate for one block and round.

    This proves that a supermajority prevoted the block; it does not by itself
    authorize a signer to discard a lock. Unlock policy must additionally
    compare this valid round with the signer's persisted locked round.
    """
    try:
        if (not isinstance(height, int) or isinstance(height, bool) or height < 1
                or not isinstance(round_number, int) or isinstance(round_number, bool)
                or round_number < 0 or round_number > MAX_ROUND
                or not _is_hex(block_hash, 32)):
            return False
        if not isinstance(votes, Sequence) or isinstance(votes, (str, bytes)):
            return False
        normalized = normalize_validator_set(validators)
        expected_set_hash = validator_set_hash(validators)
        seen: set[str] = set()
        signed_power = 0
        for vote in votes:
            if not verify_vote(vote, validators, expected_chain_id):
                return False
            if (
                vote["height"] != height or vote["round"] != round_number
                or vote["step"] != "prevote"
                or vote["block_hash"] != block_hash.lower()
                or vote["validator_set_hash"] != expected_set_hash
            ):
                return False
            key = vote["validator"]
            if key in seen:
                return False
            seen.add(key)
            signed_power += normalized[key]
        return signed_power * 3 > sum(normalized.values()) * 2
    except (ValueError, TypeError, KeyError):
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
        if (not isinstance(height, int) or isinstance(height, bool) or height < 1
                or not isinstance(round_number, int) or isinstance(round_number, bool)
                or round_number < 0 or round_number > MAX_ROUND
                or not _is_hex(block_hash, 32)):
            return False
        if not isinstance(votes, Sequence) or isinstance(votes, (str, bytes)):
            return False
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
