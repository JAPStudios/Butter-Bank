"""Quorum-authorized, height-activated Milkchain validator-set transitions.

A transition is authorized by the currently active validator set. Its certificate
is committed as data by the caller; activation is at the declared block height.
This module verifies transition authorization and ordered transition histories.
It does not itself mutate a running consensus engine or chain state.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from consensus import canonical_json, normalize_validator_set, validator_set_hash, _is_hex

TRANSITION_MESSAGE = "biscuits/validator-set-transition/v1"


def transition_signing_bytes(
    chain_id: str,
    activation_height: int,
    previous_set_hash: str,
    next_validators: Sequence[Mapping[str, object]],
) -> bytes:
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise ValueError("chain_id must be non-empty")
    if (not isinstance(activation_height, int) or isinstance(activation_height, bool)
            or activation_height < 2):
        raise ValueError("activation_height must be an integer of at least 2")
    if not _is_hex(previous_set_hash, 32):
        raise ValueError("previous_set_hash must be 32-byte hex")
    normalized = normalize_validator_set(next_validators)
    if len(normalized) < 4:
        raise ValueError("next validator set must contain at least four validators")
    entries = [
        {"public_key": key, "voting_power": power}
        for key, power in normalized.items()
    ]
    return canonical_json({
        "message": TRANSITION_MESSAGE,
        "chain_id": chain_id,
        "activation_height": activation_height,
        "previous_set_hash": previous_set_hash.lower(),
        "next_validators": entries,
        "next_set_hash": validator_set_hash(entries),
    })


def make_transition_signature(
    private_key: Ed25519PrivateKey,
    chain_id: str,
    activation_height: int,
    previous_set_hash: str,
    next_validators: Sequence[Mapping[str, object]],
) -> dict[str, str]:
    public_key = private_key.public_key().public_bytes_raw().hex()
    payload = transition_signing_bytes(
        chain_id, activation_height, previous_set_hash, next_validators
    )
    return {"validator": public_key, "signature": private_key.sign(payload).hex()}


def make_transition_certificate(
    private_keys: Sequence[Ed25519PrivateKey],
    chain_id: str,
    activation_height: int,
    previous_validators: Sequence[Mapping[str, object]],
    next_validators: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    previous_hash = validator_set_hash(previous_validators)
    signatures = [
        make_transition_signature(
            key, chain_id, activation_height, previous_hash, next_validators
        )
        for key in private_keys
    ]
    return {
        "chain_id": chain_id,
        "activation_height": activation_height,
        "previous_set_hash": previous_hash,
        "next_validators": [
            {"public_key": key, "voting_power": power}
            for key, power in normalize_validator_set(next_validators).items()
        ],
        "next_set_hash": validator_set_hash(next_validators),
        "signatures": signatures,
    }


def verify_transition_certificate(
    certificate: Mapping[str, object],
    current_validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
) -> bool:
    try:
        if not isinstance(certificate, Mapping) or set(certificate) != {
            "chain_id", "activation_height", "previous_set_hash",
            "next_validators", "next_set_hash", "signatures",
        }:
            return False
        if certificate["chain_id"] != expected_chain_id:
            return False
        current = normalize_validator_set(current_validators)
        next_set = normalize_validator_set(certificate["next_validators"])
        if len(next_set) < 4:
            return False
        if certificate["previous_set_hash"] != validator_set_hash(current_validators):
            return False
        if certificate["next_set_hash"] != validator_set_hash(certificate["next_validators"]):
            return False
        payload = transition_signing_bytes(
            expected_chain_id,
            certificate["activation_height"],
            certificate["previous_set_hash"],
            certificate["next_validators"],
        )
        signatures = certificate["signatures"]
        if not isinstance(signatures, list):
            return False
        seen = set()
        signed_power = 0
        total_power = sum(current.values())
        for item in signatures:
            if not isinstance(item, Mapping) or set(item) != {"validator", "signature"}:
                return False
            validator = item["validator"]
            signature = item["signature"]
            if (not isinstance(validator, str) or validator != validator.lower()
                    or validator not in current or validator in seen
                    or not _is_hex(signature, 64) or signature != signature.lower()):
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(validator)).verify(
                bytes.fromhex(signature), payload
            )
            seen.add(validator)
            signed_power += current[validator]
        return signed_power * 3 > total_power * 2
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False


def verify_transition_history(
    transitions: Sequence[Mapping[str, object]],
    initial_validators: Sequence[Mapping[str, object]],
    expected_chain_id: str,
) -> bool:
    """Verify a gap-free, strictly ordered succession of quorum-approved sets."""
    try:
        if not isinstance(transitions, Sequence) or isinstance(transitions, (str, bytes)):
            return False
        active = [
            {"public_key": key, "voting_power": power}
            for key, power in normalize_validator_set(initial_validators).items()
        ]
        previous_activation = 1
        for certificate in transitions:
            if not verify_transition_certificate(certificate, active, expected_chain_id):
                return False
            activation = certificate["activation_height"]
            if (not isinstance(activation, int) or isinstance(activation, bool)
                    or activation <= previous_activation):
                return False
            active = certificate["next_validators"]
            previous_activation = activation
        return True
    except (ValueError, TypeError, KeyError):
        return False
