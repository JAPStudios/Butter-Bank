"""Federated, stake-free validator admission certificates.

A threshold of independent credential issuers attests that a validator key
belongs to one eligible participant. No token balance or monetary stake is
used as voting power. Issuers must enforce one active credential per person
off-chain; the chain sees only validator keys and issuer signatures.
"""
import hashlib
from collections.abc import Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from consensus import canonical_json, _is_hex


def normalize_issuers(issuers):
    if not isinstance(issuers, Sequence) or isinstance(issuers, (str, bytes)) or not issuers:
        raise ValueError("issuers must be a non-empty sequence")
    keys = []
    for item in issuers:
        key = item.get("public_key") if isinstance(item, Mapping) else item
        if not _is_hex(key, 32):
            raise ValueError("issuer keys must be 32-byte hex")
        if key in keys:
            raise ValueError("duplicate issuer key")
        keys.append(key)
    return sorted(keys)


def issuer_set_hash(issuers):
    return hashlib.sha256(canonical_json(normalize_issuers(issuers))).hexdigest()


def admission_signing_bytes(chain_id, validator_key, issued_epoch, expires_epoch, issuers_hash):
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise ValueError("chain_id must be non-empty")
    if not _is_hex(validator_key, 32) or not _is_hex(issuers_hash, 32):
        raise ValueError("validator and issuer set keys must be 32-byte hex")
    if (not isinstance(issued_epoch, int) or isinstance(issued_epoch, bool)
            or not isinstance(expires_epoch, int) or isinstance(expires_epoch, bool)
            or issued_epoch < 0 or expires_epoch <= issued_epoch):
        raise ValueError("invalid admission certificate epoch range")
    return canonical_json({
        "message": "biscuits/validator-admission/v1",
        "chain_id": chain_id,
        "validator_public_key": validator_key.lower(),
        "issued_epoch": issued_epoch,
        "expires_epoch": expires_epoch,
        "issuer_set_hash": issuers_hash.lower(),
    })


def sign_admission(private_key, chain_id, validator_key, issued_epoch, expires_epoch, issuers_hash):
    signature = private_key.sign(admission_signing_bytes(
        chain_id, validator_key, issued_epoch, expires_epoch, issuers_hash
    )).hex()
    return {"issuer": private_key.public_key().public_bytes_raw().hex(), "signature": signature}


def verify_admission_certificate(certificate, issuers, chain_id, current_epoch):
    try:
        if not isinstance(certificate, Mapping) or set(certificate) != {
            "chain_id", "validator_public_key", "issued_epoch", "expires_epoch",
            "issuer_set_hash", "signatures",
        }:
            return False
        normalized = normalize_issuers(issuers)
        if certificate["chain_id"] != chain_id:
            return False
        if certificate["issuer_set_hash"] != issuer_set_hash(issuers):
            return False
        issued, expires = certificate["issued_epoch"], certificate["expires_epoch"]
        if (not isinstance(current_epoch, int) or isinstance(current_epoch, bool)
                or not isinstance(issued, int) or isinstance(issued, bool)
                or not isinstance(expires, int) or isinstance(expires, bool)
                or not issued <= current_epoch <= expires):
            return False
        message = admission_signing_bytes(
            chain_id, certificate["validator_public_key"], issued, expires,
            certificate["issuer_set_hash"],
        )
        if not isinstance(certificate["signatures"], list):
            return False
        seen = set()
        for item in certificate["signatures"]:
            if not isinstance(item, Mapping) or set(item) != {"issuer", "signature"}:
                return False
            issuer, signature = item["issuer"], item["signature"]
            if issuer not in normalized or issuer in seen or not _is_hex(signature, 64):
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer)).verify(
                bytes.fromhex(signature), message
            )
            seen.add(issuer)
        # Require strictly more than two-thirds of the independent issuers.
        return len(seen) * 3 > len(normalized) * 2
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return False


def validator_set_from_certificates(certificates, issuers, chain_id, current_epoch):
    """Build an equal-voting-power validator set from valid admission certificates."""
    if not isinstance(certificates, Sequence) or isinstance(certificates, (str, bytes)):
        raise ValueError("certificates must be a sequence")
    result = []
    seen = set()
    for certificate in certificates:
        if not verify_admission_certificate(certificate, issuers, chain_id, current_epoch):
            raise ValueError("invalid or expired validator admission certificate")
        key = certificate["validator_public_key"]
        if key in seen:
            raise ValueError("duplicate admitted validator")
        seen.add(key)
        result.append({"public_key": key, "voting_power": 1})
    if not result:
        raise ValueError("validator set cannot be empty")
    return sorted(result, key=lambda item: item["public_key"])
