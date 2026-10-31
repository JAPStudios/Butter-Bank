"""Create one issuer signature for a stake-free validator admission certificate."""
import argparse
import json
from pathlib import Path

from admission import normalize_issuers, issuer_set_hash, sign_admission
from bft_node import load_validator_key


def create_issuer_signature(key_file, issuer_keys, chain_id, validator_key,
                            issued_epoch, expires_epoch):
    private_key = load_validator_key(key_file)
    issuers = normalize_issuers(issuer_keys)
    issuer_public = private_key.public_key().public_bytes_raw().hex()
    if issuer_public not in issuers:
        raise ValueError("issuer private key is not in the configured issuer federation")
    return sign_admission(
        private_key, chain_id, validator_key, issued_epoch, expires_epoch,
        issuer_set_hash(issuers)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer-key", required=True)
    parser.add_argument("--issuer-set", required=True,
                        help="JSON file containing the federation's public keys")
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--validator-public-key", required=True)
    parser.add_argument("--issued-epoch", type=int, required=True)
    parser.add_argument("--expires-epoch", type=int, required=True)
    args = parser.parse_args()
    issuer_keys = json.loads(Path(args.issuer_set).read_text(encoding="utf-8"))
    signature = create_issuer_signature(
        args.issuer_key, issuer_keys, args.chain_id,
        args.validator_public_key, args.issued_epoch, args.expires_epoch
    )
    print(json.dumps(signature, sort_keys=True))


if __name__ == "__main__":
    main()
