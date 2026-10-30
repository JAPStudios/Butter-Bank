# Milkchain BFT core

Milkchain is implemented in the `milkchain/` package. The initial core is an account-based, Ed25519-signed ledger with weighted validator voting and durable block storage.

## Commit rule

Each block is identified by its chain ID, height, round, previous block hash, timestamp, and ordered transactions. Validators sign votes that bind all of the following: chain ID, height, round, vote step, and block hash. A block is committed only when both its prevote certificate and precommit certificate contain at least two thirds of configured validator voting power. Duplicate votes, unknown validators, altered signatures, votes for another block, and insufficient voting power are rejected.

## Run tests

From the repository root:

```sh
python -m pip install -r emberchain/requirements.txt
python -m unittest discover -s tests -v
```

## Current scope

The package provides the consensus certificate verifier, deterministic proposal hashing, signed transfers, state execution, chain validation, and atomic local persistence. It does not yet provide a peer-to-peer transport, proposer scheduling, round-change/time-out protocol, dynamic validator-set changes, validator slashing, fee or issuance policy, RPC service, or production key management. The existing `emberchain/` proof-of-work prototype remains separate and unchanged. This is a blockchain core implementation, not a production-ready public network.
