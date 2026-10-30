# Milkchain (Rust)

This crate is the Rust implementation of Milkchain's deterministic account ledger and weighted Byzantine commit-certificate verifier.

## Implemented

- Ed25519-signed account transfers, chain binding, nonce checks, and integer-only balances.
- Deterministic SHA-256 block hashes over canonical serialized block headers.
- Validator voting power and separately verified prevote and precommit certificates.
- Commit threshold of at least two-thirds of configured validator voting power.
- Rejection of duplicate/unknown validators, invalid signatures, replayed votes, wrong-chain proposals, invalid transactions, and broken block links.
- Full ledger replay validation and atomic durable local persistence.

## Build and test

From this directory:

```sh
cargo test
```

## Protocol scope

This crate currently implements the ledger state machine and commit-certificate verification. It is not yet a complete Tendermint networking implementation: peer transport and authenticated handshakes, proposer selection, round-change/time-out protocol, mempool and gossip, dynamic validator-set updates, genesis distribution tooling, RPC, and production key custody still need implementation and adversarial integration tests. It must not be used to custody or transfer real value until those components and an independent security audit are complete.
