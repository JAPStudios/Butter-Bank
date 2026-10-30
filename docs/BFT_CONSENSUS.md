# Biscuits BFT consensus design (development branch)

## Protocol implemented in this branch

- Ed25519-signed proposals and prevote/precommit messages are domain-separated and bound to the chain ID, height, round, block hash, and validator-set hash.
- The proposer is selected deterministically from the active validator set.
- A commit certificate requires unique, valid precommit signatures representing strictly more than two-thirds of voting power.
- Validator signing intents and locks are written to disk before signed messages are returned.
- The event-driven coordinator validates proposed blocks through a caller-supplied block validator, gathers votes, and finalizes only after a valid commit certificate.
- The HTTP transport relays signed proposals and votes. Non-loopback peers must use HTTPS.
- Admission certificates require signatures from strictly more than two-thirds of a configured issuer federation. Admitted validators receive equal voting power; no stake or token balance is used.

## Safety limits that are deliberate

The current signer uses conservative locking: it will not unlock or switch to another block during a height. The coordinator halts round advancement after a lock. This is a fail-closed safety measure, not a complete liveness protocol. It can stall if a quorum locks a block but cannot finish committing it. Do not deploy this prototype as a production consensus network.

A complete production protocol still needs formally specified and adversarially tested locked-round/valid-round transitions, timeout handling, validator-set changes at committed heights, durable anti-rollback protection for signer state, authenticated operational peer management, and multi-process/multi-host fault tests.

## Stake-free admission and its trust assumption

A public network cannot be both permissionless and Sybil-resistant merely by removing mining and stake. This implementation therefore makes the admission trust assumption explicit: at least four independent credential issuers verify eligibility off-chain and sign a validator public key. At least four admitted validators are required, each with exactly one unit of voting power. A four-validator set can tolerate one faulty validator while retaining a greater-than-two-thirds quorum. The chain stores no civil identity, only the key and issuer signatures. Issuers must enforce one active credential per eligible participant and coordinate revocation. The issuer federation and its governance must be chosen independently; code cannot prove that issuers are independent or prevent coercion, key sale, or issuer collusion.

The admission module is a mechanism, not a preselected list of real-world issuers. Before mainnet, publish issuer selection criteria, independence requirements, renewal and appeal procedures, revocation rules, privacy safeguards, and a public audit process.

## Node integration and remaining production blockers

The original node.py entry point remains proof-of-work for backward compatibility. The separate bft_node.py entry point uses BFTChain for certificate-validated block acceptance, persistent account state, transaction/mempool rules, peer synchronization, and a /propose API. BFTChain refuses proof-of-work mining and rejects blocks without a valid commit certificate. The test suite includes a four-node local network finality test and tests for conflicting longer forks.

This is an integrated development prototype, not a production-ready consensus protocol. The coordinator deliberately refuses round advancement after a lock because safe Tendermint-style valid-round/unlock rules have not yet been implemented. It has no distributed round-change/timeout protocol, so a stalled proposer or incomplete commit can stall the chain. Validator-set changes and revocation activation at committed heights are not implemented; the active issuer and validator sets are fixed by node configuration. Signer state is protected against accidental modification and ordinary double-signing, but local disk rollback cannot be cryptographically prevented without a trusted monotonic store or equivalent operational control. Offline validators can catch up only from a valid committed chain and will refuse catch-up if their local lock or precommit conflicts.

The four-node test is a deterministic integration test, not a substitute for formal protocol review, independent security audit, network-partition testing, Byzantine fault injection, load testing, or a production incident/recovery exercise. Do not deploy with real funds or describe the system as production-secure until those workstreams and the issuer federation's governance decisions are complete.


## Running a development validator

1. Generate a key file with owner-only permissions:

   `PYTHONPATH=emberchain python -m keygen --output validator.key`

2. Have the configured issuer federation sign an admission certificate for the printed public key. Configure the issuer public keys, certificate signatures, and current admission epoch in a copy of config.bft.example.json. The example intentionally contains placeholders and is not a runnable network configuration.

3. For a remote consensus listener, configure a TLS certificate and key, bind consensus_host to the public interface, and use HTTPS URLs in consensus_peers. A non-loopback listener without TLS is rejected. Keep validator.key and the signer state file backed up securely; never commit either file.

4. Start the BFT node:

   `PYTHONPATH=emberchain python emberchain/bft_node.py --config config.bft.json`

5. The selected proposer can request a proposal through the local node API using POST /propose with an empty JSON object. Validators automatically prevote only after local block validation. Finality requires more than two-thirds of the admitted voting power.

This run mode is a development prototype. It currently has no safe unlock/round-timeout protocol, no automatic validator-set transition or revocation activation, and no automatic recovery from a crash between signer finalization and chain-file persistence. A signer-height mismatch causes startup to fail closed. Do not use real funds or deploy a public mainnet with this version.
