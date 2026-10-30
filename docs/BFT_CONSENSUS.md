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

A public network cannot be both permissionless and Sybil-resistant merely by removing mining and stake. This implementation therefore makes the admission trust assumption explicit: independent credential issuers verify eligibility off-chain and sign a validator public key. The chain stores no civil identity, only the key and issuer signatures. Issuers must enforce one active credential per eligible participant and coordinate revocation. The issuer federation and its governance must be chosen independently; code cannot prove that issuers are independent or prevent coercion, key sale, or issuer collusion.

The admission module is a mechanism, not a preselected list of real-world issuers. Before mainnet, publish issuer selection criteria, independence requirements, renewal and appeal procedures, revocation rules, privacy safeguards, and a public audit process.

## Not yet integrated with the existing node

The existing node.py chain remains proof-of-work. The BFT modules in this branch are separate components and do not yet replace proof-of-work block acceptance, persistence, peer synchronization, or transaction finalization. Do not advertise the current repository as a running BFT network until that integration and its end-to-end tests are complete.
