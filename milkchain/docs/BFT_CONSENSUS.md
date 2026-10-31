# Biscuits BFT consensus design (development branch)

## Protocol implemented in this branch

- Ed25519-signed proposals and prevote/precommit messages are domain-separated and bound to the chain ID, height, round, block hash, and validator-set hash.
- The proposer is selected deterministically from the active validator set. The development configuration sets the block reward to zero, so it does not mint new Biscuits. This is a configuration choice, not an assumed supply cap or issuance schedule; monetary issuance rules remain unspecified. Configured transaction fees remain payable to the selected proposer. Block rewards and transaction fees are payable only to that height/round's selected proposer; proposal validation binds the coinbase recipient to the signed proposer, and finalized-chain validation independently checks the deterministic proposer.
- Consensus round counters are unsigned 32-bit values (0 through 4,294,967,295); signed proposals, votes, round-change messages, certificates, and persisted signer state reject values outside that range.
- A commit certificate requires unique, valid precommit signatures representing strictly more than two-thirds of voting power.
- A prevote-certificate verifier checks unique, valid prevotes for one exact height, round, block hash, and validator set, with strictly more than two-thirds of voting power. The signer uses this shared verifier before persisting a lock.
- When a block commits through valid-round recovery, the finalized block stores the valid-round number and certificate. Chain validation rechecks that proof, and an offline signer may use it to catch up past a conflicting older lock (but still refuses a conflicting local precommit).
- Validator signing intents and locks are written to disk before signed messages are returned. A per-state-file OS process lock prevents two validator processes from using the same signer state simultaneously; existing state files must be regular files with mode 0600 and cannot be symlinks.
- The event-driven coordinator validates proposed blocks through a caller-supplied block validator, gathers votes, and finalizes only after a valid commit certificate.
- The HTTP transport relays signed proposals and votes, caps request bodies at 1 MB, limits concurrent handlers, and rate-limits each source address. Non-loopback peers must use HTTPS.
- Admission certificates require signatures from strictly more than two-thirds of a configured issuer federation. Admitted validators receive equal voting power; no stake or token balance is used.

## Safety limits that are deliberate

The signer retains its lock when advancing on a >2/3 round-change certificate. A proposal for a different block must carry a signed, unique >2/3 prevote certificate for that exact block at a valid round strictly newer than the persisted lock and earlier than the proposal round. The proposal signature binds the valid-round metadata and certificate. The signer verifies and persists this authorization before signing a conflicting prevote, revalidates it after restart, and changes its lock only after a new-round >2/3 prevote certificate. Do not deploy this prototype as a production consensus network.

The implemented locked-round/valid-round transitions still need formal specification, adversarial testing, and independent protocol review before production use. Signed round-change messages, >2/3 round-change certificates, network relay, and inactivity-triggered timeout requests with bounded backoff are implemented. Validator-set changes at committed heights, durable anti-rollback protection for signer state, authenticated operational peer management, and multi-process/multi-host fault tests also remain outstanding.

## Stake-free admission and its trust assumption

A public network cannot be both permissionless and Sybil-resistant merely by removing mining and stake. This implementation therefore makes the admission trust assumption explicit: at least four independent credential issuers verify eligibility off-chain and sign a validator public key. At least four admitted validators are required, each with exactly one unit of voting power. Issuer keys and validator keys must be distinct. A four-validator set can tolerate one faulty validator while retaining a greater-than-two-thirds quorum. The chain stores no civil identity, only the key and issuer signatures. Issuers must enforce one active credential per eligible participant and coordinate revocation. The issuer federation and its governance must be chosen independently; code cannot prove that issuers are independent or prevent coercion, key sale, or issuer collusion.

The admission module is a mechanism, not a preselected list of real-world issuers. Before mainnet, publish issuer selection criteria, independence requirements, renewal and appeal procedures, revocation rules, privacy safeguards, and a public audit process.

## Node integration and remaining production blockers

The original node.py entry point remains proof-of-work for backward compatibility. The separate bft_node.py entry point uses BFTChain for certificate-validated block acceptance, persistent account state, transaction/mempool rules, peer synchronization, and a /propose API. BFTChain refuses proof-of-work mining and rejects blocks without a valid commit certificate. The test suite includes a four-node local network finality test and tests for conflicting longer forks.

This is an integrated development prototype, not a production-ready consensus protocol. Certificate-gated valid-round recovery now permits a locked validator to advance rounds without discarding its lock and to change its prevote only after validating a newer-round prevote certificate. This path still requires adversarial protocol review and expanded network-level fault testing. A stalled proposer or incomplete commit can still stall the chain. Validator-set changes and revocation activation at committed heights are not implemented; the active issuer and validator sets are fixed by node configuration. Signer state is protected against accidental disclosure, concurrent-process races, accidental modification, and ordinary double-signing, but local disk rollback cannot be cryptographically prevented without a trusted monotonic store or equivalent operational control. Offline validators catch up from a valid committed chain; an embedded valid-round certificate may supersede an older lock, while a conflicting local precommit remains a hard stop.

The four-node test is a deterministic integration test, not a substitute for formal protocol review, independent security audit, network-partition testing, Byzantine fault injection, load testing, or a production incident/recovery exercise. Do not deploy with real funds or describe the system as production-secure until those workstreams and the issuer federation's governance decisions are complete.


## Running a development validator

1. Generate a key file with owner-only permissions:

   `PYTHONPATH=milkchain python -m keygen --output validator.key`

2. Each issuer independently signs the validator key. Put the federation's public keys in a JSON array file and run the issuer tool once per issuer:

   `PYTHONPATH=milkchain python -m admission_signer --issuer-key issuer.key --issuer-set issuers.json --chain-id milkchain-biscuits-devnet-1 --validator-public-key PUBLIC_KEY --issued-epoch 1 --expires-epoch 100`

   Collect more than two-thirds of the issuer signatures into that validator's admission certificate. Do not share issuer private keys or let the node operator make eligibility decisions for issuers.

3. Configure issuer public keys, certificate signatures, and the current admission epoch in a copy of config.bft.example.json. The example intentionally contains placeholders and is not a runnable network configuration. Use a unique BFT chain_id that is never reused by a proof-of-work network or another deployment; transaction signatures are scoped to chain_id.

4. For a remote consensus listener, configure a TLS certificate and key, bind consensus_host to the public interface, and use HTTPS URLs in both peers and consensus_peers. A non-loopback listener without TLS is rejected. The node API is loopback-only; expose it externally only through an authenticated TLS reverse proxy. Keep validator.key and the signer state file backed up securely; never commit either file. The signer state must be a regular owner-only file (0600 on POSIX), symlinks are rejected, and an exclusive process lock prevents two node processes from signing with the same state. The node releases that lock on shutdown.

5. Start the BFT node:

   `PYTHONPATH=milkchain python milkchain/bft_node.py --config config.bft.json`

6. The selected proposer can request a proposal through the local node API using POST /propose with an empty JSON object. If the proposer is locked on a different block, include the exact candidate `block`, `valid_round`, and `valid_round_certificate` in the JSON request; the certificate must prove more than two-thirds prevoting power for that block at a round newer than the lock and earlier than the current round. Validators automatically prevote only after local block validation and signer authorization. Finality requires more than two-thirds of the admitted voting power.

This run mode is a development prototype. Signed round-change certificates, automatic timeout requests, and certificate-gated locked-round recovery are implemented. Automatic validator-set transition and revocation activation are not implemented. The node writes the finalized block before advancing signer height; offline signers can catch up by verifying committed certificates. Disk rollback protection still requires trusted monotonic storage or equivalent operational controls. Do not use real funds or deploy a public mainnet with this version.


## Round-change transport

Validators can issue Ed25519-signed round-change messages. Each message binds the chain, height, validator-set hash, and target round. The signer persists each message before returning it. The HTTP transport relays these messages at `/consensus/round-change`; a validator advances only after verifying unique messages representing strictly more than two-thirds of voting power. A locked validator retains its lock while advancing. A conflicting proposal requires a signed valid-round prevote certificate newer than the persisted lock; the signer persists that authorization before changing its prevote. Automatic inactivity-triggered round-change requests use bounded exponential backoff and preserve signer anti-equivocation rules. Timeout configuration rejects non-finite, non-positive, inverted, and non-representable values before starting the timer loop. Formal review and adversarial validation of valid-round recovery, validator-set changes, and production deployment hardening remain outstanding.
