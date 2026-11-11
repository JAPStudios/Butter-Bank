# Butter Bank

Butter Bank is a bank.

This repository contains the Milkchain blockchain for Biscuits and the financial-ledger foundation. Milkchain provides stake-free Byzantine fault-tolerant consensus, validator admission, validator-set transitions, transaction signing, encrypted Biscuits key storage, plus node communication. The financial ledger provides exact multi-currency double-entry accounting, owner-scoped account listing and statements, atomic internal transfers, an authenticated application-service boundary, and a loopback-first HTTP API.

## Financial ledger

The SQLite-backed journal stores amounts as integer minor units, balances each transaction within one currency, prevents overdrafts by default, supports idempotent posting, and persists journal history. USD is registered with two decimal places; JPY is registered with zero. Other currencies and assets require an explicit precision registration.

Account listing is scoped to the owner reference associated with the JaMail account used for the request. Internal transfers require the source account to belong to that same account owner. The owner reference must come from trusted credential validation, never directly from an untrusted request body.

See [FINANCIAL_LEDGER.md](FINANCIAL_LEDGER.md) for the module interface and examples.

## Milkchain

Milkchain uses signed consensus messages with a quorum of more than two-thirds of validator voting power to finalize blocks. Validator admission uses a threshold of credential issuers. Validator-set changes are authorized by the active validator set, recorded in finalized blocks, then activated at their declared heights.

The development configuration disables block rewards. Monetary issuance rules, including any supply limit or issuance schedule, have not been specified. Do not infer them from the current configuration.

## Tests

Python 3.10 or newer is required.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r milkchain/requirements.txt
PYTHONPATH=milkchain python -m unittest discover -s tests -v
```

## Security status

The current code is not ready to secure live customer funds. Remaining work includes a trusted cryptographic anti-rollback anchor for validator signer state, expanded network-partition and recovery testing, formal protocol review, an independent security audit, plus production operational controls.

Signer state is written atomically and protected against concurrent local processes. Those protections do not prevent an operator or attacker from restoring an older copy of both the chain data and signer state. Do not treat local disk protections as a cryptographic rollback anchor.

The financial ledger is an accounting component, not a deposit-taking or payment-settlement system. It does not authenticate customers, custody external funds, connect to payment rails, or establish deposit insurance. POSIX database files are restricted to owner read/write permissions. The committed example Milkchain configuration contains placeholders; it is not a live validator configuration. Never commit private keys, admission credentials, completed node configuration, or signer state.
