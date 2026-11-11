# Butter Bank

Butter Bank is a financial institution owned by HeLLP.

This repository contains software for Milkchain, the blockchain for Biscuits. It includes account transaction rules, stake-free Byzantine fault-tolerant consensus, validator admission, validator-set transitions, transaction signing, encrypted Biscuits key storage, and node communication.

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

The current code is not ready to secure live customer funds. Remaining work includes cryptographic protection against signer-state rollback, expanded network-partition and recovery testing, formal protocol review, an independent security audit, plus production operational controls.

Signer state is written atomically and protected against concurrent local processes. Those protections do not prevent an operator or attacker from restoring an older copy of both the chain data and signer state. Do not treat local disk protections as a cryptographic rollback anchor.

The committed example configuration contains placeholders. It is not a live validator configuration. Never commit private keys, admission credentials, completed node configuration, or signer state.
