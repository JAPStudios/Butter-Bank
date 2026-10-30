# Emberchain: from-scratch cryptocurrency prototype

A small native-token blockchain implementation with Ed25519-signed account transactions, integer base units, nonces, fees, SHA-256 proof of work, block rewards, persistent JSON state, and basic HTTP peer propagation.

**Not production-ready. Do not use real funds.** This code is unaudited and deliberately minimal. It lacks robust fork choice/reorganizations, peer discovery, Sybil resistance, rate limiting, TLS/authentication, hardened key storage, a mature mempool, and adversarial testing. Its longest-chain rule is a demo, not production consensus. Low proof-of-work difficulty is not secure.

## Install

Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

## Create keys

```sh
python wallet.py create miner-wallet.json
python wallet.py create alice-wallet.json
python wallet.py create bob-wallet.json
```

Wallet JSON contains an unencrypted private key. Keep it secret; do not commit it to source control. A previously tracked `miner-wallet.json` was removed from the repository, but deleting it does not invalidate the exposed key: treat that key as compromised and never use it for funds. Rotate any allocation or account that depended on it.

## Configure genesis

Copy `config.example.json` to `config.json`. Add initial allocations using 64-character public-key hex addresses:

```json
"genesis_allocations": {
  "PASTE_PUBLIC_KEY_HEX_HERE": 1000000000000
}
```

All nodes must use exactly the same `chain_id`, `difficulty`, `block_reward`, and genesis allocation map. Configure genesis before launching nodes; changing it creates a different network. One EMBER is 100,000,000 base units. Amounts are integers, not floats.

## Run node and mine

```sh
python node.py --config config.json
curl http://127.0.0.1:8333/status
curl http://127.0.0.1:8333/balances
curl -X POST http://127.0.0.1:8333/mine -H 'Content-Type: application/json' -d '{"miner":"YOUR_MINER_PUBLIC_KEY_HEX"}'
```

Default bind is localhost. Keep it there for local testing. Do not expose this prototype to the public internet.

## Send funds

Get the sender nonce from `/balances`; the first transaction uses nonce 1:

```sh
python tx.py --wallet alice-wallet.json --chain-id emberchain-devnet-1 --to BOBS_PUBLIC_KEY_HEX --amount 250000000 --fee 1000 --nonce 1
```

That transfers 2.5 EMBER with a 0.00001 EMBER fee. Sender needs amount plus fee.

## Run a second local node

Copy config to `config2.json`, keep chain settings/genesis identical, set port to 8334 and optionally `peers` to `["http://127.0.0.1:8333"]`. Start with a separate data file:

```sh
python node.py --config config2.json --data node2.json
curl -X POST http://127.0.0.1:8334/connect -H 'Content-Type: application/json' -d '{"peer":"http://127.0.0.1:8333"}'
```

## API

- `GET /status`, `/chain`, `/balances`, `/mempool`, `/peers`
- `POST /tx` signed transaction; `POST /mine` with `{"miner":"<public-key-hex>"}`
- Peer endpoints: `POST /connect`, `/receive-tx`, `/receive-block`

Before any public launch, get an independent security review, specify consensus and economics, implement reliable chain reorganization and synchronization, add adversarial/multi-node tests, rate limiting and network protections, and design a secure key-management/release process.
