# Butter Bank

Butter Bank is a public financial service owned by HeLLP. This repository contains software development components for that service.

Butter Bank is a development repository with three distinct components:

- **Funding website:** the static public project page in `index.html`, mirrored as `funding.html`.
- **Android prototype:** the Kotlin Android application built from the root Gradle project.
- **Milkchain prototype:** experimental Python blockchain, wallet, and transaction tools.

These are prototypes, not a production bank or production payment network. The Android application currently provides an offline personal ledger for manually entered income, expenses, and monthly spending limits. Its records are stored locally on the device and are not verified bank transactions or funds held by a financial institution. It does not open accounts, hold deposits, process transfers, issue credit, or connect to a banking provider. The funding page intentionally keeps cryptocurrency contributions disabled until a receiving asset, network, and address have been independently verified and configured.

## Android application

The offline ledger includes exact cents-based money parsing, recorded income and expense totals, a monthly spending limit, and local transaction history. Long-press a history row to delete a manually entered record. Ledger records and the monthly limit are encrypted at rest with AES-256-GCM using a key held by Android Keystore. Existing plaintext local records are migrated to the encrypted format on first launch after this update; plaintext preferences are removed only after the encrypted copy has been committed successfully. If the encrypted data cannot be unlocked or authenticated, the app preserves the stored ciphertext and blocks writes rather than silently deleting records. Data remains on the device and is not synchronized across devices. Do not enter banking credentials or treat its displayed balance as available funds.

Requirements: JDK 17, Android SDK Platform 35, and Gradle 8.9 or a compatible Android Studio installation.

Open this repository in Android Studio and run the app. From a machine with Gradle installed:

```sh
gradle assembleDebug
```

## Funding website

Serve `index.html` from a static web host. Never put private keys, recovery phrases, exchange credentials, or other secrets in the page. Configure a receiving address only after verifying the asset and network in the receiving account.

## Milkchain development prototype

Milkchain is Butter Bank's Biscuits blockchain. Its default development configuration uses stake-free BFT finality rather than proof-of-work. It is not the funding website's payment processor and is not connected to the Android application.

Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r milkchain/requirements.txt
PYTHONPATH=milkchain python -m unittest discover -s tests -v
```

Do not use this prototype for real funds or expose its node API to the public internet. The BFT implementation includes signed consensus messages, quorum certificates, bounded/rate-limited HTTP handlers, persistent signer locks, and certificate-validated chain extension. It is not production-ready: validator-set transitions and revocation activation, cryptographic protection against signer-state rollback, robust multi-host partition/recovery testing, formal protocol review, and independent security audit remain outstanding. Remote Milkchain consensus links now require mutual TLS with CA validation and an explicit peer-certificate fingerprint allowlist. BFT-finalized history is intentionally not reorganized; a conflicting finalized history must be treated as a safety failure, not resolved by choosing a longer fork.

## Security and scope

No component in this repository should be represented as a licensed bank, deposit-taking institution, production wallet, or audited payment network. Real banking and payment functionality requires defined product requirements, regulated-provider integrations where applicable, security engineering, and legal/compliance review.

## Biscuits wallet key management

New Milkchain wallets encrypt their Ed25519 private keys with AES-256-GCM. A key is derived from a passphrase using scrypt; the passphrase is never written to the wallet file. The wallet file is created with owner-only permissions (0600 on POSIX), and the tool refuses to overwrite an existing file. The transaction CLI prompts for the passphrase when it opens an encrypted wallet. Wallet connections permit plain HTTP only for loopback nodes; remote nodes must use HTTPS.

```sh
PYTHONPATH=milkchain python -m wallet create biscuits.wallet
PYTHONPATH=milkchain python -m wallet address biscuits.wallet
```

Older wallet files contain an unencrypted private key. They remain readable for compatibility but emit a warning. Encrypt an existing legacy wallet in place with:

```sh
PYTHONPATH=milkchain python -m wallet encrypt old-wallet.json
```

Keep the passphrase separate from the wallet file. A forgotten passphrase cannot be recovered, and anyone who obtains both the wallet file and its passphrase can control its funds. This wallet format is development key storage, not a hardware wallet or audited custody system.

## Milkchain BFT node

Copy `milkchain/config.example.json` to a private `config.bft.json` file, then configure the issuer public keys, admission certificates, validator key path, and peer addresses. The committed example deliberately contains issuer placeholders and no admission certificates, so it cannot start a validator as-is. Keep private keys and the completed configuration out of version control.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r milkchain/requirements.txt
cp milkchain/config.example.json config.bft.json
# Edit config.bft.json with the independently issued validator credentials.
PYTHONPATH=milkchain python milkchain/bft_node.py --config config.bft.json
```

The BFT node requires more than two-thirds of validator voting power to finalize a block. The current development configuration does not mint new Biscuits through block rewards. Monetary issuance rules are intentionally unspecified; no supply cap or issuance schedule is assumed. Read [the consensus and validator operations specification](milkchain/docs/BFT_CONSENSUS.md) before configuring validators.

This is development software, not a production network. Validator-set transitions and revocation activation, anti-rollback signer storage, formal protocol review, independent security audit, adversarial network testing, and production recovery procedures remain necessary.
