# Butter Bank

Butter Bank is a development repository with three distinct components:

- **Funding website:** the static public project page in `index.html`, mirrored as `funding.html`.
- **Android prototype:** the Kotlin Android application built from the root Gradle project.
- **Emberchain prototype:** experimental Python blockchain, wallet, and transaction tools.

These are prototypes, not a production bank or production payment network. The Android application currently displays an informational screen only; it does not open accounts, hold deposits, process transfers, or connect to a banking provider. The funding page intentionally keeps cryptocurrency contributions disabled until a receiving asset, network, and address have been independently verified and configured.

## Android application

Requirements: JDK 17, Android SDK Platform 35, and Gradle 8.9 or a compatible Android Studio installation.

Open this repository in Android Studio and run the app. From a machine with Gradle installed:

```sh
gradle assembleDebug
```

## Funding website

Serve `index.html` from a static web host. Never put private keys, recovery phrases, exchange credentials, or other secrets in the page. Configure a receiving address only after verifying the asset and network in the receiving account.

## Emberchain / Biscuits development prototype

The Python blockchain is separate from the funding website and Android application. The original node entry point remains an experimental proof-of-work chain. A separate BFT mode is available on the development branch through bft_node.py; it finalizes account blocks with Ed25519 validator votes and requires strictly more than two-thirds of validator voting power. BFT mode disables mining and assigns equal voting power to admitted validators.

Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r emberchain/requirements.txt
PYTHONPATH=emberchain python -m unittest discover -s tests -v
```

Create a user wallet and inspect its public address with:

```sh
PYTHONPATH=emberchain python -m wallet create wallet.json
PYTHONPATH=emberchain python -m wallet address wallet.json
```

Submit a signed transfer to a running local node using the recipient's 32-byte public key and an amount in integer base units:

```sh
PYTHONPATH=emberchain python -m tx --wallet wallet.json --node http://127.0.0.1:8333 --to RECIPIENT_PUBLIC_KEY --amount 1
```

Wallet readers reject symlinks, non-regular files, group/world-readable files on POSIX, and mismatched public/private key pairs. Keep wallet files out of source control and backups that are not encrypted.

For BFT validator setup, read docs/BFT_CONSENSUS.md and start from config.bft.example.json. Generate a validator key with:

```sh
PYTHONPATH=emberchain python -m keygen --output validator.key
```

The example configuration contains placeholders and cannot start a network until the issuer federation, admission certificates, validator keys, and peer/TLS settings are configured. The admission design requires at least four independent credential issuers and at least four admitted validators; issuers must enforce one credential per eligible participant off-chain.

BFT mode is an integrated development prototype, not production consensus. Signed round-change messages and certificate-gated valid-round recovery are implemented in the development branch. Validator-set changes and revocation activation, hardware-backed anti-rollback, formal verification, independent security audit, adversarial partition testing, and production recovery exercises remain outstanding. Do not use real funds or expose the node APIs publicly without additional security controls.

## Security and scope

No component in this repository should be represented as a licensed bank, deposit-taking institution, production wallet, or audited payment network. Real banking and payment functionality requires defined product requirements, regulated-provider integrations where applicable, security engineering, and legal/compliance review.
