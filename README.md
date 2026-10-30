# Butter Bank

Butter Bank is a development repository with three distinct components:

- **Funding website:** the static public project page in `index.html`, mirrored as `funding.html`.
- **Android prototype:** an offline-first local personal-finance ledger with manually entered income, expenses, transaction history, and monthly spending limits.
- **Milkchain prototype:** experimental account-based proof-of-work blockchain, Biscuits configuration, wallet, and transaction tools. The current Python implementation remains in the historical `emberchain/` directory.

These are prototypes, not a production bank or production payment network. The Android application stores manually entered records on the device; it does not open accounts, hold deposits, issue credit, process transfers, or connect to a banking provider. The funding page intentionally keeps cryptocurrency contributions disabled until a receiving asset, network, and address have been independently verified and configured.

## Android application

Requirements: JDK 17, Android SDK Platform 35, and Gradle 8.9 or a compatible Android Studio installation.

Open this repository in Android Studio and run the app. From a machine with Gradle installed:

```sh
gradle assembleDebug testDebugUnitTest
```

The app currently provides a local ledger, monthly spending limit, and transaction history. The displayed balance is calculated only from records manually entered into this app; it is not a bank balance or verified available funds. Local app data is not encrypted by this prototype. Do not enter sensitive financial information.

## Funding website

Serve `index.html` from a static web host. Never put private keys, recovery phrases, exchange credentials, or other secrets in the page. Configure a receiving address only after verifying the asset and network in the receiving account.

## Milkchain / Biscuits development prototype

The Python implementation is an educational account-based proof-of-work prototype. Its source currently resides in `emberchain/`; the example configuration identifies the development network as `milkchain-devnet-1` and the currency symbol as `BISCUITS`. It is not the funding website's payment processor and is not connected to the Android application.

Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r emberchain/requirements.txt
PYTHONPATH=emberchain python -m unittest discover -s tests -v
```

Start a local development node:

```sh
cp emberchain/config.example.json emberchain/config.json
python emberchain/node.py --config emberchain/config.json --data emberchain/data-8333.json
```

Create and inspect a local development wallet:

```sh
python emberchain/wallet.py create biscuits-wallet.json
python emberchain/wallet.py address biscuits-wallet.json
```

The wallet file contains an unencrypted private key. Keep it private, back it up securely, and never commit it. The repository's `.gitignore` excludes wallet files matching `*-wallet.json`; use that suffix for generated keys.

Do not use this prototype for real funds or expose its node API to the public internet. It still lacks production consensus, reliable chain synchronization and reorganizations, peer authentication, rate limiting, hardened key storage, and independent security review.

## Security and scope

No component in this repository should be represented as a licensed bank, deposit-taking institution, production wallet, or audited payment network. Real banking and payment functionality requires defined product requirements, regulated-provider integrations where applicable, security engineering, and legal/compliance review.
