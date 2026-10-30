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

## Emberchain development prototype

The Python code is a separate educational account-based proof-of-work prototype. It is not the funding website's payment processor and is not connected to the Android application.

Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Do not use this prototype for real funds or expose its node API to the public internet. It still lacks production consensus, reliable chain synchronization and reorganizations, peer authentication, rate limiting, hardened key storage, and independent security review.

## Security and scope

No component in this repository should be represented as a licensed bank, deposit-taking institution, production wallet, or audited payment network. Real banking and payment functionality requires defined product requirements, regulated-provider integrations where applicable, security engineering, and legal/compliance review.
