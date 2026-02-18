# Butter Bank

Butter Bank is an Android mobile app prototype built around a single **Hybrid Account** (not checking/savings, and not wallet/vault buckets).

## What it does now

- Uses one Hybrid Account with:
  - **Cash balance**
  - **Credit line** (limit, used, available)
- Lets you **add cash funds**.
- Lets you **spend** (uses cash first, then available credit if needed).
- Lets you **repay credit from cash**.
- Records actions in an on-screen **transaction history ledger**.

## Why this matches your correction

The model now avoids checking/savings assumptions and avoids separate wallet/vault framing. It behaves like one unified account that can hold value and also support controlled credit usage.

## Project structure

- `src/main/java/com/example/butterbank/MainActivity.kt` - UI wiring and action handlers.
- `src/main/java/com/example/butterbank/Account.kt` - account model.
- `src/main/java/com/example/butterbank/BankLedger.kt` - hybrid-account money + credit rules and transaction history.
- `src/main/res/layout/activity_main.xml` - main screen layout.
- `src/main/res/values/strings.xml` - UI text resources.
- `src/main/AndroidManifest.xml` - app launch entry point.

## Running locally

1. Open this project in Android Studio.
2. Allow Gradle sync.
3. Run on an emulator/device.

## License

This project is licensed under the [MIT License](LICENSE).
