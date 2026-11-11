# Financial ledger

## Purpose

`financial_ledger.py` is the local accounting foundation for Butter Bank. It provides a persistent SQLite double-entry journal with explicit currency precision, immutable postings, idempotency keys, owner-scoped account listing, and internal transfers.

The journal records accounting entries. It does not prove that funds exist at an external institution, that a payment has settled, or that an account is insured or held in custody.

## Basic setup

```python
from financial_ledger import FinancialLedger

ledger = FinancialLedger("data/butter-bank.sqlite3")
```

The database parent directory is created when needed. On POSIX systems the database file is opened without following a symlink where the platform supports `O_NOFOLLOW`, checked as a regular file, and restricted to owner read/write permissions. SQLite uses WAL mode and full synchronous writes for file-backed databases.

Close the ledger when the owning process shuts down:

```python
ledger.close()
```

The class also supports a context manager.

## Currency precision

USD is registered with exponent 2 (cents); JPY is registered with exponent 0 (whole yen). Amounts are always signed integers in the currency's minor unit. Floating-point amounts are rejected.

Register other currencies or assets only with an explicitly selected exponent and asset class:

```python
ledger.register_currency("BISCUITS", 0, "crypto")
```

The example above is only a syntax example. It does not establish the Biscuits denomination or issuance policy. Those monetary rules remain unspecified and must be set before real-value issuance.

## Accounts and ownership

```python
account_id = ledger.create_account(
    owner_ref="trusted-account-owner-reference",
    currency_code="USD",
    account_type="deposit",
)
accounts = ledger.accounts_for_owner("trusted-account-owner-reference")
```

The owner reference is an opaque value used to associate ledger accounts with the JaMail account that owns them. The ledger does not authenticate that value. It must be derived from a verified JaMail session or credential; a client must never be allowed to choose an owner reference in a request.

## Internal transfers

```python
transaction_id = ledger.transfer(
    authenticated_owner_ref="trusted-principal-reference",
    source_account_id="source-account-id",
    destination_account_id="destination-account-id",
    amount_minor=1250,
    idempotency_key="unique-request-id",
    description="Internal transfer",
)
```

The caller must pass the owner reference returned by the trusted credential-validation layer. The source account must belong to that JaMail account. The destination may belong to a different account owner. Both accounts must use the same currency. The journal posts the debit and credit atomically, rejects overdrafts by default, and returns the original transaction ID when the same idempotent request is retried.

The idempotency key must be unique for each distinct operation. Reusing a key for different journal content is rejected.

## Direct journal posting

`post(idempotency_key, description, entries)` is the lower-level accounting operation. Each entry is a pair of account ID and signed integer minor-unit amount. At least two accounts are required, every account may appear only once, all entries must use the same currency, and the signed amounts must sum to zero.

Direct posting is an internal accounting primitive. It must not be exposed directly to an unauthenticated client or used to represent an external deposit, withdrawal, card authorization, or payment settlement without a verified external event and a controlled posting policy.

## Current boundaries

This module does not yet provide:

- Customer authentication or JaMail session validation.
- A public HTTP/API service, customer onboarding, account recovery, or permissions administration.
- External deposits, withdrawals, card issuing, ACH, wire, instant payment, merchant settlement, or reconciliation.
- Credit underwriting, lending, interest accrual, savings yields, fees, payroll, tax reporting, investment brokerage, or government-benefit integrations.
- Encryption of the SQLite database at rest, key management for customer authentication, replicated storage, or production disaster recovery.

Do not place real customer funds or production credentials in this development ledger. Those capabilities require separate designs, provider integrations, regulatory authorization, security review, and operational controls.

## Authenticated application-service boundary

`banking_service.py` exposes account opening, account listing, owner-scoped statements, and internal transfers through an injected account-owner resolver:

```python
from banking_service import BankingService
from financial_ledger import FinancialLedger

ledger = FinancialLedger("data/butter-bank.sqlite3")
service = BankingService(ledger, account_owner_resolver=trusted_account_owner_resolver)
```

The resolver receives an opaque credential and must validate it before returning the owner reference associated with the JaMail account used for the request. The service rejects missing or invalid credentials and does not accept an owner reference from the client.

A JaMail HTTPS credential-introspection adapter is present in jamail_identity.py. Its expected request and response format was authored for that adapter in this repository; it must not be mistaken for an existing JaMail endpoint or API. Do not connect it to an unverified resolver, hardcode signing secrets, or treat a client-provided owner reference as authentication.

## JaMail credential integration

Butter Bank includes a JaMail introspection adapter in jamail_identity.py and a service factory in banking_runtime.py. The adapter sends an opaque bearer credential to a configured HTTPS endpoint using an authenticated service-client credential. It expects a JSON response containing active, iss, aud, sub, and exp fields. These names and meanings are the adapter's proposed interface, not evidence of an already deployed JaMail API. The sub field is treated by this adapter as the owner reference returned after credential validation.

Configure the Butter Bank process with these runtime settings:
- JAMAIL_INTROSPECTION_URL: HTTPS URL of the credential-validation endpoint configured to check JaMail credentials; this endpoint is not supplied by the adapter itself.
- JAMAIL_INTROSPECTION_CLIENT_ID: Butter Bank's registered JaMail service-client ID.
- JAMAIL_INTROSPECTION_CLIENT_SECRET: secret issued to that service client.
- JAMAIL_ISSUER: exact JaMail token issuer.
- BUTTER_BANK_JAMAIL_AUDIENCE: audience registered for Butter Bank.

Create the service with create_jamail_banking_service(ledger). Do not commit service credentials or place them in source control. The HTTP API continues to bind to loopback by default.

Integration status: this repository contains the adapter and isolated tests for its proposed response format. Those tests do not establish a live connection to JaMail. The JaMail repository and published Wix site must be assessed against the actual JaMail account and session implementation before this adapter can be connected.

## Local HTTP API

`banking_api.py` provides a threaded HTTP server for the application service. It binds to `127.0.0.1` by default:

```python
from banking_api import create_server

server = create_server(service, host="127.0.0.1", port=8000)
server.serve_forever()
```

Every supported route requires an `Authorization: Bearer <credential>` header. The credential is passed to the injected account-owner resolver; the HTTP API never accepts an owner reference in a request body.

| Method | Route | Purpose |
|---|---|---|
| GET | `/currencies` | Read registered currency and asset precision metadata |
| POST | `/accounts` | Open an account using `currency_code` and optional `account_type` |
| GET | `/accounts` | List the authenticated owner's accounts |
| GET | `/accounts/{account_id}/statement?limit=100` | Read an owner's account statement |
| POST | `/transfers` | Transfer integer minor units between internal accounts |

JSON request bodies are limited to 64 KiB. The API does not expose arbitrary journal posting, deposits, withdrawals, card authorization, or external payment settlement. It has no built-in TLS termination, rate limiting, or production credential-validation provider. Keep it on loopback until a verified JaMail credential-validation adapter and an authenticated TLS reverse proxy are configured.
