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
    owner_ref="trusted-principal-reference",
    currency_code="USD",
    account_type="deposit",
)
accounts = ledger.accounts_for_owner("trusted-principal-reference")
```

The owner reference is an opaque stable identifier. The ledger does not authenticate it. A future identity adapter must derive it from a verified session; a client must never be allowed to choose another person's owner reference. JaMail authentication and account-access integration are not implemented by this module.

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

The caller must pass the owner reference from the trusted authentication layer. The source account must belong to that principal. The destination may belong to another account holder. Both accounts must use the same currency. The journal posts the debit and credit atomically, rejects overdrafts by default, and returns the original transaction ID when the same idempotent request is retried.

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
- Encryption of the SQLite database at rest, key management for customer identity, replicated storage, or production disaster recovery.

Do not place real customer funds or production credentials in this development ledger. Those capabilities require separate designs, provider integrations, regulatory authorization, security review, and operational controls.
