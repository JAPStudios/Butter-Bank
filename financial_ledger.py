"""Exact, balanced financial-account ledger for Butter Bank.

Balances are recorded in integer minor units. This module does not claim that
an entry is settled, insured, held in custody, or backed by an external bank.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


_CURRENCY_CODE = re.compile(r"^[A-Z][A-Z0-9]{2,11}$")
_MIN_INT64 = -(2**63)
_MAX_INT64 = 2**63 - 1


class LedgerError(ValueError):
    """Base class for rejected financial-ledger operations."""


class IdempotencyConflict(LedgerError):
    """An idempotency key was reused for different journal content."""


class InsufficientFunds(LedgerError):
    """A posting would make a non-overdraft account negative."""


class FinancialLedger:
    """SQLite-backed, multi-currency double-entry journal.

    USD uses cents (exponent 2); JPY uses whole yen (exponent 0). Other
    currencies or assets must be registered with an explicit exponent.
    Every journal transaction balances independently within one currency.
    """

    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            database_path = Path(self.path)
            database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if database_path.is_symlink():
                raise LedgerError("ledger database must not be a symbolic link")
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(str(database_path), flags, 0o600)
            except OSError as exc:
                raise LedgerError("ledger database cannot be opened safely") from exc
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise LedgerError("ledger database must be a regular file")
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        self._db = sqlite3.connect(
            self.path, isolation_level=None, check_same_thread=False, timeout=30
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 30000")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        self._create_schema()
        self.register_currency("USD", 2, "fiat")
        self.register_currency("JPY", 0, "fiat")

    def _create_schema(self):
        with self._lock:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS currencies (
                    code TEXT PRIMARY KEY,
                    minor_unit_exponent INTEGER NOT NULL
                        CHECK(minor_unit_exponent BETWEEN 0 AND 9),
                    asset_class TEXT NOT NULL
                        CHECK(asset_class IN ('fiat', 'crypto'))
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    owner_ref TEXT NOT NULL,
                    currency_code TEXT NOT NULL REFERENCES currencies(code),
                    account_type TEXT NOT NULL,
                    allow_negative INTEGER NOT NULL DEFAULT 0
                        CHECK(allow_negative IN (0, 1)),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS accounts_owner_idx
                    ON accounts(owner_ref, currency_code);
                CREATE TABLE IF NOT EXISTS journal_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    content_hash TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS journal_entries (
                    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL
                        REFERENCES journal_transactions(transaction_id),
                    account_id TEXT NOT NULL REFERENCES accounts(account_id),
                    amount_minor INTEGER NOT NULL CHECK(amount_minor <> 0),
                    UNIQUE(transaction_id, account_id)
                );
                CREATE INDEX IF NOT EXISTS journal_entries_account_idx
                    ON journal_entries(account_id, entry_id);
            """)

    @staticmethod
    def _text(value, field):
        if not isinstance(value, str) or not value.strip():
            raise LedgerError(field + " must be a non-empty string")
        return value.strip()

    def register_currency(self, code, minor_unit_exponent, asset_class):
        code = self._text(code, "currency code").upper()
        if not _CURRENCY_CODE.fullmatch(code):
            raise LedgerError("currency code must be 3 to 12 uppercase letters or digits")
        if (not isinstance(minor_unit_exponent, int)
                or isinstance(minor_unit_exponent, bool)
                or not 0 <= minor_unit_exponent <= 9):
            raise LedgerError("minor-unit exponent must be an integer from 0 to 9")
        if asset_class not in ("fiat", "crypto"):
            raise LedgerError("asset class must be fiat or crypto")
        with self._lock:
            self._db.execute(
                "INSERT INTO currencies(code, minor_unit_exponent, asset_class) "
                "VALUES (?, ?, ?) ON CONFLICT(code) DO NOTHING",
                (code, minor_unit_exponent, asset_class),
            )
            row = self._db.execute(
                "SELECT minor_unit_exponent, asset_class FROM currencies WHERE code=?",
                (code,),
            ).fetchone()
            if (row["minor_unit_exponent"], row["asset_class"]) != (
                minor_unit_exponent, asset_class
            ):
                raise LedgerError("currency is already registered with different metadata")
        return code

    def currency(self, code):
        with self._lock:
            row = self._db.execute(
                "SELECT code, minor_unit_exponent, asset_class FROM currencies WHERE code=?",
                (self._text(code, "currency code").upper(),),
            ).fetchone()
            if row is None:
                raise LedgerError("currency is not registered")
            return dict(row)

    def create_account(
        self, owner_ref, currency_code, account_type="deposit",
        allow_negative=False, account_id=None,
    ):
        owner_ref = self._text(owner_ref, "owner reference")
        account_type = self._text(account_type, "account type")
        currency = self._text(currency_code, "currency code").upper()
        if not isinstance(allow_negative, bool):
            raise LedgerError("allow_negative must be a boolean")
        self.currency(currency)
        account_id = account_id or str(uuid.uuid4())
        account_id = self._text(account_id, "account ID")
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._db.execute(
                "INSERT INTO accounts(account_id, owner_ref, currency_code, "
                "account_type, allow_negative, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (account_id, owner_ref, currency, account_type,
                 int(allow_negative), created_at),
            )
        return account_id

    def account(self, account_id):
        with self._lock:
            row = self._db.execute(
                "SELECT account_id, owner_ref, currency_code, account_type, "
                "allow_negative, created_at FROM accounts WHERE account_id=?",
                (self._text(account_id, "account ID"),),
            ).fetchone()
            if row is None:
                raise LedgerError("account does not exist")
            result = dict(row)
            result["allow_negative"] = bool(result["allow_negative"])
            return result

    def accounts_for_owner(self, owner_ref):
        """Return account metadata for one authenticated owner reference."""
        owner_ref = self._text(owner_ref, "owner reference")
        with self._lock:
            rows = self._db.execute(
                "SELECT account_id, owner_ref, currency_code, account_type, "
                "allow_negative, created_at FROM accounts "
                "WHERE owner_ref=? ORDER BY created_at, account_id",
                (owner_ref,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["allow_negative"] = bool(item["allow_negative"])
                result.append(item)
            return result

    def _balance_minor_unlocked(self, account_id):
        rows = self._db.execute(
            "SELECT amount_minor FROM journal_entries WHERE account_id=?",
            (account_id,),
        ).fetchall()
        balance = sum(row["amount_minor"] for row in rows)
        if not _MIN_INT64 <= balance <= _MAX_INT64:
            raise LedgerError("account balance exceeds the supported integer range")
        return balance

    def balance_minor(self, account_id):
        with self._lock:
            self.account(account_id)
            return self._balance_minor_unlocked(account_id)

    @staticmethod
    def _canonical_posting(description, currency, entries):
        return json.dumps(
            {"description": description, "currency": currency,
             "entries": sorted(entries)},
            sort_keys=True, separators=(",", ":"),
        )

    def post(self, idempotency_key, description, entries):
        """Commit one balanced journal transaction.

        entries is an iterable of (account_id, signed_minor_units).
        Positive values increase an account; negative values decrease it.
        """
        key = self._text(idempotency_key, "idempotency key")
        description = self._text(description, "description")
        if isinstance(entries, (str, bytes)):
            raise LedgerError("entries must be an iterable of account postings")
        try:
            postings = list(entries)
        except TypeError as exc:
            raise LedgerError("entries must be iterable") from exc
        if len(postings) < 2:
            raise LedgerError("a journal transaction requires at least two entries")

        normalized = []
        for item in postings:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise LedgerError("each entry must contain an account ID and amount")
            account_id, amount = item
            account_id = self._text(account_id, "account ID")
            if (not isinstance(amount, int) or isinstance(amount, bool)
                    or amount == 0 or not -(2**63) <= amount < 2**63):
                raise LedgerError("entry amount must be a non-zero signed integer")
            normalized.append((account_id, amount))
        if len({account_id for account_id, _ in normalized}) != len(normalized):
            raise LedgerError("each account may appear only once per journal transaction")
        if sum(amount for _, amount in normalized) != 0:
            raise LedgerError("journal transaction must balance to zero")

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                account_rows = []
                for account_id, amount in normalized:
                    row = self._db.execute(
                        "SELECT account_id, currency_code, allow_negative FROM accounts "
                        "WHERE account_id=?", (account_id,),
                    ).fetchone()
                    if row is None:
                        raise LedgerError("account does not exist: " + account_id)
                    account_rows.append((row, amount))
                currencies = {row["currency_code"] for row, _ in account_rows}
                if len(currencies) != 1:
                    raise LedgerError("one journal transaction cannot mix currencies")
                currency = next(iter(currencies))
                canonical = self._canonical_posting(description, currency, normalized)
                digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                prior = self._db.execute(
                    "SELECT transaction_id, content_hash FROM journal_transactions "
                    "WHERE idempotency_key=?", (key,),
                ).fetchone()
                if prior is not None:
                    if prior["content_hash"] != digest:
                        raise IdempotencyConflict(
                            "idempotency key was already used for different journal content"
                        )
                    self._db.execute("COMMIT")
                    return prior["transaction_id"]

                for row, amount in account_rows:
                    current = self._balance_minor_unlocked(row["account_id"])
                    next_balance = current + amount
                    if not _MIN_INT64 <= next_balance <= _MAX_INT64:
                        raise LedgerError(
                            "posting would exceed the supported account-balance range: "
                            + row["account_id"]
                        )
                    if not row["allow_negative"] and next_balance < 0:
                        raise InsufficientFunds(
                            "posting would make account negative: " + row["account_id"]
                        )

                transaction_id = str(uuid.uuid4())
                created_at = datetime.now(timezone.utc).isoformat()
                self._db.execute(
                    "INSERT INTO journal_transactions(transaction_id, idempotency_key, "
                    "content_hash, description, created_at) VALUES (?, ?, ?, ?, ?)",
                    (transaction_id, key, digest, description, created_at),
                )
                self._db.executemany(
                    "INSERT INTO journal_entries(transaction_id, account_id, amount_minor) "
                    "VALUES (?, ?, ?)",
                    [(transaction_id, account_id, amount)
                     for account_id, amount in normalized],
                )
                self._db.execute("COMMIT")
                return transaction_id
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def journal(self, account_id, limit=100):
        with self._lock:
            self.account(account_id)
            if (not isinstance(limit, int) or isinstance(limit, bool)
                    or not 1 <= limit <= 1000):
                raise LedgerError("journal limit must be between 1 and 1000")
            rows = self._db.execute(
                "SELECT t.transaction_id, t.idempotency_key, t.description, "
                "t.created_at, e.amount_minor FROM journal_entries e "
                "JOIN journal_transactions t USING(transaction_id) "
                "WHERE e.account_id=? ORDER BY e.entry_id DESC LIMIT ?",
                (account_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def transfer(
        self, authenticated_owner_ref, source_account_id,
        destination_account_id, amount_minor, idempotency_key,
        description="Account transfer",
    ):
        """Post an owner-authorized internal transfer in one currency.

        authenticated_owner_ref must come from a trusted authentication layer,
        not directly from an untrusted request field. This method does not
        initiate or represent external payment-rail settlement.
        """
        owner_ref = self._text(authenticated_owner_ref, "authenticated owner reference")
        source_id = self._text(source_account_id, "source account ID")
        destination_id = self._text(destination_account_id, "destination account ID")
        if source_id == destination_id:
            raise LedgerError("source and destination accounts must differ")
        if (not isinstance(amount_minor, int) or isinstance(amount_minor, bool)
                or not 1 <= amount_minor < 2**63):
            raise LedgerError("transfer amount must be a positive integer")
        with self._lock:
            source = self.account(source_id)
            destination = self.account(destination_id)
            if source["owner_ref"] != owner_ref:
                raise LedgerError("source account is not owned by the authenticated principal")
            if source["currency_code"] != destination["currency_code"]:
                raise LedgerError("one transfer cannot mix currencies")
            return self.post(
                idempotency_key, description,
                [(source_id, -amount_minor), (destination_id, amount_minor)],
            )

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
