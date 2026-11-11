"""Authenticated application-service boundary for Butter Bank.

The injected account-owner resolver must validate the supplied credential
before returning the owner reference used by the ledger. This module
contains no password handling, token signing, or provider secrets.
"""
from __future__ import annotations

from collections.abc import Callable

from financial_ledger import FinancialLedger, LedgerError


class AuthenticationError(PermissionError):
    """The supplied credential did not resolve to an account owner reference."""


class CredentialProviderUnavailable(RuntimeError):
    """The credential source could not be reached or did not respond."""


class BankingService:
    """Expose ledger operations scoped to the account-owner reference returned by
    the configured credential resolver. The resolver receives an opaque
    credential and must validate it before returning that reference.
    """

    def __init__(
        self,
        ledger: FinancialLedger,
        account_owner_resolver: Callable[[object], str],
    ):
        if not isinstance(ledger, FinancialLedger):
            raise TypeError("ledger must be a FinancialLedger")
        if not callable(account_owner_resolver):
            raise TypeError("account_owner_resolver must be callable")
        self.ledger = ledger
        self._account_owner_resolver = account_owner_resolver

    def _owner_ref(self, credential):
        try:
            owner_ref = self._account_owner_resolver(credential)
        except CredentialProviderUnavailable:
            raise
        except Exception as exc:
            raise AuthenticationError("credential could not be validated") from exc
        if not isinstance(owner_ref, str) or not owner_ref.strip():
            raise AuthenticationError("credential is invalid or expired")
        return owner_ref.strip()

    def open_account(self, credential, currency_code, account_type="deposit"):
        owner_ref = self._owner_ref(credential)
        return self.ledger.create_account(
            owner_ref=owner_ref,
            currency_code=currency_code,
            account_type=account_type,
        )

    def currencies(self, credential):
        self._owner_ref(credential)
        return self.ledger.currencies()

    def accounts(self, credential):
        owner_ref = self._owner_ref(credential)
        return self.ledger.accounts_for_owner(owner_ref)

    def statement(self, credential, account_id, limit=100):
        owner_ref = self._owner_ref(credential)
        return self.ledger.statement_for_owner(owner_ref, account_id, limit)

    def transfer(
        self, credential, source_account_id, destination_account_id,
        amount_minor, idempotency_key, description="Account transfer",
    ):
        owner_ref = self._owner_ref(credential)
        return self.ledger.transfer(
            authenticated_owner_ref=owner_ref,
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount_minor=amount_minor,
            idempotency_key=idempotency_key,
            description=description,
        )
