"""Authenticated application-service boundary for Butter Bank.

The injected principal resolver must validate a trusted identity credential.
This module deliberately contains no password handling, token signing, or
identity-provider secrets.
"""
from __future__ import annotations

from collections.abc import Callable

from financial_ledger import FinancialLedger, LedgerError


class AuthenticationError(PermissionError):
    """The supplied identity credential did not resolve to an owner."""


class BankingService:
    """Expose owner-scoped ledger operations through a trusted identity resolver.

    The resolver receives an opaque credential and must return the stable
    owner reference only after validating the credential's signature, issuer,
    audience, expiry, and revocation status.
    """

    def __init__(
        self,
        ledger: FinancialLedger,
        principal_resolver: Callable[[object], str],
    ):
        if not isinstance(ledger, FinancialLedger):
            raise TypeError("ledger must be a FinancialLedger")
        if not callable(principal_resolver):
            raise TypeError("principal_resolver must be callable")
        self.ledger = ledger
        self._principal_resolver = principal_resolver

    def _owner_ref(self, credential):
        try:
            owner_ref = self._principal_resolver(credential)
        except Exception as exc:
            raise AuthenticationError("identity credential could not be validated") from exc
        if not isinstance(owner_ref, str) or not owner_ref.strip():
            raise AuthenticationError("identity credential is invalid or expired")
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
