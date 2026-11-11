"""Runtime factory for the Butter Bank application service."""
from collections.abc import Callable

from banking_service import BankingService
from financial_ledger import FinancialLedger


def create_banking_service(
    ledger: FinancialLedger,
    account_owner_resolver: Callable[[object], str],
) -> BankingService:
    """Create the service with the credential validator for the account source."""
    return BankingService(ledger, account_owner_resolver)
