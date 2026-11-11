"""Production configuration helpers for the Butter Bank service."""
from banking_service import BankingService
from financial_ledger import FinancialLedger
from jamail_identity import JaMailIntrospectionResolver

def create_jamail_banking_service(ledger: FinancialLedger) -> BankingService:
    """Create a fail-closed service using JaMail HTTPS introspection.

    The JaMail endpoint must implement the documented response contract
    before this factory can authenticate real JaMail sessions.
    """
    return BankingService(ledger, JaMailIntrospectionResolver.from_env())
