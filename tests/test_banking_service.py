import tempfile
import unittest
from pathlib import Path

from banking_service import (
    AuthenticationError,
    BankingService,
    CredentialProviderUnavailable,
)
from banking_runtime import create_banking_service
from financial_ledger import FinancialLedger, LedgerError


class BankingServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = FinancialLedger(Path(self.temp.name) / "ledger.sqlite3")
        self.owner_a = self.ledger.create_account("owner-a", "USD")
        self.owner_b = self.ledger.create_account("owner-b", "USD")
        self.clearing = self.ledger.create_account(
            "system-clearing", "USD", "clearing", allow_negative=True
        )
        self.ledger.post("fund-owner-a", "Test funding entry", [
            (self.owner_a, 5000), (self.clearing, -5000),
        ])
        credentials = {"credential-a": "owner-a", "credential-b": "owner-b"}
        self.service = BankingService(self.ledger, credentials.get)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def test_open_account_and_list_only_authenticated_owners_accounts(self):
        new_account = self.service.open_account("credential-a", "JPY")
        accounts = self.service.accounts("credential-a")
        self.assertEqual(
            {item["account_id"] for item in accounts},
            {self.owner_a, new_account},
        )
        self.assertTrue(all(item["owner_ref"] == "owner-a" for item in accounts))
        self.assertEqual(
            {item["account_id"] for item in self.service.accounts("credential-b")},
            {self.owner_b},
        )

    def test_statement_requires_authenticated_account_owner(self):
        statement = self.service.statement("credential-a", self.owner_a)
        self.assertEqual(statement["balance_minor"], 5000)
        with self.assertRaisesRegex(LedgerError, "not owned"):
            self.service.statement("credential-b", self.owner_a)

    def test_transfer_uses_authenticated_account_owner_and_ledger_rules(self):
        transaction_id = self.service.transfer(
            "credential-a", self.owner_a, self.owner_b, 1250, "service-transfer"
        )
        self.assertTrue(transaction_id)
        self.assertEqual(self.ledger.balance_minor(self.owner_a), 3750)
        self.assertEqual(self.ledger.balance_minor(self.owner_b), 1250)
        with self.assertRaisesRegex(LedgerError, "not owned"):
            self.service.transfer(
                "credential-b", self.owner_a, self.owner_b, 100,
                "unauthorized-service-transfer",
            )

    def test_transfer_idempotency_keys_are_scoped_to_the_account_owner(self):
        first = self.service.transfer(
            "credential-a", self.owner_a, self.owner_b, 100, "shared-key"
        )
        second = self.service.transfer(
            "credential-b", self.owner_b, self.owner_a, 100, "shared-key"
        )
        self.assertNotEqual(first, second)
        self.assertEqual(self.ledger.balance_minor(self.owner_a), 5000)
        self.assertEqual(self.ledger.balance_minor(self.owner_b), 0)

    def test_invalid_or_expired_credential_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.service.accounts("unknown-credential")
        failing = BankingService(
            self.ledger,
            lambda credential: (_ for _ in ()).throw(ValueError("invalid token")),
        )
        with self.assertRaises(AuthenticationError):
            failing.accounts("bad-token")

    def test_credential_provider_outage_is_not_misreported_as_invalid_credentials(self):
        def unavailable(credential):
            raise CredentialProviderUnavailable("provider offline")

        service = BankingService(self.ledger, unavailable)
        with self.assertRaises(CredentialProviderUnavailable):
            service.accounts("credential-a")

    def test_account_owner_resolver_is_mandatory(self):
        with self.assertRaises(TypeError):
            BankingService(self.ledger, None)

    def test_service_startup_rejects_a_tampered_ledger(self):
        self.ledger._db.execute(
            "UPDATE journal_entries SET amount_minor=amount_minor+1 "
            "WHERE transaction_id=(SELECT transaction_id FROM journal_transactions "
            "WHERE idempotency_key='fund-owner-a') AND account_id=?",
            (self.owner_a,),
        )
        with self.assertRaisesRegex(LedgerError, "does not balance"):
            BankingService(self.ledger, lambda credential: "owner-a")

    def test_runtime_factory_uses_the_supplied_account_owner_resolver(self):
        service = create_banking_service(self.ledger, lambda credential: "owner-a")
        self.assertEqual(
            {item["account_id"] for item in service.accounts("credential")},
            {self.owner_a},
        )



if __name__ == "__main__":
    unittest.main()
