import tempfile
import unittest
from pathlib import Path

from banking_service import AuthenticationError, BankingService
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

    def test_transfer_uses_authenticated_principal_and_ledger_rules(self):
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

    def test_invalid_or_expired_credential_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.service.accounts("unknown-credential")
        failing = BankingService(
            self.ledger,
            lambda credential: (_ for _ in ()).throw(ValueError("invalid token")),
        )
        with self.assertRaises(AuthenticationError):
            failing.accounts("bad-token")

    def test_identity_resolver_is_mandatory(self):
        with self.assertRaises(TypeError):
            BankingService(self.ledger, None)


if __name__ == "__main__":
    unittest.main()
