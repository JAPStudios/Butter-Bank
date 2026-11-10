import tempfile
import unittest
from pathlib import Path

from financial_ledger import (
    FinancialLedger, IdempotencyConflict, InsufficientFunds, LedgerError,
)


class FinancialLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "financial-ledger.sqlite3"
        self.ledger = FinancialLedger(self.path)
        self.usd_a = self.ledger.create_account("customer-a", "USD")
        self.usd_b = self.ledger.create_account("customer-b", "USD")
        self.jpy_a = self.ledger.create_account("customer-a", "JPY")
        self.jpy_b = self.ledger.create_account("customer-b", "JPY")

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def test_usd_uses_cents_and_jpy_uses_whole_yen(self):
        self.assertEqual(self.ledger.currency("USD")["minor_unit_exponent"], 2)
        self.assertEqual(self.ledger.currency("JPY")["minor_unit_exponent"], 0)
        self.ledger.post("usd-opening", "USD opening entry", [
            (self.usd_a, 1250), (self.usd_b, -1250),
        ])
        self.ledger.post("jpy-opening", "JPY opening entry", [
            (self.jpy_a, 5000), (self.jpy_b, -5000),
        ])
        self.assertEqual(self.ledger.balance_minor(self.usd_a), 1250)
        self.assertEqual(self.ledger.balance_minor(self.jpy_a), 5000)

    def test_cannot_post_between_different_currencies(self):
        with self.assertRaisesRegex(LedgerError, "cannot mix currencies"):
            self.ledger.post("mixed", "Invalid cross-currency posting", [
                (self.usd_a, 100), (self.jpy_b, -100),
            ])

    def test_each_transaction_must_balance(self):
        with self.assertRaisesRegex(LedgerError, "balance to zero"):
            self.ledger.post("unbalanced", "Invalid posting", [
                (self.usd_a, 100), (self.usd_b, -99),
            ])

    def test_negative_balance_is_rejected_atomically(self):
        before = self.ledger.balance_minor(self.usd_a)
        with self.assertRaises(InsufficientFunds):
            self.ledger.post("overspend", "Attempted overdraft", [
                (self.usd_a, -1), (self.usd_b, 1),
            ])
        self.assertEqual(self.ledger.balance_minor(self.usd_a), before)
        self.assertEqual(self.ledger.balance_minor(self.usd_b), 0)

    def test_idempotency_returns_original_transaction(self):
        entries = [(self.usd_a, 900), (self.usd_b, -900)]
        first = self.ledger.post("same-request", "Transfer", entries)
        second = self.ledger.post("same-request", "Transfer", entries)
        self.assertEqual(first, second)
        self.assertEqual(self.ledger.balance_minor(self.usd_a), 900)

    def test_reused_idempotency_key_with_different_content_is_rejected(self):
        self.ledger.post("same-request", "Transfer", [
            (self.usd_a, 900), (self.usd_b, -900),
        ])
        with self.assertRaises(IdempotencyConflict):
            self.ledger.post("same-request", "Different transfer", [
                (self.usd_a, 800), (self.usd_b, -800),
            ])

    def test_currency_metadata_cannot_be_silently_changed(self):
        with self.assertRaisesRegex(LedgerError, "different metadata"):
            self.ledger.register_currency("USD", 0, "fiat")

    def test_database_persists_accounts_and_journal(self):
        self.ledger.post("persistent", "Persistent entry", [
            (self.usd_a, 250), (self.usd_b, -250),
        ])
        self.ledger.close()
        self.ledger = FinancialLedger(self.path)
        self.assertEqual(self.ledger.balance_minor(self.usd_a), 250)
        self.assertEqual(len(self.ledger.journal(self.usd_a)), 1)

    def test_amounts_must_be_integers_not_floats_or_booleans(self):
        for index, amount in enumerate((1.5, True, 0)):
            with self.subTest(amount=amount):
                with self.assertRaises(LedgerError):
                    self.ledger.post("bad-" + str(index), "Invalid amount", [
                        (self.usd_a, amount), (self.usd_b, -amount),
                    ])


if __name__ == "__main__":
    unittest.main()
