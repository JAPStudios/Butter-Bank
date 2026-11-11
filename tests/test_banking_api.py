import http.client
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from banking_api import MAX_REQUEST_BYTES, create_server
from banking_service import BankingService
from financial_ledger import FinancialLedger


class BankingAPITests(unittest.TestCase):
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
        principals = {"token-a": "owner-a", "token-b": "owner-b"}
        service = BankingService(self.ledger, principals.get)
        self.server = create_server(service, host="127.0.0.1", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = "http://127.0.0.1:" + str(self.server.server_address[1])

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.ledger.close()
        self.temp.cleanup()

    def request(self, method, path, token=None, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def test_account_opening_and_listing_require_bearer_authentication(self):
        status, body = self.request("POST", "/accounts", "token-a", {
            "currency_code": "JPY",
        })
        self.assertEqual(status, 201)
        new_account_id = body["account_id"]
        self.assertTrue(new_account_id)
        status, body = self.request("GET", "/accounts", "token-a")
        self.assertEqual(status, 200)
        self.assertEqual(
            {item["account_id"] for item in body["accounts"]},
            {self.owner_a, new_account_id},
        )
        status, body = self.request("GET", "/accounts")
        self.assertEqual(status, 401)

    def test_currency_catalog_returns_explicit_precision(self):
        status, body = self.request("GET", "/currencies", "token-a")
        self.assertEqual(status, 200)
        currencies = {item["code"]: item for item in body["currencies"]}
        self.assertEqual(currencies["USD"]["minor_unit_exponent"], 2)
        self.assertEqual(currencies["JPY"]["minor_unit_exponent"], 0)
        self.assertEqual(currencies["USD"]["asset_class"], "fiat")

    def test_statement_endpoint_enforces_account_ownership(self):
        status, body = self.request(
            "GET", "/accounts/" + self.owner_a + "/statement", "token-a"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["balance_minor"], 5000)
        status, body = self.request(
            "GET", "/accounts/" + self.owner_a + "/statement", "token-b"
        )
        self.assertEqual(status, 403)

    def test_transfer_endpoint_posts_idempotently(self):
        payload = {
            "source_account_id": self.owner_a,
            "destination_account_id": self.owner_b,
            "amount_minor": 1250,
            "idempotency_key": "http-transfer-1",
        }
        status, first = self.request("POST", "/transfers", "token-a", payload)
        self.assertEqual(status, 200)
        status, second = self.request("POST", "/transfers", "token-a", payload)
        self.assertEqual(status, 200)
        self.assertEqual(first["transaction_id"], second["transaction_id"])
        self.assertEqual(self.ledger.balance_minor(self.owner_a), 3750)
        self.assertEqual(self.ledger.balance_minor(self.owner_b), 1250)

    def test_client_cannot_supply_owner_reference(self):
        status, body = self.request("POST", "/accounts", "token-a", {
            "currency_code": "USD",
            "owner_ref": "owner-b",
        })
        self.assertEqual(status, 400)
        status, body = self.request("POST", "/transfers", "token-a", {
            "source_account_id": self.owner_a,
            "destination_account_id": self.owner_b,
            "amount_minor": 1,
            "idempotency_key": "http-transfer-2",
            "owner_ref": "owner-b",
        })
        self.assertEqual(status, 400)
        self.assertEqual(self.ledger.balance_minor(self.owner_a), 5000)

    def test_oversized_request_body_is_rejected_and_connection_closed(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=3
        )
        connection.putrequest("POST", "/accounts")
        connection.putheader("Authorization", "Bearer token-a")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        self.assertEqual(response.getheader("Connection"), "close")
        response.read()
        connection.close()

    def test_invalid_credential_and_unsupported_method_are_rejected(self):
        status, body = self.request("GET", "/accounts", "invalid-token")
        self.assertEqual(status, 401)
        status, body = self.request("DELETE", "/accounts", "token-a")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
