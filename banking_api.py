"""Loopback-first HTTP API for authenticated Butter Bank ledger operations.

The API accepts opaque bearer credentials only. Credential validation remains
in the injected BankingService resolver; this server never accepts account-owner
references from request bodies and does not implement external payment settlement.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from banking_service import AuthenticationError, BankingService
from financial_ledger import (
    AccountAccessDenied,
    IdempotencyConflict,
    InsufficientFunds,
    LedgerError,
)

MAX_REQUEST_BYTES = 64 * 1024


class BankingAPIHandler(BaseHTTPRequestHandler):
    service: BankingService | None = None
    server_version = "ButterBankAPI/0.1"
    sys_version = ""

    def _send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _credential(self):
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1:
            raise AuthenticationError("exactly one bearer credential is required")
        scheme, separator, credential = headers[0].partition(" ")
        if scheme.lower() != "bearer" or not separator or not credential.strip():
            raise AuthenticationError("bearer credential required")
        return credential.strip()

    def _json_body(self):
        if len(self.headers.get_all("Content-Type", [])) != 1:
            raise ValueError("exactly one Content-Type is required")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        if self.headers.get_all("Transfer-Encoding", []):
            raise ValueError("Transfer-Encoding is not supported")
        if self.headers.get_all("Content-Encoding", []):
            raise ValueError("Content-Encoding is not supported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            raise ValueError("exactly one Content-Length is required")
        raw_length = lengths[0]
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise ValueError("invalid Content-Length")
        length = int(raw_length)
        if not 0 <= length <= MAX_REQUEST_BYTES:
            raise ValueError("request body exceeds the permitted size")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("incomplete request body")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object")
        return payload

    def _handle_errors(self, operation):
        try:
            operation()
        except AuthenticationError:
            self.close_connection = True
            self._send_json(401, {"error": "unauthorized"})
        except AccountAccessDenied:
            self.close_connection = True
            self._send_json(403, {"error": "forbidden"})
        except (InsufficientFunds, IdempotencyConflict):
            self.close_connection = True
            self._send_json(409, {"error": "conflict"})
        except (LedgerError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.close_connection = True
            self._send_json(400, {"error": "invalid_request"})
        except Exception:
            self.close_connection = True
            self._send_json(500, {"error": "internal_error"})

    def do_GET(self):
        def operation():
            credential = self._credential()
            parsed = urlsplit(self.path)
            if parsed.path == "/currencies":
                if parsed.query:
                    raise ValueError("query parameters are not supported on this route")
                self._send_json(200, {"currencies": self.service.currencies(credential)})
                return
            if parsed.path == "/accounts":
                if parsed.query:
                    raise ValueError("query parameters are not supported on this route")
                self._send_json(200, {"accounts": self.service.accounts(credential)})
                return
            parts = parsed.path.split("/")
            if len(parts) == 4 and parts[1] == "accounts" and parts[3] == "statement":
                query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
                if set(query) - {"limit"} or any(len(values) != 1 for values in query.values()):
                    raise ValueError("invalid statement query parameters")
                limit = int(query["limit"][0]) if "limit" in query else 100
                account_id = unquote(parts[2])
                statement = self.service.statement(credential, account_id, limit)
                self._send_json(200, statement)
                return
            self._send_json(404, {"error": "not_found"})

        self._handle_errors(operation)

    def do_POST(self):
        def operation():
            credential = self._credential()
            parsed = urlsplit(self.path)
            if parsed.query:
                raise ValueError("query parameters are not supported on POST routes")
            payload = self._json_body()
            if parsed.path == "/accounts":
                if set(payload) - {"currency_code", "account_type"}:
                    raise ValueError("unexpected account fields")
                if "currency_code" not in payload:
                    raise ValueError("currency_code is required")
                account_id = self.service.open_account(
                    credential,
                    payload["currency_code"],
                    payload.get("account_type", "deposit"),
                )
                self._send_json(201, {"account_id": account_id})
                return
            if parsed.path == "/transfers":
                allowed = {
                    "source_account_id", "destination_account_id",
                    "amount_minor", "idempotency_key", "description",
                }
                if set(payload) - allowed or not {
                    "source_account_id", "destination_account_id",
                    "amount_minor", "idempotency_key",
                } <= set(payload):
                    raise ValueError("invalid transfer fields")
                transaction_id = self.service.transfer(
                    credential,
                    payload["source_account_id"],
                    payload["destination_account_id"],
                    payload["amount_minor"],
                    payload["idempotency_key"],
                    payload.get("description", "Account transfer"),
                )
                self._send_json(200, {"transaction_id": transaction_id})
                return
            self._send_json(404, {"error": "not_found"})

        self._handle_errors(operation)

    def do_PUT(self):
        self._send_json(405, {"error": "method_not_allowed"})

    def do_PATCH(self):
        self._send_json(405, {"error": "method_not_allowed"})

    def do_DELETE(self):
        self._send_json(405, {"error": "method_not_allowed"})

    def log_message(self, format, *args):
        # Avoid writing request headers or account identifiers to default logs.
        return


def create_server(service: BankingService, host="127.0.0.1", port=8000):
    """Create a threaded API server; remote exposure requires a TLS proxy."""
    if not isinstance(service, BankingService):
        raise TypeError("service must be a BankingService")
    handler = type("ConfiguredBankingAPIHandler", (BankingAPIHandler,), {
        "service": service,
    })
    return ThreadingHTTPServer((host, port), handler)
