import io
import unittest
from email.message import Message

from tx import read_limited_response, validate_node_url


class WalletNodeUrlTests(unittest.TestCase):
    def test_local_http_and_remote_https_are_allowed(self):
        self.assertEqual(validate_node_url("http://127.0.0.1:8333/"), "http://127.0.0.1:8333")
        self.assertEqual(validate_node_url("http://localhost:8333"), "http://localhost:8333")
        self.assertEqual(validate_node_url("https://node.example:8333/"), "https://node.example:8333")

    def test_remote_http_and_urls_with_credentials_or_paths_are_rejected(self):
        for value in (
            "http://node.example:8333",
            "http://user:secret@127.0.0.1:8333",
            "https://node.example:8333/api",
            "https://node.example:8333?debug=1",
            "ftp://node.example:8333",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_node_url(value)


class BoundedNodeResponseTests(unittest.TestCase):
    class Response(io.BytesIO):
        def __init__(self, body, headers=None):
            super().__init__(body)
            self.headers = headers or Message()

    def test_reads_complete_response_within_limit(self):
        headers = Message()
        headers.add_header("Content-Length", "8")
        response = self.Response(b'{"ok":1}', headers)
        self.assertEqual(read_limited_response(response, 8), b'{"ok":1}')

    def test_rejects_oversized_declared_and_actual_responses(self):
        headers = Message()
        headers.add_header("Content-Length", "9")
        with self.assertRaisesRegex(ValueError, "exceeds size limit"):
            read_limited_response(self.Response(b'{"ok":1}', headers), 8)
        with self.assertRaisesRegex(ValueError, "exceeds size limit"):
            read_limited_response(self.Response(b'{"ok":1}'), 7)

    def test_rejects_duplicate_and_truncated_content_lengths(self):
        headers = Message()
        headers.add_header("Content-Length", "8")
        headers.add_header("Content-Length", "8")
        with self.assertRaisesRegex(ValueError, "duplicate response Content-Length"):
            read_limited_response(self.Response(b'{"ok":1}', headers))
        headers = Message()
        headers.add_header("Content-Length", "9")
        with self.assertRaisesRegex(ValueError, "incomplete node response"):
            read_limited_response(self.Response(b'{"ok":1}', headers))


if __name__ == "__main__":
    unittest.main()
