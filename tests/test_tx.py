import io
import unittest
from email.message import Message

from tx import read_limited_response


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
