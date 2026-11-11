import base64, json, unittest
from io import BytesIO
from urllib.parse import parse_qs
from jamail_identity import IdentityProviderUnavailable, JaMailIntrospectionResolver

class FakeResponse(BytesIO):
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class JaMailIntrospectionTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"active": True, "iss": "https://identity.jamail.net",
                        "aud": ["butter-bank"], "sub": "jamail-account-42", "exp": 2000}
        self.requests = []
        def transport(request, timeout):
            self.requests.append((request, timeout))
            return FakeResponse(json.dumps(self.payload).encode())
        self.resolver = JaMailIntrospectionResolver(
            "https://identity.jamail.net/oauth/introspect", "butter-bank-service",
            "test-client-secret", "https://identity.jamail.net", "butter-bank",
            timeout=2, transport=transport, clock=lambda: 1000)

    def test_resolves_subject_and_authenticates_client(self):
        self.assertEqual(self.resolver("opaque-session-token"), "jamail-account-42")
        request, timeout = self.requests[0]
        self.assertEqual(timeout, 2)
        self.assertEqual(request.get_method(), "POST")
        expected = "Basic " + base64.b64encode(b"butter-bank-service:test-client-secret").decode()
        self.assertEqual(request.get_header("Authorization"), expected)
        self.assertEqual(parse_qs(request.data.decode()),
                         {"token": ["opaque-session-token"], "token_type_hint": ["access_token"]})

    def test_accepts_string_audience(self):
        self.payload["aud"] = "butter-bank"
        self.assertEqual(self.resolver("token"), "jamail-account-42")

    def test_rejects_inactive_wrong_issuer_and_wrong_audience(self):
        cases = [{"active": False}, {"iss": "https://wrong.example"}, {"aud": ["other"]}]
        for change in cases:
            original = self.payload.copy()
            self.payload.update(change)
            with self.subTest(change=change), self.assertRaises(IdentityProviderUnavailable):
                self.resolver("token")
            self.payload = original

    def test_rejects_expired_and_missing_subject(self):
        self.payload["exp"] = 999
        with self.assertRaises(IdentityProviderUnavailable): self.resolver("token")
        self.payload["exp"] = 2000
        self.payload["sub"] = ""
        with self.assertRaises(IdentityProviderUnavailable): self.resolver("token")

    def test_requires_https_and_complete_environment(self):
        with self.assertRaises(ValueError):
            JaMailIntrospectionResolver("http://identity.jamail.net/introspect",
                                        "id", "secret", "issuer", "audience")
        with self.assertRaises(ValueError):
            JaMailIntrospectionResolver.from_env({})

    def test_fails_closed_on_provider_error(self):
        def failed(request, timeout): raise OSError("offline")
        resolver = JaMailIntrospectionResolver(
            "https://identity.jamail.net/oauth/introspect", "id", "secret",
            "https://identity.jamail.net", "butter-bank", transport=failed)
        with self.assertRaises(IdentityProviderUnavailable): resolver("token")

if __name__ == "__main__": unittest.main()
