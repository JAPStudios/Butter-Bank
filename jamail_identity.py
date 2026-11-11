"""JaMail credential introspection for Butter Bank."""
from __future__ import annotations
import base64, json, os, time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

class IdentityProviderUnavailable(RuntimeError):
    """JaMail could not validate the credential."""

class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class JaMailIntrospectionResolver:
    """Resolve JaMail bearer tokens to stable JaMail account IDs.

    JaMail must return active, iss, aud, sub and exp fields, and calculate
    active using current token state, including revocation.
    """
    def __init__(self, endpoint, client_id, client_secret, issuer, audience,
                 timeout=3.0, transport=None, clock=time.time):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.netloc or
            parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ValueError("JaMail introspection endpoint must be an HTTPS URL")
        if any(not isinstance(v, str) or not v.strip()
               for v in (client_id, client_secret, issuer, audience)):
            raise ValueError("JaMail client credentials, issuer, and audience are required")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.endpoint, self.client_id, self.client_secret = endpoint, client_id, client_secret
        self.issuer, self.audience = issuer, audience
        self.timeout, self._clock = float(timeout), clock
        self._transport = transport or build_opener(_RejectRedirects()).open

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        keys = {
            "JAMAIL_INTROSPECTION_URL": env.get("JAMAIL_INTROSPECTION_URL"),
            "JAMAIL_INTROSPECTION_CLIENT_ID": env.get("JAMAIL_INTROSPECTION_CLIENT_ID"),
            "JAMAIL_INTROSPECTION_CLIENT_SECRET": env.get("JAMAIL_INTROSPECTION_CLIENT_SECRET"),
            "JAMAIL_ISSUER": env.get("JAMAIL_ISSUER"),
            "BUTTER_BANK_JAMAIL_AUDIENCE": env.get("BUTTER_BANK_JAMAIL_AUDIENCE"),
        }
        missing = [k for k, v in keys.items() if not v]
        if missing:
            raise ValueError("missing JaMail configuration: " + ", ".join(missing))
        return cls(keys["JAMAIL_INTROSPECTION_URL"], keys["JAMAIL_INTROSPECTION_CLIENT_ID"],
                   keys["JAMAIL_INTROSPECTION_CLIENT_SECRET"], keys["JAMAIL_ISSUER"],
                   keys["BUTTER_BANK_JAMAIL_AUDIENCE"])

    def __call__(self, credential):
        if not isinstance(credential, str) or not credential.strip():
            raise IdentityProviderUnavailable("JaMail credential is missing")
        basic = base64.b64encode((self.client_id + ":" + self.client_secret).encode()).decode("ascii")
        request = Request(
            self.endpoint,
            data=urlencode({"token": credential.strip(), "token_type_hint": "access_token"}).encode("ascii"),
            headers={"Authorization": "Basic " + basic,
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json", "Cache-Control": "no-store"},
            method="POST",
        )
        try:
            with self._transport(request, timeout=self.timeout) as response:
                raw = response.read(16 * 1024 + 1)
            if len(raw) > 16 * 1024:
                raise IdentityProviderUnavailable("JaMail response exceeded the permitted size")
            payload = json.loads(raw.decode("utf-8"))
        except IdentityProviderUnavailable:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeError) as exc:
            raise IdentityProviderUnavailable("JaMail credential validation failed") from exc
        except Exception as exc:
            raise IdentityProviderUnavailable("JaMail credential validation failed") from exc
        if not isinstance(payload, dict) or payload.get("active") is not True:
            raise IdentityProviderUnavailable("JaMail credential is inactive")
        if payload.get("iss") != self.issuer:
            raise IdentityProviderUnavailable("JaMail issuer did not match")
        aud = payload.get("aud")
        if not (aud == self.audience or isinstance(aud, list) and self.audience in aud):
            raise IdentityProviderUnavailable("JaMail audience did not match")
        subject, expiry = payload.get("sub"), payload.get("exp")
        if not isinstance(subject, str) or not subject.strip():
            raise IdentityProviderUnavailable("JaMail subject is invalid")
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or expiry <= self._clock():
            raise IdentityProviderUnavailable("JaMail credential has expired or has invalid expiry")
        return subject.strip()
