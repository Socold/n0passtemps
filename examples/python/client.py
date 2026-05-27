"""A small n0passtemps client, standard library only.

It covers the parts of the flow a server-side integration performs: resolving a
subject, TOTP enrolment and verification, recovery codes, the two server-side
halves of a WebAuthn ceremony, and the claim checks that go with verifying an
assertion.

The one thing it cannot finish is the Ed25519 signature check, because the
standard library has no Ed25519. AssertionVerifier therefore takes the raw
signature check as a callable and performs every other check itself, so the
parsing rules stay in one place whichever backend supplies the primitive.
verify_assertion.py passes in an implementation from the cryptography package.

Environment:
    N0PASSTEMPS_URL      the base URL, for example http://127.0.0.1:8080
    N0PASSTEMPS_API_KEY  an npt_ token minted by POST /admin/v1/api-keys
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

__all__ = [
    "ConfigurationError",
    "ProblemError",
    "AssertionInvalid",
    "Client",
    "AssertionVerifier",
    "b64url_decode",
    "b64url_encode",
    "jwk_thumbprint",
]

# The alphabet of RFC 4648 section 5, without the padding character. A JWS
# segment has exactly one valid encoding, and accepting a second one would let
# an attacker re-encode a captured header or payload into a different string
# that a laxer implementation would still read past the signature check.
_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


class ConfigurationError(Exception):
    """A required environment variable is unset or unusable."""


class ProblemError(Exception):
    """An RFC 9457 problem document returned by the service.

    The service deliberately keeps ``title`` and ``type`` to a class of failure
    and never explains why one particular request was refused, so ``detail`` is
    populated only for input validation and state conflicts. ``request_id`` is
    the one field a support exchange needs: it locates the log and audit entries
    where the real reason was written.
    """

    def __init__(self, status: int, document: Mapping[str, Any]) -> None:
        self.status = status
        self.type = str(document.get("type", ""))
        self.title = str(document.get("title", ""))
        self.detail = str(document.get("detail", ""))
        self.request_id = str(document.get("request_id", ""))
        self.retry_after_seconds = document.get("retry_after_seconds")
        self.document = dict(document)

        parts = [f"{status}", self.type or "(no type)", self.title or "(no title)"]
        if self.detail:
            parts.append(self.detail)
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        super().__init__(": ".join(parts))


class AssertionInvalid(Exception):
    """An assertion failed verification.

    Like the service's own verifier, this carries no indication of which check
    failed. Reporting it would tell an attacker whether a forged token had the
    right audience, whether a key identifier exists, or whether a captured token
    is merely expired rather than wrongly signed.
    """


def b64url_encode(raw: bytes) -> str:
    """Encode one compact serialisation segment: base64url, no padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Decode one compact serialisation segment, strictly.

    Padding is refused, characters outside the alphabet are refused, and the
    result is re-encoded and compared with the input so that a final quantum
    whose unused bits are not zero is refused as well. Those three together
    leave each segment exactly one valid spelling.
    """
    if not segment:
        raise ValueError("empty segment")
    if not set(segment) <= _B64URL_ALPHABET:
        raise ValueError("segment is not unpadded base64url")

    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    if b64url_encode(raw) != segment:
        raise ValueError("segment is not canonically encoded")
    return raw


def jwk_thumbprint(public_key: bytes) -> str:
    """Return the RFC 7638 thumbprint of an Ed25519 public key.

    RFC 7638 section 3 fixes the hash input as the JSON object of the required
    members only, with no whitespace and the member names in lexicographic
    order; RFC 8037 section 2 names those members for an OKP key. The
    construction has to be exact, because two implementations that disagree
    about it derive different identifiers for the same key.
    """
    encoded = b64url_encode(public_key)
    document = '{"crv":"Ed25519","kty":"OKP","x":"' + encoded + '"}'
    return b64url_encode(hashlib.sha256(document.encode("ascii")).digest())


class Client:
    """A thin wrapper over the /v1 surface."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: float = 10.0,
        ca_file: str | None = None,
    ) -> None:
        if not base_url:
            raise ConfigurationError("base_url is empty")

        # An empty api_key is allowed so that the JWKS route, which carries no
        # credential, can be reached by a verifier that holds none. Every other
        # method will be refused with a 401 without one.
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._ssl_context: ssl.SSLContext | None = None
        if ca_file:
            # An on-premise deployment commonly serves an internal certificate.
            # Trusting that one certificate is the supported way to reach it;
            # disabling verification would remove the only thing that
            # distinguishes the real service from anything on the same network.
            self._ssl_context = ssl.create_default_context(cafile=ca_file)

    @classmethod
    def from_env(cls, timeout: float = 10.0, require_api_key: bool = True) -> "Client":
        """Build a client from the shared environment variables.

        Pass require_api_key=False when only the JWKS route is needed, which is
        the case for a verifier: that route is unauthenticated, and asking a
        verifying party for a credential it has no use for would be asking it
        to hold one it should not.
        """
        base_url = os.environ.get("N0PASSTEMPS_URL", "").strip()
        api_key = os.environ.get("N0PASSTEMPS_API_KEY", "").strip()

        missing = []
        if not base_url:
            missing.append("N0PASSTEMPS_URL (for example http://127.0.0.1:8080)")
        if require_api_key and not api_key:
            missing.append(
                "N0PASSTEMPS_API_KEY (an npt_ token from POST /admin/v1/api-keys)"
            )
        if missing:
            raise ConfigurationError("unset: " + ", ".join(missing))

        return cls(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            ca_file=os.environ.get("N0PASSTEMPS_CA_FILE") or None,
        )

    # --- transport -----------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> Any:
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json"}

        if method in ("POST", "PUT", "PATCH"):
            # Every write route requires the JSON content type even when it
            # carries no body. A request without one is refused with 415, which
            # is what stops a form-encoded request being read as an empty JSON
            # object and treated as a request with no fields.
            headers["Content-Type"] = "application/json"
            data = json.dumps(body if body is not None else {}).encode("utf-8")

        if authenticated:
            headers["Authorization"] = "Bearer " + self.api_key

        request = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._ssl_context
            ) as response:
                return self._decode(response.status, response.read(), response.headers)
        except urllib.error.HTTPError as error:
            # HTTPError is itself a response, so the problem document is
            # readable from it.
            raise self._problem(error) from None

    def _decode(self, status: int, raw: bytes, headers: Any) -> Any:
        if not raw:
            return None
        content_type = (headers.get("Content-Type") or "").split(";")[0].strip()
        if content_type in ("application/json", "application/jwk-set+json"):
            return json.loads(raw.decode("utf-8"))
        return raw

    def _problem(self, error: urllib.error.HTTPError) -> Exception:
        raw = error.read()
        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            document = {"title": raw.decode("utf-8", "replace")[:200]}
        if not isinstance(document, dict):
            document = {"title": str(document)[:200]}
        return ProblemError(error.code, document)

    @staticmethod
    def _ref(subject_ref: str) -> str:
        """Percent-encode a subject reference for use in a path segment."""
        if not subject_ref:
            raise ValueError("subject_ref is empty")
        return urllib.parse.quote(subject_ref, safe="")

    # --- health and keys ----------------------------------------------

    def liveness(self) -> Any:
        """Read the unauthenticated probe.

        It answers 503 when the store is unreachable, which urlopen surfaces as
        a ProblemError even though the body is a liveness report rather than a
        problem document.
        """
        return self._request("GET", "/v1/health", authenticated=False)

    def health_detail(self) -> Any:
        return self._request("GET", "/v1/health/detail")

    def jwks(self) -> Any:
        """Fetch the JWK Set that verifies assertions.

        Unauthenticated, because the contents are public keys and an
        integrating application has to be able to fetch them in order to verify
        an assertion offline.
        """
        return self._request("GET", "/v1/.well-known/jwks.json", authenticated=False)

    # --- subjects ------------------------------------------------------

    def resolve_subject(self, subject_ref: str, display_name: str | None = None) -> Any:
        """Resolve a reference to a subject, creating it if needed.

        Idempotent, so it is safe to call on every login rather than tracking
        whether this service has seen the user before.
        """
        body: dict[str, Any] = {"subject_ref": subject_ref}
        if display_name:
            body["display_name"] = display_name
        return self._request("POST", "/v1/subjects", body)

    def get_subject(self, subject_ref: str) -> Any:
        return self._request("GET", f"/v1/subjects/{self._ref(subject_ref)}")

    # --- WebAuthn, server-side halves ---------------------------------

    def register_begin(self, subject_ref: str, label: str | None = None) -> Any:
        """Start a registration ceremony.

        The returned ``options`` go to the browser unchanged, and the
        ``PublicKeyCredential`` that comes back comes here unchanged. The
        subject must already exist; call resolve_subject first.
        """
        body: dict[str, Any] = {}
        if label:
            body["label"] = label
        return self._request(
            "POST", f"/v1/webauthn/{self._ref(subject_ref)}/register", body
        )

    def register_complete(
        self, subject_ref: str, challenge_id: str, credential: Mapping[str, Any]
    ) -> Any:
        return self._request(
            "POST",
            f"/v1/webauthn/{self._ref(subject_ref)}/register/complete",
            {"challenge_id": challenge_id, "credential": credential},
        )

    def assert_begin(self, subject_ref: str) -> Any:
        return self._request(
            "POST", f"/v1/webauthn/{self._ref(subject_ref)}/assert", {}
        )

    def assert_complete(
        self, subject_ref: str, challenge_id: str, credential: Mapping[str, Any]
    ) -> Any:
        return self._request(
            "POST",
            f"/v1/webauthn/{self._ref(subject_ref)}/assert/complete",
            {"challenge_id": challenge_id, "credential": credential},
        )

    # --- TOTP ----------------------------------------------------------

    def totp_enrol(self, subject_ref: str) -> Any:
        """Issue a TOTP secret.

        The seed and the provisioning URI are disclosed in this response and
        nowhere else. The secret is not usable until totp_confirm succeeds.
        """
        return self._request("POST", f"/v1/totp/{self._ref(subject_ref)}/enrol", {})

    def totp_confirm(self, subject_ref: str, code: str) -> Any:
        return self._request(
            "POST", f"/v1/totp/{self._ref(subject_ref)}/enrol/confirm", {"code": code}
        )

    def totp_verify(self, subject_ref: str, code: str) -> Any:
        """Authenticate with a TOTP code and receive a signed assertion."""
        return self._request(
            "POST", f"/v1/totp/{self._ref(subject_ref)}/verify", {"code": code}
        )

    # --- recovery codes ------------------------------------------------

    def recovery_issue(self, subject_ref: str) -> Any:
        """Issue a batch of single-use codes, retiring any unused earlier ones.

        The codes appear in this response and nowhere else. Present them to the
        user immediately; there is no operation that can show them again.
        """
        return self._request("POST", f"/v1/recovery/{self._ref(subject_ref)}/issue", {})

    def recovery_consume(self, subject_ref: str, code: str) -> Any:
        return self._request(
            "POST", f"/v1/recovery/{self._ref(subject_ref)}/consume", {"code": code}
        )


class AssertionVerifier:
    """Verifies an assertion against a JWK Set.

    Construct it with the set returned by Client.jwks and a signature check.
    The check receives the raw public key, the signing input and the signature,
    and returns True when the signature is valid; see verify_assertion.py.

    The order of the checks below is deliberate and mirrors the service's own
    verifier: nothing in the payload is parsed, let alone trusted, until the
    signature has been verified.
    """

    def __init__(
        self,
        jwks: Mapping[str, Any],
        expected_issuer: str,
        ed25519_verify: Callable[[bytes, bytes, bytes], bool],
        skew_seconds: int = 30,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not expected_issuer:
            # Fail closed. An empty expected issuer would accept a token from
            # any deployment.
            raise ValueError("expected_issuer is required")

        self.keys = self._load_keys(jwks)
        if not self.keys:
            raise ValueError("the JWK Set contains no usable Ed25519 signing key")

        self.expected_issuer = expected_issuer
        self.ed25519_verify = ed25519_verify
        self.skew_seconds = max(0, skew_seconds)
        self.now = now

    @staticmethod
    def _load_keys(jwks: Mapping[str, Any]) -> dict[str, bytes]:
        """Index the OKP keys of a JWK Set by key identifier.

        Anything that is not an Ed25519 signing key is skipped rather than
        rejected, so a deployment publishing an unrelated key alongside does not
        break verification. A key whose ``kid`` disagrees with its own
        thumbprint is skipped too: the service derives ``kid`` from the key, so
        a mismatch means the document was not produced the way this verifier
        expects.
        """
        keys: dict[str, bytes] = {}
        for entry in jwks.get("keys") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
                continue
            if entry.get("use") not in (None, "sig"):
                continue
            if entry.get("alg") not in (None, "EdDSA"):
                continue

            kid = entry.get("kid")
            encoded = entry.get("x")
            if not isinstance(kid, str) or not kid or not isinstance(encoded, str):
                continue
            try:
                public_key = b64url_decode(encoded)
            except ValueError:
                continue
            if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
                continue
            if jwk_thumbprint(public_key) != kid:
                continue

            keys[kid] = public_key
        return keys

    def verify(self, token: str, expected_audience: str) -> dict[str, Any]:
        """Verify an assertion and return its claims.

        expected_audience is the identifier of the API key the ceremony was
        performed for, which is the ``id`` of the key in
        ``GET /admin/v1/api-keys``. It is required: an empty audience would
        accept a token minted for any other key, which is the whole point of
        pinning it.
        """
        if not expected_audience:
            raise AssertionInvalid()

        # RFC 7515 section 7.1: the compact serialisation is exactly three
        # segments. Splitting on every full stop and requiring three rejects a
        # fourth segment, which a lenient parser would ignore while a second
        # recipient might read it, and rejects a two-segment unsecured JWS.
        parts = token.split(".")
        if len(parts) != 3:
            raise AssertionInvalid()

        try:
            header = json.loads(b64url_decode(parts[0]))
        except (ValueError, UnicodeDecodeError):
            raise AssertionInvalid() from None
        if not isinstance(header, dict):
            raise AssertionInvalid()

        # The algorithm is fixed here, never read from the token to decide what
        # to do. This single check stops the whole family of algorithm
        # confusion attacks: "alg":"none" with an empty signature, and
        # "alg":"HS256" with the published public key used as the HMAC secret.
        if header.get("alg") != "EdDSA":
            raise AssertionInvalid()

        # RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a
        # "crit" extension it does not understand. This verifier understands
        # none, so any "crit" at all is fatal.
        if header.get("crit"):
            raise AssertionInvalid()

        # A JWS signed by the same key for another purpose must not pass as an
        # assertion.
        if header.get("typ") not in (None, "", "JWT"):
            raise AssertionInvalid()

        # The key is selected by "kid", and one candidate only. Trying every
        # known key in turn would mean a token signed under a revoked key still
        # verifies as long as that key is in the set.
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AssertionInvalid()
        public_key = self.keys.get(kid)
        if public_key is None:
            raise AssertionInvalid()

        try:
            signature = b64url_decode(parts[2])
        except ValueError:
            raise AssertionInvalid() from None
        if len(signature) != ED25519_SIGNATURE_SIZE:
            raise AssertionInvalid()

        # The signature covers the header and the payload exactly as they were
        # received, which is why the encoded form is signed rather than any
        # re-serialisation of the parsed structures.
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        if not self.ed25519_verify(public_key, signing_input, signature):
            raise AssertionInvalid()

        # Only now is the payload worth parsing.
        try:
            claims = json.loads(b64url_decode(parts[1]))
        except (ValueError, UnicodeDecodeError):
            raise AssertionInvalid() from None
        if not isinstance(claims, dict):
            raise AssertionInvalid()

        if claims.get("iss") != self.expected_issuer:
            raise AssertionInvalid()
        if claims.get("aud") != expected_audience:
            raise AssertionInvalid()
        if not claims.get("sub") or not claims.get("amr"):
            raise AssertionInvalid()

        # "exp" is required. Treating a missing "exp" as no expiry turns a
        # captured assertion into a permanent credential.
        expires_at = claims.get("exp")
        if not isinstance(expires_at, int) or expires_at == 0:
            raise AssertionInvalid()

        now = self.now()
        if now > expires_at + self.skew_seconds:
            raise AssertionInvalid()

        not_before = claims.get("nbf")
        if isinstance(not_before, int) and not_before != 0:
            if now < not_before - self.skew_seconds:
                raise AssertionInvalid()

        return claims
