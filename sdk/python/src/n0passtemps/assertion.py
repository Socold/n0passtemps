"""Offline verification of the signed assertion.

A successful ceremony returns a compact JWS (RFC 7515) signed with Ed25519
under the "EdDSA" algorithm of RFC 8037, carrying JWT claims (RFC 7519). The
integrating application verifies it against the public key the service
publishes as a JWK Set, so it does not have to trust the network path between
itself and the service.

The JWS is parsed here rather than through a JWT library. The format is a few
dozen lines, and the recurring vulnerabilities of those libraries have all been
on the parsing side: honouring the "none" algorithm, letting the token choose
which verification routine runs, or accepting a public key as an HMAC secret.
Verifier.verify refuses all three by construction, and mirrors, check for
check, the verifier the service runs against its own output.

Only the Ed25519 primitive is borrowed, from the ``cryptography`` package
(``pip install n0passtemps[verify]``).

Two duties stay with the caller, because they depend on state and policy this
package cannot see:

* enforce single use of ``jti``. An assertion stays valid until ``exp``, a
  minute or so, and within that window nothing here stops it being presented
  twice. Record each accepted ``jti`` until its ``exp`` has passed and refuse
  a repeat;
* check ``amr`` against the application's own policy. The verifier proves that
  the listed factors authenticated the subject; whether ``recovery-code``
  alone may open a session, or whether an operation needs ``webauthn-uv``, is
  for the application to decide.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
)

from .client import VERSION, _build_opener, _checked_url, _read_capped, _transport_error
from .errors import (
    InvalidAssertion,
    N0PasstempsError,
    ProtocolError,
    TransportError,
    VerificationUnavailable,
)

__all__ = [
    "Claims",
    "Risk",
    "KeySource",
    "StaticKeys",
    "RemoteJWKS",
    "Verifier",
    "InvalidAssertion",
    "VerificationUnavailable",
    "jwk_thumbprint",
    "parse_jwks",
]

_ALG = "EdDSA"
_TYP = "JWT"
_PUBLIC_KEY_SIZE = 32
_SIGNATURE_SIZE = 64

# An assertion from the service is a few hundred bytes. Anything far beyond
# that is not one, and is refused before any decoding work is spent on it.
_MAX_TOKEN_LENGTH = 8192

# The alphabet of RFC 4648 section 5, without the padding character.
_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

# The members RFC 8037 section 2 requires in the RFC 7638 thumbprint input of
# an OKP key.
_THUMBPRINT_MEMBERS = ("crv", "kty", "x")


# --- encoding ----------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    """Decode one compact serialisation segment, strictly.

    Padding is refused, characters outside the alphabet are refused, and the
    result is re-encoded and compared with the input so that a final quantum
    whose unused bits are not zero is refused as well. Together they leave each
    segment exactly one valid spelling. A lenient decoder would let an attacker
    re-encode a captured header or payload into a different string that still
    carries the same bytes past a second, laxer implementation.

    The standard library decoder cannot be used directly: it silently discards
    characters outside the alphabet and tolerates stray padding.
    """
    if not segment or not set(segment) <= _B64URL_ALPHABET:
        raise ValueError("not unpadded base64url")
    if len(segment) % 4 == 1:
        raise ValueError("impossible base64url length")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if _b64url_encode(raw) != segment:
        raise ValueError("not canonically encoded")
    return raw


def _refuse_constant(_: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


def _unique_members(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    # json.loads keeps the last of two members with the same name. Two parsers
    # that disagree on which one wins can be shown two different tokens, so a
    # duplicate is refused outright.
    document: Dict[str, Any] = {}
    for name, value in pairs:
        if name in document:
            raise ValueError("duplicate member")
        document[name] = value
    return document


def _parse_object(segment: str) -> Dict[str, Any]:
    document = json.loads(
        _b64url_decode(segment).decode("utf-8"),
        object_pairs_hook=_unique_members,
        parse_constant=_refuse_constant,
    )
    if not isinstance(document, dict):
        raise ValueError("not a JSON object")
    return document


def _numeric_date(value: Any) -> Optional[int]:
    """Return an integer NumericDate, or None for anything else.

    bool is excluded by hand because it is a subclass of int in Python, and
    ``"exp": true`` must not read as one second past the epoch.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


# --- keys --------------------------------------------------------------------


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Return the RFC 7638 SHA-256 thumbprint of an OKP JWK, base64url encoded.

    The hash input is the JSON object of the required members only, with no
    whitespace and the member names in lexicographic order. The construction
    has to be exact, because two implementations that disagree about it derive
    different identifiers for the same key. The service uses this value as the
    ``kid`` of every key it publishes.

    Only the OKP key type is handled, because Ed25519 keys are the only ones
    this package ever meets; the required members differ for other types.
    Raises ValueError for another ``kty`` or a missing member.
    """
    if jwk.get("kty") != "OKP":
        raise ValueError("only OKP keys are supported")
    required: Dict[str, str] = {}
    for name in _THUMBPRINT_MEMBERS:
        value = jwk.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError("the JWK member " + name + " is missing or not a string")
        required[name] = value
    canonical = json.dumps(
        required, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    )
    return _b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def parse_jwks(document: Mapping[str, Any]) -> Dict[str, bytes]:
    """Index the Ed25519 signing keys of a JWK Set by ``kid``.

    Anything that is not an Ed25519 signing key is skipped rather than
    rejected, so a deployment publishing an unrelated key alongside does not
    break verification. A key whose ``kid`` disagrees with its own thumbprint
    is skipped too: the service derives ``kid`` from the key, so a mismatch
    means the document was not produced the way this verifier expects.
    """
    keys: Dict[str, bytes] = {}
    entries = document.get("keys") if isinstance(document, Mapping) else None
    if not isinstance(entries, list):
        return keys
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        if entry.get("use") not in (None, "sig") or entry.get("alg") not in (None, _ALG):
            continue
        kid = entry.get("kid")
        encoded = entry.get("x")
        if not isinstance(kid, str) or not kid or not isinstance(encoded, str):
            continue
        try:
            public_key = _b64url_decode(encoded)
        except ValueError:
            continue
        if len(public_key) != _PUBLIC_KEY_SIZE or jwk_thumbprint(entry) != kid:
            continue
        keys[kid] = public_key
    return keys


class KeySource(Protocol):
    """Where a Verifier looks a public key up.

    ``get`` returns the raw 32-byte Ed25519 public key for a ``kid``, or None
    when the source does not know it. It receives a ``kid`` taken from an
    unverified token, so an implementation must treat it as hostile input.
    """

    def get(self, kid: str) -> Optional[bytes]: ...


class StaticKeys:
    """A fixed set of keys, from a JWK Set document held by the application.

    The right choice when the keys are pinned in configuration, and the one
    that keeps verification free of any network dependency. A key rotation on
    the service then needs a configuration change here.
    """

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self._keys = parse_jwks(jwks)
        if not self._keys:
            raise ValueError("the JWK Set contains no usable Ed25519 signing key")

    @classmethod
    def from_public_keys(cls, public_keys: Iterable[bytes]) -> "StaticKeys":
        """Build the set from raw 32-byte public keys; each ``kid`` is derived."""
        entries = []
        for public_key in public_keys:
            if len(public_key) != _PUBLIC_KEY_SIZE:
                raise ValueError("an Ed25519 public key is 32 bytes")
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(bytes(public_key))}
            jwk["kid"] = jwk_thumbprint(jwk)
            entries.append(jwk)
        return cls({"keys": entries})

    def get(self, kid: str) -> Optional[bytes]:
        return self._keys.get(kid)

    def key_ids(self) -> Tuple[str, ...]:
        return tuple(self._keys)


class RemoteJWKS:
    """Keys fetched from the service's JWKS endpoint and cached.

    ``url`` is normally ``<base_url>/v1/.well-known/jwks.json``. The route is
    unauthenticated, so no API key is involved.

    The set is refetched when it is older than ``cache_seconds``, and once more
    when a token names a ``kid`` that is not in it, which is how a rotated key
    is picked up without waiting for the cache to lapse. That second path is
    driven by unverified input: anybody can mint tokens with random ``kid``
    values. ``min_refetch_interval`` therefore bounds the fetches, whatever
    their cause, to one per interval, so the verifier cannot be turned into a
    request amplifier aimed at the service.

    Failure policy: while the cached set is within ``cache_seconds``, a failed
    refetch leaves it in use and the unknown ``kid`` is an invalid assertion.
    Once it has lapsed, a failed fetch raises TransportError rather than
    trusting keys of unknown age; the service may have withdrawn one. The
    failure is remembered for ``min_refetch_interval``, so an outage of the
    endpoint does not become one fetch per verification either.

    The URL must be https unless the host is loopback, for the same reason as
    the client's base URL, with higher stakes: whoever can rewrite this
    response chooses the keys that assertions are checked against.
    """

    def __init__(
        self,
        url: str,
        cache_seconds: float = 300,
        min_refetch_interval: float = 10,
        *,
        timeout: float = 10.0,
        allow_insecure_transport: bool = False,
        ca_file: Optional[str] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min_refetch_interval < 0 or cache_seconds < min_refetch_interval:
            # A cache that lapses faster than it may be refilled would spend
            # part of every interval with no usable keys.
            raise ValueError(
                "min_refetch_interval must not be negative, and cache_seconds "
                "must be at least min_refetch_interval"
            )
        self._url = _checked_url(url, allow_insecure_transport, "url")
        self._cache_seconds = float(cache_seconds)
        self._min_refetch_interval = float(min_refetch_interval)
        self._timeout = float(timeout)
        self._clock = clock
        self._opener = _build_opener(ca_file)

        # The lock also serialises fetches, so a burst of concurrent
        # verifications after a rotation produces one request, not one each.
        self._lock = threading.Lock()
        self._keys: Dict[str, bytes] = {}
        self._fetched_at: Optional[float] = None
        self._attempted_at: Optional[float] = None
        self._last_failure = ""

    def __repr__(self) -> str:
        return "RemoteJWKS(url=" + repr(self._url) + ")"

    def get(self, kid: str) -> Optional[bytes]:
        with self._lock:
            now = self._clock()
            fresh = (
                self._fetched_at is not None
                and now - self._fetched_at < self._cache_seconds
            )
            if fresh and kid in self._keys:
                return self._keys[kid]

            may_fetch = (
                self._attempted_at is None
                or now - self._attempted_at >= self._min_refetch_interval
            )
            if may_fetch:
                self._attempted_at = now
                try:
                    self._keys = self._fetch()
                    self._fetched_at = now
                    self._last_failure = ""
                    fresh = True
                except N0PasstempsError as error:
                    self._last_failure = str(error)

            if not fresh:
                raise TransportError(
                    "the JWK Set could not be refreshed: " + self._last_failure
                )
            return self._keys.get(kid)

    def _fetch(self) -> Dict[str, bytes]:
        request = urllib.request.Request(
            self._url,
            headers={
                "Accept": "application/jwk-set+json, application/json",
                "User-Agent": "n0passtemps-python/" + VERSION,
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = _read_capped(response)
        except N0PasstempsError:
            raise
        except urllib.error.HTTPError as error:
            error.close()
            raise TransportError(
                "the JWKS endpoint answered " + str(error.code)
            ) from None
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            raise _transport_error(error) from None

        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            raise ProtocolError("the JWKS response is not valid JSON") from None
        keys = parse_jwks(document) if isinstance(document, dict) else {}
        if not keys:
            # An empty set is treated as a failed fetch rather than cached: it
            # would otherwise refuse every assertion for a full cache period.
            raise ProtocolError("the JWKS response holds no usable Ed25519 signing key")
        return keys


# --- signature primitive -----------------------------------------------------

_SignatureCheck = Callable[[bytes, bytes, bytes], bool]


def _load_ed25519() -> _SignatureCheck:
    """Return an Ed25519 check backed by the ``cryptography`` package.

    The import is deferred so that the rest of the SDK stays usable without the
    optional dependency, and so that its absence is reported in a sentence
    rather than as a traceback from the top of a module.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise VerificationUnavailable(
            "verifying an assertion needs the Ed25519 primitive of the "
            "'cryptography' package, which is not installed: "
            "pip install n0passtemps[verify]"
        ) from None

    def check(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    return check


# --- verifier ----------------------------------------------------------------


@dataclass(frozen=True)
class Risk:
    """What the service made of the ceremony, from the ``risk`` claim.

    It is a report and never a refusal: the service verified the ceremony
    before signing it, so ``level == "high"`` is not a failed authentication.
    What to do about it belongs to the application, which knows what the user
    is about to do.

    ``level`` is ``"low"``, ``"elevated"`` or ``"high"``. ``reasons`` names
    every signal that fired, in a fixed order; the set is closed and
    documented in docs/RISK.md, but a deployment newer than this library may
    report a member it does not know, so do not treat the list as exhaustive.
    ``score`` is the total weight, carried so a decision can be explained
    rather than so applications can invent their own thresholds.
    """

    level: str
    reasons: Tuple[str, ...]
    score: int


def _risk_from_claim(value: Any) -> Optional[Risk]:
    """Read the ``risk`` claim, refusing one that is present but malformed.

    A claim absent from the token yields ``None``, which means the deployment
    does not report risk. That is deliberately not the same as a low
    assessment: an application that steps up must handle the absent case
    explicitly, or disabling the feature would silently turn every step-up
    off.

    A claim that is present but the wrong shape invalidates the assertion.
    Dropping it to ``None`` instead would present "risk was not reported" to
    an application when risk *was* reported, which fails open on exactly the
    signal the application asked for. Unknown members are ignored, so a
    service that adds a field does not break this library.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidAssertion()

    level = value.get("level")
    reasons = value.get("reasons", [])
    score = value.get("score", 0)

    if not isinstance(level, str) or not level:
        raise InvalidAssertion()
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        raise InvalidAssertion()
    # bool is a subclass of int, and a boolean score is a malformed one.
    if not isinstance(score, int) or isinstance(score, bool):
        raise InvalidAssertion()

    return Risk(level=level, reasons=tuple(reasons), score=score)


@dataclass(frozen=True)
class Claims:
    """The verified claims of an assertion.

    The dates are seconds since the Unix epoch, exactly as signed. ``subject``
    is the service's internal subject identifier (the ``subject_id`` of the
    API), not the caller's own reference. ``amr`` lists the factors that
    authenticated the subject: ``webauthn``, ``webauthn-uv`` (the authenticator
    also verified the user with a PIN or a biometric), ``totp``,
    ``recovery-code``. ``risk`` is present only when the deployment reports
    risk; see :class:`Risk`.
    """

    issuer: str
    subject: str
    audience: str
    expires_at: int
    not_before: Optional[int]
    issued_at: Optional[int]
    jti: str
    amr: Tuple[str, ...]
    credential_id: Optional[str]
    tenant_id: Optional[str]
    risk: Optional[Risk]
    raw: Dict[str, Any] = field(repr=False, compare=False)


class Verifier:
    """Verifies assertions for one issuer and one audience.

    ``issuer`` is the ``iss`` the deployment is configured with. ``audience``
    is the identifier of the API key the ceremonies are performed with (the
    ``id`` of the key in the administration API); pinning it is what stops an
    assertion minted for another integration being presented to this one. Both
    are required, so that leaving one out fails at construction instead of
    quietly accepting everything.

    ``clock_skew`` is the tolerance, in seconds, applied to ``exp`` and
    ``nbf``. It absorbs clock drift between the service and the verifier and
    nothing more: it extends the life of every token, so keep it well below
    the assertion lifetime.

    The caller must still enforce single use of ``jti`` and check ``amr``
    against its own policy; see the module documentation.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        keys: KeySource,
        *,
        clock_skew: float = 30,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer is required")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience is required")
        if clock_skew < 0:
            raise ValueError("clock_skew must not be negative")

        # Resolved now rather than on first use, so that a deployment missing
        # the optional dependency fails when it starts, not at the first login.
        self._check_signature = _load_ed25519()
        self._issuer = issuer
        self._audience = audience
        self._keys = keys
        self._clock_skew = clock_skew
        self._now = now

    def verify(self, token: str) -> Claims:
        """Verify an assertion and return its claims.

        Every failure raises InvalidAssertion with no further detail; see that
        class. The one exception is a key source that cannot reach its
        endpoint, which raises TransportError: that is an outage of the
        verifier's own dependencies, not a property of the token.

        The order of the checks is deliberate: nothing in the payload is
        parsed, let alone trusted, until the signature has been verified.
        """
        try:
            return self._verify(token)
        except (ValueError, RecursionError):
            # Malformed base64url, UTF-8 or JSON anywhere in the token,
            # including a header nested deeply enough to exhaust the parser.
            raise InvalidAssertion() from None

    def _verify(self, token: str) -> Claims:
        if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH:
            raise InvalidAssertion()

        # RFC 7515 section 7.1: the compact serialisation is exactly three
        # segments. Splitting on every full stop and requiring three rejects a
        # fourth segment, which a lenient parser would ignore while a second
        # recipient might read it, and rejects a two-segment unsecured JWS.
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidAssertion()

        header = _parse_object(parts[0])

        # The algorithm is fixed here and never read from the token to decide
        # what to do. This single comparison stops the whole family of
        # algorithm confusion attacks: "alg":"none" with an empty signature,
        # and "alg":"HS256" with the published public key used as the HMAC
        # secret. Both end here, before any key is looked up.
        if header.get("alg") != _ALG:
            raise InvalidAssertion()

        # RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a
        # "crit" extension it does not understand. This verifier understands
        # none, so the mere presence of the member is fatal. Ignoring it would
        # let an attacker attach a header that a stricter verifier acts on
        # while this one does not.
        if "crit" in header:
            raise InvalidAssertion()

        # A JWS signed by the same key for another purpose must not pass as an
        # assertion.
        if header.get("typ", _TYP) not in ("", _TYP):
            raise InvalidAssertion()

        # The key is selected by "kid", and one candidate only. Trying every
        # known key in turn would let a token signed under a withdrawn key
        # verify for as long as that key lingers in a set, and would make the
        # cost of a failure grow with the size of the set.
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidAssertion()
        public_key = self._keys.get(kid)
        if public_key is None or len(public_key) != _PUBLIC_KEY_SIZE:
            raise InvalidAssertion()

        signature = _b64url_decode(parts[2])
        if len(signature) != _SIGNATURE_SIZE:
            raise InvalidAssertion()

        # The signature covers the header and the payload exactly as they were
        # received, which is why the encoded form is checked rather than any
        # re-serialisation of the parsed structures.
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        if not self._check_signature(public_key, signing_input, signature):
            raise InvalidAssertion()

        # Only now is the payload worth parsing.
        claims = _parse_object(parts[1])

        if claims.get("iss") != self._issuer:
            raise InvalidAssertion()
        # "aud" must be the one expected string. The service never issues the
        # array form, and "is a member of" is a weaker test than "is".
        if claims.get("aud") != self._audience:
            raise InvalidAssertion()

        subject = claims.get("sub")
        amr = claims.get("amr")
        if not isinstance(subject, str) or not subject:
            raise InvalidAssertion()
        if not isinstance(amr, list) or not amr:
            raise InvalidAssertion()
        if not all(isinstance(factor, str) and factor for factor in amr):
            raise InvalidAssertion()

        # "exp" is required. Treating a missing "exp" as "no expiry" turns a
        # captured assertion into a permanent credential.
        expires_at = _numeric_date(claims.get("exp"))
        if expires_at is None or expires_at <= 0:
            raise InvalidAssertion()

        now = self._now()
        if now > expires_at + self._clock_skew:
            raise InvalidAssertion()

        not_before: Optional[int] = None
        if "nbf" in claims:
            not_before = _numeric_date(claims["nbf"])
            if not_before is None:
                raise InvalidAssertion()
            if now < not_before - self._clock_skew:
                raise InvalidAssertion()

        issued_at: Optional[int] = None
        if "iat" in claims:
            issued_at = _numeric_date(claims["iat"])
            if issued_at is None:
                raise InvalidAssertion()

        # The service always sets "jti". It is required here because the
        # caller's replay cache is keyed on it, and a token without one could
        # not be bound to single use.
        jti = claims.get("jti")
        credential_id = claims.get("cid")
        tenant_id = claims.get("tid")
        if not isinstance(jti, str) or not jti:
            raise InvalidAssertion()
        if credential_id is not None and not isinstance(credential_id, str):
            raise InvalidAssertion()
        if tenant_id is not None and not isinstance(tenant_id, str):
            raise InvalidAssertion()

        return Claims(
            issuer=self._issuer,
            subject=subject,
            audience=self._audience,
            expires_at=expires_at,
            not_before=not_before,
            issued_at=issued_at,
            jti=jti,
            amr=tuple(amr),
            credential_id=credential_id or None,
            tenant_id=tenant_id or None,
            risk=_risk_from_claim(claims.get("risk")),
            raw=claims,
        )
