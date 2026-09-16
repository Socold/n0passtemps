"""Tests of assertion verification and of the key sources.

The encoding, thumbprint and key source tests need nothing beyond the standard
library. The Verifier tests sign real tokens, which needs the ``cryptography``
package; without it they are skipped with a message saying so.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import unittest
from typing import Any, Dict, List, Optional
from unittest import mock

from support import Recorded, RecordingServer, Reply, closed_port, json_reply

from n0passtemps import (
    Claims,
    ConfigurationError,
    InvalidAssertion,
    N0PasstempsError,
    RemoteJWKS,
    StaticKeys,
    TransportError,
    VerificationUnavailable,
    Verifier,
    jwk_thumbprint,
    parse_jwks,
)
from n0passtemps.assertion import _b64url_decode

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

NEEDS_CRYPTOGRAPHY = unittest.skipUnless(
    HAVE_CRYPTOGRAPHY,
    "the 'cryptography' package is not installed, so no Ed25519 signature can "
    "be made or checked: pip install n0passtemps[verify]",
)

ISSUER = "n0passtemps"
AUDIENCE = "4f0c7a52-0d3e-4a0e-9f4e-8a4f1f6f2b10"
NOW = 1_800_000_000

# RFC 8037 appendix A.2 and A.3.
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def segment(document: Any) -> str:
    return b64(json.dumps(document, separators=(",", ":")).encode("utf-8"))


def jwk_for(public_key: bytes) -> Dict[str, str]:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(public_key), "use": "sig", "alg": "EdDSA"}
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


class CountingKeys:
    """A key source that records every kid it is asked for."""

    def __init__(self, inner: StaticKeys) -> None:
        self.inner = inner
        self.asked: List[str] = []

    def get(self, kid: str) -> Optional[bytes]:
        self.asked.append(kid)
        return self.inner.get(kid)


class EncodingTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        for raw in (b"a", b"ab", b"abc", b"\xff\xfe\xfd\xfc", bytes(range(64))):
            self.assertEqual(_b64url_decode(b64(raw)), raw)

    def test_padding_is_refused(self) -> None:
        for text in ("YQ==", "YWI=", "YQ=", "="):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    _b64url_decode(text)

    def test_foreign_characters_are_refused(self) -> None:
        # The standard library decoder drops these silently, which is exactly
        # the leniency being ruled out. "+" and "/" belong to the other base64
        # alphabet.
        for text in ("", "YW Jj", "YWJj\n", "YW+j", "YW/j", "YWJj.", "YWJjé"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    _b64url_decode(text)

    def test_non_canonical_trailing_bits_are_refused(self) -> None:
        # "YQ" and "YR" both decode to b"a" under a lenient decoder: the last
        # character carries four bits that are not part of the data.
        self.assertEqual(base64.urlsafe_b64decode("YR=="), b"a")
        self.assertEqual(_b64url_decode("YQ"), b"a")
        with self.assertRaises(ValueError):
            _b64url_decode("YR")
        with self.assertRaises(ValueError):
            _b64url_decode("YWJ")  # b"ab" is "YWI"

    def test_impossible_length_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            _b64url_decode("YWJjZ")


class ThumbprintTests(unittest.TestCase):
    def test_rfc8037_a3_vector(self) -> None:
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X}
        self.assertEqual(jwk_thumbprint(jwk), RFC8037_THUMBPRINT)

    def test_only_the_required_members_are_hashed(self) -> None:
        jwk = {
            "x": RFC8037_X, "use": "sig", "kid": "whatever", "alg": "EdDSA",
            "crv": "Ed25519", "kty": "OKP", "d": "must never matter",
        }
        self.assertEqual(jwk_thumbprint(jwk), RFC8037_THUMBPRINT)

    def test_unusable_keys(self) -> None:
        for jwk in (
            {},
            {"kty": "RSA", "n": "AQAB", "e": "AQAB"},
            {"kty": "OKP", "crv": "Ed25519"},
            {"kty": "OKP", "crv": "Ed25519", "x": 5},
            {"kty": "OKP", "crv": "", "x": RFC8037_X},
        ):
            with self.subTest(jwk=jwk):
                with self.assertRaises(ValueError):
                    jwk_thumbprint(jwk)


class JWKSParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.public_key = _b64url_decode(RFC8037_X)
        self.good = jwk_for(self.public_key)

    def test_a_published_set_is_indexed_by_kid(self) -> None:
        self.assertEqual(self.good["kid"], RFC8037_THUMBPRINT)
        self.assertEqual(parse_jwks({"keys": [self.good]}), {RFC8037_THUMBPRINT: self.public_key})

    def test_unrelated_and_inconsistent_keys_are_skipped(self) -> None:
        bad = [
            "not an object",
            {"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB"},
            dict(self.good, crv="X25519"),
            dict(self.good, use="enc"),
            dict(self.good, alg="HS256"),
            dict(self.good, kid="not-the-thumbprint"),
            dict(self.good, kid=""),
            dict(self.good, x=self.good["x"] + "="),
            {k: v for k, v in self.good.items() if k != "kid"},
        ]
        short = {"kty": "OKP", "crv": "Ed25519", "x": b64(b"\x01" * 31)}
        short["kid"] = jwk_thumbprint(short)
        bad.append(short)
        self.assertEqual(parse_jwks({"keys": bad}), {})
        self.assertEqual(list(parse_jwks({"keys": bad + [self.good]})), [RFC8037_THUMBPRINT])

    def test_a_malformed_document_has_no_keys(self) -> None:
        documents: List[Dict[str, Any]] = [{}, {"keys": None}, {"keys": "x"}, {"keys": {}}]
        for document in documents:
            self.assertEqual(parse_jwks(document), {})

    def test_static_keys(self) -> None:
        keys = StaticKeys({"keys": [self.good]})
        self.assertEqual(keys.get(RFC8037_THUMBPRINT), self.public_key)
        self.assertIsNone(keys.get("unknown"))
        self.assertEqual(keys.key_ids(), (RFC8037_THUMBPRINT,))
        with self.assertRaises(ValueError):
            StaticKeys({"keys": []})

    def test_static_keys_from_raw_public_keys(self) -> None:
        keys = StaticKeys.from_public_keys([self.public_key])
        self.assertEqual(keys.key_ids(), (RFC8037_THUMBPRINT,))
        with self.assertRaises(ValueError):
            StaticKeys.from_public_keys([b"short"])


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class RemoteJWKSTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = RecordingServer()
        self.addCleanup(self.server.close)
        self.first = jwk_for(b"\x01" * 32)
        self.second = jwk_for(b"\x02" * 32)
        self.publish(self.first)
        self.clock = FakeClock()
        self.source = RemoteJWKS(
            self.server.url + "/v1/.well-known/jwks.json",
            cache_seconds=300,
            min_refetch_interval=10,
            clock=self.clock,
        )

    def publish(self, *jwks: Dict[str, str]) -> None:
        self.server.reply = json_reply(
            200, {"keys": list(jwks)}, {"Content-Type": "application/jwk-set+json"}
        )

    def fetches(self) -> int:
        return len(self.server.requests)

    def test_the_request(self) -> None:
        self.source.get(self.first["kid"])
        seen = self.server.requests[0]
        self.assertEqual(seen.method, "GET")
        self.assertEqual(seen.target, "/v1/.well-known/jwks.json")
        self.assertNotIn("authorization", seen.headers)
        self.assertTrue(seen.headers["user-agent"].startswith("n0passtemps-python/"))

    def test_the_set_is_cached(self) -> None:
        for _ in range(20):
            self.assertEqual(self.source.get(self.first["kid"]), b"\x01" * 32)
            self.clock.advance(14)
        self.assertEqual(self.fetches(), 1)

    def test_the_set_is_refetched_once_the_cache_lapses(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(299)
        self.source.get(self.first["kid"])
        self.assertEqual(self.fetches(), 1)
        self.clock.advance(1)
        self.source.get(self.first["kid"])
        self.assertEqual(self.fetches(), 2)

    def test_an_unknown_kid_triggers_one_refetch_and_finds_a_rotated_key(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(60)
        self.publish(self.first, self.second)
        self.assertEqual(self.source.get(self.second["kid"]), b"\x02" * 32)
        self.assertEqual(self.fetches(), 2)
        # Now known, so no further fetch.
        self.source.get(self.second["kid"])
        self.assertEqual(self.fetches(), 2)

    def test_a_withdrawn_key_disappears_on_refetch(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(300)
        self.publish(self.second)
        self.assertIsNone(self.source.get(self.first["kid"]))

    def test_random_kids_cannot_amplify_requests(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(60)
        for index in range(200):
            self.assertIsNone(self.source.get("random-kid-" + str(index)))
        # One refetch for the first unknown kid, none for the other 199.
        self.assertEqual(self.fetches(), 2)

        self.clock.advance(9.9)
        self.source.get("still-too-soon")
        self.assertEqual(self.fetches(), 2)

        self.clock.advance(0.1)
        self.source.get("interval-elapsed")
        self.assertEqual(self.fetches(), 3)

        # Known keys stay served from the cache throughout.
        self.assertEqual(self.source.get(self.first["kid"]), b"\x01" * 32)
        self.assertEqual(self.fetches(), 3)

    def test_the_first_lookup_counts_towards_the_limit(self) -> None:
        self.assertIsNone(self.source.get("unknown"))
        self.assertIsNone(self.source.get("unknown-too"))
        self.assertEqual(self.fetches(), 1)

    def test_a_failed_refetch_keeps_a_fresh_set_in_use(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(60)
        self.server.reply = (500, {}, b"")
        self.assertIsNone(self.source.get("unknown"))
        self.assertEqual(self.source.get(self.first["kid"]), b"\x01" * 32)

    def test_a_lapsed_set_is_not_trusted_when_the_fetch_fails(self) -> None:
        self.source.get(self.first["kid"])
        self.clock.advance(300)
        self.server.reply = (500, {}, b"")
        with self.assertRaises(TransportError):
            self.source.get(self.first["kid"])
        self.assertEqual(self.fetches(), 2)

        # The failure is remembered for the interval: an outage is not turned
        # into one fetch per verification.
        with self.assertRaises(TransportError):
            self.source.get(self.first["kid"])
        self.assertEqual(self.fetches(), 2)

        self.clock.advance(10)
        self.publish(self.first)
        self.assertEqual(self.source.get(self.first["kid"]), b"\x01" * 32)
        self.assertEqual(self.fetches(), 3)

    def test_unusable_responses_are_failures(self) -> None:
        replies: Dict[str, Reply] = {
            "not json": (200, {}, b"<html>"),
            "array": json_reply(200, [1]),
            "empty set": json_reply(200, {"keys": []}),
            "oversized": (200, {}, b" " * ((1 << 20) + 1)),
        }
        for name, reply in replies.items():
            with self.subTest(case=name):
                source = RemoteJWKS(self.server.url + "/jwks.json", clock=self.clock)
                self.server.reply = reply
                with self.assertRaises(N0PasstempsError):
                    source.get(self.first["kid"])

    def test_unreachable_endpoint(self) -> None:
        source = RemoteJWKS("http://127.0.0.1:" + str(closed_port()) + "/jwks.json", timeout=2)
        with self.assertRaises(TransportError):
            source.get("any")

    def test_a_cross_origin_redirect_is_refused(self) -> None:
        elsewhere = RecordingServer()
        self.addCleanup(elsewhere.close)
        elsewhere.reply = json_reply(200, {"keys": [self.second]})
        self.server.reply = (302, {"Location": elsewhere.url + "/jwks.json"}, b"")
        with self.assertRaises(TransportError):
            self.source.get(self.second["kid"])
        self.assertEqual(elsewhere.requests, [])

    def test_https_is_required_off_loopback(self) -> None:
        with self.assertRaises(ConfigurationError):
            RemoteJWKS("http://auth.example.org/v1/.well-known/jwks.json")
        RemoteJWKS("https://auth.example.org/v1/.well-known/jwks.json")
        RemoteJWKS("http://auth.internal/jwks.json", allow_insecure_transport=True)

    def test_settings_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            RemoteJWKS(self.server.url, cache_seconds=5, min_refetch_interval=10)
        with self.assertRaises(ValueError):
            RemoteJWKS(self.server.url, min_refetch_interval=-1)


class VerificationUnavailableTests(unittest.TestCase):
    def test_a_missing_primitive_is_reported_in_a_sentence(self) -> None:
        hidden = {
            "cryptography": None,
            "cryptography.exceptions": None,
            "cryptography.hazmat.primitives.asymmetric.ed25519": None,
        }
        keys = StaticKeys.from_public_keys([b"\x01" * 32])
        with mock.patch.dict(sys.modules, hidden):
            with self.assertRaises(VerificationUnavailable) as caught:
                Verifier(ISSUER, AUDIENCE, keys)
        self.assertIn("pip install n0passtemps[verify]", str(caught.exception))
        self.assertIsInstance(caught.exception, N0PasstempsError)


@NEEDS_CRYPTOGRAPHY
class VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        from cryptography.hazmat.primitives import serialization

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.jwk = jwk_for(self.public_key)
        self.kid = self.jwk["kid"]
        self.keys = CountingKeys(StaticKeys({"keys": [self.jwk]}))
        self.now = float(NOW)
        self.verifier = Verifier(ISSUER, AUDIENCE, self.keys, now=lambda: self.now)

    # --- helpers ---

    def header(self, **changes: Any) -> Dict[str, Any]:
        header: Dict[str, Any] = {"alg": "EdDSA", "kid": self.kid, "typ": "JWT"}
        header.update(changes)
        return {k: v for k, v in header.items() if v is not ...}

    def claims(self, **changes: Any) -> Dict[str, Any]:
        claims: Dict[str, Any] = {
            "iss": ISSUER,
            "sub": "0b6f6c1e-8f1e-4a67-9d0b-3a0c0f2e7f11",
            "aud": AUDIENCE,
            "iat": NOW,
            "nbf": NOW - 30,
            "exp": NOW + 60,
            "jti": "c29tZS1yYW5kb20tanRp",
            "amr": ["webauthn", "webauthn-uv"],
            "cid": "Y3JlZA",
        }
        claims.update(changes)
        return {k: v for k, v in claims.items() if v is not ...}

    def sign(self, signing_input: str, key: Optional[Any] = None) -> str:
        signer = key if key is not None else self.private_key
        signed: bytes = signer.sign(signing_input.encode("ascii"))
        return b64(signed)

    def mint(
        self,
        header: Optional[Dict[str, Any]] = None,
        claims: Optional[Dict[str, Any]] = None,
        key: Optional[Any] = None,
    ) -> str:
        signing_input = (
            segment(header if header is not None else self.header())
            + "."
            + segment(claims if claims is not None else self.claims())
        )
        return signing_input + "." + self.sign(signing_input, key)

    def assertRefused(self, token: Any, verifier: Optional[Verifier] = None) -> None:
        with self.assertRaises(InvalidAssertion) as caught:
            (verifier or self.verifier).verify(token)
        # One outcome for every failure: same message, and no chained cause
        # that would say which check it was.
        self.assertEqual(str(caught.exception), "the assertion is not valid")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__ or caught.exception.__context__ is None)

    # --- the accepted case ---

    def test_valid(self) -> None:
        claims = self.verifier.verify(self.mint())
        self.assertIsInstance(claims, Claims)
        self.assertEqual(claims.issuer, ISSUER)
        self.assertEqual(claims.audience, AUDIENCE)
        self.assertEqual(claims.subject, "0b6f6c1e-8f1e-4a67-9d0b-3a0c0f2e7f11")
        self.assertEqual(claims.expires_at, NOW + 60)
        self.assertEqual(claims.not_before, NOW - 30)
        self.assertEqual(claims.issued_at, NOW)
        self.assertEqual(claims.jti, "c29tZS1yYW5kb20tanRp")
        self.assertEqual(claims.amr, ("webauthn", "webauthn-uv"))
        self.assertEqual(claims.credential_id, "Y3JlZA")
        self.assertIsNone(claims.tenant_id)
        self.assertEqual(claims.raw["cid"], "Y3JlZA")
        self.assertEqual(self.keys.asked, [self.kid])

    def test_valid_in_the_servers_exact_wire_form(self) -> None:
        # The header exactly as internal/assertion builds it, and no "cid".
        header = b64(('{"alg":"EdDSA","kid":"' + self.kid + '","typ":"JWT"}').encode("ascii"))
        payload = segment(self.claims(cid=..., tid="tenant-1", amr=["totp"]))
        signing_input = header + "." + payload
        claims = self.verifier.verify(signing_input + "." + self.sign(signing_input))
        self.assertEqual(claims.amr, ("totp",))
        self.assertIsNone(claims.credential_id)
        self.assertEqual(claims.tenant_id, "tenant-1")

    def test_typ_may_be_absent(self) -> None:
        self.verifier.verify(self.mint(header=self.header(typ=...)))

    # --- signature ---

    def test_tampered_payload(self) -> None:
        head, _, signature = self.mint().split(".")
        forged = segment(self.claims(sub="somebody-else"))
        self.assertRefused(head + "." + forged + "." + signature)

    def test_tampered_header(self) -> None:
        _, payload, signature = self.mint().split(".")
        forged = segment(self.header(typ=""))
        self.assertRefused(forged + "." + payload + "." + signature)

    def test_tampered_signature(self) -> None:
        head, payload, signature = self.mint().split(".")
        raw = bytearray(_b64url_decode(signature))
        raw[10] ^= 0x01
        self.assertRefused(head + "." + payload + "." + b64(bytes(raw)))

    def test_signature_of_the_wrong_length(self) -> None:
        head, payload, signature = self.mint().split(".")
        raw = _b64url_decode(signature)
        for other in (raw[:63], raw + b"\x00", b""):
            with self.subTest(length=len(other)):
                self.assertRefused(head + "." + payload + "." + b64(other))

    def test_signed_by_another_key_under_a_known_kid(self) -> None:
        self.assertRefused(self.mint(key=Ed25519PrivateKey.generate()))

    # --- algorithm confusion ---

    def test_alg_none(self) -> None:
        for alg in ("none", "None", "NONE", "nOnE"):
            with self.subTest(alg=alg):
                unsigned = segment(self.header(alg=alg)) + "." + segment(self.claims())
                self.assertRefused(unsigned + ".")
                self.assertRefused(unsigned)
        self.assertEqual(self.keys.asked, [], "no key may be looked up for a refused alg")

    def test_hs256_with_the_public_key_as_the_hmac_secret(self) -> None:
        signing_input = segment(self.header(alg="HS256")) + "." + segment(self.claims())
        for secret in (self.public_key, self.jwk["x"].encode("ascii")):
            with self.subTest(secret=len(secret)):
                mac = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
                self.assertRefused(signing_input + "." + b64(mac))
        self.assertEqual(self.keys.asked, [], "no key may be looked up for a refused alg")

    def test_every_other_alg(self) -> None:
        for alg in ("HS384", "HS512", "RS256", "ES256", "PS256", "Ed25519", "eddsa", "EDDSA",
                    "EdDSA ", "", None, 5, ["EdDSA"], ...):
            with self.subTest(alg=alg):
                # Properly signed, so the algorithm name is the only fault.
                self.assertRefused(self.mint(header=self.header(alg=alg)))

    def test_crit_is_refused(self) -> None:
        for crit in (["exp"], ["b64"], [], None, "exp"):
            with self.subTest(crit=crit):
                self.assertRefused(self.mint(header=self.header(crit=crit)))

    def test_another_typ_is_refused(self) -> None:
        for typ in ("at+jwt", "JOSE", "jwt", None, 5):
            with self.subTest(typ=typ):
                self.assertRefused(self.mint(header=self.header(typ=typ)))

    # --- key selection ---

    def test_unknown_kid(self) -> None:
        stranger = Ed25519PrivateKey.generate()
        self.assertRefused(self.mint(header=self.header(kid="unknown-kid"), key=stranger))
        self.assertEqual(self.keys.asked, ["unknown-kid"])

    def test_the_key_is_selected_by_kid_only(self) -> None:
        # Two trusted keys. A token signed by the second but naming the first
        # must fail: a verifier that tried every key would accept it.
        from cryptography.hazmat.primitives import serialization

        other = Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        keys = StaticKeys({"keys": [self.jwk, jwk_for(other_public)]})
        verifier = Verifier(ISSUER, AUDIENCE, keys, now=lambda: self.now)
        self.assertRefused(self.mint(key=other), verifier)
        verifier.verify(self.mint(header=self.header(kid=jwk_for(other_public)["kid"]), key=other))

    def test_missing_or_malformed_kid(self) -> None:
        for kid in (..., "", None, 7, [self.kid]):
            with self.subTest(kid=kid):
                self.assertRefused(self.mint(header=self.header(kid=kid)))

    def test_an_embedded_jwk_is_ignored(self) -> None:
        stranger = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization

        embedded = jwk_for(stranger.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        header = self.header(jwk=embedded, kid=embedded["kid"])
        self.assertRefused(self.mint(header=header, key=stranger))

    # --- time ---

    def test_expired(self) -> None:
        self.assertRefused(self.mint(claims=self.claims(exp=NOW - 31, nbf=NOW - 120)))
        self.assertRefused(self.mint(claims=self.claims(exp=NOW - 3600, nbf=NOW - 7200)))

    def test_not_yet_valid(self) -> None:
        self.assertRefused(self.mint(claims=self.claims(nbf=NOW + 31, exp=NOW + 120)))

    def test_skew_boundaries(self) -> None:
        token = self.mint(claims=self.claims(nbf=NOW, exp=NOW + 60))

        self.now = NOW + 60 + 30
        self.verifier.verify(token)
        self.now = NOW + 60 + 30 + 0.001
        self.assertRefused(token)
        self.now = NOW + 60 + 31
        self.assertRefused(token)

        self.now = NOW - 30
        self.verifier.verify(token)
        self.now = NOW - 30 - 0.001
        self.assertRefused(token)
        self.now = NOW - 31
        self.assertRefused(token)

    def test_zero_skew(self) -> None:
        verifier = Verifier(ISSUER, AUDIENCE, self.keys, clock_skew=0, now=lambda: self.now)
        token = self.mint(claims=self.claims(nbf=NOW, exp=NOW + 60))
        self.now = NOW
        verifier.verify(token)
        self.now = NOW + 60
        verifier.verify(token)
        self.now = NOW + 61
        self.assertRefused(token, verifier)
        self.now = NOW - 1
        self.assertRefused(token, verifier)

    def test_missing_exp(self) -> None:
        self.assertRefused(self.mint(claims=self.claims(exp=...)))

    def test_exp_must_be_a_positive_integer(self) -> None:
        for exp in (0, -1, None, True, str(NOW + 60), float(NOW + 60), [NOW + 60]):
            with self.subTest(exp=exp):
                self.assertRefused(self.mint(claims=self.claims(exp=exp)))

    def test_nbf_is_optional_but_typed(self) -> None:
        self.verifier.verify(self.mint(claims=self.claims(nbf=...)))
        for nbf in (None, True, "0", 1.5):
            with self.subTest(nbf=nbf):
                self.assertRefused(self.mint(claims=self.claims(nbf=nbf)))

    # --- claims ---

    def test_wrong_iss(self) -> None:
        for iss in ("another-deployment", "", None, ..., [ISSUER], ISSUER + " "):
            with self.subTest(iss=iss):
                self.assertRefused(self.mint(claims=self.claims(iss=iss)))

    def test_wrong_aud(self) -> None:
        for aud in ("another-key", "", None, ..., [AUDIENCE], [AUDIENCE, "x"], AUDIENCE.upper()):
            with self.subTest(aud=aud):
                self.assertRefused(self.mint(claims=self.claims(aud=aud)))

    def test_sub_amr_and_jti_are_required(self) -> None:
        changes: List[Dict[str, Any]] = [
            {"sub": ...}, {"sub": ""}, {"sub": 5},
            {"amr": ...}, {"amr": []}, {"amr": "totp"}, {"amr": [5]}, {"amr": [""]},
            {"jti": ...}, {"jti": ""}, {"jti": 5},
            {"cid": 5}, {"tid": ["t"]}, {"iat": "now"},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertRefused(self.mint(claims=self.claims(**change)))

    def test_failures_are_indistinguishable(self) -> None:
        head, payload, signature = self.mint().split(".")
        failures = [
            self.mint(claims=self.claims(exp=NOW - 3600)),
            self.mint(claims=self.claims(aud="another-key")),
            self.mint(header=self.header(kid="unknown")),
            head + "." + payload + "." + b64(b"\x00" * 64),
            "garbage",
        ]
        seen = set()
        for token in failures:
            with self.assertRaises(InvalidAssertion) as caught:
                self.verifier.verify(token)
            seen.add((type(caught.exception), str(caught.exception), caught.exception.args))
        self.assertEqual(len(seen), 1)

    # --- serialisation ---

    def test_two_and_four_segments(self) -> None:
        head, payload, signature = self.mint().split(".")
        self.assertRefused(head + "." + payload)
        self.assertRefused(head + "." + payload + "." + signature + "." + signature)
        self.assertRefused(head + "." + payload + "." + signature + ".")
        self.assertRefused("." + head + "." + payload + "." + signature)
        self.assertRefused(head)
        self.assertRefused("")
        self.assertRefused("..")

    def test_padded_base64(self) -> None:
        head, payload, signature = self.mint().split(".")
        # A lenient decoder accepts all of these and recovers the same bytes.
        self.assertRefused(head + "." + payload + "." + signature + "==")
        self.assertRefused(head + "=" * (-len(head) % 4 or 4) + "." + payload + "." + signature)
        self.assertRefused(head + "." + payload + "=" * (-len(payload) % 4 or 4) + "." + signature)

    def test_non_canonical_trailing_bits(self) -> None:
        head, payload, signature = self.mint().split(".")
        # 64 bytes encode to 86 characters, the last carrying four spare bits.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        respelt = signature[:-1] + alphabet[alphabet.index(signature[-1]) + 1]
        self.assertEqual(
            base64.urlsafe_b64decode(respelt + "=="), base64.urlsafe_b64decode(signature + "==")
        )
        self.assertRefused(head + "." + payload + "." + respelt)

    def test_foreign_characters_in_a_segment(self) -> None:
        head, payload, signature = self.mint().split(".")
        self.assertRefused(head + "." + payload + "." + signature + "\n")
        self.assertRefused(" " + head + "." + payload + "." + signature)
        self.assertRefused(head + "." + payload[:4] + "\n" + payload[4:] + "." + signature)

    def test_malformed_json(self) -> None:
        def raw_token(header_text: str, payload_text: str) -> str:
            signing_input = b64(header_text.encode()) + "." + b64(payload_text.encode())
            return signing_input + "." + self.sign(signing_input)

        good_header = json.dumps(self.header())
        good_payload = json.dumps(self.claims())
        self.verifier.verify(raw_token(good_header, good_payload))

        self.assertRefused(raw_token("not json", good_payload))
        self.assertRefused(raw_token("[1]", good_payload))
        self.assertRefused(raw_token("[" * 5000, good_payload))
        self.assertRefused(raw_token(good_header, "not json"))
        self.assertRefused(raw_token(good_header, '"a string"'))
        self.assertRefused(raw_token(good_header, good_payload[:-1] + ',"exp":NaN}'))
        self.assertRefused(raw_token(good_header, "\xff\xfe"))
        # The same member twice: parsers disagree on which one wins.
        self.assertRefused(raw_token(good_header[:-1] + ',"alg":"EdDSA"}', good_payload))
        self.assertRefused(raw_token(good_header, good_payload[:-1] + ',"aud":"' + AUDIENCE + '"}'))

    def test_oversized_and_non_string_tokens(self) -> None:
        self.assertRefused("A" * 9000 + "." + "A" * 10 + "." + "A" * 86)
        for token in (None, 5, b"a.b.c", ["a", "b", "c"]):
            with self.subTest(token=token):
                self.assertRefused(token)
        self.assertEqual(self.keys.asked, [])

    # --- construction ---

    def test_issuer_and_audience_are_mandatory(self) -> None:
        for issuer, audience in (("", AUDIENCE), (ISSUER, ""), (None, AUDIENCE), (ISSUER, None)):
            with self.subTest(issuer=issuer, audience=audience):
                with self.assertRaises(ValueError):
                    Verifier(issuer, audience, self.keys)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Verifier(ISSUER, AUDIENCE, self.keys, clock_skew=-1)


@NEEDS_CRYPTOGRAPHY
class VerifierWithRemoteJWKSTests(unittest.TestCase):
    def test_end_to_end_with_rotation(self) -> None:
        from cryptography.hazmat.primitives import serialization

        def public_bytes(key: Any) -> bytes:
            raw: bytes = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return raw

        def mint(key: Any, kid: str) -> str:
            claims = {
                "iss": ISSUER, "sub": "subject-1", "aud": AUDIENCE, "iat": NOW,
                "nbf": NOW - 30, "exp": NOW + 60, "jti": "jti-1", "amr": ["totp"],
            }
            signing_input = segment({"alg": "EdDSA", "kid": kid, "typ": "JWT"}) + "." + segment(claims)
            return signing_input + "." + b64(key.sign(signing_input.encode("ascii")))

        server = RecordingServer()
        self.addCleanup(server.close)
        old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        old_jwk, new_jwk = jwk_for(public_bytes(old)), jwk_for(public_bytes(new))

        def reply(request: Recorded) -> Reply:
            return json_reply(200, {"keys": published})

        published = [old_jwk]
        server.reply = reply
        clock = FakeClock()
        source = RemoteJWKS(server.url + "/v1/.well-known/jwks.json", clock=clock)
        verifier = Verifier(ISSUER, AUDIENCE, source, now=lambda: float(NOW))

        self.assertEqual(verifier.verify(mint(old, old_jwk["kid"])).subject, "subject-1")
        self.assertEqual(len(server.requests), 1)

        # The service rotates. The first token under the new key is picked up
        # by the refetch on an unknown kid, without waiting for the cache.
        published = [old_jwk, new_jwk]
        clock.advance(30)
        self.assertEqual(verifier.verify(mint(new, new_jwk["kid"])).subject, "subject-1")
        self.assertEqual(len(server.requests), 2)

        # A flood of forged kids costs the service nothing more.
        stranger = Ed25519PrivateKey.generate()
        for index in range(50):
            with self.assertRaises(InvalidAssertion):
                verifier.verify(mint(stranger, "forged-" + str(index)))
        self.assertEqual(len(server.requests), 2)

    def test_an_unreachable_jwks_is_an_outage_not_an_invalid_token(self) -> None:
        source = RemoteJWKS("http://127.0.0.1:" + str(closed_port()) + "/jwks.json", timeout=2)
        verifier = Verifier(ISSUER, AUDIENCE, source)
        token = segment({"alg": "EdDSA", "kid": "k"}) + "." + segment({}) + "." + b64(b"\x00" * 64)
        with self.assertRaises(TransportError):
            verifier.verify(token)


if __name__ == "__main__":
    unittest.main()
