#!/usr/bin/env python3
"""Verify an assertion against the JWKS endpoint.

Usage:
    N0PASSTEMPS_URL=http://127.0.0.1:8080 \\
    N0PASSTEMPS_EXPECTED_AUDIENCE=00000000-0000-0000-0000-000000000000 \\
    ./verify_assertion.py '<assertion>'

No API key is needed: the JWKS route carries no credential.

The assertion may also arrive on standard input:

    ./verify_totp.py | tail -1 | ./verify_assertion.py

N0PASSTEMPS_EXPECTED_AUDIENCE is the identifier of the API key the ceremony was
performed for, which is the ``id`` member of that key in
``GET /admin/v1/api-keys``. It is mandatory. Verifying without pinning the
audience would accept a token minted for a different key, which is the one
thing pinning exists to prevent. N0PASSTEMPS_ISSUER pins ``iss`` and defaults
to n0passtemps, matching the shipped configuration default.

This is the only file in examples/python that needs a dependency. Python's
standard library has no Ed25519, so the raw signature check cannot be written
here honestly without one; see requirements.txt. Every other check in the
verification, including the parsing rules that the JWS confusion attacks
exploit, lives in client.py and needs nothing but the standard library.
"""

from __future__ import annotations

import os
import sys

from client import (
    AssertionInvalid,
    AssertionVerifier,
    Client,
    ConfigurationError,
    ProblemError,
)

DEFAULT_ISSUER = "n0passtemps"


def load_ed25519_verifier():
    """Return a signature check backed by the cryptography package.

    The import is deferred so that an environment without the package gets a
    sentence explaining what to install rather than a traceback from the top of
    the file.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as error:  # pragma: no cover - environment dependent
        raise ConfigurationError(
            "this file needs the cryptography package for the Ed25519 check: "
            "python3 -m pip install -r requirements.txt"
        ) from error

    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except InvalidSignature:
            return False
        except ValueError:
            # A public key of the wrong length. Treated as a failed
            # verification rather than an error, because a malformed key in the
            # published set must not let a token through.
            return False
        return True

    return verify


def run(token: str) -> int:
    expected_audience = os.environ.get("N0PASSTEMPS_EXPECTED_AUDIENCE", "").strip()
    if not expected_audience:
        raise ConfigurationError(
            "unset: N0PASSTEMPS_EXPECTED_AUDIENCE (the id of the API key the "
            "ceremony was performed for, from GET /admin/v1/api-keys)"
        )
    expected_issuer = os.environ.get("N0PASSTEMPS_ISSUER", "").strip() or DEFAULT_ISSUER

    ed25519_verify = load_ed25519_verifier()

    # No API key. The JWKS route carries no credential, because its contents
    # are public keys and a verifying party has to be able to fetch them.
    client = Client.from_env(require_api_key=False)
    print(f"Fetching {client.base_url}/v1/.well-known/jwks.json")
    jwks = client.jwks()

    verifier = AssertionVerifier(
        jwks=jwks,
        expected_issuer=expected_issuer,
        ed25519_verify=ed25519_verify,
    )
    print(f"  keys published: {', '.join(sorted(verifier.keys))}")
    print()
    print(f"Pinning iss={expected_issuer} aud={expected_audience}")

    try:
        claims = verifier.verify(token, expected_audience)
    except AssertionInvalid:
        print()
        print("The assertion is not valid.", file=sys.stderr)
        print(
            "No further detail is available by design. Reporting which check "
            "failed would tell an attacker whether a forged token had the right "
            "audience, whether a key identifier exists, or whether a captured "
            "token is merely expired rather than wrongly signed.",
            file=sys.stderr,
        )
        return 1

    print()
    print("The assertion is valid.")
    print(f"  iss: {claims['iss']}")
    print(f"  sub: {claims['sub']}")
    print(f"  aud: {claims['aud']}")
    print(f"  iat: {claims['iat']}")
    print(f"  nbf: {claims['nbf']}")
    print(f"  exp: {claims['exp']}")
    print(f"  jti: {claims['jti']}")
    print(f"  amr: {', '.join(claims['amr'])}")
    if claims.get("cid"):
        print(f"  cid: {claims['cid']}")
    if claims.get("tid"):
        print(f"  tid: {claims['tid']}")

    print()
    print("Two things remain for a real integration.")
    print()
    print("Record jti in a replay cache until exp passes. Signature validity")
    print("alone does not make a token single use, and an assertion captured in")
    print("transit is replayable for the rest of its lifetime otherwise.")
    print()
    print("Apply your own policy to amr. A WebAuthn assertion with user")
    print("verification is a different assurance from a recovery code, which is")
    print("why the factors are listed separately rather than collapsed into a")
    print("single boolean.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("Usage: verify_assertion.py '<assertion>'", file=sys.stderr)
        return 2

    if len(argv) == 2:
        token = argv[1].strip()
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()
    else:
        print(
            "No assertion given. Pass it as an argument or on standard input.",
            file=sys.stderr,
        )
        return 2

    if not token:
        print("The assertion is empty.", file=sys.stderr)
        return 2

    try:
        return run(token)
    except ConfigurationError as error:
        print(f"Configuration is incomplete: {error}", file=sys.stderr)
        return 2
    except ProblemError as error:
        print(f"The service refused the request: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Could not reach the service: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
