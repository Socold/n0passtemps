"""Client SDK for the n0passtemps authentication server.

``Client`` speaks to the /v1 API with nothing but the standard library.
``n0passtemps.assertion.Verifier`` checks the signed assertion offline and
needs the optional ``cryptography`` dependency for the Ed25519 primitive:
``pip install n0passtemps[verify]``.
"""

from .assertion import (
    Claims,
    KeySource,
    RemoteJWKS,
    StaticKeys,
    Verifier,
    jwk_thumbprint,
    parse_jwks,
)
from .client import (
    VERSION as __version__,
    AssertionResult,
    Client,
    RecoveryBatch,
    Subject,
    TOTPEnrolment,
)
from .errors import (
    APIError,
    AuthenticationFailed,
    ConfigurationError,
    Conflict,
    Forbidden,
    InvalidAssertion,
    N0PasstempsError,
    NotFound,
    ProtocolError,
    Throttled,
    TransportError,
    Unauthorized,
    Unavailable,
    VerificationUnavailable,
)

__all__ = [
    "__version__",
    "Client",
    "Subject",
    "AssertionResult",
    "RecoveryBatch",
    "TOTPEnrolment",
    "Verifier",
    "Claims",
    "KeySource",
    "StaticKeys",
    "RemoteJWKS",
    "jwk_thumbprint",
    "parse_jwks",
    "N0PasstempsError",
    "ConfigurationError",
    "TransportError",
    "ProtocolError",
    "APIError",
    "Unauthorized",
    "Forbidden",
    "NotFound",
    "Conflict",
    "AuthenticationFailed",
    "Throttled",
    "Unavailable",
    "InvalidAssertion",
    "VerificationUnavailable",
]
