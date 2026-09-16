"""Exceptions raised by the n0passtemps SDK.

Everything derives from N0PasstempsError, so an integration that wants one
catch-all has one, while the subclasses let it branch on the outcomes that call
for different handling: a refused end user, a misconfigured API key, a
throttled subject, a service that is down.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Type

__all__ = [
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
    "error_from_problem",
]

_TYPE_PREFIX = "urn:n0passtemps:error:"


class N0PasstempsError(Exception):
    """Base class of every exception this package raises on purpose."""


class ConfigurationError(N0PasstempsError, ValueError):
    """The client or the verifier was constructed with unusable settings.

    It is also a ValueError, because that is what a caller validating its own
    configuration at start-up is most likely to be catching already.
    """


class TransportError(N0PasstempsError):
    """The request did not produce an HTTP response from the service.

    Connection refused, DNS failure, TLS failure, timeout, a connection dropped
    halfway, or a redirect the client refused to follow. The SDK never retries:
    several routes consume single-use material (a challenge, a TOTP step, a
    recovery code), so whether a repeat is safe is a decision for the caller.
    """


class ProtocolError(N0PasstempsError):
    """The service answered, but not with what its contract describes.

    A success body that is not a JSON object, a missing member, or a body over
    the size cap. In practice this means the base URL points at something that
    is not n0passtemps, or at an intermediary that rewrote the response.
    """


class APIError(N0PasstempsError):
    """An RFC 9457 problem document returned by the service.

    The service keeps ``title`` and ``type`` to a class of failure and never
    explains why one particular request was refused, so ``detail`` is populated
    only where disclosure is harmless: input validation and state conflicts.
    ``request_id`` is the field a support exchange needs, because it locates
    the log and audit entries where the real reason was written.
    """

    def __init__(
        self,
        status: int,
        type: str = "",
        title: str = "",
        detail: str = "",
        request_id: str = "",
        retry_after: Optional[int] = None,
        *,
        raw: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.status = status
        self.type = type
        self.title = title
        self.detail = detail
        self.request_id = request_id
        self.retry_after = retry_after
        self.raw: Dict[str, Any] = dict(raw) if raw is not None else {}

        parts = [str(status), type or "(no type)", title or "(no title)"]
        if detail:
            parts.append(detail)
        message = ": ".join(parts)
        if request_id:
            message += " (request_id=" + request_id + ")"
        super().__init__(message)


class Unauthorized(APIError):
    """The API key is missing, malformed, unknown or revoked.

    This is about the integration's own credential, never about the end user.
    A failed end-user authentication is AuthenticationFailed, which shares the
    401 status and is told apart by the problem ``type``.
    """


class Forbidden(APIError):
    """The API key is valid but lacks the scope, or policy refused the request.

    The second case covers an authenticator model the operator does not permit;
    the title says so, because the user has to be told to use another key.
    """


class NotFound(APIError):
    """The resource does not exist. Only get_subject reports an unknown subject
    this way; the authentication routes answer AuthenticationFailed instead, so
    they cannot be used to test whether somebody has an account."""


class Conflict(APIError):
    """The request conflicts with the current state, for example an
    authenticator that is already registered. ``detail`` names the conflict."""


class AuthenticationFailed(APIError):
    """A WebAuthn, TOTP or recovery-code ceremony did not succeed.

    The service gives no reason on purpose: a wrong signature, an expired
    challenge, an unknown subject and a spent code all look the same. Treat it
    as "not authenticated" and nothing more.
    """


class Throttled(APIError):
    """Too many attempts. ``retry_after`` is the number of seconds to wait."""


class Unavailable(APIError):
    """A dependency of the service, such as its database, is down."""


class InvalidAssertion(N0PasstempsError):
    """An assertion failed verification.

    Like the service's own verifier, this carries no indication of which check
    failed. Reporting it would tell an attacker whether a forged token had the
    right audience, whether a key identifier exists, or whether a captured
    token is merely expired rather than wrongly signed.
    """

    def __init__(self) -> None:
        super().__init__("the assertion is not valid")


class VerificationUnavailable(N0PasstempsError):
    """The Ed25519 primitive is not installed.

    The standard library has no Ed25519, and this package deliberately ships no
    implementation of its own: signature code deserves an audited, maintained
    home. Install the optional extra: ``pip install n0passtemps[verify]``.
    """


_BY_TYPE: Dict[str, Type[APIError]] = {
    _TYPE_PREFIX + "unauthorized": Unauthorized,
    _TYPE_PREFIX + "forbidden": Forbidden,
    _TYPE_PREFIX + "not-found": NotFound,
    _TYPE_PREFIX + "conflict": Conflict,
    _TYPE_PREFIX + "ceremony-failed": AuthenticationFailed,
    _TYPE_PREFIX + "throttled": Throttled,
    _TYPE_PREFIX + "unavailable": Unavailable,
}

# Used only when the body carries no recognised type, which means the response
# came from an intermediary rather than from the service. 401 maps to
# Unauthorized and never to AuthenticationFailed: without the service's own
# type there is no evidence that a ceremony ran at all.
_BY_STATUS: Dict[int, Type[APIError]] = {
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    409: Conflict,
    429: Throttled,
    503: Unavailable,
}


def _text(document: Mapping[str, Any], member: str) -> str:
    value = document.get(member)
    return value if isinstance(value, str) else ""


def error_from_problem(
    status: int,
    document: Mapping[str, Any],
    *,
    request_id: str = "",
    retry_after: Optional[int] = None,
) -> APIError:
    """Build the APIError subclass matching a problem document.

    The class is chosen from the problem ``type``, because the status alone is
    ambiguous: 401 is both a bad API key and a failed ceremony, and an
    integration must not confuse the two. ``request_id`` and ``retry_after``
    are the values taken from the response headers; the body wins for the
    identifier and the header wins for the delay, which is the order the
    service itself treats as authoritative.
    """
    problem_type = _text(document, "type")
    cls = _BY_TYPE.get(problem_type) or _BY_STATUS.get(status, APIError)

    if retry_after is None:
        seconds = document.get("retry_after_seconds")
        if isinstance(seconds, int) and not isinstance(seconds, bool) and seconds >= 0:
            retry_after = seconds

    return cls(
        status,
        problem_type,
        _text(document, "title"),
        _text(document, "detail"),
        _text(document, "request_id") or request_id,
        retry_after,
        raw=document,
    )
