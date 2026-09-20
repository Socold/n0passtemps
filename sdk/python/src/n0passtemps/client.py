"""HTTP client for the /v1 surface of an n0passtemps server.

Built on urllib so the package has no runtime dependency. The transport rules
that protect the API key (HTTPS only, no cross-origin redirect, no key in any
message) live in this module and are shared with the JWKS fetcher in
assertion.py.
"""

from __future__ import annotations

import copy
import datetime as _dt
import email.utils
import http.client
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import IO, Any, Dict, Mapping, Optional, Tuple

from .errors import (
    ConfigurationError,
    N0PasstempsError,
    ProtocolError,
    TransportError,
    error_from_problem,
)

__all__ = [
    "VERSION",
    "MAX_RESPONSE_BYTES",
    "Client",
    "Subject",
    "AssertionResult",
    "RecoveryBatch",
    "TOTPEnrolment",
]

VERSION = "1.1.2"

# No response of this API comes anywhere near this size. The cap exists so that
# a wrong base URL, or a hostile endpoint, cannot make the caller buffer an
# unbounded body in memory.
MAX_RESPONSE_BYTES = 1 << 20

_DEFAULT_USER_AGENT = "n0passtemps-python/" + VERSION

_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)


# --- shared transport helpers ------------------------------------------------


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _checked_url(url: str, allow_insecure_transport: bool, what: str) -> str:
    """Validate an endpoint URL and return it without a trailing slash."""
    if not isinstance(url, str) or not url.strip():
        raise ConfigurationError(what + " is empty")
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        _ = parts.port
    except ValueError:
        raise ConfigurationError(what + " is not a valid URL") from None

    if parts.scheme not in ("http", "https") or not host:
        raise ConfigurationError(what + " must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        # Credentials in the URL would end up in repr(), in error messages and
        # in proxy logs.
        raise ConfigurationError(what + " must not contain credentials")
    if parts.query or parts.fragment:
        raise ConfigurationError(what + " must not contain a query or a fragment")

    # Over plain HTTP anybody on the network path can read what is sent and
    # rewrite what comes back. For the client that means the API key, which is
    # a bearer credential: whoever reads it can use it. For the JWKS it means
    # the verification keys themselves could be substituted. Loopback is
    # exempt because the traffic never leaves the machine, which is what local
    # development and a sidecar deployment need.
    if parts.scheme != "https" and not allow_insecure_transport and not _is_loopback(host):
        raise ConfigurationError(
            what + " must use https: over plain http the traffic can be read "
            "and rewritten on the network. Loopback hosts are exempt; pass "
            "allow_insecure_transport=True to accept the risk elsewhere."
        )
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path.rstrip("/"), "", "")
    )


def _origin(url: str) -> Tuple[str, str, int]:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
    return scheme, (parts.hostname or "").lower(), port


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only when it stays on the same scheme, host and port.

    urllib copies the request headers onto the redirected request, including
    Authorization. Left alone, a 302 answered by anything on the path (a
    misconfigured proxy, a captive portal, a compromised front end) would hand
    the API key to whichever host the Location header names. Comparing the
    whole origin rather than the host alone also refuses a downgrade from
    https to http on the same name.

    Only GET and HEAD are ever redirected. urllib would otherwise replay a
    redirected POST as a GET without its body, which is never what a ceremony
    route means.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        if req.get_method() not in ("GET", "HEAD"):
            fp.close()
            raise TransportError("refused a redirect of a " + req.get_method() + " request")
        try:
            same = _origin(req.full_url) == _origin(newurl)
        except ValueError:
            same = False
        if not same:
            fp.close()
            raise TransportError(
                "refused a redirect to a different origin: credentials are "
                "only ever sent to the configured host"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(ca_file: Optional[str]) -> urllib.request.OpenerDirector:
    # An on-premise deployment commonly serves a certificate from an internal
    # authority. Trusting that one authority is the supported way to reach it;
    # there is deliberately no switch to disable verification, which would
    # remove the only thing that tells the real service from anything else on
    # the same network.
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError):
        raise ConfigurationError("ca_file could not be loaded") from None
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _SameOriginRedirectHandler(),
    )


def _read_capped(stream: Any) -> bytes:
    """Read a response body, refusing one above MAX_RESPONSE_BYTES."""
    raw = stream.read(MAX_RESPONSE_BYTES + 1)
    if not isinstance(raw, bytes):
        raise ProtocolError("the response body could not be read")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("the response body exceeds the 1 MiB cap")
    return raw


def _transport_error(error: BaseException) -> TransportError:
    # Built from the failure reason only. The request, and therefore the
    # Authorization header, never takes part in the message.
    reason = getattr(error, "reason", None)
    text = str(reason if reason is not None else error) or type(error).__name__
    return TransportError("the request failed: " + text)


def _parse_retry_after(value: Optional[str]) -> Optional[int]:
    """Read a Retry-After header, in either form RFC 9110 allows."""
    if not value:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        return int(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    delta = (when - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    return max(0, int(delta))


# --- response models ---------------------------------------------------------


def _parse_timestamp(value: Any, member: str) -> _dt.datetime:
    """Parse an RFC 3339 timestamp as the service writes it.

    datetime.fromisoformat is not used: before Python 3.11 it refuses the "Z"
    suffix, and it has never accepted the nanosecond fractions that Go emits.
    Digits beyond microseconds are dropped.
    """
    match = _TIMESTAMP.match(value) if isinstance(value, str) else None
    if match is None:
        raise ProtocolError("the response member " + member + " is not a timestamp")
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    fraction = (match.group(7) or "")[:6].ljust(6, "0")
    zone = match.group(8)
    if zone in ("Z", "z"):
        tz = _dt.timezone.utc
    else:
        offset = _dt.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        tz = _dt.timezone(-offset if zone[0] == "-" else offset)
    try:
        return _dt.datetime(year, month, day, hour, minute, second, int(fraction), tz)
    except ValueError:
        raise ProtocolError(
            "the response member " + member + " is not a timestamp"
        ) from None


def _str(document: Mapping[str, Any], member: str) -> str:
    value = document.get(member)
    if not isinstance(value, str):
        raise ProtocolError("the response member " + member + " is missing or not a string")
    return value


def _int(document: Mapping[str, Any], member: str) -> int:
    value = document.get(member)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolError("the response member " + member + " is missing or not an integer")
    return value


def _str_tuple(document: Mapping[str, Any], member: str) -> Tuple[str, ...]:
    value = document.get(member)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProtocolError("the response member " + member + " is missing or not a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class Subject:
    """What the service discloses about a subject.

    The reference the caller supplied is never echoed back: the caller already
    has it, and the service keeps it out of response bodies that intermediaries
    may cache or log. ``subject_id`` is the internal identifier, the same value
    as the ``sub`` claim of an assertion.
    """

    subject_id: str
    status: str
    created_at: _dt.datetime
    credential_count: int
    totp_enrolled: bool
    recovery_codes_remaining: int
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "Subject":
        enrolled = document.get("totp_enrolled")
        if not isinstance(enrolled, bool):
            raise ProtocolError("the response member totp_enrolled is missing or not a boolean")
        return cls(
            subject_id=_str(document, "subject_id"),
            status=_str(document, "status"),
            created_at=_parse_timestamp(document.get("created_at"), "created_at"),
            credential_count=_int(document, "credential_count"),
            totp_enrolled=enrolled,
            recovery_codes_remaining=_int(document, "recovery_codes_remaining"),
            raw=dict(document),
        )


@dataclass(frozen=True)
class AssertionResult:
    """The outcome of a successful authentication.

    ``assertion`` is the signed proof. The values beside it (``factors``,
    ``expires_at``, ``subject_id``) are conveniences that travelled over the
    same connection as everything else; an application that wants to be
    independent of that path verifies the assertion with
    n0passtemps.assertion.Verifier and reads the claims instead.

    ``signals`` reports conditions that did not refuse the authentication but
    may justify a step-up: ``sign_count_regression`` (a possible cloned
    authenticator) and ``binding_changed``. ``recovery_codes_remaining`` is set
    only by consume_recovery_code.

    The assertion is a short-lived bearer token, so it is left out of repr().
    """

    subject_id: str
    assertion: str = field(repr=False)
    expires_at: _dt.datetime
    factors: Tuple[str, ...]
    signals: Dict[str, Any] = field(hash=False)
    recovery_codes_remaining: Optional[int]
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AssertionResult":
        signals = document.get("signals")
        if signals is None:
            signals = {}
        if not isinstance(signals, dict):
            raise ProtocolError("the response member signals is not an object")
        remaining: Optional[int] = None
        if "recovery_codes_remaining" in document:
            remaining = _int(document, "recovery_codes_remaining")
        return cls(
            subject_id=_str(document, "subject_id"),
            assertion=_str(document, "assertion"),
            expires_at=_parse_timestamp(document.get("expires_at"), "expires_at"),
            factors=_str_tuple(document, "factors"),
            signals=dict(signals),
            recovery_codes_remaining=remaining,
            raw=dict(document),
        )


@dataclass(frozen=True)
class RecoveryBatch:
    """A freshly issued batch of recovery codes.

    The codes exist in this object and nowhere else: the service stores only a
    hash, and no operation can show them again. They are left out of repr() so
    that a stray log line does not become the second copy.
    """

    batch_id: str
    codes: Tuple[str, ...] = field(repr=False)
    count: int
    warning: str
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "RecoveryBatch":
        warning = document.get("warning")
        return cls(
            batch_id=_str(document, "batch_id"),
            codes=_str_tuple(document, "codes"),
            count=_int(document, "count"),
            warning=warning if isinstance(warning, str) else "",
            raw=dict(document),
        )


@dataclass(frozen=True)
class TOTPEnrolment:
    """A pending TOTP enrolment.

    ``secret`` (base32, for typing by hand) and ``provisioning_uri`` (otpauth,
    for a QR code) are disclosed once, here. Both are left out of repr(). The
    secret cannot authenticate anybody until confirm_totp succeeds, and an
    unconfirmed enrolment lapses at ``expires_at``.
    """

    secret_id: str
    secret: str = field(repr=False)
    provisioning_uri: str = field(repr=False)
    algorithm: str
    digits: int
    period_seconds: int
    expires_at: _dt.datetime
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "TOTPEnrolment":
        return cls(
            secret_id=_str(document, "secret_id"),
            secret=_str(document, "secret"),
            provisioning_uri=_str(document, "provisioning_uri"),
            algorithm=_str(document, "algorithm"),
            digits=_int(document, "digits"),
            period_seconds=_int(document, "period_seconds"),
            expires_at=_parse_timestamp(document.get("expires_at"), "expires_at"),
            raw=dict(document),
        )


# --- client ------------------------------------------------------------------


class Client:
    """A client for one n0passtemps deployment and one API key.

    The subject reference taken by most methods is the integrating
    application's own identifier for its user. Prefer an opaque identifier to
    an email address: it travels in the request path, where an intervening
    reverse proxy may log it.

    Nothing is retried. Several routes consume single-use material (a
    challenge, a TOTP step, a recovery code), so a blind repeat after a timeout
    can turn one failure into two; the caller is better placed to decide.

    Instances hold no per-request state and may be shared between threads.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        allow_insecure_transport: bool = False,
        user_agent: str = _DEFAULT_USER_AGENT,
        ca_file: Optional[str] = None,
    ) -> None:
        self._base_url = _checked_url(base_url, allow_insecure_transport, "base_url")

        # Checked here rather than left to http.client, whose own complaint
        # about an unusable header value quotes the value, and would therefore
        # put the key into a traceback.
        if not isinstance(api_key, str) or not api_key:
            raise ConfigurationError("api_key is empty")
        if not all(0x21 <= ord(char) <= 0x7E for char in api_key):
            raise ConfigurationError(
                "api_key contains whitespace or non-ASCII characters"
            )
        if not timeout > 0:
            raise ConfigurationError("timeout must be positive")
        if not user_agent or any(ord(char) < 0x20 or ord(char) > 0x7E for char in user_agent):
            raise ConfigurationError("user_agent must be printable ASCII")

        self.__api_key = api_key
        self._timeout = float(timeout)
        self._user_agent = user_agent
        self._opener = _build_opener(ca_file)
        # Set only on the view for_end_user returns.
        self._end_user_ip: Optional[str] = None

    @property
    def base_url(self) -> str:
        return self._base_url

    def for_end_user(self, ip: str) -> "Client":
        """Return a client that declares ``ip`` as the end user's address.

        The service sees every call arrive from the application's backend,
        which says nothing about who is signing in, so its per-address rate
        limit and its network risk signal work from the address declared here,
        in the ``X-End-User-IP`` header. Without it the service applies no
        per-address limit to the call. Pass the address the application
        observed for the user's browser, once per incoming request::

            auth = client.for_end_user(request.remote_addr)
            result = auth.verify_totp(subject_ref, code)

        The view shares the connection settings of the client it came from,
        and the original client is not changed.
        """
        # Refused here because the service would refuse it with a 400 anyway,
        # and not quoted: it may be the one thing about the user the
        # application does not log. A zone is refused with the rest, since it
        # names an interface of the host that saw the packet and means nothing
        # anywhere else.
        try:
            if not isinstance(ip, str) or "%" in ip:
                raise ValueError
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise ConfigurationError(
                "ip must be an IPv4 or IPv6 address, with no port and no zone"
            ) from None
        view = copy.copy(self)
        view._end_user_ip = str(address)
        return view

    def __repr__(self) -> str:
        # The base URL only. A client object ends up in logs, tracebacks and
        # debugger output, none of which is a place for a bearer credential.
        return "Client(base_url=" + repr(self._base_url) + ")"

    # --- transport ---

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        *,
        report_statuses: Tuple[int, ...] = (),
    ) -> Dict[str, Any]:
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
        elif method == "POST":
            # An explicit empty body, so the request carries Content-Length: 0
            # and no proxy on the way has to guess.
            data = b""

        headers = {
            "Accept": "application/json, application/problem+json",
            "Authorization": "Bearer " + self.__api_key,
            # Sent on every request. The service refuses a write without it
            # with 415, even when the route takes no body: that rule is what
            # stops a form-encoded cross-origin request being read as an empty
            # JSON object.
            "Content-Type": "application/json",
            "User-Agent": self._user_agent,
        }
        if self._end_user_ip is not None:
            headers["X-End-User-IP"] = self._end_user_ip
        request = urllib.request.Request(
            self._base_url + path, data=data, headers=headers, method=method
        )

        try:
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    raw = _read_capped(response)
            except urllib.error.HTTPError as error:
                # HTTPError is itself the response, so the problem document is
                # read from it.
                with error:
                    return self._refused(error, report_statuses)
        except N0PasstempsError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            raise _transport_error(error) from None

        return self._object(raw)

    @staticmethod
    def _object(raw: bytes) -> Dict[str, Any]:
        if not raw.strip():
            return {}
        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            raise ProtocolError("the response body is not valid JSON") from None
        if not isinstance(document, dict):
            raise ProtocolError("the response body is not a JSON object")
        return document

    @staticmethod
    def _refused(
        error: urllib.error.HTTPError, report_statuses: Tuple[int, ...]
    ) -> Dict[str, Any]:
        document: Dict[str, Any] = {}
        try:
            parsed = json.loads(_read_capped(error).decode("utf-8"))
            if isinstance(parsed, dict):
                document = parsed
        except (ProtocolError, ValueError, RecursionError):
            # An error page from an intermediary. The status is still worth
            # reporting; its body is not.
            pass

        if error.code in report_statuses and document and "type" not in document:
            return document

        raise error_from_problem(
            error.code,
            document,
            request_id=error.headers.get("X-Request-Id") or "",
            retry_after=_parse_retry_after(error.headers.get("Retry-After")),
        )

    @staticmethod
    def _ref(subject_ref: str) -> str:
        """Encode a subject reference as exactly one path segment.

        safe="" matters: the default leaves "/" alone, and a reference such as
        "tenant/42" would then address a different route altogether.
        """
        if not isinstance(subject_ref, str) or not subject_ref:
            raise ValueError("subject_ref is empty")
        if subject_ref in (".", ".."):
            # Percent-encoding leaves these as they are, and every HTTP stack
            # on the way would resolve them as path navigation.
            raise ValueError("subject_ref cannot be '.' or '..'")
        return urllib.parse.quote(subject_ref, safe="")

    # --- subjects ---

    def resolve_subject(
        self, subject_ref: str, display_name: Optional[str] = None
    ) -> Subject:
        """Resolve a reference to a subject, creating it if needed.

        Idempotent, so it is safe to call on every login rather than tracking
        whether the service has seen the user before. It is also the only call
        that creates a subject: the ceremony routes refuse an unknown one, so
        that a caller cannot fill the database by starting ceremonies it never
        finishes.
        """
        if not isinstance(subject_ref, str) or not subject_ref:
            raise ValueError("subject_ref is empty")
        body: Dict[str, Any] = {"subject_ref": subject_ref}
        if display_name:
            body["display_name"] = display_name
        return Subject.from_dict(self._request("POST", "/v1/subjects", body))

    def get_subject(self, subject_ref: str) -> Subject:
        """Report which factors a subject has enrolled, without creating it.

        Raises NotFound for an unknown reference.
        """
        return Subject.from_dict(
            self._request("GET", "/v1/subjects/" + self._ref(subject_ref))
        )

    # --- WebAuthn ---

    def begin_registration(
        self, subject_ref: str, label: Optional[str] = None
    ) -> Dict[str, Any]:
        """Start a WebAuthn registration ceremony.

        Returns ``challenge_id``, ``options`` and ``expires_at``. ``options``
        is the PublicKeyCredentialCreationOptions structure and goes to the
        browser unchanged, which is why it stays a plain dict: a model of it
        here could only lose members the browser needs.
        """
        body: Optional[Dict[str, Any]] = {"label": label} if label else None
        return self._request(
            "POST", "/v1/webauthn/" + self._ref(subject_ref) + "/register", body
        )

    def complete_registration(
        self, subject_ref: str, challenge_id: str, credential: Mapping[str, Any]
    ) -> Dict[str, Any]:
        """Finish a registration with the PublicKeyCredential from the browser.

        ``credential`` is forwarded verbatim. Returns the stored ``credential``
        and ``recovery_codes_remaining``; zero after a first registration is
        the cue to call issue_recovery_codes.
        """
        return self._request(
            "POST",
            "/v1/webauthn/" + self._ref(subject_ref) + "/register/complete",
            {"challenge_id": challenge_id, "credential": credential},
        )

    def begin_assertion(self, subject_ref: str) -> Dict[str, Any]:
        """Start a WebAuthn authentication ceremony.

        Returns ``challenge_id``, ``options`` (PublicKeyCredentialRequestOptions,
        for the browser, unchanged) and ``expires_at``.
        """
        return self._request(
            "POST", "/v1/webauthn/" + self._ref(subject_ref) + "/assert"
        )

    def complete_assertion(
        self, subject_ref: str, challenge_id: str, credential: Mapping[str, Any]
    ) -> AssertionResult:
        """Finish an authentication. Raises AuthenticationFailed when refused."""
        return AssertionResult.from_dict(
            self._request(
                "POST",
                "/v1/webauthn/" + self._ref(subject_ref) + "/assert/complete",
                {"challenge_id": challenge_id, "credential": credential},
            )
        )

    def begin_discoverable_assertion(self) -> Dict[str, Any]:
        """Start an authentication ceremony without naming the subject.

        This is the passkey flow. The options carry no allow list, so the
        browser offers whichever credentials the authenticator holds for this
        relying party and the user picks one.

        The ceremony always requires user verification, whatever the deployment
        configures for the named flow: a ceremony that names nobody is answered
        by the authenticator alone, so possession on its own would let a found
        passkey sign in as its owner.

        Returns ``challenge_id``, ``options`` and ``expires_at``.
        """
        return self._request("POST", "/v1/webauthn/assert/discoverable")

    def complete_discoverable_assertion(
        self, challenge_id: str, credential: Mapping[str, Any]
    ) -> AssertionResult:
        """Finish a ceremony begun without a subject.

        The result's ``subject_id`` reports which subject the credential
        belonged to. ``credential`` must carry the ``userHandle`` the
        authenticator returned, which a browser includes for a discoverable
        credential.

        Verify ``assertion`` before granting anything, and take the subject
        identifier from the verified claims rather than from the body, which is
        unsigned. Raises AuthenticationFailed when refused.
        """
        return AssertionResult.from_dict(
            self._request(
                "POST",
                "/v1/webauthn/assert/discoverable/complete",
                {"challenge_id": challenge_id, "credential": credential},
            )
        )

    # --- TOTP ---

    def enrol_totp(self, subject_ref: str) -> TOTPEnrolment:
        """Issue a TOTP secret. It stays inert until confirm_totp succeeds."""
        return TOTPEnrolment.from_dict(
            self._request("POST", "/v1/totp/" + self._ref(subject_ref) + "/enrol")
        )

    def confirm_totp(self, subject_ref: str, code: str) -> Dict[str, Any]:
        """Confirm a pending enrolment with a first code.

        Returns ``secret_id`` and ``confirmed``. A wrong code raises
        AuthenticationFailed.
        """
        return self._request(
            "POST",
            "/v1/totp/" + self._ref(subject_ref) + "/enrol/confirm",
            {"code": code},
        )

    def verify_totp(self, subject_ref: str, code: str) -> AssertionResult:
        """Authenticate with a TOTP code and receive a signed assertion."""
        return AssertionResult.from_dict(
            self._request(
                "POST", "/v1/totp/" + self._ref(subject_ref) + "/verify", {"code": code}
            )
        )

    # --- recovery codes ---

    def issue_recovery_codes(self, subject_ref: str) -> RecoveryBatch:
        """Issue a batch of single-use codes, retiring every unused earlier one.

        Show the codes to the user straight away; there is no second chance.
        """
        return RecoveryBatch.from_dict(
            self._request("POST", "/v1/recovery/" + self._ref(subject_ref) + "/issue")
        )

    def consume_recovery_code(self, subject_ref: str, code: str) -> AssertionResult:
        """Authenticate with a recovery code.

        The assertion carries ``amr`` of ``["recovery-code"]``. Applications
        commonly treat that as lower assurance and force a re-enrolment.
        """
        return AssertionResult.from_dict(
            self._request(
                "POST",
                "/v1/recovery/" + self._ref(subject_ref) + "/consume",
                {"code": code},
            )
        )

    # --- health ---

    def health(self) -> Dict[str, Any]:
        """Read the liveness probe: ``{"status": ...}``.

        The probe answers 503 with the same report when the service is
        degraded. That is an answer to the question asked rather than a failed
        request, so the report is returned and the caller reads ``status``. A
        503 carrying a problem document still raises Unavailable.
        """
        return self._request("GET", "/v1/health", report_statuses=(503,))

    def health_detail(self) -> Dict[str, Any]:
        """Read the authenticated health report (needs the health scope)."""
        return self._request("GET", "/v1/health/detail")
