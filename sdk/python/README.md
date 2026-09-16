# n0passtemps for Python

Client SDK for the [n0passtemps](https://github.com/Socold/n0passtemps)
authentication server: WebAuthn ceremonies, TOTP, recovery codes, and offline
verification of the signed assertion that a successful authentication returns.

- Python 3.9 and later, fully typed (`py.typed`).
- The client has no runtime dependency; it is built on `urllib`.
- Verifying assertions needs an Ed25519 primitive, which the standard library
  lacks. It comes from the optional `cryptography` dependency. The SDK ships no
  signature code of its own.

## Install

```sh
pip install n0passtemps            # client only
pip install "n0passtemps[verify]"  # client and assertion verification
```

## End to end

The browser half of a WebAuthn ceremony (`navigator.credentials.create` and
`.get`) is yours. The SDK covers the server half: it hands you the `options`
for the browser and takes the `credential` the browser produced, both as plain
dicts, untouched.

```python
import os

from n0passtemps import Client, AuthenticationFailed, Throttled
from n0passtemps import Verifier, RemoteJWKS

BASE_URL = "https://auth.example.org"
API_KEY_ID = os.environ["N0PASSTEMPS_API_KEY_ID"]  # the id of the key, from the admin API

client = Client(BASE_URL, api_key=os.environ["N0PASSTEMPS_API_KEY"])

# 1. Make sure the subject exists. Idempotent: call it on every login.
subject = client.resolve_subject("user-8f3a1c", display_name="Alice")

# 2. Registration, when the subject has no authenticator yet.
if subject.credential_count == 0:
    begun = client.begin_registration("user-8f3a1c", label="Laptop")
    # send begun["options"] to the browser, get its PublicKeyCredential back
    client.complete_registration("user-8f3a1c", begun["challenge_id"], credential)
    batch = client.issue_recovery_codes("user-8f3a1c")
    show_once(batch.codes)  # they cannot be displayed again

# 3. Authentication.
begun = client.begin_assertion("user-8f3a1c")
try:
    result = client.complete_assertion("user-8f3a1c", begun["challenge_id"], credential)
except AuthenticationFailed:
    ...  # not authenticated; the service never says why
except Throttled as error:
    ...  # wait error.retry_after seconds

# 4. Verify the proof before opening a session (see the next section).
verifier = Verifier(
    issuer="n0passtemps",
    audience=API_KEY_ID,
    keys=RemoteJWKS(BASE_URL + "/v1/.well-known/jwks.json"),
)
claims = verifier.verify(result.assertion)
```

Build the `Verifier` once, at start-up, and share it: that is what makes its
key cache useful.

TOTP and recovery codes follow the same shape:

```python
enrolment = client.enrol_totp("user-8f3a1c")     # .secret, .provisioning_uri: shown once
client.confirm_totp("user-8f3a1c", "123456")     # the secret is inert until this succeeds
result = client.verify_totp("user-8f3a1c", "654321")
result = client.consume_recovery_code("user-8f3a1c", "ABCD-EFGH-JKLM")
result.recovery_codes_remaining
```

| Method | Route | Returns |
|---|---|---|
| `resolve_subject(ref, display_name=None)` | `POST /v1/subjects` | `Subject` |
| `get_subject(ref)` | `GET /v1/subjects/{ref}` | `Subject` |
| `begin_registration(ref, label=None)` | `POST /v1/webauthn/{ref}/register` | `dict` |
| `complete_registration(ref, challenge_id, credential)` | `POST /v1/webauthn/{ref}/register/complete` | `dict` |
| `begin_assertion(ref)` | `POST /v1/webauthn/{ref}/assert` | `dict` |
| `complete_assertion(ref, challenge_id, credential)` | `POST /v1/webauthn/{ref}/assert/complete` | `AssertionResult` |
| `enrol_totp(ref)` | `POST /v1/totp/{ref}/enrol` | `TOTPEnrolment` |
| `confirm_totp(ref, code)` | `POST /v1/totp/{ref}/enrol/confirm` | `dict` |
| `verify_totp(ref, code)` | `POST /v1/totp/{ref}/verify` | `AssertionResult` |
| `issue_recovery_codes(ref)` | `POST /v1/recovery/{ref}/issue` | `RecoveryBatch` |
| `consume_recovery_code(ref, code)` | `POST /v1/recovery/{ref}/consume` | `AssertionResult` |
| `health()` | `GET /v1/health` | `dict` |
| `health_detail()` | `GET /v1/health/detail` | `dict` |

The result classes are frozen dataclasses. Each keeps the decoded response in
`.raw`, so a member added by a newer server is reachable without an SDK
release. `AssertionResult` carries `.assertion`, `.expires_at`, `.factors`,
`.signals`, `.subject_id` and, after a recovery code,
`.recovery_codes_remaining`. `health()` returns the liveness report even when
the service answers 503 with one; read its `status`.

The subject reference is your own identifier for the user. It is
percent-encoded into a single path segment, so any character is safe, but
prefer an opaque identifier to an email address: it travels in the request
path, where a reverse proxy may log it.

### What the client does to protect the API key

The key is a bearer credential, so the client is strict about where it goes:

- a base URL that is not `https` is refused, unless the host is loopback or you
  pass `allow_insecure_transport=True`;
- a redirect is followed only for a `GET` that stays on the same scheme, host
  and port. `urllib` would otherwise copy the `Authorization` header to
  whichever host a `Location` header names;
- `repr(client)` shows the base URL only, and no exception message contains
  the key;
- TLS verification cannot be switched off. For an internal certificate
  authority, pass `ca_file="/path/to/ca.pem"`.

Responses are capped at 1 MiB, the default timeout is 10 seconds, and nothing
is retried: several routes consume single-use material (a challenge, a TOTP
step, a recovery code), so whether a repeat is safe is your decision.

## Verifying the assertion

`result.assertion` is a compact JWS signed with Ed25519. Verifying it means
your application does not have to trust the network path between itself and
the service: a bare `200 OK` can be faked by whoever sits on that path, a
signature cannot.

```python
from n0passtemps import Verifier, RemoteJWKS, StaticKeys, InvalidAssertion

verifier = Verifier(
    issuer="n0passtemps",            # the iss your deployment is configured with
    audience=API_KEY_ID,             # the id of your API key, not the key itself
    keys=RemoteJWKS("https://auth.example.org/v1/.well-known/jwks.json"),
    clock_skew=30,
)

try:
    claims = verifier.verify(result.assertion)
except InvalidAssertion:
    ...  # refuse; there is deliberately no further detail
```

`verify` performs, in this order:

1. exactly three segments, each strict unpadded base64url (padding,
   characters outside the alphabet and non-canonical trailing bits are all
   refused);
2. the header `alg` is exactly `EdDSA`. The algorithm is never chosen from the
   token, so `none`, `HS256` keyed with the public key, and everything else
   are refused before any key is looked up;
3. any `crit` header is refused, and `typ`, when present, must be `JWT`;
4. the key is selected by `kid`, and only that key is tried;
5. the signature is verified **before** any claim is read;
6. then `iss`, `aud`, `sub`, `amr`, `jti`, `exp` (required) and `nbf`, the last
   two with `clock_skew`.

Every failure raises the same `InvalidAssertion`, with no indication of which
check failed. Telling a caller that a forged token had the right audience, or
that a `kid` exists, would help nobody but an attacker. The one separate
outcome is `TransportError`, when `RemoteJWKS` cannot fetch the keys: that is
an outage on your side, not a property of the token.

### Two checks that remain yours

- **Enforce single use of `jti`.** An assertion stays valid until `exp`, about
  a minute. Within that window nothing in the verifier stops it being
  presented twice. Record each accepted `claims.jti` until `claims.expires_at`
  has passed, and refuse a repeat.
- **Check `amr` against your own policy.** `claims.amr` lists the factors that
  authenticated the subject: `webauthn`, `webauthn-uv` (the authenticator also
  verified the user with a PIN or a biometric), `totp`, `recovery-code`. The
  verifier proves the list is authentic; whether `recovery-code` alone may open
  a session, or whether a sensitive operation needs `webauthn-uv`, is for your
  application to decide.

```python
if not replay_cache.add(claims.jti, until=claims.expires_at):
    raise PermissionError("assertion already used")
if "webauthn-uv" not in claims.amr:
    raise PermissionError("user verification required")
```

### Key sources

`RemoteJWKS(url, cache_seconds=300, min_refetch_interval=10)` fetches the
published key set and caches it. A token naming an unknown `kid` triggers one
refetch, which is how a rotated key is picked up straight away. Because that
path is driven by unverified input, all fetches are limited to one per
`min_refetch_interval`: a flood of tokens with random `kid` values cannot turn
your verifier into a request amplifier aimed at the service. Once the cache has
lapsed, a failed fetch raises `TransportError` instead of trusting keys of
unknown age. The URL must be `https` unless the host is loopback, since whoever
can rewrite that response chooses your verification keys.

`StaticKeys(jwks)` takes a JWK Set document you hold in configuration, and
`StaticKeys.from_public_keys([raw32bytes])` takes raw keys. No network is
involved, at the price of a configuration change when the service rotates its
key.

`jwk_thumbprint(jwk)` returns the RFC 7638 thumbprint of an Ed25519 JWK, the
value the service uses as `kid`. A published key whose `kid` does not match its
own thumbprint is ignored.

Without the `cryptography` package, constructing a `Verifier` raises
`VerificationUnavailable` with the install command, at start-up and not at the
first login.

## Errors

Everything derives from `N0PasstempsError`. An `APIError` carries the RFC 9457
problem document: `status`, `type`, `title`, `detail`, `request_id`,
`retry_after`, and `raw`. The subclass is chosen from the problem `type`, not
from the status, because 401 means two different things.

| Exception | Problem `type` (after `urn:n0passtemps:error:`) | Status | Meaning |
|---|---|---|---|
| `Unauthorized` | `unauthorized` | 401 | Your API key is missing, unknown or revoked. |
| `AuthenticationFailed` | `ceremony-failed` | 401 | The end user did not authenticate. No reason is given, by design. |
| `Forbidden` | `forbidden` | 403 | The key lacks the scope, or the authenticator model is not permitted. |
| `NotFound` | `not-found` | 404 | No such subject (`get_subject` only). |
| `Conflict` | `conflict` | 409 | State conflict, named in `detail`: authenticator already registered, credential limit, no authenticator. |
| `Throttled` | `throttled` | 429 | Too many attempts. Wait `retry_after` seconds. |
| `Unavailable` | `unavailable` | 503 | A dependency of the service is down. |
| `APIError` | `bad-request`, `payload-too-large`, `unsupported-media-type`, `internal` | 400, 413, 415, 500 | Everything else; `detail` explains a 400. |
| `TransportError` | | | No HTTP response: connection, TLS, timeout, or a refused redirect. |
| `ProtocolError` | | | A response that is not what the API describes, or a body over 1 MiB. |
| `ConfigurationError` | | | Unusable constructor arguments. Also a `ValueError`. |
| `InvalidAssertion` | | | The assertion failed verification. |
| `VerificationUnavailable` | | | `cryptography` is not installed. |

An unknown subject on an authentication route is reported as
`AuthenticationFailed`, not `NotFound`, so those routes cannot be used to test
whether somebody has an account. When a response carries no recognised `type`
(an error page from a proxy, say), the class falls back on the status; a bare
401 then maps to `Unauthorized`, never to `AuthenticationFailed`.

Quote `error.request_id` when asking the operator about a failure: it locates
the log and audit entries where the real reason was written.

## Development

```sh
cd sdk/python
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m mypy --strict src
```

The tests use a local `http.server` on loopback and never touch the network.
The verifier tests are skipped, with a message, when `cryptography` is not
installed.

## Licence

MIT, like the server.
