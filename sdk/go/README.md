# n0passtemps Go SDK

The Go client for the [n0passtemps](https://github.com/Socold/n0passtemps)
authentication server: WebAuthn, TOTP and single-use recovery codes, called
server to server with an API key.

It does two things. `Client` calls the `/v1` routes. `Verifier` checks the
signed assertion that a successful ceremony returns, which is the step that
frees your application from trusting the network path to the server, and the
step integrations most often get wrong.

Standard library only. No global state. Go 1.22 or later.

## Install

```sh
go get github.com/Socold/n0passtemps/sdk/go
```

The import path ends in `/go` while the package is named `n0passtemps`, so name
the import:

```go
import n0passtemps "github.com/Socold/n0passtemps/sdk/go"
```

The SDK is its own module, nested in the server repository. It shares no
dependency with the server, and being nested its releases are tagged in the
form `sdk/go/v1.1.0`, which is what the go command looks for.

## End to end

A TOTP sign-in, from the code the user typed to a decision your application
can act on.

```go
func signIn(ctx context.Context, userRef, code string) (*n0passtemps.Claims, error) {
	client, err := n0passtemps.New("https://auth.example.org", os.Getenv("N0PASSTEMPS_API_KEY"))
	if err != nil {
		return nil, err
	}
	keys, err := n0passtemps.RemoteJWKS("https://auth.example.org/v1/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	verifier, err := n0passtemps.NewVerifier("n0passtemps", os.Getenv("N0PASSTEMPS_API_KEY_ID"), keys)
	if err != nil {
		return nil, err
	}
	result, err := client.VerifyTOTP(ctx, userRef, code)
	switch {
	case errors.Is(err, n0passtemps.ErrAuthenticationFailed):
		return nil, errWrongCode // an answer for the user, not a fault
	case err != nil:
		return nil, err
	}

	claims, err := verifier.Verify(ctx, result.Assertion)
	if err != nil {
		return nil, err
	}
	if !replayCache.FirstUse(claims.ID, time.Unix(claims.ExpiresAt, 0)) {
		return nil, errReplayed
	}
	return claims, nil // now issue your own session for claims.Subject
}
```

The audience given to `NewVerifier` is the identifier of your API key, the
`api_key.id` member of the response that minted it; it is not the secret token.

Build the client, the key source and the verifier once, at start-up, and share
them: all three are safe for concurrent use, and the key source holds the JWKS
cache. They are built inline above only to keep the example in one piece.
`replayCache`, `errWrongCode` and `errReplayed` are yours to define.

Runnable versions of this and of the WebAuthn flow are in
[`example_test.go`](example_test.go); `go test -run Example -v` executes them
against a stand-in server.

### WebAuthn

Each ceremony is two round trips with the browser in the middle.

```go
ceremony, err := client.BeginAssertion(ctx, userRef)
// Send ceremony.Options to the page. Keep ceremony.ChallengeID in the session.

// The page calls navigator.credentials.get() and posts the result back.
result, err := client.CompleteAssertion(ctx, userRef, challengeID, credentialJSON)
claims, err := verifier.Verify(ctx, result.Assertion)
```

`Options` and the credential are `json.RawMessage` and the SDK never looks
inside them. Forward them byte for byte. The server parses the credential with
a WebAuthn library, and a member dropped by an intermediate struct is a member
the library can no longer verify. `Options` is an object with one `publicKey`
member in WebAuthn's JSON form; the page converts its base64url members to
buffers before the call, as `examples/node/register.html` in the server
repository shows.

Registration is the same shape: `BeginRegistration`, then
`CompleteRegistration`. The subject must exist first, so call `ResolveSubject`,
which is idempotent and may be called on every login.

### The other calls

| Method | Route |
| --- | --- |
| `ResolveSubject`, `GetSubject` | `POST /v1/subjects`, `GET /v1/subjects/{ref}` |
| `BeginRegistration`, `CompleteRegistration` | `POST /v1/webauthn/{ref}/register`, `.../register/complete` |
| `BeginAssertion`, `CompleteAssertion` | `POST /v1/webauthn/{ref}/assert`, `.../assert/complete` |
| `EnrolTOTP`, `ConfirmTOTP`, `VerifyTOTP` | `POST /v1/totp/{ref}/enrol`, `.../enrol/confirm`, `.../verify` |
| `IssueRecoveryCodes`, `ConsumeRecoveryCode` | `POST /v1/recovery/{ref}/issue`, `.../consume` |
| `Health`, `HealthDetail` | `GET /v1/health` (no API key sent), `GET /v1/health/detail` |

The subject reference is escaped with `url.PathEscape`, so it may contain a
slash, a space or an at sign. Prefer an opaque identifier to an email address
all the same: the reference travels in URL paths, and reverse proxies log
paths. The SDK keeps it out of its own error messages for the same reason. The
values `.` and `..` are refused, because no escaping makes them a single path
segment.

## Configuration

```go
client, err := n0passtemps.New(baseURL, apiKey,
	n0passtemps.WithTimeout(5*time.Second),      // per attempt; the default is 10s
	n0passtemps.WithHTTPClient(myHTTPClient),    // your transport, proxy, mTLS
	n0passtemps.WithUserAgent("acme-portal/2.1"),
	n0passtemps.WithRetries(2),                  // off by default; see below
)
```

**https is required.** The API key is a bearer credential: whoever reads it off
the wire can run ceremonies against every subject of your tenant, and nothing
binds it to the connection it travelled on. `New` therefore refuses a plain
`http` base URL unless the host is loopback (`localhost`, `127.0.0.0/8`,
`::1`), where the traffic never leaves the machine. If TLS is terminated by a
proxy you trust on a private segment, say so in code with
`WithInsecureTransport()`. `RemoteJWKS` applies the same rule, with
`WithInsecureJWKS()` as the opt-out: whoever can alter the key set in transit
can forge a login for anyone.

**Redirects are not followed** by the default HTTP client. The API never
redirects, and a redirect is a way to walk a credential to another origin. If
you pass your own client, that decision becomes yours.

**Retries are narrow.** With `WithRetries(n)`, only `GetSubject`,
`ResolveSubject`, `Health` and `HealthDetail` are repeated, and only after a
transport failure or a 502, 503 or 504. No ceremony call is ever retried:
challenges, TOTP codes and recovery codes are single use on the server, so a
second attempt can only fail and would count against the subject's throttle.
An authentication failure and a 429 always go straight back to you.

Responses are read up to 1 MiB and refused beyond that with
`ErrResponseTooLarge`.

## Verifying an assertion

`VerifyTOTP`, `CompleteAssertion` and `ConsumeRecoveryCode` return an
`AssertionResult` (inside a `RecoveryResult` for the last of them). Its `Assertion` field is a compact JWS signed with Ed25519.
The other fields (`SubjectID`, `Factors`) are a convenience and are **not
signed**: decide nothing on them. Verify the assertion and act on the claims.

```go
keys, err := n0passtemps.RemoteJWKS(baseURL+"/v1/.well-known/jwks.json", nil)
verifier, err := n0passtemps.NewVerifier(issuer, audience, keys)
claims, err := verifier.Verify(ctx, result.Assertion)
```

`issuer` is the server's configured issuer name, `n0passtemps` by default.
`audience` is the identifier of your API key (`api_key.id`). Both are
required: pinning the audience is what stops an assertion obtained through
another tenant's key from being presented to you.

### What `Verify` checks, in this order

1. Exactly three segments. Two is an unsecured JWS, four is something a second
   parser might read differently.
2. Strict unpadded base64url in every segment. Padding, the standard alphabet,
   stray line breaks and non-zero trailing bits are refused, so a token has one
   spelling only.
3. `alg` is exactly `EdDSA`. The algorithm is fixed by the SDK and never chosen
   by the token. This one comparison is what refuses `alg: none`, and `HS256`
   computed with your public key as the HMAC secret.
4. No `crit` header. The verifier understands no extension, so it refuses them
   all.
5. `typ`, when present, is `JWT`.
6. The key is selected by `kid`, one candidate only. The verifier never tries
   the other keys of the set.
7. **The signature**, over the header and payload bytes as received. Nothing in
   the payload is parsed before this holds.
8. `iss` and `aud` match. `sub` and `amr` are present.
9. `exp` is present and not past; `nbf` is not in the future. Both allow a
   clock skew, 30 seconds by default (`WithClockSkew`). A missing `exp` is a
   refusal, never "no expiry". The clock is injectable with `WithClock`.

Every failure returns the same `ErrInvalidAssertion`. Which check failed is
deliberately not reported, because the difference tells an attacker whether a
forgery had the right audience or whether a `kid` exists, and error strings
tend to reach the person on the other end. One operational distinction is kept:
when the key source itself fails, the error matches both `ErrInvalidAssertion`
and `ErrKeysUnavailable`, so you can alert on a JWKS outage without treating it
as an attack. It still fails closed.

### What `Verify` leaves to you

**Enforce single use of `jti`.** An assertion lives sixty seconds by default,
and within that window a copy verifies as well as the original. Record
`claims.ID` until `claims.ExpiresAt`, in a store shared by every instance of
your application, and refuse an identifier seen before.

**Check `amr` against your own policy.** The factors are not equivalent.

```go
switch {
case claims.HasFactor(n0passtemps.FactorWebAuthnUV):
	// possession and user verification: your strongest sign-in
case claims.HasFactor(n0passtemps.FactorWebAuthn), claims.HasFactor(n0passtemps.FactorTOTP):
	// fine for a sign-in; step up before a sensitive operation
case claims.HasFactor(n0passtemps.FactorRecoveryCode):
	// a bearer secret that may have sat in a drawer for a year:
	// allow re-enrolling an authenticator, and little else
}
```

`webauthn-uv` is reported only when the authenticator verified the user during
that very ceremony. It is never inferred from how the credential was
registered.

`AssertionResult.Signals` may carry `sign_count_regression` or
`binding_changed`. They did not refuse the authentication; they are there so
that you can decide to step up.

### Key sources

`RemoteJWKS(url, client)` fetches the JWK Set and caches it for five minutes
(`WithJWKSCacheTTL`), which is the `max-age` the server sets. A `kid` missing
from a fresh cache triggers **one** refetch, so a key rotation is picked up at
once. Such refetches are at least ten seconds apart
(`WithJWKSRefetchInterval`): the `kid` is attacker controlled and is read
before any signature can be checked, so without that spacing anyone able to
submit tokens could turn your verifier into a request amplifier aimed at the
server. Tokens refused on their header or signature length never reach the key
source at all.

When the endpoint is down and the cache has lapsed, verification fails. A
stale key is not served: a key withdrawn after a compromise must stop verifying
once the cache lifetime has passed.

An entry of the set is used only if it is an Ed25519 signing key whose `kid` is
the RFC 7638 thumbprint of its own `x`. Anything else is skipped.

`StaticKeys` pins keys in your configuration and makes no network call:

```go
keys, err := n0passtemps.NewStaticKeys(serverPublicKey)  // indexed by thumbprint
keys, err := n0passtemps.ParseJWKS(savedJWKSDocument)    // from a saved document
```

With static keys a rotation on the server needs a configuration change on your
side. Any type with a `Key(ctx, kid)` method is a `KeySource`; return
`ErrKeyNotFound` for an unknown `kid`, and never fall back on another key.

## Errors

A refusal from the server is an `*Error`, decoded from its RFC 9457 problem
body.

```go
var apiErr *n0passtemps.Error
if errors.As(err, &apiErr) {
	log.Printf("n0passtemps refused: status=%d type=%s request=%s", apiErr.Status, apiErr.Type, apiErr.RequestID)
}
```

| Field | Meaning |
| --- | --- |
| `Status` | The HTTP status code |
| `Type` | The stable `urn:n0passtemps:error:*` identifier; empty if a proxy answered |
| `Title` | A fixed description of the class of failure |
| `Detail` | Present on input validation and state conflicts only |
| `RequestID` | Matches `X-Request-Id`; quote it to the operator, it locates the audit entry |
| `RetryAfter` | The `Retry-After` header as a `time.Duration`; zero when absent |

Branch with `errors.Is`:

| Sentinel | Status | Problem type | What to do |
| --- | --- | --- | --- |
| `ErrUnauthorized` | 401 | `unauthorized` | The API key is missing, unknown or revoked. A configuration fault; nothing to do with the end user |
| `ErrAuthenticationFailed` | 401 | `ceremony-failed` | The user did not authenticate. Tell them so. Do not retry |
| `ErrForbidden` | 403 | `forbidden` | The API key lacks the scope for this route |
| `ErrNotFound` | 404 | `not-found` | Unknown subject, from `GetSubject` only |
| `ErrConflict` | 409 | `conflict` | State conflict, such as confirming an expired TOTP enrolment. `Detail` says which |
| `ErrThrottled` | 429 | `throttled` | Wait `RetryAfter`, and show the user a lockout message |
| `ErrUnavailable` | 503 | `unavailable` | The server cannot reach its store. The key was not examined; try again later |

Two statuses are shared. A 401 is either your API key or the user's ceremony,
and only the problem type tells them apart, which is why
`ErrAuthenticationFailed` matches on the type alone and never on the status. A
sentinel falls back on the status code only when the body carried no type, as
when a proxy in front of the server produced the answer.

The server gives the same `ceremony-failed` answer for a wrong code, an expired
challenge, an unknown subject and a locked one, on purpose. There is nothing
more to learn from it. Use `GetSubject` beforehand to decide what to offer.

`bad-request`, `payload-too-large`, `unsupported-media-type` and `internal`
have no sentinel; compare `Type` with the `Type*` constants if you need them.

Errors that are not an `*Error` are local: a transport failure, a timeout
(`context.DeadlineExceeded`), `ErrResponseTooLarge`, or an argument refused
before any request was sent.

## Testing

```sh
go test -race ./...
```

The tests use `httptest` servers and make no network call. They cover the
request shape of every method, problem decoding, and a verifier suite with the
known thumbprint vector of RFC 8037 appendix A.3, tampering, `alg: none`,
HS256 key confusion, `crit`, time boundaries, encoding strictness, and the JWKS
cache with its refetch limit.
