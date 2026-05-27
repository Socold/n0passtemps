# Examples

Working clients for the `/v1` and `/admin/v1` surfaces, in shell, Python, Node
and Go. They are written to be read as much as run: each one says why a call is
shaped the way it is, and none of them hides a step.

The contract they implement is `../api/openapi.yaml`.

## The WebAuthn ceremony needs a browser

Registration and assertion are two round trips with
`navigator.credentials.create()` or `navigator.credentials.get()` in the middle.
That call needs a browser, a secure context, a user gesture and an
authenticator. No shell script, Python script or Node script can perform it.

What the non-browser examples therefore cover is everything on either side of
it: resolving subjects, starting a ceremony and obtaining the options the
browser needs, finishing one with a credential the browser has already
produced, and verifying the assertion that comes back. `node/register.html` is
the only example that runs a ceremony end to end, and it runs in a browser.

TOTP and recovery codes have no browser requirement, which is why the shell and
Python examples cover those in full.

## Shared environment

| Variable | Used by | Meaning |
| --- | --- | --- |
| `N0PASSTEMPS_URL` | everything | The base URL, for example `http://127.0.0.1:8080`. |
| `N0PASSTEMPS_API_KEY` | the `/v1` examples | An `npt_` token from `POST /admin/v1/api-keys`. A key minted with `scopes` reaches only those route families, so give it the ones the example calls: `subjects` for all of them, plus `totp`, `recovery`, `webauthn` or `health`. A key minted without scopes is unrestricted. |
| `N0PASSTEMPS_ADMIN_TOKEN` | `curl/admin.sh` | An `npa_` token from `POST /admin/v1/admin-tokens`. On a fresh deployment the first ones come from the one-shot command `n0passtemps-server -config <path> -bootstrap-admin -admins 2`, or `docker compose run --rm n0passtemps -bootstrap-admin -admins 2`; the running service never prints a token. |
| `N0PASSTEMPS_EXPECTED_AUDIENCE` | the verifiers | The `id` of the API key the ceremony was performed for, as `GET /admin/v1/api-keys` reports it. It is the `aud` claim a verifier pins. |
| `N0PASSTEMPS_ISSUER` | the verifiers | Pins the `iss` claim. Defaults to `n0passtemps`, which matches the shipped configuration. |
| `N0PASSTEMPS_CA_FILE` | `python/client.py` | A PEM certificate to trust, for a deployment serving an internal certificate. |

Every example stops with a sentence when a variable it needs is unset. None of
them carries a default credential, and the placeholders in the usage headers
are not valid tokens.

The two credential kinds are not interchangeable. An `npt_` token is refused on
`/admin/v1` and an `npa_` token is refused on `/v1`: the kind is bound into the
stored digest as well as checked on the way in. Both are shown once, when they
are minted, and cannot be retrieved afterwards.

## curl

Bash with `jq`. Each script checks for `jq` and says where to get it.

| Script | What it does |
| --- | --- |
| `curl/health.sh` | The unauthenticated liveness probe, then the authenticated component report. |
| `curl/subject.sh` | Resolves a subject reference, then reads back its enrolled factors. |
| `curl/totp.sh` | The whole TOTP flow: enrol, show the provisioning URI, confirm with a code you type, then authenticate with a second one. |
| `curl/recovery.sh` | Issues a batch of recovery codes, spends one, then shows that the same code is refused a second time. |
| `curl/admin.sh` | Mints an API key, lists the keys and the subjects, reads the audit log, and verifies the audit hash chain. |

`curl/subject.sh`, `curl/totp.sh` and `curl/recovery.sh` take the subject
reference as their first argument and default to `example-user-0001`.
`curl/health.sh` and `curl/admin.sh` take no arguments.

Two of them change state. `curl/recovery.sh` retires any unused codes the
subject was holding, and `curl/admin.sh` mints a real key unless you set
`N0PASSTEMPS_SKIP_MINT=1`. Point them at a development deployment.

For a deployment with an internal certificate, `curl` reads `CURL_CA_BUNDLE`.

## Python

The standard library only, with one documented exception.

| File | What it does |
| --- | --- |
| `python/client.py` | A reusable client: subjects, TOTP, recovery codes, the server-side halves of a WebAuthn ceremony, and the claim checks of assertion verification. |
| `python/verify_totp.py` | Drives a TOTP enrolment and verification with it. Interactive. |
| `python/verify_assertion.py` | Verifies an assertion against the JWKS endpoint. |
| `python/requirements.txt` | One line, for `verify_assertion.py` alone. |

`python/verify_assertion.py` is the exception. Python has no Ed25519 in its
standard library, so the raw signature check cannot be written there honestly
without a dependency, and the file uses `cryptography` for that one primitive.
Everything else in the verification lives in `client.py` and needs nothing:
`AssertionVerifier` performs all of the parsing and claim checks itself and
takes the signature check as a callable. That split keeps the rules the JWS
confusion attacks exploit in one dependency-free place, whichever backend
supplies the primitive.

```sh
python3 -m pip install -r python/requirements.txt   # for verify_assertion.py only
cd python && ./verify_totp.py
```

`verify_assertion.py` needs no API key: the JWKS route carries no credential,
because its contents are public keys and a verifying party has to be able to
fetch them.

## Node

Node 20 or later. No npm dependencies: `fetch` and `crypto` are built in.

| File | What it does |
| --- | --- |
| `node/assert.mjs` | Drives an assertion ceremony from the server side, printing the options for the browser and the `navigator.credentials.get()` call the front end must run. |
| `node/verify.mjs` | Fetches the JWKS document and verifies an assertion with `crypto.createPublicKey` on the OKP JWK and `crypto.verify`. |
| `node/register.html` | A self-contained page performing a real `navigator.credentials.create()` ceremony, with the base64url conversions written out. |

`node/assert.mjs` runs in two passes. The first prints the challenge and the
options; the second, with `--credential`, sends what the browser returned:

```sh
node assert.mjs example-user-0001
node assert.mjs example-user-0001 --credential credential.json
```

`node/register.html` has to be served over HTTP from an origin the deployment
lists in `server.cors_allowed_origins`, from a host matching `webauthn.rp_id`:

```sh
python3 -m http.server 5173 --directory node
```

then open `http://localhost:5173/register.html`. Browsers treat
`http://localhost` as a secure context, so no certificate is needed for local
work.

That page asks for the API key in a form field, which is wrong anywhere but a
developer's machine, and it says so on the page. In a deployment the key stays
on your server: the front end calls your backend and the backend relays the two
round trips. The two `fetch` calls in the page stand in for that relay.

## Go

| File | What it does |
| --- | --- |
| `go/client.go` | Subject resolution, the server-side halves of an assertion, TOTP verification, and assertion verification against `crypto/ed25519`. |

It carries `//go:build ignore`, so `go build ./...` and `go vet ./...` at the
repository root skip it and it is run on its own:

```sh
cd go
go run client.go subject example-user-0001
go run client.go assert-begin example-user-0001
go run client.go assert-complete -credential credential.json example-user-0001
go run client.go totp -code 000000 example-user-0001
go run client.go verify -audience <api key id> '<assertion>'
```

The verification is written out against `crypto/ed25519` rather than calling
`internal/assertion`, which ships in this repository. Go's internal-package
rule confines that package to importers inside this module, so a reader who
copies the file into their own project, which is the only reason an example
exists, would find the import refused at compile time. Where the two disagree,
`internal/assertion` is authoritative.

## Verifying an assertion, and why it matters

A completed WebAuthn assertion, a verified TOTP code and a consumed recovery
code all return an `assertion`: a compact JWS signed with Ed25519, carrying JWT
claims. A `200` from this service only says the request arrived. The detached
signature is what removes the need to trust the network path between your
application and the service, so verify it and only then issue your own session.

The three verifiers here, in Python, Node and Go, apply the same checks in the
same order, and each says why:

- the algorithm is fixed at `EdDSA` rather than read from the token, which is
  what defeats `alg: none` and the trick of using the published public key as
  an HMAC secret;
- any `crit` header is fatal, because this is a verifier that understands none;
- the key is selected by `kid` and one candidate only, so a token signed under
  a key that should no longer be used does not pass because that key is still
  published;
- nothing in the payload is parsed until the signature has been verified;
- `iss` and `aud` are both pinned, and a missing `exp` is invalid rather than
  meaning no expiry.

Two things none of them does, and a real integration must:

- record `jti` in a replay cache until `exp` passes, because a valid signature
  does not make a token single use;
- apply a policy to `amr`. A WebAuthn assertion with user verification is a
  different assurance from a recovery code, which is why the factors are listed
  separately rather than collapsed into a boolean.

## Reading an error

Every refusal is an RFC 9457 problem document with the media type
`application/problem+json`:

```json
{
  "type": "urn:n0passtemps:error:ceremony-failed",
  "title": "authentication did not succeed",
  "status": 401,
  "request_id": "9f2a1c7b5d3e4f60a1b2c3d4"
}
```

`type` is stable and is the member to branch on. `title` describes a class of
failure and never the reason one particular request was refused, and `detail`
is populated only for input validation and state conflicts. Every WebAuthn,
TOTP and recovery-code failure returns the same body, so a caller cannot tell a
wrong signature from an expired challenge from an unknown subject, and cannot
use an authentication route to discover whether a given person has an account.

Two other statuses are worth handling apart from a 401. A 403 with the type
`urn:n0passtemps:error:forbidden` on a `/v1` route means the API key is valid and
was not minted with the scope that route family needs; presenting it again will
not help. A 503 with the type `urn:n0passtemps:error:unavailable` means the
service could not reach its credential store; the credential was not rejected,
and the request is worth retrying.

The reason is written to the log and the audit trail. `request_id`, which is
also the `X-Request-Id` response header, is what locates it, and it is the one
thing worth quoting when asking an operator to look.
