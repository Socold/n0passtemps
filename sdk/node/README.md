# n0passtemps for Node.js

Client SDK for the [n0passtemps](https://github.com/Socold/n0passtemps)
passwordless authentication server. It covers the three things an integrating
application has to get right:

- calling the `/v1` API with an API key, without leaking that key;
- verifying the signed assertion a successful ceremony returns, offline;
- converting WebAuthn payloads between JSON and `ArrayBuffer` in the browser.

Node 20 or later. No dependencies: `fetch`, `AbortSignal.timeout` and
`node:crypto` are all the SDK uses.

## Install

```sh
npm install n0passtemps
```

```js
import { Client, Verifier, remoteJwks } from "n0passtemps";
```

The package is ES modules only and ships hand-written TypeScript declarations.
Browser code imports `n0passtemps/browser`, which has no Node imports.

## How a login flows

The browser never talks to n0passtemps. It talks to your back end, and your back
end talks to n0passtemps with the API key. A WebAuthn ceremony is two round
trips with your back end in the middle:

1. `beginAssertion` returns a `challenge_id` and `options`.
2. The browser turns `options` into `ArrayBuffer`s, calls
   `navigator.credentials.get()`, and turns the result back into JSON.
3. `completeAssertion` sends the `challenge_id` and that credential, verbatim.
4. The response carries an `assertion`. **Verify it**, then open your session.

Registration has the same shape with `beginRegistration`,
`navigator.credentials.create()` and `completeRegistration`.

### The server half

Plain `node:http`, no framework. Session handling is reduced to a comment
because it is yours, not the SDK's.

```js
import http from "node:http";
import { readFile } from "node:fs/promises";
import {
  ApiError,
  AuthenticationFailedError,
  Client,
  InvalidAssertionError,
  ThrottledError,
  Verifier,
  remoteJwks,
} from "n0passtemps";

const baseUrl = process.env.N0PASSTEMPS_URL; // https://auth.example.org

const client = new Client({ baseUrl, apiKey: process.env.N0PASSTEMPS_API_KEY });

const verifier = new Verifier({
  issuer: "n0passtemps",
  // The id (a UUID) of the API key above, from GET /admin/v1/api-keys.
  // Not the key itself.
  audience: process.env.N0PASSTEMPS_API_KEY_ID,
  keys: remoteJwks(new URL("/v1/.well-known/jwks.json", baseUrl)),
});

// Replay cache: jti -> expiry. Use a shared store such as Redis when more
// than one process serves logins.
const seen = new Map();

function consumeOnce(claims) {
  const now = Date.now() / 1000;
  for (const [jti, until] of seen) if (until < now) seen.delete(jti);
  if (!claims.jti || seen.has(claims.jti)) return false;
  seen.set(claims.jti, claims.exp + 30);
  return true;
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function send(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const routes = {
  "POST /login/begin": async (body) => {
    // The options go to the browser unchanged.
    const { challenge_id, options } = await client.beginAssertion(body.userId);
    return { challenge_id, options };
  },

  "POST /login/complete": async (body) => {
    const result = await client.completeAssertion(body.userId, {
      challengeId: body.challenge_id,
      credential: body.credential, // forwarded verbatim
    });

    // The 200 says the request reached something. The signature says it
    // reached n0passtemps.
    const claims = await verifier.verify(result.assertion);

    if (claims.sub !== result.subject_id) throw new InvalidAssertionError();
    if (!consumeOnce(claims)) throw new InvalidAssertionError();
    // Your policy, not the SDK's: this application wants user verification.
    if (!claims.amr.includes("webauthn-uv")) return { ok: false, stepUp: true };

    // Open your own session here, keyed on claims.sub.
    return { ok: true };
  },

  "POST /register/begin": async (body) => {
    await client.resolveSubject(body.userId); // idempotent
    const { challenge_id, options } = await client.beginRegistration(body.userId, {
      label: body.label,
    });
    return { challenge_id, options };
  },

  "POST /register/complete": async (body) => {
    const result = await client.completeRegistration(body.userId, {
      challengeId: body.challenge_id,
      credential: body.credential,
    });
    return { ok: true, recoveryCodes: result.recovery_codes_remaining };
  },
};

http
  .createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/n0passtemps-browser.js") {
        const file = new URL(import.meta.resolve("n0passtemps/browser"));
        res.writeHead(200, { "Content-Type": "text/javascript" });
        return res.end(await readFile(file));
      }
      const route = routes[`${req.method} ${req.url}`];
      if (!route) return send(res, 404, { error: "not found" });
      // In a real application /register/* sits behind an existing session and
      // userId comes from that session, never from the request body.
      send(res, 200, await route(await readJson(req)));
    } catch (error) {
      if (error instanceof AuthenticationFailedError || error instanceof InvalidAssertionError) {
        return send(res, 401, { error: "authentication failed" });
      }
      if (error instanceof ThrottledError) {
        res.setHeader("Retry-After", String(error.retryAfterSeconds ?? 60));
        return send(res, 429, { error: "too many attempts" });
      }
      // error.requestId is what the n0passtemps operator needs to find the
      // audit entry. Log it; do not show the rest to the user.
      if (error instanceof ApiError) console.error(error.message);
      else console.error(error);
      send(res, 502, { error: "authentication is unavailable" });
    }
  })
  .listen(3000);
```

### The browser half

`n0passtemps/browser` is one file with no imports. Bundle it, or serve it as the
example above does.

```html
<script type="module">
  import { toGetOptions, credentialToJSON } from "/n0passtemps-browser.js";

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`${path} answered ${response.status}`);
    return response.json();
  }

  export async function login(userId) {
    const { challenge_id, options } = await post("/login/begin", { userId });

    // base64url strings -> ArrayBuffers. The service wraps the options under
    // "publicKey", which is the shape navigator.credentials takes.
    const credential = await navigator.credentials.get(toGetOptions(options));

    // ArrayBuffers -> base64url strings. Send the result as it is.
    return post("/login/complete", {
      userId,
      challenge_id,
      credential: credentialToJSON(credential),
    });
  }
</script>
```

Registration is the same with `toCreateOptions` and
`navigator.credentials.create()`.

| function | direction | what it converts |
| --- | --- | --- |
| `toCreateOptions(options)` | server to browser | `challenge`, `user.id`, `excludeCredentials[].id` |
| `toGetOptions(options)` | server to browser | `challenge`, `allowCredentials[].id` |
| `credentialToJSON(credential)` | browser to server | `rawId`, every member of `response`, `ArrayBuffer`s nested in `clientExtensionResults`; adds `response.transports` from `getTransports()` and `authenticatorAttachment` when present |

Everything else is copied untouched, and the inputs are never modified. The
page has to be served from an origin the deployment lists in its configuration:
the relying party identifier and the accepted origins are server settings and
are never read from a request.

## Client

```js
const client = new Client({
  baseUrl: "https://auth.example.org",
  apiKey: process.env.N0PASSTEMPS_API_KEY,
  timeoutMs: 10000, // default; covers the response body too
});
```

| method | route | resolves to |
| --- | --- | --- |
| `resolveSubject(ref, { displayName })` | `POST /v1/subjects` | subject summary; creates the subject when needed |
| `getSubject(ref)` | `GET /v1/subjects/{ref}` | subject summary |
| `beginRegistration(ref, { label })` | `POST /v1/webauthn/{ref}/register` | `{ challenge_id, options, expires_at }` |
| `completeRegistration(ref, { challengeId, credential })` | `POST .../register/complete` | `{ credential, recovery_codes_remaining }` |
| `beginAssertion(ref)` | `POST /v1/webauthn/{ref}/assert` | `{ challenge_id, options, expires_at }` |
| `completeAssertion(ref, { challengeId, credential })` | `POST .../assert/complete` | `{ subject_id, assertion, expires_at, factors, signals? }` |
| `enrolTotp(ref)` | `POST /v1/totp/{ref}/enrol` | the secret and its `otpauth://` URI, shown once |
| `confirmTotp(ref, code)` | `POST .../enrol/confirm` | `{ secret_id, confirmed: true }` |
| `verifyTotp(ref, code)` | `POST /v1/totp/{ref}/verify` | assertion result, `factors: ["totp"]` |
| `issueRecoveryCodes(ref)` | `POST /v1/recovery/{ref}/issue` | `{ batch_id, codes, count, warning }`, shown once |
| `consumeRecoveryCode(ref, code)` | `POST /v1/recovery/{ref}/consume` | assertion result plus `recovery_codes_remaining` |
| `health()` | `GET /v1/health` | `{ status }`, including the `503` liveness body |
| `healthDetail()` | `GET /v1/health/detail` | the component report |

Responses are returned as the service wrote them, snake_case included. The
WebAuthn `options` and `credential` payloads pass through byte for byte.

What the client does on every call, and why:

- **https only.** The API key is a bearer credential: over plain http anyone on
  the path reads it once and holds it until it is revoked. `http://` is accepted
  for a loopback host (`localhost`, `127.0.0.0/8`, `::1`), which is the layout
  when a reverse proxy terminates TLS on the same machine. Anything else needs
  `allowInsecureTransport: true`.
- **No redirects.** `fetch` would replay the `Authorization` header to the
  redirect target. The service never redirects an API route, so a redirect is
  refused with a `TransportError`.
- **Bounded.** One timeout covers connection, headers and body. Responses are
  cut off at 1 MiB while they are being read.
- **The key stays private.** It lives in a `#private` field. It does not appear
  in `JSON.stringify(client)`, `util.inspect(client)`, `console.log(client)` or
  any error message, and it is scrubbed from text an intermediary echoes back.
- **No retries.** A throttled or unavailable answer is reported once. The
  caller knows whether repeating a login attempt makes sense; a library does
  not.
- **`Content-Type: application/json` always**, because the service answers 415
  to a write without it, even one that takes no body.

The subject reference is percent-encoded into the path, so `/`, `@`, spaces and
`?` are safe. `"."` and `".."` are refused: no URL can carry them as a path
segment. Prefer an opaque identifier to an email address anyway, because paths
end up in the access logs of whatever proxy sits in between.

## Verifying an assertion

A successful `completeAssertion`, `verifyTotp` or `consumeRecoveryCode` returns a
compact JWS signed with Ed25519. Verifying it means a forged or intercepted
response from something that is not n0passtemps cannot log anyone in.

```js
import { Verifier, remoteJwks, staticKeys } from "n0passtemps";

const verifier = new Verifier({
  issuer: "n0passtemps",             // the deployment's assertion issuer
  audience: "5f0c2a2e-...",          // the id of YOUR API key
  keys: remoteJwks("https://auth.example.org/v1/.well-known/jwks.json"),
  clockSkewSeconds: 30,              // default
});

const claims = await verifier.verify(result.assertion);
```

`verify` checks, in this order:

1. exactly three segments;
2. each segment is strict unpadded base64url: `=`, `+`, `/` and non-canonical
   trailing bits are refused, so a token has exactly one spelling;
3. `alg` is exactly `EdDSA`. The algorithm is a constant of the verifier and is
   never selected from the token, which refuses `none`, `HS256` keyed with the
   public key, and everything else;
4. no `crit` header, and `typ` is `JWT` when present;
5. the key is selected by `kid`, one candidate only;
6. the Ed25519 signature, over the bytes as received;
7. only then the claims: `iss`, `aud`, `sub`, `amr`, a required `exp`, and `nbf`,
   the last two with the clock skew.

Every failure is the same `InvalidAssertionError` with the same message. Which
check failed is not reported, because that would tell an attacker whether a
forged token had the right audience, whether a `kid` exists, or whether a
captured token is merely expired.

### Two things the verifier cannot do for you

**Enforce single use of `jti`.** A valid signature does not make a token single
use. An assertion captured in transit stays replayable until it expires, sixty
seconds by default. Record every `jti` until `exp` plus your skew has passed and
refuse a repeat, as `consumeOnce` does above.

**Check `amr` against your own policy.** The factors are `webauthn`,
`webauthn-uv` (the authenticator verified the user with a PIN or a biometric),
`totp` and `recovery-code`. They are different assurances. A common policy is to
require `webauthn-uv` for sensitive operations and to force re-enrolment after a
`recovery-code` login.

### Key sources

`remoteJwks(url, options)` fetches the JWK Set on first use and caches it for
`cacheSeconds` (default 300, the `max-age` the service sends). A `kid` that is
not in the cache triggers one refetch, so a key rotation is picked up without
waiting out the cache. Because the `kid` comes from an unauthenticated token,
refetches are spaced at least `minRefetchIntervalSeconds` apart (default 10):
a flood of tokens with random `kid`s cannot turn your verifier into a request
amplifier aimed at the authentication service. When no fresh set can be
obtained, `verify` rejects with `TransportError`, not `InvalidAssertionError`,
and stale keys are not used. The URL must be https or loopback, like the client's.

`staticKeys(jwks)` pins the JWK Set in your configuration and takes the network
out of verification. You then have to ship the new key before the operator
rotates.

Both accept only OKP / Ed25519 entries whose `kid`, when present, equals the
RFC 7638 thumbprint of the key, which is how the service names its keys.
`jwkThumbprint(jwk)` computes it.

## Errors

Everything the SDK throws on purpose extends `N0PasstempsError`. Invalid
arguments throw the built-in `TypeError`.

| class | problem `type` | status | meaning |
| --- | --- | --- | --- |
| `UnauthorizedError` | `unauthorized` | 401 | the API key is missing, unknown or revoked; a deployment fault |
| `AuthenticationFailedError` | `ceremony-failed` | 401 | the user did not authenticate; no reason is given, by design |
| `ForbiddenError` | `forbidden` | 403 | the key lacks the scope, or the authenticator model is not permitted |
| `NotFoundError` | `not-found` | 404 | unknown subject (`getSubject` only) |
| `ConflictError` | `conflict` | 409 | already registered, credential limit, no authenticator, no pending TOTP enrolment; see `detail` |
| `ThrottledError` | `throttled` | 429 | wait `retryAfterSeconds` |
| `UnavailableError` | `unavailable` | 503 | a dependency of the service is down; the key is not at fault |
| `ApiError` | `bad-request`, `payload-too-large`, `unsupported-media-type`, `internal`, or none | 400, 413, 415, 500, other | any other refusal |
| `TransportError` | | | no usable response: connection, timeout, redirect, size cap, invalid JSON, JWKS outage |
| `InvalidAssertionError` | | | the assertion did not verify |

The `type` values are prefixed with `urn:n0passtemps:error:`; `ProblemType`
exports them as constants.

Two statuses are shared, so the class is chosen from `type`, never from the
status: a 401 is either your key (`UnauthorizedError`) or your user
(`AuthenticationFailedError`). A response with no recognised `type`, typically
from a proxy, becomes a plain `ApiError` with `type: "about:blank"`, except for
403, 404, 409, 429 and 503 where the status alone is unambiguous.

Every `ApiError` carries `status`, `type`, `title`, `detail`, `requestId` and
`retryAfterSeconds`. `title` and `type` name a class of failure and never the
specific reason, so `requestId` is the field to log: it is what the operator
needs to find the real reason in the audit trail.

## Tests

```sh
npm test   # node --test, no network, local servers on an ephemeral port
```

## Licence

MIT
