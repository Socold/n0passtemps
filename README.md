# n0passtemps

[![ci](https://github.com/Socold/n0passtemps/actions/workflows/ci.yml/badge.svg)](https://github.com/Socold/n0passtemps/actions/workflows/ci.yml)
[![security](https://github.com/Socold/n0passtemps/actions/workflows/security.yml/badge.svg)](https://github.com/Socold/n0passtemps/actions/workflows/security.yml)
[![release](https://github.com/Socold/n0passtemps/actions/workflows/release.yml/badge.svg)](https://github.com/Socold/n0passtemps/actions/workflows/release.yml)

An on-premise passwordless authentication server. It runs WebAuthn and FIDO2
ceremonies, time-based one-time passwords per RFC 6238, and single-use recovery
codes, behind an HTTP API that an application delegates its login to. It is one
static Go binary with no runtime dependencies, stores its data in SQLite or
PostgreSQL, makes no outbound network connection other than to that database,
and is MIT-licensed. It is built for organisations that want to keep
authentication data on infrastructure they control, and for the operator who
will run it without a support contract: the configuration validator refuses the
settings known to be unsafe and says why, the audit log is hash-chained, and the
documentation states its limits rather than working around them.

It is not an identity provider. There is no OIDC, no SAML, no user directory and
no session management; the application keeps its own users and its own sessions
and asks this service only whether the person in front of it is who they claim.
See [docs/FAQ.md](docs/FAQ.md#can-this-replace-my-identity-provider) for the
full list of what is out of scope.

## Lite or complete

One binary and one schema serve both. Moving between them is a configuration
change and a restart, never a migration.

```
Does more than one person administer this deployment?
├── No ──── Do you need a 30-day window to cancel a GDPR erasure?
│           ├── No ──── Is one node with SQLite enough?
│           │           ├── Yes ──> LITE.      features.lite_mode = true
│           │           └── No ───> LITE + Postgres.
│           │                       lite_mode = true, database.driver = "postgres"
│           └── Yes ──> COMPLETE. Leave the defaults.
└── Yes ─── Do the administrators need different authority?
            ├── No ──── COMPLETE without dual approval.
            │           features.dual_approval = false
            └── Yes ──> COMPLETE. Leave the defaults.
```

What `features.lite_mode = true` actually changes, and nothing else does:

| Setting | Complete | Lite |
|---|---|---|
| `features.admin_rbac` | `true`, three roles enforced | `false`, every valid role has full authority |
| `features.dual_approval` | `true`, four operations held for a second administrator | `false` |
| `features.deferred_erasure` | `true`, 30-day cancellation window | `false`, purge due immediately |
| `features.kek_rotation_reminder` | `true` | `false` |
| `database.driver` | `sqlite` unless set | `sqlite` unless set |
| `recovery.code_count` | 16 | 8 |

WebAuthn, TOTP, recovery codes, the hash-chained audit log, the throttle and the
ten alert types are identical in both. Lite is a shorthand applied after the
file and the environment are read, and only to settings the file did not name,
so "lite plus RBAC" is a valid configuration. Details in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#what-lite-mode-actually-changes).

## Five minutes

This is the single-container SQLite form, from `deploy/docker-compose.yml`.
Docker 24 or newer with the compose plugin.

```bash
git clone https://github.com/Socold/n0passtemps.git
cd n0passtemps/deploy

cp .env.example .env
$EDITOR .env                      # set N0PASSTEMPS_VERSION
```

Write the configuration:

```bash
cat > config.toml <<'TOML'
[tenant]
id   = "acme"
name = "Acme"

[server]
addr                = "0.0.0.0:8080"
trust_proxy         = true
trusted_proxy_cidrs = ["172.16.0.0/12"]

[database]
driver   = "sqlite"
dsn      = "/var/lib/n0passtemps/n0passtemps.db"
data_dir = "/var/lib/n0passtemps"

[kek]
provider = "file"
path     = "/etc/n0passtemps/kek/keyring.json"

[webauthn]
rp_id           = "auth.example.com"
rp_display_name = "Acme"
origins         = ["https://auth.example.com"]

[assertion]
issuer           = "https://auth.example.com"
signing_key_path = "/etc/n0passtemps/kek/assertion-key.pem"

[admin]
ui_enabled    = true
ip_allow_list = ["10.0.0.0/8"]
TOML
```

Generate the two key files the server will not generate for you. They go into
their own volume, which the service mounts read-only and which is deliberately
not the data volume. The wizard ships in the image, and the image owns
`/etc/n0passtemps/kek` as uid 65532, so a fresh named volume is writable by the
non-root wizard and no helper container is needed:

```bash
docker volume create n0passtemps_n0passtemps-kek

docker run --rm -v n0passtemps_n0passtemps-kek:/etc/n0passtemps/kek \
  --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 \
  kek init -out /etc/n0passtemps/kek/keyring.json

docker run --rm -v n0passtemps_n0passtemps-kek:/etc/n0passtemps/kek \
  --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 \
  assertion-key init -out /etc/n0passtemps/kek/assertion-key.pem
```

The volume name is the compose project name, `n0passtemps`, which the compose
file declares, followed by the volume's own name, `n0passtemps-kek`.

Generate the pepper and put the line it prints into `.env`, replacing the empty
`N0PASSTEMPS_SUBJECT_PEPPER=` entry. The compose file refuses to start without
it:

```bash
docker run --rm --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 pepper
# N0PASSTEMPS_SUBJECT_PEPPER=...
```

Back all three up now, somewhere the data volume's loss does not reach. Losing
the keyring costs the TOTP secrets and the readable subject references; losing
the pepper makes every existing subject unfindable.

```bash
docker run --rm -v n0passtemps_n0passtemps-kek:/kek:ro alpine:3.20 \
  tar -C /kek -cf - . > n0passtemps-kek-backup.tar
```

Nothing in the compose file needs editing. It passes the pepper through from
`.env`, points the signing key at `/etc/n0passtemps/kek/assertion-key.pem`,
relabels the `config.toml` bind mount for SELinux hosts, and sets
`server.allow_plaintext`, which acknowledges that the container binds every
interface while the port is published to loopback only. The image already
starts the server with `-config /etc/n0passtemps/config.toml`. Start it:

```bash
docker compose up -d
docker compose logs -f n0passtemps

curl -sS http://127.0.0.1:8080/v1/health
# {"status":"ok"}
```

**Create the first administrators.** The running service never prints a token.
With no administrator in the database it logs a warning that names the command,
and the command is a separate, one-shot run of the same binary:

```bash
docker compose run --rm n0passtemps -bootstrap-admin -admins 2
```

```

bootstrap-1  npa_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-TOKEN
bootstrap-2  npa_EXAMPLEONLY0001.EXAMPLE-NOT-A-REAL-TOKEN

Each token is shown once. Only a digest is stored, so none can be displayed
again. Put them in a password manager now, one per person.
```

Two, because dual approval is on by default and minting an administrative token
through the API is then held for a second administrator. A deployment with one
administrator has nobody to approve its second, and the API carries no exemption
for a sole administrator, because a rogue administrator could reach one by
revoking the others. The initial quorum is created here instead. With
`features.lite_mode` or `features.dual_approval = false`, plain
`-bootstrap-admin` creates one.

The tokens go to the terminal you ran the command from and to nothing else; a
log stream is shipped and retained by systems with looser access rules than a
credential store, so the long-running service is never the thing that writes
them. See
[ADR 0014](docs/adr/0014-bootstrap-by-explicit-command.md). Use them to sign in
at `/admin`, mint named replacements, and revoke them. The command refuses once
a usable full administrator exists; `-force` is the way back in when every token
has been lost.

The container speaks plain HTTP on loopback. Terminate TLS in front of it and
forward `X-Forwarded-For` and `X-Forwarded-Proto`; the reverse proxy
configuration, and the other three deployment forms, are in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

If it refuses to start, it will say why, in full sentences, listing every
problem it found. [docs/TROUBLESHOOT.md](docs/TROUBLESHOOT.md) quotes the real
messages.

## Minimum configuration

Six things, and two of them are secrets that never appear in the file.

| What | Where | Note |
|---|---|---|
| Tenant identifier | `tenant.id` | Written into every row. Changing it later orphans all of the data. Lowercase letters, digits, hyphen and underscore. `system` is reserved |
| Relying party identifier | `webauthn.rp_id` | A bare registrable domain. **Set it once, before the first registration**: credentials registered under `app.example.com` never validate under `example.com` |
| Origins | `webauthn.origins` | The origins your front end is served from. `rp_id` must equal each origin's host or be a parent of it, which the validator checks at startup. `http` is accepted for `localhost`, `127.0.0.1` and `::1` only |
| Keyring | `kek.path`, or `kek.env_var` | Mode 0600, and **outside** `database.data_dir`. A key beside the ciphertext it protects gives no confidentiality once the volume is copied, so the server refuses to start; see [ADR 0009](docs/adr/0009-refuse-a-kek-inside-the-data-directory.md) |
| Subject pepper | `N0PASSTEMPS_SUBJECT_PEPPER` | At least 32 bytes. Hexadecimal, or base64 of at least 32 bytes, or any value whose encoding is named with a `hex:`, `base64:` or `raw:` prefix. The encoding is never guessed: anything else is refused. A separate secret from the keyring, so that the key able to decrypt secrets is not also the key able to confirm whether a person has an account. Unset by the process once read |
| Database | `database.driver`, `database.dsn` | `sqlite` with a file path, or `postgres` with a DSN carrying an explicit `sslmode`. libpq defaults to `prefer`, which falls back to plaintext without reporting it, so the validator refuses a DSN with none |

Plus the assertion signing key at `assertion.signing_key_path`: Ed25519, PKCS#8
PEM, mode 0600. Every other key has a default that is safe.
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) is the complete reference.

## Integrating: the two round trips

Both ceremonies are two calls. Your application holds the API key server side
and proxies them; a browser never calls `/v1` directly, because that would ship
the key to every visitor. See
[ADR 0002](docs/adr/0002-authenticate-every-call-to-the-public-api-surface.md).

Mint a key first, from an administrative token:

```bash
curl -sS -X POST https://auth.example.com/admin/v1/api-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"web-frontend","expires_in_days":365,"scopes":["subjects","webauthn"]}'
```

The response carries `token`, once. Only a selector and a digest are stored, so
there is no operation that can show it again. `scopes` restricts the key to the
named route families: `subjects`, `webauthn`, `totp`, `recovery` and `health`.
An unknown scope is refused with 400. An empty or absent list leaves the key
unrestricted, and the response then carries `"unrestricted": true` so that the
choice is visible. A key that calls outside its scopes gets 403 and the attempt
is audited.

### Round trip one: get the options

```bash
API_KEY="npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY"

# Resolve your user reference to a subject. Idempotent, so call it on every
# login rather than tracking whether you have registered the user here.
curl -sS -X POST https://auth.example.com/v1/subjects \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject_ref":"user-1234","display_name":"A. User"}'

# Start an authentication ceremony.
curl -sS -X POST https://auth.example.com/v1/webauthn/user-1234/assert \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json'
```

```json
{
  "challenge_id": "7c1e0f4a-3b2d-4c58-9e10-a6f2b8d43c91",
  "options": { "publicKey": { "challenge": "...", "rpId": "auth.example.com", "allowCredentials": [] } },
  "expires_at": "2026-09-17T08:19:02Z"
}
```

Forward `options` to the browser and keep `challenge_id`. The challenge, the
expected user handle and the user-verification requirement stay on the server:
handing them to the client would let the client edit any of the three between
the two calls.

```javascript
// In the browser. The binary members arrive base64url-encoded, and have to go
// back the same way.
const fromB64url = s => Uint8Array.from(
  atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

const toB64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const opts = options.publicKey;
opts.challenge = fromB64url(opts.challenge);
for (const c of opts.allowCredentials ?? []) c.id = fromB64url(c.id);

const cred = await navigator.credentials.get({ publicKey: opts });

// Post this back to your own server, which forwards it verbatim.
const payload = {
  id:    cred.id,
  rawId: toB64url(cred.rawId),
  type:  cred.type,
  response: {
    clientDataJSON:    toB64url(cred.response.clientDataJSON),
    authenticatorData: toB64url(cred.response.authenticatorData),
    signature:         toB64url(cred.response.signature),
    userHandle:        cred.response.userHandle ? toB64url(cred.response.userHandle) : null,
  },
};
```

### Round trip two: complete it

```bash
curl -sS -X POST https://auth.example.com/v1/webauthn/user-1234/assert/complete \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
        "challenge_id": "7c1e0f4a-3b2d-4c58-9e10-a6f2b8d43c91",
        "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { "...": "..." } }
      }'
```

```json
{
  "subject_id": "0f7a5c81-9b2e-4d13-8a6f-1c4e7b90d2a3",
  "assertion": "eyJhbGciOiJFZERTQSIsImtpZCI6Il8tU2...",
  "expires_at": "2026-09-17T08:15:02Z",
  "factors": ["webauthn", "webauthn-uv"]
}
```

`assertion` is a compact JWS signed with Ed25519. Verify it offline against the
key published at `GET /v1/.well-known/jwks.json`, then issue your own session. A
bare `200 OK` would oblige you to trust the network path between your
application and this service; a detached signature does not. See
[ADR 0004](docs/adr/0004-return-a-signed-assertion-result.md).

What a verifier has to check, in order:

```go
// Fetch and cache the JWK Set, keyed by "kid".
keys := map[string]ed25519.PublicKey{ /* from /v1/.well-known/jwks.json */ }

v := assertion.NewVerifier(keys, "https://auth.example.com", 30*time.Second)

claims, err := v.Verify(resp.Assertion, apiKeyID) // audience is the API key's id
if err != nil {
    return err // one error for every failure, by design
}
// Then, in your own code:
//   - reject a "jti" you have already seen, within the token's lifetime
//   - apply your own policy to claims.AMR: a recovery-code login is not a
//     WebAuthn login with user verification
```

Skipping the `jti` cache loses the single-use property and gains nothing over a
bare 200. The lifetime is 60 seconds by default, which is unforgiving on hosts
whose clocks drift.

Registration is the same shape against
`POST /v1/webauthn/{subject_ref}/register` and
`/register/complete`, with `navigator.credentials.create` in between. TOTP is
`POST /v1/totp/{subject_ref}/enrol`, `/enrol/confirm` and `/verify`; the
`enroll` spelling is served too, so a published integration does not break over
an orthography choice. Recovery codes are
`POST /v1/recovery/{subject_ref}/issue` and `/consume`.

## Features

| Feature | Status | Note |
|---|---|---|
| WebAuthn and FIDO2 registration and assertion | Yes | W3C WebAuthn Level 2. This service is the relying party and `rp_id` is server configuration |
| Platform and roaming authenticators | Yes | Windows Hello, Touch ID, Face ID, Android, USB, NFC and BLE security keys |
| User verification required by default | Yes | `webauthn.user_verification = "required"`, which is what makes a single WebAuthn factor sufficient. `discouraged` is refused by the validator |
| AAGUID allow and block lists | Yes | The offline alternative to attestation verification |
| Attestation verification | Optional, off by default | Needs a FIDO MDS3 BLOB on disk (`webauthn.metadata_path`) or an allow list. The BLOB's signature is verified against the FIDO root and it is never fetched over the network, so refreshing it is an operator duty |
| Signature counter clone detection | Reported, never refused | Many authenticators legitimately report a constant zero. It raises an alert and a signal in the response |
| TOTP, RFC 6238 | Yes | SHA1, SHA256 or SHA512; 6 or 8 digits; a replay high-water mark enforced by compare-and-swap |
| HOTP, RFC 4226 | No | Deliberately. [ADR 0011](docs/adr/0011-drop-hotp.md) |
| Single-use recovery codes | Yes | Argon2id-hashed, never recoverable, issuing a batch retires the previous one |
| Signed assertion result | Yes | Compact JWS, Ed25519, 60 second lifetime, single-use `jti`, JWK Set published |
| Passwords | No | There are none, anywhere |
| Hash-chained audit log | Yes | SHA-256 chain, verification route, tamper-**evident** rather than tamper-proof |
| GDPR erasure that keeps the chain verifiable | Yes | Through a salted commitment to the personal fields |
| Three administrative roles, 27 permissions | Yes | Enforced per route at mount time. `features.admin_rbac` |
| Dual approval | Yes, four operations | Erasure, administrative token creation, revoking every credential of a subject, and the keyring rewrap. An approval is redeemed by the requester, who repeats the identical request with `X-Approval-Id`; self-approval is refused. [ADR 0013](docs/adr/0013-approvals-are-redeemed-not-executed.md) |
| API key scopes | Yes | `subjects`, `webauthn`, `totp`, `recovery`, `health`. An empty list is unrestricted, and the minting response says so. A key outside its scope gets 403 and the attempt is audited |
| Revoke every authenticator of a subject | Yes | One transaction covering all WebAuthn credentials and the TOTP secret. Recovery codes are left, and the response reports how many remain |
| Keyring rewrap | Yes | `POST /admin/v1/kek/rewrap` moves sealed records onto the current key version and reports which versions are still in use, so an old version can be retired |
| Rate limiting on three dimensions at once | Yes | Per subject, per source network, per API key, plus a per-administrator revocation burst |
| Ten alert types | Yes | Deduplicated by fingerprint, so a brute-force attempt is one row with a rising count |
| SQLite and PostgreSQL | Yes | Identical schema, enforced by `make migrate-check` in CI |
| Server-rendered administration interface | Yes | `html/template`, embedded, no Node.js anywhere. [ADR 0012](docs/adr/0012-server-rendered-administration-interface.md) |
| Multi-tenancy | Not yet | Every table carries a tenant identifier; the tenant comes from configuration, not from the credential |
| OIDC, SAML, user directory, session management | No | Out of scope |
| Bootstrap administrators | Yes, by explicit command | `n0passtemps-server -config <path> -bootstrap-admin` prints the first token once, to the operator's terminal; `-admins 2` creates the quorum that dual approval needs. The running service never prints one. [ADR 0014](docs/adr/0014-bootstrap-by-explicit-command.md) |
| In-process janitor | Yes | Sweeps abandoned challenges, stale throttle buckets, undecided approvals, due erasures and audit entries past retention, every `features.janitor_interval` |
| Metrics endpoint | No | State is exposed through the authenticated health report and the audit log |
| Telemetry | No | No phone-home, no update check, no analytics |

## Security posture

| Property | How | Reference |
|---|---|---|
| Both API surfaces authenticated | API key on `/v1`, administrative token on `/admin/v1`. Only the liveness probe and the JWK Set are anonymous, and both are listed explicitly in the router | [ADR 0002](docs/adr/0002-authenticate-every-call-to-the-public-api-surface.md), [ADR 0008](docs/adr/0008-split-the-health-endpoint.md) |
| Origin binding cannot be influenced by a caller | `rp_id` and the origin list are server configuration and never read from a request | [ADR 0003](docs/adr/0003-the-service-is-the-webauthn-relying-party.md) |
| The ceremony result is verifiable offline | Detached Ed25519 JWS, not a status code | [ADR 0004](docs/adr/0004-return-a-signed-assertion-result.md) |
| Recovery codes survive losing the key | Hashed with Argon2id, not sealed. A stolen database yields no usable code even to an attacker holding the keyring | [ADR 0005](docs/adr/0005-hash-recovery-codes-do-not-encrypt-them.md) |
| WebAuthn enrolments survive losing the key | Public keys stored in clear, because a public key needs integrity and not confidentiality. Losing the keyring costs the TOTP secrets and the readable subject references, and nothing else | [ADR 0006](docs/adr/0006-store-webauthn-public-keys-in-clear.md) |
| Audit tampering is detectable | SHA-256 chain, each entry committing to its predecessor. It does **not** prevent tampering: an operator with the database file can rewrite the chain consistently, and closing that needs a witness outside their control | [ADR 0007](docs/adr/0007-chain-the-audit-log.md) |
| Encryption at rest is actually at rest | The keyring is refused inside the data directory, and refused if readable by group or other | [ADR 0009](docs/adr/0009-refuse-a-kek-inside-the-data-directory.md) |
| A contained credential stays contained | Revocation is final, with no un-revoke. A rate limit and an alert replace reversibility | [ADR 0010](docs/adr/0010-revocation-is-final.md) |
| An approval runs what was approved, for the person who asked | Approvals are redeemed by the original requester, bound to the operation, the requester and the payload, and spent once | [ADR 0013](docs/adr/0013-approvals-are-redeemed-not-executed.md) |
| No administrative token in a log stream | The first token is created by a one-shot command that writes to the operator's terminal | [ADR 0014](docs/adr/0014-bootstrap-by-explicit-command.md) |
| One anti-replay surface, not two | TOTP only, with a single high-water mark advanced by compare-and-swap | [ADR 0011](docs/adr/0011-drop-hotp.md) |
| The build has no Node.js in it | Server-rendered interface, embedded templates, six direct Go dependencies | [ADR 0012](docs/adr/0012-server-rendered-administration-interface.md) |
| Personal data pseudonymised at rest | Subject references stored as an HMAC under a separate pepper, plus an envelope-encrypted copy. No substring search, because that would undo the encryption | [docs/GDPR.md](docs/GDPR.md) |
| Secrets never in a log line | Redaction enforced in the log handler, not at the call site | [docs/MONITORING.md](docs/MONITORING.md) |

Stated limits, in brief, and in full in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md): an operator with the database file
can rewrite the whole audit chain consistently and detection needs an external
witness; `zeroize` is best-effort because the Go runtime may copy or page
memory; a TOTP-only user is phishable in a way a WebAuthn user is not; one
Ed25519 key signs every assertion and reading it is a forgery capability; an
API key minted with no scopes reaches every `/v1` route, and keys are
unrestricted unless the operator names scopes when minting them.

Standards this is built against: W3C WebAuthn Level 2, RFC 6238, RFC 4226,
RFC 7515, RFC 7517, RFC 7638, RFC 8037, RFC 9457, OWASP ASVS 4.0, OWASP API
Security Top 10 2023, and GDPR Articles 15, 17 and 32.

## Documentation

| File | What it is for |
|---|---|
| [README.md](README.md) | This file: what it is, installing it, integrating with it |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Package layout, the request path, the two-pool SQLite arrangement, where each secret lives, the dependency policy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What is done, what comes next, and the decisions still open |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | The four supported forms, with a pre-flight checklist, TLS, backup, restore and upgrade for each |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every configuration key, its default, its environment variable, and every message the validator refuses with |
| [docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md) | Minting and revoking credentials, the five things an operator actually does, the approval queue, verifying the chain |
| [docs/TROUBLESHOOT.md](docs/TROUBLESHOOT.md) | Symptom first: it will not start, WebAuthn fails, a user is locked out, the keyring is lost |
| [docs/FAQ.md](docs/FAQ.md) | Short answers, including what this is not |
| [docs/RBAC.md](docs/RBAC.md) | The 27 permissions against the three roles, and which are dual-approval candidates |
| [docs/WEBAUTHN.md](docs/WEBAUTHN.md) | The ceremony here specifically, the challenge store, the user handle, attestation, the counter, platform notes |
| [docs/GDPR.md](docs/GDPR.md) | Lawful basis, the personal data inventory, the Article 15 and 17 paths, how the chain survives erasure |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Assets, trust boundaries, ten attackers, and what is not mitigated |
| [docs/MONITORING.md](docs/MONITORING.md) | What to scrape, the Prometheus endpoint, the ten alert types and their responses, log fields, database tuning |
| [docs/EXTENSIONS.md](docs/EXTENSIONS.md) | What sits around the core and what never goes in it: the trust-path test, the adapters that exist, the ones that are candidates, and the ones that would be a different product |
| [docs/SIEM.md](docs/SIEM.md) | Getting the two log streams into a SIEM: why there is no syslog client, the field mapping to ECS and OCSF, the closed audit event vocabulary, and what a sink receiver has to do |
| [docs/adr/README.md](docs/adr/README.md) | Eighteen architecture decision records: the deliberate deviations from the original specification, and the convention itself |
| [examples/README.md](examples/README.md) | Working clients in shell, Python, Node and Go, against `api/openapi.yaml` |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, the `make ci` gate, the code style, the ADR process, commit messages |
| [CHANGELOG.md](CHANGELOG.md) | What each release contains |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, what is in scope, and the honest disclosure policy |
| [LICENSE](LICENSE) | MIT |

`api/openapi.yaml` is the machine-readable contract for both surfaces, and
`config/config.example.toml` is a commented configuration to start from.

`cdc-n0passtemps-v3-complet.html` at the repository root is the original
specification. It is useful for the product framing and it disagrees with the
code on eleven points. Where they disagree, the code wins and
[docs/adr](docs/adr/README.md) says why. Two further records cover questions
the specification leaves open.

## Support

GitHub issues, with the templates in `.github/ISSUE_TEMPLATE`, for bugs and
feature requests. GitHub's [private vulnerability
reporting](https://github.com/Socold/n0passtemps/security/advisories/new) for
anything security-relevant; do not open a public issue for a vulnerability,
because it is visible to operators who have not yet upgraded.

There is no support email address. There is no Slack channel, no call booking
and no sales contact, and none of them is planned. The documentation above and
the examples in `examples/` are the support channel, which is why the
documentation is as long as it is.

**No response time is promised.** One person maintains this project, with no
commercial support behind it, and publishing a number would be dishonest.
Issues are read and triaged as time allows. A report that includes the version,
the redacted configuration, the output of the authenticated health endpoint and
the `request_id` from the failing response is the one most likely to be
actionable on the first reply.

## Build from source

Go 1.27.1 or newer, which is the floor CI tests against. No C toolchain: the
SQLite driver is `modernc.org/sqlite`, which is pure Go, so `CGO_ENABLED=0`
everywhere and the result is a static binary.

```bash
git clone https://github.com/Socold/n0passtemps.git
cd n0passtemps

make build          # bin/n0passtemps-server and bin/n0passtemps-wizard
make test           # unit tests
make ci             # the full gate, in the order CI runs it
```

`make help` lists every target. The ones worth knowing:

| Target | What it does |
|---|---|
| `make build` | Both binaries for the host platform, into `bin/` |
| `make build-all` | Cross-compiles for linux, darwin and windows on amd64 and arm64, into `dist/` |
| `make test` | `go test ./...` |
| `make test-race` | The same under the race detector |
| `make test-integration` | The PostgreSQL integration tests, behind the `integration` build tag. Needs a reachable instance at `TEST_POSTGRES_URL`, which the target exports to the suite as `N0PASSTEMPS_TEST_POSTGRES_DSN` |
| `make cover` | Writes `coverage.out` and prints total statement coverage |
| `make lint` | `golangci-lint`, at the version pinned in the `Makefile` |
| `make sec` | `gosec` and `govulncheck` |
| `make secrets` | `gitleaks` over the working tree and the history |
| `make migrate-check` | Asserts the SQLite and PostgreSQL migrations declare the same tables and indexes |
| `make docker` | Builds the image from `deploy/Dockerfile` |
| `make setup-wizard` | Runs the interactive setup tool |
| `make ci` | `fmt-check vet lint migrate-check test-race cover sec secrets build` |

The version, commit and build date are injected at link time, so a binary built
without them reports `dev` and falls back to the Go toolchain's own VCS stamp.

The two binaries:

```bash
n0passtemps-server -config /etc/n0passtemps/config.toml   # run
n0passtemps-server -check-config                          # validate and exit
n0passtemps-server -migrate                               # apply migrations and exit
n0passtemps-server -config <path> -bootstrap-admin        # create the first administrator, print the token once
n0passtemps-server -config <path> -bootstrap-admin -admins 2   # the same, for a deployment with dual approval on
n0passtemps-server -version

n0passtemps-wizard setup                                  # write config.toml, compose, .env
n0passtemps-wizard kek init -out /etc/n0passtemps/kek/keyring.json
n0passtemps-wizard kek rotate -file /etc/n0passtemps/kek/keyring.json
n0passtemps-wizard kek inspect
n0passtemps-wizard assertion-key init -out /etc/n0passtemps/kek/assertion-key.pem
n0passtemps-wizard assertion-key inspect
n0passtemps-wizard pepper
n0passtemps-wizard check -config config.toml
```

Nothing in the wizard is required: every file it writes can be written by hand,
and the service validates its configuration at startup either way.

Contributing, including the rule that a schema change ships migrations for both
engines and a security-relevant change ships a test proving the property, is in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE).

Copyright (c) 2016-2026 Socold.
