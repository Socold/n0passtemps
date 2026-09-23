# Threat model

What this service defends, against whom, and where the defence stops. The
limits are stated as plainly as the controls: a threat model that only lists
mitigations is a marketing document.

Scope is the service itself, as configured by the defaults and deployed as
`deploy/` describes. The integrating application, the reverse proxy, the host
and the database server are outside it, and where a control depends on one of
them that dependency is named.

## Assets

In order of what their loss costs.

| # | Asset | Where it is | Loss means |
|---|---|---|---|
| 1 | The ability to authenticate as any subject | The credential tables, and the assertion signing key | Total compromise of every application relying on this service |
| 2 | The assertion signing key | `assertion.signing_key_path`, Ed25519 PKCS#8 PEM, mode 0600 | Forged assertions, accepted by every verifier, with no ceremony having happened |
| 3 | Administrative tokens | `admin_tokens`, selector clear, verifier as a SHA-256 digest | Authority over every subject of the tenant, and the ability to mint more authority |
| 4 | API keys | `api_keys`, same construction | Authority to run ceremonies against any subject of the tenant |
| 5 | The key encryption keyring | `kek.path` or `kek.env_var`, outside the data directory | The TOTP secrets and the readable subject references become readable to whoever also holds the database |
| 6 | The subject pepper | `subject.pepper_env` | With the database, the ability to confirm whether a given person has an account |
| 7 | TOTP shared secrets | `totp_secrets.secret_sealed`, envelope-encrypted | The second factor of every affected subject |
| 8 | Recovery codes | `recovery_codes.verifier_hash`, Argon2id | Nothing from the database. From a printed sheet, one login each |
| 9 | The audit log's integrity | `audit_log`, SHA-256 chain | The record every investigation rests on |
| 10 | Subject references | `subjects.ref_hmac` and `.ref_sealed` | Personal data: who has an account here |

## Trust boundaries

```
  internet
     |
     |  TLS terminates here or in process
     v
  +---------------------------+
  |  reverse proxy / ingress  |   outside scope; trusted only for the addresses
  +---------------------------+   in server.trusted_proxy_cidrs
     |
     |  [1] network: admin.ip_allow_list, applied before authentication
     v
  +---------------------------+
  |  n0passtemps process      |
  |                           |
  |  [2] credential: API key on /v1, admin token on /admin/v1
  |  [3] authorisation: rbac, per route, at mount time
  |  [4] tenant: the caller's credential must name the configured tenant
  |                           |
  |  in-process memory:       |
  |    KEK, pepper, signing key, plaintext secrets in flight
  +---------------------------+
     |                      \
     |  [5] DSN               \  [6] filesystem
     v                          v
  database                   keyring (separate volume), signing key, config
```

Six boundaries, and the honest characterisation of each:

| # | Boundary | Enforced by | Holds against |
|---|---|---|---|
| 1 | Network reachability of `/admin` | `admin.ip_allow_list`, before authentication, answering 404 | An unauthenticated internet attacker, entirely, when the list is set. Nothing, when it is not, which is why the validator refuses an enabled UI on a non-loopback listener with no list |
| 2 | Bearer credential | `internal/crypto/token`: structural parse, indexed selector lookup, constant-time digest comparison, single indistinguishable failure | Guessing, at 160 bits of verifier entropy. Not against a leaked credential |
| 3 | Role | `internal/rbac`, mounted per route, failing closed on an unknown role | An operator token reaching for a full-administrator operation. Nothing, when `features.admin_rbac` is off |
| 4 | Tenant | `Server.callerTenant`, on every handler | A credential carried over from another deployment. It is not a multi-tenancy control: v1 serves one tenant |
| 5 | Database connection | `sslmode` validation refusing silent plaintext fallback, and refusing `sslmode=disable` off the machine unless `database.allow_plaintext` says the link is private | A passive observer on the database path. Not against the database server itself, and not against an operator who sets `database.allow_plaintext` on a link that is not private: the validator cannot see network topology |
| 6 | Filesystem | Mode 0600 enforced on the keyring and the signing key; the keyring refused inside a data directory | The obvious misconfiguration. Not against root, and not against the operator |
| 7 | Enrolment ticket delivery | Nothing in this service: the channel belongs to the integrating application. Bounded by `tickets.ttl`, single use, one live ticket per subject and the factor guard | Nobody. It is a transferred risk, not an enforced boundary, and attacker 10 is what it costs |

## Attacker by attacker

### 1. An unauthenticated internet attacker

**Starts with** network reach to the listener. No credential.

**Can do**

- Reach exactly three routes: `GET /v1/health`, and the JWK Set at
  `GET /v1/.well-known/jwks.json` and `GET /v1/jwks.json`. Everything else on
  `/v1` requires an API key; everything on `/admin/v1` requires the allow list
  and a token. The unauthenticated set is listed explicitly in
  `mountUnauthenticated` so that adding a fourth is a visible decision.
- Learn that the process is alive, and read the public verification key. The
  key is public by construction: an integrating application has to fetch it to
  verify an assertion offline.
- Present guesses at API keys and administrative tokens, and be refused
  identically each time.

**Stopped by**

| Control | Effect |
|---|---|
| Authentication on every other route | An unauthenticated registration route would let anyone enrol an authenticator against any subject and then assert as them, with the attacker supplying both halves of the ceremony. That is a complete bypass, not a missing hardening measure; see [ADR 0002](adr/0002-authenticate-every-call-to-the-public-api-surface.md) |
| The liveness report carries one field | No version, no keyring state, no rotation status, no certificate expiry. Each of those is reconnaissance before it is diagnostics; see [ADR 0008](adr/0008-split-the-health-endpoint.md) |
| `admin.ip_allow_list` returning 404 | The administrative surface does not announce its existence |
| Per-address throttle | `throttle.max_failures_per_ip`, default 50 per 15 minutes, IPv6 bucketed by `/64` |
| Per-key volume limit | `throttle.max_requests_per_key`, default 6000 per window |
| `server.read_header_timeout`, default 5s | Slow-header denial of service |
| `server.max_body_bytes`, default 256 KiB, through `http.MaxBytesReader` | An oversized body is refused as it is read, never buffered |
| `Recover` middleware | A panic on one request returns 500 rather than dropping the process, so every other user's ability to log in does not depend on one malformed input |
| Uniform refusals | Every credential failure and every ceremony failure returns one body. A caller cannot tell an unknown selector from a wrong verifier, or an expired challenge from a bad signature |

**Not mitigated**

- **Volumetric denial of service.** There is no connection-rate limit, no
  SYN-flood defence, no per-address concurrency cap. The throttle counts
  attempts, not bandwidth, and it writes to the database to do so. An attacker
  with capacity can saturate the listener or the database. That belongs at the
  proxy and the network, and this service does not pretend to provide it.
- **The JWK Set as an oracle.** It tells an attacker that the service exists,
  which version of the key is current, and when a rotation happened. That is
  accepted: the alternative is an authenticated JWKS, which defeats offline
  verification.
- **Timing of the selector lookup.** The lookup is indexed and the comparison is
  constant time, but a present selector and an absent one are not guaranteed to
  take identical time at the database level. Exploiting it would require
  distinguishing a microsecond difference across a network, against 64 bits of
  selector space.
- **TLS, when it is not configured here.** The validator refuses plain HTTP on a
  non-loopback listener without `trust_proxy` or `server.allow_plaintext`, which
  forces the operator to make a decision, not to make the right one. A
  `trust_proxy` deployment behind no proxy is plaintext on the wire, and so is
  an `allow_plaintext` deployment whose port is reachable from anywhere but
  loopback. `allow_plaintext` is an acknowledgement that something outside the
  process constrains reachability; the binary cannot check that it is true.

### 2. A caller holding a leaked API key

**Starts with** a valid `npt_` credential for the tenant, and network reach to
`/v1`. This is the most likely real compromise, because the key lives in the
integrating application's configuration.

**Can do**

- Everything on `/v1` that the key's scopes cover, for every subject of the
  tenant. For an unrestricted key, which is what a key minted without scopes
  is, that means all of it: create subjects, start and complete ceremonies,
  enrol TOTP, issue and consume recovery codes, read the detailed health
  report. The rest of this list assumes such a key.
- **Not** authenticate as a subject whose authenticator they do not hold. The
  key authorises running a ceremony; the ceremony still requires the
  authenticator's signature over a server-chosen challenge.
- Enrol an authenticator of their own choosing against any subject, and then
  assert as that subject. This is the real damage: the API key is authority over
  the tenant's subjects, not merely access to an endpoint.
- Issue a fresh batch of recovery codes for any subject and read them from the
  response, which retires the user's existing sheet.
- Issue an enrolment ticket for any subject who holds no factor, and read it
  from the response. It adds nothing to what the key can already do, since the
  key can enrol an authenticator directly; it is listed because it is one more
  route whose response carries a secret, and because a ticket issued and
  delivered nowhere is a live secret the key holder alone knows about until it
  expires.
- Read the detailed health report: version, keyring state, rotation status,
  certificate expiry.

**Stopped by**

| Control | Effect |
|---|---|
| `webauthn.max_credentials_per_subject`, default 10 | Bounds silent mass enrolment |
| API key scopes | A key minted with `scopes` reaches only the named route families: `subjects`, `webauthn`, `totp`, `recovery`, `health`, `tickets`. A key that only verifies TOTP codes cannot issue recovery codes or enrol an authenticator, and cannot mint an enrolment ticket. A call outside the scopes is a 403 and an `api_key.rejected` audit entry, so a stolen key being explored leaves a trace |
| Per-key volume limit | `throttle.max_requests_per_key` is metered by a middleware on every public route, so it bounds starting ceremonies and resolving subjects as well as failed authentications |
| Every action audited | `subject.created`, `webauthn.registration.completed`, `recovery.issued` and the rest carry `actor_type: api_key` and the key's identifier, so the blast radius of a specific key is reconstructable |
| `recovery.exhausted` and `recovery.low` alerts | A user whose sheet was retired out from under them shows up |
| Key expiry | `expires_in_days` at creation. The response reports `no_expiry: true` rather than refusing a key without one |
| Revocation | `POST /admin/v1/api-keys/{key_id}/revoke`, effective immediately on the next request |
| Tenant check | A key from another deployment is refused rather than operating on rows it does not own |

**Not mitigated**

- **Scopes are opt-in and coarse.** A key minted without scopes is
  unrestricted; the minting response says `"unrestricted": true` and nothing
  refuses it. A scope is a route family, not a route: a key holding `webauthn`
  in order to run assertions can also register authenticators, which is the
  enrolment bypass below. Scopes do not restrict which subjects a key may act
  on.
- **Enrolment as authentication bypass.** There is no out-of-band confirmation
  of a new authenticator. A leaked key plus a silent registration is a working
  login, and the only thing standing between that and the user noticing is the
  audit log and the credential count.
- **Reading the health detail.** It is authorised for any API key, not only for
  an administrative role, because `GET /v1/health/detail` is mounted on the
  public surface. A leaked key therefore discloses the version and the keyring
  state, which ADR 0008 withheld from the unauthenticated caller.
- **Detection latency.** Nothing alerts on a key being used from a new address,
  or at a new time, or for an unusual mix of routes. The alert engine has thirteen
  conditions and none of them is behavioural.

### 3. A rogue administrator

**Starts with** a valid `npa_` credential, from inside the allow list.

**Can do, with `admin_operator`**

Lock and unlock subjects, revoke one credential at a time, reissue recovery
codes and read them, reset throttles, acknowledge alerts, and issue or withdraw
an enrolment ticket. Every one of those is a denial of service against a user,
or a way to obtain a working login for one: reissuing recovery codes returns
them in the response, and an enrolment ticket lets the holder enrol an
authenticator of their own against the subject. The ticket is the narrower of
the two, because it produces no assertion and because issuing it for a subject
who still holds a factor requires an explicit override that raises an alert; it
is not narrow enough to matter against an administrator who is willing to revoke
the factor first.

**Can do, with `admin_full`**

All of the above, plus mint an API key, mint another administrative token of any
role, revoke any credential or every credential of a subject in one call,
request an erasure, rewrap the keyring, and decide approvals.

**Stopped by**

| Control | Effect |
|---|---|
| The role split | An auditor changes nothing but its own token, which it may rotate, not even an alert acknowledgement, because an auditor who can quietly clear an alert can quietly cover a trace. An operator cannot change who may administer the service |
| `throttle.admin_revoke_burst`, default 10 | The revoke route is rate limited per administrator. This is the control that replaces reversible revocation; see [ADR 0010](adr/0010-revocation-is-final.md) |
| `credential.bulk_revoked` alert | Raised above the burst |
| The last-credential guard | Revoking a subject's only authenticator requires `allow_last: true` |
| The last-administrator guard | The last usable `admin_full` token cannot be revoked, so the deployment cannot be made unadministrable |
| Dual approval | `subject.erase`, `admin_token.create`, `credential.revoke_bulk` and `kek.rotate` are held for a second, distinct administrator. Self-approval is refused inside the same transaction as the state change, so a second code path cannot bypass it. An approval is redeemed by the original requester and is bound to the operation, the requester and the payload, so it cannot be stolen, spent on something else, or used to run a request other than the one the second administrator read. It expires, and a conditional update spends it exactly once. See [ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md) |
| Every action audited | With the actor's token identifier, never its secret, so revoking a token does not make the history of what it did ambiguous |
| `admin.denied` alert | A token reaching beyond its role is visible |

**Not mitigated**

- **A full administrator is trusted.** By design. `admin_full` holds all
  twenty-eight permissions, and the only thing standing between it and total
  control is the dual-approval queue on four operations and the audit log
  afterwards. Separation of duty here is a speed bump and a record, not a
  barrier.
- **Dual approval with one token is theatre.** Every queued request sits until
  it expires, because the only token able to decide it raised it. The API
  carries no exemption for a sole administrator, on purpose: a rogue
  administrator could reach one by revoking the others, mint a token they
  control, and approve their own requests from then on. The quorum is created
  at install time with `-bootstrap-admin -admins 2`, or completed later with
  `-bootstrap-admin -force -admins 1`, and the second token goes to a different
  person. Running the feature with one token is worse than not running it,
  because it creates the belief that a second person is involved.
- **Two tokens are not two people.** The queue tells administrators apart by
  token identifier. One person holding two `admin_full` tokens satisfies it
  alone. The bootstrap command hands out the initial pair to whoever runs it,
  and nothing in the software checks that the second token reached a second
  person. Anyone with a shell on the host can obtain further tokens with
  `-bootstrap-admin -force`. The control is against a single stolen token and a
  single hasty administrator, not against collusion or a compromised host.
- **The binding on `admin_token.create` covers the name and the role.**
  `expires_in_days` is not part of the approved payload, so a requester can
  redeem an approval with a longer lifetime than the one first submitted.
- **Most mutating operations are not held at all.** Minting an API key, revoking
  a single credential with `allow_last`, reissuing recovery codes and revoking
  an administrative token run on one administrator's say.
- **`features.admin_rbac = false` collapses the model.** Which
  `features.lite_mode` implies. Every valid role then carries full authority.
- **Recovery code reissue is an authentication bypass for an operator.** It
  returns working codes for any subject. It has to, because that is the
  operation behind a user who has lost everything. There is no approval gate on
  it and it is available to `admin_operator`.
- **Reading personal data.** `subject.read` plus `?reveal_ref=true` decrypts a
  subject reference, and every role holds `subject.read`. There is no second
  check inside the handler, so any role able to read a subject can reveal its
  reference. The disclosure is audited as `admin.subject_ref_revealed`, which is
  detection, not prevention.
- **Reading the credential inventory.** `api_key.list` and `admin_token.list`
  are held by every role, so an auditor sees which API keys and administrative
  tokens exist, with their names, roles and last use. No selector and no
  verifier is ever in a response, so it is the inventory and not the
  credentials.
- **Acknowledging an alert hides it.** `alert.acknowledge` removes a row from
  the open set and from the fingerprint deduplication, so the same condition
  recurring afterwards creates a new row rather than incrementing the old one.
  An operator can acknowledge the alert that describes their own action.

### 4. An attacker with a copy of the database

**Starts with** the SQLite file, or a `pg_dump`, or a volume snapshot, or a
backup archive. No keyring, no pepper, no signing key.

**Can read**

| Data | What it gives them |
|---|---|
| Every WebAuthn public key, credential identifier, AAGUID, attestation type and flag | Which authenticator models are in use across the population, which is inventory information to act on when a model-specific weakness is published. Credential identifiers are exposed, and an allow list built from them is visible. See [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) |
| The subject graph | How many subjects exist, how many credentials each has, who has TOTP, how many recovery codes remain, when each last authenticated |
| The audit log | Every event, every source address, every actor identifier |
| API key and administrative token selectors, names, roles and timestamps | Which credentials exist and what authority each has |
| Alert rows | Which subjects have had trouble, and of what kind |
| Recovery code selectors | 30 bits each, and nothing about the code |

**Cannot read**

| Data | Why |
|---|---|
| Any TOTP secret | Envelope-encrypted under a KEK they do not have. AES-256-GCM |
| Any readable subject reference | Same |
| Which person a subject is | `ref_hmac` is an HMAC under a pepper they do not have. They can neither read nor enumerate the references |
| Any usable recovery code | Argon2id over a 70-bit verifier. Out of reach regardless of the hash cost |
| Any usable API key or administrative token | SHA-256 over a 160-bit verifier, bound to the kind and the selector |

**Can also do**

- **Forge nothing that verifies.** Assertions are signed by a key that is not in
  the database.
- **Rewrite the audit chain**, if they have write access rather than a copy.
  See the next attacker.

**Not mitigated**

- **Everything in the first table.** The design accepts it. Encrypting the
  credential table would put it on the KEK dependency path, so a lost KEK would
  destroy enrolments that were never secret, and would force an unseal on every
  assertion where a direct read would do.
- **Confirming a specific person, with the pepper.** An attacker holding the
  database and the pepper can compute the HMAC of a guessed reference and check
  whether it exists. They still cannot enumerate: the HMAC is one way. This is
  why the pepper is a separate secret from the KEK.
- **Offline analysis.** Nothing in the database expires on its own. A snapshot
  is as useful in a year as it is today, except for the credentials that have
  since been revoked.

### 5. An attacker with the database and the keyring

**Starts with** both halves. This is the arrangement
[ADR 0009](adr/0009-refuse-a-kek-inside-the-data-directory.md) exists to
prevent, and the single most likely way to arrive at it is a backup archive
containing both, or a deployment that put the keyring in the data volume.

**Can additionally read**

- Every TOTP shared secret, in clear. They can generate valid codes for every
  enrolled subject indefinitely, because a TOTP secret has no expiry.
- Every sealed subject reference, in clear. The pseudonymisation is gone: the
  database becomes a list of who has an account.

**Cannot still**

| Data | Why |
|---|---|
| Any recovery code | Hashed, not sealed. This is the direct benefit of [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md): the codes that exist to be used when other things have gone wrong do not depend on the key that has gone wrong |
| Any API key or administrative token | Digested, not sealed |
| A forged assertion | The signing key is a separate file |
| A WebAuthn assertion | The private key is on the authenticator and was never here |

So even with both halves, an attacker cannot log in as a WebAuthn-only subject.
They can log in as a TOTP-only subject, from the secret, which is one of the
reasons a TOTP-only user is a weaker position than a WebAuthn user.

**Not mitigated**

- **Nothing in the above.** With both halves the confidentiality of the sealed
  data is gone. That is what encryption at rest means and what its loss means.
- **Detection.** Reading a stolen copy leaves no trace anywhere. The audit log
  records what the service did, not what somebody did to a file.
- **Rotation does not help retroactively.** Rotating the KEK re-wraps the data
  keys of new and rewrapped records; it does not change the plaintext an
  attacker already extracted from an old snapshot.

### 6. A compromised end-user device

**Starts with** code execution on the user's machine or phone, or a
sufficiently convincing phishing page.

**Can do**

- Drive the browser, and therefore the ceremony, while the user is present. A
  WebAuthn assertion requires a user gesture and, with
  `user_verification = "required"`, a PIN or a biometric, so the attacker needs
  the user to act. With that, they get one assertion, and that assertion is what
  the calling application exchanges for a session.
- Read a recovery code the user has on screen or in a password manager.
- Read a TOTP secret from the provisioning URI at enrolment, or a code from the
  authenticator app, or the seed from the app's storage.
- Steal the application's own session after the assertion has been exchanged,
  which is outside this service entirely.

**Stopped by**

| Control | Effect |
|---|---|
| Origin binding | A phishing page on a domain not in `webauthn.origins` cannot complete a ceremony. The authenticator signs over the origin the browser actually saw, and this service compares it against a list the caller cannot influence; see [ADR 0003](adr/0003-the-service-is-the-webauthn-relying-party.md) |
| `user_verification = "required"` | The authenticator proves identity, not merely possession, so malware cannot silently use a plugged-in key |
| Challenge single use | `ConsumeChallenge` is atomic: an assertion cannot be replayed to obtain a second session |
| Counter compare-and-swap | Two concurrent completions have exactly one winner |
| User verification reported per ceremony | The `webauthn-uv` factor in `amr` is set from the authenticator data of the assertion in hand, never from the stored credential. Under `user_verification = "preferred"`, a stolen key used without its PIN yields an assertion signed as possession only, and the application can refuse it |
| 60 second assertion lifetime, single-use `jti` | A captured assertion is neither replayable later nor usable twice, provided the verifier keeps a replay cache |

**Not mitigated**

- **A TOTP-only user is phishable in a way a WebAuthn user is not.** This is
  worth stating on its own, because it is the sharpest asymmetry in the whole
  design. A TOTP code carries no origin binding: a page at
  `auth-example.com.evil.test` can ask for a code and the user can supply one
  that verifies against the real service. A WebAuthn assertion cannot be
  obtained that way at all, because the authenticator refuses to sign for an
  origin that does not match the credential's relying party. A deployment that
  offers TOTP as an alternative first factor has a phishable authentication path
  whatever its WebAuthn configuration says, and the `amr` claim on the assertion
  is what lets the calling application treat the two differently.
- **A recovery code is phishable the same way**, and is the single most valuable
  thing to phish, because one code is one login.
- **Malware present during a ceremony.** There is no defence. The user
  authenticated; the attacker was in the session.
- **A cloned platform authenticator.** A synchronised passkey exists on every
  device in the user's account, and the signature counter is constantly zero on
  those platforms, so the clone signal is not available for them at all.
- **Session theft after the exchange.** The assertion's job ends when the
  application issues its own session. What happens to that session is the
  application's problem.

### 7. A malicious dependency

**Starts with** commit access to one of the six direct dependencies, or to
anything in their transitive closure, or to a GitHub Action used by the
workflows.

**Can do**

- Reach the binary an operator installs to protect their logins, without
  touching any Go code a reviewer of this repository would read. Inside an
  authentication product that is the highest-value target in the tree.
- Specifically: `go-webauthn/webauthn` parses attestation objects and validates
  ceremonies, so a change there is an authentication bypass. `modernc.org/sqlite`
  and `pgx` see every plaintext that reaches the database layer.
  `golang.org/x/crypto` provides the Argon2id that protects recovery codes.
- A build-time compromise of an Action reaches the release artefact and the
  container image.

**Stopped by**

| Control | Effect |
|---|---|
| Six direct dependencies | Each argued for in [ARCHITECTURE.md](ARCHITECTURE.md). The JWS is hand-written rather than taken from a JWT library, and the administration interface is `html/template` rather than React, which keeps Node.js and its transitive closure out of the build and out of CI entirely; see [ADR 0012](adr/0012-server-rendered-administration-interface.md) |
| `go.sum` and `go mod verify` | A published version cannot change under a fixed hash |
| `govulncheck`, weekly and on every push | A new advisory turns the security workflow red without a commit |
| `gosec`, CodeQL, `gitleaks`, Trivy, dependency review | The `security` workflow |
| Every Action pinned to a commit SHA | A tag is a moving reference the upstream owner can repoint, which is the shape of the `tj-actions` compromise |
| Tool versions pinned in the `Makefile` | A lint or scan result is reproducible across machines and across time |
| `CGO_ENABLED=0`, `-trimpath`, distroless static base | No C toolchain in the build, no shell in the image |
| Dependabot | Upgrades arrive as reviewable pull requests |

**Not mitigated**

- **A compromise published before an advisory exists.** Every control above is
  either reactive, `govulncheck` and Dependabot, or a reproducibility guarantee,
  `go.sum` and the pinned SHAs. None of them detects malicious code in a version
  nobody has reported yet.
- **No reproducible build verification.** `-trimpath` and the pinned toolchain
  make the build deterministic in principle, and nothing in the release pipeline
  proves that the published binary corresponds to the published source. There
  is no SLSA provenance attestation and no signed artefact in this release.
- **No vendored dependencies.** The module cache is fetched from the proxy at
  build time. A verified hash is not the same thing as a reviewed diff.
- **The upgrade treadmill.** A dependency that is not upgraded for long enough
  becomes one that cannot be upgraded safely, and a one-person project has a
  finite budget for the reviews.

### 8. Whoever reads the startup log

**Starts with** read access to the service's standard output: the container log,
the journal, or whatever the log pipeline ships it to. This is a wider group
than the people who may hold a credential. A log stream is shipped, indexed and
retained by systems whose access rules are looser than those of a credential
store.

**Can do**

- Read what the service logs: request identifiers, source addresses, tenant and
  actor identifiers, problem types, the reasons requests were refused, and the
  warning that no administrator exists yet, which tells them the deployment is
  fresh.
- **Not** obtain an administrative token. The running service never creates one
  and never writes one. The first token is created by a separate, one-shot run
  of the binary, `n0passtemps-server -config <path> -bootstrap-admin`, which
  prints it to the terminal of the operator who ran it and exits. Nothing that
  the long-running process writes contains a credential. See
  [ADR 0014](adr/0014-bootstrap-by-explicit-command.md).

**Stopped by**

| Control | Effect |
|---|---|
| Bootstrap by explicit command | The tokens, one or up to five with `-admins`, go to the standard output of a one-shot process attached to a terminal, not to a log stream |
| It is printed once and never again | Only a selector and a digest are stored |
| The command refuses once a usable `admin_full` exists | It cannot be re-run casually to obtain another token. `-force` lifts the refusal, records `detail.forced: true` in the audit entry, and is reachable only by someone who already holds the configuration, the keyring and the database |
| Redaction in the log handler | A value wrapped in `logging.Secret` is redacted wherever it appears, including inside a struct |
| Revocation | Mint a named replacement and revoke the bootstrap token, which the deployment guide makes step three of the install |

**Not mitigated**

- **The operator's own terminal.** Each token is displayed once, in clear. With
  `-admins 2` both tokens of the quorum are on one person's screen until the
  second is handed over, and for that interval the two-person rule rests on that
  person.
  Terminal scrollback, a multiplexer's history buffer, a recorded or shared
  session, and a screen someone else can see all hold it for as long as they
  hold anything. That exposure is the operator's own and is far narrower than a
  log pipeline, but it is not nothing.
- **Shell history and redirection.** The command line carries no secret. An
  operator who captures the output, with a redirect to a file, a `tee`, or a
  command substitution into an exported variable, has made a copy the service
  knows nothing about. So has one who pastes the token into a later `curl`
  command that the shell records in its history file.
- **Running it through something that logs.** `docker compose run` and
  `kubectl exec` return the output to the caller, and `systemd-run --pty`
  attaches it to the terminal. Running the command as an ordinary unit, a CI
  job, or a Kubernetes Job puts the token straight back into a log stream, and
  nothing in the binary can tell the difference.
- **`-force` is as strong as host access.** It is audited in a log the same
  person can rewrite; see attacker 9.

The remedy for all four is the one in the install procedure: use the bootstrap
token to mint a named one, then revoke it.

### 9. The operator themselves

The party most likely to want history rewritten, and the party the software
cannot constrain.

**Starts with** root on the host, the database file, the keyring, the pepper,
the signing key and the configuration.

**Can do**

- **Rewrite the whole audit chain consistently.** This is the important one, and
  it is worth spelling out. The immutability triggers are inside the artefact
  they protect: anyone holding the database file can open it with the `sqlite3`
  shell, drop the triggers, edit or delete rows, recompute `prev_hash` and
  `entry_hash` for every entry from the edit onwards, recreate the triggers, and
  the resulting file is indistinguishable from an untouched one.
  `GET /admin/v1/audit/verify` will report `intact: true`. The chain raises the
  cost of tampering from one `UPDATE` to a scripted rewrite; it does not prevent
  it. See [ADR 0007](adr/0007-chain-the-audit-log.md).
- Read every secret the process holds, from `/proc` or from a core dump.
- Substitute a WebAuthn public key, since no store method updates
  `public_key` after insertion and integrity there rests on the filesystem
  rather than on cryptography.
- Mint any credential, disable any control, and configure the service to lie.
- Weaken the configuration within what the validator permits, for instance
  `features.admin_rbac = false`, `throttle.enabled = false`, or
  `logging.include_source_ip = false`.

**Stopped by**

Nothing in this software by itself, and the software says so rather than implying
otherwise. `SECURITY.md` puts operator tampering with the audit log explicitly
out of scope, because it is a documented limitation and not a vulnerability.

**What closes the gap, once it is configured**

An external witness. `audit.sink.endpoint` ships the hash-covered part of every
entry to an HTTP receiver with a bearer credential, and a receiver that has kept
those hashes can detect a rewrite, because a chain recomputed after an edit
cannot reproduce hashes somebody else already holds. That is what turns this
attacker from undetectable into detectable, and it is the only thing that does.

It is off unless an endpoint is configured, and the configuration makes the
operator declare that the receiver is outside their control, because the feature
is worthless rather than merely weaker when it is not: a file on this host, a
bucket under the same credentials or a log collector the same root account
administers all fall to this same attacker.

Four limits are worth stating plainly.

- **It protects the past, not the present.** Entries delivered before the
  operator turned hostile are witnessed. From the moment they control the
  process they can stop the shipper, revoke the credential, point the endpoint
  elsewhere or simply not write the entries they do not want written. A witness
  proves what was sent; it cannot make a compromised deployment send anything.
- **Detection still depends on somebody comparing.** The receiver holds the
  hashes. Nothing in this service asks it whether they still match, and nothing
  can: a check this service performed would be a check the operator controls.
  The comparison is the receiver's job and an operator's procedure.
- **The copy proves and does not explain.** Only the fields the chain hash
  commits to are sent, which excludes the subject, the source address and the
  entry detail. The witness answers whether the history was rewritten. It cannot
  be used to investigate an incident or to rebuild the log, and a reader of it
  cannot tell which person an entry concerns. That is deliberate: see
  [ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md).
- **A trimmed prefix looks like tampering.** Entries removed by
  `audit.retention_days` before they were delivered leave a gap the receiver
  cannot tell from an edit. The shipper reports that case at error level, and
  the guidance is to prune only what the receiver has acknowledged.

Within a single database, detection is the strongest property available, and it
is enough to make undetected selective deletion impractical for anybody who does
not have write access.

### 10. Whoever controls ticket delivery

**Starts with** read access to the channel an enrolment ticket travels over, and
nothing else: no credential of this service, no key, no database. A mail relay,
a shared inbox, an SMS gateway, an unlocked phone on a lock screen, the helpdesk
queue the ticket was read out from, a Slack channel somebody pasted it into.

This attacker exists because of a deliberate design decision. The service does
not deliver tickets. It has no SMTP dependency, no outbound network access and no
opinion about the channel, so the delivery risk is transferred whole to the
integrating application. That is the right place for it, because the knowledge of
the user and of the channel lives there. It is not a way of making the risk
disappear, and this section is what the transfer costs.

**Can do**

- Redeem an intercepted ticket before the legitimate user does, and enrol an
  authenticator of their own choosing against that subject. From then on they
  can assert as the subject through the ordinary ceremony, indefinitely, until
  the credential is revoked.
- Do it silently from the user's point of view. The user finds a ticket that no
  longer works and reports a broken link, which reads as a delivery problem
  rather than as a compromise.
- Nothing else with the ticket itself. Redeeming one never produces a signed
  assertion, so the ticket is not a session and cannot be exchanged for one. It
  cannot read a subject, issue recovery codes, enrol TOTP, or reach any other
  route: both redemption routes accept it and no other route does.

**Stopped by**

| Control | Effect |
|---|---|
| `tickets.ttl`, default `1h`, maximum 24h | The window is the exposure. An attacker with read access to a mailbox they do not watch continuously has an hour, not a fortnight |
| Single use, enforced by a compare-and-swap | A ticket redeemed by the legitimate user is dead. The race is winnable, but only once, and only by whoever gets there first |
| One live ticket per subject, enforced by a partial unique index | Issuing again revokes the previous one, so tickets cannot accumulate and a reissue after a suspected interception closes the first window rather than adding a second |
| `tickets.require_existing_factor_default`, default on | A subject who still holds an authenticator or a confirmed TOTP secret cannot be issued a ticket without an explicit `require_existing_factor: false`. This is the control that stops the channel from being a general account-takeover route rather than a recovery one |
| The `enrolment_ticket.factor_override` alert | Every override is a warning-level row an operator sees in `GET /admin/v1/alerts`, collapsed by fingerprint so a campaign is one row with a rising count |
| Full audit trail | `enrolment_ticket.issued` names who issued it and what factors the subject held at the time; `webauthn.registration.started` and `.completed` carry `via: enrolment_ticket` and the ticket identifier; `enrolment_ticket.redeemed` records which credential the redemption produced. An enrolment through a ticket is therefore distinguishable from an ordinary one, after the fact |
| Rate limiting per source address and per ticket selector | Guessing a ticket costs the per-subject failure budget per selector, and spraying across selectors costs the per-address budget. A wrong ticket is indistinguishable from an expired or consumed one, so nothing tells an attacker which selectors exist |
| Revocation | `POST /admin/v1/enrolment-tickets/{ticket_id}/revoke` kills a ticket believed intercepted, and `POST /admin/v1/subjects/{subject_id}/credentials/{credential_id}/revoke` kills whatever it enrolled |

**Not mitigated**

- **Interception inside the window is a full account takeover.** Every control
  above bounds it, records it or makes it noisy. None of them prevents it. An
  attacker who reads the ticket and redeems it first owns the account until
  somebody revokes the credential, and the service cannot tell the two
  redemptions apart because both present a valid ticket from a plausible
  address.
- **The service cannot see the channel.** It does not know whether the ticket
  went to a corporate mailbox behind MFA or to a webmail account whose password
  was in a breach dump. It cannot verify that the person on the helpdesk call
  was the subject. `reason` is free text nobody validates.
- **The factor guard protects accounts that have factors, not accounts that do
  not.** A subject with nothing enrolled is exactly the case a ticket is for,
  and is exactly the case where the guard does not apply. Enrolment tickets
  move the root of trust from "holds an authenticator" to "receives what the
  application sent", for that one subject, for that one hour. That is the
  trade, and it is the same trade a password reset email makes, with a shorter
  window, a single use, no assertion at the end, and an audit trail.
- **Detection is after the fact.** Nothing alerts on a redemption from an
  unexpected address, or on a redemption minutes before the legitimate user
  tries. The alert list has thirteen conditions and none of them is behavioural.
- **Delivery is unauthenticated at the application's end.** If the integrating
  application emails tickets and its mail path is compromised, every ticket it
  ever sends is readable. That is a property of the application's
  infrastructure, and this service's contribution to it is to keep the ticket
  out of its own logs: it appears in the issuing response body and in no path,
  no header and no log line.

**What would actually narrow it**

Requiring a second, independent factor at redemption, which is to say requiring
the subject to already hold one, which is the case tickets exist to handle. The
honest narrowing is operational rather than technical: set `tickets.ttl` as low
as the delivery channel tolerates, issue on a live call rather than in a batch,
and read `enrolment_ticket.` in the audit log as a routine review rather than
during an incident.

## Cross-cutting limits

These limits apply to every attacker above and are easy to overlook.

### The console's passkeys close the pasted secret, and not much else

The administration interface accepts a passkey in place of the administrative
token, over a credential space of its own; see
[ADR 0017](adr/0017-administrative-sign-in-with-webauthn.md).

What that closes is narrow and worth naming exactly. It removes the long-lived
bearer token from a form field, and with it the browser form history that field
fed, the password manager entry nobody audits, the terminal scrollback the token
was copied out of, and the reading of it over an operator's shoulder. It removes
the credential from the wire on the sign-in request, since what travels is a
signature over a server-chosen challenge that is good once. It also makes a
console sign-in phishing-resistant in the way every subject sign-in already is:
the authenticator signs over the origin, so a page on a lookalike host obtains
nothing a genuine sign-in would accept. With `admin.passkey_required` the token
stops being accepted in the form at all once that administrator holds a key.

What it does not close:

- **`/admin/v1` is unchanged.** The bearer token is still the credential for the
  API, because its caller is a script with no authenticator to touch. An
  attacker who obtains a token has everything that token's role carries, exactly
  as before. Enrolling a passkey neither revokes the token nor narrows it.
- **The bearer token still exists, and must.** It is how the first
  administrator exists ([ADR 0014](adr/0014-bootstrap-by-explicit-command.md))
  and the way back in when a key is lost.
  `admin.passkey_required` is per token, not per deployment, so a token with no
  passkey is always accepted. That floor is what stops the setting locking a
  deployment out, and it is also the thing to reason about: whoever can run
  `-bootstrap-admin -force` on the host can mint a fresh token, and that token
  can be pasted. Nothing here narrows attacker 9, the operator themselves.
- **A compromised operator device is still a compromised console.** The session
  cookie the ceremony produces is the same cookie a pasted token produces, with
  the same lifetime; a key with a resident credential that has been left
  unlocked is a key that signs in. Withdrawing the credential is final and
  immediate, and is the answer.
- **It is not a second factor.** A passkey replaces the token for that
  administrator; it is not required in addition to it. What it proves depends on
  the authenticator, which is why user verification is required on this route
  whatever `webauthn.user_verification` says: without it, a found key would open
  the console with nothing else needed.
- **The separation from subject credentials is a property of this code, not of
  WebAuthn.** Both spaces share one relying party identifier, so a browser will
  show an administrator's key and a user's key in the same prompt. What keeps
  them apart is that the rows live in different tables, that the user handles
  are derived under different domain separators, and that neither registration
  will store an identifier the other already holds. A future change that merged
  the two tables, or reused the handle construction, would make every enrolled
  user an administrator, and the two cross-use tests in
  `internal/webauthn/admin_test.go` exist to fail loudly if one does.

### `zeroize` is best-effort

`zeroize.Bytes` overwrites a slice and reads it back through a constant-time
comparison so the compiler cannot eliminate the write. That is all it can do.
The Go runtime may copy a slice during garbage collection or stack growth, and
the operating system may page it to swap before the overwrite is reached, so a
plaintext key may exist in memory or on disk in a location the process no longer
has a reference to. Go strings are immutable and their backing array cannot be
overwritten at all, which is why secrets are carried as `[]byte` from the moment
they are read and why `zeroize.Strings` is a documented no-op.

Zeroizing shortens the window in which key material sits in reachable memory. It
does not eliminate it. A deployment that needs a hard guarantee needs key
material in an HSM or an external KMS, which this service does not provide.

The same applies to the `env` KEK provider. It unsets the variable once parsed,
which removes it from the process environment block and from `/proc/self/environ`
for anything reading afterwards, but the Go runtime has already copied the value
into an immutable string and the orchestrator still holds it in its own state.

### The signing key is a single point of forgery

One Ed25519 key signs every assertion. An attacker who reads it can mint a token
for any subject, with any `amr`, that every verifier accepts, with no ceremony
having happened and nothing in this service's audit log to show it. There is no
key hierarchy, no per-tenant key and no hardware backing. Mode 0600 and the
filesystem are the whole defence.

The mitigations that exist are indirect: the 60 second lifetime limits a captured
token but not a forged one, and the `kid` header with a JWK Set lets an operator
rotate to a new key and stop publishing the old one, which invalidates forgeries
made with it from that moment on.

### Detection depends on somebody reading

The alert types, the hash chain and the audit log are all detection. Every one
of them assumes an operator who looks. The alert engine deliberately has a
short, closed list of conditions, because an alert stream nobody reads is worse
than no alert stream: it creates the belief that someone would notice.
[MONITORING.md](MONITORING.md) says what to alert on and what response each one
warrants.

### An audit sink adds a party, and a credential

A deployment with `audit.sink.endpoint` set has one more party in its trust
boundary and one more credential to look after, and both are worth naming.

The receiver holds the hash-covered part of every entry. That is a commitment to
the personal fields rather than the fields themselves, and the per-entry salt is
never sent, so a receiver, or whoever compromises one, learns the shape and the
timing of a deployment's activity and not who it concerned. The sequence
numbers, the event types and the outcomes are enough to tell that forty
authentications failed on a Tuesday night, and not enough to tell whose.

Whoever holds the bearer credential can write to the receiver. A witness the
sender can also poison is weaker than one it cannot, and the answer is the
receiver's: it stores the first copy of a sequence number it is given and treats
a second, different copy as evidence rather than as a correction. That is stated
as a receiver obligation in [CONFIGURATION.md](CONFIGURATION.md#auditsink),
because this service cannot enforce it from the sending end.

The credential is read from the environment, unset once read, and appears in no
log line, no alert row and no health response. Losing it costs delivery until the
receiver issues a new one, and nothing else.

### Risk signals report, and that is all they buy

[RISK.md](RISK.md) describes the risk claim: nine signals, each with a weight,
and two thresholds. It is worth being precise about what it adds to this model
and what it does not.

What it buys. Three signals that were already collected and only reachable by
reading the audit log now travel in the signed assertion, where the integrating
application can act on them at the moment it matters rather than the morning
after: a stalled signature counter, a changed authenticator binding and a
possession-only assertion. A recovery-code redemption and a failure burst
followed by a success become visible to the application in the same way. That
moves the step-up decision to the only party that knows what the user is about
to do, and it does so without this service holding any new data about anyone.

What it does not buy. Every signal is a property of the ceremony, not of the
person. An attacker who holds the authenticator and its PIN produces a ceremony
indistinguishable from the legitimate one, and no threshold will say otherwise:
against that attacker the assessment reads `low`, correctly, because nothing
about the ceremony was wrong. The signals that would catch such an attacker are
the ones this service deliberately does not have: no geolocation, no device
fingerprint, no behavioural baseline, no reputation feed. Those need data the
service refuses to collect, or network access it refuses to make, and each of
them would also be a new way to lock out a legitimate user for travelling.

Two further limits. The service never refuses on risk, so a high assessment
that the integrating application ignores changes nothing at all: the control is
the application's, and this service can only report and alert. And the level in
the response body is unsigned, so an attacker on the network path between the
service and a careless caller can downgrade it at will; only the claim inside
the assertion is covered by the signature, which is why the documentation says
so in every place the fields appear.

Risk reporting is therefore not a mitigation for any attacker listed above. It
is a way of telling the integrating application what this service saw, so that
its own mitigations can be applied in proportion.

### The metadata BLOB is as fresh as the operator keeps it

Attestation verification, when it is turned on, trusts a FIDO MDS3 BLOB read
from `webauthn.metadata_path`. The file's JWT signature is verified against the
FIDO root, so an attacker who can write to the disk cannot substitute their own
trust anchors, and the file is never fetched, so there is no network path to
tamper with. Entries that do not parse are dropped, which fails safe, because an
unknown model is refused when attestation is required.

Staleness fails safe in one direction only. A model certified after the download
is unknown and refused. A model whose status report turned to revoked or
compromised after the download is still trusted, because the report is in a file
the service has not been given. Nothing in the service measures the age of the
BLOB or alerts on it. An attacker with write access to the disk can also replace
a current file with an older, genuinely signed one, and the signature check
passes.

## Out of scope, deliberately

| Threat | Why |
|---|---|
| Tampering with the audit log by whoever holds the database file | Documented above. `SECURITY.md` says so |
| An operator who weakens their own configuration within what the validator permits | A setting the validator permits and documents as a trade-off is a choice |
| Volumetric denial of service | Belongs at the network and the proxy |
| The integrating application's session handling | Outside the boundary. The assertion's job ends at the exchange |
| Physical access to the host | Nothing in software survives it |
| Findings that require running without TLS on a public interface | The validator refuses that combination |
| A supply-chain compromise published before any advisory exists | Named above as unmitigated, not as out of scope |

## Standards this is measured against

| Standard | Where it bites |
|---|---|
| W3C WebAuthn Level 2 | The relying party model, the origin and RP ID comparisons, the signature counter |
| RFC 6238, RFC 4226 | TOTP, the HMAC counter construction, the 128-bit minimum secret |
| RFC 7515, RFC 7517, RFC 7638, RFC 8037 | The compact JWS, the JWK Set, the thumbprint used as `kid`, the Ed25519 `EdDSA` algorithm |
| RFC 9457 | The problem detail format of every error response |
| OWASP ASVS 4.0 | Section 4, an access control decision on every request; section 6, key material not readable by group or other; section 7, log protection against tampering |
| OWASP API Security Top 10 2023 | API2:2023 Broken Authentication, which is what an unauthenticated `/v1` would have been; API4:2023 Unrestricted Resource Consumption, which the throttle and the body limit address |
| GDPR Articles 15, 17 and 32 | [GDPR.md](GDPR.md) |

## Related documents

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Where each secret lives and what the boundaries are |
| [GDPR.md](GDPR.md) | The personal data inventory and the erasure mechanism |
| [MONITORING.md](MONITORING.md) | Turning the detection above into something somebody reads |
| [RISK.md](RISK.md) | The risk signals reported on a completed ceremony, and what they are not |
| [RBAC.md](RBAC.md) | The role split in full |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability, and what is in and out of scope |
| [docs/adr](adr/README.md) | The reasoning behind each accepted limit |
