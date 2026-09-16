# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.0] - 2026-09-16

First release. An on-premise passwordless authentication server: WebAuthn and
FIDO2, TOTP, single-use recovery codes, one static binary, SQLite or PostgreSQL.

### Added

- **WebAuthn and FIDO2 ceremonies**, per W3C WebAuthn Level 2. Registration and
  assertion, each as two round trips, with the ceremony state held server side
  in `webauthn_challenges` and consumed atomically. Platform and roaming
  authenticators, an AAGUID allow list and block list, and a configurable
  credential limit per subject. User verification is reported from the
  authenticator data of the ceremony in hand and from nothing else, so a
  possession-only assertion is never signed as user-verified, whatever the
  credential did at registration. The ceremony layer is tested end to end
  against a software authenticator.
- **Optional attestation verification, offline.** `webauthn.metadata_path`
  names a FIDO MDS3 BLOB on disk. Its JWT signature is verified against the FIDO
  root, so a file altered on disk is refused, and it is never fetched over the
  network. Entries that do not parse are dropped, which fails safe: an unknown
  model is refused when attestation is required.
- **TOTP**, per RFC 6238 over the HMAC counter construction of RFC 4226. SHA1,
  SHA256 or SHA512; six or eight digits; a period between 15 and 120 seconds; a
  shared secret of at least 160 bits; enrolment confirmed by the user producing
  a code before the secret becomes usable; a replay high-water mark advanced by
  compare-and-swap.
- **Single-use recovery codes**. Twenty characters of Crockford base32 with `I`,
  `L`, `O` and `U` removed, split into a six-character indexed selector and a
  fourteen-character verifier stored as an Argon2id PHC string. Issuing a batch
  retires every unused code from the previous one in the same transaction.
- **A signed assertion result**. A compact JWS (RFC 7515) signed with Ed25519
  under the `EdDSA` algorithm of RFC 8037, carrying JWT claims including an
  `amr` array naming the factor used, a unique `jti`, and a 60 second lifetime.
  The verification key is published as a JWK Set (RFC 7517) with a `kid` that is
  its RFC 7638 thumbprint, so an integrating application verifies offline.
- **Two authenticated HTTP surfaces**. `/v1` for an integrating application,
  behind an API key; `/admin/v1` for an operator, behind an administrative
  token, a network allow list and a per-route permission. Errors follow
  RFC 9457, with a URN type per class and a `request_id` on every response.
- **Three administrative roles and twenty-five permissions**, enforced where
  each route is mounted rather than inside its handler. `admin_auditor` reads
  and changes nothing; `admin_operator` adds the operations that recover a
  locked-out user; `admin_full` holds everything.
- **Dual approval as a redeemable capability**, for four operations by default:
  `subject.erase`, `admin_token.create`, `credential.revoke_bulk` and
  `kek.rotate`. The first request queues the operation and performs nothing,
  answering 202 with the problem type `approval-required`. A different
  administrator approves it; self-approval is refused in the same transaction
  as the state change. The original requester then repeats the identical request
  with the header `X-Approval-Id`, and only that redemption runs the operation.
  An approval is bound to the operation, the requester and the payload, expires
  after `features.approval_ttl`, and is spent exactly once by a conditional
  update made before the operation runs. See
  [ADR 0013](docs/adr/0013-approvals-are-redeemed-not-executed.md).
- **API key scopes**: `subjects`, `webauthn`, `totp`, `recovery` and `health`,
  one per public route family, enforced where each route is mounted. An unknown
  scope is refused with 400 when the key is minted. An empty list means
  unrestricted, and the minting response carries `unrestricted` so that the
  choice is visible. A key that calls outside its scopes gets 403 and the
  attempt is audited.
- **Revoking every authenticator of a subject in one call.**
  `POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` revokes all
  WebAuthn credentials and the TOTP secret in one transaction, requires a
  reason, leaves the recovery codes alone and reports how many remain.
- **A keyring rewrap route.** `POST /admin/v1/kek/rewrap` moves every sealed
  record onto the current key version and reports `versions_in_use`, which is
  what tells an operator that an older version can be deleted from the keyring
  file. It completes the rotation that `n0passtemps-wizard kek rotate` starts.
- **A hash-chained audit log**. Every security-relevant event, with a SHA-256
  chain committing each entry to its predecessor, a verification route that
  reports the first entry that does not reproduce its hash, and append-only
  guards in both engines. Erasure and retention are the two narrow, attested
  exceptions, each of which records itself.
- **Rate limiting on three dimensions at once**, per subject, per source network
  and per API key, plus a per-administrator revocation burst. The per-key
  request volume, `throttle.max_requests_per_key`, is metered by a middleware on
  every public route, not only on those that record an authentication outcome.
  Buckets are keyed
  by a digest of a domain-separated, length-prefixed tuple, so a caller cannot
  choose which bucket their failures land in. IPv6 sources are bucketed by
  `/64`.
- **Ten alert types**, deduplicated by fingerprint so that a brute-force attempt
  produces one row with a rising occurrence count. Each is logged at the level
  its severity deserves, so a deployment that ships logs but does not query the
  table still sees the critical ones.
- **Two health reports.** An unauthenticated liveness probe carrying a single
  field, and an authenticated report carrying the version, the storage engine
  and its latency, the keyring state and rotation status, the TLS certificate
  expiry, the audit chain head, the open alert counts and the active feature
  set.
- **GDPR Article 15 and Article 17 support.** An audited reveal of the
  application's subject reference, and a two-phase erasure that blocks a subject
  immediately and purges after a configurable retention window, while leaving
  the audit chain verifiable. Cancelling an erasure inside the window restores
  the subject, who can authenticate again at once.
- **Both storage engines.** SQLite, with a two-pool arrangement and
  `BEGIN IMMEDIATE` write transactions; PostgreSQL, with one pool and an
  advisory lock on the audit append. Identical schema, asserted in CI by
  `make migrate-check`.
- **A server-rendered administration interface**, with its templates and assets
  embedded in the binary, servable at `/admin` behind the network allow list, or
  disabled entirely.
- **PostgreSQL DSN validation that parses the DSN.** Both the URL form and the
  `key=value` form are read. A DSN with no `sslmode` is refused, `prefer` and
  `allow` are always refused, and `sslmode=disable` is accepted towards loopback,
  a Unix socket directory or an empty host. Towards any other host it needs the
  explicit `database.allow_plaintext`, because the validator cannot see network
  topology and the operator has to say that the link is private.
- **Strict configuration validation.** Defaults, then a TOML file with unknown
  keys refused, then the environment. Every problem is reported at once rather
  than one per restart, and each refusal explains itself.
- **Two binaries.** `n0passtemps-server`, with `-config`, `-check-config`,
  `-migrate`, `-bootstrap-admin`, `-admins`, `-force` and `-version`; and
  `n0passtemps-wizard`, which generates the keyring, the Ed25519 signing key and the subject pepper, writes a
  configuration, rotates and inspects a keyring, and validates a configuration
  file. Nothing the wizard does is required: every file it writes can be written
  by hand.
- **Bootstrap administrators, created by an explicit command.**
  `n0passtemps-server -config <path> -bootstrap-admin` is a one-shot run of the
  binary that mints the first administrative tokens, prints each once to the
  operator's terminal and exits. `-admins N`, from 1 to 5, creates the initial
  quorum: with dual approval on, one administrator cannot mint a second through
  the API, and the API carries no exemption for a sole administrator, because a
  rogue administrator could reach one by revoking the others. The command
  refuses when a usable full administrator exists, unless `-force` is passed by
  an operator who has lost every token or has to complete a quorum. The running
  service never prints a token: with no administrator it logs a warning that
  names the command, with `-admins 2` when dual approval is on. With compose the
  command is `docker compose run --rm n0passtemps -bootstrap-admin -admins 2`.
  The tenant named by `tenant.id` is provisioned at every start. See
  [ADR 0014](docs/adr/0014-bootstrap-by-explicit-command.md).
- **An in-process janitor**, running every `features.janitor_interval`. Five
  sweeps: abandoned WebAuthn challenges, stale throttle buckets, undecided
  approval requests, erasure requests past their retention window, and audit
  entries past `audit.retention_days`. Each sweep is independent, so a failure
  in one does not stop the others, and each is idempotent, so a multi-replica
  deployment repeating them is wasteful rather than harmful. The same pass
  raises the `kek.rotation_overdue` alert when `features.kek_rotation_reminder`
  is on and the current key version is older than `kek.rotation_interval`.
- **Four deployment forms**, in `deploy/`: a single container with SQLite,
  compose with PostgreSQL, a hardened systemd unit, and Kubernetes manifests
  with a restricted Pod Security profile and a default-deny NetworkPolicy. Every
  form passes every secret: the subject pepper comes from `.env`, the systemd
  environment file or the Kubernetes Secret, and the signing key sits beside the
  keyring under `/etc/n0passtemps/kek`. The image owns that directory as uid
  65532 and ships the wizard, so a fresh named volume is populated with
  `docker run --entrypoint /usr/local/bin/n0passtemps-wizard` and no root
  helper. The `config.toml` bind mount is relabelled for SELinux hosts. The two
  compose files and the Kubernetes ConfigMap set `server.allow_plaintext`, the
  explicit acknowledgement that the container binds every interface while
  something outside the process constrains who can reach the port, and the
  PostgreSQL compose file sets `database.allow_plaintext` for its private bridge
  network. A test in
  `internal/config` fails when a file in `deploy/`, `config/`, `examples/`,
  `.github/` or the `Makefile` names a prefixed variable that nothing reads.
- **The documentation set** listed in the README, including fourteen architecture
  decision records.

### Security

- **Every route on both surfaces requires a credential.** The only exceptions
  are the liveness probe and the JWK Set, both listed explicitly in the router
  so that a third is a visible decision. An unauthenticated registration route
  would let anyone enrol an authenticator against any subject and then assert as
  them, which is a complete authentication bypass and the condition OWASP API
  Security Top 10 2023 records as API2:2023.
- **The relying party identifier and the origin list are server configuration**
  and are never read from a request. A caller able to nominate either could
  declare its own origin, and the binding that makes WebAuthn resistant to
  phishing would prove nothing.
- **Envelope encryption for the material that genuinely needs it.** AES-256-GCM
  under a per-record data key, wrapped under a versioned key encryption key,
  with the record header as additional authenticated data so that a KEK version
  and a wrapped key cannot be swapped between records. Rewrapping a record keeps
  its data key and always opens and authenticates the payload, even for a record
  already on the current version, so a rewrap error is a reliable integrity
  report. Key versions in the
  keyring are canonical decimal starting at 1: `"01"` and `"0"` are refused.
- **The keyring is refused if it lives in the data directory**, with symbolic
  links resolved on both sides, and refused if its mode grants anything to group
  or other. A key stored beside the ciphertext it protects gives no
  confidentiality once the volume is copied. It is never generated implicitly at
  startup.
- **Recovery codes are hashed, not encrypted**, so losing the keyring does not
  destroy the codes that exist to be used when other things have gone wrong, and
  a stolen database yields no usable code even to an attacker who holds the
  keyring.
- **WebAuthn public keys are stored in clear**, so losing the keyring does not
  destroy enrolments that were never secret. The cost of a lost keyring is
  therefore the TOTP secrets and the readable subject references, and nothing
  else.
- **Subject references are pseudonymised at rest**: an HMAC-SHA256 under a
  server-held pepper for lookup, and an envelope-encrypted copy for disclosure.
  The pepper is a separate secret from the keyring, so the key able to decrypt
  secrets is not also the key able to confirm whether a given person has an
  account. There is no substring search, because the encryption exists precisely
  to make scanning impossible. The pepper's encoding is never guessed: a `hex:`,
  `base64:` or `raw:` prefix names it, unprefixed hexadecimal and unprefixed
  base64 of at least 32 bytes are accepted, and anything else is refused.
- **Bearer credentials carry 160 bits of verifier entropy**, are shown once, and
  are stored as a selector plus a SHA-256 digest bound to the credential kind
  and the selector, so a stored digest cannot be moved between rows or between
  the two tables. Verification is one indexed lookup and a constant-time
  comparison.
- **Uniform refusals.** Every credential failure returns one response and every
  ceremony failure returns another, with no detail, so a caller cannot
  distinguish an unknown selector from a wrong verifier, or an expired challenge
  from a bad signature from a subject that does not exist. The real reason is
  logged and audited. A credential-store outage is not a refusal: it answers 503
  with the problem type `unavailable` and is not audited as a rejected
  credential.
- **No administrative token in a log stream.** A log is shipped and retained by
  systems with looser access rules than a credential store, so the long-running
  service never writes a token; only the one-shot bootstrap command does, to the
  terminal of the operator who ran it.
- **Replay is closed at the store, not by convention.** The challenge
  consumption, the TOTP timestep advance, the signature counter advance and the
  recovery code consumption are each a single conditional statement, so two
  concurrent attempts have exactly one winner.
- **A forwarded client address is honoured only from a configured proxy
  network.** Trusting `X-Forwarded-For` from any source would let a caller
  choose the address that rate limiting and audit entries key on, turning both
  controls off.
- **Security headers on every response**, including error responses: a
  restrictive Content-Security-Policy, `nosniff`, `frame-ancestors 'none'`,
  `no-referrer`, and HSTS only over a request that actually arrived on TLS.
- **Secrets are carried as `[]byte` and overwritten when done**, through a
  helper the optimiser cannot eliminate. The limits of that are documented
  rather than implied. In logs, a value wrapped in `logging.Secret` is redacted
  wherever it appears, including inside a struct.
- **Six direct dependencies**, each argued for, with the JWS assembled by hand
  rather than taken from a JWT library, and no Node.js in the build or in CI.
  Every GitHub Action is pinned to a commit SHA and every tool version is pinned
  in the `Makefile`.
- **A supported CI security gate**: `gosec`, `govulncheck`, `gitleaks` over the
  working tree and the history, CodeQL, Trivy and dependency review, on every
  push and weekly on a schedule.

### Notes

- **The implementation deviates from the original specification on eleven
  points.** `cdc-n0passtemps-v3-complet.html` at the repository root is that
  specification, and it remains in the repository because it is useful for the
  product framing. Where it disagrees with the code, the code is authoritative.
  Each deviation is recorded, with its context, its decision and its costs, in
  [docs/adr](docs/adr/README.md): records 0002 to 0012. A reader comparing the
  two documents should start there, so that a considered decision is not
  mistaken for drift. Records 0013 and 0014 cover two questions the
  specification leaves open: how an approved operation comes to run, and where
  the first administrative token comes from.

  In brief: the public API surface is authenticated rather than anonymous
  (0002); the relying party is this service and its identifier is server
  configuration (0003); a completed ceremony returns a signed assertion rather
  than a bare 200 (0004); recovery codes are hashed rather than sealed (0005);
  WebAuthn public keys are stored in clear rather than sealed (0006); the audit
  log is hash-chained rather than protected by triggers alone (0007); the health
  endpoint is split by audience (0008); a keyring inside the data directory is
  refused rather than warned about (0009); revocation is final rather than
  reversible for 24 hours (0010); HOTP is not offered (0011); and the
  administration interface is server-rendered rather than a React
  single-page application (0012).

- **The audit chain is tamper-evident, not tamper-proof.** An operator holding
  the database file can rewrite it consistently, and detecting that needs a
  witness outside their control. Shipping the chain head to an append-only
  external sink is not in this release.
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) states this and the other
  accepted limits plainly.

- **Multi-tenancy is prepared but not offered.** Every table carries a tenant
  identifier and every query filters on it, so the schema and the access paths
  are ready. The tenant is read from configuration rather than from the caller's
  credential, so one deployment serves one tenant. The check that refuses a
  credential from another tenant exists so that a database carried over from
  another deployment fails loudly, not as a multi-tenancy control.

- **An API key minted without scopes is unrestricted.** That is the default, so
  a deployment that never names scopes has keys that reach every `/v1` route.
  The minting response says `"unrestricted": true`; nothing refuses it.

- **A redeemed approval is spent before the operation runs.** If the operation
  then fails, the approval is gone and a new request and a new approval are
  needed. Nothing executes at approval time, so an approved operation whose
  requester never returns expires unperformed. For `admin_token.create` the
  approval is bound to the name and the role, not to `expires_in_days`.

- **A keyring rotation has three steps, and the middle one is a restart.**
  `n0passtemps-wizard kek rotate` adds a version to the file; the service reads
  the keyring once, at startup, so it has to be restarted before
  `POST /admin/v1/kek/rewrap` can target the new version. An older version may
  be deleted from the file only when the response shows `versions_in_use`
  holding the current version alone and `failed` at zero.

- **The metadata BLOB is only as fresh as the operator keeps it.** A model
  certified after the file was downloaded is unknown, and refused when
  attestation is required. A model compromised after the download is still
  trusted. The service never fetches the file.

- **Migrations are forward-only.** There is no down migration. A rollback across
  a schema change means restoring the database, and an applied migration is
  immutable: the runner records each file's SHA-256 and refuses to proceed if an
  already applied version hashes differently.

- **The 60 second assertion lifetime is unforgiving on hosts whose clocks
  drift**, which is common on unmanaged on-premise machines without NTP. The
  failure looks like a signature problem rather than a clock problem. The same
  exposure applies to TOTP, where the default tolerance is one period of 30
  seconds either side.

- **Support is GitHub issues and nothing else.** No email address, no chat, no
  call booking. No response time is promised, because one person maintains this
  project.

[Unreleased]: https://github.com/Socold/n0passtemps/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Socold/n0passtemps/releases/tag/v1.0.0
