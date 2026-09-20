# Security review, September 2026

This is the public record of a white-box security review of n0passtemps carried
out on 2026-09-18 against `v1.1.0` and the development tree that followed it,
together with what was done about each finding.

It is not an independent audit. It was commissioned by the maintainer and run
with automated reviewers, and every finding kept here was checked against the
code by hand before it was believed. It is published so that the next person to
look knows what has been looked at, what was found, and what was not covered.

**Status of the fixes.** Everything listed as fixed is on `main` and is not yet
in a release. `v1.1.0` is still the current release and still carries these
findings. An operator running it should read the table below, decide which
findings reach their deployment, and follow the release that carries the fixes.
Advisories accompany that release, as [SECURITY.md](../../SECURITY.md)
describes.

**What this document deliberately leaves out.** The reproduction steps. Several
of these are straightforward to exploit against a deployment that has not
upgraded, and a public page that makes the sequence easy to copy helps the wrong
reader first. Each entry says what an attacker gains and what they need to
start, which is what an operator needs to judge their own exposure.

## Method

- The project's own gate: `go vet`, `go test -race`, `gosec`, `golangci-lint`,
  `gitleaks` over the working tree and the history, and `govulncheck`. All of it
  passed before the review and after the fixes, which is the point worth making
  about tooling: none of the findings below were things a scanner reports.
- Six manual reviews by area: cryptography and secrets, the public API and its
  middleware, the administrative surface and RBAC, the WebAuthn ceremonies and
  the reference kit, persistence and the audit chain, and configuration,
  deployment and supply chain.
- The documentation was not taken as true. Claims were checked against the code,
  and six of them turned out to be wrong or overstated; they are listed under
  hardening below.

## Limits of this review

- **PostgreSQL and the TPM-sealed keyring were not exercised.** Their test
  suites skip without a database and a simulator, so findings specific to them
  were confirmed by reading only. Both now run in CI, which is itself one of the
  findings: the software TPM was started for tests that then skipped, because
  its environment sat on the wrong step.
- **Not covered at all:** the Node and Python SDKs beyond the address plumbing,
  the curl examples, the systemd unit, the JavaScript of the reference page
  beyond a search, and any load testing. Where a document says an impact is
  memory exhaustion, that is reasoned from the code and was measured only for
  the metrics label.
- A finding not listed here is a finding nobody looked for.

## What held

Checked and found correct: nonce and key handling in the envelope; KEK versions
bound as associated data; assertion verification in the server, the Go SDK and
the examples, with the algorithm pinned, the key identifier equal to the
thumbprint, `crit` refused, and audience, issuer and expiry required; TOTP
replay protection by compare-and-swap; unbiased recovery codes and constant-time
comparison throughout; WebAuthn challenges that are single use and bound to
subject, tenant, ceremony and relying party, and consumed before anything is
parsed; origin and relying party identifier never taken from a request; tenant
isolation on every query; no SQL built from a value; `X-Forwarded-For` honoured
only from a trusted peer, walked from the right; IPv6 bucketed by `/64`; an
administrative console free of XSS, CSRF, open redirects and session fixation;
approvals that cannot be replayed or executed twice; GitHub Actions pinned by
commit with minimal permissions and no `pull_request_target`; a container that
runs unprivileged with a read-only root; and no secret in the tree or in the
history.

## Findings

Severity is this project's own reading of what an attacker gains against what
they need to start, in the terms SECURITY.md asks a reporter to use.

### High

| Finding | What it gave, and what it needed | Fixed in |
|---|---|---|
| The reference sign-in backend, `kits/login`, relayed the subject from the request body on every route and checked its own session on none. It holds an API key, so any visitor held what that key allows: a subject's recovery codes, an enrolled passkey or TOTP secret, and then a session as that subject. Only deployments that copied or ran the kit are affected; the server was never the weak part. | Nothing. Reachable by anyone who could load the page. | [`de08998`](https://github.com/Socold/n0passtemps/commit/de08998) |
| Dual approval could be satisfied by one administrator. An administrator was identified by the identifier of their token, and a self-rotation mints a new one while the old stays valid, so one token could queue an operation, rotate, approve and redeem. Every operation the rule guards was reachable that way. | One valid `admin_full` token, which is the position the rule exists to cover. | [`158d164`](https://github.com/Socold/n0passtemps/commit/158d164) |
| The request method was used as a Prometheus label unchanged, and `net/http` accepts any token as a method, so each invented one created series that live as long as the process. Memory growth with no bound, and a metrics document that stops being usable. | Nothing. In scope by SECURITY.md's own list. | [`2f489a4`](https://github.com/Socold/n0passtemps/commit/2f489a4) |
| The `/v1` routes are called from an application's backend, so the only address the service saw belonged to the caller. Every user of one application shared one per-address budget, and exhausting it refused every ceremony from that application for the lockout duration. | Nothing beyond the application's own sign-in page. | [`155578c`](https://github.com/Socold/n0passtemps/commit/155578c), [`aea2e1d`](https://github.com/Socold/n0passtemps/commit/aea2e1d) |
| Every failure was charged to one budget per subject, so wrong TOTP codes locked that subject out of their passkey and their recovery codes as well. Knowing a subject reference was enough to keep somebody out of their own account indefinitely. | A subject reference. | [`155578c`](https://github.com/Socold/n0passtemps/commit/155578c) |
| An audited action could leave no entry. Events are recorded after the change commits, and a failed append was logged while the request succeeded; closing the connection at that moment, or placing a NUL in a free-text field, which PostgreSQL refuses in JSONB and SQLite accepts, was enough. | An administrative credential for the actions worth hiding. | [`1a485ca`](https://github.com/Socold/n0passtemps/commit/1a485ca) |

### Medium

| Finding | Fixed in |
|---|---|
| The envelope bound a ciphertext to nothing but its own header, so a sealed value opened in any row, column or tenant. Somebody able to write to the database without holding the keyring could place their own TOTP seed on another subject's row, or move another tenant's sealed reference into a subject of their own and read it back. See [ADR 0021](../adr/0021-bind-sealed-records-to-the-row-they-live-in.md). | [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| A console session outlived the token it was made with, for up to the absolute session lifetime, including deciding approval requests under a role its holder no longer had. | [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| `require_attestation` with no metadata BLOB verified no trust chain at all, and the AAGUID an allow list matches on is declared by the client. With a BLOB loaded, the opposite: a key could register and then never sign in again. | [`10f3c84`](https://github.com/Socold/n0passtemps/commit/10f3c84) |
| The administration console's passkey ceremonies accepted any origin the public surface accepted, which is the anti-phishing property a passkey exists for. | [`10f3c84`](https://github.com/Socold/n0passtemps/commit/10f3c84) |
| A subject reference, which applications supply as an email address, reached the request log. The middleware that records metrics handed the multiplexer a copy of the request, so the matched route was lost and the log fell back to the concrete path. This was a regression of an earlier fix, unseen because the test chained one middleware and a deployment has both. | [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| Retention pruning could delete the whole audit log. The bound was the highest sequence number older than the cutoff, and timestamps come from the process clock, so one entry written by a machine with a backwards clock took every recent entry before it, through a checkpoint that still verified. | [`1a485ca`](https://github.com/Socold/n0passtemps/commit/1a485ca) |
| A checkpoint was attested by nothing and an erased entry's personal fields were covered by nothing, so somebody able to write to the database could truncate the chain, or move another subject into an existing entry, with verification still reporting no break and the external witness seeing nothing. | [`1a485ca`](https://github.com/Socold/n0passtemps/commit/1a485ca) |
| The external witness could be silenced by editing one file beside the database, and could not tell a quiet deployment from a severed connection. It also followed redirects, carrying its credential, and a 2xx from the wrong place marked a batch delivered. | [`1a485ca`](https://github.com/Socold/n0passtemps/commit/1a485ca) |
| Unauthenticated requests wrote one audit entry and one alert each, through the single writer SQLite has, against a table retention cannot freely prune. | [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| The rate limiter checked and recorded in two operations with the secret comparison between them, so a parallel burst was evaluated several times over its budget. Argon2id had no concurrency bound on the routes that reach it. | [`155578c`](https://github.com/Socold/n0passtemps/commit/155578c), [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| A token's lifetime was not part of what a second administrator approved, so a request approved as lasting a day could be redeemed for one that never expires. | [`fd20548`](https://github.com/Socold/n0passtemps/commit/fd20548) |
| An erasure whose cancellation landed while the sweep was running purged the restored subject anyway, factors included, under a request marked cancelled. | [`56b3ca0`](https://github.com/Socold/n0passtemps/commit/56b3ca0) |
| The configuration validator accepted a dozen settings that switch a protection off, including a trusted-proxy or administrative allow list wide enough to admit everything, zero timeouts, a typo in the dual-approval operation list, and a lite mode that silently overrode settings named by the environment. | [`4826d68`](https://github.com/Socold/n0passtemps/commit/4826d68) |
| The container image set `server.allow_plaintext` in its own environment, so the refusal to serve cleartext beyond loopback was off in every container before an operator chose anything. The Kubernetes ingress policy named every namespace. | [`ddd0dc4`](https://github.com/Socold/n0passtemps/commit/ddd0dc4) |
| A tag published without any test job running first; the container scans uploaded reports and blocked nothing; the release archives carried a checksum file and no attestation. | [`d7e831c`](https://github.com/Socold/n0passtemps/commit/d7e831c) |

### Low

Twenty-seven lower findings were recorded and all but the ones listed under
*Accepted* below are fixed in the same series. In summary: the keyring was
rewritten in place rather than by rename, so a crash during a rotation could
leave it empty; a rotation quietly repaired the mode of a keyring that had been
world-readable instead of saying so; stored Argon2 parameters were read and
ignored, which would have invalidated every recovery code the day they were
raised; consumed recovery-code selectors were never pruned, so a large tenant
eventually failed to issue a sheet; the SQLite database and its write-ahead log
were left readable by other local accounts when the data directory already
existed; commits could be lost on power failure, un-spending a recovery code or
a TOTP timestep; PostgreSQL transactions inherited whatever isolation the server
was configured with; the janitor lease trusted the caller's clock and two
identical containers could delete each other's; metadata loading reached the
network without a timeout and never checked the BLOB's freshness; an assertion
on a credential revoked mid-ceremony succeeded on one branch; an erasure left
identifiers in the alerts table and in the free text of erasure requests; and
the label a caller gave an authenticator was never stored, so the column an
operator reads to tell one key from another was empty for every credential ever
enrolled.

## Hardening and corrections that came out of it

None of this describes a way in.

- **Six documentation claims were wrong or overstated** and are corrected: the
  count of direct dependencies, where `go mod verify` actually runs, the log
  fingerprint described as an HMAC when it is an unkeyed digest, unsetting an
  environment variable described as removing it from `/proc/self/environ`,
  metadata loading described as never reaching the network, and the scope
  statement about running without TLS.
- **The Windows build was broken** by a transport import, so the release matrix
  would have failed on a target it claims.
- **The software TPM ran in CI for tests that skipped**, because its environment
  was attached to the coverage step rather than the test step. PostgreSQL and
  the TPM now run for real.
- Base images are pinned by digest, Dependabot's group configuration was invalid
  and is fixed, and the threat model gains the attacker most of this was about:
  the anonymous visitor of an application's sign-in page.

## Accepted, and written down rather than fixed

- **The log fingerprint is an unkeyed SHA-256 under a domain separator.**
  Whoever holds the logs can confirm a guessed reference by hashing it. The
  comment now says so. No call site logs a reference today.
- **The shipped Kubernetes manifest does not start as written.** A Secret
  mounted with `fsGroup` arrives at mode 0440 and the server refuses a key
  readable by its group. The manifest documents the limit; solving it properly
  needs an init container or a secrets CSI driver, which has to be tested on a
  real cluster.
- **Rotating an administrative token that holds passkeys is refused** rather
  than carrying them across, which would need a schema change.
- **Two guards remain narrow windows across processes**: the last-administrator
  check and the per-subject credential cap. Closing them means moving the
  condition into the SQL statement, which is written out in a comment
  above each.
- **Records in the older sealed format stay readable** until a rewrap pass
  lifts them. While that path exists, somebody able to write to the database can
  put an old ciphertext back. ADR 0021 says so, and says when to remove it.
- **WebAuthn public keys are stored in clear without a MAC**, by the decision in
  [ADR 0006](../adr/0006-store-webauthn-public-keys-in-clear.md). Somebody able
  to write to the database can still insert an authenticator. Binding sealed
  records does not change that, and saying otherwise would overstate it.

## If you are running v1.1.0

The findings that need no credential are the reference kit, the metrics label,
and the two denial-of-service paths in the rate limiter. The kit is the urgent
one: if you copied `kits/login`, require your own session on the routes that add
or replace a factor and take the subject from that session, whatever else you
do. Everything else needs either a credential you issued or write access to your
database.
