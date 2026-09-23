# Architecture

What the packages are, why the shape is what it is, and where each secret
lives. This document describes the code in `internal/`; it does not restate the
decisions, which are in [docs/adr](adr/README.md).

## Shape of the whole thing

One process, one static binary, no sidecars, no message broker, no cache. The
service answers HTTP, reads and writes one database, and holds three pieces of
key material in memory. Everything else is derived.

```
                        +-------------------------------+
   integrating          |  n0passtemps-server           |
   application  ------->|                               |
   (holds an API key)   |  net/http listener            |
                        |    |                          |
   operator ----------->|    v                          |
   (admin token or      |  middleware chain             |
    browser session)    |    RequestID                  |
                        |    Recover                    |
                        |    SourceIP                   |
                        |    RequestLog                 |
                        |    SecurityHeaders            |
                        |    BodyLimit                  |
                        |    |                          |
                        |    v                          |
                        |  ServeMux (internal/api)      |
                        |    /v1        + API key       |
                        |    /admin/v1  + admin token   |
                        |    /admin     + session       |
                        |    |                          |
                        |    v                          |
                        |  services                     |
                        |    subject   webauthn   totp  |
                        |    assertion recovery  rbac   |
                        |    throttle  alerts    audit  |
                        |    health                     |
                        |    |                          |
                        |    v                          |
                        |  store.Store (interface)      |
                        |    sqlite/  or  postgres/     |
                        +----|--------------------|-----+
                             |                    |
                             v                    v
                      SQLite file          PostgreSQL cluster
                      (+ WAL, data_dir)
                             ^
                             |  never the same volume
                             |
                      keyring.json (KEK), mode 0600
                      assertion-key.pem, mode 0600
                      subject pepper (environment)
```

## Package layout

| Package | Responsibility | Depends on |
|---|---|---|
| `cmd/n0passtemps-server` | The entrypoint: parses seven flags, loads the configuration, opens the keyring and the store, provisions the tenant, builds every service, starts the janitor and serves. With `-bootstrap-admin` it creates the first administrative tokens, as many as `-admins` says, prints each once and exits without serving; the long-running path never writes a token and only warns when no administrator exists. See [ADR 0014](adr/0014-bootstrap-by-explicit-command.md) | everything |
| `cmd/n0passtemps-wizard` | Generates the keyring, the signing key and the pepper, writes a configuration, and validates one. Nothing it does is required | `config`, `kek`, `assertion` |
| `internal/janitor` | The six periodic sweeps, in process and behind a deployment-wide sweep lock so that several replicas do not each repeat them, and the keyring age check that raises `kek.rotation_overdue` | `config`, `store`, `audit`, `alerts` |
| `internal/admin/ui` | The server-rendered interface, embedded, mounted at `/admin` | `config`, `store`, `audit`, `subject`, `throttle`, `webauthn` |
| `internal/config` | Loads defaults, the TOML file and the environment; validates once at startup | `go-toml/v2` |
| `internal/api` | The HTTP surface: routing, middleware, problem responses, both handler sets | everything below |
| `internal/rbac` | Decides what an administrative role may do | `internal/store` |
| `internal/subject` | Resolves an application's user reference into a subject record | `envelope`, `store` |
| `internal/webauthn` | Drives the two ceremonies against the store, and loads the FIDO metadata BLOB from disk when `webauthn.metadata_path` is set. Tested end to end against a software authenticator | `go-webauthn/webauthn`, `config`, `store` |
| `internal/totp` | RFC 6238 code generation and verification. Holds no state | `zeroize` |
| `internal/assertion` | Issues and verifies the signed ceremony result; publishes the JWK Set | `zeroize` |
| `internal/audit` | The hash chain, the event vocabulary and the recorder | `store` |
| `internal/auditsink` | Delivers the hash-covered part of each entry to an append-only destination outside the operator's control. The only package that makes an outbound connection, and it exists only when `audit.sink.endpoint` is set | `config`, `store`, `audit`, `version` |
| `internal/alerts` | Turns thirteen detected conditions into rows an operator can act on | `store` |
| `internal/throttle` | Evaluates and records the rate limits | `config`, `store` |
| `internal/health` | Builds the two health reports | `config`, `store`, `version` |
| `internal/logging` | Configures structured output and enforces redaction | `config` |
| `internal/crypto/envelope` | Authenticated envelope encryption for secrets at rest | `zeroize` |
| `internal/crypto/kek` | Supplies key encryption keys from a file or a variable | `zeroize` |
| `internal/crypto/recovery` | Generates and verifies single-use recovery codes | `x/crypto/argon2`, `zeroize` |
| `internal/crypto/token` | Mints and verifies the bearer credentials of both surfaces | `zeroize` |
| `internal/crypto/zeroize` | Overwrites sensitive byte slices | standard library |
| `internal/store` | The persistence contract, its models and its sentinel errors | standard library |
| `internal/store/sqlite` | SQLite implementation | `modernc.org/sqlite` |
| `internal/store/postgres` | PostgreSQL implementation | `jackc/pgx/v5` |
| `internal/store/migrations` | Embeds the schema and splits it into statements | standard library |
| `internal/version` | Build metadata injected at link time | standard library |

### Why it is shaped this way

**The store is an interface, and both implementations are hidden behind it.**
Any behaviour that differs between the engines, how a compare-and-swap is
expressed or how a busy database is retried, is resolved inside the
implementation rather than surfaced to callers. One difference cannot be hidden
and is documented in `store.Store`: PostgreSQL stores JSON as JSONB, which is a
decomposed representation, so `AuditEntry.Detail`, `Alert.Detail` and
`ApprovalRequest.Payload` are semantically stable but not byte stable. Compare
them as documents, never as strings. The audit chain is unaffected because the
PostgreSQL implementation canonicalises a document through the server before
hashing it, so the hash covers what is actually stored. A chain is valid within
the database that produced it; moving a database between engines means
rebuilding it.

**Cryptography is four small packages, not one.** `envelope`, `kek`, `recovery`
and `token` exist separately because they answer different questions and the
answers are different constructions. Envelope encryption is for material the
server must read back. Argon2id hashing is for a secret a person typed.
SHA-256 over a domain separator is for a high-entropy secret the service minted
itself. Putting them in one package would invite the assumption that one
construction fits all three, which is the mistake the original specification
made twice; see [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md)
and [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md).

**`rbac` depends on `store` and nothing else.** It needs the `Role` type and no
HTTP, no configuration struct and no logger. That keeps the authorisation
decision testable as a pure function, which is what `Authorise` is.

**`totp` and `assertion` hold no state and no store handle.** Anti-replay for
TOTP is the caller's responsibility: the store persists the highest timestep
spent and hands it to `Verify`. Keeping the algorithm free of persistence is
what makes the verification path exhaustively testable.

**`api` is the only package that imports everything else.** Dependencies point
inwards. A handler can reach the store, but no store, no crypto package and no
service reaches back into `api`, so there is no way for a persistence change to
alter an HTTP contract by accident.

**Nothing in the request path calls `time.Now` directly.** Clocks are injected
into `api.Deps`, `webauthn.New`, `throttle.New`, `alerts.New`, `health.New`,
`audit.NewRecorder` and `subject.New`. Tests are then deterministic without
sleeping, which is what makes a lockout window or a challenge expiry testable at
all.

## The request path

Reading outwards in, the outer chain in `internal/api/router.go` is:

| Order | Middleware | Why it is where it is |
|---|---|---|
| 1 | `RequestID` | Assigns the identifier everything else references. A client-supplied `X-Request-Id` is accepted so a trace can span the calling application and this service, but it is capped at 64 characters and filtered to `[A-Za-z0-9._-]`, because the value reaches log lines and audit entries where a newline could forge an entry and a terminal escape could rewrite what an operator sees. |
| 2 | `Recover` | Inside `RequestID` so a panic is logged with its identifier, outside everything else so a panic anywhere below is caught. `http.ErrAbortHandler` is re-panicked: that is a client disconnecting mid-write, not a fault, and there is nobody left to answer. |
| 3 | `SourceIP` | Resolves the client address once, before anything keys on it. A forwarded header is honoured only when the immediate peer is inside `server.trusted_proxy_cidrs`. |
| 4 | `RequestLog` | Attaches the request-scoped logger and emits one line per request with the matched route pattern rather than the concrete path. |
| 5 | `SecurityHeaders` | Applied to every response, including error responses, so the header cannot be forgotten on the one route that needed it. |
| 6 | `BodyLimit` | Caps the body through `http.MaxBytesReader` before any handler reads it, so an oversized body is refused without being buffered. |

Then the mux dispatches into one of three groups.

**`/v1`, the public surface**, wrapped in `CORS`, `RequireAPIKey`,
`RequireScope`, `MeterAPIKey`, `RequireJSON`, `NoStore`. Each route names its
scope where it is mounted, for the same reason administrative routes name their
permission there. A key outside its scope is refused with 403 and an audit
entry, before it is metered. `MeterAPIKey` counts every request against
`throttle.max_requests_per_key` in one place; counting inside the handlers that
record an authentication outcome would leave the other routes unmetered. A
limiter that cannot reach its state lets the request through and logs a warning,
so a degraded database does not become an outage.

The API key is parsed structurally first, so
malformed input is refused without a query; the selector then drives a single
indexed lookup and the verifier is compared in constant time. Every failure
returns the same error, because distinguishing an unknown selector from a wrong
verifier would let a caller enumerate valid selectors. A lookup that fails
because the store is unreachable is not a credential failure: it answers 503
`unavailable` on both surfaces and is not audited as a rejection.

**`/admin/v1`, the administrative API**, wrapped in `IPAllowList`,
`RequireAdmin`, `RequirePermission`, `RequireJSON`, `NoStore`. The allow list
runs before authentication on purpose: a caller outside it cannot even present
a token for verification, which keeps the token-guessing surface off the public
internet. It answers 404 rather than 403, so a caller outside the list does not
learn that an administrative surface exists here.

Four administrative operations pass through `approvalGate` before they act:
erasure, administrative token creation, revoke-all and the keyring rewrap. With
dual approval on, the first call queues and performs nothing, and the original
requester later repeats the identical request with the `X-Approval-Id` header.
The gate sits inside the ordinary handler, so there is no second executor with
its own checks. See
[ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md).

**`/admin`, the interface**, wrapped in `IPAllowList` and `NoStore` only. It
authenticates through its own session cookie rather than a bearer token, so it
is mounted with the network control and outside the token middleware. It is an
`http.Handler` supplied as `api.Deps.AdminUI`, which is what keeps
`internal/admin/ui` out of `internal/api`'s import graph: `api` holds `ui` as a
dependency, so the reverse import would be a cycle. When
`admin.ui_enabled` is false the handler is nil and the routes are never
registered at all, so a disabled interface presents no surface to probe.

Two routes carry no credential at all, and both are listed explicitly in
`mountUnauthenticated` so that adding a third is a visible decision:
`GET /v1/health`, which a load balancer has to be able to ask without holding a
key, and the JWK Set, which an integrating application has to fetch in order to
verify an assertion offline. See [ADR 0008, Split the health
endpoint](adr/0008-split-the-health-endpoint.md).

Inside a handler the sequence is fixed:

1. `requireCaller` fetches the identity the route was mounted behind. A missing
   caller means the route was mounted without authentication, which is treated
   as a refusal rather than a panic so a misrouted request cannot take the
   process down.
2. `callerTenant` refuses a credential issued for a different tenant. In a
   single-tenant deployment the two always agree; the check exists so that a
   database carried over from another deployment fails loudly instead of
   operating on rows it does not own.
3. The body is decoded with `DisallowUnknownFields`, and a second JSON document
   in the same body is refused.
4. The subject is resolved. An unknown subject and an inactive one produce the
   same refusal as a failed ceremony, so no endpoint can be used to test whether
   a given person has an account.
5. The throttle is consulted before any expensive work, so a locked-out caller
   does not get an Argon2id evaluation or a signature verification for free.
6. The work happens.
7. The attempt is recorded against the limiter and an audit entry is appended.

Handlers return an error rather than writing a response. That way the status
code, the logged message and the audit outcome are decided in one place instead
of drifting apart across handlers, and anything that is not an `*api.APIError`
becomes a bare 500, so a new handler cannot accidentally leak error text.

Error bodies follow RFC 9457 with a URN `type`, a fixed `title` per class, and
`detail` present only where disclosure is safe, which in practice means input
validation. The real reason is logged and audited. A ceremony failure always
returns the same body: a caller learns that authentication did not succeed,
which is all it needs, and cannot tell a wrong signature from an expired
challenge from an unknown credential.

## Where the external audit sink sits

Step 7 above is where `internal/auditsink` attaches, and it attaches after the
append rather than around it. `audit.Recorder` appends the entry, the store
returns it with its sequence number and its chain hashes filled in, and only
then is it offered to the sink. An entry that never committed is never offered,
and an offer that fails changes nothing about an entry that did.

`Offer` is a non-blocking send onto a bounded queue. It returns nothing, it can
fail at nothing, and it is the only part of the sink that any request path
touches. Everything else happens on one background goroutine, started from
`main` beside the janitor and stopped the same way, which makes one last
delivery attempt as the process shuts down.

The queue is a latency optimisation and not the buffer. The buffer is the audit
log: it is ordered by sequence number, the receiver acknowledges up to a
sequence number, and a file in the data directory records that number. So
whenever the queue overflows, an offer arrives out of order, a POST fails or the
process restarts, the shipper stops trusting the queue and reads from the log
one past the watermark instead. A full buffer costs latency and a database read;
it cannot cost the witness an entry.

What travels is narrower than the entry. The chain hash covers a salted digest
of the three personal fields rather than the fields themselves, which is what
makes erasure possible, and it is that digest which is delivered. `subject_id`,
`source_ip` and `detail` are not sent at all, and neither is the salt. The
result is exactly the hash input, which is exactly enough for a receiver to
recompute every hash and detect a gap, and not enough to tell which person an
entry concerns. See [ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md).

This is the only outbound connection the service makes, and the only one it can
make. With `audit.sink.endpoint` unset no shipper exists, so there is no idle
client and no timer.

## Storage

### The two-pool SQLite arrangement

SQLite in WAL mode allows many concurrent readers and exactly one writer. A
single `database/sql` pool of several connections therefore produces
`SQLITE_BUSY` under write contention, which surfaces as intermittent failures
that are hard to reproduce.

`internal/store/sqlite` opens two pools instead:

| Pool | Connections | Used for |
|---|---|---|
| read | `database.max_open_conns`, default 8 | every `SELECT` |
| write | exactly 1, never expired | every statement that writes, and every transaction |

Writes queue in Go rather than colliding in SQLite, so a busy error becomes a
short wait instead of an error the caller has to retry. The single write
connection is the serialisation point, which is also what makes the
compare-and-swap operations the schema relies on genuinely atomic.

Three further SQLite-specific decisions:

- Every write transaction is opened with `BEGIN IMMEDIATE`, set through the DSN
  as `_txlock=immediate`. The default deferred transaction takes its write lock
  at the first write statement, so a read-then-write sequence can have its
  premise invalidated in between and fail at commit with
  `SQLITE_BUSY_SNAPSHOT`. Taking the lock up front is what makes the TOTP
  replay counter and the audit chain head correct under concurrency.
- Pragmas are set in the DSN, not with an `Exec` after connecting, because
  `database/sql` may open a new connection at any time and a pragma set on one
  connection does not apply to the others. The set is `foreign_keys(1)`,
  `journal_mode(WAL)`, `synchronous(NORMAL)`, `busy_timeout`,
  `temp_store(MEMORY)` and `trusted_schema(0)`. `Open` then reads
  `foreign_keys` and `journal_mode` back on both pools and refuses to start if
  either did not take effect, because a pragma the driver does not recognise is
  ignored silently and a typo would otherwise mean foreign keys are off in
  production.
- Instants are stored as fixed-width RFC 3339 in UTC with nine fractional
  digits. `time.RFC3339Nano` removes trailing zeros, which would break the
  lexicographic ordering that every `ORDER BY` and every range index on these
  columns depends on. Several layouts are accepted on read, so a database
  touched with the `sqlite3` shell still loads.

### Why PostgreSQL needs none of it

PostgreSQL has real multi-version concurrency control. Writers to different rows
do not block each other, and writers to the same row take a row lock for the
duration of the statement rather than locking the database. Serialising every
write through one connection would throw away the engine's concurrency without
buying any safety, so `internal/store/postgres` uses one `pgxpool.Pool` for
reads and writes alike.

The compare-and-swap operations need no surrounding transaction either. A single
conditional `UPDATE ... WHERE <expected value>` locks the row it matches for the
rest of the statement, and a concurrent update of the same row waits and then
re-evaluates its own `WHERE` clause against the committed result. Under READ
COMMITTED that is already exactly-once: the second writer finds the expected
value gone and matches nothing. So `ConsumeTOTPStep`, `AdvanceSignCount`,
`ConsumeRecoveryCode`, `ConsumeChallenge` and `DecideApproval` each stay one
statement.

The audit append is the one operation that needs more, because it reads the
chain head and then inserts an entry committing to it, and two concurrent
appends under READ COMMITTED can both read the same head. That is resolved with
an advisory lock.

The janitor's sweep lock is the one other advisory lock, and it is a different
kind: session level rather than transaction level, and tried rather than waited
for. A pass is not one statement but six independent deletes that must be able
to fail one at a time, so it cannot live in a transaction, and a replica that
does not get the lock wants to skip its pass rather than queue behind somebody
else's. On SQLite the same coordination is a lease row with an expiry, because
that engine has no advisory locks and a dead holder must not keep the lock.

Timestamps are native `TIMESTAMPTZ`, normalised to UTC on read. PostgreSQL
stores them as a count of microseconds, so `audit.Prepare` truncates to
microseconds before hashing, in one shared place rather than in one backend, and
the hashed value therefore does not depend on which engine stores it.

### The schema

Two migrations per engine, embedded in the binary by
`internal/store/migrations`, applied in order, each in its own transaction, each
recorded with the SHA-256 of its file. A later run that finds a different
checksum for an already applied version stops:

```
sqlite: migration 0001_initial was applied with checksum <a> but the embedded
file now hashes to <b>; the database and this binary disagree about the schema
```

Each file is split into statements by `migrations.Split`, a small state machine
that recognises line and block comments, string literals, quoted identifiers,
dollar quotes, and the `BEGIN ... END` and `CASE ... END` blocks of a SQLite
trigger body, so a semicolon or an `END` inside a `CASE` expression does not
close the trigger early. An unterminated quote or block comment is reported as
an error with its offset; left alone it would swallow every statement after it.

`0001_initial` carries tenants, subjects, WebAuthn credentials, TOTP secrets,
recovery codes, WebAuthn challenges, the audit log with its two trigger guards
and its retention checkpoints, API keys, administrative tokens and the throttle
buckets. `0002_governance` carries alerts, the approval queue and erasure
requests. Both governance tables exist in every deployment; the features that
write to them are gated by configuration, not by schema, so switching from lite
to complete never requires a migration.

SQLite tables are `STRICT`, which raises the minimum engine version to 3.37 and
stops a column declared `INTEGER` from silently accepting a string.

`make migrate-check` compares the tables and indexes the two engines declare and
fails if either declares a schema object the other does not. It runs in CI.

## Where each secret lives

| Secret | Where it is | What protects it | What its loss costs |
|---|---|---|---|
| Key encryption keyring | A JSON file at `kek.path`, or the variable named by `kek.env_var` | File mode 0600 enforced at load; refused if it resolves inside a data directory; the `env` provider unsets the variable once parsed | The TOTP secrets and the readable form of every subject reference. Nothing else. See [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md) and [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) |
| Subject pepper | The variable named by `subject.pepper_env` | At least 32 bytes required; the variable is unset once read; zeroized on `Service.Close` | Every existing subject becomes unfindable, because the lookup key cannot be re-derived |
| Assertion signing key | An Ed25519 PKCS#8 PEM at `assertion.signing_key_path` | File mode 0600 enforced at load; exactly one PEM block, no trailing data | Nothing stored, but every previously issued assertion stops verifying and a new key must be published in the JWK Set |
| Data encryption keys | Only ever inside a sealed record, wrapped under a KEK version | AES-256-GCM, with the record header as additional authenticated data | Not applicable: they exist only in ciphertext |
| API keys and administrative tokens | Selector in clear and indexed; verifier as a SHA-256 digest over a domain separator, the kind, the selector and the verifier | Shown once at creation and never recoverable; constant-time comparison; the digest is bound to the kind and the selector so it cannot be moved between rows or between tables | Nothing recoverable from the database; the credential must be reminted |
| Recovery codes | Selector in clear and indexed; verifier as an Argon2id PHC string | 70 bits of verifier entropy; `m=19456` KiB, `t=2`, `p=1`; constant-time comparison | Nothing: hashes are not reversible, and a lost sheet means a fresh batch |
| TOTP secrets | `totp_secrets.secret_sealed`, envelope-encrypted | AES-256-GCM under a per-record data key, wrapped under the KEK | The secret is unrecoverable and the user re-enrols |
| Subject reference | `subjects.ref_hmac` for lookup, `subjects.ref_sealed` for disclosure | HMAC-SHA256 under the pepper; the sealed copy under the KEK | The readable form, which costs the Article 15 access path and the administration interface's ability to name a person |
| External audit sink credential | The variable named by `audit.sink.token_env`, only when a sink is configured | The variable is unset once read; never logged, never in an alert row, never in the health report | Nothing stored. Delivery stops being accepted until the receiver issues a new credential, which raises `audit.sink_failing` |

The envelope format is versioned and self-describing: a one-byte format
version, a big-endian KEK version, the DEK-wrapping nonce, the wrapped DEK, the
payload nonce, then the payload. The header is additional authenticated data for
both `Seal` calls, so the KEK version and the wrapped DEK cannot be swapped
between records. `Rewrap` re-seals the DEK under the current KEK and keeps the
DEK itself. Because the header is authenticated data of the payload and the
header changes, the payload is opened and sealed again under the same DEK. It is
opened even when the record is already on the current version: a rotation pass
reads the error from `Rewrap` as its integrity report, and a path that returned
early without authenticating would report a corrupted row as rotated.
`Sealer.CurrentVersion` tells a caller which version a rewrap will target.
`POST /admin/v1/kek/rewrap` drives the pass over `totp_secrets.secret_sealed` and
`subjects.ref_sealed`, a page of 200 at a time, and writes each record back with
a compare-and-swap on the old sealed value, so a record resealed by another
request in the meantime is left alone.

Key versions in the keyring are canonical decimal starting at 1. `"01"` and
`"0"` are refused at load.

`zeroize.Bytes` overwrites a slice and then reads it back through a
constant-time comparison so the optimiser cannot remove the write. It is
best-effort and the package says so: the Go runtime may copy a slice during
garbage collection or stack growth, and the operating system may page it before
the overwrite happens. Go strings are immutable, so secrets are carried as
`[]byte` from the moment they are read. A deployment that needs a hard guarantee
needs an HSM or an external KMS, which this service does not provide.

## Dependency policy

Six direct dependencies, and each one earns its place:

| Module | Why it is not written here |
|---|---|
| `github.com/go-webauthn/webauthn` | The CBOR parsing, COSE key handling and attestation format coverage of W3C WebAuthn Level 2. Reimplementing it would be a larger and less reviewed attack surface than importing it. |
| `github.com/jackc/pgx/v5` | The PostgreSQL wire protocol. |
| `modernc.org/sqlite` | A pure-Go SQLite. It is what makes `CGO_ENABLED=0` possible, and therefore what makes the binary static and the distroless base runnable. |
| `github.com/pelletier/go-toml/v2` | TOML with strict unknown-field rejection. |
| `golang.org/x/crypto` | Argon2id. |
| `github.com/google/uuid` | Identifier generation. |

Everything else is the standard library. The JWS is assembled and parsed by
hand in `internal/assertion` rather than through a JWT library: the format is a
few dozen lines, and the recurring vulnerabilities of those libraries have all
been on the parsing side, honouring the `none` algorithm, letting the token
choose which verification routine runs, or accepting a public key as an HMAC
secret. The administration interface is `html/template` rather than React; see
[ADR 0012](adr/0012-server-rendered-administration-interface.md).

### Why a transitive dependency is a liability here

An authentication product is the wrong place to hold a large dependency
closure. Three reasons, in order of how likely they are:

1. **The artefact is what protects logins.** A compromised build or runtime
   dependency reaches the binary an operator installs to secure their
   authentication, and it does so without touching any code a reviewer of this
   repository would read.
2. **Every dependency is an advisory queue.** `govulncheck` and Dependabot run
   on this repository, and each addition raises the rate at which a published
   advisory demands a release. A one-person project has a finite budget for that.
3. **A dependency cannot be audited once.** It has to be re-audited at every
   upgrade, and an upgrade that is skipped for long enough becomes an upgrade
   that cannot be taken safely.

The practical rules that follow are in [CONTRIBUTING.md](../CONTRIBUTING.md): a
new direct dependency needs an argument in the pull request, tool versions are
pinned in the `Makefile`, every GitHub Action is pinned to a commit SHA rather
than a tag, and Node.js is absent from the build and from CI entirely.

## Related documents

| Document | What it covers |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Putting this on a host, in a container or in a cluster |
| [CONFIGURATION.md](CONFIGURATION.md) | Every key the loader accepts |
| [WEBAUTHN.md](WEBAUTHN.md) | The ceremony in detail |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What each boundary above is holding back |
| [docs/adr](adr/README.md) | The twelve deliberate deviations from the specification, and three decisions on questions it leaves open |
