# Contributing

This is an authentication server. A change here reaches the artefact operators
install to protect their logins, so the bar is correctness first and everything
else second. What follows is the bar, stated so it does not have to be
rediscovered in review.

## Build and test

Go 1.27.1 or newer, which is the floor the CI matrix tests against and the
version the `go` directive in `go.mod` implies. No C toolchain is needed: the
SQLite driver is `modernc.org/sqlite`, which is pure Go, so `CGO_ENABLED=0` is
exported by the `Makefile` and every build is static.

```bash
git clone https://github.com/Socold/n0passtemps.git
cd n0passtemps

make build      # bin/n0passtemps-server and bin/n0passtemps-wizard
make test       # go test ./...
make test-race  # the same under the race detector
make cover      # writes coverage.out and prints total statement coverage
```

`make help` lists every target.

The PostgreSQL tests are behind the `integration` build tag, because they need a
live instance:

```bash
docker run --rm -d --name n0pg -p 5432:5432 \
  -e POSTGRES_USER=n0passtemps -e POSTGRES_PASSWORD=n0passtemps \
  -e POSTGRES_DB=n0passtemps_test postgres:16-alpine

make test-integration
```

`TEST_POSTGRES_URL` in the `Makefile` is kept identical to the CI service
container and to `deploy/docker-compose.postgres.yml`, so a failure reproduces
locally. The target exports it as `N0PASSTEMPS_TEST_POSTGRES_DSN`, which is the
variable the suite reads; with that variable unset the PostgreSQL tests skip
rather than fail, so set it yourself when calling `go test -tags=integration`
directly.

## The gate

```bash
make ci
```

That is `fmt-check vet lint migrate-check test-race test-kits cover sec secrets
build`, in the order CI runs it. A pull request that has not passed it locally
will fail on the runner, and the runner is slower than you are.

| Step | Tool | Refuses |
|---|---|---|
| `fmt-check` | `gofmt -s -l` | Any file that is not gofmt-clean |
| `vet` | `go vet` | The standard suspicious constructs |
| `lint` | `golangci-lint`, pinned in the `Makefile` | See below |
| `migrate-check` | A shell diff over the migration files | A table or index declared for one engine and not the other |
| `test-race` | `go test -race ./...` | A data race |
| `cover` | `go test -covermode=atomic` | A total below `COVER_MIN` in the `Makefile` |
| `sec` | `gosec`, `govulncheck` | Any gosec finding that is not answered in place, and known-vulnerable dependencies |
| `secrets` | `gitleaks`, over the working tree **and the history** | A committed token, keyring or credential |
| `build` | `go build` | A compilation failure in a package the tests do not reach |

The linter set is explicit in `.golangci.yml`, with `default: none`, so adding a
linter is a visible decision and a `golangci-lint` upgrade cannot quietly
enable one. `errcheck` runs with `check-type-assertions` and `check-blank`, so
`_ = f()` has to be a deliberate, commented choice. `govet` has `shadow` on,
because a shadowed `err` is the standard way a handled error becomes an
unhandled one. `gocyclo` budgets 35 branches per function and `lll` budgets 120
columns. Both numbers carry their reasoning in `.golangci.yml`, and `gocyclo`'s
in particular is a ratchet one above the largest function in the tree rather
than a round number: read it before raising it.

`make lint` runs all of them and passes. It did not until the style budget in
[docs/ROADMAP.md](docs/ROADMAP.md) was burned down, and while that was happening
the gate ran a subset called `make lint-cleared`. That name survives as an alias
so older scripts keep working; new work should call `make lint`.

Three `gocritic` checks are disabled by name in `.golangci.yml` rather than
satisfied, each with its argument beside it: `sloppyReassign` because it
contradicts `govet`'s `shadow`, and `hugeParam` and `rangeValCopy` because in
this codebase they ask to replace a copy with an alias on the audit and
configuration paths. Disagreeing with one of those is a reasonable pull
request; removing the reasoning without replacing it is not.

Tool versions are pinned in the `Makefile`. If a tool is missing, the recipe
prints the exact `go install` command for the pinned version rather than failing
on an opaque "command not found".

The security workflow, `.github/workflows/security.yml`, runs `gosec`,
`govulncheck`, `gitleaks`, CodeQL, Trivy and dependency review on every push and
weekly on a schedule, because most findings there come from a newly published
advisory rather than from a new commit.

### gosec has to be clean

A clean `gosec` report is the baseline, locally through `make sec` and on the
runner, where the SARIF report is still uploaded to code scanning but a finding
now fails the job. Both invocations pass `-conf .gosec.json`, so a run on a
laptop and a run in CI reach the same verdict.

Every finding is either fixed or answered where it sits, with a
`// #nosec RULE -- reason` naming that rule and saying why this line is not the
thing the rule looks for. The reason has to be specific to the line: "safe" is
not a reason, "table is a literal chosen by the two callers in this file, and
the values travel as `?` parameters" is. `.gosec.json` turns on
`nosec-require-rules` and `nosec-require-justification`, so a bare `#nosec`, or
one without a `--` reason, suppresses nothing.

Excluding a whole rule is not acceptable. The one thing `.gosec.json` tunes is
the G101 entropy threshold, because that rule reports every constant whose name
contains `token`, `cred` or `secret`, and this repository holds a few dozen of
them as permission names, audit event names and column projections. The
thresholds sit above the entropy that identifier-shaped text reaches and below
the entropy of a random token, so a real secret literal is still reported. If
you change them, prove that with a throwaway file holding a secret-shaped
literal before you keep the change.

## Code style

Not preferences. These are the patterns the existing code uses, and a change
that departs from them reads as a change in intent.

### Doc comments on every exported symbol

Starting with the symbol's name, as `go doc` expects. Package comments say what
the package is for and, where there is one, what the non-obvious constraint is.
Compare `internal/crypto/token`, whose package comment exists to explain why
these credentials are hashed with SHA-256 while recovery codes are hashed with
Argon2id.

### Comments explain why, not what

The code says what it does. A comment earns its place by recording a decision, a
constraint or a rejected alternative.

```go
// A deferred transaction upgrades to a write lock at its first write, which is
// exactly the window the compare-and-swap operations must not have.
q.Set("_txlock", "immediate")
```

Not:

```go
// Set the transaction lock mode to immediate.
q.Set("_txlock", "immediate")
```

Where a decision has an ADR, cite it by number: `See docs/adr/0009`. Where a
comment states a security property, state the limit too. `internal/crypto/zeroize`
is the model: it says what it does and then says plainly that it is best-effort
because the runtime may copy or page memory.

### Errors wrapped with a package prefix

Every error that leaves a package names it:

```go
return fmt.Errorf("sqlite: create challenge: %w", mapError(err))
return fmt.Errorf("webauthn: begin registration: %w", err)
return fmt.Errorf("config: kek.path %q cannot be resolved: %w", c.KEK.Path, err)
```

`%w`, never `%v`, when the caller might need `errors.Is`. Sentinel errors are
declared at the top of the package and compared with `errors.Is`, never matched
on their message text; `errorlint` enforces it.

Two rules specific to this codebase:

- **A refusal an attacker can trigger is coarse on the way out and precise on
  the way in.** `internal/crypto/token` returns one `ErrInvalid` for a
  malformed token, an unknown selector and a wrong verifier, because
  distinguishing them tells an attacker which half of a guess was right. The
  real reason goes to the log and the audit entry. `internal/api/problem.go` is
  where the split is made: `Internal` is logged and never sent, `Detail` reaches
  the client and is left empty unless disclosure is safe.
- **A corrupted stored value is an error, not a failed attempt.** A malformed
  Argon2id hash returns an error rather than `false`, so a bad row is not
  silently read as a wrong password and left to look like an attack.

### Injected clocks

Nothing in the request path calls `time.Now` directly. A constructor takes a
`func() time.Time` and falls back to `time.Now` when it is nil:

```go
func New(s store.ThrottleStore, cfg config.Throttle, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{store: s, cfg: cfg, now: clock}
}
```

This is what makes a lockout window, a challenge expiry, a TOTP skew and an
assertion lifetime testable without sleeping. A test that sleeps to advance time
will be asked to inject a clock instead.

### Table-driven tests

One table, one loop, `t.Run` per case, and a name that says what the case is
about:

```go
tests := []struct {
	name     string
	skew     int
	presented string
	lastStep int64
	wantOK   bool
}{
	{name: "current step accepted", ...},
	{name: "spent step refused even inside its period", ...},
}

for _, tt := range tests {
	t.Run(tt.name, func(t *testing.T) {
		...
	})
}
```

Test files are linted too, because most of the crypto and store invariants are
asserted there and an unchecked error in a test hides a passing assertion.

### Other things the code does consistently

| Pattern | Where to see it |
|---|---|
| Domain separators on every digest, versioned | `internal/audit/chain.go`, `internal/throttle/throttle.go`, `internal/crypto/token/token.go` |
| Length-prefixed fields before hashing | The same three, and `internal/alerts/alerts.go`. Without it, two different inputs can serialise to one byte string |
| Constant-time comparison for anything secret | `crypto/subtle`, or `hmac.Equal` |
| Secrets as `[]byte`, never `string`, and zeroized with `defer` | `internal/totp`, `internal/api/public.go` |
| An interface narrowed to what the consumer needs | `health.KeyringInspector`, `envelope.KEKProvider` |
| Permissions attached where a route is mounted, not checked in the handler | `internal/api/router.go` |
| Dependencies pointing inwards: nothing outside `internal/api` imports it | Everywhere |

## Rules that are not style

### A schema change ships migrations for both engines

Not one. Both, `internal/store/migrations/sqlite/` and
`internal/store/migrations/postgres/`, numbered `NNNN_name.sql`, and
`make migrate-check` must pass:

```bash
make migrate-check
# migration parity: 41 objects declared for both engines
```

It compares the tables and the indexes each engine declares and fails with a
diff when they diverge. It runs in CI as its own job.

Migrations are forward-only. There is no down migration and there will not be
one: a rollback across a schema change means restoring the database, and an
operator needs to be told that rather than handed a routine that half works.

An applied migration is immutable. The runner records the SHA-256 of each file
and refuses to proceed when an already applied version hashes differently:

```
sqlite: migration 0001_initial was applied with checksum <a> but the embedded
file now hashes to <b>; the database and this binary disagree about the schema
```

So edit a migration only before it has been released. Afterwards, add a new one.

### A security-relevant change ships a test proving the property

Not a test that exercises the code. A test that fails if the property stops
holding.

| Change | The test that has to exist |
|---|---|
| Anything touching anti-replay | Two attempts with the same code, token or challenge, where the second is refused. Concurrently, if the mechanism is a compare-and-swap |
| A new route | One case asserting it refuses an absent credential, one asserting it refuses the wrong credential kind, and one per permission boundary it claims |
| A change to a hash or a digest | A case asserting that two inputs which differ only in a field boundary produce different digests |
| A change to the audit chain | A case asserting that an altered entry breaks verification at exactly its own sequence number, and that an erased entry still verifies |
| A change to the throttle | A case asserting the limit trips at the threshold and not before, and that a lockout is not ended early by a window roll |
| A change to a validator | A case per refusal, asserting the message names the setting |
| A change to an error path an attacker can reach | A case asserting the response body is indistinguishable from the neighbouring failure |

A fix comes with a test that failed before it. The pull request template asks
for this, and it is the item most often skipped.

### A new dependency needs an argument

Nine direct dependencies, each of which earns its place;
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) says why for each. A tenth needs
a paragraph in the pull request answering three questions: what it does that the
standard library does not, what its own transitive closure is, and what happens
to this project if it is abandoned.

A dependency for convenience will be declined. `internal/api/admin.go` contains
a four-line `slicesContains` rather than an import, and `internal/assertion`
assembles and parses a JWS by hand rather than taking a JWT library, because the
recurring vulnerabilities of those libraries have all been on the parsing side.

Node.js stays out of the build and out of CI entirely. See
[ADR 0012](docs/adr/0012-server-rendered-administration-interface.md).

### Documentation is part of the change

A change that alters observable behaviour updates the documentation in the same
pull request. The table in [README.md](README.md#documentation) says which file
covers what. Specifically:

| Change | Also update |
|---|---|
| A configuration key added, renamed or given a new default | `docs/CONFIGURATION.md`, and `docs/TROUBLESHOOT.md` if it adds a refusal |
| A route added or changed | `docs/RBAC.md` if it carries a permission, and the README's feature table if it is user-visible |
| A permission added | `docs/RBAC.md`, which must stay generated to match `internal/rbac/rbac.go` exactly |
| An alert type added | `docs/MONITORING.md`, with the operator response |
| A new personal data field | `docs/GDPR.md`, in the inventory table |
| A new limitation discovered | `docs/THREAT-MODEL.md`, under "not mitigated". A limit that is known and undocumented is worse than one that is not known |

## The ADR process

A decision that changes an interface, weakens or strengthens a security
property, or makes the code disagree with the original specification, gets an
architecture decision record.

The existing fourteen are in [docs/adr](docs/adr/README.md). Records 0002 to
0012 document the eleven deliberate deviations from the specification, which is
what lets a reader comparing the two tell a considered decision from drift.
Records 0013 and 0014 cover questions the specification leaves open: how an
approved operation comes to run, and where the first administrative token comes
from.

### When one is needed

| Needs an ADR | Does not |
|---|---|
| Changing what a route returns, or its authentication | A new field on an existing response |
| Adding or removing a factor | A new configuration key with a safe default |
| Changing how something is stored: hashed, sealed, or in clear | A new index |
| Changing a default that alters the security posture | A performance change with identical behaviour |
| Declining something the specification asks for | A bug fix |
| A new dependency that the product's shape depends on | A dependency version bump |

### How to write one

`docs/adr/NNNN-imperative-title.md`, next number in sequence, and the form
Michael Nygard described: context, decision, consequences, and nothing else.

```markdown
# 0013. Short imperative title

Status: accepted
Date: 2026-09-17

## Context

What the situation is, and what constraint makes the obvious answer wrong.
Name the standard or the specification clause if one applies.

## Decision

Stated in the imperative. "Require a tenant-scoped API key on every /v1 route",
not "we decided that it would be good to".

## Consequences

The costs, honestly, alongside the benefits. What gets harder. What an operator
or an integrator now has to do that they did not before. What this decision
makes expensive to reverse.
```

Then add the row to `docs/adr/README.md`.

Two conventions:

- **An accepted record is immutable.** A decision that stops holding is
  superseded by a new record that references it, never edited in place, so the
  history of the design stays legible.
- **State the costs.** Every existing record does. A record that lists only
  benefits has not finished thinking, and 0001 records the risk that the set
  drifts from the code, which is what makes the superseding discipline worth
  enforcing in review.

## Commit messages

An imperative subject under 72 characters, a blank line, then a body explaining
why.

```
Refuse a keyring inside the configured data directory

A key stored on the same volume as the ciphertext it protects gives no
confidentiality once that volume is copied: a stolen disk, a snapshot or a
backup archive hands over both halves at once. The quickstart in the original
specification did exactly this, and a quickstart is the configuration most
deployments keep.

The check resolves symbolic links on both sides before comparing, because a
textual comparison is defeated by a symlink or a bind mount. It is a guard
against the obvious mistake, not a security boundary.

See docs/adr/0009.
```

Rules:

| Rule | Reason |
|---|---|
| Imperative mood in the subject: "Refuse", not "Refused" or "Refuses" | It completes "this commit will ..." |
| Under 72 characters, no trailing full stop | `git log --oneline` stays readable |
| No type prefix. Not `feat:`, not `fix:` | The repository does not use conventional commits |
| A body, wrapped at 72 columns, for anything that is not a typo | The diff says what changed. The body says why, and that is the part nobody can reconstruct later |
| Cite the ADR by number when one applies | A reviewer in two years has the reasoning |
| One logical change per commit | A commit that does two things cannot be reverted for one of them |

No attribution trailers, no tool names and no session links in a commit message,
a pull request description, an issue or a comment.

## Pull requests

`.github/pull_request_template.md` is the checklist, and it is short on purpose:

- Tests cover the change, and a fix comes with a test that failed before it
- `make ci` passes locally
- No secret, keyring, token or real credential is in the diff **or the history**
- Schema changes ship a migration for both engines, and `make migrate-check`
  passes
- Documentation under `docs/` reflects the new behaviour

Plus the section the reviewer actually reads: anything that is not obvious from
the diff. A rejected alternative, a behaviour change an operator has to know
about, a follow-up left out on purpose.

Keep the diff to what the change requires. Do not reformat adjacent code, do not
"improve" a comment you are passing, and do not fold a refactor into a fix. If
you spot dead code or an unrelated bug, say so in the pull request rather than
fixing it in the same commit.

## Reporting a vulnerability

Not through a pull request and not through an issue. Use GitHub's private
vulnerability reporting, on the [Security
tab](https://github.com/Socold/n0passtemps/security/advisories/new).
[SECURITY.md](SECURITY.md) has the scope, what to include, and the honest
statement that no response time is promised.

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of the project. There is no contributor licence
agreement to sign.
