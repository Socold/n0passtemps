# Roadmap

Where the project stands after 1.1.0, what comes next, and which decisions are
still open. A roadmap that lists only intentions is a wish list, so each item
below says what problem it solves, what it costs, and what would make it a bad
idea.

## Status

| Phase of the specification | State |
|---|---|
| 0, foundations | Done |
| 1, authentication core | Done, see the two notes below |
| Launch | Tagged `v1.0.0`, then `v1.1.0`, both published from the release workflow. Registry publication below is the maintainer's |
| 2, this document | Complete. All three specified themes answered, and all five candidates of 2.4 landed |
| 3, a key the process cannot read | Signing key rotation and the TPM-sealed keyring landed; a second signing key rejected; the signing key itself still open on a decision, not on tooling. See below, [ADR 0018](adr/0018-reducing-the-blast-radius-of-a-central-key.md) and [ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md) |
| 6, hosted offering | Not started, and not planned before the on-premise product has users |
| Maintenance | The style budget below is closed: `make lint` runs whole in CI and reports nothing |
| Security review | Done, September 2026. Findings fixed and disclosed; see the note below and `docs/audits/` |

Three phase 1 exit criteria deserved an honest note. Two of them, the
external security review and the coverage threshold, are now met; the third,
registry publication, needs accounts that belong to the maintainer.

**Client libraries.** The specification asks for SDKs in Node, Python and Go.
All three live under `sdk/`, each its own package with its own test suite and no
runtime dependency beyond its standard library, except that Python needs
`cryptography` for the one Ed25519 verification primitive. None is published to
a registry yet, which needs accounts that belong to the maintainer.

**Test coverage: met.** The specification asks for more than 80% of statements
and the suite reaches **80.0%**, counting the PostgreSQL store and the TPM
provider, which a plain `go test ./...` reports as zero because their tests sit
behind the `integration` build tag and behind a device that has to be present.
Without those two it is 72.3%, and `make cover-integration`, which starts no
software TPM, reads 79.5%; the three numbers differ by what was running, not by
what is true.

The last two tenths came from the part of `run` that returns before a listener
is opened: `-version`, `-check-config` and `-migrate`. Those are the three
commands the documentation tells an operator to run, one of them from a
deployment pipeline before it starts a new version, and none of them had a test.
Reaching a threshold that way is worth doing; reaching it by covering whatever
was cheapest would not have been.

Neither number was measured against anything until 1.1.0: the coverage upload
was configured not to fail a build and there was no threshold file, so the gate
existed in the specification and nowhere else. `COVER_MIN` and `COVER_MIN_FULL`
in the Makefile are enforced by `make cover`, `make cover-integration` and by
CI, each set just under what the suite reaches so that nothing may fall below
it.

Where the rest is, in order of what it would be worth:

| Package | Statements covered | What is untested |
|---|---|---|
| `cmd/n0passtemps-server` | 71.0% | The part of `run` past the early exits, and `main`, which are reached only by starting the process and signalling it |
| `internal/crypto/kek` | 43.1% | The TPM provider's error paths, which need a device that fails in a particular way |
| `internal/admin/ui` | 69.4% | Template rendering branches |

The crypto, audit, assertion, risk, throttle, rbac, totp, metrics, alerts and
store packages are all above 87%, and those are the ones a reviewer looks at
first, which is why the aggregate is not the most useful number here.

What moved it from 65.6% was not one change. The WebAuthn ceremony handlers had
no test that ran them over HTTP, because the tests that drove a real ceremony
lived in `internal/webauthn` and called the service directly; the software
authenticator they use is now `internal/webauthn/virtual`, a package both that
one and `internal/api` share, so a ceremony both accept means the same keys, the
same CBOR and the same signatures produced it. Beside that: the administrative
credential store on both engines, the setup wizard over every combination of
answers, the startup path, the eight model predicates that decide whether a
token authenticates, and the console's approval and acknowledgement actions.

**External security review: done, and its findings are fixed and disclosed.**
The specification requires one before shipping, and for two releases this entry
said it had not happened. It happened in September 2026. The redacted report is
[docs/audits/2026-09-security-review.md](audits/2026-09-security-review.md), the
advisories are published, and the fixes shipped in 1.1.1 with the SDK packages
following in 1.1.2.

The findings are worth knowing about rather than summarising away. Two were
exploitable: the reference application under `kits/` let a caller add a factor
to a subject it had not authenticated, and an administrator could satisfy the
two-person rule alone by rotating their own token mid-request, because an
administrator was identified by the identifier of their token and a rotation
mints a new one. The second is why `admin_tokens` now carries a principal that
outlives rotation. A third was quieter and had defeated an earlier fix: the
metrics middleware handed a copy of the request down the chain, so the
multiplexer set the matched route on the copy and every request log line fell
back to the concrete path, which on a ceremony route is the subject reference.

None of that replaces reading [THREAT-MODEL.md](THREAT-MODEL.md) before putting
this in front of something that matters. A review is a point in time, and the
model is what says which attacks were considered at all.

## Steps that need the maintainer

Done since this table was first written: `main`, `v1.1.0` and `sdk/go/v1.1.0`
are pushed, private vulnerability reporting is enabled, and every pinned action
SHA was verified against the GitHub API.

The claim that stood here before, that the release workflow builds and
publishes the image and the archives, was true of the workflow that cut 1.0.0
and not of the one that replaced it. The rewrite left an action's `uses` block
attached to the step that replaced it, which GitHub refuses before it creates a
job, so every push produced a run that failed in zero seconds. It was never
seen because the file was not pushed until the tag was. The tag was re-cut on
the fix, which is why `v1.1.0` names a commit later than `release: 1.1.0` and
why the 1.1.0 entry in [../CHANGELOG.md](../CHANGELOG.md) carries what had
accumulated after it.

| Step | Why it cannot be automated from here |
|---|---|
| Register the two trusted publishers | A setting on npmjs.com and on pypi.org, under accounts only the maintainer holds. See below |
| Announce | The specification names the venues; the wording is personal |

The Go SDK needs no registry, only the `sdk/go/v1.1.0` tag, which is pushed.

### Publishing the Node and Python SDKs

`release.yml` carries `sdk-npm` and `sdk-pypi`, which run on a `v*` tag after
the GitHub release exists. Both were exercised as far as they can be without the
accounts: `npm pack` produces an eleven-file tarball that installs into a clean
project and whose public API answers, `python -m build` produces a wheel and an
sdist that `twine check` passes and that install with the `verify` extra, and
the names `n0passtemps` are unclaimed on both registries.

**No token is stored anywhere, and none should be.** Both jobs publish through
trusted publishing: the registry verifies an OIDC claim naming this repository,
this workflow file and the deployment environment, so there is no long-lived
credential to leak, rotate or find in a log. The npm job also passes
`--provenance`, which records the same signed statement the container image
already gets.

What the maintainer does once, and cannot be done from here:

1. On npmjs.com, add a trusted publisher for `n0passtemps` naming this
   repository, `release.yml` and the environment `npm`.
2. On pypi.org, add a pending publisher for `n0passtemps` naming this
   repository, `release.yml` and the environment `pypi`.
3. Create both environments in the repository's settings.

Until the environments exist the two jobs are skipped, which is deliberate: a
release should not fail because a registry nobody has set up yet was not
published to. Both jobs refuse to publish a version the tag does not name, which
is the one mistake neither registry lets anybody take back -- npm allows
unpublishing for 72 hours and PyPI not at all.

## Phase 2

The specification names three themes: token rotation, magic links and adaptive
risk. They are not equally clear-cut, so they are treated differently here. The
third shipped under a more honest name, risk signals; see 2.3.

### 2.1 Credential rotation: landed

Shipped in 1.1.0; see [../CHANGELOG.md](../CHANGELOG.md).

**Problem.** Replacing an API key meant minting a new one and revoking the old
one. Revoke first and the integration is down until it is reconfigured; mint
first and the overlap lasts until somebody remembers to close it, which in
practice means for ever.

**Design.** Rotation mints a successor with the same name and scopes and gives
the predecessor an expiry a grace period away, in one transaction. The overlap
is explicit, bounded (seven days at most) and closes itself. Rotating never
extends a credential's life: a predecessor due to expire sooner keeps its
earlier date.

An administrative token can rotate itself and only itself. Rotating someone
else's token would hand the caller that person's successor credential, which is
impersonation, so no such route exists.

**What it does not cover.** The assertion signing key has no overlap mechanism,
deliberately. An assertion lives for sixty seconds, so replacing the key costs
at most the logins in flight during one restart. Publishing retired keys to
save those would add a configuration surface out of proportion to the gain.

### 2.2 Enrolment tickets, in place of magic links: landed

Decided as proposed below: enrolment tickets, not magic links. Shipped in
1.1.0; see [../CHANGELOG.md](../CHANGELOG.md),
[ADR 0015](adr/0015-enrolment-tickets-instead-of-magic-links.md), the
procedure in [ADMIN-GUIDE.md](ADMIN-GUIDE.md) under "A user has lost every
authenticator", the `[tickets]` section of [CONFIGURATION.md](CONFIGURATION.md),
the new permission in [RBAC.md](RBAC.md), and attacker 10 in
[THREAT-MODEL.md](THREAT-MODEL.md). The four routes are in `api/openapi.yaml`
under the Enrolment tickets tag.

**What the specification meant.** A link, sent by email, that signs the user in.

**Why it does not fit as specified.** Three reasons, in increasing order of
weight.

1. It requires this service to send email, which means an SMTP dependency,
   credentials for it, deliverability problems, and outbound network access.
   The service is built to run with none.
2. A magic link is phishable and forwardable. Everything else this project does
   is aimed at credentials that are neither.
3. It makes the mailbox the root of trust again. The first design note in this
   repository, from 2017, identifies exactly that as the problem to get away
   from: resets routed through a mailbox weaker than the thing it protects.

**What was built instead: enrolment tickets.** Keep the useful half, a way in
for a user who holds no authenticator yet, and drop the harmful half.

- The integrating application asks for a ticket for a subject. The service
  returns a single-use, short-lived secret and stores only its hash, the same
  construction as recovery codes.
- The application delivers it however it likes: email, SMS, a printed letter, a
  helpdesk call. Delivery is its responsibility and its risk, which is where
  the knowledge of the user and the channel actually lives.
- Redeeming a ticket permits exactly one thing: starting a WebAuthn
  registration. It never produces a signed assertion, so a stolen ticket lets
  an attacker enrol a key but the enrolment is audited, alerts the operator,
  and can be made to require an existing factor when the subject already has
  one.

**Cost, as estimated.** One more table, one more hashed secret type, two routes.
No new dependency and no outbound traffic.

**Cost, as built.** One table, one migration per engine, and four routes rather
than two. Issuing turned out to need both an administrative and a public route,
because it is both an operator action for a user who has lost everything and an
application action for a user who has not enrolled yet. No new dependency and no
outbound traffic, as estimated. The secret needed no new construction at all:
`internal/crypto/recovery` already produces exactly the selector plus
Argon2id-verifier shape a ticket wants, and is reused unchanged.

Two questions the proposal left open were settled during implementation. The
ticket travels in the request body rather than in a path segment, because a path
reaches the access log of every proxy in front of the service and a body does
not. And "can be made to require an existing factor" became the default rather
than an option: issuing for a subject who already holds a factor is refused
unless the caller explicitly says otherwise, because a ticket is a way in for
someone with no factor, and issuing one silently for an account that has factors
turns whoever controls delivery into an account-takeover route. The override is
audited and raises an alert.

**What would make it a bad idea.** If the actual need is a sign-in method for
users who will never hold an authenticator, tickets do not meet it, and the
honest answer is that TOTP already does. That remains true as built: a ticket
enrols a WebAuthn credential and nothing else.

### 2.3 Risk signals: landed

Shipped in 1.1.0; see [RISK.md](RISK.md) for the reason table, the
weights and the thresholds, and [../CHANGELOG.md](../CHANGELOG.md) for what
shipped.

**Problem.** The service already saw a stalled signature counter, a change in
the authenticator's characteristics, failure bursts per subject and per
network, the use of a recovery code and the time since a credential was last
used. All of it went to the audit log, where an integrating application could
not reach it at the moment it mattered.

**Design.** A `risk` claim on the signed assertion: a level (`low`, `elevated`,
`high`), the reasons that produced it and the score they add up to. Nine
reasons, each derived from a signal the service already collected, each with a
weight, summed against two configured thresholds. Deterministic, documented,
and readable as one table. No model, no training data, no third-party
reputation feed, and therefore nothing that needs network access and nothing
that cannot be explained to a user who was asked for a second factor.

The service never refuses on risk alone. It reports, and the application
decides whether to ask for a second factor, because it knows what the user is
about to do. A test asserts that property directly: a maximally risky
authentication still succeeds and still returns a signed assertion.

**Named for what it is.** Risk signals, not adaptive risk. A handful of
thresholds is not adaptation, and an operator promised machine learning would
be right to be disappointed. The word does not appear in the feature, the
configuration or the documentation.

**The scope question is settled: reporting only.** The service does not enforce
a step-up of its own. Doing so would mean knowing which factors a subject
holds, running a second ceremony, and holding an opinion about which actions
warrant which factor, which is the integrating application's opinion to hold.
A high assessment raises a `risk.high` alert so that an operator finds out even
when the application ignores the claim, and that is the whole of the service's
own response.

**What it does not cover.** Every signal is a property of the ceremony, not of
the person. An attacker holding the authenticator and its PIN produces a
ceremony indistinguishable from the legitimate one, and the assessment reads
`low`, correctly. The signals that would catch them, geolocation, device
fingerprinting, a behavioural baseline, need data this service refuses to
collect or network access it refuses to make, and each is also a new way to
lock out a user for travelling. [THREAT-MODEL.md](THREAT-MODEL.md) states this
in full.

### 2.4 Candidates not in the specification

Found while building 1.0.0, in rough order of value. All five have landed, so
this section is a record of what they turned out to cost rather than a list of
intentions. Each one is worth reading for the part the original entry got
wrong.

**Discoverable-credential sign-in: landed.** Unreleased; see
[../CHANGELOG.md](../CHANGELOG.md) and the reasoning in
[WEBAUTHN.md](WEBAUTHN.md) under "Usernameless sign-in". The caller no longer
has to name the subject first.

**External audit sink: landed.** Unreleased; see
[../CHANGELOG.md](../CHANGELOG.md),
[ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md), the
`audit.sink` section of [CONFIGURATION.md](CONFIGURATION.md) and attacker 9 in
[THREAT-MODEL.md](THREAT-MODEL.md).

It is off unless an endpoint is configured, because running with no outbound
network access is the point of the product, and what it sends is narrower than
an audit entry: only the fields the chain hash commits to, which is enough for a
receiver to recompute the hashes and notice a gap and not enough to tell which
person an entry concerns. So the witness proves the history was not rewritten
and cannot be used to investigate an incident. The proposal did not anticipate
that trade and it is worth stating plainly: closing the gap and shipping a
readable copy of the log are two different features, and this is the first.

One other thing the proposal got wrong. The delivery machinery was the easy
half. The hard half was deciding what may leave the deployment at all, and the
answer only exists because the chain already commits to a salted digest of the
personal fields rather than to the fields themselves; without that erasure
compromise from 1.0.0 there would have been no projection that is both
verifiable and free of personal data.

**Administrative sign-in with WebAuthn: landed.** Unreleased; see
[../CHANGELOG.md](../CHANGELOG.md),
[ADR 0017](adr/0017-administrative-sign-in-with-webauthn.md), the passkey
section of [ADMIN-GUIDE.md](ADMIN-GUIDE.md) and the cross-cutting limit in
[THREAT-MODEL.md](THREAT-MODEL.md).

The interesting part was not the ceremony, which the relying party already ran
for subjects. It was deciding what separates an administrative credential from a
subject credential, because getting that wrong in one direction turns every
enrolled user into an administrator. The answer is a separate table, a
domain-separated user handle and a refusal by each registration to store an
identifier the other already holds, with a separate challenge table so that
neither ceremony can be completed through the other's route.

The other thing the item did not anticipate: the pasted token cannot go away, so
"use a passkey" had to become "use a passkey, and decide per token whether the
paste is still accepted". A deployment-wide switch would have had no floor under
it, and a console that can lock out its only administrator permanently is worse
than one with a pasted token.

**A `verify` subcommand for backups: landed.** Unreleased; see
[../CHANGELOG.md](../CHANGELOG.md), the routine in
[ADMIN-GUIDE.md](ADMIN-GUIDE.md) under "Verifying a backup" and the verdicts in
[TROUBLESHOOT.md](TROUBLESHOOT.md).

The entry said nothing checks that a given trio still opens, which was the
point, but it understated what checking means. Parsing the three artefacts
proves nothing: the command has to decrypt real records under the keyring and
recompute a stored lookup value under the pepper, because that is the only
thing that ties all three together rather than testing two of its corners. The
second surprise was that being precise here is correct. Everything else in this
project refuses to say which check failed; this runs on the operator's own host
against their own backup, for somebody who already holds all three secrets, so
a useful diagnosis costs nothing. That reasoning is written where the code is,
because it is exactly the kind of thing a later reader would "harden" into
uselessness.

**Multi-replica janitor lock: landed.** Unreleased; see
[../CHANGELOG.md](../CHANGELOG.md) and "Running more than one replica" in
[DEPLOYMENT.md](DEPLOYMENT.md).

The entry called it harmless and wasteful, and that was right, which is why the
lock had to stay harmless too: losing the race is not an error anywhere in the
code and the sweeps are still idempotent, so a deployment whose lock never
worked would be exactly as correct as this one and merely busier. What the
entry did not anticipate is that the two engines need different mechanisms and
that only one of them is a real lock. PostgreSQL takes a session-level advisory
lock the server drops when the connection dies. SQLite takes a lease row, and
its single-writer property serialises the statement that takes the lease and
never the sweep it guards, so it coordinates nothing by itself; one process to
one file remains the only supported arrangement and the lease is what stands
between two processes that share a file anyway.

## Phase 3, a key the process cannot read

[ADR 0018](adr/0018-reducing-the-blast-radius-of-a-central-key.md) answers what
to do about the two keys whose loss nothing else here recovers from, and
[ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md) does the first half of the
answer.

**Landed.** Rotating the assertion signing key is an operation rather than a
choice between a forgery window and an outage. And `kek.provider = "tpm"` seals
the keyring to the machine's TPM 2.0, which closes the half of attacker 5 that
comes from copying files: a backup archive, a volume snapshot or a
decommissioned drive now carries ciphertext that opens on one machine. It is
opt-in, because a TPM cannot be backed up and the failure it introduces is as
total as the one it removes.

**Rejected by name.** A second signing key held by the same process on the same
host is one key with an extra file to steal.

**What the sealing does not do**, stated here as well as in the record because
it is the thing most likely to be over-read: nothing against a live compromise
of the host, which asks the same TPM to unseal exactly as the service does. It
is protection at rest.

### What remains: the signing key

The keyring was the easier of the two and is now done. The signing key is the
larger exposure, because losing it is an authentication bypass rather than a
disclosure, and it is the one still open.

The obstacle is now named rather than guessed at. `internal/assertion` signs
with Ed25519 and says in its package comment that Ed25519 is the only algorithm
it will ever accept. TPM 2.0 parts do ECDSA and RSA; EdDSA is permitted by the
specification and absent from the field. So the two options are:

| Option | Cost |
|---|---|
| A PKCS#11 token that does Ed25519, such as a YubiHSM 2 or SoftHSM | A new direct dependency, and either cgo or a dynamically linked binary. See below |
| Teach the assertion format ES256 | 41 files across three SDKs, both examples, the specification and the core, and a written decision reopened. No new dependency. See below |

Neither is obviously right, and picking one is a decision rather than a task.
What is no longer an obstacle is testing: `swtpm` is a TPM in a process and
SoftHSM is a PKCS#11 token in a process, both are packaged everywhere, and CI
already starts the first.

### What each option actually costs, measured

The table above said "needs cgo, so it ships two binaries" and "grows the
negotiation surface". Both were roughly right and neither was measured. They are
now, and the result is less balanced than the table suggests.

**A, PKCS#11.** `github.com/miekg/pkcs11` does need cgo, and that part of the
entry stands. What the entry did not know is that a PKCS#11 module can be loaded
without cgo at all: `github.com/ebitengine/purego` does `dlopen` and `dlsym`
from pure Go, and a throwaway program built with `CGO_ENABLED=0` against it
loads a shared object and calls into it. So the build tag and the second binary
are avoidable.

What is not avoidable is the linking. A `CGO_ENABLED=0` binary is statically
linked, which is what this one is today and what README.md promises. The same
binary with purego linked in is **dynamically linked against the system
loader**, because `dlopen` is the platform's and not Go's. `deploy/Dockerfile`
builds on `gcr.io/distroless/static-debian12:nonroot`, which carries no loader
and no libc, so that image would not start the binary at all. Adopting A
therefore means moving the image to a base that carries a libc, on every
deployment, for a feature most of them will not enable.

So A costs: one new direct dependency, the static binary, the distroless static
base, and a token to plug in. It leaves the assertion format untouched.

**B, ES256.** The blast radius is 41 files that mention Ed25519 or EdDSA: seven
in the Go SDK, five in the Python SDK, four in the Node SDK, five in the
examples, nine in the documentation, the OpenAPI document, and the core. That is
the real number and it is large.

Against it: **B needs no new dependency at all.** `github.com/google/go-tpm` is
already a direct dependency, `tpm2.Sign` is already in it, and `TPMAlgECDSA` is
already among its constants while `TPMAlgEdDSA` is not, which is the same
absence this section already described from the specification's side. The key
would live in the TPM that `kek.provider = "tpm"` already talks to, under
machinery [ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md) has built and CI
already exercises against `swtpm`.

**One correction to how B is framed here.** "The format grows the negotiation
surface that package exists to not have" is not forced. Teaching the issuer
ES256 does not oblige the verifier to accept two algorithms: a deployment can
hold exactly one, with `Verify` refusing every header that does not name it,
including `EdDSA` where ES256 is configured. The token still chooses nothing,
which is the property the package comment is defending. What genuinely does grow
is the SDKs: one SDK build talks to deployments of either kind, so the three of
them do have to verify both, and that is where most of the 41 files sit.

**What is not on the table.** A third option, leaving the key on disk and
relying on the rotation that landed in phase 3, is not written up as an option
because rotation shortens the window and does not close it: an attacker who
reads the key forges assertions until the next rotation, and the decision here is
about whether reading it is possible at all.

**No seam before a backend.** An interface with one in-process implementation
and nothing else behind it is decoration, and decoration around a key is worse
than none because it is believed. The TPM provider was added to `kek` because
that interface already had two implementations and a third fitted; a signer
interface with nothing behind it would not earn its place, and would fix the
shape before the first real backend could argue with it.

## Maintenance backlog

Work that is owed rather than proposed. It is listed with counts so that it can
be burned down deliberately instead of drifting.

### The style budget in golangci-lint

The pinned linter could not run at all until 1.1.0: `v2.6.0` cannot read the
export data of the toolchain this project builds with, so every `make lint`
ended with one `typecheck` error and no analysis. With the pin moved and the
misconfigurations corrected, the correctness linters report nothing. The budget
is now empty: `errcheck`, `lll`, `govet`, `revive`, `gocritic` and `gocyclo` all
report nothing, and `make lint` runs whole in CI. Five of the six were cleared
by fixing the findings; the sixth, `gocyclo`, was closed by moving its threshold,
which is set out at the end of this section.

Each category returned something for the effort.

`revive` was 34 rather than the 33 recorded here, for the measurement reason
`lll` established below. Twenty-three were missing doc comments, which cost
nothing but the writing. The other eleven were worth the pass: two parameters
were dead rather than merely undocumented, `openStore` took a `context.Context`
neither engine's `Open` accepts and `clientThrottleDims` took the `*Caller` left
behind when the per-key dimension moved to `MeterAPIKey`, so both were removed
rather than renamed to `_`. Two were tests whose parameter is unused because the
race detector and a nil dereference are what fail them, and both now say so,
because the obvious repair is to add an assertion that tests nothing.

`gocritic` was 88, and the half of it worth acting on was acted on: naming the
results the `store.Store` interface already names, `http.NoBody`, `bytes.Equal`,
and renaming the locals that shadowed `max`, `real` and the `bytes` package. One
`truncateCmp` looked like a defect and was not, because `strconv.ParseUint` with
a bit size of 32 already bounds the value the comparison truncates; the
comparison was widened anyway, since that is clearer than the reasoning.

**`hugeParam` and `rangeValCopy` are refused by name**, in `.golangci.yml` with
the reasoning attached, the same way `sloppyReassign` is. Both ask to replace a
copy with an alias, and every site they fire on is a descriptor a caller hands
in and the callee must not change: `audit.Event`, `alerts.Input`, `risk.Input`,
`store.AuditFilter`, `config.WebAuthn`, the constructors' `Deps` and `Options`.
`Recorder.Success`, `.Failure`, `.Denied` and `.Errored` each set `ev.Outcome` on
their own copy before passing it on, so taking a pointer there would write the
outcome back into the caller's event: a style fix that silently changes what
gets audited. The copies are 80 to 232 bytes on paths that also run Argon2id and
Ed25519.

`gocyclo` is the one still open, and it is open on a judgement rather than on
effort. The count went from 14 to 13 while the worst case fell from 134 to 34:
`(*Config).Validate` was a single function over every setting in the file, and
is now one method per section, which is how the file was already organised in
comments. A test asserts nothing was lost in the move, in the only way that
matters: the 102 message literals the file carries are the same 102 before and
after. What remains is thirteen functions between 17 and 34, and they are the
inherently branchy kind, a SQL statement splitter, the startup path, a JWS
verifier, four handlers. Splitting those to satisfy a counter scatters the logic
without reducing it, and this project has already written down once that a
control believed to do more than it does is worse than none. The honest choices
are to refactor them on their own merits or to say in this file that 15 is the
wrong threshold for them; neither has been decided.

`errcheck` turned up two real faults and one class of false positive.

`lll` turned up no defect, as expected of a line-length rule, but it did turn up
how the backlog was being measured: 127 lines were over the limit rather than
the 119 a full `golangci-lint run` reported, because eight were not in that
report at all and appeared as soon as the other linters were switched off. A
count taken from a run that enables everything is a lower bound, and the numbers
above are to be read as such. `govet` measured 179 in isolation against the 175
recorded here, for the same reason.

`govet` (`shadow`) was the large one and it turned up the thing worth writing
down. The 179 sites divide by what a rewrite would actually mean, which is not
visible from the message:

| Shape | Count | What it became |
|---|---|---|
| The assignment is an `if` statement's init, in the same function as the variable it shadows, and nothing reads that variable before it is written again | 152 | `:=` became `=`. Behaviour-preserving by construction |
| The site is in a closure and the shadowed variable belongs to the enclosing function | 8 | Renamed. Writing to the captured variable is a different program when the closure is deferred or concurrent, and two of these are |
| The statement declares another variable as well, so `=` will not compile | 18 | Restructured, usually by assigning straight into the field the temporary was copied to |
| One `var err error` inside a closure | 1 | The prelude that made the outer name live across the closure was renamed instead |

Deciding those by hand would have been guesswork, so it was decided by a
throwaway program over the syntax tree: for each site, is the shadowed
declaration inside the same innermost function, and is the first mention of the
name after the statement a write or a read? The first pass of that program was
wrong in a way worth recording, because it counted the `err != nil` of the very
`if` being rewritten as a read, and so reported forty-five sites as dangerous
that were not.

**`shadow` and `gocritic`'s `sloppyReassign` cannot both be at nought.** They
contradict each other on exactly these lines: one asks for `if err := f()`
wherever the value is used only inside the `if`, the other refuses that form
whenever an `err` already exists in the function. Clearing `shadow` moved 51
findings into `gocritic`. `sloppyReassign` is disabled in `.golangci.yml` with
that reasoning attached, because `shadow` catches a bug and it catches a
looseness: a variable declared inside a block while an outer one of the same
name is checked after the block is how a handled error becomes an unhandled
one, whereas a scope wider than it needs to be is untidy and not wrong.

**The budget is closed, and the exit criterion it set is the one that was
used.** `UNCLEARED_LINTERS` is empty, `lint-cleared` is an alias for `lint`, CI
runs the whole linter on every push, and `make lint` reports nothing. The
mechanism is kept described here rather than deleted, because a future budget
should reintroduce the split rather than invent a new one: the target ran
everything except the categories still listed, a category left the variable as
it reached nought, and the gate tightened one category at a time.

It was written as what to disable rather than what to enable because
golangci-lint's `--enable` adds to the set in `.golangci.yml` instead of
replacing it. The first version of the target used `--default=none --enable=`
and passed while three categories were failing, which is the failure mode a
gate has to not have.

**`gocyclo` was closed by moving the threshold, not by refactoring to it**, and
that is the one entry in this section where the budget lost an argument rather
than won it. 15 was set on the reasoning that anything above it is a function
doing two jobs. That was true of exactly one function, `(*Config).Validate` at
134, and false of the other thirteen: a SQL statement splitter tracking quote
and comment state, the startup path, a JWS verifier checking the claims a JWS
has, an interactive setup, four handlers that validate, act, audit and answer.
Splitting those at 15 yields helpers called from one place, which moves branches
without removing them and costs the reader the whole decision at once. The
threshold is now 35, one above the largest function in the tree, so it holds the
line where it is and would still have caught Validate by a factor of four. The
reasoning is in `.golangci.yml` beside the number, and raising it again wants
the same kind of note.

## Around the core

[EXTENSIONS.md](EXTENSIONS.md) is the standing answer to "could it also do X".
It is separate from this document on purpose: this one is what the core owes,
that one is what could sit beside it without the core becoming something else.
The position it records is that the engine stays narrow and that optional
modules around it are open, decided by whether the thing is on the trust path
rather than by what category it belongs to.

Nothing in it is built, and its ordering is a guess at what integrators find
hard. The first report from somebody actually integrating this should change it.

## Phase 6, hosted offering

Out of scope until the on-premise product has users. The groundwork that is
cheap to do early has been done: every table carries a tenant identifier and
every query is tenant-scoped. What remains is substantial: row-level security,
per-tenant keyrings and relying parties, a provisioning surface and billing.

A hosted version of a product whose argument is data sovereignty needs a
clearer reason to exist than the specification currently gives it.
