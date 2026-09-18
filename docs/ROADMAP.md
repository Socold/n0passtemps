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
| 3, a key the process cannot read | Part one landed, part two rejected, part three waits on hardware to test it against. See below and [ADR 0018](adr/0018-reducing-the-blast-radius-of-a-central-key.md) |
| 6, hosted offering | Not started, and not planned before the on-premise product has users |
| Maintenance | The style budget below is the only work this document still owes |

Two phase 1 exit criteria deserve an honest note.

**Client libraries.** The specification asks for SDKs in Node, Python and Go.
All three live under `sdk/`, each its own package with its own test suite and no
runtime dependency beyond its standard library, except that Python needs
`cryptography` for the one Ed25519 verification primitive. None is published to
a registry yet, which needs accounts that belong to the maintainer.

**External security review.** The specification requires one before shipping.
It has not happened, and nothing in this repository substitutes for it. The
test suites and the threat model make a reviewer's work shorter; they do not
replace a second pair of eyes that did not write the code. Anyone deploying
this in front of something that matters should read
[THREAT-MODEL.md](THREAT-MODEL.md) with that in mind.

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
| Publish `sdk/node` and `sdk/python` | npm and PyPI accounts. The Go SDK needs no registry, only the `sdk/go/v1.1.0` tag |
| Announce | The specification names the venues; the wording is personal |

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
to do about the two keys whose loss nothing else here recovers from. Part one of
that record has landed: rotating the assertion signing key is now an operation
rather than a choice between a forgery window and an outage. Part two is
rejected by name, because a second signing key held by the same process on the
same host is one key with an extra file to steal.

Part three is the one left, and it is the only one that changes what a host
compromise costs. `assertion.Issuer` needs a signer rather than a private key,
and `envelope.Sealer` already reaches its KEK through an interface with
`Current` and `ByVersion`. Behind those two seams a deployment could put a
PKCS#11 token, a cloud KMS or a TPM, and the key would stop being readable at
all: a compromise becomes the ability to *use* the key while it lasts, bounded
by eviction, counted by the device and logged where the operator of this host
cannot rewrite it.

**Why it is not in the next release.** A PKCS#11 backend nobody has run against
real hardware is a configuration option that fails in production, and this
project has no hardware to test it on. A KMS backend puts a network call on the
assertion path and needs its own design for what happens when that call is slow,
and it contradicts the product's argument unless it stays optional. Either one
deserves a record with a working implementation behind it rather than a
paragraph here, and the seam has to be introduced by the first backend that
proves it fits, not before.

**No seam before a backend.** An interface with one in-process implementation
and nothing else behind it is decoration, and decoration around a key is worse
than none because it is believed. The first backend that proves the shape fits
is what introduces it, which is the same rule ADR 0018 applies to the second
signing key it rejects.

## Maintenance backlog

Work that is owed rather than proposed. It is listed with counts so that it can
be burned down deliberately instead of drifting.

### The style budget in golangci-lint

The pinned linter could not run at all until 1.1.0: `v2.6.0` cannot read the
export data of the toolchain this project builds with, so every `make lint`
ended with one `typecheck` error and no analysis. With the pin moved and the
misconfigurations corrected, the correctness linters report nothing and the
`errcheck` backlog has been cleared. What remains is 423 findings from the
budget linters, which accumulated in code written while nothing was checking
it:

| Linter | Count | What it is |
|---|---|---|
| `govet` (`shadow`) | 175 | A nested `err` shadowing an outer one. Idiomatic in most cases, and the check is famously noisy, but it is also how a handled error becomes an unhandled one |
| `lll` | 119 | Lines past 120 columns |
| `gocritic` | 82 | Diagnostic, style and performance suggestions |
| `revive` | 33 | Mostly missing doc comments on methods with unexported receivers |
| `gocyclo` | 14 | Functions past 15 branches |

None is a defect today, and none of them is `errcheck`, which was the one
category worth reading line by line. Clearing it turned up two real faults and
one class of false positive, all recorded in the changelog.

The `shadow` count grew by ten with the signing key rotation, every one of them
`if err := f(); err != nil` in a test, which is the form the surrounding files
use throughout. Contorting the new code to avoid a finding the rest of the tree
carries 165 of would buy a smaller number and a file that reads unlike its
neighbours. The count is recorded here rather than worked around, because the
point of a budget is to be visible: it goes to zero when the category is cleared
across the tree, in one deliberate pass, and not by writing unidiomatic Go at
the edges in the meantime.

`make lint` is deliberately not wired into CI while this stands. Wiring it in is
the exit criterion, not the starting point: the backlog goes to zero first, and
`errcheck` is where to start, since an unchecked error in a test can hide a
passing assertion.

## Phase 6, hosted offering

Out of scope until the on-premise product has users. The groundwork that is
cheap to do early has been done: every table carries a tenant identifier and
every query is tenant-scoped. What remains is substantial: row-level security,
per-tenant keyrings and relying parties, a provisioning surface and billing.

A hosted version of a product whose argument is data sovereignty needs a
clearer reason to exist than the specification currently gives it.
