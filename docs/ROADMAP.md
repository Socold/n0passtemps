# Roadmap

Where the project stands after 1.0.0, what comes next, and which decisions are
still open. A roadmap that lists only intentions is a wish list, so each item
below says what problem it solves, what it costs, and what would make it a bad
idea.

## Status

| Phase of the specification | State |
|---|---|
| 0, foundations | Done |
| 1, authentication core | Done, see the two notes below |
| Launch | Tagged `v1.0.0`. Publication steps below are the maintainer's |
| 2, this document | Credential rotation, risk signals and enrolment tickets landed; all three themes answered |
| 6, hosted offering | Not started, and not planned before phase 2 has users |

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
1.0.0 in front of something that matters should read
[THREAT-MODEL.md](THREAT-MODEL.md) with that in mind.

## Launch steps that need the maintainer

| Step | Why it cannot be automated from here |
|---|---|
| Push `main` and the `v1.0.0` tag | Rewrites the remote branch, so it is a deliberate act |
| Let the release workflow build and publish the image | Runs on the tag push; needs the repository's package permissions |
| Confirm the pinned action SHAs in `.github/workflows/` | They were written without network verification; the first Dependabot run corrects them, or `gh api` does |
| Enable private vulnerability reporting | A repository setting; [SECURITY.md](../SECURITY.md) points at it |
| Publish `sdk/node` and `sdk/python` | npm and PyPI accounts |
| Announce | The specification names the venues; the wording is personal |

## Phase 2

The specification names three themes: token rotation, magic links and adaptive
risk. They are not equally clear-cut, so they are treated differently here. The
third shipped under a more honest name, risk signals; see 2.3.

### 2.1 Credential rotation: landed

Implemented after 1.0.0; see the Unreleased section of
[../CHANGELOG.md](../CHANGELOG.md).

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

Decided as proposed below: enrolment tickets, not magic links. Implemented after
1.0.0; see the Unreleased section of [../CHANGELOG.md](../CHANGELOG.md), the
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

Implemented after 1.0.0; see [RISK.md](RISK.md) for the reason table, the
weights and the thresholds, and the Unreleased section of
[../CHANGELOG.md](../CHANGELOG.md) for what shipped.

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

Found while building 1.0.0, in rough order of value.

| Item | Why |
|---|---|
| External audit sink | The hash chain makes tampering detectable, not impossible. Shipping entries to an append-only destination outside the operator's control is the only way to do better, and the threat model says so |
| Discoverable-credential sign-in | Today the caller names the subject first. Usernameless sign-in is what users now expect from passkeys, and the ceremony layer is most of the way there |
| Administrative sign-in with WebAuthn | The administration interface authenticates with a bearer token pasted into a form. A passwordless product whose own console does not use passkeys is an awkward demonstration |
| A `verify` subcommand for backups | Operators back up the database, the keyring and the pepper separately. Nothing checks that a given trio still opens |
| Multi-replica janitor lock | Each replica runs every sweep. Harmless, since the sweeps are idempotent, and wasteful |

## Maintenance backlog

Work that is owed rather than proposed. It is listed with counts so that it can
be burned down deliberately instead of drifting.

### The style budget in golangci-lint

The pinned linter could not run at all until 1.0.1: `v2.6.0` cannot read the
export data of the toolchain this project builds with, so every `make lint`
ended with one `typecheck` error and no analysis. With the pin moved and three
genuine misconfigurations corrected, the correctness linters report nothing.
What remains is 430 findings from the budget linters, which accumulated in code
written while nothing was checking it:

| Linter | Count | What it is |
|---|---|---|
| `govet` (`shadow`) | 141 | A nested `err` shadowing an outer one. Idiomatic in most cases, and the check is famously noisy, but it is also how a handled error becomes an unhandled one |
| `lll` | 97 | Lines past 120 columns |
| `errcheck` | 81 | Unchecked error returns, 63 of them in tests. These are the ones worth reading individually: the rest is formatting, this is not |
| `gocritic` | 69 | Diagnostic, style and performance suggestions |
| `revive` | 30 | Mostly missing doc comments on methods with unexported receivers |
| `gocyclo` | 12 | Functions past 15 branches |

None is a defect today. They were not fixed in the same change that made the
linter run, because a mechanical pass over 430 sites across nearly every file
would bury the three real fixes it shipped alongside, and a diff nobody can
review is not an improvement.

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
