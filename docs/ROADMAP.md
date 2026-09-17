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
| 2, this document | Credential rotation landed, two themes awaiting a decision |
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
risk. They are not equally clear-cut, so they are treated differently here.

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

### 2.2 Magic links: needs a decision

**What the specification means.** A link, sent by email, that signs the user in.

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

**Proposal: enrolment tickets.** Keep the useful half, a way in for a user who
holds no authenticator yet, and drop the harmful half.

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

**Cost.** One more table, one more hashed secret type, two routes. No new
dependency and no outbound traffic.

**What would make it a bad idea.** If the actual need is a sign-in method for
users who will never hold an authenticator, tickets do not meet it, and the
honest answer is that TOTP already does.

**Decision needed:** tickets as proposed, magic links as specified (accepting
the SMTP dependency and the weaker assurance), or neither.

### 2.3 Adaptive risk: needs a scope decision

**What is already collected.** A stalled signature counter, a change in the
authenticator's characteristics, failure bursts per subject and per network,
the use of a recovery code, the time since a credential was last used.

**Proposal: a transparent risk signal, not a risk engine.**

- Add a `risk` claim to the signed assertion: a level (`low`, `elevated`,
  `high`) and the list of reasons that produced it.
- Rules are deterministic, documented, and configured by threshold. No model,
  no training data, no third-party reputation feed, and therefore nothing that
  needs network access or that cannot be explained to a user who was stepped
  up.
- The service never refuses an authentication on risk alone. It reports, and
  the integrating application decides whether to ask for a second factor. It
  knows what the user is about to do; this service does not.

**What would make it a bad idea.** Calling it adaptive. A handful of thresholds
is not adaptation, and an operator promised machine learning will be
disappointed. The feature should be named for what it is: risk signals.

**Decision needed:** whether reporting is enough, or whether the service should
also be able to enforce a step-up itself (which means it needs to know which
factors a subject holds and to run a second ceremony, a larger change).

### 2.4 Candidates not in the specification

Found while building 1.0.0, in rough order of value.

| Item | Why |
|---|---|
| External audit sink | The hash chain makes tampering detectable, not impossible. Shipping entries to an append-only destination outside the operator's control is the only way to do better, and the threat model says so |
| Discoverable-credential sign-in | Today the caller names the subject first. Usernameless sign-in is what users now expect from passkeys, and the ceremony layer is most of the way there |
| Administrative sign-in with WebAuthn | The administration interface authenticates with a bearer token pasted into a form. A passwordless product whose own console does not use passkeys is an awkward demonstration |
| A `verify` subcommand for backups | Operators back up the database, the keyring and the pepper separately. Nothing checks that a given trio still opens |
| Multi-replica janitor lock | Each replica runs every sweep. Harmless, since the sweeps are idempotent, and wasteful |

## Phase 6, hosted offering

Out of scope until the on-premise product has users. The groundwork that is
cheap to do early has been done: every table carries a tenant identifier and
every query is tenant-scoped. What remains is substantial: row-level security,
per-tenant keyrings and relying parties, a provisioning surface and billing.

A hosted version of a product whose argument is data sovereignty needs a
clearer reason to exist than the specification currently gives it.
