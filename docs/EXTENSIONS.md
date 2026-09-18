# Extensions: what sits around the core, and what never goes in it

This document is the standing answer to "could it also do X". It is an analysis
and a direction, not a commitment: nothing listed under **Candidates** is built,
and some of it never will be.

[ROADMAP.md](ROADMAP.md) is about what the core owes. This is about what could
sit beside it. [ADR 0020](adr/0020-core-and-adapters.md) is the reasoning
compressed into a decision record; this is the working document that record came
out of, and the place to add to when the question comes up again.

## The position

The engine stays narrow. What is open is adding **optional** modules around it
so that integrating it is less work, and each of those is opt-in, separately
versioned where that helps, and never a dependency of the core.

Two things follow that are easy to say and easy to lose:

1. A deployment that wants none of this must keep working exactly as it does,
   with the same binary and the same configuration.
2. Nothing here is allowed to make the core answer for it. If an adapter needs
   a hook in the engine, that hook is a change to the engine and is argued as
   one.

## The test

Categories are the wrong axis. Sorting by category puts the audit sink and a
CEF renderer in one bucket although the first is the external witness the
threat model depends on and the second is a convenience, and it puts a KMS
backend outside the core although it would hold the key that seals everything
at rest.

> **Is it on the trust path?** Can getting it wrong forge an authentication,
> disclose a secret, or break the record of what happened?
>
> Yes → core, whatever its category.
> No → adapter, whatever its category.

## Where the line currently falls

### Core, and staying there

| | Why |
|---|---|
| WebAuthn, TOTP, recovery codes, the assertion | The engine |
| The audit log and its hash chain | The record |
| `audit.sink` | Not an integration. It is the external witness of [ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md), without which the chain detects nothing against the operator |
| KEK providers: `file`, `env`, `tpm`, and any KMS or HSM that follows | They hold the key. A provider maintained out of tree is reviewed less often than the thing it protects and versions separately from it. [ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md) put the first one here |
| The assertion signing key, and whatever comes to hold it | Same, and more so: its compromise is an authentication bypass rather than a disclosure |
| RBAC, dual approval, throttling, the alert engine | Controls |
| The administration interface | It is how an operator reaches the controls |
| `/v1/health`, and metrics when they exist | The engine's own operational surface |

### Adapter

They call the HTTP API and hold nothing.

| | State |
|---|---|
| SDKs for Node, Python and Go | Built, in `sdk/`. Node and Python are unpublished |
| Browser helpers | Built, `sdk/node/src/browser.js`: the base64url and `ArrayBuffer` conversions every WebAuthn integration gets wrong |
| A reference enrolment and login page | `examples/node/register.html` is a sketch, not a deployable page |
| Helm chart, Terraform module | Not built. `deploy/kubernetes/` is raw manifests |
| SIEM field mapping and shipping recipes | [SIEM.md](SIEM.md), and it is documentation with no code, which is the right amount |
| A reverse-proxy authentication helper | Not built |

### Not this product

| | Why not |
|---|---|
| A full OIDC provider | See below. It is the dangerous one |
| A SAML identity provider | Same argument, more XML |
| SCIM, directory or IAM binding, provisioning | An identity platform manages accounts. This authenticates people who already have one |
| A policy engine, a federation hub, a user portal | Same |
| Session management | The integrating application exchanges the assertion for its own session. Taking that over is taking over the application's security model |

A deployment that needs these should probably run Keycloak, and the honest
answer when somebody asks is to say so.

## The constraint that decides the mechanics

**Every package is under `internal/`.** Nothing outside the module can import
any of it, and that stays.

It reads as a limitation and is the opposite. An adapter that has to speak HTTP
can be written in whatever the integrator already uses; a Go extension point
would make Go adapters first-class and everything else second-class, for a
project whose users are not mostly writing Go. It also keeps the core free to
refactor `internal/` with no compatibility promise, which is the freedom that
lets a small codebase stay small.

**The supported surface is `api/openapi.yaml`, the three SDKs and
[CONFIGURATION.md](CONFIGURATION.md). Nothing else.**

The price is paid in one place and should be paid knowingly: the Go SDK keeps a
deliberate duplicate of the assertion verification checks, which
`internal/assertion` already documents as a duplicate of `examples/go/client.go`
for the same reason. A change to those checks is a change in three places, and
review has to catch it.

## Where an adapter lives

`sdk/go` is already its own Go module with its own tag, so the multi-module
pattern is established rather than hypothetical.

**App kits stay in this repository.** SDKs, browser helpers, the reference UI,
Helm, Terraform. They version against the API they call, one CI run covers
them, and one maintainer is not running five release processes. The cost is a
longer directory listing.

**A different product goes to a different repository.** Not because of the code:
because of the README. A reader who finds an OIDC provider here has been told
what this project is, whatever directory it sits in.

## On OIDC, which is the one to be careful about

It looks nearly free, and that is the trap.

The assertion is already a compact JWS carrying JWT claims with `iss`, `sub`,
`aud`, `exp`, `nbf`, `jti` and `amr`, and the JWK Set is already published at
`/v1/.well-known/jwks.json`. Adding `/.well-known/openid-configuration` is an
afternoon.

What is not an afternoon: the authorization code flow, PKCE, consent, refresh
tokens, session management and RP-initiated logout, dynamic client
registration, `prompt` and `max_age`, and the difference between an id_token and
an access token. Nobody hand-rolls against a partial OIDC provider. They point a
conformant client library at it, and the library holds the project to the
promise the discovery document made.

**Conformant and separate, or not at all.** Not a discovery document bolted onto
the assertion route.

## On an enterprise edition

Adapters may be a separate commercial offering.

Nothing that changes a deployment's ability to respond to an incident ever goes
behind one. That is the position [ADR 0018](adr/0018-reducing-the-blast-radius-of-a-central-key.md)
already took when it refused to make signing key rotation an enterprise
feature, and it is restated here because the temptation returns every time the
list of adapters grows. Rotation, keyring sealing, the audit sink, the alert
engine and the RBAC model stay in the free core permanently.

## Candidates, in the order their value divided by their cost puts them

Nothing below is built. The ordering is the part most likely to be wrong,
because it is a guess at what integrators find hard rather than a report of what
they said, and the first thing that should change this document is somebody
saying otherwise.

| # | Candidate | Cost | What it removes | What would make it a bad idea |
|---|---|---|---|---|
| 1 | **Publish `sdk/node` and `sdk/python`** | No engineering. It needs registry accounts | Today the answer to "how do I use this" is "clone the repository". Already the first row of the maintainer table in [ROADMAP.md](ROADMAP.md) | Nothing. It is the cheapest thing on this list by a wide margin |
| 2 | **A reference enrolment and login page**, deployable rather than illustrative | Small. The hard part, the encoding conversions, is already in `sdk/node/src/browser.js` | The wall an integrator hits first: both ceremonies, the TOTP fallback and recovery codes, in a page to adapt rather than write | If it grows into a user portal. It is a page, not an account management surface |
| 3 | **`/metrics`** | Small, and it goes in the core beside `/v1/health` | [MONITORING.md](MONITORING.md) currently answers "scrape health and parse the logs". That is a weak answer in a procurement review, and there is no Prometheus endpoint at all | Emitting a per-subject label, which turns the metrics endpoint into a list of users |
| 4 | **A Helm chart** | Small | The distance between "there are manifests" and "it is installable" | Carrying deployment opinions the raw manifests deliberately do not |
| 5 | **An integration architecture document** | Documentation | [ARCHITECTURE.md](ARCHITECTURE.md) describes the service. Nothing describes where it sits next to an application that already has users, sessions and a login page | Nothing |
| 6 | **A reverse-proxy authentication helper** | Medium | The deployments that want to put this in front of an application they cannot change | Becoming a session manager, which is the line in the table above |
| 7 | **A KMS or HSM key provider**, in the core | Medium | Nothing yet. The TPM provider covers the stolen-disk case; a KMS covers a fleet, and there is no fleet | Building it before somebody has a fleet. ADR 0019 says the same about the seam |
| 8 | **A conformant OIDC bridge**, separate repository | Large | The single most common integration request for anything in this space | Doing it partially. See above |

## Related

- [ADR 0020](adr/0020-core-and-adapters.md), this argument as a decision record,
  status **proposed**
- [ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md), why the
  audit sink is a control and not an integration
- [ADR 0018](adr/0018-reducing-the-blast-radius-of-a-central-key.md), the
  refusal to put a security response behind an edition
- [ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md), the first key provider
  added under the rule above
- [ROADMAP.md](ROADMAP.md), what the core owes
