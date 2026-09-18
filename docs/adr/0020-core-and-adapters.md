# 0020. Core and adapters: decide by the trust path, not by the category

Status: proposed
Date: 2026-09-18

## Context

The question is what to add to make this usable by more people without turning
it into something else. The framing it arrived with is right: the strength of
this project is that it is narrow, sober, self-hostable and legible, and adding
OIDC, SAML, SCIM, a directory, a policy engine and a federation hub produces a
small Keycloak that nobody asked for and one person cannot maintain.

A core-versus-modules split is therefore the right shape. What this record
disagrees with is the axis on which the split is drawn.

The proposal sorted candidates by category: SDKs here, observability there,
KMS/HSM as an adapter, SIEM export as an adapter. Sorting by category puts two
things in the same bucket that belong on opposite sides. `audit.sink` is not an
integration convenience: it is the external witness that
[ADR 0016](0016-ship-the-audit-chain-to-an-external-witness.md) exists for, and
[THREAT-MODEL.md](../THREAT-MODEL.md) says the hash chain detects nothing
against the operator without it. Rendering the same entries as CEF for a
particular appliance *is* an integration convenience. Both are "SIEM".

The same applies to key handling. A KMS or HSM backend was listed as an adapter.
It holds the key that seals every secret at rest, and the TPM backend that
landed in [ADR 0019](0019-seal-the-keyring-to-a-tpm.md) went into `kek` in the
core for that reason. A key provider maintained out of tree gets reviewed less
often than the thing it protects and versions separately from it, which is the
wrong way round.

There is also a constraint that neither list mentions and that decides the
mechanics. Every package in this repository is under `internal/`, so nothing
outside the module can import any of it. That is deliberate and it is worth
keeping.

## Decision

### The test

> Is it on the trust path? Can getting it wrong forge an authentication,
> disclose a secret, or break the record of what happened?
>
> If yes, it belongs in the core, whatever its category.
> If no, it is an adapter, whatever its category.

Applied to the candidates:

| Candidate | Side | Why |
|---|---|---|
| WebAuthn, TOTP, recovery, assertions, audit, admin, storage | Core | The engine |
| KEK and signing key providers: file, env, TPM, and any KMS or HSM | **Core** | They hold the keys. Behind the `Provider` interface that already has three implementations |
| The audit sink | **Core** | It is a threat model control, not a feature. The chain is undetectable against the operator without it |
| Metrics, health | Core | The engine's own operational surface, like `/v1/health` |
| SDKs, browser helpers | Adapter | They call the HTTP API and hold nothing |
| Enrolment and login UI | Adapter | Same |
| SIEM format rendering, log shipping recipes | Adapter, and mostly documentation. [SIEM.md](../SIEM.md) does this job with no code, which is the right amount |
| Helm, Terraform, reverse-proxy helpers | Adapter | Packaging |
| OIDC provider, SAML IdP, SCIM, directory binding, policy engine, federation | **Neither** | A different product; see below |

### The boundary is the HTTP API, not a Go package

`internal/` stays as it is. No package is promoted to the public surface to let
an adapter import it.

This looks like a limitation and is the opposite. An adapter that has to speak
HTTP is an adapter that can be written in any language, which is what an
integrator actually needs; a Go extension point would make Go adapters
first-class and everything else second-class, for a project whose users write
in whatever they already use. It also keeps the core free to refactor
`internal/` without a compatibility promise, which is the freedom that lets a
small codebase stay small.

The supported surface is therefore exactly: `api/openapi.yaml`, the three SDKs,
and the configuration reference. Nothing else.

### Where adapters live

`sdk/go` is already its own Go module with its own tag, so the multi-module
pattern is established rather than hypothetical.

**App kits stay in this repository**, as separate modules or packages: SDKs,
browser helpers, the reference UI, Helm, Terraform. They version against the API
they call, one CI run covers them, and a solo maintainer is not running five
release processes. The cost of keeping them here is a larger directory listing
and nothing else.

**A different product goes to a different repository.** Not because of the code:
because of the README. A reader who finds an OIDC provider in this repository
has been told what this project is, whatever the directory it sits in, and the
positioning damage is done by the front page rather than by the dependency
graph.

### On OIDC specifically, and why it is the dangerous one

It looks nearly free here, and that is the trap. The assertion is already a
compact JWS carrying JWT claims with `iss`, `sub`, `aud`, `exp`, `nbf`, `jti`
and `amr`, and the JWK Set is already published at
`/v1/.well-known/jwks.json`. Adding `/.well-known/openid-configuration` is an
afternoon.

What is not an afternoon is the rest: the authorization code flow, PKCE,
consent, refresh tokens, session management and RP-initiated logout, dynamic
client registration, `prompt` and `max_age`, and the distinction between an
id_token and an access token. An integrator does not hand-roll against a
partial OIDC provider; they point a conformant client library at it, and the
library holds the promise the discovery document made. A half-implemented OIDC
provider is worse than none, because "it speaks OIDC" is believed.

So: conformant and separate, or not at all. Not a discovery document bolted
onto the assertion route.

### On an enterprise edition

Adapters may be a separate commercial offering. Nothing that changes a
deployment's ability to respond to an incident ever goes behind one, which is
the position [ADR 0018](0018-reducing-the-blast-radius-of-a-central-key.md)
already took when it refused to make signing key rotation an enterprise
feature. Rotation, sealing, the audit sink and the alert engine stay in the free
core permanently.

### What to build, in order

Ordered by what it removes from an integrator's path divided by what it costs.
The first two are the ones that decide whether the rest matters.

| # | Item | Cost | What it removes |
|---|---|---|---|
| 1 | **Publish `sdk/node` and `sdk/python`** | None. It needs accounts, not engineering | Today the answer to "how do I use this" is "clone the repository". It is already the first row of the maintainer table in [ROADMAP.md](../ROADMAP.md) |
| 2 | **A reference enrolment and login page**, deployable rather than illustrative | Small. `sdk/node/src/browser.js` already does the base64url and ArrayBuffer conversions, and `examples/node/register.html` is the sketch | The wall. Both ceremonies, the TOTP fallback and recovery codes, in a page an integrator adapts instead of writing |
| 3 | **`/metrics`** | Small, and it belongs in the core beside `/v1/health` | [MONITORING.md](../MONITORING.md) currently answers "scrape health and parse the logs". That is a weak answer in a procurement review and there is no Prometheus endpoint at all |
| 4 | **A Helm chart** | Small. `deploy/kubernetes/` is raw manifests | The gap between "there are manifests" and "it is installable" |
| 5 | **An integration architecture document** | Documentation | `ARCHITECTURE.md` describes the service. Nothing describes where the service sits next to an application that already has users, sessions and a login page |
| 6 | **A KMS or HSM key provider** | Medium, and in the core | Only after somebody asks. The TPM provider covers the disk-theft case; a KMS covers a fleet, which needs a fleet first |

Nothing on that list changes what the product is. Items 1 to 5 are what is
missing for the thing that already exists to be usable, which is a different
statement from what is missing for it to be a platform.

## Consequences

The core gains two things this record puts there deliberately against the
proposal it answers: key providers and the audit sink. Both are already there,
so the consequence is that they stay, and that a future KMS backend is a change
to `internal/crypto/kek` rather than a plugin.

Refusing a Go extension point means an adapter cannot reuse `internal/webauthn`
or `internal/assertion`, and the Go SDK will keep a deliberate duplicate of the
verification checks, which `internal/assertion` already documents as a duplicate
of `examples/go/client.go`. That duplication is the price of the boundary and it
has to be paid in review: a change to the checks is a change in three places.

Keeping app kits in this repository makes it larger, and a reader judging the
project by its directory listing will see more than the engine. The mitigation
is the front page rather than the layout: `README.md` says what the core is and
where the kits are, in that order.

Saying no to OIDC now costs the deployments that need it, and some of them will
choose something else. That is the intended outcome of a narrow product, and the
alternative on offer is not "OIDC too" but "a worse authentication engine and a
worse OIDC provider".

This record is a proposal. Nothing in it is built, and the ordering in the last
table is the part most likely to be wrong, because it is a guess at what
integrators find hard rather than a report of what they said.

## Related

- [ADR 0016](0016-ship-the-audit-chain-to-an-external-witness.md), why the audit
  sink is a control rather than an integration
- [ADR 0018](0018-reducing-the-blast-radius-of-a-central-key.md), the refusal to
  put a security response behind an edition
- [ADR 0019](0019-seal-the-keyring-to-a-tpm.md), the first key provider added
  under the rule this record states
- [ROADMAP.md](../ROADMAP.md), the maintainer steps that item 1 is already on
