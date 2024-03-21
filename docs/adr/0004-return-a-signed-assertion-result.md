# 0004. Return a signed assertion rather than a bare 200

Status: accepted
Date: 2024-03-20

## Context

The specification defined the assertion endpoints but not what a successful
assertion returns. The implicit answer, a bare `200 OK`, makes the calling
application derive an authentication decision from a status code it received
over the network.

That decision is then only as trustworthy as the path it travelled. Anything
able to answer on that path, a misconfigured reverse proxy, a caching layer, a
service mesh sidecar with a stale route, or an attacker inside the perimeter,
can manufacture an authentication by returning an empty 200. The calling
application has no way to tell the difference, because there is nothing in the
response to check. An on-premise deployment is exactly the setting where such a
path exists and is not audited.

The constraint is that verification must not require a second call back to the
service: a callback reintroduces the same trust in the same network path.

## Decision

Return a detached, short-lived signed statement of the ceremony result: a
compact JWS as defined by RFC 7515, signed with Ed25519.

The payload names the issuer, the audience, the subject identifier, `iat`,
`exp`, a unique `jti`, and an `amr` array naming the factor that was actually
used, `webauthn`, `totp` or `recovery`. Set the lifetime to 60 seconds and treat
the `jti` as single use, so a captured token is neither replayable later nor
usable twice.

Publish the verification key as a JWK Set per RFC 7517 from a JWKS endpoint,
with a `kid` matching the protected header, so the caller verifies offline
against a key it has cached.

## Consequences

The caller now has work to do. It has to fetch and cache the JWKS document,
handle key rollover when a `kid` is unknown, verify the signature, check the
audience, and keep a short-lived record of spent `jti` values. A caller that
skips the last step loses the single-use property and gains nothing over a bare
200.

A 60 second lifetime is unforgiving. Hosts whose clocks drift by more than that,
which is common on unmanaged on-premise machines without NTP, will reject valid
assertions, and the failure looks like a signature problem rather than a clock
problem.

The `amr` claim tells the caller which factor was used, which lets it apply its
own policy, for example refusing a recovery code for a privileged action. See
ADR 0005 for why recovery is a distinct factor.
