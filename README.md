# n0passtemps

An on-premise passwordless authentication service. Design phase.

## What changed

WebAuthn Level 1 became a W3C Recommendation in March 2019. User verification is
now a first class part of the ceremony, which means one gesture can prove both
possession of an authenticator and the identity of the person holding it. That
is the condition the 2017 note set: passwordless stops being a slogan.

## Shape

A service the calling application talks to, not one users are redirected to.

The application keeps its own origin and its own sessions. This service verifies
a factor and returns a result the application can check. A credential registered
against the customer's domain stays useful to them if they stop using this,
which is the point of not being a hosted identity provider.

## Scope

In:

- WebAuthn registration and assertion
- TOTP, as a fallback for users without an authenticator
- single-use recovery codes
- an audit trail
- administration for the handful of things an operator actually does

Out:

- SAML and OIDC. This verifies a factor, it is not an identity provider.
- session management. The application already has sessions.
- anything hosted.

## Open questions

- retention and erasure against an append-only audit trail, which pull in
  opposite directions
- attestation verification without network egress
- how much of the configuration can be validated before the listener starts

See docs/notes/ for the working through.

## Status

Design. No implementation.
