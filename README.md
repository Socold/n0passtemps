# n0passtemps

On-premise passwordless authentication: WebAuthn/FIDO2, TOTP and single-use
recovery codes. One static binary, SQLite or PostgreSQL.

Implementation in progress.

## What it is

A service the calling application talks to. It verifies an authentication factor
and returns a short-lived signed result the application exchanges for its own
session.

The application remains the WebAuthn relying party from its users' point of
view: credentials are registered against the origins the operator configures, so
nothing is tied to this service's domain.

## What it is not

Not an identity provider. There is no SAML, no OIDC, no session management and
no user directory. It answers one question, whether this person just proved a
factor, and it answers it verifiably.

## Design decisions

The implementation deviates from the original specification on several points,
each recorded in `docs/adr/` with the reasoning. The ones worth knowing up
front:

- every call to the public API requires a key. An unauthenticated registration
  endpoint is an authentication bypass, not a missing hardening measure.
- a successful ceremony returns a signed assertion, not a bare 200, so the
  caller does not have to trust the network path.
- recovery codes are hashed, not encrypted. Losing the encryption key therefore
  does not invalidate them.
- WebAuthn public keys are stored in clear. They are public keys.
- the audit log is hash chained. That makes tampering detectable, not
  impossible, and the documentation says so.

## Status

Under construction. The schema, the configuration layer and the cryptographic
core are in place. Not usable yet.

## Licence

MIT.
