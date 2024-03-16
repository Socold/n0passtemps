# 0003. The service is the WebAuthn relying party, and the relying party identifier is server configuration

Status: accepted
Date: 2024-03-16

## Context

The specification described the ceremony endpoints without ever saying who the
relying party is. W3C WebAuthn Level 2 does not leave that open. A credential is
scoped to a relying party identifier, and the verification steps for both
registration and assertion require the server to compare the client data origin
against an expected origin, and the RP ID hash against the hash of an expected
`rpId`.

Both comparisons are only worth making against a value the caller cannot
choose. If `rpId` or the origin were read from the request body, an attacker
would present the origin it is actually operating from, the check would pass,
and the origin binding that makes WebAuthn resistant to phishing would be gone.
Being vague about the relying party is therefore not an omission in the
documentation, it is an unspecified security control.

The persistence layer already assumes an answer: the credential table stores
`rp_id` per row and enforces uniqueness on `(tenant_id, rp_id, credential_id)`.

## Decision

The service is the relying party. Take `rp_id` and the list of allowed origins
from server-side configuration only, never from a request. Refuse a ceremony
whose client data origin is not in the configured list, and record the
configured `rp_id` on the challenge row and on the credential it produces, so
the value used at assertion is the value that was in force at registration.

Keep the ceremony session opaque and server-side in `webauthn_challenges`, so
the expected challenge, the user handle and the user verification requirement
cannot be edited by the caller between the two round trips.

## Consequences

The integrating application has to serve its front end from a configured origin.
That is a constraint on its deployment, not only on ours, and it rules out
serving the same authentication flow from arbitrary customer domains without
reconfiguring the server.

Changing `rp_id`, for example moving from `app.example.com` to `example.com`, is
a configuration change and a restart. Worse, it is not backward compatible:
credentials registered under the old identifier will not validate under the new
one, so an `rp_id` change means every subject re-enrols. Deployments that
foresee a domain move should set `rp_id` to the registrable suffix from the
start.

ADR 0004 covers what a completed ceremony returns.
