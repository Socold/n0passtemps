# Architecture decision records

A written specification preceded the code. A technical review of that document
found defects, and the implementation deliberately deviates from it on eleven
points. Each deviation is recorded below, so that a reader comparing the
specification with the repository can tell a considered decision from drift.

Records are immutable once accepted. A decision that no longer holds is
superseded by a new record rather than edited in place. See
[0001](0001-record-architecture-decisions.md) for the convention.

| # | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | accepted |
| [0002](0002-authenticate-every-call-to-the-public-api-surface.md) | Authenticate every call to the public API surface | accepted |
| [0003](0003-the-service-is-the-webauthn-relying-party.md) | The service is the WebAuthn relying party, and the relying party identifier is server configuration | accepted |
| [0004](0004-return-a-signed-assertion-result.md) | Return a signed assertion rather than a bare 200 | accepted |
