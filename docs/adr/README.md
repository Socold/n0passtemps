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
| [0005](0005-hash-recovery-codes-do-not-encrypt-them.md) | Hash recovery codes, do not encrypt them | accepted |
| [0006](0006-store-webauthn-public-keys-in-clear.md) | Store WebAuthn public keys in clear | accepted |
| [0007](0007-chain-the-audit-log.md) | Chain the audit log; do not rely on triggers alone | accepted |
| [0008](0008-split-the-health-endpoint.md) | Split the health endpoint | accepted |
| [0009](0009-refuse-a-kek-inside-the-data-directory.md) | Refuse to load a key encryption key stored inside the data directory | accepted |
| [0010](0010-revocation-is-final.md) | Revocation is final | accepted |
