# 0002. Authenticate every call to the public API surface

Status: accepted
Date: 2024-03-13

## Context

The specification defined a bearer token for `/admin/v1/*` and left `/v1/*` with
no authentication scheme at all. The `/v1` surface carries the ceremony
endpoints, including `POST /v1/webauthn/{subject}/register`.

Left unauthenticated, that route lets anyone who can reach the port enrol an
authenticator of their own choosing against any subject identifier, then
complete an assertion as that subject. The attacker supplies both halves of the
ceremony, so nothing in WebAuthn detects it. This is a total authentication
bypass, not a missing hardening measure, and it is the condition OWASP API
Security Top 10 2023 records as API2:2023 Broken Authentication. OWASP ASVS 4.0
section 4 requires an access control decision on every request rather than on a
subset of routes.

The constraint is cost. Authentication runs on the assertion path, so it must
not scan the key table and must not depend on a secondary service.

## Decision

Require a tenant-scoped API key on every `/v1` route. Present it as
`Authorization: Bearer <selector>.<verifier>`.

Store the selector in clear under a unique index, and store the verifier only as
an SHA-256 hash in PHC string form. Verification is one indexed lookup on
`api_keys.selector` followed by one SHA-256 evaluation of the presented
verifier and a constant-time comparison. Refuse revoked and expired keys, and
audit a failed attempt with actor type `api_key` and outcome `denied`. Admin
tokens use the same selector and verifier layout and additionally carry a role.

## Consequences

Anonymous access to the service no longer exists, which puts key distribution,
storage and rotation onto the operator. A leaked key is authority over every
subject of its tenant until it is revoked.

The integrating application must hold the key server-side and proxy the ceremony
endpoints. A browser front end cannot call `/v1` directly, because doing so
would ship the key to every visitor. That changes the integration shape for
anyone who expected to talk to the service from JavaScript.

The SHA-256 evaluation is paid on every request at m=19456 KiB, t=2, p=1. That
bounds request throughput and makes an unthrottled endpoint a memory-cost
denial-of-service target, so the throttle buckets are not optional. ADR 0008
covers the one route that stays unauthenticated.

A note on the hash. Recovery codes in this project are stretched with
Argon2id and these credentials are not, which is deliberate rather than
inconsistent. Stretching exists to make each guess expensive, which is worth
paying for when a secret has little entropy. These are generated here and
carry 160 bits in the verifier, so a fast hash helps no attacker. Meanwhile
the cost would fall on every request, and Argon2id at the OWASP baseline
allocates 19 MiB per evaluation, which would hand an unauthenticated caller a
way to exhaust memory by presenting invalid credentials. See
internal/crypto/token for the construction.
