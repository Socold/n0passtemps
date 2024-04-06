# 0006. Store WebAuthn public keys in clear

Status: accepted
Date: 2024-04-06

## Context

The specification sealed all credential material under the key encryption key,
describing it uniformly as secret. Applied to WebAuthn, that means the
COSE-encoded credential public key is treated as a secret.

It is not one. W3C WebAuthn Level 2 has the authenticator keep the private key
and hand the relying party the public half, which the browser is free to expose
and which carries no confidentiality requirement. What the server needs from
that column is integrity: a public key that has been substituted lets the
substituter authenticate, whereas a public key that has been read does nothing
for the reader.

Encrypting it has a real cost. It puts the credential table on the KEK
dependency path, so a lost or corrupted KEK destroys enrolments that were never
secret, and it forces an unseal on every assertion where a direct read would do.
ADR 0005 makes the same argument from the other direction for recovery codes.

## Decision

Store `webauthn_credentials.public_key` in clear, along with the credential
identifier, the AAGUID, the attestation type and the authenticator flags.

Reserve envelope encryption for material that is genuinely a symmetric secret:
`totp_secrets.secret_sealed`, and `subjects.ref_sealed`, the encrypted copy of
the identifier the calling application uses for its own user, which is very
often an email address and is therefore treated as personal data.

## Consequences

A KEK loss now costs the TOTP seeds and the readable form of the subject
references. It does not cost the WebAuthn credentials, which is the factor most
deployments rely on, so the service degrades rather than failing closed.
Assertions no longer perform an unseal.

The credential rows are readable to anyone who obtains the database file. The
AAGUID identifies the authenticator model, so a stolen copy reveals which
security keys are in use across the population, which is inventory information
an attacker can act on when a model-specific weakness is published. Credential
identifiers are exposed too, and an allow list built from them is visible.

The AEAD tag no longer covers this column, so integrity rests on the database
and the filesystem rather than on cryptography. An attacker with write access
could substitute a public key. No store method updates `public_key` after
insertion, and credential changes are audited, but that is detection rather than
prevention. ADR 0007 states the limits of what the audit log can prove.
