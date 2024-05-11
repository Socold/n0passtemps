# 0010. Revocation is final

Status: accepted
Date: 2024-05-11

## Context

The specification allowed a revoked credential to be restored within 24 hours by
an administrator other than the one who revoked it, as protection against
mistaken revocation.

The reason a credential gets revoked is that it is believed compromised: a lost
security key, a departing employee, a suspected clone reported by the signature
counter. A window in which that decision can be reversed is therefore a window
in which a compromised credential can be put back into service, and it is
reachable by exactly the actor an attacker wants to become. An administrative
token stolen during those 24 hours undoes the containment action taken against
the attacker who stole it.

It also conflicts with the audit model. ADR 0007 makes the log append-only and
hash-chained so that a recorded event is a fact. A credential whose revocation
can be withdrawn leaves a trail in which the same credential is revoked and
active, and the current state is a function of a time window rather than of the
last recorded decision.

## Decision

There is no un-revoke operation, in the API, in the store interface or in the
admin interface. `revoked_at` is written once and never cleared, and a
credential bearing it is invisible to the active credential lookups.

Address the mistaken-revocation case with prevention and detection rather than
reversal: rate limit the revoke endpoint, raise an alert when revocations in a
window exceed a threshold, and refuse to revoke a subject's last active
credential without an explicit override, so the ordinary path cannot silently
lock a user out.

Recovery from a genuine mistake is re-enrolment.

## Consequences

The state of a credential is whatever the audit log last recorded, with no
pending window to reason about, and an attacker who obtains an administrative
token cannot resurrect a credential that has been contained.

A mistaken revocation cannot be undone. The subject must re-enrol their
authenticator, in person or through the recovery path of ADR 0005, and that is
support work the specification's design would have avoided. A bulk revocation
run against the wrong filter is unrecoverable for every subject it touched.

Revocation is now a denial-of-service primitive available to any holder of a
sufficiently privileged token. Rate limiting and alerting make that noisy and
slow; they do not make it impossible, and an operator who ignores the alert gets
no second chance.

The last-credential guard adds friction to legitimate cleanup, because removing
a subject's final authenticator requires an explicit override rather than the
normal call.
