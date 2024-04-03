# 0005. Hash recovery codes, do not encrypt them

Status: accepted
Date: 2024-04-03

## Context

The specification placed recovery codes under the same key encryption key
envelope as the other secrets, so that the admin interface could display them
again on request.

That confuses two different requirements. Envelope encryption exists for
material the server has to read back in order to work, as a TOTP seed does. The
server never needs to read a recovery code: it needs only to decide whether a
code a user has typed matches one it issued. That is a verification problem, and
the standard answer to a verification problem is a password hash, not
reversible encryption.

Sealing the codes also has an operational cost that the specification did not
account for. It makes the recovery path depend on the KEK, so losing the KEK
destroys the codes that exist precisely to be used when other things have gone
wrong.

## Decision

Split each code into a clear selector and a secret verifier, and store only a
hash of the verifier.

Draw 20 characters from the Crockford base32 alphabet with `I`, `L`, `O` and `U`
removed: 6 characters of selector, 30 bits, indexed unique per tenant, and 14
characters of verifier, 70 bits. Hash the verifier with Argon2id at the OWASP
Password Storage Cheat Sheet baseline, m=19456 KiB, t=2, p=1, and store the
result as a PHC string so the parameters travel with the row. Compare in
constant time.

The selector makes verification one indexed lookup plus one Argon2id evaluation.
Hashing against every stored code would cost one evaluation per issued code per
attempt, which is both slow and a denial-of-service lever.

## Consequences

Losing the KEK no longer destroys recovery codes, so a KEK loss stays
recoverable through re-enrolment. A stolen database yields no usable code even
to an attacker who also holds the KEK, and 70 bits puts an offline search out of
reach regardless of the hash cost.

The codes cannot be shown again. A user who loses the printed sheet has no
recourse except a fresh batch, and issuing a batch retires every unused code
from the previous one, so the old sheet dies with it. Support cannot read a code
out to a caller, which is the point, and also a recurring support complaint.

The Argon2id cost is paid per attempt, so the redemption endpoint must be
throttled or it becomes a memory-exhaustion target, as in ADR 0002. Raising the
parameters later applies to new rows only; existing rows keep the cost recorded
in their PHC string until they are reissued.
