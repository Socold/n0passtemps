# 0007. Chain the audit log; do not rely on triggers alone

Status: accepted
Date: 2024-04-17

## Context

The specification made the audit log immutable with `BEFORE UPDATE` and
`BEFORE DELETE` triggers that raise an abort, and treated the matter as closed.

In an on-premise deployment it is not closed. The operator owns the database
file. Anyone holding it can open it with the `sqlite3` shell, drop the triggers,
edit or delete rows, and recreate the triggers, and the resulting file is
indistinguishable from an untouched one. The triggers stop an application bug or
a careless administrative query from rewriting history. They do not stop the
party most likely to want history rewritten, and presenting them as immutability
misleads anyone relying on the log as evidence. OWASP ASVS 4.0 section 7 asks
for log protection against tampering, which a trigger inside the protected
artefact does not provide.

## Decision

Keep the triggers, as a guard against application-level writes, and add a
SHA-256 hash chain over the log.

Each entry stores `prev_hash` and `entry_hash`, where `entry_hash` commits to
the entry's own fields and to its predecessor's hash. Compute both inside the
same transaction as the insert, reading the current chain head there, so two
concurrent appends cannot chain onto the same predecessor. Expose the head and a
verification routine that recomputes the chain from a given sequence number and
reports the first entry that does not match.

State the property plainly: this makes tampering detectable, not impossible.
Detection is the strongest property achievable without an external witness. An
append-only external sink, with the head published off the box, is the phase 2
answer and the only thing that closes the gap.

## Consequences

Any insertion, deletion or field edit breaks verification for every later entry,
so a silent rewrite of one row is no longer available. The log can be checked by
a third party who has the file and the expected head.

Appends serialise. Reading the head inside the writing transaction means one
writer at a time on the hottest table in the system, which bounds the audited
request rate. Verification is linear in the number of entries and gets slower
for the lifetime of the deployment.

An operator with write access can still edit an entry and recompute every hash
after it, provided nobody recorded the earlier head elsewhere. The chain raises
the cost of tampering; it does not prevent it.

GDPR Article 17 forces one further compromise.reference on surviving entries. The implementation is stronger than this paragraph originally described: rather than leaving `subject_id` out of the hash, where it could then be altered undetectably, the chain commits to a salted digest of the personal fields and the per-entry salt is destroyed on erasure. The digest is unchanged so the chain still verifies, and without the salt it cannot be reversed even for a low-entropy value such as a source address. See `internal/audit/chain.go`.
