# Data protection

How this service handles personal data, and what the operator has to do that
the software cannot do for them. Article references are to the General Data
Protection Regulation (EU) 2016/679.

This document describes the software. It is not legal advice, and it cannot be:
the lawful basis, the retention periods and the record of processing are
decisions the controller makes about their own deployment. What the software
does is stated precisely so those decisions can be made from facts.

## Who the controller is

The service is deployed on premise, by the organisation that operates it, on
infrastructure that organisation controls. That organisation is the controller
for the personal data the service processes.

The project maintainer is not a processor and has no access to any deployment.
There is no telemetry, no phone-home, no licence check and no usage reporting.
The service makes no outbound network connection other than to its own database,
which is why the shipped Kubernetes NetworkPolicy can deny egress except for DNS
and PostgreSQL.

### Sub-processors

There are none.

Not "none by default", and not "a list you can review". The software transmits
no personal data anywhere. A deployment's own sub-processors, the hosting
provider, the managed database, the log aggregator, are the operator's
relationships and belong in the operator's Article 30 record, not here.

Attestation verification is the one feature that would ordinarily require an
external service, the FIDO Metadata Service. It is off by default, and when an
operator turns it on the metadata is supplied as a file on disk
(`webauthn.metadata_path`) rather than fetched, precisely so that enabling it
does not create an egress dependency. See
[WEBAUTHN.md](WEBAUTHN.md).

## Lawful basis

The service processes personal data for one purpose: to authenticate a person to
the application that is integrating with it. The bases available for that,
under Article 6, are:

| Basis | When it applies |
|---|---|
| Article 6(1)(b), performance of a contract | The usual case. Authentication is necessary to provide the service the data subject has signed up for. A user cannot use an account they cannot log in to |
| Article 6(1)(f), legitimate interests | The security-specific processing that goes beyond letting someone in: the audit log, the source addresses in it, the rate-limiting counters and the alert rows. The interest is preventing unauthorised access to the data subject's own account, which is also in the data subject's interest |
| Article 6(1)(c), legal obligation | Where a sector obligation requires retention of authentication records. This is the basis that turns `audit.retention_days = 0` from a default into a requirement |

Article 32 requires security appropriate to the risk, and names pseudonymisation
and encryption specifically. What this service does towards that is the table
below.

Consent, Article 6(1)(a), is a poor fit and is not assumed anywhere. A user who
withdrew consent for authentication would be withdrawing consent for having an
account.

## Every personal data item

| Item | Where it lives | Form | Protected by | Retention |
|---|---|---|---|---|
| Application's subject reference, for lookup | `subjects.ref_hmac` | HMAC-SHA256 under the server-held pepper, domain-separated | The pepper, a separate secret from the KEK. An attacker with the database alone can neither read nor enumerate references. One with the database and the pepper can confirm a guess, but still not enumerate | Until purge |
| Application's subject reference, readable | `subjects.ref_sealed` | Envelope-encrypted: AES-256-GCM under a per-record data key, wrapped under the KEK | The KEK, which lives outside the data directory. Omitted entirely when `subject.seal_reference = false` | Until purge |
| Display name, optional | `subjects.display_name` | Clear | Database access controls only | Until purge |
| Internal subject identifier | `subjects.id`, and every table referencing it | Random UUID, clear | Pseudonymous: it identifies a person only in combination with `ref_hmac` and the pepper | Until purge |
| WebAuthn credential identifier and public key | `webauthn_credentials.credential_id`, `.public_key` | Clear, COSE-encoded | Database access controls. A public key needs integrity, not confidentiality; see [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) | Until purge, cascaded |
| Authenticator model, flags, transports, counter | `webauthn_credentials.aaguid` and the flag columns | Clear | Database access controls. The AAGUID reveals which authenticator models are in use, which is inventory information | Until purge, cascaded |
| Credential label | `webauthn_credentials.label` | Clear | Database access controls. Supplied by the caller, so it holds whatever the caller put there | Until purge, cascaded |
| TOTP shared secret | `totp_secrets.secret_sealed` | Envelope-encrypted | The KEK. This is a symmetric secret the server must read back, which is what genuinely requires encryption rather than hashing | Until purge, cascaded |
| Recovery code verifiers | `recovery_codes.verifier_hash` | Argon2id PHC string, `m=19456` KiB, `t=2`, `p=1` | Not reversible. A stolen database yields no usable code even to an attacker holding the KEK; see [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md) | Until purge, cascaded |
| Recovery code selectors | `recovery_codes.selector` | Clear, 30 bits | Not personal data on its own; it is a lookup key for a code, not for a person | Until purge, cascaded |
| Ceremony state | `webauthn_challenges` | Opaque session blob plus `subject_id` | Swept by the janitor once `expires_at` passes | `webauthn.challenge_ttl`, default 5 minutes, then the next janitor pass |
| Source IP address, in the audit log | `audit_log.source_ip` | Clear, committed through the salted digest | Cleared and its salt destroyed on erasure | `audit.retention_days`, default 0, meaning kept indefinitely |
| Source IP address, in rate-limiting state | `throttle_buckets.bucket_key` | Not stored. The bucket key is a truncated SHA-256 over a domain separator, the dimension, the tenant and the normalised network | The address itself never reaches the table. IPv6 is bucketed by `/64`, IPv4 by the address | Swept by the janitor once the window has long passed |
| Source IP address, in logs | Log field `source_ip` | Clear, and only when `logging.include_source_ip` is true | Operator's log retention. The setting is a deliberate choice rather than a default because the field is personal data | Operator's log retention |
| Subject reference, in logs | Log field `subject_ref` | Replaced with `ref:` plus six bytes of a domain-separated digest when `logging.redact_subject_refs` is true, which is the default | Redaction is enforced in the log handler, not at the call site, so a new call site cannot forget it | Operator's log retention |
| Subject identifier, in the audit log | `audit_log.subject_id` | Clear, committed through the salted digest | Cleared and its salt destroyed on erasure | `audit.retention_days` |
| Audit event detail | `audit_log.detail` | JSON, clear | Cleared on erasure. Holds counts, reasons and identifiers, and specifically not secrets | `audit.retention_days` |
| Alert rows | `alerts.subject_id`, `.resource_id`, `.summary`, `.detail` | Clear | Database access controls. An alert summary never carries a secret: a secret in an alert row is a secret in a screenshot | No automatic expiry. Acknowledged alerts remain |
| Erasure request | `erasure_requests` | Clear, including the reason the operator typed | Database access controls. Survives the purge of the subject it refers to, as the record that the erasure happened | No automatic expiry |

Two things the service never stores in any form: a password, because there are
none, and a recovery code in a readable form.

### The route path

A subject reference appears in the path of the `/v1` routes, because that is the
shape the API contract specifies. This service logs the route pattern rather
than the concrete path, so `POST /v1/webauthn/{subject_ref}/assert` is what
reaches its own logs. An intervening reverse proxy logs the concrete path unless
configured otherwise, which puts the reference into the proxy's access log.

Two consequences for an operator:

- Configure the proxy not to log the path, or to redact it.
- Ask the integrating application for an opaque identifier rather than an email
  address. The documentation asks for one; applications supply email addresses
  anyway, which is why the reference is encrypted at rest regardless and
  redacted in logs by default.

## Article 15: the right of access

The access path has two halves, and only one of them is a route.

**What the service can produce about a subject.** Everything in
`GET /admin/v1/subjects/{subject_id}`: the internal identifier, the status, the
display name, the creation and update timestamps, every credential with its
model and timestamps, whether TOTP is enrolled, how many recovery codes remain,
and any pending erasure request. Plus the audit history from
`GET /admin/v1/audit?subject_id=...`, which is the record of when and from where
the person authenticated.

**The reference itself.** Turning a row back into something that identifies a
person is a separate, audited operation:

```bash
curl -sS "$BASE/admin/v1/subjects/$SUB?reveal_ref=true" \
  -H "Authorization: Bearer $ADMIN" | jq '.subject_ref'
```

It requires `subject.read`, which every administrative role holds. There is
deliberately no second check inside the handler: the route is already guarded by
that permission, and a duplicate check would have to decide for itself whether
the role model is enabled, which is the kind of second code path that drifts
from the first. Decrypting `ref_sealed` appends an audit entry:

```
event_type:    admin.subject_ref_revealed
actor_type:    admin
actor_id:      <the administrative token's identifier>
subject_id:    <the subject>
resource_type: subject
outcome:       success
```

The disclosure is recorded because it is the one operation in the service that
converts pseudonymous storage back into identifying data. An access request is a
legitimate reason to perform it; so is naming a person in the administration
interface; and both leave a trail.

A subject created while `subject.seal_reference` was false has nothing to
reveal. The handler logs that the reference could not be revealed and returns
the record without it, because that is a configuration consequence rather than a
fault. Finding the subject still works, through
`GET /admin/v1/subjects?subject_ref=...`, which matches the HMAC.

Finding the record for a reference the data subject supplies never needs
decryption at all:

```bash
curl -sS "$BASE/admin/v1/subjects?subject_ref=user-1234" \
  -H "Authorization: Bearer $ADMIN"
```

There is deliberately no substring search. The reference is encrypted precisely
so that it cannot be scanned, and a search that decrypted every row to match a
pattern would undo that. An access request arrives with the exact reference, so
the exact match is what is offered.

## Article 17: the right to erasure

Two modes, chosen by `features.deferred_erasure`.

### Deferred, the default

```bash
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/erasure" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"subject request received 2026-09-17, verified by ticket 4711"}'
```

Requires `erasure.request`, and is held by the dual-approval queue when
`subject.erase` is in `features.dual_approval_operations`, which is the default.
Held means that the first call queues the request, answers 202 with the problem
type `approval-required`, and does nothing to the subject. After a different
administrator has approved it, the requester repeats the identical call, same
subject and same `reason`, with the header `X-Approval-Id`, and only that call
starts the erasure. The approval is bound to the subject and to the reason, so
what runs is what the second administrator read. The controller's time limit
for answering the data subject keeps running while a request waits: an approval
that expires after `features.approval_ttl`, or that the requester never
redeems, has erased nothing.

Two things happen in the same request:

1. An `erasure_requests` row is created with status `pending`, the requesting
   administrator, the reason, and `purge_after` set to now plus
   `features.erasure_retention`, default 30 days.
2. `SoftDeleteSubject` sets `deleted_at`. The subject stops being visible to
   every getter and can no longer authenticate, immediately. That is the part of
   Article 17 that cannot wait for a retention window.

Inside the window the request can be cancelled, which is the window's purpose:

```bash
curl -sS -X DELETE "$BASE/admin/v1/subjects/$SUB/erasure" \
  -H "Authorization: Bearer $ADMIN"
```

Requires `erasure.cancel`. It withdraws the pending request and, in the same
call, `RestoreSubject` lifts the soft deletion: the subject is visible again and
can authenticate at once with the factors they had. A withdrawn request that
left the person blocked would be the worst of both outcomes, nothing erased and
the user still unable to sign in. The event is `erasure.cancelled`. Once purged
there is nothing to restore.

When `purge_after` passes, the janitor picks the request up through
`ListDueErasures` and performs four steps in order: it clears the personal
fields from every audit entry naming the subject through
`EraseSubjectAuditEntries`, purges the subject through `PurgeSubject`, marks the
request `purged`, and records an `erasure.purged` audit entry naming how many
entries were redacted.

`PurgeSubject` is one transaction, and it:

- deletes the subject's `webauthn_challenges` rows,
- deletes the subject's `throttle_buckets` rows, found through the
  `subject_id` column that exists for exactly this reason, since the bucket key
  is an opaque hash no predicate could otherwise match,
- deletes the `subjects` row, which cascades to `webauthn_credentials`,
  `totp_secrets` and `recovery_codes` through `ON DELETE CASCADE`,
- confirms the subject belongs to the tenant before removing anything, so a
  purge aimed at another tenant's identifier deletes nothing at all.

The erasure request itself is then marked `purged` and survives, as the record
that the erasure happened and who asked for it.

The audit entries are handled separately, and that is the next section.

### Immediate

With `features.deferred_erasure = false`, `purge_after` is set to the moment of
the request, so the purge is due at once and runs on the next janitor pass,
`features.janitor_interval`, default 5 minutes. The cancel route still exists
but has no window to act in.

The specification asked for immediate deletion as the only behaviour. The
deferred mode is the default instead, for two reasons an operator should weigh
before switching:

- An immediate hard delete destroys the evidence that the erasure was
  legitimate. The erasure request row survives either way, but the retention
  window is what allows a request made in error, or withdrawn by the person who
  made it, to be undone before anything is destroyed.
- It hands anyone who obtains one administrative token a way to wipe accounts
  irreversibly, at the rate they can issue requests.

Against that: an organisation whose interpretation of Article 17 is that a
thirty-day window is not "without undue delay" has a legal reason to turn the
window off, and the setting exists for them.

## How the audit hash chain survives erasure

An append-only log and a right to erasure pull in opposite directions. The log
must not change; Article 17 says some of its contents must go. The mechanism
that satisfies both is in `internal/audit/chain.go`.

### Why the obvious approaches do not work

| Approach | Why it fails |
|---|---|
| Hash the personal fields directly | Erasing them breaks verification for every entry after the erased one. The log becomes unverifiable the first time anyone exercises Article 17 |
| Leave the personal fields out of the hash | The subject reference on an entry could be altered without detection, and the subject reference is precisely the field an attacker would want to alter |
| Commit to a bare digest of the fields | A source address has about thirty-two bits of entropy. Its digest is recovered by exhaustive search in seconds, so the digest is not erasure |

### What is actually done

Each entry carries a random 16-byte salt, `pii_salt`, and a digest,
`pii_digest`, computed over a domain separator, the salt and the three personal
fields, each length-prefixed:

```
pii_digest = SHA-256(
    len || "n0passtemps/audit-pii/v1" ||
    len || pii_salt                   ||
    len || subject_id                 ||
    len || source_ip                  ||
    len || detail
)
```

The chain hash then commits to `pii_digest` rather than to the fields
themselves, alongside the non-personal fields and the predecessor's hash:

```
entry_hash = SHA-256(
    len || "n0passtemps/audit-chain/v1" ||
    len || prev_hash                    ||
    u64 || seq                          ||
    len || tenant_id                    ||
    u64 || occurred_at (Unix nanoseconds, truncated to microseconds) ||
    len || event_type                   ||
    len || actor_type                   ||
    len || actor_id                     ||
    len || resource_type                ||
    len || resource_id                  ||
    len || outcome                      ||
    len || request_id                   ||
    len || pii_digest
)
```

Erasing an entry clears `subject_id`, `source_ip` and `detail`, and destroys
`pii_salt`, while keeping `pii_digest`, `prev_hash` and `entry_hash` bit for
bit. The chain therefore still verifies, the fields are gone, and without the
salt the digest cannot be reversed even for a low-entropy value such as an IPv4
address.

Every field is length-prefixed because without the prefixes two different
entries could serialise to the same byte string: an entry with event type
`credential.revoke` and an empty actor would be indistinguishable from one with
event type `credential` and actor `.revoke`. That ambiguity would let an
attacker construct a substitute entry with a matching hash, which is exactly
what the chain exists to rule out.

The genesis hash is derived from the domain separator rather than being a block
of zero bytes, so the log cannot be truncated to nothing and the result
presented as a valid empty chain.

### The one narrow exception in the database

The audit table refuses updates through a trigger, and the erasure is the single
shape it permits. In SQLite:

```sql
CREATE TRIGGER audit_log_update_guard
BEFORE UPDATE ON audit_log
WHEN NOT (
        NEW.subject_id IS NULL
    AND NEW.source_ip  IS NULL
    AND NEW.pii_salt   IS NULL
    AND NEW.detail     = '{}'
    AND OLD.pii_salt   IS NOT NULL
    AND NEW.seq = OLD.seq AND NEW.tenant_id = OLD.tenant_id
    ...
    AND NEW.pii_digest = OLD.pii_digest
    AND NEW.prev_hash  = OLD.prev_hash
    AND NEW.entry_hash = OLD.entry_hash
)
BEGIN
    SELECT RAISE(ABORT, 'audit_log permits no update other than erasure of the personal fields');
END;
```

An update that changes anything else, including the digest or either hash, is
aborted. `EraseSubjectAuditEntries` issues exactly that statement, for every
entry naming the subject, and then appends a tombstone in the same transaction:

```
event_type: erasure.entries_redacted
detail:     {"erased_entries": 12}
```

So the erasure of audit entries is itself an audited event, chained onto the
entries it has modified.

### What the limitation is

`VerifyEntry` checks an entry that still holds its salt fully, including that
its personal fields reproduce the stored digest. An erased entry has no salt, so
its digest is taken as given and only the chain link is checked.

That is the intended trade, and it is worth stating plainly: erasure exchanges
the ability to re-derive one entry's personal fields for the ability to erase
them at all. An attacker who could write to the database could therefore clear
the personal fields of an entry, destroy its salt, and the chain would still
verify. They would be limited to erasure, not substitution: they cannot put a
different `subject_id` in place, because that would have to reproduce the
digest, and after erasure there is no salt with which to make it do so. And the
erasure of an entry that carried personal fields is visible as an entry with a
null salt where its neighbours have one.

[ADR 0007](adr/0007-chain-the-audit-log.md) records this compromise. Its wording
predates the salted-commitment construction: the mechanism described here is
what the code implements, and it is stronger than the ADR's summary, because
`subject_id` is inside the hashed field set through the digest rather than
outside it.

## Retention

| Data | Default | Setting |
|---|---|---|
| Subject, credentials, TOTP secret, recovery codes | Kept until erasure | None. A record is kept while the account exists |
| Audit log | Kept indefinitely | `audit.retention_days`, default 0 |
| Ceremony state | 5 minutes | `webauthn.challenge_ttl` |
| Throttle counters | Swept once stale | `throttle.window`, and the janitor |
| Approval requests | 24 hours from the request to decide and to redeem, then `expired` or unredeemable | `features.approval_ttl` |
| Pending erasure | 30 days, then purged | `features.erasure_retention` |
| Alerts | Kept indefinitely | None |
| Logs | Not the service's concern | The operator's log pipeline |

`audit.retention_days = 0` is the default because silently discarding audit
history is a decision an operator must take explicitly. Setting it non-zero
enables a prune, which only ever removes a contiguous prefix by sequence number
and only after a checkpoint has recorded the trim. The checkpoint commits to the
hash of the last entry removed, so verification resumes from it and the trim
cannot be carried out silently. The mechanism is described in
[MONITORING.md](MONITORING.md).

An operator with a legal obligation to retain authentication records should
leave `audit.retention_days` at 0 and prune deliberately, rather than set a
number that happens to match the obligation and then forget it.

## Data residency

The service runs where the operator puts it. It writes to one database, at the
DSN the operator configured, and nowhere else. There is no region setting
because there is no region: residency is a property of the host and the database,
both of which the operator chose.

For a deployment in the European Union, the practical residency questions are
therefore about the operator's own infrastructure: where the host is, where the
database is, where the backups go, where the logs are shipped, and whether any
of those crosses a border. None of them is a setting in this software.

What the software contributes to the answer:

- No outbound connection other than to the database. Nothing leaves the
  deployment because the service sent it somewhere.
- The static binary and the distroless image have no update check, no crash
  reporter and no analytics.
- Attestation metadata, if used, is a file the operator supplies, not a fetch.

## Article 33 and 34: a breach

Nothing in the software notifies a supervisory authority or a data subject. That
is the controller's obligation and it is not automatable.

What the software gives an operator for the assessment:

| Question the assessment asks | Where the answer is |
|---|---|
| What data was exposed? | The table above, read against what the attacker obtained |
| Was it encrypted? | The same table. A stolen database without the keyring yields no TOTP secret and no readable reference; Article 34(3)(a) treats that as relevant to whether notification of data subjects is required |
| Who accessed what, and when? | The audit log, and specifically `admin.subject_ref_revealed` for disclosures of the reference |
| Is the record trustworthy? | `GET /admin/v1/audit/verify`. Read the limits in [THREAT-MODEL.md](THREAT-MODEL.md) before relying on it against an attacker who held the host |
| Which authenticator models are affected? | The AAGUIDs, which are in clear precisely so that an operator can answer this, and which an attacker with the database can read for the same reason |

A lost keyring is a loss of availability, and Article 4(12) counts that as a
personal data breach. [TROUBLESHOOT.md](TROUBLESHOOT.md) says exactly what
becomes unavailable.

## Related documents

| Document | What it covers |
|---|---|
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | The access and erasure operations, step by step |
| [CONFIGURATION.md](CONFIGURATION.md) | `subject.seal_reference`, `logging.redact_subject_refs`, `audit.retention_days`, `features.deferred_erasure` |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What an attacker with the database, with or without the keyring, actually gets |
| [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md) | Why recovery codes are hashed |
| [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) | Why public keys are not sealed |
| [ADR 0007](adr/0007-chain-the-audit-log.md) | The audit chain and the erasure compromise |
