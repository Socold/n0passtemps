# Getting the logs into a SIEM

This service emits two streams. They are not alternatives, they answer different
questions, and a deployment that ships only one will find out which when it
needs the other.

| Stream | Where | What it is for | Guarantee |
|---|---|---|---|
| **Operational log** | JSON on standard output | Detection and investigation. Every request, every refusal, every panic, with source addresses and reasons | Best effort. It is a log. A crash between the event and the write loses the line |
| **Audit log** | A table, readable at `GET /admin/v1/audit`, shipped by `audit.sink` | The record of what was done and by whom. Hash-chained, so a later rewrite is detectable | Written in the same transaction as the change wherever the store allows it. Nothing is dropped |

The short version: send the operational log to the SIEM the way the SIEM
already collects logs, and configure `audit.sink` as well, pointing at somewhere
the operator of this host cannot rewrite. The first is what a detection rule
runs against. The second is what makes the first trustworthy, and there is no
way to get that property out of a log collector the same root account
administers. See
[ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md).

## Syslog, and why there is no syslog client here

There is no `logging.format = "syslog"`, no facility setting and no remote log
host. That is a decision rather than a gap, and it is the same one systemd and
every container runtime already made: a service writes structured lines to
standard output and the supervisor decides where they go.

Under systemd, the unit's output is already in the journal, and the journal
already forwards:

```ini
# /etc/systemd/journald.conf.d/forward.conf
[Journal]
ForwardToSyslog=yes
```

Then, in rsyslog, select the unit and send it on. `@@` is TCP; `@` is UDP, which
loses lines silently under load and should not be used for an authentication
log:

```
# /etc/rsyslog.d/30-n0passtemps.conf
if $programname == 'n0passtemps-server' then {
  action(type="omfwd" target="siem.internal" port="6514" protocol="tcp"
         StreamDriver="gtls" StreamDriverMode="1"
         StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="siem.internal")
  stop
}
```

Under Docker, Kubernetes or Nomad, point the runtime's log driver or the node's
collector at the SIEM and change nothing here.

What an in-process syslog client would add is a network write on a code path
that must not block, or a second queue to stop it blocking, in exchange for a
framing that carries less than the JSON already does: RFC 5424 structured data
would have to re-encode fields the JSON handler emits natively, and a receiver
would have to parse them back out. If a deployment genuinely needs RFC 5424
framing, the collector in front of the SIEM produces it from these lines and
does so better, because it already handles batching, retries and back pressure.

The one thing worth checking on a syslog path is the message size limit. An
operational line stays well under 2 KiB, but rsyslog's default
`$MaxMessageSize` of 8 KiB and some appliances' 1 KiB will truncate a line
carrying a long problem detail. Truncated JSON parses as nothing, so raise the
limit rather than discovering the loss during an incident.

## Field mapping

`internal/logging/logging.go` declares the field names as constants so a query
written against one line works against all of them.
[MONITORING.md](MONITORING.md#log-fields-worth-indexing) says what each field is
worth indexing for. What follows is the same set, mapped to the two schemas a
SIEM is likely to normalise into. Nothing in this service emits ECS or OCSF
directly: the mapping belongs in the collector, where it can be changed without
a release.

| This service | ECS 8.x | OCSF 1.x (Authentication, class 3002) |
|---|---|---|
| `request_id` | `trace.id` | `metadata.correlation_uid` |
| `route` | `url.path` (the matched pattern, not the concrete path) | `http_request.url.path` |
| `method` | `http.request.method` | `http_request.http_method` |
| `status` | `http.response.status_code` | `http_request.http_status` |
| `duration_ms` | `event.duration` (nanoseconds; multiply) | `duration` |
| `bytes` | `http.response.bytes` | — |
| `source_ip` | `source.ip` | `src_endpoint.ip` |
| `tenant_id` | `organization.id` | `metadata.tenant_uid` |
| `actor_type` | `user.roles` or a custom field | `actor.invoked_by` |
| `actor_id` | `user.id` of the calling credential | `actor.user.uid` |
| `subject_id` | `user.target.id` | `user.uid` |
| `subject_ref` | `user.target.name`, redacted by default | `user.name`, redacted by default |
| `event_type` | `event.action` | `activity_name` |
| `outcome` | `event.outcome` | `status` |
| `credential_id` | `user.target.id` of the authenticator | `user.credential_uid` |
| `problem_type` | `error.type` | `status_detail` |
| `reason` | `error.message` | `status_detail` |
| `alert_type`, `severity` | `rule.name`, `event.severity` | `severity_id` |
| `panic`, `stack` | `error.stack_trace` | — |

Three cautions that matter more than the table.

**`subject_ref` is personal data and is redacted by default.** With
`logging.redact_subject_refs` on, the field holds `ref:` plus six bytes of a
domain-separated digest, which correlates two lines about one person without
making the logs a list of users. Turning redaction off to make the SIEM more
useful moves email addresses into the SIEM's retention, its backups and its
access model. That is a decision for whoever owns the SIEM, not a default.

**`source_ip` is removed entirely when `logging.include_source_ip` is false**,
not blanked. A rule that keys on its presence will see nothing rather than an
empty string.

**`route` is the matched pattern.** A rule counting distinct paths will see one
value per route, which is the point: a thousand requests to
`/v1/webauthn/assert/{subject_ref}` produce one label rather than a thousand,
and no subject reference reaches the field.

## The audit event vocabulary

The names are dotted and hierarchical, so a rule selects a family with a prefix
match: `approval.` is the whole dual-approval lifecycle. They are stable by
construction, because they are written into a hash-covered record and renaming
one would change the meaning of history.

This is the closed set. A name not on this list is not emitted by this version,
and `internal/audit/events_catalogue_test.go` fails the build if the two ever
disagree.

| Event type | Raised when |
|---|---|
| `admin.auth_failed` | An administrative credential was refused |
| `admin.authorised` | An administrative sign-in succeeded. `detail.method` says whether it was a token or a passkey |
| `admin.denied` | An authenticated administrator was refused an action by RBAC |
| `admin.subject_ref_revealed` | A pseudonymous subject identifier was turned back into the reference the application chose |
| `admin.subjects_listed` | The list of people was read |
| `admin_credential.enrolled` | An operator added a console passkey |
| `admin_credential.revoked` | A console passkey was withdrawn |
| `admin_token.created` | An administrative token was minted. `detail.bootstrap: true` is the one-shot command |
| `admin_token.revoked` | An administrative token was withdrawn |
| `admin_token.rotated` | An administrator replaced their own token |
| `alert.acknowledged` | An alert was acknowledged |
| `alert.raised` | The alert engine raised a condition |
| `api_key.created` | A caller credential was minted |
| `api_key.rejected` | A caller credential was refused |
| `api_key.revoked` | A caller credential was withdrawn |
| `api_key.rotated` | A caller credential was replaced by a successor with a bounded overlap |
| `approval.executed` | An approved request was redeemed |
| `approval.expired` | A request for a second approval timed out |
| `approval.granted` | A second administrator approved |
| `approval.rejected` | A second administrator refused, or a redemption was refused |
| `approval.requested` | An operation was held for a second administrator |
| `audit.chain_broken` | Verification found the chain does not hold |
| `audit.chain_verified` | Verification found the chain holds |
| `credential.bulk_revoked` | Every authenticator of a subject was revoked in one call |
| `credential.labelled` | An authenticator was renamed |
| `credential.revoked` | An authenticator was revoked |
| `enrolment_ticket.issued` | An enrolment ticket was minted |
| `enrolment_ticket.redeemed` | A ticket was redeemed |
| `enrolment_ticket.rejected` | A ticket was refused. `detail` carries the reason, which the caller is never told |
| `enrolment_ticket.revoked` | A ticket was withdrawn before use |
| `erasure.cancelled` | A deletion request was cancelled |
| `erasure.entries_redacted` | The personal fields of a subject's history were removed |
| `erasure.purged` | A subject's record was deleted |
| `erasure.requested` | Deletion was requested |
| `kek.loaded` | The keyring was loaded at start |
| `kek.rewrapped` | A rewrap pass ran. `outcome=error` with `detail.interrupted` means it stopped early |
| `kek.rotated` | A new key version was made current |
| `recovery.consumed` | A recovery code was used |
| `recovery.exhausted` | The last recovery code was used |
| `recovery.issued` | Recovery codes were issued |
| `recovery.rejected` | A recovery code was refused |
| `service.migration_applied` | A schema migration ran |
| `service.started` | The service started |
| `service.stopping` | The service began shutting down |
| `subject.created` | A person was added |
| `subject.locked` | Sign-in was blocked for a person |
| `subject.status_changed` | A person's status changed |
| `subject.unlocked` | Sign-in was allowed again |
| `throttle.reset` | A limit was cleared |
| `throttle.tripped` | A limit was reached |
| `totp.confirmed` | A TOTP enrolment was confirmed |
| `totp.enrolled` | A TOTP secret was issued |
| `totp.rejected` | A TOTP code was refused |
| `totp.replay_detected` | A TOTP code was presented twice |
| `totp.revoked` | A TOTP enrolment was removed |
| `totp.verified` | A TOTP code was accepted |
| `webauthn.assertion.completed` | An assertion ceremony succeeded |
| `webauthn.assertion.rejected` | An assertion ceremony was refused |
| `webauthn.assertion.started` | An assertion ceremony began |
| `webauthn.binding_changed` | The binding of an authenticator changed |
| `webauthn.registration.completed` | A registration ceremony succeeded |
| `webauthn.registration.rejected` | A registration ceremony was refused |
| `webauthn.registration.started` | A registration ceremony began |
| `webauthn.sign_count_regression` | An authenticator's signature counter went backwards, which is the clone signal |

`outcome` is one of `success`, `denied` or `error`, and a rule should branch on
it rather than on the event name: `webauthn.assertion.rejected` and
`webauthn.assertion.completed` with `outcome=error` are different situations.

## Receiving the audit sink

`audit.sink.endpoint` POSTs batches of JSON with a bearer credential, which is
the shape a Splunk HTTP Event Collector, an Elastic ingest endpoint, a Datadog
logs intake or thirty lines of anything else already speak. What the receiver
has to do is short, and the details are in
[ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md) and the
package documentation of `internal/auditsink`:

- **Branch on `kind` first.** A body is either a `batch`, which carries
  `entries`, or a `heartbeat`, which carries the head of the chain and no
  entries. A heartbeat stored as a batch is an empty delivery filed as though it
  were one; a batch read as a heartbeat drops entries. A body with no `kind` is
  a batch, which is what the field's absence meant before it existed.
- **De-duplicate on `seq`.** Delivery is at least once by design. The watermark
  moves only after an acknowledgement, so a process that dies in between resends
  the batch. The opposite order would give at most once, which is a silent hole
  in the witness.
- **Acknowledge only what is stored.** A 2xx is taken as durable, for a
  heartbeat as much as for a batch.
- **Follow `prev_hash`, not the numbering.** Each entry names the hash of the
  one before it, and that is what says the run is whole. `seq` increases and is
  **not** contiguous: on PostgreSQL it comes from a sequence, which spends a
  number even when the transaction that drew it rolls back, so an ordinary log
  has holes no entry will ever fill. Given 41, 42, 44 the question is whether 44
  chains onto 42. If it does, 43 was never written and nothing is missing. If it
  does not, something between them has gone. A receiver that alerts on the
  numbering alone will report every cancelled request as tampering.
  `auditsink.CheckSequence` is that check written once, so it can be quoted
  rather than described.
- **Alert on silence.** The sender POSTs a heartbeat when nothing has reached
  the receiver for five minutes, so a receiver that has heard nothing for longer
  than that is looking at a path somebody cut and not at a quiet weekend. The
  two are the ends of one attack: stop the deliveries, act, remove the tail of
  the local log, let the deliveries resume. The heartbeat carries `head_seq` and
  `head_hash`, so keeping them lets a receiver say later that the chain it is
  now offered does not continue the one it was told about.
- **Expect no personal data.** The projection is exactly the fields the chain
  hash commits to. `subject_id`, `source_ip` and `detail` are not among them; a
  salted digest of all three travels instead, and the salt never leaves the
  database. A receiver cannot widen what a deployment exposes, which is what
  makes shipping to a third party defensible in the first place.
- **A trim announces itself in the chain.** Retention pruning appends an entry
  before it removes anything, and that entry commits to the sequence number and
  the entry hash it stopped at. The receiver sees it as an
  `event_type=audit.chain_verified` entry from the `system` actor; what the
  marker names is in `detail`, which stays in the database and is read at
  `GET /admin/v1/audit`. It is the only thing that makes a run starting above
  the boundary legitimate, so a receiver holding entries below a boundary the
  deployment later announces should keep them: they are the part the deployment
  no longer has.

A receiver that verifies the chain rather than merely storing it is the
arrangement that actually detects a rewrite. Storing alone still helps, since a
rewritten local chain will not reproduce hashes somebody else already holds, but
it means the detection happens whenever a person thinks to compare.

## A starting set of rules

Detection rules belong in the SIEM, not here, but these are the ones a
deployment with no rules yet should have first. The log-based conditions and the
response each one warrants are in
[MONITORING.md](MONITORING.md#the-alert-types).

| Rule | Shape |
|---|---|
| Authority granted | `event_type=admin_token.created`. Every one deserves a question, and `detail.forced: true` deserves two |
| The chain stopped holding | `event_type=audit.chain_broken`, or the sink falling behind, or an entry at the receiver that does not chain onto the one before it |
| The witness stopped hearing | Nothing from a deployment for more than five minutes, neither a batch nor a heartbeat. It is the shape of an outbound path cut for the duration of an intrusion |
| Someone looked up who has an account | `event_type=admin.subject_ref_revealed`, grouped by `actor_id`. Volume is the signal, not any single entry |
| A credential being probed | `event_type=api_key.rejected` grouped by `source_ip` |
| An administrator reaching past their role | `event_type=admin.denied` grouped by `actor_id` |
| Containment, or a rogue script | `event_type=credential.bulk_revoked`, and the rate of `credential.revoked` |
| The clone signal | `event_type=webauthn.sign_count_regression` |
| A code reused | `event_type=totp.replay_detected` |
| Audit writes failing | Message `audit append failed` at error level in the operational log. An audit log that has started dropping entries is itself an incident |
| Limits not being applied | Message `throttle state unavailable` at warn level. The limiter fails open on a read error, deliberately |
| Handler panic | The `panic` field present |

## Related documents

- [MONITORING.md](MONITORING.md), what to scrape, the alert types, the log
  fields and what each is worth indexing for
- [CONFIGURATION.md](CONFIGURATION.md#logging), `logging` and `audit.sink`
- [THREAT-MODEL.md](THREAT-MODEL.md), "Detection depends on somebody reading"
- [ADR 0007](adr/0007-chain-the-audit-log.md), why the chain exists
- [ADR 0016](adr/0016-ship-the-audit-chain-to-an-external-witness.md), why a
  copy has to leave the operator's reach
