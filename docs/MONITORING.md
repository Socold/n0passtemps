# Monitoring

There is no metrics endpoint. The service exposes its state through two things
an operator already has: the authenticated health report, and the audit log and
alert table in the database it already backs up. This document says what to
scrape from them, what to alert on, and what to tune.

## What to scrape

### The liveness probe

```
GET /v1/health
```

Unauthenticated, one field, and it touches the database with a 2 second timeout:

```json
{"status":"ok"}
```

`200` with `ok`, or `503` with `error`. Use it for exactly what it is for: a
load balancer or container runtime deciding whether to keep sending traffic. It
carries no version, no keyring state and no certificate data, because handing
that to an unauthenticated caller is reconnaissance material; see
[ADR 0008](adr/0008-split-the-health-endpoint.md).

### The detailed report

```
GET /admin/v1/health      # needs an admin token with health.read_detailed
GET /v1/health/detail     # needs an API key
```

Both return the same `health.Report`. The first is authorised for an
administrative role, so reading it is an act by a named token; the second is on
the public surface and any API key reaches it.

```json
{
  "status": "degraded",
  "version": { "version": "1.0.0", "commit": "9f1c4e2", "build_date": "2026-09-16T11:02:41Z", "go_version": "go1.27.1" },
  "uptime_seconds": 86400,
  "database": { "status": "ok", "engine": "postgres", "latency_ms": 2 },
  "kek": { "status": "degraded", "current_version": 1, "retained_versions": 1, "rotation_overdue": true,
           "detail": "the current key has been in use for 402 days, the interval is 365" },
  "tls": { "status": "ok", "not_after": "2026-12-01T00:00:00Z", "expires_in_days": 75, "subject": "auth.example.com" },
  "audit": { "status": "ok", "head_seq": 48213 },
  "open_alerts": { "info": 3, "warning": 1, "critical": 0 },
  "features": { "lite_mode": false, "admin_rbac": true, "dual_approval": true,
                "deferred_erasure": true, "kek_rotation_reminder": true,
                "throttle": true, "admin_ui": true },
  "timestamp": "2026-09-17T08:14:02Z"
}
```

Field by field, and what to do with each:

| Field | Alert on | Why |
|---|---|---|
| `status` | Not `ok` for more than one scrape interval | `degraded` means the service still authenticates users but something needs attention. `error` means it cannot authenticate users, which in practice means the database is unreachable |
| `version.version` | A change you did not deploy | An unplanned rollback or an unexpected image pull |
| `uptime_seconds` | Resetting repeatedly | A crash loop. `Recover` turns a panic into a 500 rather than a restart, so a restart loop is the process dying, not a handler |
| `database.status` | `error`, at once. `degraded`, after a few minutes | `degraded` is a single round trip above 500ms, which means the storage is in trouble even though it answers |
| `database.latency_ms` | Trend it. A rising floor is the early signal | A stopwatch reading of one round trip, taken on the wall clock. Above 500 the database reports `degraded`. On SQLite this is dominated by the single write connection under contention |
| `kek.rotation_overdue` | `true` | The current key has been in use longer than `kek.rotation_interval`. Nothing is broken; this is a reminder. The janitor raises the `kek.rotation_overdue` alert from the same reading. The keyring file records no history, so the age is anchored on the oldest audit entry, which errs towards reporting early |
| `kek.retained_versions` | Above 1, for longer than a rotation should take | Two retained versions means a rotation is in progress or was never finished. Records still sealed under the old version are the ones to rewrap, with `POST /admin/v1/kek/rewrap`; its `versions_in_use` says when the old version can go |
| `kek.status` | `error` | `no keyring is loaded` or `the current key is not available`. Every TOTP verification and every reference reveal is failing |
| `tls.expires_in_days` | At or below 14, which the report already reports as `degraded` | Fourteen days sits outside an ACME client's thirty-day renewal window, so this only fires when automated renewal has actually stopped working |
| `tls` absent or `null` | Not an alert | TLS is terminated by a reverse proxy, whose certificate this service cannot see. Reporting nothing is honest; monitor the proxy's certificate with the proxy's tooling |
| `audit.head_seq` | Flat during working hours | The chain head not moving means nothing is being audited, which means either no traffic or a broken append path |
| `audit.status` | `error` | The chain head could not be read |
| `open_alerts.critical` | Above 0, at once | There is exactly one critical alert type and it is the audit chain |
| `open_alerts.warning` | Trend it, and page on a jump | A jump is the shape of an attack in progress |
| `features` | A change you did not make | Confirms which mode the deployment is actually in, which is the fastest way to catch a `lite_mode` that was left on |
| `last_error` | Present | The most recent component failure, as a component name and a short reason. Never a stack trace or a query |

A minimal scrape, for a monitoring system that speaks HTTP and JSON:

```bash
curl -sS --max-time 5 "$BASE/admin/v1/health" \
  -H "Authorization: Bearer $ADMIN" \
  | jq -e '
      .status == "ok"
      and .database.status == "ok"
      and .kek.status == "ok"
      and (.kek.rotation_overdue | not)
      and ((.tls // {expires_in_days: 999}).expires_in_days > 14)
      and .open_alerts.critical == 0
    ' > /dev/null || echo "n0passtemps: health check failed"
```

The report is built fresh on every call, including re-reading the certificate
from disk, so a renewal is reflected without a restart. It is not on the hot
path; a 60 second interval is ample.

### The audit log

```bash
curl -sS -G "$BASE/admin/v1/audit" -H "Authorization: Bearer $ADMIN" \
  --data-urlencode "after_seq=$LAST_SEQ" --data-urlencode 'limit=500'
```

Keyset paging with `after_seq`, taking `next_seq` from the previous page, is how
to ship the log somewhere else incrementally. `limit` is capped by
`audit.max_query_limit`, default 500.

Shipping the log off the box is worth doing for a reason beyond convenience: it
is the closest thing available to the external witness the hash chain needs. A
copy held somewhere the operator of this host cannot rewrite is what makes a
later rewrite detectable. See [ADR 0007](adr/0007-chain-the-audit-log.md) and
[THREAT-MODEL.md](THREAT-MODEL.md).

Event families worth a saved query:

| Query | Watches for |
|---|---|
| `outcome=denied` | Authorisation refusals and throttle refusals |
| `event_type=api_key.rejected` | A leaked key being probed, or a deployment running with a revoked credential. With `outcome=denied` and `resource_type` `scope`, a valid key calling outside its scopes |
| `event_type=admin.` with `outcome=denied` | A token reaching beyond its role |
| `event_type=admin_token.created` | Authority being granted. `detail.bootstrap: true` is the one-shot bootstrap command, one entry per token with its name in `detail.name`, and `detail.forced: true` is that command run with `-force` while an administrator already existed, which deserves a question every time |
| `event_type=approval.` | The dual-approval lifecycle: `approval.requested`, the decision, `approval.executed` for a redemption, and `approval.rejected` with `outcome=denied` for a refused redemption or a self-approval |
| `event_type=credential.bulk_revoked` | Every authenticator of a subject revoked in one call |
| `event_type=kek.rewrapped` | A rewrap pass, with its counts. `outcome=error` and `detail.interrupted` mean the pass stopped early |
| `event_type=credential.revoked` | Containment actions, and a rogue script |
| `event_type=webauthn.sign_count_regression` | The clone signal |
| `event_type=totp.replay_detected` | A code presented twice |
| `event_type=admin.subject_ref_revealed` | Disclosures of a subject reference |
| `event_type=erasure.` | The Article 17 lifecycle |
| `event_type=audit.chain_broken` | The chain failing verification |

### Chain verification

```bash
curl -sS -o /tmp/verify.json -w '%{http_code}' \
  "$BASE/admin/v1/audit/verify?from_seq=1" -H "Authorization: Bearer $ADMIN"
```

`200` when intact, `409` when broken, so a check reading only the status code
does not miss it. The result is recorded as `audit.chain_verified` or
`audit.chain_broken`, and a broken chain raises the critical alert, so a
verification cannot be performed quietly.

Verification is linear in the number of entries and gets slower for the lifetime
of the deployment. Measure it before scheduling it. On a large log, verify in
slices with `from_seq` rather than the whole chain every night.

## The ten alert types

`internal/alerts/alerts.go` declares exactly ten conditions. The list is short
on purpose: an alert stream nobody reads is worse than no alert stream, because
it creates the belief that someone would notice. Each condition is either
evidence of an attack in progress, evidence that a control has failed, or a
state that will lock a user out if it is left alone.

Repetition collapses by fingerprint, a truncated SHA-256 over a domain
separator, the type, the tenant, the subject and the resource. A brute-force
attempt therefore produces one row with a rising `occurrences` count, which is
what an operator needs to see, instead of one row per request. The fingerprint
covers neither the timestamp nor the detail payload, because both change on
every occurrence and including either would produce exactly the flood the
fingerprint exists to collapse.

Severity is a property of the condition, not of the occurrence, so a caller
cannot file the same condition at three different levels.

| # | Type | Severity | What it means | Response |
|---|---|---|---|---|
| 1 | `auth.failure_burst.subject` | warning | `throttle.max_failures_per_subject` failures against one subject inside the window. The shape of a targeted guess | Read the subject's audit history. If the failures are the user's own, reset the throttle. If they are not, lock the subject and treat it as a suspected compromise |
| 2 | `auth.failure_burst.ip` | warning | `throttle.max_failures_per_ip` failures from one normalised network. The shape of a spray across many accounts. The resource is the network, a `/64` for IPv6 | Check how many distinct subjects are involved. One subject from one address is a user with a broken client; many subjects from one address is an attack. Block at the firewall; the per-address bucket has no reset route |
| 3 | `webauthn.sign_count_regression` | warning | An authenticator's signature counter failed to advance. The documented signal for two copies of a credential private key in use | Check the platform. Apple and Android synchronised passkeys report a constant zero, and the service suppresses that case, so a regression here is from an authenticator that does keep a counter and is worth investigating. The assertion was not refused: this alert is the only durable record. Warning rather than critical because treating every regression as an emergency trains an operator to ignore the type |
| 4 | `credential.bulk_revoked` | warning | Revocations by one administrator above `throttle.admin_revoke_burst`. Revocation is final, so a run of them is either an incident response or an attacker with an administrative token denying service | Identify the actor from the `actor_id` in the detail. If it is not a planned response, revoke that administrative token. The revocations cannot be undone; the affected subjects re-enrol. See [ADR 0010](adr/0010-revocation-is-final.md) |
| 5 | `recovery.exhausted` | warning | A subject has no recovery codes left. They are the last way back in when every authenticator is lost | Reissue a batch and get it to the user. This is a warning rather than info because the subject is one lost key away from having no route in at all |
| 6 | `recovery.low` | info | A subject is at or below `recovery.low_watermark`, default 3 | Prompt the user to reissue. Early enough that nothing is urgent |
| 7 | `api_key.rejected` | warning | An unknown or revoked API key presented repeatedly. Either a leaked key being tried, or a deployment still running with a credential someone revoked | Compare the selector in the detail against `GET /admin/v1/api-keys`. A selector that matches a revoked key is a deployment nobody updated; one that matches nothing is a guess. The verifier half is never in the alert row, because an alert row is read by people and a secret in it is a secret in a screenshot |
| 8 | `admin.denied` | warning | An administrative token was denied a permission its role does not hold. Either a misconfigured integration or a stolen token being explored | Read the `admin.denied` audit entries for that token. A single denial after a role change is a misconfiguration; a sequence probing different permissions is not |
| 9 | `audit.chain_broken` | **critical** | The hash chain failed verification. The audit log is the record every other investigation rests on, which is why this is the one condition that is critical by itself | Stop writing to the database, take a filesystem copy, and work through the procedure in [ADMIN-GUIDE.md](ADMIN-GUIDE.md). Do not attempt a repair: a routine that recomputed the chain would be exactly the tool an attacker needs |
| 10 | `kek.rotation_overdue` | info | A key encryption key is past `kek.rotation_interval`. Nothing is broken yet, which is why it is informational. Raised by the janitor pass rather than by a request | Plan a rotation: `n0passtemps-wizard kek rotate`, restart, then `POST /admin/v1/kek/rewrap`. It is an explicit operator action and the service will never perform one on its own. Requires `features.kek_rotation_reminder`; see [ADMIN-GUIDE.md](ADMIN-GUIDE.md#rotating-the-keyring) |

Reading them:

```bash
curl -sS -G "$BASE/admin/v1/alerts" -H "Authorization: Bearer $ADMIN" \
  --data-urlencode 'severity=critical' | jq -r \
  '.alerts[] | "\(.severity) \(.alert_type) x\(.occurrences) first=\(.first_seen_at) \(.summary)"'
```

`?include_acknowledged=true` includes closed rows. `?subject_id=`, `?severity=`
and `?alert_type=` narrow. `?after=` pages by identifier.

Acknowledging closes a row:

```bash
curl -sS -X POST "$BASE/admin/v1/alerts/$ALERT/acknowledge" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json'
```

Note what acknowledgement does to deduplication. The uniqueness index on the
fingerprint is partial, `WHERE acknowledged_at IS NULL`, so once a row is
acknowledged the same condition recurring creates a new row rather than
incrementing the old one. That is what makes a recurrence visible; it also means
acknowledging early turns one row with a rising count into a series of rows.
Acknowledge when the condition has been dealt with, not to clear the list.

Alerts have no automatic expiry. They accumulate, and acknowledged rows stay.
On a long-lived deployment the table grows; there is no prune for it.

Every alert is also logged, at the level its severity deserves, so a deployment
that ships logs but does not query the alert table still sees the critical ones:

| Severity | Log level |
|---|---|
| critical | error |
| warning | warn |
| info | info |

## Log fields worth indexing

`internal/logging/logging.go` declares the field names as constants so that a
query written against one log line works against all of them. Structured JSON on
standard output is the default: there is no log file and no rotation, because
writing to standard output and letting the supervisor handle the rest is what
both systemd and every container runtime expect.

| Field | On | Index it for |
|---|---|---|
| `request_id` | Everything | The single most useful field. It is the one piece of information a refused request hands the caller, and it joins the log line, the audit entry and the problem response |
| `route` | Every request | The matched pattern, not the concrete path, so a thousand requests to one route produce one label instead of a thousand, and no subject reference reaches the field |
| `method` | Every request | |
| `status` | Every request, and every problem response | The rate of 401 and 429 is the shape of an attack. A rise in 500 is a fault |
| `duration_ms` | Every request | Percentiles. A rising p99 on the assertion routes is the database |
| `bytes` | Every request | |
| `source_ip` | Every request, when `logging.include_source_ip` is true | Personal data. The setting is a deliberate choice rather than a default for that reason. Removed from the record entirely when false, not blanked |
| `tenant_id` | Every authenticated request | |
| `actor_type` | Every authenticated request | `api_key` or `admin`. Separates application traffic from operator traffic |
| `actor_id` | Every authenticated request | The credential's identifier, never its secret. The blast radius of a specific key |
| `role` | Every administrative request | |
| `subject_ref` | Where a reference is logged | Replaced with `ref:` plus six bytes of a domain-separated digest when `logging.redact_subject_refs` is true, which is the default. Enough to correlate two lines about the same person without the logs becoming a list of users. It is not a security control: the input space for an email address is small enough that a determined holder of the logs could confirm a guess |
| `subject_id` | Where a subject is logged | The internal identifier, which is pseudonymous |
| `event_type` | Audit-adjacent lines | |
| `outcome` | Audit-adjacent lines | |
| `credential_id` | Credential operations | |
| `problem_type` | Every problem response | The URN, such as `urn:n0passtemps:error:throttled`. Branch on it rather than on the title |
| `reason` | Every problem response with an internal cause | The real reason a request was refused. It is logged and never sent |
| `alert_type`, `severity`, `fingerprint`, `occurrences` | Every raised alert | |
| `panic`, `stack` | A handler panic | Logged, never sent. A panic line is always worth an alert |

Two things never reach a log line at any level: a secret, and an unredacted
subject reference when redaction is on. Redaction is enforced in the handler's
`ReplaceAttr` rather than at the call site, so a new call site cannot forget it,
and `logging.Secret` renders as `[redacted]` through `LogValue`, `String`,
`GoString`, `MarshalText` and `MarshalJSON`, so that a struct holding one is
safe whether it is logged as an attribute, printed with `%#v` or serialised by
the JSON handler.

The service never logs an administrative token. The first one is printed by the
one-shot `-bootstrap-admin` command to the operator's terminal, not by the
running process, so a first start's log needs no special handling. What a fresh
deployment does log, at warning level and at every start until an administrator
exists, is `no administrator exists yet; create the first with:
n0passtemps-server -config <path> -bootstrap-admin`, with `-admins 2` appended
when dual approval is on.

A useful starting set of log-based alerts:

| Condition | Query shape |
|---|---|
| Handler panic | `panic` field present |
| Audit append failing | message `audit append failed`, level error. An audit log that has started silently dropping entries is itself a security incident |
| Throttle state unavailable | message `throttle state unavailable`, level warn. The limiter fails open on a read error, deliberately, so a database hiccup does not become an outage. A run of these means the limits are not being applied |
| Rising 401 rate | `status=401` grouped by `route` |
| Rising 429 rate | `status=429`, grouped by `route` and `source_ip` |
| Any 500 | `status>=500` |
| Credential last-use not recorded | message `api key last-use timestamp not recorded`, level warn |
| Janitor failing | message `janitor pass completed with errors`, level error. A pass that removes nothing logs at debug, and a pass that removed something logs at info with the counts `challenges`, `throttles`, `approvals`, `erasures` and `audit_pruned` |

## Database tuning

### Both engines

The tables that grow without bound are `audit_log` and `alerts`. Everything else
is proportional to the number of subjects, and the janitor keeps the ephemeral
tables small.

`internal/janitor` runs every `features.janitor_interval`, default 5 minutes,
and sweeps five things: WebAuthn challenges whose ceremony was abandoned,
throttle buckets whose window has long passed, approval requests nobody decided,
erasure requests whose `purge_after` has closed, and audit entries past
`audit.retention_days`. Most sweeps span every tenant, because the janitor acts
on behalf of none of them.

Three details worth knowing:

- Each sweep is independent, and a failure in one does not stop the others. A
  janitor that stopped after its first error would be one that silently stopped
  working.
- The throttle sweep does not clear a bucket whose `blocked_until` is still in
  the future, because that would turn the janitor into a way to unlock an
  account by waiting.
- It runs in-process rather than as a cron job, so a correctly deployed service
  is a maintained service. The cost is that a deployment running several
  replicas performs each sweep once per replica. Every sweep is idempotent and
  expressed as a conditional delete, so the duplication is wasteful rather than
  harmful.

### Audit log growth

Sizing, per entry: the fixed columns, a 16-byte salt, three 32-byte digests, and
the `detail` JSON, which is where the variance is. Reckon on roughly 400 bytes
to 1 KiB per entry, plus four indexes:

```
al_tenant_time_idx   (tenant_id, occurred_at)
al_event_idx         (tenant_id, event_type, occurred_at)
al_subject_idx       (tenant_id, subject_id, occurred_at)
al_entry_hash_uq     (entry_hash) unique
```

One authentication produces two entries on the happy path, the ceremony start
and its completion, plus more on any failure or signal. A deployment doing ten
thousand logins a day is therefore adding something in the order of twenty
thousand entries a day, and a few tens of megabytes a month with the indexes.

Two consequences beyond disk:

- **Appends serialise.** Reading the chain head inside the writing transaction
  means one writer at a time on the hottest table in the system. On SQLite that
  is the single write connection; on PostgreSQL it is an advisory lock. This
  bounds the audited request rate, and it is the first thing to measure when
  throughput matters. [ADR 0007](adr/0007-chain-the-audit-log.md) records the
  cost.
- **Verification gets slower for the lifetime of the deployment.** Linear in the
  number of entries.

### The retention checkpoint mechanism

`audit.retention_days` defaults to 0, meaning entries are kept forever, because
silently discarding audit history is a decision an operator must take
explicitly. Setting it non-zero enables `PruneAuditLog`, which is not a plain
`DELETE`.

The table's delete guard refuses any removal above a recorded watermark:

```sql
CREATE TRIGGER audit_log_delete_guard
BEFORE DELETE ON audit_log
WHEN OLD.seq > COALESCE((SELECT MAX(pruned_through_seq) FROM audit_checkpoints), 0)
BEGIN
    SELECT RAISE(ABORT, 'audit_log entries may only be removed below a recorded retention checkpoint');
END;
```

So a prune has to happen in this order, all inside one transaction:

1. Find the newest entry older than the cut, by sequence number. Pruning is by
   sequence rather than by timestamp so the chain is trimmed as a contiguous
   prefix: deleting a scattered set would break verification after every gap,
   whereas trimming a prefix only moves the point a verifier starts from.
2. Append an audit entry recording the trim, with
   `detail.action = "retention_prune"`, `pruned_through_seq` and the entry
   count. The record of the trim is written before the trim happens, so a log
   that has been trimmed always carries the evidence of having been trimmed.
3. Insert an `audit_checkpoints` row committing to `pruned_through_seq` and
   `pruned_through_hash`, the hash of the last entry removed. That hash is what
   verification resumes from.
4. Delete the entries at or below that sequence number, which the guard now
   permits.

`audit_checkpoints` is itself append-only, guarded by two triggers, and
`pruned_through_seq` only ever moves forward: a checkpoint that lowered it would
re-expose already deleted rows to the delete guard.

The consequence for monitoring: after a prune, verifying from `from_seq = 1`
reports a break, because sequence 1 no longer exists and there is nothing for the
first surviving entry to chain onto in the table. Verify from above the
watermark:

```bash
sqlite3 n0passtemps.db 'SELECT MAX(pruned_through_seq) FROM audit_checkpoints'
# then
curl -sS "$BASE/admin/v1/audit/verify?from_seq=$((WATERMARK + 1))" \
  -H "Authorization: Bearer $ADMIN"
```

### SQLite specifics

| Concern | Note |
|---|---|
| Write concurrency | One write connection, always. Under load, writes queue in Go rather than colliding in the engine, so `SQLITE_BUSY` becomes a short wait. `database.busy_timeout`, default 5s, is the ceiling on that wait, and reaching it means the write queue is saturated |
| Read concurrency | `database.max_open_conns` bounds the read pool. 8 is a reasonable default; raising it does not help write throughput at all |
| WAL growth | `journal_mode(WAL)` with `synchronous(NORMAL)`. A crash can lose the tail of the most recent transactions but cannot corrupt the database. The `-wal` file grows until a checkpoint; SQLite checkpoints automatically at 1000 pages by default, and a long-running read transaction can hold one off. Watch the size of `n0passtemps.db-wal` |
| Filesystem | Must support WAL. Some network mounts do not, and the symptom is a startup refusal saying `pragma journal_mode is "delete", expected "wal"` |
| `VACUUM` | Not run automatically. After a large prune or a purge of many subjects the file does not shrink. Run it during a maintenance window, with the service stopped |
| Backup | `sqlite3 file.db ".backup '/dest.db'"` is consistent against a live writer. Copying the file alone is not, because of the WAL |
| Horizontal scale | None. SQLite does not support concurrent writers across processes or pods. One instance, one file |

### PostgreSQL specifics

| Concern | Note |
|---|---|
| Pool size | `database.max_open_conns`, default 8, becomes `pgxpool.MaxConns`. Multiply by the replica count and keep the total below the server's `max_connections`, or the surplus fails intermittently under load rather than at startup |
| Connection lifetime | `database.conn_max_lifetime`, default 30m, becomes `MaxConnLifetime`. It matters in front of a connection proxy, which may move the backend under a long-lived connection |
| The advisory lock | Held only for the audit append. A long-running transaction that blocks it stalls every audited request, so watch `pg_locks` for an advisory lock with waiters |
| Autovacuum | `audit_log` is append-mostly, so it accumulates little bloat, but the index on `(tenant_id, subject_id, occurred_at)` is updated by every erasure. After a large erasure run, `REINDEX` it |
| JSONB | `detail` and `payload` are JSONB, which is decomposed: keys come back in the server's order. Compare them as documents, never as strings. The chain is unaffected because the implementation canonicalises through the server before hashing |
| `TIMESTAMPTZ` | Microsecond resolution. `audit.Prepare` truncates before hashing, which is why an entry written with nanosecond precision still verifies when read back |
| Backup | `pg_dump -Fc`, which is consistent against a live writer. A dump and restore preserves the chain |
| Horizontal scale | Two or more replicas share the database and the limits, because the throttle holds no state of its own. The audit append serialises across all of them through the advisory lock |
| TLS | `sslmode=verify-full` for anything that crosses a network. `sslmode=disable` is accepted towards loopback or a Unix socket, and towards another host only with `database.allow_plaintext`, which is for a private container network on the same host. The validator refuses a DSN with no `sslmode` at all, because libpq's default of `prefer` falls back to plaintext without reporting it |

## A monitoring baseline

For an operator who wants a starting point rather than a menu:

| Check | Interval | Severity |
|---|---|---|
| `GET /v1/health` returns 200 | 10s, from the load balancer | Page |
| `open_alerts.critical > 0` | 60s | Page |
| `database.status != "ok"` | 60s | Page |
| `kek.status != "ok"` | 60s | Page |
| Log `panic` field present | streaming | Page |
| Log message `audit append failed` | streaming | Page |
| `GET /admin/v1/audit/verify` returns 409 | daily, in slices | Page |
| `tls.expires_in_days <= 14` | hourly | Ticket |
| `kek.rotation_overdue == true` | daily | Ticket |
| `open_alerts.warning` rising | 60s | Ticket |
| `audit.head_seq` flat for an hour during working hours | hourly | Ticket |
| `status == "degraded"` | 60s | Ticket |
| 401 or 429 rate above baseline | streaming | Ticket |
| Disk free on the data volume below 20 percent | 5m | Ticket |

## Related documents

| Document | What it covers |
|---|---|
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | What to do when one of these fires |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | Symptom-first diagnosis |
| [CONFIGURATION.md](CONFIGURATION.md) | `audit.retention_days`, `features.janitor_interval`, the throttle thresholds |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Why detection needs an external witness |
| [ADR 0008](adr/0008-split-the-health-endpoint.md) | Why the liveness probe says so little |
