# Administrator guide

Written for the person who operates the deployment. Every command below is a
real route from `internal/api/router.go`; every permission is the one the route
is mounted under in `internal/rbac/rbac.go`.

Throughout, `$ADMIN` is an administrative token and `$BASE` the service origin:

```bash
export BASE="https://auth.example.com"
export ADMIN="npa_3f9a2c1d8b7e6f5a.Zm9vYmFyYmF6cXV1eHF1dXhmb29iYXJiYXo"
```

The administrative surface is guarded by three layers, in this order: the
network allow list `admin.ip_allow_list`, the token, and the permission. A
caller outside the allow list gets 404, not 403, so the surface does not
announce itself.

There are two ways in, and they authenticate differently. `/admin/v1` takes the
token as a bearer credential, which is what this guide uses. `/admin`, when
`admin.ui_enabled` is true, is the server-rendered interface: it takes the same
token pasted into `GET /admin/sign-in` and then carries a session cookie bounded
by `admin.session_ttl`. Both sit behind the same network allow list.

## The three roles

| Role | Can read | Can also do | Cannot |
|---|---|---|---|
| `admin_auditor` | Subjects, credentials, the audit log, chain verification, alerts, the approval queue, the detailed health report, the credential inventory | Nothing. It changes no state at all | Acknowledge an alert. An auditor who can quietly clear an alert can quietly cover a trace |
| `admin_operator` | Everything an auditor can | Lock and unlock a subject, revoke one credential, reissue recovery codes, reset a throttle, acknowledge an alert | Mint or revoke any credential, decide an approval, request or cancel an erasure, revoke every credential of a subject in one call, rewrap the keyring |
| `admin_full` | Everything | Everything | Nothing |

The full matrix, all twenty-five permissions against all three roles, is in
[RBAC.md](RBAC.md).

With `features.admin_rbac = false`, which `features.lite_mode` implies, every
valid role carries full authority. An unrecognised role still holds nothing.

## The first administrative token

The running service never creates one and never prints one. On a fresh
deployment it starts, serves traffic, and logs a warning at every start until an
administrator exists. With dual approval on, the hint ends in `-admins 2`:

```
no administrator exists yet; create the first with: n0passtemps-server -config <path> -bootstrap-admin -admins 2
```

The first tokens are created by a separate, one-shot run of the same binary,
with the same configuration, keyring, pepper and database as the service:

```bash
# On a host, as the service account, with the service's environment.
n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2

# With compose. The image's entrypoint already carries -config.
docker compose run --rm n0passtemps -bootstrap-admin -admins 2
```

```

bootstrap-1  npa_3f9a2c1d8b7e6f5a.Zm9vYmFyYmF6cXV1eHF1dXhmb29iYXJiYXo
bootstrap-2  npa_8d1c4b7a2e9f6035.cXV1eGZvb2JhcmJhenF1dXhmb29iYXJiYXo

Each token is shown once. Only a digest is stored, so none can be displayed
again. Put them in a password manager now, one per person.
```

The tokens go to standard output, one `name  token` line each, and the notice to
standard error. The command creates tokens named `bootstrap-1` onwards with the
role `admin_full` and `created_by` recorded as `system:bootstrap`, audits each
as `admin_token.created` with `detail.bootstrap: true`, the token's name and
actor type `system`, and exits. It does not start a listener, so it can run
while the service is up.

### Why two

`-admins N` sets how many tokens are created, from 1 to 5, and defaults to 1.
With `features.dual_approval` on, which is the default outside lite mode, create
two and give them to two different people.

With dual approval on, minting an administrative token through the API is held
for a second administrator. A deployment with exactly one administrator
therefore cannot create its second: nobody exists to approve the request, and it
would sit in the queue until it expired.

The tempting fix is an exemption in the API that lets a sole administrator mint
without approval. That exemption is reachable by an attacker. One rogue
administrator revokes the others, becomes the sole administrator, mints a token
they control, and from then on approves their own requests; the two-person rule
is gone. So the API keeps no exemption at all, and the initial quorum is created
by this command instead, by whoever can run it. That person already holds the
configuration, the keyring and the database, so the ability grants them nothing
they did not have. The ceiling of five is deliberate: the command establishes a
quorum, it does not provision a team, and everyone after the quorum is minted
through the API, where the action is attributed to a named administrator.

When the command leaves a single administrator under dual approval it says so:

```
Dual approval is on and this deployment now has a single administrator.
Minting another through the API needs a second administrator to approve it,
and there is none. Run this command again with -force -admins 1, or start
over with -admins 2, and give the second token to a different person.
```

`-force -admins 1` is therefore also the recovery path for a deployment that was
bootstrapped with one administrator and has dual approval on. Taking
`admin_token.create` out of `features.dual_approval_operations` would work too,
and is not recommended: it switches the control off for everyone for as long as
it lasts, and it is the change most likely to be forgotten.

### Why a command

A long-running service writes to a log stream, and log streams are shipped,
indexed and retained by systems whose access rules are looser than those of a
credential store. A one-shot command writes to the terminal of the operator who
ran it and to nothing else. See
[ADR 0014](adr/0014-bootstrap-by-explicit-command.md). What remains is the
operator's own terminal: scrollback, a multiplexer's history, a recorded
session. Clear it, and do not pipe the output into a file that outlives the
moment.

Once a usable `admin_full` token exists, the command refuses:

```
n0passtemps: 1 usable full administrator token(s) already exist; mint further tokens through POST /admin/v1/admin-tokens, or pass -force if every token has been lost
```

`-force` lifts the refusal. It is for the operator who has lost every token, or
who has to complete a quorum, and it grants nothing new: whoever can run the
command already holds the configuration, the keyring and the database. The audit
entry then carries `detail.forced: true`, which is worth an alert rule of your
own if you ship the audit log anywhere.

What to do with the bootstrap tokens, in order: sign in with each and confirm it
works, mint a named token per administrator with the role you actually want, one
bootstrap token requesting and the other approving, then revoke the bootstrap
tokens. That order matters, because of the last-administrator guard below.

## Minting and revoking credentials

There are two credential families and they are not interchangeable. An API key
authenticates an integrating application on `/v1` and carries the prefix `npt_`.
An administrative token authenticates an operator on `/admin/v1` and carries
`npa_`. The kind is bound into the stored digest, so a token minted for one
surface cannot authenticate on the other even if it leaks.

Both are shown exactly once. Only the selector and a digest of the verifier are
stored, so there is no operation, anywhere, that can display a credential again.

### An API key

Requires `api_key.create`.

```bash
curl -sS -X POST "$BASE/admin/v1/api-keys" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"billing-app","expires_in_days":365,"scopes":["subjects","totp"]}'
```

```json
{
  "api_key": {
    "id": "3f0c7e61-...",
    "tenant_id": "acme",
    "name": "billing-app",
    "scopes": ["subjects", "totp"],
    "created_at": "2026-09-17T08:14:02Z",
    "created_by": "b71f...",
    "expires_at": "2027-09-17T08:14:02Z"
  },
  "token": "npt_3f9a2c1d8b7e6f5a.Zm9vYmFyYmF6cXV1eHF1dXhmb29iYXJiYXo",
  "warning": "this token is shown once and cannot be retrieved again",
  "no_expiry": false,
  "unrestricted": false
}
```

`name` is required. `expires_in_days` is optional; zero or absent means no
expiry, which the response reports as `no_expiry: true` rather than refusing. A
long-lived key is sometimes the only practical option for an integration that
cannot rotate, and the response says so instead of pretending otherwise.

`scopes` restricts the key to the named families of public routes. It is
enforced where each route is mounted, in `internal/api/router.go`:

| Scope | Routes |
|---|---|
| `subjects` | `POST /v1/subjects`, `GET /v1/subjects/{subject_ref}` |
| `webauthn` | The four routes under `/v1/webauthn/{subject_ref}/` |
| `totp` | `/v1/totp/{subject_ref}/enrol`, `/enrol/confirm`, `/verify`, and the `enroll` spellings |
| `recovery` | `/v1/recovery/{subject_ref}/issue` and `/consume` |
| `health` | `GET /v1/health/detail` |

Names are matched without regard to case, and the stored list is lowercased,
deduplicated and sorted. An unknown scope is refused with 400 when the key is
minted, because a key holding a misspelled scope would hold a permission that
matches nothing and the mistake would surface as an unexplained 403 in
production.

An empty or absent list means the key is unrestricted, and the response then
says `"unrestricted": true`. That is the default and nothing refuses it, so
issue scoped keys on purpose: a service that only checks TOTP codes has no
business issuing recovery codes, and a key that cannot do so costs less when it
leaks. Almost every integration needs `subjects`, because resolving a subject is
the first call of every login.

A key that calls a route outside its scopes gets 403, not 401: the credential is
valid and presenting it again would not help. The attempt is audited as
`api_key.rejected` with outcome `denied`, resource type `scope`, and the route
and the scopes held in the detail. Scopes cannot be changed on an existing key;
mint a new one and revoke the old.

Every request a key makes on a public route counts against
`throttle.max_requests_per_key` within `throttle.window`, whether or not
the route records an authentication outcome. Over the limit the answer is 429
with `Retry-After`.

List keys with `GET /admin/v1/api-keys`, which is mounted under
`api_key.list` and is therefore readable by every role, including
`admin_auditor`. Neither the selector nor the digest is ever in a response.

Revoke with `api_key.revoke`:

```bash
curl -sS -X POST "$BASE/admin/v1/api-keys/3f0c7e61-.../revoke" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json'
```

### An administrative token

Requires `admin_token.create`, and is a dual-approval candidate: with
`features.dual_approval` on and `admin_token.create` in
`features.dual_approval_operations`, which is the default, this call queues the
operation instead of performing it.

```bash
curl -sS -X POST "$BASE/admin/v1/admin-tokens" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"support-desk","role":"admin_operator","expires_in_days":90}'
```

`role` must be `admin_full`, `admin_operator` or `admin_auditor`. Anything else
is a 400 naming the three.

Queued, the response is a 202:

```json
{
  "type": "urn:n0passtemps:error:approval-required",
  "title": "the operation requires approval by a second administrator",
  "status": 202,
  "detail": "queued as approval request 8c2d...; once a different administrator approves it, repeat this exact request with the header X-Approval-Id: 8c2d..."
}
```

Nothing has been minted at that point. Once another administrator has approved
the request, repeat the call with the header, and the token is returned to you,
the requester, and to nobody else:

```bash
curl -sS -X POST "$BASE/admin/v1/admin-tokens" \
  -H "Authorization: Bearer $ADMIN" \
  -H "X-Approval-Id: $APPROVAL" \
  -H 'Content-Type: application/json' \
  -d '{"name":"support-desk","role":"admin_operator","expires_in_days":90}'
```

The approval is bound to `name` and `role`. `expires_in_days` is not part of
what the second administrator approved, so it can differ between the two calls;
state the intended lifetime in the ticket if it matters to you. The full rules
are under [The dual-approval queue](#the-dual-approval-queue).

### Why the last full administrator cannot be revoked

`POST /admin/v1/admin-tokens/{token_id}/revoke` counts the usable `admin_full`
tokens before acting. If the target is the last one, the call is refused:

```json
{
  "type": "urn:n0passtemps:error:conflict",
  "title": "the request conflicts with the current state",
  "status": 409,
  "detail": "this is the last usable full administrator; mint a replacement before revoking it, or the deployment becomes unadministrable"
}
```

A deployment with no full administrator left has no way to mint one. Minting
requires `admin_token.create`, which only `admin_full` holds, so the service
would become permanently unadministrable and the only recovery would be editing
the database by hand. The guard costs one extra step during a handover: mint the
replacement, verify it works, then revoke the old one.

Mint the replacement first, in that order, always. The count is of usable
tokens, so an unexpired unrevoked `admin_full` token whose holder has lost it
still counts and still blocks the revocation of the other one.

## The five things an operator actually does

### 1. A user cannot log in

Distinguish three states before changing anything. They have different fixes and
two of them look identical to the user.

```bash
SUB=$(curl -sS "$BASE/admin/v1/subjects?subject_ref=user-1234" \
  -H "Authorization: Bearer $ADMIN" | jq -r '.subjects[0].subject_id')

curl -sS "$BASE/admin/v1/subjects/$SUB" -H "Authorization: Bearer $ADMIN" | jq '{
  status,
  deleted_at,
  totp_enrolled,
  recovery_codes_remaining,
  credentials: [.credentials[] | {id, label, revoked_at, last_used_at, clone_warning}]
}'
```

| What you see | State | Fix |
|---|---|---|
| `"status": "locked"` | An operator locked the subject. A lock persists until an operator lifts it | `POST /admin/v1/subjects/{subject_id}/unlock`, needs `subject.unlock` |
| `"status": "active"` and the user reports repeated refusals | A throttle lockout, which is automatic and expires on its own after `throttle.lockout_duration` | `POST /admin/v1/subjects/{subject_id}/throttle/reset`, needs `throttle.reset`, or wait |
| `"status": "pending_deletion"` or a non-null `deleted_at` | An erasure request is pending | Cancel it if it was raised in error: `DELETE /admin/v1/subjects/{subject_id}/erasure`, needs `erasure.cancel` |

Note the subject lookup: `?subject_ref=` matches the exact reference through its
HMAC. There is no substring search. The reference is encrypted at rest precisely
so that it cannot be scanned, and offering a search that decrypted every row to
match a pattern would undo that.

Unlocking and resetting a throttle are different operations and the difference
matters. A lock is a deliberate operator decision recorded in the audit log; a
throttle lockout is the rate limiter's automatic response to repeated failures.
Unlocking a subject whose problem is a throttle changes nothing the user can
see; resetting a throttle on a locked subject does the same.

Confirm from the audit log which one it was:

```bash
curl -sS "$BASE/admin/v1/audit?subject_id=$SUB&limit=50" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.entries[] | "\(.occurred_at) \(.event_type) \(.outcome)"'
```

`throttle.tripped` with `outcome: denied` is the lockout. `subject.locked` is
the operator action.

### 2. A lost authenticator

Three cases, in order of how common they are.

**The user has another authenticator.** Revoke the lost one and stop.

```bash
curl -sS -X POST \
  "$BASE/admin/v1/subjects/$SUB/credentials/$CRED/revoke" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"reported lost by the user on 2026-09-17"}'
```

`reason` is required. A revocation with no stated reason is an audit entry
nobody can act on later.

Revocation is final. There is no un-revoke, in the API, in the store interface
or in the interface. A credential is revoked because it is believed
compromised, and a window in which that can be reversed is a window in which the
compromised credential can be restored by exactly the actor an attacker wants to
become. See [ADR 0010, Revocation is final](adr/0010-revocation-is-final.md).

**It was the only authenticator.** The call is refused:

```
this is the subject's only remaining authenticator; set allow_last to revoke it
anyway, and make sure the user holds recovery codes first
```

Check `recovery_codes_remaining` first. If it is zero, the user has no way back
in, so reissue codes, get them to the user out of band, and only then revoke
with `{"reason":"...","allow_last":true}`.

**The user has no authenticator and no codes.** There is no route back in from
the outside. Re-enrol them: verify who they are by whatever means the
organisation uses, reissue recovery codes, transmit them over a channel you
trust, and have the user consume one and register a new authenticator in the
same session.

```bash
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/recovery/reissue" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json'
```

```json
{
  "batch_id": "6ab3...",
  "codes": ["MC4TK-B9YQZ-3HDWR-7FGNP", "..."],
  "count": 16,
  "warning": "these codes are shown once and cannot be retrieved again; transmit them to the user over a channel you trust, and any unused codes from a previous batch have been retired"
}
```

Issuing a batch retires every unused code from the previous batch, in the same
transaction. The old printed sheet dies with the new one being issued. That is
deliberate: leaving old codes live would put codes in circulation that the user
believes are dead.

### 3. A suspected compromise

The order matters. Contain first, investigate second, because the audit log does
not go anywhere but a live attacker does.

```bash
# 1. Stop the subject authenticating. Immediate, and reversible.
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/lock" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"suspected credential compromise, ticket 4711"}'

# 2. Read what happened. Successes first: a failed attack is noise, a
#    successful one is the incident.
curl -sS "$BASE/admin/v1/audit?subject_id=$SUB&outcome=success&limit=200" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.entries[] | "\(.occurred_at) \(.event_type) \(.source_ip // "-") \(.request_id // "-")"'

# 3. Check the alerts the service raised on its own.
curl -sS "$BASE/admin/v1/alerts?subject_id=$SUB&include_acknowledged=true" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.alerts[] | "\(.severity) \(.alert_type) x\(.occurrences) \(.summary)"'

# 4. Revoke what is compromised: one credential at a time, or every
#    authenticator in one transaction. A reason is required either way.
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/credentials/revoke-all" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"suspected account compromise, ticket 4711"}'

# 5. Reissue recovery codes, which retires the old batch.
# 6. Verify the chain covering the incident window, so the record is trustworthy.
curl -sS "$BASE/admin/v1/audit/verify?from_seq=1" -H "Authorization: Bearer $ADMIN"
```

What to look for in step 2 and 3:

| Signal | Means |
|---|---|
| `webauthn.sign_count_regression` | The authenticator's signature counter did not advance. Two copies of a private key in use, or an authenticator that reports a constant zero, which is common. See [WEBAUTHN.md](WEBAUTHN.md) |
| `webauthn.binding_changed` | The authenticator's characteristics differ from registration. A firmware update does this legitimately |
| `recovery.consumed` you did not expect | Someone used a code. If the user did not, the sheet is compromised |
| `api_key.rejected` in volume | A leaked key being probed, or a deployment still running with a credential someone revoked |
| `admin.denied` | A token reaching for a permission its role does not hold: a misconfigured integration, or a stolen token being explored |
| `totp.replay_detected` | A code that verified but whose timestep was already spent. Either a race, or a replay |

If an administrative token or an API key is implicated, revoke it, and check
whether it was used to mint anything: `admin_token.created` and
`api_key.created` entries carry the actor that created them.

A lock is not a revocation. It stops the subject authenticating and is
reversible with `unlock`. Revoking the credentials is what removes the
attacker's access permanently.

#### Revoking every authenticator at once

`POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` requires
`credential.revoke_bulk`, which only `admin_full` holds, and is held for a
second administrator under the operation name `credential.revoke_bulk` when
dual approval is on. It revokes every active WebAuthn credential and every TOTP
secret that is not already revoked, in one store transaction, and reports a
count of each. A TOTP enrolment that was started and never confirmed is revoked
too, because an attacker inside the account may have started it. A subject with
nothing left to revoke yields two zero counts, not an error. Revoking factors
one request at a time can stop
half way and leave an attacker one working factor while the operator believes
the account is closed.

```json
{
  "subject_id": "0b9d2f6e-...",
  "credentials_revoked": 3,
  "totp_revoked": 1,
  "recovery_codes_remaining": 11
}
```

Recovery codes are deliberately left alone. They are the user's way back in, and
revoking them here would turn every incident response into a permanent lockout.
If you believe the codes were taken as well, reissue them, which retires the old
batch. When `recovery_codes_remaining` is zero the response carries a `warning`:
the subject is then locked out until an operator reissues codes and gets them to
the user over a trusted channel.

`reason` is required, and a blank one is a 400. The call counts as one
revocation against `throttle.admin_revoke_burst`, on the same counter as the
single revoke, however many authenticators it removed. Revocation is final here
exactly as it is for one credential.

### 4. An erasure request

GDPR Article 17. Requires `erasure.request`, and is a dual-approval candidate
queued under the operation name `subject.erase`.

```bash
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/erasure" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"subject request received 2026-09-17, verified by ticket 4711"}'
```

With dual approval on, the first call answers 202 with the problem type
`approval-required` and nothing has happened to the subject yet. Once a
different administrator has approved it, repeat the identical call, same subject
and same `reason`, with the header `X-Approval-Id`. A successful erasure request
also answers 202, so tell the two apart by the body: a problem document with a
`type`, or the erasure request itself.

With `features.deferred_erasure` on, which is the default, the response is a 202
carrying the request, and two things happen at once:

1. The subject is soft-deleted immediately and stops authenticating. That is
   the part of Article 17 that cannot wait.
2. `purge_after` is set to now plus `features.erasure_retention`, default 30
   days. The record is destroyed when the janitor reaches that point.

With `features.deferred_erasure` off, `purge_after` is now and the purge is due
immediately.

Cancel inside the window, and only inside it:

```bash
curl -sS -X DELETE "$BASE/admin/v1/subjects/$SUB/erasure" \
  -H "Authorization: Bearer $ADMIN"
```

Cancelling withdraws the pending request and restores the subject in the same
call: the soft deletion is lifted and the user can authenticate again at once,
with the authenticators they had. The response is
`{"erasure_id": "...", "cancelled": true}` and the event is `erasure.cancelled`.
Once purged there is nothing to restore.

A 409 means one of three things, and the `detail` says which: the request is
not pending, it stopped being pending while the call was in flight, or the
request was cancelled but the subject was no longer pending deletion, so there
was nothing to restore. In the last case read the subject before telling the
user anything.

What the purge removes and what survives is in [GDPR.md](GDPR.md). The short
version: the subject row and everything cascading from it goes, and the audit
entries stay with their personal fields cleared and their salt destroyed, which
is what keeps the hash chain verifiable.

### 5. Reading the audit log

```bash
curl -sS -G "$BASE/admin/v1/audit" \
  -H "Authorization: Bearer $ADMIN" \
  --data-urlencode 'event_type=credential.revoked' \
  --data-urlencode 'since=2026-09-01T00:00:00Z' \
  --data-urlencode 'until=2026-09-18T00:00:00Z' \
  --data-urlencode 'limit=200'
```

| Parameter | Accepts |
|---|---|
| `event_type` | An exact event type, or a family prefix such as `webauthn.` |
| `subject_id` | A subject identifier |
| `actor_id` | The identifier of the API key or administrative token that acted |
| `outcome` | `success`, `failure`, `denied` or `error` |
| `since`, `until` | RFC 3339 timestamps. A malformed value is a 400 saying so |
| `after_seq` | Keyset paging: pass the `next_seq` from the previous page |
| `limit` | Default 100, capped by `audit.max_query_limit`, default 500 |

The response carries `entries`, `next_seq` and the `limit` that was applied. A
`next_seq` of zero means the page was the last one.

The four outcomes are distinct and the distinction is useful:

| Outcome | Means |
|---|---|
| `success` | The action happened |
| `failure` | It was attempted and did not succeed, such as a rejected assertion |
| `denied` | An authorisation refusal, or a throttle refusal |
| `error` | A fault in the service, not a rejected request |

Reading the log is itself audited as `admin.subjects_listed` for a subject
listing, and revealing a subject reference is audited separately as
`admin.subject_ref_revealed`. Both are deliberate: the operations that turn a
row back into a person are recorded.

## The dual-approval queue

With `features.dual_approval` on, an operation named in
`features.dual_approval_operations` is held for a second, distinct
administrator. An approval is a capability that the original requester redeems;
nothing runs at the moment of approval. The reasoning is in
[ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md).

The default list names four operations, and each has a route:

| Operation | Route | What the approval is bound to |
|---|---|---|
| `subject.erase` | `POST /admin/v1/subjects/{subject_id}/erasure` | The subject and the `reason` |
| `admin_token.create` | `POST /admin/v1/admin-tokens` | The `name` and the `role` |
| `credential.revoke_bulk` | `POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` | The subject and the `reason` |
| `kek.rotate` | `POST /admin/v1/kek/rewrap` | The fixed action `rewrap` |

The flow has three steps.

1. **The requester calls the route.** The operation is queued, nothing is
   performed, and the answer is 202 with the problem type `approval-required`.
   The `detail` names the approval identifier.
2. **A different administrator approves it**, or rejects it.
3. **The requester repeats the identical request** with the header
   `X-Approval-Id: <id>`. Only this call runs the operation, through the same
   handler and the same checks as any other call, and its result goes to the
   requester.

```bash
# What is waiting.
curl -sS "$BASE/admin/v1/approvals?status=pending" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.approvals[] | "\(.id) \(.operation) by=\(.requested_by) expires=\(.expires_at)"'

# Approve, as a different administrator.
curl -sS -X POST "$BASE/admin/v1/approvals/$APPROVAL/approve" \
  -H "Authorization: Bearer $OTHER_ADMIN" -H 'Content-Type: application/json' \
  -d '{"note":"verified with the requester by phone"}'

# Or refuse.
curl -sS -X POST "$BASE/admin/v1/approvals/$APPROVAL/reject" \
  -H "Authorization: Bearer $OTHER_ADMIN" -H 'Content-Type: application/json' \
  -d '{"note":"no ticket, asked the requester to raise one"}'

# Redeem, as the original requester, with the body of the first call.
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/erasure" \
  -H "Authorization: Bearer $ADMIN" -H "X-Approval-Id: $APPROVAL" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"subject request received 2026-09-17, verified by ticket 4711"}'
```

Deciding requires `approval.decide`, which only `admin_full` holds. `status` in
the listing accepts `pending`, `approved`, `rejected`, `expired`, `executed` and
`failed`; it defaults to `pending`. An approved request that has not been
redeemed yet is `approved`; a redeemed one is `executed`.

A redemption is accepted only when all five of these hold:

| Check | What it closes |
|---|---|
| The approval names the same operation | An approval for one action spent on another |
| The redeemer is the original requester | A stolen or borrowed approval |
| The payload equals the approved payload | Running something other than what the second administrator read |
| It has not expired | An old approval held in reserve |
| The conditional update from `approved` to `executed` succeeds | One approval spent twice under concurrent redemption |

Every refusal is the same 403, with no detail, because telling a caller which
check failed would let them probe for another administrator's approvals. The
reason is in the audit log, as `approval.rejected` with outcome `denied`. A
header that is not a valid identifier is a 400. A successful redemption is
audited as `approval.executed`, carrying the operation and `approved_by`, and is
followed by the operation's own audit entry.

The approval is claimed before the operation runs. If the operation then fails,
for instance on a database error, the approval is spent anyway and a new request
and a new approval are needed. That fails closed: the cost is a repeated
request, where failing open would let one approval run an operation twice.

Self-approval is refused, and the refusal is enforced in the same transaction as
the state change rather than in the handler, so a second code path cannot
bypass it:

```json
{
  "type": "urn:n0passtemps:error:forbidden",
  "title": "this credential is not permitted to perform that operation",
  "status": 403
}
```

The attempt is audited as `approval.rejected` with `reason: self approval`. A
two-administrator rule that one administrator can satisfy alone is not a
control.

A decision on a request that is no longer pending returns 409. Requests expire
after `features.approval_ttl`, default 24 hours, counted from the moment the
request was raised, and the window covers the redemption as well as the
decision. The janitor moves undecided requests to `expired`. An approved
request whose requester never returns is not performed, and nothing alerts on
it.

Running dual approval with one administrative token is possible and pointless:
every request will sit in the queue until it expires, because the only token
able to decide it is the one that raised it. Minting the second token is itself
a held operation under the defaults, and the API carries no exemption for a sole
administrator; the quorum is created with `-bootstrap-admin -admins 2`, as
described under [The first administrative token](#the-first-administrative-token).

## Rotating the keyring

A rotation has four steps, and only the third is a call to the service.

```bash
# 1. Add a key version to the keyring file. The previous versions stay in it.
n0passtemps-wizard kek rotate -file /etc/n0passtemps/kek/keyring.json

# 2. Restart the service. It reads the keyring once, at startup. Until it is
#    restarted it still sees the old version as current, and a rewrap reports
#    every record as already current: true of the running process, not of the
#    file.
systemctl restart n0passtemps

# 3. Move the sealed records onto the new version.
curl -sS -X POST "$BASE/admin/v1/kek/rewrap" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json'
```

```json
{
  "current_version": 2,
  "examined": 1840,
  "rewrapped": 1838,
  "already_current": 2,
  "failed": 0,
  "versions_in_use": [2]
}
```

The route requires `kek.rotate`, which only `admin_full` holds, and is held for
a second administrator under the operation name `kek.rotate` when dual approval
is on. It takes no body, though like every POST on either surface it is
refused with 415 without `Content-Type: application/json`. It walks the sealed TOTP secrets and the sealed subject
references, 200 records to a page, and re-seals each data key under the current
version. The data key itself is kept. The payload is always opened and
authenticated, even for a record already on the current version, so a record
that fails is a record whose integrity or key version is in question, and the
`failed` count is a reliable integrity report. The pass covers every tenant, because one keyring serves them
all; it discloses nothing and changes no plaintext.

4. **Retire the old version only when the numbers allow it.** An older version
   may be deleted from the keyring file when `versions_in_use` holds the current
   version alone **and** `failed` is zero. Both conditions matter: a record that
   could not be read at all has no version to report, so it appears in `failed`
   and nowhere else. Back the file up before editing it, and restart after.

A record that fails is counted, logged with its identifier and key version,
never its bytes, and the pass carries on. The answer is 200 with the counts even
then, because the operator needs the numbers more than a status code. A record
changed by another request during the pass is counted as failed against its old
version and settles on the next pass, so run it again before concluding
anything. A 500 means the pass was interrupted; the records it reached are
rewritten, and the audit entry `kek.rewrapped` records what it did with
`interrupted: true`. Running the pass again is safe.

With `features.kek_rotation_reminder` on, the janitor raises the
`kek.rotation_overdue` alert once the current version is older than
`kek.rotation_interval`. The keyring file records no history, so the age is
anchored on the oldest audit entry, which errs towards reporting early.

## Verifying the audit chain

```bash
curl -sS "$BASE/admin/v1/audit/verify?from_seq=1" \
  -H "Authorization: Bearer $ADMIN"
```

Intact:

```json
{ "from_seq": 1, "checked": 48213, "intact": true, "broken_at": 0 }
```

Broken, returned with HTTP 409 rather than 200 so that a monitoring check
looking only at the status code does not miss it:

```json
{ "from_seq": 1, "checked": 48213, "intact": false, "broken_at": 10472 }
```

Requires `audit.verify`, which every role holds. The run is itself recorded, as
`audit.chain_verified` or `audit.chain_broken`, so a verification cannot be
performed quietly. A broken result also raises the
`audit.chain_broken` alert, which is the only alert type that is critical by
itself.

`from_seq` restarts the walk from a given sequence number, which is how a long
log is checked in slices. Verification is linear in the number of entries and
gets slower for the lifetime of the deployment, so a nightly full verification
on a large log is worth measuring before it is scheduled.

### What a broken chain means

Each entry commits to a hash of the entry before it. An insertion, a deletion or
a field edit breaks verification for every entry after it, so `broken_at` is the
first entry that does not reproduce its stored hash. Everything before it is
intact.

This detects tampering. It does not prevent it. In an on-premise deployment the
operator owns the database file and can rewrite the whole chain consistently,
provided nobody recorded the earlier head elsewhere. See [ADR 0007, Chain the
audit log](adr/0007-chain-the-audit-log.md) and the honest account in
[THREAT-MODEL.md](THREAT-MODEL.md).

Three causes, in order of likelihood:

| Cause | How to tell |
|---|---|
| The database was restored from a backup taken at a different point, or two databases were merged | `broken_at` sits at a restore boundary, and the entries around it are contiguous in time but not in content |
| A retention prune was carried out without its checkpoint, or the chain was verified from a sequence number below a checkpoint | Check `audit_checkpoints`. Verification resumes from `pruned_through_hash`, so a `from_seq` below the watermark has nothing to chain onto |
| Somebody edited the log | Everything else is ruled out |

What to do:

1. Do not write to the database while investigating. Take a copy first, at the
   filesystem level, and work on the copy.
2. Note `broken_at` and read the entries either side of it from the copy.
3. Compare the head against any external record of it. This is the only step
   that distinguishes a restore from a rewrite, and it only works if somebody
   published the head off the box. If nothing did, the honest conclusion is that
   the log cannot be trusted from `broken_at` onwards and can be trusted before
   it.
4. Treat the incident as a compromise of the host, not of the log. An actor able
   to edit the database can do everything else the database permits.

Publishing the chain head somewhere outside the operator's control, on every
append or on a schedule, is what closes this gap. It is not in this release.

## Related documents

| Document | What it covers |
|---|---|
| [RBAC.md](RBAC.md) | All twenty-five permissions against the three roles |
| [MONITORING.md](MONITORING.md) | The ten alert types and what to do about each |
| [GDPR.md](GDPR.md) | The access and erasure paths in full |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | Symptom-first diagnosis |
| [CONFIGURATION.md](CONFIGURATION.md) | Every setting named above |
