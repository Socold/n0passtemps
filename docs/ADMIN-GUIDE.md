# Administrator guide

Written for the person who operates the deployment. Every command below is a
real route from `internal/api/router.go`; every permission is the one the route
is mounted under in `internal/rbac/rbac.go`.

Throughout, `$ADMIN` is an administrative token and `$BASE` the service origin:

```bash
export BASE="https://auth.example.com"
export ADMIN="npa_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-TOKEN"
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

The console also takes a passkey in place of the pasted token, over its own
credential space; see
[Signing in to the console with a passkey](#signing-in-to-the-console-with-a-passkey).

## The three roles

| Role | Can read | Can also do | Cannot |
|---|---|---|---|
| `admin_auditor` | Subjects, credentials, the audit log, chain verification, alerts, the approval queue, the detailed health report, the credential inventory | Rotate its own token, and nothing else. It changes no other state at all | Acknowledge an alert. An auditor who can quietly clear an alert can quietly cover a trace |
| `admin_operator` | Everything an auditor can | Lock and unlock a subject, revoke one credential, reissue recovery codes, reset a throttle, acknowledge an alert, rotate its own token | Mint, rotate or revoke any other credential, decide an approval, request or cancel an erasure, revoke every credential of a subject in one call, rewrap the keyring |
| `admin_full` | Everything | Everything | Nothing |

The full matrix, all twenty-eight permissions against all three roles, is in
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

bootstrap-1  npa_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-TOKEN
bootstrap-2  npa_EXAMPLEONLY0001.EXAMPLE-NOT-A-REAL-TOKEN

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
  "token": "npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY",
  "warning": "this token is shown once and cannot be retrieved again",
  "no_expiry": false,
  "unrestricted": false
}
```

`name` is required. `expires_in_days` is optional; zero or absent means no
expiry, which the response reports as `no_expiry: true` rather than refusing. A
long-lived key is sometimes the only practical option for an integration that
cannot rotate, and the response says so instead of pretending otherwise.

A stated lifetime is bounded at 730 days, two years, and a negative one is
refused rather than read as no expiry. That is not in tension with leaving the
field out: no expiry is a decision the response reports and every listing
shows, while `"expires_in_days": 36500` is almost always a digit too many and
produces a credential that reads as bounded on every screen an operator will
look at. The same bound applies when minting an administrative token.

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
and the scopes held in the detail. The call is counted against the key's volume
before the scope is checked, so a key making that mistake in a loop is stopped
by `throttle.max_requests_per_key` like any other traffic. Scopes cannot be
changed on an existing key; mint a new one and revoke the old.

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

### Rotating an API key without downtime

Requires `api_key.rotate`, which `admin_full` holds.

Replacing a key by minting a new one and revoking the old one forces a choice.
Revoke first and the integration is down until it is redeployed. Mint first and
there are two live keys and a revocation somebody has to remember, and the one
nobody remembers is how a retired key is still valid when it turns up in a leak
a year later. Rotation makes the overlap explicit and closes it for you:

```bash
curl -sS -X POST "$BASE/admin/v1/api-keys/3f0c7e61-.../rotate" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"grace":"24h","expires_in_days":365}'
```

```json
{
  "api_key": {
    "id": "a94be210-...",
    "tenant_id": "acme",
    "name": "billing-app",
    "scopes": ["subjects", "totp"],
    "created_at": "2026-09-17T08:14:02Z",
    "created_by": "b71f...",
    "expires_at": "2027-09-17T08:14:02Z"
  },
  "token": "npt_EXAMPLEONLY0001.EXAMPLE-NOT-A-REAL-KEY",
  "warning": "this token is shown once and cannot be retrieved again",
  "no_expiry": false,
  "unrestricted": false,
  "predecessor_id": "3f0c7e61-...",
  "predecessor_expires_at": "2026-09-18T08:14:02Z"
}
```

The successor carries the same name, scopes and tenant. The old key is given an
expiry of now plus `grace` in the same database transaction that inserts the new
one, so there is no moment at which the old key is unbounded and the new one
exists.

The procedure:

1. Rotate. Store the new token in the integration's secret store.
2. Redeploy or reload the integration inside the grace window. Both keys work
   until `predecessor_expires_at`.
3. Confirm the switch: in `GET /admin/v1/api-keys` the successor's
   `last_used_at` moves and the predecessor's stops.
4. Do nothing else. The old key stops at `predecessor_expires_at` without a
   further call. If the switch is confirmed early and you would rather not
   wait, revoke the predecessor.

The body is optional, and so is each field in it:

| Field | Meaning |
|---|---|
| `grace` | A duration such as `"24h"` or `"90m"`. Absent means `features.rotation_grace`, 24 hours by default. `"0s"` stops the old key at once, which is what you want when the reason for rotating is that the key leaked. Above `168h` the call is refused with 400, because an overlap that long is two live credentials, not a rotation. |
| `expires_in_days` | The successor's lifetime, as when minting. Absent means none, reported as `no_expiry: true`. |

Three rules are worth knowing before relying on it:

- Rotation never extends a key. A predecessor that already expires sooner than
  now plus `grace` keeps its earlier expiry, and `predecessor_expires_at` reports
  the real instant, not the one asked for.
- The successor does not inherit the predecessor's expiry. A key minted for a
  year and rotated in month eleven does not produce a successor with a month to
  live; set `expires_in_days` again if you want one.
- A revoked or expired key cannot be rotated, and the answer is 409. Rotating
  it would bring back, under a fresh token, an integration somebody switched
  off. Mint a new key instead.

If the response is lost, the new token is lost with it: nothing can display it
again. Rotate the successor, with `"grace":"0s"` since nothing uses it, and the
original key is still inside its own window while you do.

Each rotation is audited as `api_key.rotated`, against the predecessor, with
`predecessor_id`, `successor_id`, `grace`, `predecessor_expires_at` and
`successor_expires_at` in the detail. The token is never in it.

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

The approval is bound to `name`, `role` and `expires_in_days`, so the token that
is minted is the token that was approved. Redeeming with a different lifetime,
the omitted field included, is refused: asking for a credential that lasts a day
and redeeming it for one that never expires was a way to have one thing approved
and another issued. The full rules
are under [The dual-approval queue](#the-dual-approval-queue).

### Rotating your own token

Requires `admin_token.rotate_self`, which every role holds, `admin_auditor`
included.

```bash
curl -sS -X POST "$BASE/admin/v1/admin-tokens/self/rotate" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"grace":"1h"}'
```

The response has the shape of the API key one, with `admin_token` in place of
`api_key`. The successor has the same name and the same role. Put it in your
password manager, confirm it works, and the old token stops at
`predecessor_expires_at`. `grace` follows the same rules as for an API key.

If this token has a console passkey enrolled, the call is refused with 409 and
says so. A passkey belongs to the token it signs in as and cannot be moved to
the successor, so a rotation would leave it working until the grace ran out and
then not at all, and would hand you a successor that
`admin.passkey_required` no longer applies to. Withdraw the passkeys from the
overview screen first and enrol again on the successor, or ask a full
administrator to mint you a replacement token and revoke this one.

The path names no token, on purpose. The token that is rotated is the one that
authenticated the request, and there is no route for rotating another
administrator's token. The response carries the successor credential, so such a
route would hand the caller that person's next token, under their name and with
their role, which is impersonation. To replace a colleague's token, revoke it
and mint a new one for them; the mint is held for approval.

Rotating your own token changes no authority, which is why it is not held for a
second administrator and why an auditor may do it. It is the one write the
auditor role performs, and it touches nothing but the caller's own credential.

Because it changes no authority, it cannot lengthen a token's life either. A
token issued with an expiry passes that expiry on to its successor.
`expires_in_days` may bring it forward and is refused with 400 if it would push
it back. A token issued for thirty days to a contractor is still gone after
thirty days, however often it is rotated; a longer life is a new token, minted
by a full administrator.

One caution. `"grace":"0s"` on the only `admin_full` token, followed by a lost
response, leaves the deployment with a working administrator nobody holds. The
last-administrator guard cannot see that, because the successor exists and is
usable. Keep a grace on a sole administrator's rotation, or accept that the way
back is `-bootstrap-admin -force` on the host.

Audited as `admin_token.rotated`, with the actor and `predecessor_id` always the
same token.

### Signing in to the console with a passkey

The console takes a passkey instead of a pasted token, and this is the way to
use it. It needs `admin.ui_enabled`, a `webauthn.rp_id` and origins that cover
wherever `/admin` is served, and a browser on a secure origin.

Nothing here changes `/admin/v1`. That surface takes a bearer token because its
caller is a script, and a script has no authenticator to touch.

**Enrol a key.** Sign in to `/admin` with your token as usual, and look at the
"Your sign-in" section of the overview screen. Name the key something you will
recognise on a list, press "Add a passkey", and confirm on the device. The name
is for you; the service does not read it.

You enrol for the token you are signed in with and for no other. There is no
form that names a colleague's token, for the reason there is no route to rotate
one: what the ceremony produces signs in as that token, which would be
impersonation rather than help. A colleague enrols their own, from their own
session.

It is not held for a second administrator either. The passkey carries no
authority: what you may do still comes from your token, and the role on the
screen after a passkey sign-in is the role on the token record. Enrolling one
changes nothing anybody would weigh, and a queue would mean an administrator who
has just lost a key waits for somebody else to wake up.

Every role may do this, `admin_auditor` included. It is part of how you
authenticate, not something you do as an administrator, which is why it carries
no permission and why signing in and signing out carry none either.

Audited as `admin_credential.enrolled`.

**Sign in.** On `/admin/sign-in`, press "Sign in with a passkey" and confirm on
the device. You are not asked who you are first: the key says which
administrative sign-in it belongs to. The session that results is the ordinary
one, with the same `admin.session_ttl` and the same idle bound.

A refused passkey says only "That passkey was not accepted", whatever went
wrong. The history says which: look at `admin.auth_failed` and read the
`reason` on the entry. An unknown key, a withdrawn one, a token that has expired
and a token that has been revoked each produce a different reason there and the
same sentence on the screen.

Audited as `admin.authorised` with `"method": "passkey"`. A sign-in with a
pasted token carries `"method": "sign-in token"`, so the two are one query.

**Require it.** With `admin.passkey_required` set, an administrative token stops
being accepted in the form once that token has a passkey enrolled. The setting
is scoped to the token, not to the deployment: a token with no passkey is still
accepted whatever it is set to. That is what stops the setting locking a
deployment out, and it is why it is safe to turn on with one administrator.

**When a passkey is lost.** In order:

1. Sign in with another passkey you hold, or with your token if the deployment
   does not require one, and withdraw the lost key from the overview screen. A
   reason is required and is kept with the record. Withdrawal is final, as it is
   for a user's authenticator and for the same reason; see
   [ADR 0010](adr/0010-revocation-is-final.md).
2. If `admin.passkey_required` is on and that was your last key, withdrawing it
   reopens the form for your token, so the token works again immediately.
3. If you cannot sign in at all, the way back is the host. Somebody with access
   to it runs `n0passtemps-server -config <path> -bootstrap-admin -force`, which
   mints a fresh `admin_full` token; a fresh token has no passkey, so it can be
   pasted whatever `admin.passkey_required` says. Then revoke the token whose
   key is gone, and mint a named replacement.

There is deliberately no remote recovery secret for this. Whoever can run that
command already holds the configuration, the keyring and the database, so it
grants nothing new; a recovery code that worked over the network would be a
second console credential nobody rotates.

Audited as `admin_credential.revoked`.

### Why the last full administrator cannot be revoked

`POST /admin/v1/admin-tokens/{token_id}/revoke` counts the usable `admin_full`
tokens before acting, at two instants. The first is now, which is who the
deployment has to administer itself with the moment the call returns. The
second is a week from now, the longest rotation grace: a token that has just
been rotated still works today, so counting only the present would let its
successor be revoked and leave nobody once the grace ran out. A target that
expires inside that week is not counted at the second instant, because it will
not be there either, but it is still counted at the first. If either count
leaves nobody, the call is refused:

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

The guard is a check and a write, in that order, and the service holds them
together within one process. Two instances of the service over one database can
still interleave two revocations, each having seen the other's token. Mint the
replacement before either revocation and the case does not arise.

## The six things an operator actually does

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

**The user has no authenticator and no codes.** Two ways back in, and they
differ in what the user ends up holding. Reissuing recovery codes gives them a
sheet of secrets, each of which authenticates; an enrolment ticket gives them one
secret that enrols one authenticator and authenticates nothing. Prefer the
ticket when the goal is to get the user back onto a key, which it usually is, and
see [A user has lost every authenticator](#6-a-user-has-lost-every-authenticator)
for the procedure.

The recovery-code route is here for when the user needs codes as well, for
instance because they are travelling without the new key:

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
| `api_key.rejected` in volume | A leaked key being probed, or a deployment still running with a credential someone revoked. Read the `refusals` count on the entry rather than counting entries: refusals from one address are folded into one entry a minute, and a request that presented no credential at all is counted on the alert and written nowhere |
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

### 6. A user has lost every authenticator

This is the case nothing else covers. The user holds no WebAuthn credential and
no unused recovery code, so there is no secret they can present and no ceremony
they can complete. An enrolment ticket is the way back in: a single-use,
short-lived secret that permits exactly one WebAuthn registration and nothing
else.

It never produces a signed assertion. Redeeming a ticket gets the user onto a new
authenticator; it does not log them in. That is what makes a ticket safer to
send than a recovery code: the worst a stolen ticket achieves is an authenticator
enrolled against the account, which is audited, alertable and revocable, rather
than a session.

**Before you issue one, establish who you are talking to.** Whoever receives the
ticket can enrol an authenticator against this account until it expires. The
service cannot help you here: it does not know your organisation's identity
proofing and it has no view of the channel you are about to use. This step is
the control. Everything below is mechanism.

```bash
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/enrolment-ticket" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"telephone identity check passed, ref HD-4417"}'
```

```json
{
  "ticket_id": "9f2c...",
  "subject_id": "0b71...",
  "ticket": "MC4TK-B9YQZ-3HDWR-7FGNP",
  "expires_at": "2026-09-18T11:14:03Z",
  "warning": "this ticket is shown once and cannot be retrieved again; it permits one WebAuthn registration and never produces a signed assertion; deliver it over a channel you trust, because whoever holds it can enrol an authenticator until it expires; any live ticket the subject already had has been revoked"
}
```

`reason` is not required by the route, and you should supply it anyway. It is the
only place the audit trail records why an account was opened up.

Needs `enrolment_ticket.issue`, held by `admin_operator` and `admin_full`.

Then the user, in the application's own interface:

1. The application calls `POST /v1/enrolment/register` with
   `{"ticket": "MC4TK-..."}` and passes the returned `options` to
   `navigator.credentials.create()`.
2. It calls `POST /v1/enrolment/register/complete` with the ticket again, the
   `challenge_id` and the credential the browser produced.
3. The response carries the new credential. The ticket is now spent.

The ticket is in the request body on both calls, never in a URL. A path reaches
the access log of every proxy in front of the service; a body does not.

Three things to know about the mechanics.

**Starting the ceremony does not spend the ticket.** If the user's browser
refuses the prompt, or they close the tab, the ticket still works until it
expires. Only a completed registration consumes it, and the consumption records
which credential it produced, so
`GET /admin/v1/audit?event_type=enrolment_ticket.` tells you what each ticket
was used for rather than only that it was used.

**Issuing again revokes the previous ticket.** There is never more than one live
ticket per subject; the schema enforces it with a partial unique index. So if a
ticket went to the wrong mailbox, issuing a fresh one kills it. If you would
rather not put a second secret into circulation, withdraw the first instead:

```bash
curl -sS -X POST "$BASE/admin/v1/enrolment-tickets/$TICKET_ID/revoke" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json'
```

**Issuing over an existing factor needs an explicit override.** If the subject
still holds an active authenticator or a confirmed TOTP secret, the call is
refused:

```
the subject already holds an authenticator or a confirmed TOTP secret; send
require_existing_factor=false to issue a ticket anyway
```

Read that refusal as a question: does this user really have no way in? A user
whose TOTP secret is on a phone they no longer have does hold a factor as far as
this service can tell, and the honest answer is to override. A user who has a
working key and has forgotten about it does not, and issuing a ticket for them
turns the delivery channel into an account-takeover route. Override with
`{"reason":"...","require_existing_factor":false}`; the override is audited with
`existing_factor_override: true` and raises the
`enrolment_ticket.factor_override` alert, so a run of them is visible in
`GET /admin/v1/alerts` whether or not anyone was watching at the time.

A ticket for a subject who is locked or pending erasure is refused outright, and
is not overridable. They could not redeem it, so issuing one would only put a
live secret into a delivery channel for nothing. Lift the lock or cancel the
erasure first.

Finally, tell the user to issue themselves recovery codes once they are back on a
key, through whatever your application exposes for it. Otherwise the next lost
authenticator brings them back to this page.

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

## Verifying a backup

Three artefacts are backed up separately, on purpose: the database, the keyring
and the pepper. Nothing about holding all three proves that they belong
together, and the moment an operator usually finds out is during a restore,
which is the worst moment available.

```bash
export N0PASSTEMPS_SUBJECT_PEPPER=...     # from wherever you keep it
n0passtemps-wizard verify \
  -db /backup/n0passtemps-2026-09-18.db \
  -keyring /backup/keyring.json
```

A trio that opens:

```
Database:  /backup/n0passtemps-2026-09-18.db
Keyring:   /backup/keyring.json (mode 0600, current version 1, retained [1])
Pepper:    N0PASSTEMPS_SUBJECT_PEPPER (32 bytes)

The database is open read-only, so verifying it cannot change it. Nothing
below writes, migrates or upgrades anything.

Integrity:  SQLite reports the file structure as ok
Schema:     4 migrations applied, through 0004_janitor_lease

Sealed records, across every tenant, by the key version they were sealed
under:

  subjects.ref_sealed          version 1      412 records  key present
  totp_secrets.secret_sealed   version 1      143 records  key present

Unsealed 2 records and every one authenticated.
Recomputed a subject's lookup value from its sealed reference under the
pepper, and it matches the value stored on the row.
  subject    b7779ae8-86ca-4a21-87b0-6e8e01fcb8d0

The trio opens.
```

The report then states what that proved and what it did not, which is the half
worth reading twice: what was covered is one record per key version per sealed
column, plus one subject's lookup value.

### It is a routine, not a rescue

The point of the command is that it runs on a schedule, against the backup you
have not needed yet. The exit status is the interface, so it goes in a cron job:

```cron
# Sundays, an hour after the weekly backup. Anything on stderr is mailed.
30 4 * * 0  N0PASSTEMPS_SUBJECT_PEPPER=$(cat /etc/n0passtemps/pepper) \
            /usr/local/bin/n0passtemps-wizard verify \
              -db /backup/n0passtemps-latest.db \
              -keyring /backup/keyring.json >/dev/null
```

| Status | Meaning | What to do |
|---|---|---|
| 0 | The trio opens | Nothing. This is the answer you wanted before the disaster, not during it |
| 1 | The trio does not open | Read the line on stderr; it names which of the three is wrong. [TROUBLESHOOT.md](TROUBLESHOOT.md) has a verdict-by-verdict table |
| 2 | Verification could not run | No verdict was reached. A path is wrong, the pepper is not exported, the database holds nothing sealed, or it came from a newer build |

Two statuses rather than one, because "your backup will not open" and "you
typed the path wrongly" need different reactions, and reporting both as failure
teaches an operator to ignore the alert.

### What it actually checks

- It **decrypts**. Parsing a keyring proves only that it is a keyring; opening
  an envelope-encrypted record proves it is *this database's* keyring, because
  the payload is authenticated and AES-GCM rejects a wrong key rather than
  returning plausible plaintext. One record per key version per sealed column,
  or every record with `-all`.
- It **recomputes a lookup value**. The stored reference is unsealed with the
  keyring, hashed again under the pepper, and matched against the `ref_hmac`
  the row is found by. That needs both secrets to be the right ones, so it is
  the check that ties the trio together rather than testing two of its corners.
- It reads the **key version out of every sealed record's header**, which needs
  no key at all, and reports the counts per version against the versions the
  keyring holds. A keyring taken before a rotation therefore produces the
  diagnosis and not a shrug: `the keyring has no key version 2, which 143
  records in totp_secrets.secret_sealed are sealed under`.
- It says so precisely, unlike the API surface, which deliberately says
  nothing. The difference is the audience: this runs on your host, against your
  backup, for somebody who already holds all three secrets.
- It prints no key material, no pepper, no token, no recovery code and no
  subject reference. Counts, versions, identifiers and verdicts only.

It does **not** write to the database. The file is opened through SQLite's
read-only mode, so a write is refused by SQLite rather than merely avoided, and
the command does not use the store package at all, so the migration runner is
not reachable from it. Reading a database in write-ahead-log mode does make
SQLite create a `-shm` index file beside it; the backup's own bytes, database
and log alike, are untouched. If the directory must stay exactly as it is, run
the check against a copy.

### Two things it cannot check

`subject.seal_reference = false` leaves nothing to recompute the pepper from.
The command says so and exits 2 rather than reporting a trio it only half
checked. Pass `-ref` with a reference you know is enrolled and it checks the
pepper against that subject's stored lookup value instead. That path is weaker
and the message says why: a miss means either a wrong pepper or a reference
that was never enrolled here, and the two are indistinguishable from outside.

PostgreSQL is out of scope, and the help text gives the reason: a `pg_dump`
archive cannot be read without restoring it into a server first, so "here are
my three artefacts" has no meaning for it. [DEPLOYMENT.md](DEPLOYMENT.md) gives
the restore-and-check sequence instead.

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
| [RBAC.md](RBAC.md) | All twenty-eight permissions against the three roles |
| [MONITORING.md](MONITORING.md) | The thirteen alert types and what to do about each |
| [GDPR.md](GDPR.md) | The access and erasure paths in full |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | Symptom-first diagnosis |
| [CONFIGURATION.md](CONFIGURATION.md) | Every setting named above |
