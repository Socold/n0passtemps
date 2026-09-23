# Administrative roles and permissions

Three roles, twenty-eight permissions, one mapping. The authority is in
`internal/rbac/rbac.go`; the matrix below is generated to match it.

## The design principle

Authority grows with the damage the holder is trusted to cause, and reading is
never bundled with writing, other than self-service credential hygiene: every
role may rotate its own token, and that is the only write an auditor holds. See
[The self-service rule](#the-self-service-rule).

| Role | Held by | Line it stops at |
|---|---|---|
| `admin_auditor` | Someone who reviews the service without operating it | Changes nothing but its own token, not even an alert acknowledgement. An auditor who can quietly clear an alert can quietly cover a trace, which is the one thing the role exists to prevent. |
| `admin_operator` | Day to day user support | Adds the operations that recover a locked-out user. Stops short of anything that changes who may administer the service, anything that acts on many records at once, and anything that touches key material. |
| `admin_full` | The operator of the deployment | Holds every permission. |

Membership is an explicit permission set per role, not a numeric level. A level
invites the assumption that a higher role is a superset of a lower one, which
then makes it impossible to grant an operator something an auditor must not have
without reordering the levels.

The mapping is validated at package initialisation. Every declared permission
must be granted to `admin_full`, and no role may hold an undeclared permission;
either fault panics at start rather than leaving an operation nobody can perform
or a privilege nobody intended.

Authorisation fails closed. A token carrying a role this build does not
recognise, for instance after a downgrade, holds nothing.

## The matrix

The read permissions come first, then the one self-service write every role
holds, then the operations an operator may perform, then the operations reserved
to `admin_full`.

| # | Permission | `admin_auditor` | `admin_operator` | `admin_full` | Dual-approval candidate |
|---|---|---|---|---|---|
| 1 | `subject.list` | yes | yes | yes | no |
| 2 | `subject.read` | yes | yes | yes | no |
| 3 | `credential.list` | yes | yes | yes | no |
| 4 | `audit.read` | yes | yes | yes | no |
| 5 | `audit.verify` | yes | yes | yes | no |
| 6 | `alert.read` | yes | yes | yes | no |
| 7 | `approval.read` | yes | yes | yes | no |
| 8 | `health.read_detailed` | yes | yes | yes | no |
| 9 | `api_key.list` | yes | yes | yes | no |
| 10 | `admin_token.list` | yes | yes | yes | no |
| 11 | `admin_token.rotate_self` | yes | yes | yes | no |
| 12 | `subject.lock` | no | yes | yes | no |
| 13 | `subject.unlock` | no | yes | yes | no |
| 14 | `credential.revoke` | no | yes | yes | no |
| 15 | `recovery.reissue` | no | yes | yes | no |
| 16 | `throttle.reset` | no | yes | yes | no |
| 17 | `alert.acknowledge` | no | yes | yes | no |
| 18 | `enrolment_ticket.issue` | no | yes | yes | no |
| 19 | `credential.revoke_bulk` | no | no | yes | yes |
| 20 | `approval.decide` | no | no | yes | no |
| 21 | `erasure.request` | no | no | yes | yes |
| 22 | `erasure.cancel` | no | no | yes | no |
| 23 | `api_key.create` | no | no | yes | no |
| 24 | `api_key.revoke` | no | no | yes | no |
| 25 | `api_key.rotate` | no | no | yes | no |
| 26 | `admin_token.create` | no | no | yes | yes |
| 27 | `admin_token.revoke` | no | no | yes | no |
| 28 | `kek.rotate` | no | no | yes | yes |

Counts: `admin_auditor` holds 11, `admin_operator` holds 18, `admin_full` holds
all 28.

`audit.verify` sits among the read permissions because verification recomputes
hashes and writes nothing. It does append one audit entry recording that a
verification ran, which is the log recording its own inspection rather than the
caller changing state.

`enrolment_ticket.issue` sits with the user support permissions because the
case it serves is the one that role exists for: a user who has lost every
authenticator and holds no recovery code. Its effect is confined to one subject
and is undone by revoking the ticket or the credential it produced. It is not a
dual-approval candidate, because a user with no way in cannot wait for a second
administrator to wake up, and because the two controls that actually bound the
risk are the short lifetime and the factor guard rather than a second signature.
Issuing over an existing factor raises an alert, which is the after-the-fact
review a queue would have provided in advance.

The same permission covers withdrawing a ticket. Whoever may put one into
circulation must be able to take it out, and an operator who had to find a full
administrator to withdraw their own mis-delivery would in practice wait for the
expiry instead.

`api_key.list` and `admin_token.list` are read only and metadata only: neither
listing can disclose a token, because only a selector and a digest of the
verifier are ever stored. They are separate permissions rather than a reuse of
`subject.list`, because sharing a permission between unrelated resources means a
later decision to withhold one of them has nowhere to express itself.

## The self-service rule

`admin_token.rotate_self` is a write, and every role holds it, the auditor
included. It is the one exception to "an auditor changes nothing", and it is
narrow by construction rather than by policy:

- The route is `POST /admin/v1/admin-tokens/self/rotate`. It takes no token
  identifier, in the path or in the body. The token that is rotated is the one
  that authenticated the request.
- The successor carries the same name and the same role, and it cannot outlive
  the token it replaces: an expiry is inherited, and `expires_in_days` may only
  bring it forward. The caller ends the call holding exactly the authority it
  began with, for no longer than it was given.
- Nothing else is touched: no subject, no record, no other credential. The
  rotation is audited as `admin_token.rotated`.

Because it changes no authority it is not a dual-approval candidate. There is
nothing for a second administrator to weigh, and holding it would mean that a
token its owner believes has leaked stays valid until somebody else is awake.

There is deliberately no permission, and no route, for rotating another
administrator's token. The response to a rotation carries the successor
credential, so rotating someone else's token would hand the caller that
person's next credential, under their name and with their role. That is
impersonation. Replacing another administrator's token is `admin_token.revoke`
followed by `admin_token.create`, and the second is approval-gated.

The console's own passkeys carry no permission at all, and the omission is the
decision rather than an oversight. Enrolling or withdrawing a passkey for your
own administrator sign-in is part of how you authenticate, not something you do
as an administrator: it changes no record anybody else can see, and the role a
passkey sign-in produces is read from the administrative token, never from the
credential. The console's other authentication routes, `/admin/sign-in` and
`/admin/sign-out`, carry no permission either, and these sit beside them.

A permission would also have had to be granted to all three roles to be useful,
since an auditor who cannot enrol a passkey is an auditor who can never stop
pasting a token, and a permission every role holds unconditionally is not a
boundary. What bounds these routes instead is that each acts on the caller's own
administrative token and on no other: there is no form that names a colleague's
token, for the reason there is no route to rotate one. See
[ADR 0017](adr/0017-administrative-sign-in-with-webauthn.md).

`api_key.rotate` is not self-service and is reserved to `admin_full`. Its
response carries a working credential for the public surface, so it sits with
`api_key.create`. Like `api_key.create`, it is not a dual-approval candidate.

In `internal/rbac` the rule is a separate list, `selfServicePermissions`, rather
than an entry among the read permissions, so the statement that every read
permission changes no state stays true. A test pins the list to exactly this one
permission, so granting the auditor a second write means changing that test in
review.

## Which route requires which permission

Every administrative route carries three layers: the network allow list, the
administrative token, and the permission. The permission is attached where the
route is mounted, not checked inside the handler, so a handler that forgot the
check cannot exist as an open route.

| Route | Permission |
|---|---|
| `GET /admin/v1/subjects` | `subject.list` |
| `GET /admin/v1/subjects/{subject_id}` | `subject.read` |
| `POST /admin/v1/subjects/{subject_id}/lock` | `subject.lock` |
| `POST /admin/v1/subjects/{subject_id}/unlock` | `subject.unlock` |
| `GET /admin/v1/subjects/{subject_id}/credentials` | `credential.list` |
| `POST /admin/v1/subjects/{subject_id}/credentials/{credential_id}/revoke` | `credential.revoke` |
| `POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` | `credential.revoke_bulk` |
| `POST /admin/v1/subjects/{subject_id}/recovery/reissue` | `recovery.reissue` |
| `POST /admin/v1/subjects/{subject_id}/throttle/reset` | `throttle.reset` |
| `POST /admin/v1/subjects/{subject_id}/enrolment-ticket` | `enrolment_ticket.issue` |
| `POST /admin/v1/enrolment-tickets/{ticket_id}/revoke` | `enrolment_ticket.issue` |
| `POST /admin/v1/subjects/{subject_id}/erasure` | `erasure.request` |
| `DELETE /admin/v1/subjects/{subject_id}/erasure` | `erasure.cancel` |
| `GET /admin/v1/audit` | `audit.read` |
| `GET /admin/v1/audit/verify` | `audit.verify` |
| `GET /admin/v1/alerts` | `alert.read` |
| `POST /admin/v1/alerts/{alert_id}/acknowledge` | `alert.acknowledge` |
| `GET /admin/v1/approvals` | `approval.read` |
| `POST /admin/v1/approvals/{approval_id}/approve` | `approval.decide` |
| `POST /admin/v1/approvals/{approval_id}/reject` | `approval.decide` |
| `GET /admin/v1/api-keys` | `api_key.list` |
| `POST /admin/v1/api-keys` | `api_key.create` |
| `POST /admin/v1/api-keys/{key_id}/revoke` | `api_key.revoke` |
| `POST /admin/v1/api-keys/{key_id}/rotate` | `api_key.rotate` |
| `GET /admin/v1/admin-tokens` | `admin_token.list` |
| `POST /admin/v1/admin-tokens` | `admin_token.create` |
| `POST /admin/v1/admin-tokens/{token_id}/revoke` | `admin_token.revoke` |
| `POST /admin/v1/admin-tokens/self/rotate` | `admin_token.rotate_self` |
| `POST /admin/v1/kek/rewrap` | `kek.rotate` |
| `GET /admin/v1/health` | `health.read_detailed` |

Four of these are worth stating plainly.

Both credential listings are readable by every role, including `admin_auditor`.
An auditor can therefore see which API keys and which administrative tokens
exist, with their names, roles, creation and last-use timestamps. No selector
and no verifier is ever in a response body, so the listing discloses the
inventory of credentials and not the credentials themselves.

`credential.revoke_bulk` and `kek.rotate` are held by `admin_full` alone and
each guards one route. `credential.revoke_bulk` is a separate permission from
`credential.revoke`, which `admin_operator` holds: an operator can revoke one
named credential, with the last-credential guard in the way, and cannot remove
every factor a subject holds in one call. `kek.rotate` guards the rewrap pass
over the sealed records. Adding a key version to the keyring file is not an API
operation at all; it is `n0passtemps-wizard kek rotate`, run on the host by
someone who can write the file.

`enrolment_ticket.issue` guards two routes rather than one, and the second is a
revocation. That is deliberate and is the only place in this table where an
issuing permission also withdraws; the reasoning is above, in
[The matrix](#the-matrix). The revoke route names the ticket and not the
subject, so the audit entry for it carries no subject; the issuance entry for
the same resource identifier does.

Revealing a subject reference is part of `GET /admin/v1/subjects/{subject_id}`,
not a separate route. Passing `?reveal_ref=true` decrypts `subjects.ref_sealed`
and audits the disclosure as `admin.subject_ref_revealed`. There is
deliberately no second permission check inside the handler: the route is already
guarded by `subject.read`, and a duplicate check would have to decide for itself
whether the role model is enabled, which is exactly the kind of second code path
that drifts from the first. The consequence is that any role able to read a
subject is able to reveal its reference, and the audit entry is what records who
did.

## Dual-approval candidates

`internal/rbac` names four permissions whose effect is wide enough, or hard
enough to undo, to be worth a second administrator:

| Permission | Why |
|---|---|
| `credential.revoke_bulk` | Removes every factor a subject holds in one call, and revocation is final. |
| `erasure.request` | Destroys data, and cannot be undone once the retention window closes. |
| `admin_token.create` | Grants administrative authority. |
| `kek.rotate` | Rewrites key material for every sealed record in the deployment. |

They are candidates, not requirements. Whether the queue actually intercepts an
operation is decided by `features.dual_approval_operations`, which names
operations while this package names permissions. The default list covers exactly
these four. The mapping between the two vocabularies is made in the
administrative layer.

All four are wired to the queue:

| Permission | Operation name | Route |
|---|---|---|
| `credential.revoke_bulk` | `credential.revoke_bulk` | `POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` |
| `erasure.request` | `subject.erase` | `POST /admin/v1/subjects/{subject_id}/erasure` |
| `admin_token.create` | `admin_token.create` | `POST /admin/v1/admin-tokens` |
| `kek.rotate` | `kek.rotate` | `POST /admin/v1/kek/rewrap` |

A held operation does not run when it is approved. The original requester
redeems the approval by repeating the identical request with the header
`X-Approval-Id`, and the redemption passes through the same permission check as
the first call, so a requester whose role changed in between is refused by the
ordinary rule. Deciding needs `approval.decide`; redeeming needs only the
permission of the route itself. See
[ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md) and
[ADMIN-GUIDE.md](ADMIN-GUIDE.md#the-dual-approval-queue).

API key scopes are a separate mechanism. They restrict which families of `/v1`
routes an API key may call, they apply whether or not `features.admin_rbac` is
on, and they are described in
[ADMIN-GUIDE.md](ADMIN-GUIDE.md#an-api-key).

## Turning RBAC off

`features.admin_rbac = false`, which `features.lite_mode` implies, is what the
lite deployment means: one administrator, no separation of duty, and no pretence
of one. Every valid role then carries full authority, and the decision recorded
in the audit log says so:

```
role-based access control is disabled, every valid role has full authority
```

An unknown role is still refused, because the value comes from a persisted token
rather than from the operator, and an unrecognised one means the token is not
interpretable rather than unrestricted.

`features.dual_approval` requires `features.admin_rbac`; the configuration
validator refuses the combination, because without distinct roles there is no
way to tell two administrators apart.

## What a denial looks like

A refused call returns RFC 9457 `403` with a fixed title and no explanation of
which permission was missing:

```json
{
  "type": "urn:n0passtemps:error:forbidden",
  "title": "this credential is not permitted to perform that operation",
  "status": 403,
  "request_id": "9f1c4e2b7a5d8c3f"
}
```

The reason names the role and the permission, which would tell a caller holding
a valid token exactly which capability it is missing and therefore which token
is worth stealing next. It goes to the log, to an `admin.denied` audit entry and
to an `admin.denied` alert instead. Correlate through `request_id`.

## Related documents

| Document | What it covers |
|---|---|
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | What an operator does with these permissions |
| [CONFIGURATION.md](CONFIGURATION.md) | `features.admin_rbac`, `features.dual_approval` and the operation list |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What a rogue administrator can and cannot do |
| [ADR 0002](adr/0002-authenticate-every-call-to-the-public-api-surface.md) | Why both surfaces are authenticated |
| [ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md) | Why an approval is redeemed by the requester |
