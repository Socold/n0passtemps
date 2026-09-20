# Frequently asked questions

Short answers, with a pointer to the longer one where there is one.

## Should I run lite or complete?

Lite if one person administers the deployment, SQLite is enough, and nobody has
asked you for separation of duty. Complete otherwise.

`features.lite_mode = true` turns off four things: the three administrative
roles, the dual-approval queue, the deferred erasure window and the key rotation
reminder. It also defaults the driver to SQLite and drops the recovery code
count from 16 to 8. Nothing else changes: WebAuthn, TOTP, recovery codes, the
audit chain, the throttle and the alert engine are identical in both.

It is a shorthand, not a mode. Each of the four is an independent setting, so
"lite plus RBAC" is a valid configuration, and any setting the TOML file names
explicitly wins over the shorthand. One binary and one schema serve both, so
moving from lite to complete is a configuration change and a restart, never a
migration.

The decision tree is in the [README](../README.md#lite-or-complete), and the
exact effects are in
[CONFIGURATION.md](CONFIGURATION.md#what-lite-mode-actually-changes).

## Why is there no password reset?

Because there are no passwords. The service stores no password, no password
hash, and no password history, and there is no route that accepts one.

The equivalent operations, when a user cannot get in, are:

| Situation | Operation |
|---|---|
| Locked out by repeated failures | Reset the throttle |
| Locked by an operator | Unlock the subject |
| Lost one authenticator, has another | Revoke the lost one |
| Lost every authenticator, has recovery codes | Consume a code, then register a new authenticator in the same session |
| Lost everything | An operator reissues recovery codes and transmits them out of band |

The last one is the only path that requires a human decision, and it is the
equivalent of a password reset: an operator who has verified who the person is
hands them a single-use secret. What is different is that the secret cannot be
read back afterwards, is single use, and retires the previous batch when it is
issued.

See [ADMIN-GUIDE.md](ADMIN-GUIDE.md#the-five-things-an-operator-actually-does).

## Can this replace my identity provider?

No.

It authenticates. It does not do any of the following, and adding them is not on
the roadmap:

| Not provided | Meaning |
|---|---|
| OIDC or SAML | No authorisation endpoint, no ID token, no SAML assertion, no metadata document. The result of a ceremony is a compact JWS of this service's own shape, which the calling application verifies and exchanges for its own session |
| User directory | No groups, no attributes, no profile. A subject is an identifier, a status, a display name and its enrolled factors |
| Session management | No cookie for the calling application, no single sign-on, no back-channel logout. The assertion's job ends at the exchange |
| Authorisation | No roles for end users and no policies. The scopes on an API key restrict which families of `/v1` routes that key may call; they say nothing about what an end user may do in your application |
| Provisioning | No SCIM. A subject is created on first reference and erased on request |
| Federation | No upstream identity providers, no social login, no account linking |
| Password fallback | See above |
| Multi-tenancy | See below |

What it is: a passwordless authentication server that an application delegates
the ceremony to, keeping its own sessions, its own user records and its own
authorisation. If you need OIDC, run an OIDC provider. If you have one and want
it to offer WebAuthn, configure it in that provider.

## Why is there no HOTP?

Counter-based one-time passwords per RFC 4226 look like TOTP and are not.

A TOTP verification needs a shared seed and the current time, and its replay
state is a single high-water mark that only moves forward. HOTP replaces the
clock with a counter held on both sides, and those counters drift apart whenever
a user generates a code without submitting it, which happens constantly with
hardware tokens that have a button. Making HOTP usable therefore requires a
look-ahead window, a resynchronisation procedure, and a policy for how far ahead
to search.

Each of those is where authentication bugs live. A look-ahead window that is too
wide accepts codes generated long ago; resynchronisation is an authenticated
state change driven by unauthenticated input; and the interaction between
look-ahead and rate limiting is a documented source of bypasses.

The schema carries no counter column, there is no look-ahead setting, and there
is no resynchronisation endpoint. Adding HOTP later would mean a schema
migration and a second verification path, so the decision is cheap now and not
cheap to reverse.

The cost: an organisation with a stock of counter-based hardware tokens cannot
use them. Those users move to a WebAuthn authenticator or fall back on recovery
codes. See [ADR 0011, Drop HOTP](adr/0011-drop-hotp.md).

## Why is the administration interface not React?

Because a React build brings Node.js, a package manager and a lock file whose
transitive closure runs to hundreds of packages, most of them build-time code
that executes on developer machines and in continuous integration with full
filesystem access. Inside an authentication product that is the highest-value
target in the repository: a compromised build dependency reaches the artefact
operators install to protect their logins, without touching any Go code a
reviewer would read.

Against that, the interface is six screens of lists with filters, detail views
and forms that post. Nothing in them needs client-side routing or a virtual DOM.

So it is `html/template`, with the templates and assets embedded by `embed.FS`,
which keeps the single-artefact promise and keeps Node.js out of the build and
out of CI entirely. `go build` produces the whole product.

The cost is real and worth naming. Navigation means full page loads, a filter
change is a round trip, anything resembling live updates is out of reach, and
changing a stylesheet requires recompiling the binary. Contributors who expected
a component library will find each screen hand-written, with markup duplicated
between templates that a component system would have shared. And because
rendering happens in the same process as authentication, a template that
interpolates into an unexpected context turns an interface bug into a
cross-site scripting flaw in the security domain of the server;
`html/template` escapes contextually by default, which is why it was chosen over
`text/template`, but that guarantee is lost the moment a value is marked as
trusted HTML.

See [ADR 0012](adr/0012-server-rendered-administration-interface.md).

The interface can be turned off entirely with `admin.ui_enabled = false`, which
removes the surface and leaves `/admin/v1`.

## Is attestation verified by default?

No. `webauthn.attestation_preference` is `none` and
`webauthn.require_attestation` is `false`.

Verifying an attestation statement means checking a certificate chain against
either the FIDO Metadata Service over the network or a metadata blob on disk.
This service is meant to run offline, on premise, with no egress. Turning
attestation on by default would mean either a network dependency in the default
configuration or a metadata blob that ships stale and has to be refreshed.

The offline-friendly alternative, and the recommended control, is the AAGUID
allow list:

```toml
[webauthn]
allowed_aaguids = ["ee882879-721c-4913-9775-3dfcce97072a"]
```

That restricts registration to named authenticator models without any external
lookup. It is weaker than attestation verification in one specific way: an
AAGUID is self-asserted by the authenticator unless the attestation statement
that would prove it is verified, so a determined attacker with a programmable
device can claim a permitted model. It is enough to stop a user enrolling the
wrong key, and not enough to stop a forged one.

To verify properly, set `attestation_preference = "direct"`,
`require_attestation = true`, and supply a `metadata_path`. The configuration
validator refuses `require_attestation` without one of those, because with
neither a metadata source nor an allow list there is nothing to verify against.

`metadata_path` names a FIDO MDS3 BLOB that you download and place on disk. The
service loads it at startup, verifies its JWT signature against the FIDO root so
that a file altered on disk is refused, and never fetches it over the network.
Entries that do not parse are dropped, which fails safe: an unknown model is
refused when attestation is required. Staleness fails safe in one direction
only. A model certified after your download is refused; a model compromised
after your download is still trusted. Refreshing the file is your duty, and
nothing in the service reminds you.

See [WEBAUTHN.md](WEBAUTHN.md#attestation-policy).

## Is it multi-tenant yet?

No. One deployment serves one tenant, named by `tenant.id`.

Every table carries a tenant identifier, every query filters on it, every index
leads with it, and the throttle bucket keys are derived with it, so the schema
and the access paths are already multi-tenant. What is missing is the part that
would make it useful: the tenant is read from configuration, not from the
caller's credential.

`Server.callerTenant` refuses a credential whose tenant does not match the
configured one. That is not a multi-tenancy control; it exists so that a
database carried over from another deployment, or a credential minted before
`tenant.id` was changed, fails loudly instead of operating on rows it does not
own.

Run one deployment per tenant. They are cheap: one static binary, one database,
two secrets.

Do not change `tenant.id` on a running deployment. It is written into every row,
so changing it orphans all of the data. The validator refuses `system`, which is
reserved for records that cannot be attributed to a tenant, such as a failed
authentication whose credential did not verify.

## What happens if the process dies mid-ceremony?

Nothing is lost and nothing is left in a bad state.

The ceremony's state is a row in `webauthn_challenges`, written by the `begin`
call and committed before the response goes out. If the process dies after that:

- A replacement process, or the same one restarted, finds the row and can
  complete the ceremony, because the state is in the database rather than in
  memory.
- If the row's `expires_at` has passed, `webauthn.challenge_ttl`, default 5
  minutes, the completion is refused and the user starts again.
- The janitor deletes expired rows on its next pass,
  `features.janitor_interval`, default 5 minutes.

If the process dies before the `begin` response is written, the challenge row
may exist while the caller never received its identifier. That row is unusable
by anybody, expires on its own and is swept. It costs one row for five minutes.

A completion interrupted between consuming the challenge and storing the
credential is the one case worth knowing: the challenge is consumed, so the
retry is refused and the user starts a new ceremony. Nothing is half registered,
because the credential insert is a single statement. The same applies to TOTP
confirmation and to recovery code consumption, both of which are conditional
single statements.

This is also why the same reasoning makes several instances behind a load
balancer work with PostgreSQL: any instance can complete a ceremony any other
instance started.

## Can an assertion be replayed?

Not against this service, and not against a correctly written verifier.

Two independent mechanisms stop a replay here:

| Mechanism | What it stops |
|---|---|
| `ConsumeChallenge` is a single conditional statement, marking the row consumed and returning it in one transaction | Presenting the same signed assertion twice. The second attempt finds no unconsumed challenge and is refused as unknown, expired or used, indistinguishably |
| `AdvanceSignCount` is a compare-and-swap against the counter read at the start | Two concurrent completions of the same assertion. Exactly one wins; the loser sees a stale write and is refused |

The signature counter is not the anti-replay mechanism, and it is worth being
clear about that, because many authenticators report a constant zero and for
those the counter provides nothing at all. The challenge consumption is what
does the work.

For the token this service returns, the replay protection is partly the
verifier's job:

| Property | Who enforces it |
|---|---|
| 60 second lifetime, `assertion.ttl` | Issued here, checked by the verifier |
| `nbf` with `assertion.allowed_clock_skew` subtracted | Same |
| A unique 128-bit `jti` | Issued here. **The verifier must keep a short-lived record of spent values** |
| Audience pinned to the API key's identifier | The verifier must pin it. An empty expected audience is refused by the shipped verifier for exactly this reason |

A caller that skips the `jti` cache loses the single-use property and gains
nothing over a bare 200. [ADR 0004](adr/0004-return-a-signed-assertion-result.md)
says so, and lists what else the caller has to do.

## How do I rotate the keyring?

Rotation is always an explicit operator action. The service will never perform
one, and it will never generate a key: a key that appears by itself is a key
nobody has backed up.

The shape of it:

1. **Add a new version to the keyring and make it current.** Keep the old
   version in `keys`, because existing records are still wrapped under it.

   ```bash
   n0passtemps-wizard kek rotate -file /etc/n0passtemps/kek/keyring.json
   n0passtemps-wizard kek inspect -file /etc/n0passtemps/kek/keyring.json
   ```

   `rotate` adds a version, makes it current and retains the old one, because
   removing it would make every record still sealed under it unreadable. The
   result is the document below, which can equally be written by hand:

   ```json
   {
     "current": 2,
     "keys": {
       "1": "<the old key, do not delete yet>",
       "2": "<32 fresh random bytes, base64>"
     }
   }
   ```

2. **Back the new keyring up** before restarting anything. The backup is the
   whole point of rotation being manual.

3. **Restart the service.** New secrets are sealed under version 2 immediately.
   Existing records keep working, because `Unseal` reads the KEK version from
   the record header and asks the keyring for it. The detailed health report
   will show `current_version: 2` and `retained_versions: 2`.

4. **Rewrap the existing records**, as an `admin_full` administrator:

   ```bash
   curl -sS -X POST https://auth.example.com/admin/v1/kek/rewrap \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'Content-Type: application/json'
   ```

   ```json
   { "current_version": 2, "examined": 1840, "rewrapped": 1838,
     "already_current": 2, "failed": 0, "versions_in_use": [2] }
   ```

   The pass re-seals each record's data key under the current version. The
   payload is always opened and authenticated on the way through, so `failed`
   doubles as an integrity report. The sealed material is
   `totp_secrets.secret_sealed` and `subjects.ref_sealed`, which is all there
   is. With dual approval on, the call is held under the operation name
   `kek.rotate`: a second administrator approves it and you repeat it with the
   header `X-Approval-Id`.

5. **Remove version 1 only when the numbers allow it**: `versions_in_use` holds
   the current version alone **and** `failed` is zero. A record that could not
   be read at all has no version to report and shows up only in `failed`, which
   is why both conditions matter. Then back the keyring up again and restart.
   Until then, deleting the old version makes the records still wrapped under it
   unreadable.

Three things to know:

- Step 3 is not optional. The service reads the keyring once, at startup. A
  rewrap run before the restart sees version 1 as current and reports every
  record as already current, which is true of the running process and not of
  the file.
- The route answers 200 with the counts even when some records failed, because
  the numbers are what you act on. A record changed by another request during
  the pass is counted as failed and settles on the next pass, so run it again
  before drawing a conclusion.
- `retained_versions` above 1 in the health report is the signal that a rotation
  is in progress or was never finished. Watch it; see
  [MONITORING.md](MONITORING.md). With `features.kek_rotation_reminder` on, the
  janitor also raises the `kek.rotation_overdue` alert once the current version
  is older than `kek.rotation_interval`.

Rotating does not help retroactively. It changes nothing about a snapshot an
attacker already took, and it does not re-encrypt plaintext they already
extracted.

## What does losing the keyring actually cost?

The TOTP secrets and the readable form of every subject reference. Nothing else.

WebAuthn credentials are stored in clear and keep working. Recovery codes are
hashed and keep verifying. API keys and administrative tokens are digested and
keep authenticating. The audit chain still verifies. So the service degrades
rather than failing closed, and the users it affects can still log in with a key
or a recovery code in order to re-enrol TOTP.

The full account, and the recovery procedure, is in
[TROUBLESHOOT.md](TROUBLESHOOT.md#the-key-encryption-keyring-is-lost).

Losing the **pepper** is worse: `ref_hmac` cannot be re-derived, so no existing
subject can be found at all.

## Why does every `/v1` route need an API key?

Because an unauthenticated `POST /v1/webauthn/{subject_ref}/register` lets anyone
who can reach the port enrol an authenticator of their own choosing against any
subject identifier, then complete an assertion as that subject. The attacker
supplies both halves of the ceremony, so nothing in WebAuthn detects it. That is
a total authentication bypass, not a missing hardening measure.

The consequence for an integrating application is that it has to hold the key
server side and proxy the ceremony endpoints. A browser front end cannot call
`/v1` directly, because doing so would ship the key to every visitor. That
changes the integration shape for anyone who expected to talk to the service
from JavaScript, and it is the single most common surprise in adopting this.

A key does not have to reach every route. Mint it with `scopes`, from
`subjects`, `webauthn`, `totp`, `recovery` and `health`, and it is confined to
those route families; a call outside them is a 403 and an audit entry. A key
minted with no scopes is unrestricted, and the minting response says so.

See [ADR 0002](adr/0002-authenticate-every-call-to-the-public-api-surface.md).

## Where is my first administrative token?

Nowhere, until you create it. The running service never prints one. With no
administrator in the database it logs a warning naming the command:

```bash
n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2

# with compose
docker compose run --rm n0passtemps -bootstrap-admin -admins 2
```

`-admins 2` is for a deployment with dual approval on, which is the default
outside lite mode. One administrator cannot mint a second there, because the
request needs someone else to approve it, and the API has no exemption for a
sole administrator: a rogue administrator could reach one by revoking the
others. So the initial pair is created together, and the second token goes to a
different person. With dual approval off, leave the flag out.

The command prints each token once, to your terminal, and exits. It is a command
and not a line in the service log because a log stream is shipped and retained
by systems with looser access rules than a credential store. It refuses when a
usable full administrator exists; `-force` is for the operator who has lost
every token, or who bootstrapped one administrator under dual approval and needs
the second, and it gives nothing to anyone who does not already hold the
configuration, the keyring and the database. What is left is your own terminal's
scrollback, which is yours to clear. See
[ADR 0014](adr/0014-bootstrap-by-explicit-command.md).

## Why did my approved operation not run?

Because approving does not run anything. The administrator who raised the
request repeats the identical request with the header `X-Approval-Id: <id>`, and
that call runs it. Executing at approval time would hand the result, which for
`POST /admin/v1/admin-tokens` is a secret shown once, to the approver and not to
the person who asked.

The redemption is refused, always with the same 403, when the approval is for a
different operation, belongs to a different requester, is not in the `approved`
state, has expired, or does not match the payload that was approved. The reason
is in the audit log under `approval.rejected`. An approval is spent before the
operation runs, so if the operation then fails the approval is gone and a new
one is needed. See [ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md).

## Why does `/v1/health` tell me so little?

The unauthenticated probe returns one field because a container runtime and a
load balancer need to know whether to keep sending traffic and nothing else.

The version, the keyring state, the rotation status and the certificate expiry
are useful to an attacker before they are useful to an operator: the version
says which published advisories to try, the rotation status says whether the
deployment is mid-rotation and the operator is distracted, and the expiry date
gives a date on which changes will be made in a hurry. They are behind
authentication.

The cost, which ADR 0008 records: an operator debugging at three in the morning
has to find a token, and a monitoring system that used to scrape the URL
anonymously has to be given credentials.

## Can I run more than one instance?

With PostgreSQL, yes. The throttle holds no state of its own, so several
instances share one set of limits, and any instance can complete a ceremony any
other instance started. Two things serialise across all of them: the audit
append, through an advisory lock, and nothing else.

With SQLite, no. It does not support concurrent writers across processes, so one
instance and one file. The shipped Kubernetes deployment has `replicas: 2` and
an `emptyDir` data volume, which is correct only with PostgreSQL; a SQLite
deployment there means `replicas: 1` and a PersistentVolumeClaim.

## Is there a support email?

No, and there will not be one.

GitHub issues, with the templates in `.github/ISSUE_TEMPLATE`, and GitHub's
private vulnerability reporting for anything security-relevant. No email, no
chat, no Slack, no call booking, no sales contact. The documentation and the
runnable examples are the support channel, which is why this set is as long as
it is.

Response times are not promised, because one person maintains this and
publishing a number would be dishonest. See [SECURITY.md](../SECURITY.md) for
the same statement about vulnerability reports.

## Why does the API disclose so little when something fails?

An authentication service that explains why a ceremony failed is an oracle for
probing its own configuration.

Every ceremony failure returns the same body: `authentication did not succeed`,
with no detail. A caller cannot tell an expired challenge from a wrong signature
from an unknown credential from a subject that does not exist. Every credential
failure returns `authentication is required`, so a caller cannot tell a missing
credential from an unknown selector from a wrong verifier from a revoked key.
Every authorisation refusal returns the same fixed title, so a caller holding a
valid token cannot learn which permission it is missing and therefore which
token is worth stealing next. A refused approval redemption is that same 403,
whichever of its checks failed.

One thing is told apart on purpose. When the credential store cannot be reached,
the answer is 503 with the problem type `unavailable`, not 401, and nothing is
audited as a rejected credential, because nothing was rejected. A caller should
retry a 503 and should not retry a 401.

The real reason is logged and audited, where an operator can read it and an
attacker cannot. Every response carries a `request_id`, echoed in the
`X-Request-Id` header, which is the one piece of information a support exchange
actually needs.

The exceptions, where disclosure is safe and useful: input validation, which
tells a caller a field is missing and tells an attacker nothing, and the
authenticator model policy, because a user holding an unsupported key needs to
be told to use a different one.

## Related documents

| Document | What it covers |
|---|---|
| [README](../README.md) | What this is, and the five-minute install |
| [CONFIGURATION.md](CONFIGURATION.md) | Every setting named above |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | Symptom-first diagnosis |
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | Day to day operation |
| [docs/adr](adr/README.md) | The twelve deviations from the original specification, and three further decisions |
