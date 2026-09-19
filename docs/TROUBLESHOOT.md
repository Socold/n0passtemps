# Troubleshooting

Symptom first. Each entry gives what a user or an operator would report, how to
confirm it, the cause, and the fix. The quoted messages are the real ones from
`internal/config/config.go`, `internal/crypto/kek/kek.go` and
`internal/assertion/assertion.go`.

Two things to have to hand before anything else:

```bash
export BASE="https://auth.example.com"
export ADMIN="npa_..."           # an administrative token

# The authenticated health report says what the service thinks of itself.
curl -sS "$BASE/admin/v1/health" -H "Authorization: Bearer $ADMIN" | jq .
```

Every refused request carries a `request_id`, echoed in the
`X-Request-Id` response header. It is the one piece of information a diagnosis
actually needs: the reason a request was refused is in the logs and the audit
log under that identifier, never in the response body.

## The service refuses to start

### Symptom

The process exits immediately. The log carries one or more lines beginning
`config:` and nothing else.

### Confirm

```bash
# systemd
journalctl -u n0passtemps -n 40 --no-pager
# container
docker compose -f deploy/docker-compose.yml logs n0passtemps
# Kubernetes
kubectl -n n0passtemps logs -l app.kubernetes.io/name=n0passtemps --previous
```

Then reproduce it without starting a listener, which is faster and does not
touch the database:

```bash
n0passtemps-server -config /etc/n0passtemps/config.toml -check-config
```

### Cause

Validation is strict and runs once, at startup. It reports every problem it
found rather than the first, so one round of fixes usually clears it. A
misconfigured authentication server refusing to start is the intended behaviour.

### Fix, by message

| Message | Fix |
|---|---|
| `config: webauthn.rp_id is required` | Set `webauthn.rp_id` to the registrable domain. There is no default, because a wrong one invalidates every credential later |
| `config: webauthn.origins must list at least one origin` | Set `webauthn.origins` to the origins your front end is served from |
| `config: server.addr "0.0.0.0:8080" is not loopback but TLS is not configured and server.trust_proxy is false; either terminate TLS here, set trust_proxy with trusted_proxy_cidrs when a reverse proxy terminates it, or set server.allow_plaintext when something outside this process already constrains who can reach the port, such as a container published to loopback` | Set both `server.tls_cert_file` and `server.tls_key_file`, or set `trust_proxy = true` with a `trusted_proxy_cidrs` list. In a container that binds every interface and is published to loopback only, `server.allow_plaintext = true` is the acknowledgement; the shipped compose files set it. Do not set it to make the message go away on a host whose port is reachable from elsewhere |
| `config: server.trust_proxy requires server.trusted_proxy_cidrs; accepting a forwarded client address from any source lets a caller spoof the address that rate limiting and audit entries are keyed on` | List the networks your proxy connects from. Narrow them: `172.16.0.0/12` for a default Docker bridge, `127.0.0.1/32` for a proxy on the same host |
| `config: admin.ui_enabled on the non-loopback listener "0.0.0.0:8080" without admin.ip_allow_list exposes the administration interface to every network that can reach the service; set an allow list or disable the UI` | Set `admin.ip_allow_list`, or `admin.ui_enabled = false` |
| `config: kek.path "/var/lib/n0passtemps/keyring.json" is inside the data directory "/var/lib/n0passtemps"; a key stored beside the ciphertext it protects gives no confidentiality if the volume is copied, so mount it separately or use kek.provider "env"` | Move the keyring. See the next entry |
| `config: database.dsn: sslmode=disable towards "db" sends credentials and secrets in clear; use sslmode=require, verify-ca or verify-full, or set database.allow_plaintext when the link is a private container network that never leaves the host` | Use `sslmode=verify-full`. Only when the database really is on a private container network on the same host, as in `deploy/docker-compose.postgres.yml`, set `database.allow_plaintext = true`, which that compose file already does. It does not make `prefer` or `allow` acceptable |
| `config: database.dsn: no sslmode is set; libpq defaults to "prefer", which falls back to an unencrypted connection without reporting it. Set sslmode=require or stronger, or sslmode=disable explicitly for a loopback socket` | Add `?sslmode=verify-full` to the DSN, or `sslmode=disable` if and only if the host is a Unix socket, `localhost` or `127.0.0.1` |
| `config: webauthn.origins: origin "https://app.example.com" is not covered by rp_id "other.example.com"; the relying party identifier must equal the origin's domain or be a parent of it` | Set `rp_id` to `example.com` or to `app.example.com` |
| `config: webauthn.user_verification "discouraged" means the authenticator proves possession only, so a WebAuthn assertion is no longer sufficient on its own; set "required" or "preferred"` | Use `required`, or `preferred` if some of your authenticators cannot do user verification |
| `config: features.dual_approval requires features.admin_rbac; without distinct roles there is no way to tell two administrators apart` | Turn on `features.admin_rbac`, or turn off `features.dual_approval` |
| `config: tenant.id "system" is reserved for records that cannot be attributed to a tenant, such as a failed authentication` | Pick another identifier |
| `config: recovery.low_watermark (16) must be below code_count (16), otherwise a fresh batch is already in the warning state` | Lower `recovery.low_watermark` |
| `config: totp.secret_bytes must be at least 20, RFC 4226 section 4 requires a shared secret of at least 128 bits and recommends 160, got 10` | Set it to 20 or higher |
| `config: assertion.ttl must be positive and at most 5m; the assertion proves a ceremony just completed and is exchanged immediately, got 1h0m0s` | Lower it. 60 seconds is the default and is usually right |

If a TOML key is reported as unknown, the loader refuses unknown fields on
purpose: a misspelled `require_attestation` would silently leave attestation
unverified. Check the spelling against [CONFIGURATION.md](CONFIGURATION.md),
which lists every key that exists.

Four startup refusals are not configuration problems and have their own entries
below: the keyring, the signing key, the database, and this one, which appears
only with `audit.verify_on_start = true`:

```
the audit chain does not verify from entry 10472; the log has been altered since
it was written. Investigate before serving traffic, or set
audit.verify_on_start to false to start anyway
```

That is the service refusing to serve while its own record is untrustworthy. See
[the audit chain entry](#the-audit-chain-reports-broken) before turning the
setting off.

If the configuration is valid and the process still exits, the next things it
does are, in order: load the keyring, open the store, apply migrations, read the
subject pepper, load the signing key, build the WebAuthn relying party, which
loads the metadata BLOB when `webauthn.metadata_path` is set, provision the
tenant, and verify the chain if asked. The first line of the failure names which
one. It does not create an administrator; see
[There is no administrative token](#there-is-no-administrative-token).

Two of those have refusals worth quoting.

The pepper's encoding is never guessed. A value that is not hexadecimal, not
base64 of at least 32 bytes, and carries no prefix is refused:

```
subject: pepper is too short: the value is not hexadecimal and is not base64 of
at least 32 bytes. Generate one with "n0passtemps-wizard pepper", or prefix the
value with hex:, base64: or raw: to say what it is
```

If the value is a passphrase, say so with `raw:`. If it is base64 of fewer than
32 bytes, it is too short whatever it is called; generate a new one only on a
deployment with no subjects, because changing the pepper makes every existing
subject unfindable.

The metadata BLOB is refused when it is not a signed JWT or its signature does
not chain to the FIDO root:

```
webauthn relying party: webauthn: metadata blob "/etc/n0passtemps/mds/blob.jwt" did not verify: ...
webauthn relying party: webauthn: metadata blob "/etc/n0passtemps/mds/blob.jwt": not a signed JWT: expected three non-empty segments
webauthn relying party: webauthn: metadata blob "/etc/n0passtemps/mds/blob.jwt": the JWT declares no signature algorithm; an unsigned file cannot be a source of trust anchors
```

Download the file again from the FIDO Alliance and compare digests. A file that
was edited, truncated or saved as the decoded JSON payload fails here by
design, because the signature is the only reason a local file can be trusted as
a source of attestation roots.

## The container cannot read its configuration

### Symptom

On Fedora, RHEL or another host with SELinux enforcing, the container exits at
once and its log carries:

```
n0passtemps: configuration is not valid:
config: read "/etc/n0passtemps/config.toml": open /etc/n0passtemps/config.toml: permission denied
```

### Confirm

```bash
getenforce                                   # Enforcing
ls -lZ deploy/config.toml                    # the label, and the mode
sudo ausearch -m avc -ts recent | grep config.toml
```

### Cause and fix

| Cause | How to tell | Fix |
|---|---|---|
| The SELinux label on the bind-mounted file does not allow a container to read it | An AVC denial naming `config.toml`, and a label such as `user_home_t` | The shipped compose files mount the file with `:ro,z`, which relabels it for containers. If you wrote your own compose file or `docker run` line, add `z` to the mount options. Do not use `z` on a directory you share with the rest of the system, such as a home directory: it relabels everything under it |
| The file is not readable by uid 65532, which is the user the container runs as | Mode 0600 owned by you, and no AVC denial. This one is not specific to SELinux | `chmod 0644 config.toml`. The file holds no secret: the keyring, the signing key and the pepper live elsewhere |
| `N0PASSTEMPS_CONFIG_FILE` in `.env` names a path that did not exist at `up` | Docker created a directory at that path, and the message ends `is a directory` | Remove the directory, write the file, and start again |

Named volumes are labelled by Docker itself and are not affected.

## The keyring is refused

### Symptom

The process exits with a line beginning `kek:`.

### Confirm

```bash
ls -l /etc/n0passtemps/kek/keyring.json
stat -c '%a %U:%G %n' /etc/n0passtemps/kek/keyring.json
readlink -f /etc/n0passtemps/kek/keyring.json
```

### Cause and fix

**Inside the data directory.**

```
kek: "/var/lib/n0passtemps/keyring.json" is inside the data directory
"/var/lib/n0passtemps"; a key stored beside the ciphertext it protects gives no
confidentiality if the volume is copied. Mount it from a separate volume or use
the env provider
```

Move it out. The check resolves symbolic links on both sides first, so a symlink
from `/etc` into the data directory is caught too, and the message says
`(it resolves to ...)` when that is what happened.

```bash
sudo install -d -o n0passtemps -g n0passtemps -m 0700 /etc/n0passtemps/kek
sudo install -o n0passtemps -g n0passtemps -m 0600 \
  /var/lib/n0passtemps/keyring.json /etc/n0passtemps/kek/keyring.json
sudo shred -u /var/lib/n0passtemps/keyring.json
```

Then set `kek.path` to the new location. Nothing in the database needs to
change: the keyring content is the same, and the key versions are unchanged.

See [ADR 0009, Refuse to load a key encryption key stored inside the data
directory](adr/0009-refuse-a-kek-inside-the-data-directory.md).

**World or group readable.**

```
kek: "/etc/n0passtemps/kek/keyring.json" is mode 0644, must not be readable by
group or other (chmod 600)
```

```bash
sudo chown n0passtemps:n0passtemps /etc/n0passtemps/kek/keyring.json
sudo chmod 600 /etc/n0passtemps/kek/keyring.json
```

A keyring readable by group or other is readable by every process on the box.
In Kubernetes this is the `defaultMode` on the secret volume: set `0400` and
`fsGroup: 65532` in the pod security context, as `deploy/kubernetes` does.

**Malformed.**

| Message | Cause |
|---|---|
| `kek: keyring contains no keys` | The `keys` object is empty |
| `kek: key 1 is not valid base64` | The value is not standard base64 |
| `kek: key must be 32 bytes: key 1 has 16 bytes` | Wrong key length. It must be exactly 32 bytes, base64-encoded |
| `kek: unknown key version: current is 2 but that key is absent` | `current` names a version that is not in `keys` |
| `kek: key version "01" is not in canonical form, write it as 1` | Versions are canonical decimal. `"1"` and `"01"` parse to the same version, and a keyring holding both would protect the database with a different key from one start to the next |
| `kek: key version 0 is reserved; versions start at 1` | Renumber from 1. On a keyring already in use, do not renumber a version that records are sealed under: the version is in every record header |
| `kek: N0PASSTEMPS_KEK is not set` | `kek.provider = "env"` and the variable named by `kek.env_var` is unset or empty |

## WebAuthn fails in the browser

This is the most common failure, and the cause is almost always `rp_id` or an
origin.

### Symptom

`navigator.credentials.create` or `.get` rejects in the browser, often with
`SecurityError` or `NotAllowedError`. Or the browser succeeds and the completion
call returns:

```json
{
  "type": "urn:n0passtemps:error:ceremony-failed",
  "title": "authentication did not succeed",
  "status": 401,
  "request_id": "9f1c4e2b7a5d8c3f"
}
```

The response says nothing more, on purpose: a service that explains why a
ceremony failed is an oracle for probing its own configuration. The reason is in
the audit log.

### Confirm

```bash
# The real reason, keyed on the request identifier from the response.
curl -sS -G "$BASE/admin/v1/audit" -H "Authorization: Bearer $ADMIN" \
  --data-urlencode 'event_type=webauthn.' --data-urlencode 'outcome=failure' \
  --data-urlencode 'limit=20' | jq -r '.entries[] | "\(.occurred_at) \(.request_id) \(.detail)"'
```

The `detail.reason` field carries the library's message. Then compare the three
values that have to agree:

```bash
# What the server expects.
grep -A4 '^\[webauthn\]' /etc/n0passtemps/config.toml

# What the browser is actually on.
#   in the browser console:
#   window.location.origin
```

### Cause and fix

| What you see | Cause | Fix |
|---|---|---|
| `SecurityError` in the browser before any request reaches the service | The page's domain is not a registrable suffix of `rp_id`, or the reverse. The browser refuses before calling out | Set `rp_id` to the page's domain or a parent of it. `rp_id = "example.com"` works for `app.example.com`; `rp_id = "app.example.com"` does not work for `example.com` |
| `NotAllowedError` after the prompt appears | User cancelled, timed out, or no available authenticator satisfies `user_verification = "required"` | Nothing to fix server side unless the authenticator genuinely cannot do user verification, in which case `preferred` is the setting |
| `detail.reason` mentions an origin | The `origin` in the client data is not in `webauthn.origins` | Add it. It is an exact string match on scheme, host and port after normalisation, so `https://app.example.com` and `https://app.example.com:443` are the same but `http://` and a different port are not |
| The ceremony works on `localhost` and fails in production | `origins` lists the development origin only | Add the production origin. `http` is accepted only for `localhost`, `127.0.0.1` and `::1` |
| Every existing user suddenly fails, new registrations work | `rp_id` was changed | Change it back. Credentials registered under the old identifier will never validate under the new one. If the move is intended, every subject re-enrols. See [ADR 0003](adr/0003-the-service-is-the-webauthn-relying-party.md) |
| `detail.reason` is `webauthn: challenge is unknown, expired or already used` | The completion arrived after `webauthn.challenge_ttl`, or twice, or the `challenge_id` is wrong | Start the ceremony again. The three cases are indistinguishable by design |
| `this authenticator model is not permitted` with HTTP 403 | The AAGUID is blocked, or not in `webauthn.allowed_aaguids` | Either use a permitted key, or add the AAGUID. This is the one ceremony refusal whose reason is disclosed, because a user with an unsupported key needs to be told |
| `the subject has reached the credential limit` with HTTP 409 | `webauthn.max_credentials_per_subject`, default 10 | Revoke an unused credential, or raise the limit |
| `this authenticator is already registered` with HTTP 409 | The same authenticator is already enrolled, under this or another subject. A credential identifier is unique per relying party | Use a different authenticator, or find the existing registration |
| The prompt never appears on Linux | The browser cannot see the USB device | Install the `udev` rules for the key, so the logged-in user has access to the HID device. Nothing server side is involved |

Details of the ceremony, and what differs per platform, are in
[WEBAUTHN.md](WEBAUTHN.md).

## A user is locked out

Two different conditions with two different fixes. They look identical to the
user.

### Symptom

The user reports that every attempt is refused. On a throttle they see HTTP 429:

```json
{
  "type": "urn:n0passtemps:error:throttled",
  "title": "too many attempts",
  "status": 429,
  "retry_after_seconds": 612
}
```

On a lock they see the same refusal as a failed ceremony, HTTP 401, because
distinguishing an inactive subject from a wrong credential would turn every
endpoint into a way to test whether a person has an account.

### Confirm

```bash
SUB=$(curl -sS "$BASE/admin/v1/subjects?subject_ref=user-1234" \
  -H "Authorization: Bearer $ADMIN" | jq -r '.subjects[0].subject_id')

curl -sS "$BASE/admin/v1/subjects/$SUB" -H "Authorization: Bearer $ADMIN" \
  | jq '{status, deleted_at, recovery_codes_remaining}'

curl -sS "$BASE/admin/v1/audit?subject_id=$SUB&limit=30" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.entries[] | "\(.occurred_at) \(.event_type) \(.outcome)"'
```

### Cause and fix

| Evidence | Condition | Fix |
|---|---|---|
| `throttle.tripped` entries, `status` still `active`, HTTP 429 with `retry_after_seconds` | A throttle lockout. Automatic, and it expires after `throttle.lockout_duration`, default 15 minutes | `POST /admin/v1/subjects/{subject_id}/throttle/reset`, permission `throttle.reset`. Or wait |
| `subject.locked`, `status` is `locked`, HTTP 401 | An operator locked the subject. It persists until an operator lifts it | `POST /admin/v1/subjects/{subject_id}/unlock`, permission `subject.unlock` |
| `status` is `pending_deletion`, or `deleted_at` is set | An erasure request is pending | `DELETE /admin/v1/subjects/{subject_id}/erasure`, permission `erasure.cancel`, and only inside the retention window |

Resetting a throttle on a locked subject changes nothing the user can see, and
unlocking a subject whose problem is a throttle does the same. Read the audit
log before acting.

A whole office locked out at once is the per-address dimension, not the
per-subject one: `throttle.max_failures_per_ip`, default 50, counts failures
from one normalised network, and everyone behind one NAT gateway shares it. On
the ceremony routes the address is the one the application declares in
`X-End-User-IP`; an application that sends none has no per-address limit there,
because the only address the service sees is the application's own. The alert is
`auth.failure_burst.ip`. The per-address reset is not exposed as a
route; either wait out `throttle.lockout_duration` or raise
`throttle.max_failures_per_ip`. IPv6 sources are bucketed by `/64`, because a
single host is routinely delegated a whole `/64` and a per-address limit there is
bypassed at no cost.

## There is no administrative token

### Symptom

A fresh deployment is up, `GET /v1/health` answers `{"status":"ok"}`, and there
is no token anywhere in the log. Or every token has been lost.

### Confirm

The service logs this at every start while no usable `admin_full` token exists:

```
no administrator exists yet; create the first with: n0passtemps-server -config <path> -bootstrap-admin -admins 2
```

### Cause

By design. The running service never creates or prints an administrative token,
because its log stream is shipped and retained by systems with looser access
rules than a credential store. See
[ADR 0014](adr/0014-bootstrap-by-explicit-command.md).

### Fix

Run the one-shot command with the service's own configuration, keyring, pepper
and database. It prints each token once, to your terminal, and exits. With dual
approval on, create two and give the second to a different person; with it off,
leave `-admins` out:

```bash
# host
n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2
# compose
docker compose -f deploy/docker-compose.yml run --rm n0passtemps -bootstrap-admin -admins 2
# Kubernetes
kubectl -n n0passtemps exec deploy/n0passtemps -- \
  /usr/local/bin/n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2
```

| What you see | Cause | Fix |
|---|---|---|
| `1 usable full administrator token(s) already exist; mint further tokens through POST /admin/v1/admin-tokens, or pass -force if every token has been lost` | An unexpired, unrevoked `admin_full` token exists, whether or not anyone still holds it | If every token really is lost, add `-force`. The audit entry records `detail.forced: true`. Then revoke the tokens nobody holds |
| `subject: pepper is not set: set N0PASSTEMPS_SUBJECT_PEPPER` | The command was run without the service's environment | Run it the way the service runs: through `docker compose run`, `kubectl exec`, or with the environment file loaded. [DEPLOYMENT.md](DEPLOYMENT.md#post-install-the-first-credentials) has a `systemd-run` line for the host form |
| A `kek:` refusal about mode or ownership | The command was run as a user who does not own the keyring | Run it as the service account |
| `-admins must be between 1 and 5, got 8` | The command establishes a quorum, it does not provision a team | Create two, and mint everyone else through `POST /admin/v1/admin-tokens`, where the action is attributed to a named administrator |
| `Dual approval is on and this deployment now has a single administrator.` on standard error, or an `admin_token.create` request that nobody can approve | The deployment was bootstrapped with one administrator while `features.dual_approval` is on. The API carries no exemption for a sole administrator, because a rogue administrator could reach one by revoking the others | Run the command again with `-force -admins 1` and give the new token to a different person. One token then requests, the other approves |

## An approved operation did not run

### Symptom

An administrator raised an erasure, a token creation, a revoke-all or a keyring
rewrap, got a 202 with the type `approval-required`, a colleague approved it,
and nothing happened. Or the requester repeated the call and got a 403.

### Cause

Approving runs nothing. The original requester redeems the approval by repeating
the identical request with the header `X-Approval-Id: <id>`. See
[ADR 0013](adr/0013-approvals-are-redeemed-not-executed.md).

### Confirm

Every refused redemption is the same 403 with no detail. The reason is in the
audit log:

```bash
curl -sS -G "$BASE/admin/v1/audit" -H "Authorization: Bearer $ADMIN" \
  --data-urlencode 'event_type=approval.rejected' --data-urlencode 'limit=20' \
  | jq -r '.entries[] | "\(.occurred_at) \(.resource_id) \(.detail.reason)"'
```

### Fix, by reason

| `detail.reason` | Cause | Fix |
|---|---|---|
| `approval is for a different operation` | The identifier belongs to another kind of request | Use the identifier from the 202 of this operation |
| `approval belongs to a different requester` | Someone other than the requester is redeeming, including the approver | The requester redeems, with the token that raised the request |
| `approval is pending` | Nobody has approved it yet | Have a different `admin_full` administrator approve it |
| `approval is rejected`, `approval is expired` | Decided against, or past `features.approval_ttl` | Raise it again |
| `approval is executed` or `approval was already spent` | It has been redeemed once. An approval is spent before the operation runs, so this is also what a retry after a failed operation sees | Raise it again |
| `approval has expired` | Approved, and the requester came back after `features.approval_ttl`, which is counted from the request | Raise it again |
| `request differs from what was approved` | The subject, the `reason`, the `name` or the `role` differs from the first call | Repeat the first call exactly. A changed reason is a different request |
| `unknown approval` | No such identifier in this tenant | Check the identifier |
| `self approval` | The requester tried to approve their own request | A different administrator decides |

A 400 saying `X-Approval-Id is not a valid identifier` means the header is not a
UUID.

## An API key gets 403, or 429 on every route

### Symptom

A valid API key is refused with HTTP 403 and the type
`urn:n0passtemps:error:forbidden`, on some routes and not others. Or it gets 429
on routes that record no authentication outcome, such as
`GET /v1/subjects/{subject_ref}`.

### Confirm

```bash
curl -sS "$BASE/admin/v1/api-keys" -H "Authorization: Bearer $ADMIN" \
  | jq -r '.api_keys[] | "\(.id) \(.name) scopes=\(.scopes)"'

curl -sS -G "$BASE/admin/v1/audit" -H "Authorization: Bearer $ADMIN" \
  --data-urlencode 'event_type=api_key.rejected' --data-urlencode 'outcome=denied' \
  | jq -r '.entries[] | "\(.occurred_at) \(.actor_id) wanted=\(.resource_id) \(.detail)"'
```

### Cause and fix

| What you see | Cause | Fix |
|---|---|---|
| 403, and the audit entry names a scope in `resource_id` that is not in `detail.held` | The key was minted with scopes that do not cover the route family. The families are `subjects`, `webauthn`, `totp`, `recovery`, `health`, `tickets` and `metrics` | Scopes cannot be edited. Mint a key with the scopes the integration needs, deploy it, revoke the old one. Most integrations need `subjects` as well as their factor |
| 403 from a key nobody expected to be calling that route | Either a misconfiguration, or a stolen key being explored | Treat it as the second until shown otherwise: read the source addresses in the audit entries |
| 400 when minting, `unknown scope ...; the scopes are subjects, webauthn, totp, recovery, health` | A misspelled scope | Correct it. The refusal exists so that the mistake does not surface later as this 403 |
| 429 with `Retry-After` on every public route | The key reached `throttle.max_requests_per_key` inside `throttle.window`. Every request on a public route counts, not only ceremonies | Wait, or raise the limit if the volume is legitimate. A sudden ceiling on a quiet integration is what a leaked key looks like |

## The database is unreachable

### Symptom

Requests return HTTP 503:

```json
{
  "type": "urn:n0passtemps:error:unavailable",
  "title": "the service is temporarily unavailable",
  "status": 503
}
```

`GET /v1/health` returns 503 with `{"status":"error"}`.

An authenticated route answers 503 as well, not 401, when the lookup of the
presented credential fails because the store is down. The credential was not
wrong, so nothing is audited as `api_key.rejected` or `admin.auth_failed`, and a
client should retry a 503 where it should not retry a 401.

### Confirm

```bash
curl -sS "$BASE/admin/v1/health" -H "Authorization: Bearer $ADMIN" | jq '.database'
```

```json
{ "status": "error", "engine": "postgres", "latency_ms": 3001, "detail": "database is not reachable" }
```

### Cause and fix

| Engine | Check | Fix |
|---|---|---|
| PostgreSQL | `psql "$DSN" -c 'select 1'` from the same host or pod | The usual: the cluster is down, the credentials changed, the network policy blocks 5432, or DNS fails. Under the shipped Kubernetes NetworkPolicy, a missing DNS egress rule looks exactly like a database outage, so check name resolution first |
| PostgreSQL | `database.max_open_conns` against the server's `max_connections` | A pool larger than the server allows fails intermittently under load, not at startup |
| SQLite | `ls -l` the database file and its `-wal` and `-shm` siblings; `stat -c '%U:%G %a'` | Wrong ownership after a restore, or a full filesystem. The service account must own all three |
| SQLite | `df -h` on the data directory | WAL mode needs room to write. A full volume makes every write fail |
| SQLite | `sqlite3 file.db 'pragma integrity_check'` | A genuinely corrupt file. Restore from backup |

Two SQLite-specific startup refusals are not outages but look like them:

```
sqlite: pragma journal_mode is "delete", expected "wal": readers would block behind every write
sqlite: pragma foreign_keys is "0", expected "1": ON DELETE CASCADE in the schema would not fire
```

Both mean the DSN's pragmas did not take effect, which in practice means the DSN
was overridden with one the builder did not construct, or the file is on a
filesystem that does not support WAL, such as some network mounts. Move the
database to local storage.

A `store: relation is append-only` error from a write means something tried to
modify the audit log outside the one permitted shape. That is a bug, not a
configuration problem; report it with the `request_id`.

## The audit chain reports broken

### Symptom

```bash
curl -sS "$BASE/admin/v1/audit/verify?from_seq=1" -H "Authorization: Bearer $ADMIN"
```

```json
{ "from_seq": 1, "checked": 48213, "intact": false, "broken_at": 10472 }
```

Returned with HTTP 409, not 200, so a check that reads only the status code does
not miss it. An `audit.chain_broken` alert is raised at critical severity, and
the failed run is itself recorded as `audit.chain_broken`.

### Confirm

Take a filesystem-level copy of the database before doing anything else, and
work on the copy.

```bash
# Where verification thinks the chain resumes from.
sqlite3 n0passtemps.db 'SELECT pruned_through_seq, entries_removed, created_at FROM audit_checkpoints ORDER BY pruned_through_seq'

# The entries either side of the break.
sqlite3 n0passtemps.db \
  'SELECT seq, occurred_at, event_type, outcome FROM audit_log WHERE seq BETWEEN 10468 AND 10476'
```

### Cause and fix

| Cause | How to tell | Fix |
|---|---|---|
| Verification started below a retention checkpoint | `audit_checkpoints.pruned_through_seq` is above `from_seq` | Verify from above the watermark. Pruned entries are gone and the chain resumes from `pruned_through_hash` |
| The database was restored from a backup taken at a different point, or two databases were merged | `broken_at` sits at a restore boundary; entries around it are contiguous in time but not in content | Nothing to repair. Record which range is trustworthy and why |
| The chain was rebuilt by an engine migration | The deployment moved between SQLite and PostgreSQL | A chain is valid only within the engine that produced it. Verify from the first entry the new engine wrote |
| Somebody edited the log | Everything else is ruled out | Treat it as a compromise of the host, not of the log |

What the result means, exactly: each entry commits to a hash of the entry before
it, so `broken_at` is the first entry that does not reproduce its stored hash,
and everything before it is intact. The chain makes tampering detectable, not
impossible. An operator with write access can edit an entry and recompute every
hash after it, provided nobody recorded the earlier head elsewhere. Comparing
the head against an external record is the only step that distinguishes a
restore from a rewrite, and it works only if something published the head off
the box. See [ADR 0007](adr/0007-chain-the-audit-log.md) and
[THREAT-MODEL.md](THREAT-MODEL.md).

There is no repair operation and there will not be one. A routine that
recomputed the chain would be exactly the tool an attacker needs.

## A certificate has expired

### Symptom

Browsers refuse the connection. If TLS terminates in process, every request
fails at the handshake and nothing reaches the logs.

### Confirm

```bash
curl -sS "$BASE/admin/v1/health" -H "Authorization: Bearer $ADMIN" | jq '.tls'
```

```json
{ "status": "error", "not_after": "2026-09-01T00:00:00Z", "expires_in_days": -16,
  "subject": "auth.example.com", "detail": "the certificate has expired" }
```

Fourteen days out it reports `degraded` with
`the certificate expires in 12 days`. Fourteen days sits well outside an ACME
client's thirty-day renewal window, so the warning only fires when automated
renewal has actually stopped working.

`"tls": null`, or the field absent, means TLS is not terminated in process. The
service cannot see a reverse proxy's certificate and reports nothing rather than
claiming something it does not know.

### Cause and fix

```bash
# Renew, then restart: the health report re-reads the file on every call, but
# the listener holds the certificate it started with.
sudo certbot renew
sudo systemctl restart n0passtemps
```

If the report says `the certificate file could not be read` or
`could not be parsed`, check the path in `server.tls_cert_file`, the ownership,
and that the file is a PEM bundle whose first `CERTIFICATE` block is the leaf.
The health check reads the first certificate block it finds, so a bundle
ordered with the root first reports the root's expiry.

For a proxy-terminated deployment, monitor the proxy's certificate with the
proxy's own tooling. This service has no visibility of it.

## TOTP codes are always refused

### Symptom

Every code the user enters is refused, including one read from a working
authenticator app. Confirmation of a fresh enrolment fails too.

```json
{ "type": "urn:n0passtemps:error:ceremony-failed", "title": "authentication did not succeed", "status": 401 }
```

### Confirm

Clock drift is the cause in the large majority of cases. Check both ends.

```bash
# The server.
timedatectl status
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null

# In a container, the host's clock is the container's clock.
docker exec n0passtemps date -u 2>/dev/null || date -u
```

Then check what the service recorded:

```bash
curl -sS "$BASE/admin/v1/audit?subject_id=$SUB&event_type=totp.&limit=20" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.entries[] | "\(.occurred_at) \(.event_type) \(.outcome) \(.detail)"'
```

### Cause and fix

| Evidence | Cause | Fix |
|---|---|---|
| Server clock is more than `totp.period × (totp.skew + 1)` away from real time | Clock drift. With the defaults, 30 seconds and a skew of 1, anything beyond about 45 seconds of drift refuses every code | Fix the clock. Enable NTP, and keep it enabled. Do not raise `totp.skew` to compensate: each extra period widens the window an attacker may guess in, and the validator caps it at 2 |
| `totp.replay_detected` entries | The code verified but its timestep was already spent. Either the user submitted twice, or a request is being replayed | Wait for the next period. A code is single-use even inside its own validity window, which is the point |
| `there is no enrolment awaiting confirmation`, HTTP 409 | The confirm call arrived with no pending secret | Start the enrolment again |
| `the enrolment has expired, start again`, HTTP 409 | The confirm call arrived after `totp.enrolment_ttl`, default 15 minutes. The pending secret is revoked | Start again. A secret shown to a user long ago must not be activatable by someone who later obtained it |
| The user's app shows a different number of digits than expected | The secret was enrolled under different parameters | Each secret carries the algorithm, digits and period it was issued with, and verification uses those. Changing `totp.digits` or `totp.period` does not migrate existing enrolments. Re-enrol, or revert the setting |
| The app rejected the QR code at enrolment | Padded base32 | The service strips the padding from both the typed secret and the provisioning URI, because several widely used authenticator applications reject a padded secret. If the app still refuses, the QR code was re-encoded somewhere in between |
| A subject with no confirmed secret | Refused identically to a wrong code, so the route cannot be used to discover who has TOTP enrolled | Check `totp_enrolled` on `GET /admin/v1/subjects/{subject_id}` |

Only `totp.skew` is read from the live configuration at verification time.
Everything else comes from the stored secret.

## A recovery code is refused

### Symptom

The user types a code from their sheet and it is refused.

### Confirm

```bash
curl -sS "$BASE/admin/v1/audit?subject_id=$SUB&event_type=recovery.&limit=20" \
  -H "Authorization: Bearer $ADMIN" | jq -r \
  '.entries[] | "\(.occurred_at) \(.event_type) \(.outcome) \(.detail.reason // "")"'

curl -sS "$BASE/admin/v1/subjects/$SUB" -H "Authorization: Bearer $ADMIN" \
  | jq '.recovery_codes_remaining'
```

The `detail.reason` on a `recovery.rejected` entry is one of five values, and
each one is a different problem.

### Cause and fix

| `detail.reason` | Cause | Fix |
|---|---|---|
| `code is malformed` | Not twenty characters from the alphabet after normalisation | Codes are Crockford base32 without `I`, `L`, `O` and `U`. Lowercase, spaces, hyphens and underscores are accepted and stripped; `I` and `L` fold to `1` and `O` folds to `0`. A `U` is refused, because it is not in the alphabet and there is no safe fold for it |
| `selector is unknown` | The first six characters match no issued code | Either a typo in the first group, or the sheet belongs to a retired batch. Issuing a batch retires every unused code from the previous one |
| `code belongs to a different subject` | The selector exists but under another subject | The user is holding somebody else's sheet, or the wrong account is being used |
| `code was already used` | Single use | Use another code from the sheet |
| `verifier did not match` | The selector is right and the rest is wrong | A typo after the first group. If it repeats with several codes, the sheet is from a retired batch whose selectors happen to have been reissued, which is vanishingly unlikely; reissue |
| `code was consumed concurrently` | Two requests presented the same code and the other one won | Use another code |

Nobody can read a code back. They are hashed with Argon2id, not encrypted, so
there is no operation that displays one again. Support cannot read a code out to
a caller, which is the point and also a recurring complaint. See
[ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md).

A user with zero codes left and no authenticator has no route back in from the
outside. Reissue a batch and transmit it out of band:

```bash
curl -sS -X POST "$BASE/admin/v1/subjects/$SUB/recovery/reissue" \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json'
```

An `Internal` 500 rather than a refusal means the stored hash is malformed,
which is an operational fault and not a failed attempt. It is deliberately not
recorded as an attempt. Report it with the `request_id`.

## The key encryption keyring is lost

This one matters, so it is stated precisely.

### Symptom

The process starts, WebAuthn works, and TOTP verification fails for everyone
with a 500. Or `GET /admin/v1/health` reports:

```json
{ "kek": { "status": "error", "current_version": 0, "retained_versions": 0,
           "detail": "the current key is not available" } }
```

Logs carry `envelope: kek version unavailable: version 1`.

### Confirm

Look for a copy, in this order: the backup you took before the first start, the
orchestrator's secret store, the previous host's `/etc`, the configuration
management repository. A keyring is 32 bytes of base64 in a small JSON document;
it is often somewhere nobody thought of it as a backup.

Confirm which key versions the data needs:

```bash
# SQLite: the first byte is the format version, bytes 2 to 5 the KEK version.
sqlite3 n0passtemps.db "SELECT id, hex(substr(secret_sealed, 2, 4)) FROM totp_secrets LIMIT 5"
```

### What is lost, exactly

The KEK protects exactly two things. Nothing else in the schema is sealed under
it.

| Data | Sealed under the KEK | Recoverable without it | Consequence of the loss |
|---|---|---|---|
| WebAuthn credentials: `public_key`, `credential_id`, `aaguid`, attestation type, flags | No, stored in clear | Yes, entirely | None. Every registered authenticator keeps working. This is the factor most deployments rely on, so the service degrades rather than failing closed. See [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) |
| Recovery codes | No, Argon2id hashes | Yes, entirely | None. Codes on issued sheets still verify, because verification is a hash comparison and needs no key. See [ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md) |
| API keys and administrative tokens | No, SHA-256 digests | Yes, entirely | None. Every existing credential keeps authenticating |
| Audit log, including the hash chain | No | Yes, entirely | None. The chain still verifies |
| Alerts, approvals, erasure requests, throttle buckets | No | Yes, entirely | None |
| `totp_secrets.secret_sealed` | **Yes** | **No** | Every TOTP enrolment is unrecoverable. Affected users must re-enrol |
| `subjects.ref_sealed` | **Yes** | **No** | The readable form of every subject reference is unrecoverable |

So the cost of a lost keyring is the TOTP secrets and the encrypted subject
references, and nothing else. That is not an accident: it is the direct
consequence of hashing recovery codes rather than sealing them
([ADR 0005](adr/0005-hash-recovery-codes-do-not-encrypt-them.md)) and storing
WebAuthn public keys in clear
([ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md)).

What losing `ref_sealed` actually costs:

- Subject **lookup still works**. It uses `ref_hmac`, derived from the pepper,
  which is a different secret. An integrating application can still authenticate
  its users by reference as before.
- `GET /admin/v1/subjects/{subject_id}?reveal_ref=true` stops returning a reference.
  The administration interface can no longer name the person a row belongs to.
- The GDPR Article 15 access path loses its content. You can confirm that a
  record exists for a given reference, because you can compute its HMAC, but you
  cannot produce the reference from the record.

Losing the **pepper** is a different and worse failure: without it `ref_hmac`
cannot be re-derived, so no existing subject can be found at all. The two
secrets are separate precisely so that the key able to decrypt secrets is not
also the key able to confirm whether a given person has an account.

### Fix

There is no recovery of the sealed data. Losing every copy of a KEK means the
secrets sealed under it are gone, which is why generation is an explicit,
documented operator step rather than a side effect of starting the server.

Recover the service, in this order:

1. **Generate a new keyring** and place it correctly, mode 0600, outside the
   data directory.

   ```bash
   n0passtemps-wizard kek init -out /etc/n0passtemps/kek/keyring.json
   ```

   It refuses to overwrite an existing file without `-force`, which is the
   guard that stops a second mistake compounding the first. Start at version 1
   again if the old versions are gone; nothing readable references them.

2. **Back it up before the first start.** This is the step whose omission caused
   the incident.

3. **Start the service.** It will come up. WebAuthn, recovery codes and every
   caller credential work immediately.

4. **Clear the unreadable rows.** A sealed record whose KEK version is absent
   returns `envelope: kek version unavailable`. Revoke the affected TOTP
   secrets so that users are offered a fresh enrolment rather than a permanent
   500:

   ```sql
   -- Confirm the scale first.
   SELECT COUNT(*) FROM totp_secrets WHERE revoked_at IS NULL;
   ```

   Then revoke them through the service rather than by editing the database, if
   a route exists for it in your version; otherwise the users' next enrolment
   supersedes the old secret.

5. **Tell the affected users to re-enrol TOTP.** Their WebAuthn authenticators
   and recovery codes are unaffected, so they can still log in to do it.

6. **Accept that `ref_sealed` is gone** for existing subjects. New subjects, and
   any subject an application resolves again with `seal_reference = true`, get a
   fresh sealed reference under the new key. `UpsertSubject` refreshes
   `ref_sealed` only when the incoming value is non-empty, so a plain login does
   not blank it and does not restore it either: the reference is re-sealed the
   next time `POST /v1/subjects` is called with the reference itself.

7. **Record the incident** in whatever your organisation uses, and check whether
   the lost keyring constitutes a personal data breach under GDPR Article 33.
   Loss of availability is a breach; consult [GDPR.md](GDPR.md) and your own
   counsel.

### Prevention

| Practice | Why |
|---|---|
| Back the keyring up before the first start, to a destination the data volume's loss does not reach | The two must never be in the same archive: that is the arrangement ADR 0009 exists to prevent |
| Back the pepper up separately from the keyring | They protect different things and losing the pepper is worse |
| Test the restore. Restore a database and a keyring into a scratch deployment and confirm a TOTP code verifies | An untested backup is a belief, not a backup |
| Keep `features.kek_rotation_reminder` on and read the health report | A rotation that was started and never finished leaves two retained versions, and `retained_versions` above one says so |
| Never let the server generate a key | It does not, and the refusal is deliberate: a key that appears by itself is a key nobody has backed up |
| Run `n0passtemps-wizard verify` against the backup on the same schedule as the backup | It is the cheap version of testing the restore, and it fails loudly while there is still time to find the right keyring |

## A backup does not verify

### Symptom

`n0passtemps-wizard verify` exits non-zero and prints one line to stderr,
beginning `n0passtemps-wizard verify:`.

### Confirm

Nothing to confirm: the line says which artefact is wrong. The exit status says
how seriously to take it.

| Status | Meaning |
|---|---|
| 0 | The trio opens |
| 1 | The trio does not open. A finding about the backup |
| 2 | Verification could not run, so no verdict was reached. Usually the invocation, not the backup |

A missing file is deliberately status 2, because a file that is not there
cannot be told apart from a path typed wrongly. A file that is there and wrong
is status 1.

### Cause and fix, by verdict

**`the keyring has no key version 2, which 143 records in
totp_secrets.secret_sealed are sealed under`**

The keyring predates a rotation, or a version was pruned while records still
referenced it. The version is read out of each record's header and needs no key
at all, which is why the count is exact. Find the keyring that holds version 2:
the backup taken after the rotation, the orchestrator's secret store, the
configuration management repository. If every copy is gone, those records are
unreadable and [The key encryption keyring is
lost](#the-key-encryption-keyring-is-lost) says exactly what that costs, which
is less than it sounds.

**`record <id> in subjects.ref_sealed is sealed under key version 1 and that
key did not open it`**

The version numbering matches and the key behind it does not. Either this is a
different keyring that happens to start at version 1, which is the usual cause
because `kek init` always writes version 1, or the record is damaged. The
message names both because an authenticated cipher cannot distinguish them: one
that could would be an oracle. Check whether the keyring is the one this
database was written with before concluding the database is corrupt.

**`the pepper does not derive the stored lookup value of subject <id>`**

The keyring is right and the pepper is not this database's. Reached by
unsealing that subject's reference and hashing it again, so it is a definite
answer rather than a guess. Find the right pepper; with the wrong one no
existing subject can be found at all, which is a worse failure than losing the
keyring.

**`N0PASSTEMPS_SUBJECT_PEPPER holds 16 bytes and at least 32 are required`**, or
**`does not decode as a pepper`**

The value in the environment is not the value `n0passtemps-wizard pepper`
produced. The decoder refuses to guess: prefix the value with `hex:`, `base64:`
or `raw:` to say what it is. The server would refuse to start with this value
too, so fixing it is not optional.

**`kek: "..." is mode 0644, must not be readable by group or other`**

The archive lost the mode, which `tar` does when it is unpacked by a different
user or extracted without `-p`. `chmod 600` the restored file. The server
refuses this file as well, so it is a real finding and not a pedantry about
backups.

**`... does not read as a SQLite database`**, or **`SQLite reports ... as
damaged`**

The file is truncated or corrupt. `PRAGMA quick_check` is what reports it, so
the finding is structural and not about the sealed columns. Almost always a
copy taken while the service was writing: a plain `cp` of a live database in
write-ahead-log mode is not a backup. Use SQLite's own `.backup`, or stop the
service first. [DEPLOYMENT.md](DEPLOYMENT.md) gives both.

**`records in ... do not begin with an envelope header`**

The column has been damaged in place, or written by something other than this
service. A hand-edited row is the likeliest cause. The identifier of the first
one is printed; read that row and the ones around it before anything else.

**`the database has migration [9999] applied and this binary only carries 4`**

The backup was written by a newer release. Verification is refused rather than
attempted: the tables it walks may well still be there, but a binary that does
not know what changed cannot claim it covered everything. Use the wizard from
the release that wrote the database.

**`nothing in this database is sealed`**

The database is migrated and empty, so it cannot demonstrate that this keyring
opens anything. Verify one that has at least one subject or one TOTP enrolment
in it.

**`no subject in this database has a sealed reference`**

`subject.seal_reference` was off, so there is nothing to recompute the pepper
against. The keyring and the database were verified and the pepper was not, and
status 2 says exactly that. Pass `-ref` with a reference you know is enrolled
to check the pepper against that subject's stored lookup value.

**`no subject matches the lookup value this pepper derives for the reference
given`**

With `-ref`, either the pepper is wrong or that reference was never enrolled
here. The two cannot be told apart from outside, so confirm the reference
before replacing the pepper.

### Prevention

Put the check in the cron entry that takes the backup, not in a runbook nobody
reads. [ADMIN-GUIDE.md](ADMIN-GUIDE.md#verifying-a-backup) has the entry, and
what the command proves and does not prove.

## Related documents

| Document | What it covers |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Every key and every validation rule |
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | The operations referenced above |
| [MONITORING.md](MONITORING.md) | Alerting so these symptoms are noticed before a user reports them |
| [WEBAUTHN.md](WEBAUTHN.md) | The ceremony and the platform differences |
| [FAQ.md](FAQ.md) | Shorter questions |
