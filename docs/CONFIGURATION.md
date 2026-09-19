# Configuration reference

Every key accepted by `internal/config/config.go`, its type, its default, the
environment variable that overrides it, and what it does. The validator is
strict and runs once at startup: a misconfigured authentication server refuses
to start with a precise message rather than running in a state its operator did
not intend.

## How configuration is assembled

Three sources, in increasing order of precedence:

| Order | Source | Notes |
|---|---|---|
| 1 | Built-in defaults | `config.Default()`. A deployment that sets only a database DSN, an `rp_id`, an origin and the two secrets is secure. |
| 2 | TOML file | Path passed to `config.Load`. Unknown keys are refused, so a misspelled `require_attestation` cannot silently leave attestation unverified. |
| 3 | Environment | Every key below has an override. An exported variable with an empty or whitespace-only value counts as unset, not as an empty string. |

Secrets are never TOML literals. The keyring and the subject pepper are read
from the environment by their own providers, and the database DSN, which has a
TOML field, is expected to come from the environment whenever it carries a
password.

Environment variable names are the dotted key, uppercased, with dots and
underscores flattened, behind the prefix `N0PASSTEMPS_`. So `webauthn.rp_id`
becomes `N0PASSTEMPS_WEBAUTHN_RP_ID`. The prefix is the constant
`config.EnvPrefix`.

Durations are strings parsed by `time.ParseDuration`: `30s`, `15m`, `24h`,
`720h`. An empty duration string is zero.

## Minimum working configuration

```toml
[tenant]
id = "acme"

[server]
addr = "127.0.0.1:8080"

[database]
driver = "sqlite"
dsn = "/var/lib/n0passtemps/n0passtemps.db"
data_dir = "/var/lib/n0passtemps"

[kek]
provider = "file"
path = "/etc/n0passtemps/kek/keyring.json"

[webauthn]
rp_id = "auth.example.com"
origins = ["https://auth.example.com"]

[assertion]
issuer = "https://auth.example.com"
signing_key_path = "/etc/n0passtemps/kek/assertion-key.pem"
```

Plus two secrets in the environment, neither of which has a TOML counterpart:

```bash
export N0PASSTEMPS_KEK='{"current":1,"keys":{"1":"<base64 of 32 random bytes>"}}'   # only with kek.provider = "env"
export N0PASSTEMPS_SUBJECT_PEPPER="$(openssl rand -hex 32)"
```

With `kek.provider = "file"` the keyring is the file at `kek.path` instead, and
`N0PASSTEMPS_KEK` is not read.

## tenant

Every table carries a tenant identifier even though one deployment serves one
tenant, because adding the column later would mean rewriting every query and
every index.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `tenant.id` | string | `default` | `N0PASSTEMPS_TENANT_ID` | Written into every row. Not a secret and not a URL, only a stable label. |
| `tenant.name` | string | `n0passtemps` | `N0PASSTEMPS_TENANT_NAME` | What the administration interface displays. |

Changing `tenant.id` on an existing deployment orphans all of its data. The
validator refuses a value that does not look deliberate.

Refused by the validator:

- `config: tenant.id is required`
- `config: tenant.id "system" is reserved for records that cannot be attributed to a tenant, such as a failed authentication`
- `config: tenant.id %q may contain only lowercase letters, digits, hyphen and underscore`

## server

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `server.addr` | string | `127.0.0.1:8080` | `N0PASSTEMPS_SERVER_ADDR` | Listener address as `host:port`. |
| `server.tls_cert_file` | string | empty | `N0PASSTEMPS_SERVER_TLS_CERT_FILE` | PEM certificate chain. Set together with the key to terminate TLS in process. |
| `server.tls_key_file` | string | empty | `N0PASSTEMPS_SERVER_TLS_KEY_FILE` | PEM private key. |
| `server.allow_plaintext` | bool | `false` | `N0PASSTEMPS_SERVER_ALLOW_PLAINTEXT` | Permits plain HTTP on a non-loopback address without declaring a reverse proxy. See below. |
| `server.trust_proxy` | bool | `false` | `N0PASSTEMPS_SERVER_TRUST_PROXY` | Declares that a reverse proxy terminates TLS and sets `X-Forwarded-For`. |
| `server.trusted_proxy_cidrs` | list of CIDR | empty | `N0PASSTEMPS_SERVER_TRUSTED_PROXY_CIDRS` | The networks a forwarded client address is honoured from. Required with `trust_proxy`. No entry may be wider than `/8` in IPv4 or `/7` in IPv6. |
| `server.read_timeout` | duration | `15s` | `N0PASSTEMPS_SERVER_READ_TIMEOUT` | Whole-request read deadline. Must be positive. |
| `server.write_timeout` | duration | `15s` | `N0PASSTEMPS_SERVER_WRITE_TIMEOUT` | Response write deadline. Must be positive. |
| `server.idle_timeout` | duration | `60s` | `N0PASSTEMPS_SERVER_IDLE_TIMEOUT` | Keep-alive idle deadline. Must be positive. |
| `server.read_header_timeout` | duration | `5s` | `N0PASSTEMPS_SERVER_READ_HEADER_TIMEOUT` | The defence against a slow-header denial of service. |
| `server.shutdown_grace` | duration | `20s` | `N0PASSTEMPS_SERVER_SHUTDOWN_GRACE` | How long in-flight requests have to finish on shutdown. |
| `server.max_body_bytes` | int64 | `262144` (256 KiB) | `N0PASSTEMPS_SERVER_MAX_BODY_BYTES` | Caps every request body. A WebAuthn attestation object is the largest legitimate payload and stays well under this. At most `16777216` (16 MiB). |
| `server.cors_allowed_origins` | list of origin | empty | `N0PASSTEMPS_SERVER_CORS_ALLOWED_ORIGINS` | Explicit allow list for the `/v1` routes. Never a wildcard. |

Refused by the validator:

- `config: server.addr is required`
- `config: server.addr %q is not host:port: ...`
- `config: server.tls_cert_file and server.tls_key_file must be set together`
- `config: server.addr %q is not loopback but TLS is not configured and server.trust_proxy is false; either terminate TLS here, set trust_proxy with trusted_proxy_cidrs when a reverse proxy terminates it, or set server.allow_plaintext when something outside this process already constrains who can reach the port, such as a container published to loopback`
- `config: server.trust_proxy requires server.trusted_proxy_cidrs; accepting a forwarded client address from any source lets a caller spoof the address that rate limiting and audit entries are keyed on`
- `config: server.trusted_proxy_cidrs entry %q is not a CIDR: ...`
- `config: server.trusted_proxy_cidrs entry %q is wider than /%d, the widest block a single operator controls; ...`
- `config: server.max_body_bytes must be positive`
- `config: server.max_body_bytes is %d, above the maximum of 16777216; ...`
- `config: server.cors_allowed_origins must not contain "*"; these endpoints are credentialed and a wildcard is both forbidden with credentials and unsafe`
- `config: server.read_header_timeout must be positive, it is the defence against a slow-header denial of service`
- `config: server.read_timeout must be positive, got %s; ...`, and the same for `server.write_timeout` and `server.idle_timeout`

A trusted proxy network is one whose every address is believed when it names
the client, so it has to be a network the operator owns outright. The widest
blocks reserved for private use are `10.0.0.0/8` and `fc00::/7`; anything wider,
`0.0.0.0/0` and `::/0` included, takes in addresses that belong to somebody else,
and any of them could then choose the address that rate limiting,
`admin.ip_allow_list` and the audit entries rely on. List the proxies
themselves, or the subnet the load balancer sits in.

`net/http` takes a zero or negative `read_timeout` or `write_timeout` to mean no
deadline at all, which lets a stalled connection be held open for as long as the
peer likes. None of the four timeouts accepts a value that means "unlimited".
`server.max_body_bytes` is bounded above for the same reason: the cap applies
before authentication, so it is also the most an anonymous caller can make the
service read per request.

An origin must be a scheme, a host and an optional port, with no path, no query
and no fragment. `http` is accepted only for `localhost`, `127.0.0.1` and
`::1`; anything else must be `https`, because WebAuthn requires a secure
context.

`server.allow_plaintext` exists for the one arrangement where plain HTTP on a
non-loopback address is safe and the service cannot tell: a container that binds
every interface inside its own network namespace and is published to loopback
on the host, or a pod whose reachability is set by a Service and a
NetworkPolicy. The binary sees `0.0.0.0:8080` and has no way to know what is in
front of it. It is an explicit opt-in, not a relaxed default, because the check
it overrides is the one that stops credentials being served unencrypted to
whatever can reach the port. An operator who sets it without something else
constraining reachability has turned off the check that would have caught them.
It does not make the service honour `X-Forwarded-For`, and it does not enable
HSTS; both still need `trust_proxy`. The two compose files and the Kubernetes
ConfigMap in `deploy/` set it.

Setting `server.tls_cert_file`, or `server.trust_proxy`, also makes the service
emit `Strict-Transport-Security: max-age=31536000; includeSubDomains`, but only
on a request that actually arrived over TLS: at this process, or at a proxy
inside `server.trusted_proxy_cidrs` that says so in `X-Forwarded-Proto`. The
header is ignored from any other peer.

## database

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `database.driver` | string | `sqlite` | `N0PASSTEMPS_DATABASE_DRIVER` | `sqlite` or `postgres`. |
| `database.dsn` | string | `n0passtemps.db` | `N0PASSTEMPS_DATABASE_DSN` | A file path for SQLite, a libpq connection string or `postgres://` URL for PostgreSQL. |
| `database.data_dir` | string | `/var/lib/n0passtemps` | `N0PASSTEMPS_DATABASE_DATA_DIR` | Directory holding persistent state. The keyring is refused if it lives here. |
| `database.max_open_conns` | int | `8` | `N0PASSTEMPS_DATABASE_MAX_OPEN_CONNS` | Pool ceiling. For SQLite it bounds the read pool; the write pool is always one connection. |
| `database.max_idle_conns` | int | `4` | `N0PASSTEMPS_DATABASE_MAX_IDLE_CONNS` | Idle connections retained. |
| `database.conn_max_lifetime` | duration | `30m` | `N0PASSTEMPS_DATABASE_CONN_MAX_LIFETIME` | Recycles a connection after this long, which matters in front of a connection proxy. |
| `database.busy_timeout` | duration | `5s` | `N0PASSTEMPS_DATABASE_BUSY_TIMEOUT` | SQLite only. WAL mode still serialises writers, so a concurrent writer waits rather than failing immediately. |
| `database.allow_plaintext` | bool | `false` | `N0PASSTEMPS_DATABASE_ALLOW_PLAINTEXT` | PostgreSQL only. Permits `sslmode=disable` towards a host that is not loopback. An explicit acknowledgement that the link is private; see below. |
| `database.auto_migrate` | bool | `true` | `N0PASSTEMPS_DATABASE_AUTO_MIGRATE` | Applies pending migrations at startup. Set false to apply schema changes as a separate reviewed step. |

Refused by the validator:

- `config: database.driver is required`
- `config: database.driver %q is not supported, use "sqlite" or "postgres"`
- `config: database.dsn is required`
- `config: database.max_open_conns must be positive`
- `config: database.max_idle_conns (%d) cannot exceed max_open_conns (%d)`

With `driver = "postgres"` the DSN is inspected for transport encryption:

- `no sslmode is set; libpq defaults to "prefer", which falls back to an unencrypted connection without reporting it. Set sslmode=require or stronger, or sslmode=disable explicitly for a loopback socket`
- `sslmode=disable towards %q sends credentials and secrets in clear; use sslmode=require, verify-ca or verify-full, or set database.allow_plaintext when the link is a private container network that never leaves the host`
- `sslmode=%s does not guarantee an encrypted connection; use sslmode=require, verify-ca or verify-full`

Both DSN forms are parsed, the URL form and the `key=value` form, and in the URL
form a `host` query parameter overrides the authority, as libpq has it.
`require`, `verify-ca` and `verify-full` are accepted. `allow` and `prefer` are
always refused. `disable` is accepted on its own when the connection stays on
the machine: a loopback name or address, a Unix socket directory, or an
empty host, for which libpq uses the default socket.

Towards any other host, `disable` needs `database.allow_plaintext = true`. The
one arrangement where that is defensible is a database on a private container
network that never leaves the host, which is what
`deploy/docker-compose.postgres.yml` sets up and why that file sets the key. The
validator cannot see network topology, so, as with `server.allow_plaintext`, the
operator has to say so explicitly. The default remains a refusal, because a DSN
that sends credentials and TOTP seeds in clear across a real network is the
likelier mistake. The acknowledgement covers `disable` and nothing else: it does
not make `prefer` or `allow` acceptable, because those modes fall back silently
and nobody chose them on purpose.

## kek

The key encryption key wraps the data encryption keys that seal TOTP secrets
and the encrypted copy of a subject reference. A KEK is never generated
implicitly at runtime: creation is an explicit operator step, because a key
that appears by itself is a key nobody has backed up.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `kek.provider` | string | `file` | `N0PASSTEMPS_KEK_PROVIDER` | `file`, `env` or `tpm`. |
| `kek.path` | string | `/etc/n0passtemps/kek/keyring.json` | `N0PASSTEMPS_KEK_PATH` | Keyring file, used when the provider is `file` or `tpm`. Must not resolve inside `database.data_dir`. Under `file` it must also be mode 0600; under `tpm` it holds ciphertext, so the mode is not a load-time condition. |
| `kek.env_var` | string | `N0PASSTEMPS_KEK` | `N0PASSTEMPS_KEK_ENV_VAR` | Name of the variable holding the keyring, used when the provider is `env`. |
| `kek.tpm_device` | string | `/dev/tpmrm0` | `N0PASSTEMPS_KEK_TPM_DEVICE` | TPM 2.0 device node, used when the provider is `tpm`. The resource-managed node is the default, because it lets more than one process share the device's few transient object slots. |
| `kek.rotation_interval` | duration | `8760h` (365 days) | `N0PASSTEMPS_KEK_ROTATION_INTERVAL` | How long a key version may remain current before the detailed health report calls rotation overdue. Zero disables the reminder. Rotation itself is always an explicit operator action. |

Refused by the validator:

- `config: kek.provider is required`
- `config: kek.provider %q is not supported, use "file", "env" or "tpm"`
- `config: kek.path is required when kek.provider is "file"`
- `config: kek.env_var is required when kek.provider is "env"`
- `config: kek.path is required when kek.provider is "tpm"; it is the sealed keyring`
- `config: kek.path %q is inside the data directory %q; a key stored beside the ciphertext it protects gives no confidentiality if the volume is copied, so mount it separately or use kek.provider "env"`

The placement check resolves symbolic links on both sides before comparing, so
a symlink or bind mount into the data directory does not pass a textual test.
The provider repeats the check at load time and additionally refuses a keyring
whose permission bits grant anything to group or other:

```
kek: %q is mode 0644, must not be readable by group or other (chmod 600)
```

See [ADR 0009, Refuse to load a key encryption key stored inside the data
directory](adr/0009-refuse-a-kek-inside-the-data-directory.md).

### Sealing the keyring to a TPM

`provider = "tpm"` reads a keyring that has been encrypted to this machine's
TPM 2.0. It is off by default and this section says why before it says how.

**What it closes.** Attacker 5 of [THREAT-MODEL.md](THREAT-MODEL.md) holds a
copy of the database and a copy of the keyring, and against that position the
model says, in as many words, that nothing is mitigated. The likeliest way to
get there is not a clever attack: it is one backup archive or one volume
snapshot containing both. ADR 0009 keeps the two on separate volumes and cannot
keep them out of the same tar file. Sealing does: the keyring on disk becomes
ciphertext that opens on one machine, so a copied volume, a stolen backup, a
cloned virtual disk or a decommissioned drive carries nothing usable.

**What it does not close.** Anything at all against a live compromise of this
host. An attacker running as the service account asks the same TPM to unseal,
exactly as the service does, and the keyring is then in process memory as it
always was. This is protection at rest. It is not protection in use, and a
deployment that reads it as the latter has overestimated what it has.

**The cost, which is not small.** A TPM cannot be backed up. A dead board, a
replaced motherboard or a cleared owner hierarchy makes the sealed file
unreadable for ever, and with it every TOTP secret and every sealed subject
reference in the database. **Sealing adds a layer in front of the offline copy
of the plaintext keyring. It does not replace it.** Deleting the plaintext
because a sealed copy exists is building a way to lose your own data.

Sealing therefore moves a risk rather than removing one: less exposure to a
stolen disk, more to a dead one. Which of those a deployment would rather carry
is not a question this project answers for it, which is why the provider is
opt-in.

```bash
n0passtemps-wizard kek seal \
  -in  /etc/n0passtemps/kek/keyring.json \
  -out /etc/n0passtemps/kek/keyring.sealed.json
```

The command unseals what it has just produced and compares it against the input
before writing anything, so a TPM that seals but will not unseal is found here
rather than at the next start. Then:

```toml
[kek]
provider = "tpm"
path = "/etc/n0passtemps/kek/keyring.sealed.json"
# tpm_device = "/dev/tpmrm0"
```

The service account needs read and write on the device node, which on most
distributions means membership of the `tss` group.

**No PCR binding.** The sealed object is bound to the TPM's owner hierarchy and
to nothing else. Binding it to platform configuration registers as well, so that
it unseals only under the boot state it was sealed under, sounds strictly better
and is not: every firmware, kernel and bootloader update moves those registers,
the service then stops starting for a reason nobody connects to the update, and
what operators do is recover from the plaintext and turn the binding off. It
also does nothing about the attacker this is for, who has a copy of the disk and
no TPM to present it to.

**Rotation still works the same way.** `kek rotate` operates on the plaintext
keyring; seal the result again afterwards. The sealed file is not edited in
place, and the old one is worth keeping until the new one has been seen to load.

See [ADR 0019](adr/0019-seal-the-keyring-to-a-tpm.md).

Keyring format, whether in a file or in a variable:

```json
{
  "current": 1,
  "keys": {
    "1": "<standard base64 of exactly 32 bytes>"
  }
}
```

Key versions are decimal strings in canonical form, starting at 1. `"01"` is
refused, because it and `"1"` parse to the same version, and a keyring holding
both would protect the database with a different key from one start to the
next. `"0"` is refused because version 0 is reserved:

- `kek: key version %q is not in canonical form, write it as %d`
- `kek: key version 0 is reserved; versions start at 1`

Every key must decode to 32 bytes, and `current` must name a key that is
present.

The keyring is read once, at startup. After `n0passtemps-wizard kek rotate` the
service has to be restarted before it seals under the new version, and before
`POST /admin/v1/kek/rewrap` can move existing records onto it. An older version
may be deleted from the file only when that route reports `versions_in_use`
holding the current version alone and `failed` at zero. The procedure is in
[ADMIN-GUIDE.md](ADMIN-GUIDE.md#rotating-the-keyring).

## subject

The reference an integrating application uses for its own user is treated as
personal data. It is stored as a deterministic HMAC for lookup and, optionally,
as an envelope-encrypted copy.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `subject.pepper_env` | string | `N0PASSTEMPS_SUBJECT_PEPPER` | `N0PASSTEMPS_SUBJECT_PEPPER_ENV` | Names the variable holding the HMAC pepper used to derive the lookup key. |
| `subject.max_ref_length` | int | `256` | `N0PASSTEMPS_SUBJECT_MAX_REF_LENGTH` | Bounds the accepted reference, so an application cannot use the field as arbitrary storage. |
| `subject.seal_reference` | bool | `true` | `N0PASSTEMPS_SUBJECT_SEAL_REFERENCE` | Stores an encrypted copy of the original reference, which is what makes a subject access request and the administration interface able to name a person. |

Refused by the validator:

- `config: subject.pepper_env is required`
- `config: subject.max_ref_length must be between 1 and 4096, got %d`

The pepper itself is read by `internal/subject`, which requires at least 32
bytes of key material and unsets the variable once it has been read. The
encoding is never guessed. These forms are accepted, and nothing else:

| Form | Read as |
|---|---|
| `hex:<digits>` | Hexadecimal. The recommended way to be explicit |
| `base64:<text>` | Base64, standard or URL alphabet, padded or not |
| `raw:<text>` | The bytes of the text itself. This is how a passphrase is supplied, and it has to be asked for |
| Unprefixed, an even number of hexadecimal digits | Hexadecimal. Tried before base64, because a hex string is also valid base64 and would decode to a different, shorter key |
| Unprefixed base64 that decodes to at least 32 bytes | Base64 |

Anything else is refused. In particular, unprefixed base64 of fewer than 32
bytes is not quietly used as a passphrase: the base64 of a 24-byte secret is 32
characters long, and treating those characters as the key would yield one with
far less entropy than its length suggests. The output of
`n0passtemps-wizard pepper` and of `openssl rand -hex 32` are both valid as they
are.

Its own refusals:

- `subject: pepper is not set: set N0PASSTEMPS_SUBJECT_PEPPER`
- `subject: pepper is too short: N0PASSTEMPS_SUBJECT_PEPPER holds %d bytes, at least 32 are required`
- `subject: pepper is too short: the value is not hexadecimal and is not base64 of at least 32 bytes. Generate one with "n0passtemps-wizard pepper", or prefix the value with hex:, base64: or raw: to say what it is`
- `subject: pepper is marked hex but does not decode: ...`
- `subject: pepper is marked base64 but does not decode`

The pepper must be backed up with the same care as the keyring: losing it makes
every existing subject unfindable. It is a separate secret from the KEK so that
the key able to decrypt secrets is not also the key able to confirm whether a
given person has an account.

## webauthn

`rp_id` and `origins` are server configuration and are never read from a
request. See [ADR 0003, The service is the WebAuthn relying
party](adr/0003-the-service-is-the-webauthn-relying-party.md).

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `webauthn.rp_id` | string | none, required | `N0PASSTEMPS_WEBAUTHN_RP_ID` | The relying party identifier: a bare registrable domain, or `localhost`. |
| `webauthn.rp_display_name` | string | `n0passtemps` | `N0PASSTEMPS_WEBAUTHN_RP_DISPLAY_NAME` | Name shown by the authenticator during a ceremony. |
| `webauthn.origins` | list of origin | none, required | `N0PASSTEMPS_WEBAUTHN_ORIGINS` | The origins a ceremony response may declare. |
| `webauthn.challenge_ttl` | duration | `5m` | `N0PASSTEMPS_WEBAUTHN_CHALLENGE_TTL` | How long a stored challenge stays usable. |
| `webauthn.ceremony_timeout` | duration | `2m` | `N0PASSTEMPS_WEBAUTHN_CEREMONY_TIMEOUT` | Timeout given to the browser and enforced by the library on both ceremonies. |
| `webauthn.user_verification` | string | `required` | `N0PASSTEMPS_WEBAUTHN_USER_VERIFICATION` | `required`, `preferred` or `discouraged`. `required` makes the authenticator prove user presence and identity, which is what makes a single WebAuthn factor sufficient. |
| `webauthn.attestation_preference` | string | `none` | `N0PASSTEMPS_WEBAUTHN_ATTESTATION_PREFERENCE` | `none`, `indirect` or `direct`. |
| `webauthn.require_attestation` | bool | `false` | `N0PASSTEMPS_WEBAUTHN_REQUIRE_ATTESTATION` | Refuses a registration whose attestation cannot be verified. |
| `webauthn.metadata_path` | string | empty | `N0PASSTEMPS_WEBAUTHN_METADATA_PATH` | A FIDO Metadata Service (MDS3) BLOB on disk, loaded at startup. Its JWT signature is verified against the FIDO root, so a file altered on disk is refused. It is never fetched over the network; refreshing it is an operator duty. See [WEBAUTHN.md](WEBAUTHN.md#attestation-policy). |
| `webauthn.allowed_aaguids` | list of AAGUID | empty | `N0PASSTEMPS_WEBAUTHN_ALLOWED_AAGUIDS` | Restricts registration to named authenticator models. Empty means any model. |
| `webauthn.blocked_aaguids` | list of AAGUID | empty | `N0PASSTEMPS_WEBAUTHN_BLOCKED_AAGUIDS` | Refuses named models, for withdrawing a device whose firmware has a published flaw. |
| `webauthn.max_credentials_per_subject` | int | `10` | `N0PASSTEMPS_WEBAUTHN_MAX_CREDENTIALS_PER_SUBJECT` | Bounds enrolment, so a compromised API key cannot quietly add an unbounded number of authenticators. |
| `webauthn.clone_warning_alerts` | bool | `true` | `N0PASSTEMPS_WEBAUTHN_CLONE_WARNING_ALERTS` | Raises an alert when an authenticator's signature counter fails to advance. It does not refuse the assertion. |
| `webauthn.refuse_sign_count_regression` | bool | `false` | `N0PASSTEMPS_WEBAUTHN_REFUSE_SIGN_COUNT_REGRESSION` | Refuses an assertion whose signature counter moved strictly backwards from a stored value that was not zero, which no authenticator does by itself. A counter that stays still is still accepted, because most passkeys report zero for ever. Off by default: the signal is reported either way, and refusing is a policy an operator chooses. |
| `webauthn.admin_origins` | list of origin | empty | `N0PASSTEMPS_WEBAUTHN_ADMIN_ORIGINS` | The origins the administration console's own passkey ceremonies accept. Empty is allowed only when `webauthn.origins` names exactly one origin, which the console then shares. With several, the console would otherwise accept an assertion obtained from any of them, which is the anti-phishing property a passkey exists for. |

An AAGUID is the canonical 36-character 8-4-4-4-12 hexadecimal form.

Refused by the validator:

- `config: webauthn.rp_id is required`
- `config: webauthn.origins must list at least one origin`
- `config: webauthn.rp_id: %q looks like a URL; rp_id is a bare domain such as "example.com"`
- `config: webauthn.rp_id: %q must not contain a path`
- `config: webauthn.rp_id: %q must not include a port`
- `config: webauthn.rp_id: %q is an IP address; WebAuthn requires a domain name`
- `config: webauthn.rp_id: %q is not a domain name`
- `config: webauthn.origins: origin %q is not covered by rp_id %q; the relying party identifier must equal the origin's domain or be a parent of it`
- `config: webauthn.user_verification %q is not valid, use "required", "preferred" or "discouraged"`
- `config: webauthn.user_verification "discouraged" means the authenticator proves possession only, so a WebAuthn assertion is no longer sufficient on its own; set "required" or "preferred"`
- `config: webauthn.attestation_preference %q is not valid, use "none", "indirect" or "direct"`
- `config: webauthn.require_attestation needs attestation_preference "direct" or "indirect", otherwise the authenticator is never asked for a statement to verify`
- `config: webauthn.require_attestation = true needs webauthn.metadata_path; with no metadata BLOB no attestation statement is checked against a trust anchor, and allowed_aaguids does not stand in for one because the AAGUID it matches on is declared by the client...`
- `config: webauthn.admin_origins is empty while webauthn.origins lists %d origins, so a console ceremony would accept an assertion obtained from any of them...`
- `config: webauthn.metadata_path %q is not readable: ...`
- `config: webauthn.allowed_aaguids: %q is not a 36 character AAGUID`
- `config: AAGUID %s appears in both allowed_aaguids and blocked_aaguids`
- `config: webauthn.challenge_ttl must be between 30s and 15m, got %s`
- `config: webauthn.max_credentials_per_subject must be at least 1`

`user_verification = "discouraged"` is a valid WebAuthn value that this
validator refuses outright, rather than warning about. It is the one setting
where the specification's vocabulary and this deployment's security model
disagree.

Under `preferred`, an assertion made without user verification succeeds, and the
signed result says so: the `webauthn-uv` factor is reported from the
authenticator data of the ceremony in hand, never from what the credential did
at registration. An application that relies on user verification under
`preferred` has to check for that factor on every assertion. See
[WEBAUTHN.md](WEBAUTHN.md#what-a-successful-assertion-returns).

## totp

Time-based one-time passwords per RFC 6238, over the HMAC counter construction
of RFC 4226. Counter-based HOTP per RFC 4226 is not offered; see [ADR 0011,
Drop HOTP](adr/0011-drop-hotp.md).

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `totp.issuer` | string | `n0passtemps` | `N0PASSTEMPS_TOTP_ISSUER` | Issuer label in the provisioning URI. Must not contain a colon. |
| `totp.algorithm` | string | `SHA1` | `N0PASSTEMPS_TOTP_ALGORITHM` | `SHA1`, `SHA256` or `SHA512`. SHA1 is the default because it is what authenticator applications actually implement; the HMAC construction does not inherit SHA-1's collision weakness. |
| `totp.digits` | int | `6` | `N0PASSTEMPS_TOTP_DIGITS` | 6 or 8. |
| `totp.period` | duration | `30s` | `N0PASSTEMPS_TOTP_PERIOD` | The RFC 6238 time step. A whole number of seconds. |
| `totp.secret_bytes` | int | `20` | `N0PASSTEMPS_TOTP_SECRET_BYTES` | Length of a generated shared secret. |
| `totp.skew` | int | `1` | `N0PASSTEMPS_TOTP_SKEW` | Periods accepted either side of the current one, to tolerate clock drift. |
| `totp.enrolment_ttl` | duration | `15m` | `N0PASSTEMPS_TOTP_ENROLMENT_TTL` | How long an unconfirmed secret remains usable. |

Refused by the validator:

- `config: totp.algorithm %q is not valid, use "SHA1", "SHA256" or "SHA512"`
- `config: totp.digits must be 6 or 8, got %d`
- `config: totp.period must be between 15s and 120s, got %s`
- `config: totp.secret_bytes must be at least 20, RFC 4226 section 4 requires a shared secret of at least 128 bits and recommends 160, got %d`
- `config: totp.skew must be between 0 and 2; each additional period widens the window an attacker may guess in, got %d`

Changing `algorithm`, `digits` or `period` does not migrate existing
enrolments. Each secret carries the parameters it was issued with, and
verification uses those; only `totp.skew` is read from the live configuration
at verification time.

## recovery

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `recovery.code_count` | int | `16`, or `8` in lite mode | `N0PASSTEMPS_RECOVERY_CODE_COUNT` | How many codes an issuance produces. |
| `recovery.low_watermark` | int | `3` | `N0PASSTEMPS_RECOVERY_LOW_WATERMARK` | Raises an alert once a subject has this many codes left, so a user is prompted to reissue before running out. |

Refused by the validator:

- `config: recovery.code_count must be between 1 and 64, got %d`
- `config: recovery.low_watermark (%d) must be below code_count (%d), otherwise a fresh batch is already in the warning state`

## tickets

An enrolment ticket is a single-use, short-lived secret that permits exactly one
WebAuthn registration and never produces a signed assertion. It is the way back
in for a user who holds no authenticator yet, or who has lost every one they
had.

Delivering it is the integrating application's responsibility: this service sends
no email and makes no outbound connection. Whoever controls the channel the
application chooses can enrol an authenticator until the ticket expires, and the
two settings below are what bound that.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `tickets.ttl` | duration | `1h` | `N0PASSTEMPS_TICKETS_TTL` | How long a ticket may be redeemed for. The lifetime is the whole window an intercepted ticket is good for. |
| `tickets.require_existing_factor_default` | bool | `true` | `N0PASSTEMPS_TICKETS_REQUIRE_EXISTING_FACTOR_DEFAULT` | Refuse to issue a ticket for a subject who already holds an active authenticator or a confirmed TOTP secret. |

Refused by the validator:

- `config: tickets.ttl must be positive and at most 24h; the lifetime is the window in which an intercepted ticket can be redeemed, got %s`

The 24h ceiling is a judgement and it is worth stating why. A ticket is a
hand-off, not a credential: it exists to carry a user from a helpdesk call to a
registered key, which takes minutes. Anything that outlives a working day is
being used as a standing credential, and a standing credential delivered by
email is the thing enrolment tickets were designed to avoid.

Leave `require_existing_factor_default` at `true`. An individual request may
override it by sending `require_existing_factor: false`, which is the caller
stating that the existing factor is genuinely unusable; that override is audited
with `existing_factor_override: true` and raises the
`enrolment_ticket.factor_override` alert. Setting the default to `false` makes
every such issuance an override, which is only reasonable in a deployment that
enrols users through tickets as a matter of course and has accepted that a ticket
for an account with factors is an account-takeover primitive for whoever controls
delivery.

Neither setting is touched by lite mode. The guard is a security property rather
than a governance feature, and a lite deployment has fewer operators watching the
alert list, not more.

## assertion

A successful ceremony returns a detached signature the integrating application
verifies offline. See [ADR 0004, Return a signed assertion rather than a bare
200](adr/0004-return-a-signed-assertion-result.md).

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `assertion.issuer` | string | `n0passtemps` | `N0PASSTEMPS_ASSERTION_ISSUER` | The `iss` claim. Identifies this deployment, and a verifier pins it. |
| `assertion.signing_key_path` | string | `/etc/n0passtemps/kek/assertion-key.pem` | `N0PASSTEMPS_ASSERTION_SIGNING_KEY_PATH` | An Ed25519 private key in PKCS#8 PEM form. |
| `assertion.retired_public_key_paths` | list of strings | empty | `N0PASSTEMPS_ASSERTION_RETIRED_PUBLIC_KEY_PATHS` | Ed25519 public keys in SubjectPublicKeyInfo PEM form, published at the JWKS route and never signed with. Empty in normal running; see [Rotating the signing key](#rotating-the-signing-key). |
| `assertion.ttl` | duration | `60s` | `N0PASSTEMPS_ASSERTION_TTL` | How long an assertion stays valid. |
| `assertion.allowed_clock_skew` | duration | `30s` | `N0PASSTEMPS_ASSERTION_ALLOWED_CLOCK_SKEW` | Subtracted from `nbf` so a verifier whose clock lags slightly accepts a token immediately. It does not extend `exp`. |

Refused by the validator:

- `config: assertion.issuer is required`
- `config: assertion.signing_key_path is required`
- `config: assertion.ttl must be positive and at most 5m; the assertion proves a ceremony just completed and is exchanged immediately, got %s`
- `config: assertion.retired_public_key_paths[0] is empty`
- `config: assertion.retired_public_key_paths[0] is the signing key path; a rotation points signing_key_path at the new key and lists the previous public key here`
- `config: assertion.retired_public_key_paths[1] repeats %q`

The key loader refuses a file that is not exactly one PKCS#8 PEM block holding
an Ed25519 key, and refuses a permissive file mode:

- `assertion: signing key has permissive file mode: %q is mode 0644, must not be readable by group or other (chmod 600)`
- `assertion: malformed PKCS#8 PEM file: %q holds a "RSA PRIVATE KEY" block, expected "PRIVATE KEY" (convert with: openssl pkcs8 -topk8 -nocrypt)`
- `assertion: malformed PKCS#8 PEM file: %q has trailing data after the PEM block`
- `assertion: key is not an Ed25519 key: %q holds a *rsa.PrivateKey, and this package signs only with Ed25519`

A retired key is loaded by the same package with one difference: no file mode is
checked, because the file is a public key that the service serves to every
caller anyway. A private key given where a public one was expected is refused
rather than read, since the consequence would be signing material in a published
document:

- `assertion: malformed PKCS#8 PEM file: %q holds a private key, and a retired key is published to every caller; give the "PUBLIC KEY" file written beside it`

### Rotating the signing key

One Ed25519 key signs every assertion, and whoever reads it can mint a token for
any subject that every verifier accepts. Rotating is therefore the response to a
suspected compromise, and the reason it has to be an operation rather than an
emergency is that the naive version causes an outage twice over: a token issued
a few seconds before the restart is refused, and so is every token reaching an
application whose cached copy of the key set predates it.

`retired_public_key_paths` is what removes both. The outgoing public key stays in
the JWK Set for one changeover window while only the new key signs, and the `kid`
header of each token selects between them, so no verifier needs to be told
anything.

```
n0passtemps-wizard assertion-key rotate -file /etc/n0passtemps/kek/assertion-key.pem
```

It writes the new signing key in place, keeps the outgoing key beside it as a
`.pub.pem` and a `.pem`, and prints the line to add:

```toml
[assertion]
signing_key_path = "/etc/n0passtemps/kek/assertion-key.pem"
retired_public_key_paths = ["/etc/n0passtemps/kek/assertion-key.20260918T134531Z.pub.pem"]
```

Restart, then **close the window**. It has to close: a retired key goes on
verifying whatever its private half signs, so an entry left in place indefinitely
is the rotation not having happened. The window has to cover `assertion.ttl`
plus `assertion.allowed_clock_skew` plus the five minutes the JWKS response is
cacheable, which at the defaults is six and a half minutes; an hour covers it
with room to spare. Then remove the line, delete the outgoing private key and
restart again.

Every start logs a warning while the list is not empty, naming the key
identifiers still published, because the configuration is the only record that a
window is open and the warning is what stops it being open in a year.

Two entries are normal if a second rotation happens inside one window. The same
path twice, or the signing key's own path, is refused at startup.

## throttle

Limits are applied per subject, per source address and per API key at the same
time. A single limit is always the wrong one: per subject alone lets an attacker
spray one attempt across many accounts, and per address alone punishes every
user behind one NAT gateway.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `throttle.enabled` | bool | `true` | `N0PASSTEMPS_THROTTLE_ENABLED` | Turns rate limiting on. With it off nothing in this section is read and the store is never consulted. |
| `throttle.window` | duration | `15m` | `N0PASSTEMPS_THROTTLE_WINDOW` | The fixed counting window. |
| `throttle.max_failures_per_subject` | int | `10` | `N0PASSTEMPS_THROTTLE_MAX_FAILURES_PER_SUBJECT` | Failures against one subject, on one factor, before that factor is locked out for the subject. WebAuthn, TOTP and recovery codes each hold this budget separately, and a success clears the count of the factor it used. The same number bounds guesses at one enrolment ticket. |
| `throttle.max_failures_per_ip` | int | `50` | `N0PASSTEMPS_THROTTLE_MAX_FAILURES_PER_IP` | Failures from one normalised network before a lockout. On `/v1` the network is the one declared in `X-End-User-IP`, and the limit is not applied to a request that declares none; see below. |
| `throttle.max_requests_per_key` | int | `6000` | `N0PASSTEMPS_THROTTLE_MAX_REQUESTS_PER_KEY` | Total volume from one API key inside the window, which bounds what a leaked key achieves. Metered by a middleware on every public route that takes a key, whether or not the route records an authentication outcome. A rate limit, not a lockout: the request after the ceiling is refused with a `Retry-After` that runs to the end of the window, and `lockout_duration` plays no part. |
| `throttle.lockout_duration` | duration | `15m` | `N0PASSTEMPS_THROTTLE_LOCKOUT_DURATION` | How long a tripped failure bucket refuses attempts. Not shorter than `throttle.window`. |
| `throttle.admin_revoke_burst` | int | `10` | `N0PASSTEMPS_THROTTLE_ADMIN_REVOKE_BURST` | Revocations one administrator may perform inside the window. This is the control that replaces the reversible revocation the specification called for; see [ADR 0010](adr/0010-revocation-is-final.md). |

Refused by the validator, when `throttle.enabled` is true:

- `config: throttle.window must be positive when throttling is enabled`
- `config: throttle.max_failures_per_subject must be at least 1`
- `config: throttle.max_failures_per_ip (%d) below max_failures_per_subject (%d) makes the per-subject limit unreachable`
- `config: throttle.max_requests_per_key must be at least 1; the per-key ceiling cannot be switched off on its own, so raise it if an application legitimately needs more`
- `config: throttle.lockout_duration must be positive when throttling is enabled`
- `config: throttle.lockout_duration (%s) is shorter than throttle.window (%s), so a lockout would be reapplied by the first attempt after it; set lockout_duration to at least the window`
- `config: throttle.admin_revoke_burst must be at least 1`

A threshold of zero is refused rather than read as "no limit". It used to load,
and the dimension it belonged to then counted attempts and never acted on the
count.

IPv6 sources are bucketed by their `/64` prefix, IPv4 by the single address. A
single host is routinely delegated a whole `/64`, so a per-address limit there
is bypassed at no cost.

### Whose address the per-address limit counts

`/v1` is called by the integrating application's backend, so the peer address
of a request is the backend's and is the same for every one of its users.
Limiting on it would put them all in one bucket, which any visitor of the
application's sign-in page could fill with wrong codes, locking everybody out.

The application therefore declares the end user's address on the ceremony
routes, in the `X-End-User-IP` request header:

```
X-End-User-IP: 203.0.113.50
```

- The value is one IPv4 or IPv6 address, with no port, no zone and no prefix
  length. Anything else is a 400, not a silent fallback: a fallback would run
  the integration without the limit and nobody would notice.
- When the header is present, its value is the network the per-address limit
  and the `recent_failures_network` risk reason are computed on.
- When it is absent, the per-address limit is not applied to that request. The
  per-subject, per-ticket and per-key limits still are.
- The audit log keeps the peer address as `source_ip` and records the declared
  one as `end_user_ip` in the entry's detail. One was observed and the other
  was stated by an authenticated caller, and the log keeps them apart.

The header is trusted as far as the API key is: a caller that lies in it only
removes a limit from its own users. It has nothing to do with
`server.trust_proxy`, which decides how the peer address is read through a
reverse proxy. The administration console and the authentication of API keys
and administrative tokens limit on the peer address, which for them is the
right one. The three SDKs take the address as a per-request option.

A route that names no subject, the usernameless assertion, has no per-subject
dimension to fall back on. Without the header it is bounded by the per-key
ceiling alone, which is one more reason to send it.

## risk

Risk signals reported on a completed authentication. The service reports and
never refuses on risk, so nothing in this section can lock anyone out: what it
changes is the `risk` claim of the signed assertion, the `risk` key of the
audit entry detail, and whether a `risk.high` alert is raised. The reason
table, the weights and the reasoning behind every default are in
[RISK.md](RISK.md).

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `risk.enabled` | bool | `true` | `N0PASSTEMPS_RISK_ENABLED` | Reports risk. With it off the claim is omitted from the assertion entirely rather than present and empty, so a verifier written against such a deployment is unaffected by one that has it on. |
| `risk.elevated_at` | int | `20` | `N0PASSTEMPS_RISK_ELEVATED_AT` | Score at which the level becomes `elevated`, inclusive. It is the weight of the lightest single signal that says the ceremony proved less than a full unphishable factor. |
| `risk.high_at` | int | `40` | `N0PASSTEMPS_RISK_HIGH_AT` | Score at which the level becomes `high`, inclusive. Double `elevated_at`: one signal that is evidence of an attack, or the weakest factor together with the failures that preceded it. |
| `risk.dormant_after` | duration | `2160h` | `N0PASSTEMPS_RISK_DORMANT_AFTER` | How long a credential must go unused before `credential_dormant` fires. Ninety days: a spare key is routinely unused for a quarter, and a shorter window reports ordinary behaviour as a signal. |
| `risk.new_credential_within` | duration | `1h` | `N0PASSTEMPS_RISK_NEW_CREDENTIAL_WITHIN` | How recently a credential must have been registered for `credential_new` to fire. An enrolment followed by a sign-in is one sitting. |
| `risk.weights` | table of int | the defaults in [RISK.md](RISK.md) | none, file only | Overrides the weight of individual reasons, keyed on the reason strings. |

`[risk.weights]` has deliberately no environment counterpart. The weights are
the policy itself, which belongs in the file that is committed and reviewed
rather than in one deployment's environment, and a flat environment namespace
would need one variable per reason, which is a second copy of a closed set and
so a second place for it to drift.

```toml
[risk]
enabled = true
elevated_at = 20
high_at = 40
dormant_after = "2160h"
new_credential_within = "1h"

[risk.weights]
# A deployment where every user holds a security key treats a TOTP sign-in as
# more of an exception than the defaults do.
totp_only = 20
# And one that has no opinion about dormancy silences it. The reason still
# appears in the claim, because it did fire; it contributes nothing.
credential_dormant = 0
```

Refused by the validator, whether or not reporting is enabled, so that turning
it on later does not turn a file that loaded yesterday into one that refuses to:

- `config: risk.elevated_at must be at least 1, got %d`
- `config: risk.high_at must be at least 1, got %d`
- `config: risk.elevated_at (%d) must be below risk.high_at (%d)`
- `config: risk.dormant_after must be positive, got %s`
- `config: risk.new_credential_within must be positive, got %s`
- `config: risk.weights has no reason %q` for a key that is not one of the nine
- `config: risk.weights.%s is %d` for a negative weight
- `config: risk.weights sets every reason to 0, so the score is always 0 and the risk claim always reads "low"; give at least one reason a positive weight, or set risk.enabled = false so that the claim is omitted instead of always reassuring`

An unknown reason key is refused rather than ignored because a misspelled
reason would sit in the file doing nothing while the operator believed they had
retuned the policy, and nothing at runtime would ever tell them.

## audit

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `audit.retention_days` | int | `0` | `N0PASSTEMPS_AUDIT_RETENTION_DAYS` | Bounds growth. Zero keeps entries forever, which is the default: silently discarding audit history is a decision an operator must take explicitly. |
| `audit.verify_on_start` | bool | `false` | `N0PASSTEMPS_AUDIT_VERIFY_ON_START` | Recomputes the hash chain at startup. Off by default because the cost is linear in the size of the log. |
| `audit.max_query_limit` | int | `500` | `N0PASSTEMPS_AUDIT_MAX_QUERY_LIMIT` | Caps a single audit query, because this is the one table that grows without bound. It also caps the page size of the other administrative listings. |

Refused by the validator:

- `config: audit.max_query_limit must be between 1 and 10000, got %d`
- `config: audit.retention_days cannot be negative`

## audit.sink

Delivers a copy of the audit chain to a destination outside this deployment.
Everything in this section is off by default, and with it off the service makes
no outbound connection of any kind: no shipper is built, so there is no idle
client and no timer.

### The trust assumption, stated

The hash chain makes tampering detectable by anybody who kept an earlier head.
It does not survive the operator of this server, who owns the database file and
can therefore edit a row and recompute every hash from the edit onwards;
`/admin/v1/audit/verify` will then report the log as intact. Attacker 9 in
[THREAT-MODEL.md](THREAT-MODEL.md) sets this out in full.

A sink closes that only if the receiver is genuinely somebody else's. A file on
this host, a bucket under the same cloud credentials, or a log collector the
same root account administers all fall to exactly the attacker the chain already
fails to stop, so a sink of that kind is worthless rather than merely weaker.
This service cannot tell which kind it has been handed, so the operator declares
it with `receiver_outside_operator_control`, and an endpoint without that
declaration is refused at startup.

Setting it also accepts the second half of the assumption: a delivered entry is
beyond this service's reach for ever, an erasure request included. What the
receiver holds carries no personal data, so nothing there answers to Article 17;
what it holds is a salted commitment that cannot be reversed without a salt
which never leaves this database. A deployment that wants the receiver's copy
bounded anyway bounds it with the receiver's own retention.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `audit.sink.endpoint` | string | empty | `N0PASSTEMPS_AUDIT_SINK_ENDPOINT` | Where each batch is POSTed. Empty means the sink is off, and there is deliberately no separate `enabled` flag: the endpoint is the switch, so an empty section cannot be half on. Must be `https`, except towards loopback. |
| `audit.sink.token_env` | string | `N0PASSTEMPS_AUDIT_SINK_TOKEN` | `N0PASSTEMPS_AUDIT_SINK_TOKEN_ENV` | Names the variable holding the bearer credential. The credential itself has no file and no TOML form, like every other secret. |
| `audit.sink.receiver_outside_operator_control` | bool | `false` | `N0PASSTEMPS_AUDIT_SINK_RECEIVER_OUTSIDE_OPERATOR_CONTROL` | The declaration above. An endpoint is refused without it. |
| `audit.sink.buffer_size` | int | `1024` | `N0PASSTEMPS_AUDIT_SINK_BUFFER_SIZE` | Bounds the in-memory hand-off from the recorder. Overflowing it costs latency, not entries; see below. |
| `audit.sink.batch_size` | int | `128` | `N0PASSTEMPS_AUDIT_SINK_BATCH_SIZE` | Entries per POST, and the page size of a catch-up read from the audit log. Cannot exceed `buffer_size`. |
| `audit.sink.flush_interval` | duration | `5s` | `N0PASSTEMPS_AUDIT_SINK_FLUSH_INTERVAL` | How long a partial batch waits for company. It is what bounds how far behind the witness runs when traffic is light. |
| `audit.sink.timeout` | duration | `10s` | `N0PASSTEMPS_AUDIT_SINK_TIMEOUT` | Bounds one POST. Generous, because no request path waits on it. |
| `audit.sink.retry_backoff` | duration | `1s` | `N0PASSTEMPS_AUDIT_SINK_RETRY_BACKOFF` | The pause after the first failed attempt. |
| `audit.sink.max_retry_backoff` | duration | `5m` | `N0PASSTEMPS_AUDIT_SINK_MAX_RETRY_BACKOFF` | The ceiling the pause doubles up to. Delivery is retried for ever rather than abandoned: the entries stay in the audit log, so a witness that is behind catches up while one the sender gave up on never does. |
| `audit.sink.watermark_path` | path | empty | `N0PASSTEMPS_AUDIT_SINK_WATERMARK_PATH` | Where delivery progress is recorded. Empty puts it at `audit-sink.watermark` inside `database.data_dir`. It holds one sequence number and no secret. |

A minimal working section:

```toml
[audit.sink]
endpoint = "https://witness.example.org/v1/audit"
receiver_outside_operator_control = true
```

with the credential in the environment:

```
N0PASSTEMPS_AUDIT_SINK_TOKEN=<what the receiver issued>
```

Refused by the validator, and only when an endpoint is set, because with none
the section is never read:

- `config: audit.sink.endpoint %q is not a URL: ...`
- `config: audit.sink.endpoint %q must use scheme https, or http towards loopback only`
- `config: audit.sink.endpoint %q has no host`
- `config: audit.sink.endpoint %q uses plain http towards a host that is not loopback; it would send the bearer credential and the shape of this deployment's audit history in clear`
- `config: audit.sink.receiver_outside_operator_control must be set to true before an endpoint is accepted. ...`
- `config: audit.sink.token_env is required when an endpoint is set; the receiver has to be able to tell this deployment from anybody else who finds the URL`
- `config: audit.sink.buffer_size must be at least 1, got %d`
- `config: audit.sink.batch_size must be at least 1, got %d`
- `config: audit.sink.batch_size (%d) cannot exceed buffer_size (%d)`
- `config: audit.sink.flush_interval must be positive`
- `config: audit.sink.timeout must be positive`
- `config: audit.sink.retry_backoff must be positive; a zero pause would turn an unreachable receiver into a busy loop`
- `config: audit.sink.max_retry_backoff (%s) must not be below retry_backoff (%s)`

Two further failures stop the start rather than being reported by the validator,
because they are about the environment rather than the file. A `token_env` that
names an empty or unset variable is refused, and so is a `watermark_path` whose
directory cannot be written: both would otherwise leave a deployment believing
it had a witness when it did not.

### What is delivered, and what is not

Each entry is reduced to the fields the chain hash commits to, which is exactly
what a receiver needs in order to recompute the hashes and detect a gap:
`seq`, `tenant_id`, `occurred_at`, `event_type`, `actor_type`, `actor_id`,
`resource_type`, `resource_id`, `outcome`, `request_id`, `pii_digest`,
`prev_hash` and `entry_hash`.

`subject_id`, `source_ip` and `detail` are not sent. The chain covers a salted
digest of those three rather than the fields themselves, which is what allows an
entry to be erased without breaking verification, and it is the digest that
travels. The per-entry salt is not sent either: a source address carries about
thirty-two bits of entropy, so a receiver holding both the salt and the digest
would recover the address by exhaustive search.

`detail` is the field that would otherwise have been the leak. Nothing models
its shape and nothing bounds what a future handler puts in it, so it is bounded
by exclusion rather than by a filter somebody would have to keep up to date. The
consequence is that the external copy answers one question, whether this history
was rewritten, and cannot be used to investigate an incident or to rebuild the
log.

### What happens when the buffer fills

Nothing that reaches a user. `Offer` never blocks and never fails: the entry is
dropped from the queue, counted in `audit_sink.dropped_offers` in the detailed
health report, logged once per episode, and the shipper falls back to reading
the audit log from one past the last acknowledged sequence number. So a full
buffer costs a database read and some latency, never a gap in the witness. The
same fallback covers an out-of-order offer, a failed POST and a restart.

A `dropped_offers` count that keeps climbing means `buffer_size` is too small
for the deployment's write rate, or the receiver is too slow for it. Neither is
urgent, and neither loses anything.

### At least once, and what a receiver has to do

The watermark is written only after the receiver has acknowledged a batch, so a
process that dies in between sends that batch again. The other order would be at
most once: the marker would move, the entries would never arrive, and nothing
anywhere would know.

A receiver therefore has three obligations. It de-duplicates on `seq`, and a
second copy of a `seq` that differs from the first is evidence rather than a
duplicate. It checks `count`, `from_seq` and `to_seq` against the entries it was
given, so a body that arrived incomplete is refused instead of stored as though
complete. And it checks that `seq` runs consecutively and that each `prev_hash`
equals the previous `entry_hash`, which is how 41, 42, 44 is detected, twice
over. `auditsink.CheckSequence` is that check, written once so it can be copied
rather than described.

A batch looks like this:

```json
{
  "format": "n0passtemps.audit.v1",
  "source": "default",
  "sent_at": "2026-09-20T11:04:07Z",
  "from_seq": 41,
  "to_seq": 42,
  "count": 2,
  "entries": [
    {
      "seq": 41,
      "tenant_id": "default",
      "occurred_at": "2026-09-20T11:04:02.412331Z",
      "event_type": "webauthn.assertion.completed",
      "actor_type": "subject",
      "outcome": "success",
      "request_id": "01JB2...",
      "pii_digest": "9mJ...=",
      "prev_hash": "Tq4...=",
      "entry_hash": "b7F...="
    }
  ]
}
```

`source` is a label for a receiver collecting from several deployments. It is
not evidence of anything: the bearer credential the receiver issued is what
identifies the sender.

Any 2xx is an acknowledgement. Anything else, including a 401, is retried with
the backoff, because a rejected credential is fixed by an operator rotating what
the receiver expects and only a retry picks that up without a restart.

### Retention and the witness pull in opposite directions

An entry trimmed by `audit.retention_days` before it was delivered cannot be
delivered, and the receiver sees a gap it cannot tell from tampering. The
shipper reports that case at error level rather than shipping in silence:

```
audit entries are missing from the local log and cannot be delivered
expected_seq=1841 first_available_seq=2210
```

The guidance is unchanged from the [audit](#audit) section: leave
`retention_days` at 0 and prune deliberately, and with a sink configured, prune
only what the receiver has acknowledged.

## admin

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `admin.ui_enabled` | bool | `true` | `N0PASSTEMPS_ADMIN_UI_ENABLED` | Serves the server-rendered interface at `/admin`. Deployments that administer the service purely through the API turn it off to remove the surface. |
| `admin.session_ttl` | duration | `30m` | `N0PASSTEMPS_ADMIN_SESSION_TTL` | Bounds an administrator's browser session. |
| `admin.session_cookie_secure` | bool | `true` | `N0PASSTEMPS_ADMIN_SESSION_COOKIE_SECURE` | Marks the session cookie `Secure`. Forced on whenever TLS is terminated in process or a trusted proxy is declared. |
| `admin.ip_allow_list` | list of CIDR | empty | `N0PASSTEMPS_ADMIN_IP_ALLOW_LIST` | Restricts the whole `/admin` surface, the `/admin/v1` API included, to named networks. Applied before authentication, and a caller outside it receives 404 rather than 403. Required unless the listener is loopback with no trusted proxy. |
| `admin.passkey_required` | bool | `false` | `N0PASSTEMPS_ADMIN_PASSKEY_REQUIRED` | Refuses an administrative token pasted into the console once that token has a passkey enrolled, so the operator signs in with the key instead. Scoped to the token and not to the deployment. |

Refused by the validator:

- `config: admin.session_ttl must be positive and at most 12h, got %s`
- `config: admin.ip_allow_list is empty while the service is reachable beyond loopback (listener %q, trust_proxy %t); ...`
- `config: admin.ip_allow_list entry %q is not a CIDR: ...`
- `config: admin.ip_allow_list entry %q admits every address, so the list restricts nothing while reading as though it did. ...`

The first applies only when `admin.ui_enabled` is true. The others apply always,
because the allow list guards the `/admin/v1` API as well as the interface, and
turning the console off leaves that API served on the same port.

The list is required as soon as a caller on another machine can reach the
service: when `server.addr` is not loopback, and also when it is loopback but
`server.trust_proxy` is set, since the proxy in front is then what faces the
network. Behind a proxy the list is matched against the client address resolved
from `X-Forwarded-For`, not against the proxy's own. An entry of prefix length
zero, `0.0.0.0/0` or `::/0`, is refused: a list that admits everyone is not a
list.

`admin.session_cookie_secure = false` survives validation only on a loopback
listener with no proxy, or where `server.allow_plaintext` is set. TLS and
`trust_proxy` force it on, and a non-loopback listener with neither is refused
by the `server` section unless `allow_plaintext` says something else constrains
the port.

`admin.passkey_required` is refused by nothing, and the scope is why. It asks a
question per token rather than per deployment: a token that holds no usable
passkey is accepted in the form whatever this is set to. That floor is what makes
it safe to turn on with a single administrator, because
`n0passtemps-server -bootstrap-admin` mints a token with no passkey and so
always produces a way back in. Withdrawing the last passkey has the same effect
for an existing token, immediately.

It changes nothing on `/admin/v1`, which takes a bearer token because its caller
is a script. See [ADR 0017](adr/0017-administrative-sign-in-with-webauthn.md) and
the passkey section of [ADMIN-GUIDE.md](ADMIN-GUIDE.md).

## logging

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `logging.level` | string | `info` | `N0PASSTEMPS_LOGGING_LEVEL` | `debug`, `info`, `warn` or `error`. |
| `logging.format` | string | `json` | `N0PASSTEMPS_LOGGING_FORMAT` | `json` or `text`. JSON is the default: logs are meant to be ingested, not read. |
| `logging.include_source_ip` | bool | `true` | `N0PASSTEMPS_LOGGING_INCLUDE_SOURCE_IP` | Records the client address on log lines. It is personal data under GDPR, so it is a deliberate choice rather than an accident. |
| `logging.redact_subject_refs` | bool | `true` | `N0PASSTEMPS_LOGGING_REDACT_SUBJECT_REFS` | Replaces an application-supplied subject reference with a short prefix of its digest. On by default because these references are frequently email addresses whatever the documentation advises. |

Refused by the validator:

- `config: logging.level %q is not valid, use "debug", "info", "warn" or "error"`
- `config: logging.format %q is not valid, use "json" or "text"`

Redaction is enforced in the log handler rather than at the call site, so a new
call site cannot forget it.

## features

These gate the behaviour that distinguishes the lite deployment from the
complete one. They are configuration rather than build tags, so one binary and
one schema serve both and a deployment can adopt a feature without migrating.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `features.lite_mode` | bool | `false` | `N0PASSTEMPS_FEATURES_LITE_MODE`, or `LITE_MODE` | Shorthand that relaxes the four governance features below. |
| `features.admin_rbac` | bool | `true` | `N0PASSTEMPS_FEATURES_ADMIN_RBAC` | Enforces the three administrative roles. With it off, every valid role carries full authority. |
| `features.dual_approval` | bool | `true` | `N0PASSTEMPS_FEATURES_DUAL_APPROVAL` | Holds sensitive operations for a second administrator. The requester redeems the approval by repeating the identical request with the header `X-Approval-Id`. |
| `features.dual_approval_operations` | list of string | `credential.revoke_bulk`, `subject.erase`, `admin_token.create`, `kek.rotate` | `N0PASSTEMPS_FEATURES_DUAL_APPROVAL_OPERATIONS` | Names the operations the queue intercepts. Each of the four has a route: revoke-all, erasure, administrative token creation and the keyring rewrap. Any other name is refused, because the gate matches by name and a misspelled one would hold nothing. |
| `features.approval_ttl` | duration | `24h` | `N0PASSTEMPS_FEATURES_APPROVAL_TTL` | How long a queued operation lives, counted from the request. It bounds the decision and the redemption together. |
| `features.deferred_erasure` | bool | `true` | `N0PASSTEMPS_FEATURES_DEFERRED_ERASURE` | Blocks a subject immediately and purges the record after the retention window, instead of deleting at once. |
| `features.erasure_retention` | duration | `720h` (30 days) | `N0PASSTEMPS_FEATURES_ERASURE_RETENTION` | The window in which a pending erasure can still be cancelled. |
| `features.kek_rotation_reminder` | bool | `true` | `N0PASSTEMPS_FEATURES_KEK_ROTATION_REMINDER` | Reports overdue rotation in the detailed health report, and has the janitor raise the `kek.rotation_overdue` alert. |
| `features.janitor_interval` | duration | `5m` | `N0PASSTEMPS_FEATURES_JANITOR_INTERVAL` | How often expired challenges, stale throttle buckets, expired approvals and due erasures are swept. |
| `features.rotation_grace` | duration | `24h` | `N0PASSTEMPS_FEATURES_ROTATION_GRACE` | How long a rotated API key or administrative token keeps working beside its successor when the rotation request names no `grace`. `0s` stops the predecessor at once. At most `168h`; the same maximum applies to a `grace` given in a request. See [ADMIN-GUIDE.md](ADMIN-GUIDE.md#rotating-an-api-key-without-downtime). |

Refused by the validator:

- `config: features.dual_approval is on but dual_approval_operations is empty, so nothing is actually held for a second administrator`
- `config: features.dual_approval_operations has no operation %q, so it would hold nothing; the operations are credential.revoke_bulk, subject.erase, admin_token.create, kek.rotate`
- `config: features.dual_approval requires features.admin_rbac; without distinct roles there is no way to tell two administrators apart`
- `config: features.approval_ttl must be positive when dual_approval is on`
- `config: features.erasure_retention must be positive when deferred_erasure is on`
- `config: features.janitor_interval must be positive; expired challenges and due erasures would otherwise never be swept`
- `config: features.rotation_grace must not be negative; use "0s" to stop a rotated credential at once`
- `config: features.rotation_grace is 720h0m0s, above the maximum of 168h0m0s; an overlap that long is two live credentials, not a rotation`

### What lite mode actually changes

`features.lite_mode` is applied after the file and the environment have been
read, and only relaxes settings that neither of them set explicitly. An explicit
setting therefore wins over the shorthand wherever it was made:
`N0PASSTEMPS_FEATURES_ADMIN_RBAC=true` keeps role enforcement on under lite mode
exactly as `admin_rbac = true` in the file does, and
`N0PASSTEMPS_DATABASE_DRIVER=postgres` keeps PostgreSQL. A variable exported
with an empty value counts as unset here as everywhere else.

| Setting | Value lite mode applies | Condition |
|---|---|---|
| `features.admin_rbac` | `false` | Neither the file nor the environment set it |
| `features.dual_approval` | `false` | Neither the file nor the environment set it |
| `features.deferred_erasure` | `false` | Neither the file nor the environment set it |
| `features.kek_rotation_reminder` | `false` | Neither the file nor the environment set it |
| `database.driver` | `sqlite` | Neither the file nor the environment set it |
| `recovery.code_count` | `8` | Neither the file nor the environment set it and the value is still the default 16 |

`LITE_MODE` is accepted without the `N0PASSTEMPS_` prefix as well, because the
published quickstart uses the short form and changing it would break copied
commands. The two forms name one setting, so when both are present they have to
agree: `LITE_MODE=true` beside `N0PASSTEMPS_FEATURES_LITE_MODE=false` is refused
at startup rather than settled in favour of either, because the operator is the
only one who knows which was meant.

Nothing else changes. WebAuthn, TOTP, recovery codes, the audit chain, the
throttle and the alert engine are identical in both modes.

## Environment variables that are not configuration keys

| Variable | Read by | Purpose |
|---|---|---|
| `N0PASSTEMPS_KEK` | `internal/crypto/kek` | The keyring itself, when `kek.provider = "env"`. The default value of `kek.env_var`. Unset by the process once parsed. |
| `N0PASSTEMPS_SUBJECT_PEPPER` | `internal/subject` | The HMAC pepper. The default value of `subject.pepper_env`. Unset by the process once parsed. |
| `LITE_MODE` | `internal/config` | Unprefixed alias for `features.lite_mode`. Refused when it contradicts `N0PASSTEMPS_FEATURES_LITE_MODE`. |

## Related documents

| Document | What it covers |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Where each of these values goes in the four supported deployment forms |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | What to do when one of the refusals above appears at startup |
| [MONITORING.md](MONITORING.md) | The health report these settings are visible in |
| [RISK.md](RISK.md) | The reason table, the weights and the thresholds the `[risk]` section tunes |
| [docs/adr](adr/README.md) | Why the defaults are what they are |
