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
| `server.trusted_proxy_cidrs` | list of CIDR | empty | `N0PASSTEMPS_SERVER_TRUSTED_PROXY_CIDRS` | The networks a forwarded client address is honoured from. Required with `trust_proxy`. |
| `server.read_timeout` | duration | `15s` | `N0PASSTEMPS_SERVER_READ_TIMEOUT` | Whole-request read deadline. |
| `server.write_timeout` | duration | `15s` | `N0PASSTEMPS_SERVER_WRITE_TIMEOUT` | Response write deadline. |
| `server.idle_timeout` | duration | `60s` | `N0PASSTEMPS_SERVER_IDLE_TIMEOUT` | Keep-alive idle deadline. |
| `server.read_header_timeout` | duration | `5s` | `N0PASSTEMPS_SERVER_READ_HEADER_TIMEOUT` | The defence against a slow-header denial of service. |
| `server.shutdown_grace` | duration | `20s` | `N0PASSTEMPS_SERVER_SHUTDOWN_GRACE` | How long in-flight requests have to finish on shutdown. |
| `server.max_body_bytes` | int64 | `262144` (256 KiB) | `N0PASSTEMPS_SERVER_MAX_BODY_BYTES` | Caps every request body. A WebAuthn attestation object is the largest legitimate payload and stays well under this. |
| `server.cors_allowed_origins` | list of origin | empty | `N0PASSTEMPS_SERVER_CORS_ALLOWED_ORIGINS` | Explicit allow list for the `/v1` routes. Never a wildcard. |

Refused by the validator:

- `config: server.addr is required`
- `config: server.addr %q is not host:port: ...`
- `config: server.tls_cert_file and server.tls_key_file must be set together`
- `config: server.addr %q is not loopback but TLS is not configured and server.trust_proxy is false; either terminate TLS here, set trust_proxy with trusted_proxy_cidrs when a reverse proxy terminates it, or set server.allow_plaintext when something outside this process already constrains who can reach the port, such as a container published to loopback`
- `config: server.trust_proxy requires server.trusted_proxy_cidrs; accepting a forwarded client address from any source lets a caller spoof the address that rate limiting and audit entries are keyed on`
- `config: server.trusted_proxy_cidrs entry %q is not a CIDR: ...`
- `config: server.max_body_bytes must be positive`
- `config: server.cors_allowed_origins must not contain "*"; these endpoints are credentialed and a wildcard is both forbidden with credentials and unsafe`
- `config: server.read_header_timeout must be positive, it is the defence against a slow-header denial of service`

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
on a request that actually arrived over TLS.

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
| `kek.provider` | string | `file` | `N0PASSTEMPS_KEK_PROVIDER` | `file` or `env`. |
| `kek.path` | string | `/etc/n0passtemps/kek/keyring.json` | `N0PASSTEMPS_KEK_PATH` | Keyring file, used when the provider is `file`. Must be mode 0600 and must not resolve inside `database.data_dir`. |
| `kek.env_var` | string | `N0PASSTEMPS_KEK` | `N0PASSTEMPS_KEK_ENV_VAR` | Name of the variable holding the keyring, used when the provider is `env`. |
| `kek.rotation_interval` | duration | `8760h` (365 days) | `N0PASSTEMPS_KEK_ROTATION_INTERVAL` | How long a key version may remain current before the detailed health report calls rotation overdue. Zero disables the reminder. Rotation itself is always an explicit operator action. |

Refused by the validator:

- `config: kek.provider is required`
- `config: kek.provider %q is not supported, use "file" or "env"`
- `config: kek.path is required when kek.provider is "file"`
- `config: kek.env_var is required when kek.provider is "env"`
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
- `config: webauthn.require_attestation needs either a metadata_path or an allowed_aaguids list; with neither there is nothing to verify an attestation statement against`
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

## assertion

A successful ceremony returns a detached signature the integrating application
verifies offline. See [ADR 0004, Return a signed assertion rather than a bare
200](adr/0004-return-a-signed-assertion-result.md).

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `assertion.issuer` | string | `n0passtemps` | `N0PASSTEMPS_ASSERTION_ISSUER` | The `iss` claim. Identifies this deployment, and a verifier pins it. |
| `assertion.signing_key_path` | string | `/etc/n0passtemps/kek/assertion-key.pem` | `N0PASSTEMPS_ASSERTION_SIGNING_KEY_PATH` | An Ed25519 private key in PKCS#8 PEM form. |
| `assertion.ttl` | duration | `60s` | `N0PASSTEMPS_ASSERTION_TTL` | How long an assertion stays valid. |
| `assertion.allowed_clock_skew` | duration | `30s` | `N0PASSTEMPS_ASSERTION_ALLOWED_CLOCK_SKEW` | Subtracted from `nbf` so a verifier whose clock lags slightly accepts a token immediately. It does not extend `exp`. |

Refused by the validator:

- `config: assertion.issuer is required`
- `config: assertion.signing_key_path is required`
- `config: assertion.ttl must be positive and at most 5m; the assertion proves a ceremony just completed and is exchanged immediately, got %s`

The key loader refuses a file that is not exactly one PKCS#8 PEM block holding
an Ed25519 key, and refuses a permissive file mode:

- `assertion: signing key has permissive file mode: %q is mode 0644, must not be readable by group or other (chmod 600)`
- `assertion: malformed PKCS#8 PEM file: %q holds a "RSA PRIVATE KEY" block, expected "PRIVATE KEY" (convert with: openssl pkcs8 -topk8 -nocrypt)`
- `assertion: malformed PKCS#8 PEM file: %q has trailing data after the PEM block`
- `assertion: key is not an Ed25519 key: %q holds a *rsa.PrivateKey, and this package signs only with Ed25519`

## throttle

Limits are applied per subject, per source address and per API key at the same
time. A single limit is always the wrong one: per subject alone lets an attacker
spray one attempt across many accounts, and per address alone punishes every
user behind one NAT gateway.

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `throttle.enabled` | bool | `true` | `N0PASSTEMPS_THROTTLE_ENABLED` | Turns rate limiting on. With it off nothing in this section is read and the store is never consulted. |
| `throttle.window` | duration | `15m` | `N0PASSTEMPS_THROTTLE_WINDOW` | The fixed counting window. |
| `throttle.max_failures_per_subject` | int | `10` | `N0PASSTEMPS_THROTTLE_MAX_FAILURES_PER_SUBJECT` | Failures against one subject before a lockout. |
| `throttle.max_failures_per_ip` | int | `50` | `N0PASSTEMPS_THROTTLE_MAX_FAILURES_PER_IP` | Failures from one normalised source network before a lockout. |
| `throttle.max_requests_per_key` | int | `6000` | `N0PASSTEMPS_THROTTLE_MAX_REQUESTS_PER_KEY` | Total volume from one API key inside the window, which bounds what a leaked key achieves. Metered by a middleware on every public route that takes a key, whether or not the route records an authentication outcome. |
| `throttle.lockout_duration` | duration | `15m` | `N0PASSTEMPS_THROTTLE_LOCKOUT_DURATION` | How long a tripped bucket refuses attempts. |
| `throttle.admin_revoke_burst` | int | `10` | `N0PASSTEMPS_THROTTLE_ADMIN_REVOKE_BURST` | Revocations one administrator may perform inside the window. This is the control that replaces the reversible revocation the specification called for; see [ADR 0010](adr/0010-revocation-is-final.md). |

Refused by the validator, when `throttle.enabled` is true:

- `config: throttle.window must be positive when throttling is enabled`
- `config: throttle.max_failures_per_subject must be at least 1`
- `config: throttle.max_failures_per_ip (%d) below max_failures_per_subject (%d) makes the per-subject limit unreachable`
- `config: throttle.lockout_duration must be positive when throttling is enabled`
- `config: throttle.admin_revoke_burst must be at least 1`

IPv6 sources are bucketed by their `/64` prefix, IPv4 by the single address. A
single host is routinely delegated a whole `/64`, so a per-address limit there
is bypassed at no cost.

## audit

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `audit.retention_days` | int | `0` | `N0PASSTEMPS_AUDIT_RETENTION_DAYS` | Bounds growth. Zero keeps entries forever, which is the default: silently discarding audit history is a decision an operator must take explicitly. |
| `audit.verify_on_start` | bool | `false` | `N0PASSTEMPS_AUDIT_VERIFY_ON_START` | Recomputes the hash chain at startup. Off by default because the cost is linear in the size of the log. |
| `audit.max_query_limit` | int | `500` | `N0PASSTEMPS_AUDIT_MAX_QUERY_LIMIT` | Caps a single audit query, because this is the one table that grows without bound. It also caps the page size of the other administrative listings. |

Refused by the validator:

- `config: audit.max_query_limit must be between 1 and 10000, got %d`
- `config: audit.retention_days cannot be negative`

## admin

| Key | Type | Default | Environment variable | Purpose |
|---|---|---|---|---|
| `admin.ui_enabled` | bool | `true` | `N0PASSTEMPS_ADMIN_UI_ENABLED` | Serves the server-rendered interface at `/admin`. Deployments that administer the service purely through the API turn it off to remove the surface. |
| `admin.session_ttl` | duration | `30m` | `N0PASSTEMPS_ADMIN_SESSION_TTL` | Bounds an administrator's browser session. |
| `admin.session_cookie_secure` | bool | `true` | `N0PASSTEMPS_ADMIN_SESSION_COOKIE_SECURE` | Marks the session cookie `Secure`. Forced on whenever TLS is terminated in process or a trusted proxy is declared. |
| `admin.ip_allow_list` | list of CIDR | empty | `N0PASSTEMPS_ADMIN_IP_ALLOW_LIST` | Restricts the whole `/admin` surface to named networks. Applied before authentication, and a caller outside it receives 404 rather than 403. |

Refused by the validator:

- `config: admin.session_ttl must be positive and at most 12h, got %s`
- `config: admin.ui_enabled on the non-loopback listener %q without admin.ip_allow_list exposes the administration interface to every network that can reach the service; set an allow list or disable the UI`
- `config: admin.ip_allow_list entry %q is not a CIDR: ...`

The first two apply only when `admin.ui_enabled` is true. The CIDR check applies
always, because the allow list guards the `/admin/v1` API as well as the
interface.

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
| `features.dual_approval_operations` | list of string | `credential.revoke_bulk`, `subject.erase`, `admin_token.create`, `kek.rotate` | `N0PASSTEMPS_FEATURES_DUAL_APPROVAL_OPERATIONS` | Names the operations the queue intercepts. Each of the four has a route: revoke-all, erasure, administrative token creation and the keyring rewrap. |
| `features.approval_ttl` | duration | `24h` | `N0PASSTEMPS_FEATURES_APPROVAL_TTL` | How long a queued operation lives, counted from the request. It bounds the decision and the redemption together. |
| `features.deferred_erasure` | bool | `true` | `N0PASSTEMPS_FEATURES_DEFERRED_ERASURE` | Blocks a subject immediately and purges the record after the retention window, instead of deleting at once. |
| `features.erasure_retention` | duration | `720h` (30 days) | `N0PASSTEMPS_FEATURES_ERASURE_RETENTION` | The window in which a pending erasure can still be cancelled. |
| `features.kek_rotation_reminder` | bool | `true` | `N0PASSTEMPS_FEATURES_KEK_ROTATION_REMINDER` | Reports overdue rotation in the detailed health report, and has the janitor raise the `kek.rotation_overdue` alert. |
| `features.janitor_interval` | duration | `5m` | `N0PASSTEMPS_FEATURES_JANITOR_INTERVAL` | How often expired challenges, stale throttle buckets, expired approvals and due erasures are swept. |

Refused by the validator:

- `config: features.dual_approval is on but dual_approval_operations is empty, so nothing is actually held for a second administrator`
- `config: features.dual_approval requires features.admin_rbac; without distinct roles there is no way to tell two administrators apart`
- `config: features.approval_ttl must be positive when dual_approval is on`
- `config: features.erasure_retention must be positive when deferred_erasure is on`
- `config: features.janitor_interval must be positive; expired challenges and due erasures would otherwise never be swept`

### What lite mode actually changes

`features.lite_mode` is applied after the file and the environment have been
read, and only relaxes settings the TOML file did not set explicitly. An
explicit setting in the file therefore wins over the shorthand.

| Setting | Value lite mode applies | Condition |
|---|---|---|
| `features.admin_rbac` | `false` | The file did not set it |
| `features.dual_approval` | `false` | The file did not set it |
| `features.deferred_erasure` | `false` | The file did not set it |
| `features.kek_rotation_reminder` | `false` | The file did not set it |
| `database.driver` | `sqlite` | The file did not set it |
| `recovery.code_count` | `8` | The file did not set it and the value is still the default 16 |

`LITE_MODE` is accepted without the `N0PASSTEMPS_` prefix as well, because the
published quickstart uses the short form and changing it would break copied
commands.

Nothing else changes. WebAuthn, TOTP, recovery codes, the audit chain, the
throttle and the alert engine are identical in both modes.

## Environment variables that are not configuration keys

| Variable | Read by | Purpose |
|---|---|---|
| `N0PASSTEMPS_KEK` | `internal/crypto/kek` | The keyring itself, when `kek.provider = "env"`. The default value of `kek.env_var`. Unset by the process once parsed. |
| `N0PASSTEMPS_SUBJECT_PEPPER` | `internal/subject` | The HMAC pepper. The default value of `subject.pepper_env`. Unset by the process once parsed. |
| `LITE_MODE` | `internal/config` | Unprefixed alias for `features.lite_mode`. |

## Related documents

| Document | What it covers |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Where each of these values goes in the four supported deployment forms |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | What to do when one of the refusals above appears at startup |
| [MONITORING.md](MONITORING.md) | The health report these settings are visible in |
| [docs/adr](adr/README.md) | Why the defaults are what they are |
