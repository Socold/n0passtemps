# Deployment

Four supported forms, in increasing order of moving parts. Everything in
`deploy/` is real and pre-tested; where this document shows a command, it is the
command that works against those files.

| Form | When it fits | Files |
|---|---|---|
| Single container, SQLite | One node, up to a few thousand subjects, no high availability requirement | `deploy/Dockerfile`, `deploy/docker-compose.yml` |
| Compose, PostgreSQL | One node, a database you already back up, room to grow | `deploy/docker-compose.postgres.yml` |
| systemd on a host | No container runtime, or a host hardening policy expressed in systemd | `deploy/systemd/` |
| Kubernetes | A cluster you already run, more than one replica | `deploy/kubernetes/` |

## Pre-flight checklist

Run through this before the first start. Every item but the last corresponds to
a refusal the service will otherwise produce, and the refusals are in
[TROUBLESHOOT.md](TROUBLESHOOT.md).

| # | Check | Why |
|---|---|---|
| 1 | The keyring exists, is mode 0600, and its path is **outside** `database.data_dir` and outside the directory holding the SQLite file | The file provider refuses both conditions. See [ADR 0009](adr/0009-refuse-a-kek-inside-the-data-directory.md) |
| 2 | The keyring is backed up somewhere the data volume's loss does not reach | Losing every copy costs the TOTP secrets and the readable subject references |
| 3 | The subject pepper is set, at least 32 bytes, and backed up separately | Losing it makes every existing subject unfindable |
| 4 | The assertion signing key exists, is an Ed25519 PKCS#8 PEM, and is mode 0600 | The loader refuses a permissive mode and a non-Ed25519 key |
| 5 | `webauthn.rp_id` is the final domain, and every entry in `webauthn.origins` is covered by it | Changing `rp_id` later invalidates every registered credential |
| 6 | TLS terminates somewhere: in process, or at a proxy with `trust_proxy` and `trusted_proxy_cidrs` set | The validator refuses plain HTTP on a non-loopback listener, unless `server.allow_plaintext` acknowledges that something outside the process constrains who can reach the port |
| 7 | `admin.ip_allow_list` is set, or `admin.ui_enabled` is false, on a non-loopback listener | The validator refuses the combination |
| 8 | With PostgreSQL, the DSN carries an explicit `sslmode`, and it is `require` or stronger for anything that crosses a network | The validator refuses a DSN with none, and refuses `allow` and `prefer` always. `disable` is accepted towards loopback, a Unix socket directory or an empty host, and towards any other host only with `database.allow_plaintext` |
| 9 | The host clock is synchronised | A 60 second assertion lifetime and a one-period TOTP skew do not survive drift |
| 10 | The listener port is free, and the data directory is writable by the service account | |
| 11 | You know how you will run `-bootstrap-admin` in this form, and who receives the second token when dual approval is on | The running service never prints an administrative token, and one administrator cannot mint a second under dual approval. See [Post-install](#post-install-the-first-credentials) |

A dry run, without starting a listener:

```bash
n0passtemps-server -config /etc/n0passtemps/config.toml -check-config
# configuration is valid

n0passtemps-wizard check -config /etc/n0passtemps/config.toml
# prints the tenant, the listener, the driver, the relying party, the origins,
# the keyring provider and which features are on
```

Then start the process, watch it either refuse with a list of problems or log
`listening`, and check that `GET /v1/health` returns `{"status":"ok"}`.

## Common prerequisites

- **A keyring.** Generated once, by an operator, never by the server:

  ```bash
  n0passtemps-wizard kek init -out /etc/n0passtemps/kek/keyring.json
  ```

  It writes the file at mode 0600 and refuses to overwrite an existing keyring
  unless `-force` is passed, because overwriting one destroys every secret
  sealed under it. The document it writes is:

  ```json
  {
    "current": 1,
    "keys": { "1": "<standard base64 of 32 random bytes>" }
  }
  ```

  Without the wizard binary to hand, the same document is:

  ```bash
  printf '{\n  "current": 1,\n  "keys": { "1": "%s" }\n}\n' "$(openssl rand -base64 32)" \
    > keyring.json
  chmod 600 keyring.json
  ```

- **A subject pepper.** At least 32 bytes: hexadecimal, base64 of at least 32
  bytes, or a value whose encoding is named with a `hex:`, `base64:` or `raw:`
  prefix. The encoding is never guessed; see
  [CONFIGURATION.md](CONFIGURATION.md#subject).

  ```bash
  n0passtemps-wizard pepper                 # prints N0PASSTEMPS_SUBJECT_PEPPER=...
  n0passtemps-wizard pepper -bytes 64       # longer, if you prefer
  openssl rand -hex 32                      # equivalent, by hand
  ```

  `-bytes` below 32 is refused: the pepper is an HMAC key and 32 matches the
  hash output length.

- **An assertion signing key.** Ed25519, PKCS#8 PEM, mode 0600:

  ```bash
  n0passtemps-wizard assertion-key init -out /etc/n0passtemps/kek/assertion-key.pem
  n0passtemps-wizard assertion-key inspect -file /etc/n0passtemps/kek/assertion-key.pem
  ```

  Every file in `deploy/` keeps it beside `keyring.json`: both are key material,
  both are read-only to the service, and neither belongs on the data volume.

  `inspect` prints the `kid` a verifier will see and the JWK Set the service
  will publish. By hand, the equivalent is:

  ```bash
  openssl genpkey -algorithm ed25519 -out assertion-key.pem
  chmod 600 assertion-key.pem
  ```

## Where the keyring must live, and why

The file provider resolves the configured key path to an absolute path,
resolves symbolic links on both sides, and compares it against every configured
data directory: `database.data_dir`, and the directory holding the SQLite file.
If the key resolves inside one of them, loading fails:

```
kek: "/var/lib/n0passtemps/keyring.json" is inside the data directory
"/var/lib/n0passtemps"; a key stored beside the ciphertext it protects gives no
confidentiality if the volume is copied. Mount it from a separate volume or use
the env provider
```

Encryption at rest defends against someone obtaining the stored bytes: a stolen
disk, a copied volume, a backup archive, a snapshot left readable in object
storage. If the key travels in the same volume as the ciphertext, every one of
those events hands over both halves and the mechanism reduces to obfuscation.
The check is a guard against the obvious mistake, not a security boundary; see
[ADR 0009, Refuse to load a key encryption key stored inside the data
directory](adr/0009-refuse-a-kek-inside-the-data-directory.md) for what it does
not cover.

The consequence for every form below is the same: two mounts, not one.

| Path | Contains | Mount |
|---|---|---|
| `/var/lib/n0passtemps` | The SQLite database and its write-ahead log | Writable volume |
| `/etc/n0passtemps/kek` | `keyring.json` and `assertion-key.pem`, mode 0600 or 0400 | Separate volume or secret, read-only |
| `/etc/n0passtemps/config.toml` | Configuration | Read-only file |

With `kek.provider = "env"` there is no keyring mount at all: the orchestrator
injects the document into the variable named by `kek.env_var`, and the provider
unsets it once parsed. It is the weaker of the two providers, for the reasons
ADR 0009 records.

## The command line, and the variable names in `deploy/`

`n0passtemps-server` takes seven flags and reads everything else from the
configuration file and the environment:

| Flag | Effect |
|---|---|
| `-config <path>` | The TOML file to read. Empty, which is the default, configures entirely from the environment |
| `-check-config` | Validate and exit without starting a listener |
| `-migrate` | Apply pending migrations and exit |
| `-bootstrap-admin` | Create the first administrative token, print it once and exit. Refuses when a usable `admin_full` token exists |
| `-admins <n>` | With `-bootstrap-admin`, how many tokens to create, from 1 to 5, default 1. Use 2 when dual approval is on |
| `-force` | With `-bootstrap-admin`, create tokens even though an administrator exists. For the operator who has lost every token, or who has to complete a quorum |
| `-version` | Print the version, commit, build date and Go version, then exit |

`n0passtemps-wizard` has five subcommands, each with its own `-h`:

| Command | Effect |
|---|---|
| `setup` | Asks a few questions and writes `config.toml`, `docker-compose.yml` and `.env` |
| `kek init`, `kek rotate`, `kek seal`, `kek inspect` | Manage the key encryption keyring. `seal` encrypts it to this machine's TPM 2.0; see [CONFIGURATION.md](CONFIGURATION.md#sealing-the-keyring-to-a-tpm) for what that does and does not buy |
| `assertion-key init`, `assertion-key rotate`, `assertion-key inspect` | Manage the Ed25519 signing key. `rotate` replaces it without refusing the assertions already in flight; see [CONFIGURATION.md](CONFIGURATION.md#rotating-the-signing-key) |
| `pepper` | Print a subject pepper as `N0PASSTEMPS_SUBJECT_PEPPER=...` |
| `check` | Validate a configuration file and summarise it |

The files in `deploy/` use the loader's own variable names and pass the
configuration path with `-config`: the image's entrypoint is
`n0passtemps-server -config /etc/n0passtemps/config.toml`, the systemd unit's
`ExecStart` carries the same flag, and there is no environment variable for the
path, because the file is read before any override could name it. A test in
`internal/config` reads `deploy/`, `config/`, `examples/`, `.github/` and the
`Makefile` and fails when one of them names a prefixed variable that nothing
reads. [CONFIGURATION.md](CONFIGURATION.md) is the authority for the names:
every one in it is derived from `internal/config/env.go`.

The shipped files pass every secret. Both compose files take the subject pepper
from `.env` and refuse to start while it is unset; the systemd environment file
and the Kubernetes Secret have a placeholder for it. All four forms read the
signing key from `/etc/n0passtemps/kek/assertion-key.pem`. Nothing has to be
added to a shipped file by hand; what is yours to supply is the values.

## Form 1: single container with SQLite

### Prerequisites

Docker 24 or newer with the compose plugin. One host. No database server.

### Steps

```bash
git clone https://github.com/Socold/n0passtemps.git
cd n0passtemps/deploy

cp .env.example .env
$EDITOR .env            # set N0PASSTEMPS_VERSION at least
```

Write the configuration next to the compose file:

```bash
cat > config.toml <<'TOML'
[tenant]
id   = "acme"
name = "Acme"

[server]
addr = "0.0.0.0:8080"
trust_proxy         = true
trusted_proxy_cidrs = ["172.16.0.0/12"]

[database]
driver   = "sqlite"
dsn      = "/var/lib/n0passtemps/n0passtemps.db"
data_dir = "/var/lib/n0passtemps"

[kek]
provider = "file"
path     = "/etc/n0passtemps/kek/keyring.json"

[webauthn]
rp_id           = "auth.example.com"
rp_display_name = "Acme"
origins         = ["https://auth.example.com"]

[assertion]
issuer           = "https://auth.example.com"
signing_key_path = "/etc/n0passtemps/kek/assertion-key.pem"

[admin]
ui_enabled    = true
ip_allow_list = ["10.0.0.0/8"]
TOML
```

`server.addr` is `0.0.0.0:8080` inside the container, and the compose file
publishes it on `127.0.0.1` only. The compose file also sets
`N0PASSTEMPS_SERVER_ALLOW_PLAINTEXT=true`. The binary sees a non-loopback bind
address and cannot see the publish rule, so without that acknowledgement, or
`trust_proxy`, the validator would refuse to serve plain HTTP there. It is an
explicit opt-in because it overrides the check that stops credentials being
served unencrypted to whatever can reach the port: if you change the `ports:`
entry to publish on another interface, remove it. `trust_proxy` is set because a reverse proxy
on the host terminates TLS; `trusted_proxy_cidrs` must then cover the address
the proxy connects from, which for the default bridge network is inside
`172.16.0.0/12`. Check it with `docker network inspect n0passtemps_n0passtemps`
and narrow the range.

Put the keyring and the signing key into the `n0passtemps-kek` volume before
the first start. The wizard ships in the image, and the image creates
`/etc/n0passtemps/kek` owned by uid 65532, so Docker initialises a fresh named
volume with that ownership and the non-root wizard can write into it. No helper
container and no root are needed:

```bash
docker volume create n0passtemps_n0passtemps-kek

docker run --rm -v n0passtemps_n0passtemps-kek:/etc/n0passtemps/kek \
  --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 \
  kek init -out /etc/n0passtemps/kek/keyring.json

docker run --rm -v n0passtemps_n0passtemps-kek:/etc/n0passtemps/kek \
  --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 \
  assertion-key init -out /etc/n0passtemps/kek/assertion-key.pem
```

The volume name is the compose project name followed by the volume's name. Both
compose files declare `name: n0passtemps` and a volume `n0passtemps-kek`, hence
`n0passtemps_n0passtemps-kek`; with `docker compose -p <project>` the prefix is
your project name. The ownership is set only when Docker first populates an
empty volume, so a volume created earlier by another image, or a bind mount, has
to be owned by uid 65532 by your own means.

Generate the pepper and put the line it prints into `.env`, replacing the empty
`N0PASSTEMPS_SUBJECT_PEPPER=` entry:

```bash
docker run --rm --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 pepper
# N0PASSTEMPS_SUBJECT_PEPPER=...
```

The compose file requires it and stops with
`set N0PASSTEMPS_SUBJECT_PEPPER in .env, generate it with n0passtemps-wizard pepper`
while it is unset. It is a secret: it does not belong in `config.toml`. Back it
up, and back the key volume up, before going further:

```bash
docker run --rm -v n0passtemps_n0passtemps-kek:/kek:ro alpine:3.20 \
  tar -C /kek -cf - . > n0passtemps-kek-backup.tar
```

Then start it:

```bash
docker compose up -d
docker compose logs -f n0passtemps
```

The `config.toml` bind mount carries `:ro,z`, so on a host with SELinux
enforcing the file is relabelled for the container. It still has to be readable
by uid 65532; mode 0644 is fine, because it holds no secret.

Verify:

```bash
curl -sS http://127.0.0.1:8080/v1/health
# {"status":"ok"}
```

The service is now running and has no administrator. Create the initial pair
with `docker compose run --rm n0passtemps -bootstrap-admin -admins 2`;
[Post-install](#post-install-the-first-credentials) says why two.

### TLS

The container speaks plain HTTP and is published on loopback. Terminate TLS in
front of it. A minimal nginx server block:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-Id      $request_id;
    }
}
```

`X-Forwarded-Proto` matters: it is what makes the service emit HSTS and mark the
administration session cookie `Secure`. `X-Forwarded-For` matters more, and only
counts when the proxy's own address is inside `trusted_proxy_cidrs`; without
that the rate limiter and every audit entry key on the proxy's address instead
of the client's.

Configure the proxy not to log the request path. Subject references appear in
the path on the `/v1` routes; this service logs the route pattern rather than
the concrete path, but an intervening proxy does not by default.

To terminate TLS in the process instead, mount the certificate and key
read-only, set `server.tls_cert_file` and `server.tls_key_file`, and leave
`trust_proxy` false. The in-process listener floors at TLS 1.2, because some
corporate middleboxes on the deployment paths this targets still cannot complete
a 1.3 handshake.

### Backup and restore

Stop the container, copy the volume, start it again. The write-ahead log means a
hot copy of the database file alone can be inconsistent.

```bash
docker compose -f docker-compose.yml stop n0passtemps

docker run --rm \
  -v n0passtemps_n0passtemps-data:/data:ro \
  -v "$PWD":/out \
  alpine:3.20 tar czf /out/n0passtemps-data-$(date +%F).tar.gz -C /data .

docker compose -f docker-compose.yml start n0passtemps
```

For a hot backup, use SQLite's own backup, which is consistent against a live
writer:

```bash
sqlite3 /var/lib/docker/volumes/n0passtemps_n0passtemps-data/_data/n0passtemps.db \
  ".backup '/backup/n0passtemps-$(date +%F).db'"
```

Restore is the reverse: stop, replace the volume contents, start. The keyring
and the pepper are not in the backup and must not be: a backup that contains
both halves is the arrangement ADR 0009 exists to prevent. Back them up
separately, and test that you can still read the sealed data afterwards, because
a restored database with the wrong keyring loses exactly the TOTP secrets and
the readable subject references.

#### Checking that the three artefacts still belong together

There are three of them, kept apart on purpose, and holding all three proves
nothing about whether they fit. `verify` answers that without a restore. It
opens the database read-only, unseals real records under the keyring and
recomputes a subject lookup value under the pepper:

```bash
docker run --rm \
  -v "$PWD":/backup:ro \
  -e N0PASSTEMPS_SUBJECT_PEPPER \
  --entrypoint /usr/local/bin/n0passtemps-wizard \
  ghcr.io/socold/n0passtemps:1.1.0 \
  verify -db /backup/n0passtemps-2026-09-18.db -keyring /backup/keyring.json
```

The mount is `:ro` because nothing here needs to write; drop the `:ro` only if
the database is in write-ahead-log mode and SQLite has to build its `-shm`
index beside it. Exit status 0 means the trio opens, 1 means it does not, and 2
means no verdict was reached, so this belongs in the same cron entry as the
backup itself. [ADMIN-GUIDE.md](ADMIN-GUIDE.md#verifying-a-backup) has the
routine and [TROUBLESHOOT.md](TROUBLESHOOT.md) the verdicts.

Run it against the backup, not only against the live file. A live database and
the keyring the running service already loaded will pass by construction; the
copy in the archive is the one nobody has opened.

### Upgrade

```bash
$EDITOR .env                                     # raise N0PASSTEMPS_VERSION
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
```

Take a backup first. Migrations run at startup when
`database.auto_migrate` is true and are not reversible: there is no down
migration. To review the schema change before it is applied, set
`auto_migrate = false`, read the embedded migration in the release, and run the
new binary once with it enabled.

## Form 2: compose with PostgreSQL

### Prerequisites

Docker with the compose plugin. The compose file brings its own
`postgres:16-alpine` and does not publish port 5432, so nothing outside the
bridge network can reach it.

### Steps

Same clone, same `.env`, plus the database variables:

```bash
cd n0passtemps/deploy
cp .env.example .env
$EDITOR .env
# N0PASSTEMPS_VERSION=1.1.0
# POSTGRES_USER=n0passtemps
# POSTGRES_PASSWORD=<openssl rand -base64 32>
# POSTGRES_DB=n0passtemps
```

The compose file builds the DSN from those three and passes it as
`N0PASSTEMPS_DATABASE_DSN`, so the password stays out of `config.toml`, and it
sets `N0PASSTEMPS_DATABASE_DRIVER=postgres`. The pepper goes into `.env` and the
two key files into the `n0passtemps-kek` volume, exactly as in Form 1.

`config.toml` for this form differs from Form 1 in one section. The environment
overrides the file, so `dsn` is left out of it, and `driver` is stated only so
that the file reads truthfully:

```toml
[database]
driver   = "postgres"
data_dir = "/var/lib/n0passtemps"
max_open_conns = 16
max_idle_conns = 8
```

The DSN the compose file builds ends in `@db:5432/<database>?sslmode=disable`,
and `db` is not a loopback host, so the compose file also sets
`N0PASSTEMPS_DATABASE_ALLOW_PLAINTEXT=true`. The validator cannot see network
topology. It accepts `sslmode=disable` on its own only towards loopback, a Unix
socket directory or an empty host; towards any other host the operator has to
say explicitly that the link is private, which is what `database.allow_plaintext`
does, in the same spirit as `server.allow_plaintext`. Here the link is a bridge
network that is not published and never leaves the host. The acknowledgement
covers `disable` only: `prefer` and `allow` are refused whatever it says. If you
point this form at a database across a real network, remove the variable and use
`sslmode=verify-full`.

```bash
docker compose -f docker-compose.postgres.yml up -d
docker compose -f docker-compose.postgres.yml logs -f
```

The application container waits on the database's own `pg_isready` health check
before starting, because migrations run at startup and fail fast against an
unreachable database.

Then create the initial administrators:
`docker compose -f docker-compose.postgres.yml run --rm n0passtemps -bootstrap-admin -admins 2`.

### TLS, keyring, admin allow list

Identical to Form 1. Same two mounts, same reverse proxy, same
`trusted_proxy_cidrs` requirement.

### Backup and restore

Back up the database with `pg_dump`, which is consistent against a live writer,
and take the keyring separately.

```bash
docker compose -f docker-compose.postgres.yml exec -T db \
  pg_dump -U n0passtemps -Fc n0passtemps > n0passtemps-$(date +%F).dump
```

Restore into an empty database:

```bash
docker compose -f docker-compose.postgres.yml exec -T db \
  psql -U n0passtemps -c 'DROP DATABASE IF EXISTS n0passtemps_restore'
docker compose -f docker-compose.postgres.yml exec -T db \
  psql -U n0passtemps -c 'CREATE DATABASE n0passtemps_restore'
docker compose -f docker-compose.postgres.yml exec -T db \
  pg_restore -U n0passtemps -d n0passtemps_restore < n0passtemps-2026-09-17.dump
```

Point the DSN at the restored database, start, and verify the audit chain before
trusting it:

```bash
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://auth.example.com/admin/v1/audit/verify?from_seq=1'
```

`n0passtemps-wizard verify` does not cover this form. A `pg_dump` archive
cannot be read without restoring it into a server first, so handing the command
three artefacts has no meaning here; and once restored, the promise that a
verification cannot write to what it is verifying would rest on the role's
privileges rather than on how a file was opened. Restore into the scratch
database as above, point a spare configuration at it with a read-only role,
start it, and check the two things the trio actually protects: that
`GET /admin/v1/health` reports the keyring healthy, and that a TOTP code
verifies for a subject you can reach. Then verify the chain.

A `pg_dump` and `pg_restore` round trip preserves the chain, because the
PostgreSQL implementation canonicalises a JSON document through the server
before hashing it, so the hash covers what is actually stored. A chain is valid
within the engine that produced it: exporting from SQLite and importing into
PostgreSQL, or the reverse, means the chain has to be rebuilt.

### Upgrade

Raise the tag, `pull`, `up -d`. Upgrade PostgreSQL itself separately and
deliberately: the image is pinned to a minor release precisely so that a major
upgrade, which needs a data directory migration, cannot happen on a restart.

## Form 3: systemd on a host

### Prerequisites

A Linux host with systemd 247 or newer, for `ProtectProc` and `ProcSubset`. No
container runtime. A static binary, either from a release archive or from
`make build`.

### Steps

```bash
# Service account. Not DynamicUser: the keyring lives in /etc with a fixed
# owner and mode 0600, which a per-boot dynamic uid could not read.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin n0passtemps

sudo install -o root -g root -m 0755 bin/n0passtemps-server /usr/local/bin/
sudo install -o root -g root -m 0755 bin/n0passtemps-wizard /usr/local/bin/

sudo install -d -o root       -g root       -m 0755 /etc/n0passtemps
sudo install -d -o n0passtemps -g n0passtemps -m 0700 /etc/n0passtemps/kek
```

Configuration and secrets:

```bash
sudo install -o root -g n0passtemps -m 0640 config.toml /etc/n0passtemps/config.toml

sudo install -o n0passtemps -g n0passtemps -m 0600 \
  keyring.json /etc/n0passtemps/kek/keyring.json
sudo install -o n0passtemps -g n0passtemps -m 0600 \
  assertion-key.pem /etc/n0passtemps/kek/assertion-key.pem

sudo install -o root -g root -m 0600 \
  deploy/systemd/n0passtemps.env.example /etc/n0passtemps/n0passtemps.env
sudo $EDITOR /etc/n0passtemps/n0passtemps.env
```

The environment file is read by systemd as root before the service drops to the
service account, which is why it may hold the DSN and the pepper and why it is
mode 0600. The shipped example already carries every line below; the one value
to fill in is the pepper, which it leaves empty. The configuration path is not
in it: the unit passes `-config` on its `ExecStart` line. With SQLite the
database path comes from `database.dsn` in `config.toml`; with PostgreSQL,
uncomment `N0PASSTEMPS_DATABASE_DSN` so that the password stays out of the
configuration file.

```bash
N0PASSTEMPS_DATABASE_DATA_DIR=/var/lib/n0passtemps
N0PASSTEMPS_KEK_PATH=/etc/n0passtemps/kek/keyring.json
N0PASSTEMPS_SERVER_ADDR=127.0.0.1:8080
N0PASSTEMPS_LOGGING_LEVEL=info
N0PASSTEMPS_LOGGING_FORMAT=json
N0PASSTEMPS_SUBJECT_PEPPER=<the value printed by n0passtemps-wizard pepper>
N0PASSTEMPS_ASSERTION_SIGNING_KEY_PATH=/etc/n0passtemps/kek/assertion-key.pem
```

Install and start the unit:

```bash
sudo install -o root -g root -m 0644 \
  deploy/systemd/n0passtemps.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now n0passtemps
journalctl -u n0passtemps -f
```

`StateDirectory=n0passtemps` creates and chowns `/var/lib/n0passtemps` to the
service account on start and leaves it in place across restarts and package
upgrades. `/etc/n0passtemps/kek` is deliberately outside it.

The unit refuses a great deal: read-only filesystem apart from the state
directory, no capabilities at all, `MemoryDenyWriteExecute`, `ProtectClock`
(a service that verifies TOTP codes and certificate expiry must not be able to
move the system clock), a system call filter of `@system-service` minus
`@privileged` and `@resources`, and `UMask=0077` so the database it creates is
readable only by the service account. It is `Type=simple`, not `Type=notify`:
the server does not implement `sd_notify`, so `notify` would leave systemd
waiting for a readiness message that never arrives. Readiness is observed on
`GET /v1/health`.

### TLS

Either terminate at a proxy on the same host, as in Form 1, with
`trusted_proxy_cidrs = ["127.0.0.1/32"]`, or terminate in process:

```toml
[server]
addr          = "0.0.0.0:443"
tls_cert_file = "/etc/n0passtemps/tls/fullchain.pem"
tls_key_file  = "/etc/n0passtemps/tls/privkey.pem"
```

Binding 443 as an unprivileged user needs either
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, which the shipped unit deliberately
does not grant, or a redirect from 443 to 8443 in the host firewall. The
shipped unit's `CapabilityBoundingSet=` is empty on purpose: the process binds
8080 and needs no capability. Prefer the redirect, or a proxy.

Certificate renewal is picked up without a restart on the health report, which
re-reads the file on every call, but the listener itself holds the certificate
it started with. Reload the service after a renewal:

```bash
sudo systemctl restart n0passtemps
```

### Backup and restore

```bash
sudo systemctl stop n0passtemps
sudo tar czf /backup/n0passtemps-$(date +%F).tar.gz -C /var/lib/n0passtemps .
sudo systemctl start n0passtemps
```

Or hot, with SQLite's own backup:

```bash
sudo -u n0passtemps sqlite3 /var/lib/n0passtemps/n0passtemps.db \
  ".backup '/backup/n0passtemps-$(date +%F).db'"
```

`/etc/n0passtemps/kek` and the pepper in the environment file are backed up
separately, to a different destination, and restored by hand. Do not add
`/etc/n0passtemps` to the same archive as `/var/lib/n0passtemps`.

Which leaves the question the separation creates: do those three still open
together? Check it on a schedule rather than during a restore:

```bash
export N0PASSTEMPS_SUBJECT_PEPPER=...
n0passtemps-wizard verify \
  -db /backup/n0passtemps-$(date +%F).db \
  -keyring /etc/n0passtemps/kek/keyring.json
```

It opens the database read-only, unseals real records under the keyring and
recomputes a subject lookup value under the pepper. Exit status 0 means the
trio opens, 1 means it does not, 2 means no verdict was reached.
[ADMIN-GUIDE.md](ADMIN-GUIDE.md#verifying-a-backup) has the cron entry and what
the command does and does not cover.

### Upgrade

```bash
sudo systemctl stop n0passtemps
sudo install -o root -g root -m 0755 bin/n0passtemps-server /usr/local/bin/
sudo systemctl start n0passtemps
journalctl -u n0passtemps -n 50
```

Back up first. Read the release notes for schema changes. If
`database.auto_migrate` is false, the new binary will refuse to serve against an
older schema rather than running on it.

## Form 4: Kubernetes

### Prerequisites

A cluster with Pod Security Admission, a CNI that implements NetworkPolicy, and
a PostgreSQL instance. The shipped manifests assume PostgreSQL: `replicas: 2`
and an `emptyDir` data volume are only correct with a shared database. SQLite
does not support concurrent writers across pods, so a SQLite deployment there
means `replicas: 1` and a PersistentVolumeClaim.

### Steps

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
```

The namespace enforces the `restricted` Pod Security Standard. The deployment
satisfies it already; declaring it means a later manifest that drops a control
fails admission instead of being accepted silently.

```bash
cp deploy/kubernetes/secret.example.yaml /tmp/n0passtemps-secret.yaml
$EDITOR /tmp/n0passtemps-secret.yaml
```

The example has a placeholder for each of the four values, and all four are
yours to replace: the base64 key inside `keyring.json`, from
`n0passtemps-wizard kek init`; `database-url`, a real DSN carrying
`sslmode=verify-full`; `subject-pepper`, the value printed by
`n0passtemps-wizard pepper` without the variable name; and `assertion-key.pem`,
the file written by `n0passtemps-wizard assertion-key init`.

```yaml
stringData:
  keyring.json: |
    { "current": 1, "keys": { "1": "<base64 of 32 random bytes>" } }
  database-url: "postgres://user:password@db.internal:5432/n0passtemps?sslmode=verify-full"
  subject-pepper: "<the value printed by n0passtemps-wizard pepper>"
  assertion-key.pem: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```bash
kubectl apply -f /tmp/n0passtemps-secret.yaml
shred -u /tmp/n0passtemps-secret.yaml
```

Prefer an external secret manager over a manifest on disk. The example file
says so in its first line.

The shipped `configmap.yaml` parses and validates as it stands. Edit the values
that are yours: `tenant.id`, `webauthn.rp_id`, `webauthn.origins`,
`assertion.issuer` and `admin.ip_allow_list`. It sets
`server.allow_plaintext = true`, because the pod binds every interface and
reachability is constrained by the Service and the NetworkPolicy, which the
binary cannot see. When an ingress controller terminates TLS and forwards the
client address, set `trust_proxy` and `trusted_proxy_cidrs` as well, which the
file carries as comments; without them every request is attributed to the
controller's address. `database.dsn` comes from the secret and is not in the
file. Check an edit before applying it:

```bash
n0passtemps-wizard check -config config.toml
```

```bash
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/service.yaml
kubectl apply -f deploy/kubernetes/networkpolicy.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml

kubectl -n n0passtemps rollout status deploy/n0passtemps
kubectl -n n0passtemps logs -l app.kubernetes.io/name=n0passtemps -f
```

`deployment.yaml` needs no edit for the secrets. It reads the pepper from the
Secret key `subject-pepper`, and mounts `keyring.json` and `assertion-key.pem`
from the same Secret, side by side, at `/etc/n0passtemps/kek`, which is where the
ConfigMap's `assertion.signing_key_path` points.

`defaultMode: 0400` is what satisfies the mode check on both files, and
`fsGroup: 65532` in the pod security context is what lets uid 65532 read them.
The volume mounts at `/etc/n0passtemps/kek`, outside the `/var/lib/n0passtemps` data
volume, for the reason above.

### The probes

All three point at `GET /v1/health`, which is the unauthenticated liveness
report and returns `{"status":"ok"}` or a 503.

| Probe | Settings | Reason |
|---|---|---|
| `startupProbe` | every 2s, 30 failures | Migrations run at startup and the first request must not arrive before they finish |
| `readinessProbe` | every 10s, 3 failures | Takes a pod out of the Service |
| `livenessProbe` | every 30s, 6 failures | Deliberately slower to fail than readiness: a database outage should take the pod out of the Service, not restart it in a loop while the database is still recovering |

The liveness report does touch the database, with a 2 second timeout, so an
instance that cannot reach its store does report an error and does leave the
rotation. What it does not do is say why; that is the authenticated report, and
[ADR 0008](adr/0008-split-the-health-endpoint.md) explains the trade.

### TLS

The Service is ClusterIP and the container speaks plain HTTP. Terminate TLS at
an Ingress or gateway and let it forward to port 8080. The shipped ConfigMap
sets `server.allow_plaintext`, which is enough for the validator and not enough
for attribution: set `trust_proxy = true` and make `trusted_proxy_cidrs` cover
the pod network the ingress controller runs on, or every request will be
attributed to the controller's address, and the rate limiter and the audit log
will key on it.

The `restricted` profile and the default-deny NetworkPolicy mean the ingress
rule has to be narrowed by hand. The shipped policy admits any pod in the
cluster:

```yaml
ingress:
  - from:
      - namespaceSelector: {}
```

Replace `{}` with a selector naming the namespace the ingress controller runs
in.

### Backup and restore

The application holds no durable state in the cluster: the `emptyDir` survives
neither a restart nor a reschedule, and that is correct with PostgreSQL. Back up
the database with the tooling the cluster's PostgreSQL already uses, and back up
the Secret outside the cluster, because a cluster loss otherwise takes the
keyring with it.

`n0passtemps-wizard verify` does not cover this form either, and for the same
reason as Form 2: the backup is a PostgreSQL archive rather than a file the
command can open. Verify by restoring into a scratch database, as Form 2
describes. A SQLite deployment here, which means `replicas: 1` and a
PersistentVolumeClaim, can run the check against a copy of the claim's database
file in any pod carrying the image.

### Upgrade

```bash
kubectl -n n0passtemps set image deploy/n0passtemps n0passtemps=ghcr.io/socold/n0passtemps:1.1.0
kubectl -n n0passtemps rollout status deploy/n0passtemps
```

With `maxUnavailable: 0` and `maxSurge: 1` the rollout brings a new pod up
before taking an old one down. Two things follow, and both matter:

- Migrations run in whichever pod starts first, while the old pods are still
  serving against the previous schema. A migration that is not backward
  compatible with the running version will break those pods for the length of
  the rollout. Either accept the window, or scale to zero, run the migration,
  and scale back up.
- `kubectl rollout undo` reverts the image, not the schema. There are no down
  migrations. A rollback across a schema change means restoring the database.

## Post-install: the first credentials

At every start the service provisions the tenant named by `tenant.id` if it does
not exist. It never creates an administrative token and never prints one. While
no usable `admin_full` token exists it logs a warning at each start, and with
dual approval on the hint ends in `-admins 2`:

```
no administrator exists yet; create the first with: n0passtemps-server -config <path> -bootstrap-admin -admins 2
```

The first tokens come from a one-shot run of the same binary, with the same
configuration, keyring, pepper and database as the service. It prints each token
once to the terminal it was run from, as `name  token` lines named `bootstrap-1`
onwards, records an `admin_token.created` audit entry per token with
`detail.bootstrap: true`, and exits without starting a listener. A log stream is
shipped and retained by systems with looser access rules than a credential
store, which is why the long-running service is never the thing that writes a
token; see [ADR 0014](adr/0014-bootstrap-by-explicit-command.md).

`-admins N` sets how many tokens are created, from 1 to 5, default 1. Use 2
whenever `features.dual_approval` is on, which is the default outside lite mode.
Minting an administrative token through the API is then held for a second
administrator, so a deployment with exactly one cannot create its second: nobody
exists to approve the request. The API carries no exemption for a sole
administrator, because a rogue administrator could reach one by revoking the
others, mint a token they control, and approve their own requests from then on.
The initial quorum is created here instead, by someone who already holds the
configuration, the keyring and the database. Give the second token to a
different person. The command itself warns when it leaves a single
administrator under dual approval.

| Form | Command |
|---|---|
| Compose, either file | `docker compose run --rm n0passtemps -bootstrap-admin -admins 2`, adding `-f docker-compose.postgres.yml` after `compose` for Form 2 |
| systemd | `sudo systemd-run --pty --wait --collect -p User=n0passtemps -p Group=n0passtemps -p EnvironmentFile=/etc/n0passtemps/n0passtemps.env /usr/local/bin/n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2` |
| Kubernetes | `kubectl -n n0passtemps exec deploy/n0passtemps -- /usr/local/bin/n0passtemps-server -config /etc/n0passtemps/config.toml -bootstrap-admin -admins 2` |

In compose, `run` starts a second container from the service definition, with
its volumes and environment, and the arguments are appended to the image's
entrypoint, which already carries `-config`. Under systemd, `--pty` connects the
command to your terminal, so the tokens do not pass through the journal, and
the environment file supplies the pepper. In Kubernetes, `exec` runs the binary
inside a running pod, with its mounts and environment, and the output goes to
your terminal and not to `kubectl logs`.

The command refuses once a usable `admin_full` token exists. `-force` lifts the
refusal, for an operator who has lost every token, or whose deployment was
bootstrapped with one administrator and needs its second:
`-bootstrap-admin -force -admins 1`. It grants nothing to someone who does not
already hold the configuration, the keyring and the database, and the audit
entry records `detail.forced: true`.

The tokens are on your terminal in clear. Put them in a password manager, one
per person, then clear the scrollback, and do not redirect the output to a file.

Then, in order:

1. Sign in to `/admin`, or use a token as a bearer credential against
   `/admin/v1`, and confirm each works.
2. Mint a named token per administrator, with a role:
   `POST /admin/v1/admin-tokens`. Under dual approval one bootstrap token
   requests, the other approves, and the requester repeats the call with
   `X-Approval-Id`.
3. Revoke the bootstrap tokens. The guard that refuses the last usable
   `admin_full` is why step 2 comes first.
4. Mint the API key the integrating application will use, with the scopes it
   needs and no others: `POST /admin/v1/api-keys`.

Everything after that is in [ADMIN-GUIDE.md](ADMIN-GUIDE.md), including the rule
that the last usable full administrator cannot be revoked and why.

## Running more than one replica

Supported on PostgreSQL, and only there. What decides it is not the application
but the engine: the replicas share one database, they hold no state of their own
between requests, and SQLite admits one writer in one process.

| Engine | Replicas | Why |
|---|---|---|
| PostgreSQL | As many as the connection budget allows | Real concurrency. Multiply `database.max_open_conns` by the replica count and keep the total under the server's `max_connections` |
| SQLite | One | No concurrent writers across processes or pods. Form 4 therefore means `replicas: 1` and a PersistentVolumeClaim, as its prerequisites say |

Three things are shared once the replicas share a database, and each is worth
knowing before the second replica starts.

**The rate limits are shared.** The throttle keeps no state in the process, so a
caller's attempts count once across the deployment rather than once per replica.
Nothing to configure.

**The audit chain stays one chain.** Appends serialise across every replica
through an advisory lock, which is what keeps two replicas from chaining two
entries onto the same predecessor. It bounds the audited request rate for the
deployment as a whole; [MONITORING.md](MONITORING.md) says what to watch.

**The janitor sweeps once per interval, not once per replica.** Every replica
runs its own janitor, and each pass first takes a deployment-wide sweep lock.
The replica that gets it sweeps; the others skip that pass and say so in the
log. The sweeps are idempotent, so the lock removes duplicated work rather than
preventing damage: a deployment where it never worked would be correct and
merely busier.

A replica killed mid-sweep does not hold the lock. On PostgreSQL it is a
session-level advisory lock, which the server drops when the holder's connection
ends, so the next pass anywhere finds it free; the one slow case is a replica
whose host vanishes without closing anything, where the lock lasts until the
server's TCP keepalives give up on the session. On SQLite it is a lease row
valid for one sweep timeout, two minutes, so a killed holder costs nothing at
the default five-minute `features.janitor_interval` and at most one pass at a
shorter one.

Nothing needs configuring for any of this, and there is no leader election to
run: a replica that loses the lock is not degraded, it is idle for that
interval. [MONITORING.md](MONITORING.md) has the log lines that tell an idle
replica from a broken janitor.

Two warnings about SQLite, since nothing enforces the row above. Two processes
opening one file over a network mount is not a supported deployment, and the
usual symptom is a startup refusal about `journal_mode`, because some network
mounts cannot do write-ahead logging. The janitor lease is a real lease on
SQLite and does coordinate two such processes, but it coordinates housekeeping
only: the rest of the schema still assumes one writer, so do not read the lease
as support for sharing a file.

## Related documents

| Document | What it covers |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Every key, default and environment variable |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | Each refusal above, and what to do about it |
| [MONITORING.md](MONITORING.md) | What to scrape once this is running |
| [ADMIN-GUIDE.md](ADMIN-GUIDE.md) | Day to day operation |
| [ADR 0009](adr/0009-refuse-a-kek-inside-the-data-directory.md) | Why the keyring needs its own mount |
| [ADR 0014](adr/0014-bootstrap-by-explicit-command.md) | Why the first administrators are created by a command, and why two |
