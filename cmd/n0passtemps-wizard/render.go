package main

import (
	"fmt"
	"strings"
)

// The generated files are rendered from string templates rather than from
// text/template. There are three of them, they are short, and a plain Sprintf
// keeps the generated output visible in the source, which matters for files an
// operator is expected to read and edit afterwards.

// renderConfig produces config.toml.
//
// Only the settings an operator answered for, or is likely to change, are
// written. Emitting every key with its default would produce a two hundred line
// file in which the six lines that matter are invisible, and would freeze
// today's defaults into the deployment so a later release could not improve
// them.
func renderConfig(a answers) string {
	var b strings.Builder

	b.WriteString("# n0passtemps configuration.\n" +
		"#\n" +
		"# Only the settings that differ from the defaults are here. Run\n" +
		"# \"n0passtemps-wizard check -config config.toml\" after editing.\n" +
		"#\n" +
		"# No secret belongs in this file. The keyring, the subject pepper and the\n" +
		"# database password come from the environment or from a mounted file, so this\n" +
		"# file can be committed to version control.\n\n")

	fmt.Fprintf(&b, "[tenant]\nid = \"default\"\nname = %q\n\n", a.TenantName)

	fmt.Fprintf(&b, "[server]\naddr = %q\n", a.Addr)
	if !strings.HasPrefix(a.Addr, "127.0.0.1") && !strings.HasPrefix(a.Addr, "localhost") {
		b.WriteString("\n" +
			"# This listener is not loopback, so TLS has to be accounted for. Either set\n" +
			"# the two paths below, or declare the reverse proxy that terminates it.\n" +
			"# tls_cert_file = \"/etc/n0passtemps/tls/fullchain.pem\"\n" +
			"# tls_key_file  = \"/etc/n0passtemps/tls/privkey.pem\"\n" +
			"#\n" +
			"# trust_proxy must be accompanied by the networks the proxy speaks from.\n" +
			"# Accepting a forwarded client address from anywhere lets a caller choose\n" +
			"# the address rate limiting and audit entries are keyed on.\n" +
			"# trust_proxy = true\n" +
			"# trusted_proxy_cidrs = [\"10.0.0.0/8\"]\n")
	}
	b.WriteString("\n")

	switch a.Deployment {
	case "postgres":
		b.WriteString("[database]\n" +
			"driver = \"postgres\"\n" +
			"# The DSN carries a password, so it comes from N0PASSTEMPS_DATABASE_DSN.\n" +
			"# sslmode must be set explicitly: libpq defaults to \"prefer\", which falls\n" +
			"# back to an unencrypted connection without reporting it.\n" +
			"data_dir = \"/var/lib/n0passtemps\"\n\n")
	default:
		b.WriteString("[database]\n" +
			"driver = \"sqlite\"\n" +
			"dsn = \"/var/lib/n0passtemps/n0passtemps.db\"\n" +
			"data_dir = \"/var/lib/n0passtemps\"\n\n")
	}

	b.WriteString("[kek]\n" +
		"provider = \"file\"\n" +
		"# Deliberately outside data_dir. A key stored beside the ciphertext it\n" +
		"# protects gives no confidentiality if the volume is copied, and the service\n" +
		"# refuses to start in that arrangement.\n" +
		"path = \"/etc/n0passtemps/kek/keyring.json\"\n\n")

	b.WriteString("[assertion]\n" +
		"signing_key_path = \"/etc/n0passtemps/kek/assertion-key.pem\"\n\n")

	fmt.Fprintf(&b, "[webauthn]\nrp_id = %q\nrp_display_name = %q\norigins = [%q]\n\n",
		a.RPID, a.TenantName, a.Origin)

	fmt.Fprintf(&b, "[admin]\nui_enabled = %t\n", a.AdminUI)
	if a.AdminUI && !strings.HasPrefix(a.Addr, "127.0.0.1") {
		b.WriteString("# The interface is reachable from every network that can reach the\n" +
			"# service unless this list is set.\n" +
			"# ip_allow_list = [\"10.0.0.0/8\"]\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "[features]\nlite_mode = %t\n", a.Lite)
	if a.Lite {
		b.WriteString("# lite_mode is a shorthand. It turns off the three administrative roles,\n" +
			"# the approval queue and the deferred erasure window, and reduces the\n" +
			"# recovery code batch to eight. Any of those can be set back on explicitly\n" +
			"# below, and doing so needs no migration.\n")
	}
	return b.String()
}

// renderCompose produces docker-compose.yml.
//
// It follows the same arrangement as the files under deploy/, and for the same
// reasons, so that there is one deployment shape to reason about rather than
// two. In particular the key material lives in a named volume that the image
// initialises with the right ownership. Bind-mounting key files from the host
// looks simpler and does not work: a file the host user created with mode 0600
// is unreadable by the unprivileged uid the container runs as, and loosening
// the mode to fix that is exactly the wrong reflex for a keyring.
func renderCompose(a answers) string {
	var b strings.Builder

	b.WriteString("# Generated deployment. Read it before running it.\n" +
		"#\n" +
		"# The keyring and the signing key live in the n0passtemps-kek volume, which is\n" +
		"# NOT the data volume. That separation is the point: a key on the same volume\n" +
		"# as the database it protects gives no confidentiality if the volume is copied.\n\n")

	b.WriteString("name: n0passtemps\n\n" +
		"services:\n" +
		"  n0passtemps:\n" +
		"    image: ghcr.io/socold/n0passtemps:${N0PASSTEMPS_VERSION:?set N0PASSTEMPS_VERSION in .env}\n" +
		"    restart: unless-stopped\n" +
		"    env_file: [.env]\n" +
		"    environment:\n" +
		"      # Every interface inside the container, published to loopback below.\n" +
		"      # The binary cannot see the publish rule, so this is acknowledged\n" +
		"      # explicitly rather than allowed by default.\n" +
		"      N0PASSTEMPS_SERVER_ADDR: \"0.0.0.0:8080\"\n" +
		"      N0PASSTEMPS_SERVER_ALLOW_PLAINTEXT: \"true\"\n")
	if a.Deployment == "postgres" {
		b.WriteString("      # The database sits on this compose network and nowhere else. Remove\n" +
			"      # this together with sslmode=disable the day it moves off this host.\n" +
			"      N0PASSTEMPS_DATABASE_ALLOW_PLAINTEXT: \"true\"\n")
	}
	b.WriteString("    ports:\n" +
		"      - \"${N0PASSTEMPS_PUBLISH:-127.0.0.1:8080}:8080\"\n" +
		"    volumes:\n" +
		"      - n0passtemps-data:/var/lib/n0passtemps\n" +
		"      # Separate from the data volume, and read-only to the service.\n" +
		"      - n0passtemps-kek:/etc/n0passtemps/kek:ro\n" +
		"      # \"z\" relabels the file on SELinux hosts and is ignored elsewhere.\n" +
		"      - ./config.toml:/etc/n0passtemps/config.toml:ro,z\n" +
		"    # The image is distroless and runs as a non-root user already; these\n" +
		"    # settings remove what it does not need.\n" +
		"    read_only: true\n" +
		"    tmpfs:\n" +
		"      - /tmp\n" +
		"    cap_drop: [ALL]\n" +
		"    security_opt:\n" +
		"      - no-new-privileges:true\n")

	if a.Deployment == "postgres" {
		b.WriteString("    depends_on:\n" +
			"      postgres:\n" +
			"        condition: service_healthy\n" +
			"\n" +
			"  postgres:\n" +
			"    image: postgres:16-alpine\n" +
			"    restart: unless-stopped\n" +
			"    environment:\n" +
			"      POSTGRES_DB: n0passtemps\n" +
			"      POSTGRES_USER: n0passtemps\n" +
			"      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}\n" +
			"    volumes:\n" +
			"      - n0passtemps-pgdata:/var/lib/postgresql/data\n" +
			"    # No host port. The database is reachable only on the internal network.\n" +
			"    healthcheck:\n" +
			"      test: [\"CMD-SHELL\", \"pg_isready -U n0passtemps -d n0passtemps\"]\n" +
			"      interval: 5s\n" +
			"      timeout: 3s\n" +
			"      retries: 10\n")
	}

	b.WriteString("\nvolumes:\n  n0passtemps-data:\n  n0passtemps-kek:\n")
	if a.Deployment == "postgres" {
		b.WriteString("  n0passtemps-pgdata:\n")
	}
	return b.String()
}

// renderEnv produces .env.
func renderEnv(a answers) string {
	var b strings.Builder

	b.WriteString("# Secrets and per-environment settings. This file must not be committed.\n" +
		"#\n" +
		"# Generate the pepper with: n0passtemps-wizard pepper\n\n")

	b.WriteString("# Pin the image. A moving tag makes a rollback impossible to describe.\n" +
		"N0PASSTEMPS_VERSION=1.1.0\n\n")

	b.WriteString("# Derives the lookup key from your application's user reference. Losing it\n" +
		"# makes every existing subject unfindable, so back it up with the keyring.\n" +
		"N0PASSTEMPS_SUBJECT_PEPPER=\n\n")

	if a.Deployment == "postgres" {
		b.WriteString("POSTGRES_PASSWORD=\n\n" +
			"# sslmode is explicit on purpose. libpq defaults to \"prefer\", which falls\n" +
			"# back to plaintext without saying so. Inside a compose network the\n" +
			"# connection never leaves the host, which is why disable is acceptable here\n" +
			"# and verify-full is required against a managed instance.\n" +
			"N0PASSTEMPS_DATABASE_DSN=postgres://n0passtemps:${POSTGRES_PASSWORD}@postgres:5432/n0passtemps?sslmode=disable\n\n")
	}

	b.WriteString("# Where the container's port is published. Keep it on loopback unless a\n" +
		"# reverse proxy in front terminates TLS.\n" +
		"N0PASSTEMPS_PUBLISH=127.0.0.1:8080\n\n")
	return b.String()
}
