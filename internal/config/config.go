// Package config loads and validates the server configuration.
//
// Configuration comes from three places, in increasing order of precedence:
// the built-in defaults, a TOML file, and the environment. Secrets are
// accepted only from the environment or from a file path pointing at material
// outside the repository, never as a literal in the TOML file, so that a
// configuration file can be committed to version control without leaking
// anything.
//
// Validation is deliberately strict and happens once, at startup. A
// misconfigured authentication server should refuse to start with a precise
// message rather than run in a state its operator did not intend.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// EnvPrefix is prepended to every environment variable this package reads.
const EnvPrefix = "N0PASSTEMPS_"

// SystemTenantID mirrors store.SystemTenantID. It is duplicated rather than
// imported so that the configuration package does not depend on the store,
// which would make the dependency graph circular once the store reads its own
// settings. A test asserts the two stay equal.
const SystemTenantID = "system"

// Config is the complete server configuration.
type Config struct {
	Tenant    Tenant    `toml:"tenant"`
	Server    Server    `toml:"server"`
	Database  Database  `toml:"database"`
	KEK       KEK       `toml:"kek"`
	Subject   Subject   `toml:"subject"`
	WebAuthn  WebAuthn  `toml:"webauthn"`
	TOTP      TOTP      `toml:"totp"`
	Recovery  Recovery  `toml:"recovery"`
	Assertion Assertion `toml:"assertion"`
	Throttle  Throttle  `toml:"throttle"`
	Audit     Audit     `toml:"audit"`
	Admin     Admin     `toml:"admin"`
	Logging   Logging   `toml:"logging"`
	Features  Features  `toml:"features"`
}

// Tenant names the single tenant a v1 deployment serves.
//
// Every table carries a tenant identifier even though one deployment serves one
// tenant, because adding the column later would mean rewriting every query and
// every index. This section is what fills it. Changing ID on an existing
// deployment orphans all of its data, which is why Validate refuses a value
// that does not look deliberate.
type Tenant struct {
	// ID is written into every row. It is not a secret and not a URL, just a
	// stable label.
	ID string `toml:"id"`

	// Name is what the administration interface displays.
	Name string `toml:"name"`
}

// Server holds the HTTP listener settings.
type Server struct {
	Addr string `toml:"addr"`

	// TLSCertFile and TLSKeyFile enable TLS termination in the process.
	// Leaving both empty serves plain HTTP, which is only acceptable when a
	// reverse proxy in front terminates TLS. Validate refuses plain HTTP on a
	// non-loopback address unless TrustProxy is set, so that an operator
	// cannot expose the service unencrypted by omission.
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`

	// AllowPlaintext permits serving plain HTTP on a non-loopback address
	// without declaring a reverse proxy.
	//
	// It exists for the one arrangement where that is genuinely safe and the
	// service cannot tell: a container binding every interface inside its own
	// network namespace, published to loopback on the host. The binary sees a
	// non-loopback bind address and has no way to know what is in front of it.
	//
	// It is an explicit opt-in rather than a relaxed default, because the
	// setting it overrides is the one that stops credentials being served
	// unencrypted to whatever can reach the port. An operator who sets it
	// without something else constraining reachability has turned off the
	// check that would have caught them.
	AllowPlaintext bool `toml:"allow_plaintext"`

	// TrustProxy declares that a reverse proxy terminates TLS and sets
	// X-Forwarded-For. It must be set together with TrustedProxyCIDRs:
	// honouring a forwarded client address from an arbitrary source lets a
	// caller spoof the IP that rate limiting and audit entries are keyed on.
	TrustProxy        bool     `toml:"trust_proxy"`
	TrustedProxyCIDRs []string `toml:"trusted_proxy_cidrs"`

	ReadTimeout       Duration `toml:"read_timeout"`
	WriteTimeout      Duration `toml:"write_timeout"`
	IdleTimeout       Duration `toml:"idle_timeout"`
	ReadHeaderTimeout Duration `toml:"read_header_timeout"`
	ShutdownGrace     Duration `toml:"shutdown_grace"`

	// MaxBodyBytes caps every request body. WebAuthn attestation objects are
	// the largest legitimate payload and stay well under this.
	MaxBodyBytes int64 `toml:"max_body_bytes"`

	// CORSAllowedOrigins is an explicit allow list. It is never a wildcard:
	// the endpoints it guards are credentialed, and "*" with credentials is
	// both forbidden by the fetch specification and a real vulnerability.
	CORSAllowedOrigins []string `toml:"cors_allowed_origins"`
}

// Database selects and configures the storage engine.
type Database struct {
	// Driver is "sqlite" or "postgres".
	Driver string `toml:"driver"`

	// DSN is the connection string. For sqlite it is a file path. It is read
	// from the environment in production deployments because a PostgreSQL DSN
	// contains a password.
	DSN string `toml:"dsn"`

	// DataDir holds persistent state. The KEK is refused if it lives here;
	// see internal/crypto/kek.
	DataDir string `toml:"data_dir"`

	MaxOpenConns    int      `toml:"max_open_conns"`
	MaxIdleConns    int      `toml:"max_idle_conns"`
	ConnMaxLifetime Duration `toml:"conn_max_lifetime"`

	// BusyTimeout applies to SQLite only. WAL mode still serialises writers,
	// so a concurrent writer needs to wait rather than fail immediately.
	BusyTimeout Duration `toml:"busy_timeout"`

	// AllowPlaintext permits sslmode=disable towards a host that is not
	// loopback.
	//
	// The one arrangement where that is defensible is a database on a private
	// container network that never leaves the host, which is what the shipped
	// compose file sets up. The validator cannot see network topology, so as
	// with server.allow_plaintext the operator has to say so explicitly; the
	// default remains a refusal, because a DSN that silently sends credentials
	// and TOTP seeds in clear across a real network is the likelier mistake.
	AllowPlaintext bool `toml:"allow_plaintext"`

	// AutoMigrate runs pending migrations at startup. Operators who prefer to
	// apply schema changes as a separate, reviewed step set this to false.
	AutoMigrate bool `toml:"auto_migrate"`
}

// KEK selects the key encryption key provider.
type KEK struct {
	// Provider is "file" or "env".
	Provider string `toml:"provider"`

	// Path is the keyring file, used when Provider is "file". It must be mode
	// 0600 and must not resolve inside Database.DataDir.
	Path string `toml:"path"`

	// EnvVar names the variable holding the keyring, used when Provider is
	// "env".
	EnvVar string `toml:"env_var"`

	// RotationInterval is how long a key version may remain current before
	// the health check reports rotation as overdue. Zero disables the
	// reminder. Rotation itself is always an explicit operator action.
	RotationInterval Duration `toml:"rotation_interval"`
}

// Subject configures how application-supplied user references are handled.
type Subject struct {
	// PepperEnv names the environment variable holding the HMAC pepper used
	// to derive the lookup key from an application's subject reference.
	//
	// The pepper must be backed up with the same care as the KEK: losing it
	// makes every existing subject unfindable. It is separate from the KEK so
	// that the key able to decrypt secrets is not also the key able to confirm
	// whether a given person has an account.
	PepperEnv string `toml:"pepper_env"`

	// MaxRefLength bounds the accepted reference, so an application cannot use
	// the field as arbitrary storage.
	MaxRefLength int `toml:"max_ref_length"`

	// SealReference stores an encrypted copy of the original reference, which
	// is needed to answer a subject access request and to show something
	// meaningful in the admin interface. Turning it off leaves the service
	// unable to tell an operator which user a row belongs to.
	SealReference bool `toml:"seal_reference"`
}

// WebAuthn configures the relying party.
//
// RPID and Origins are server configuration and are never taken from a
// request. WebAuthn's security rests on the relying party identifier and the
// origin being what the server expects; letting a caller supply either defeats
// the binding entirely.
type WebAuthn struct {
	RPID            string   `toml:"rp_id"`
	RPDisplayName   string   `toml:"rp_display_name"`
	Origins         []string `toml:"origins"`
	ChallengeTTL    Duration `toml:"challenge_ttl"`
	CeremonyTimeout Duration `toml:"ceremony_timeout"`

	// UserVerification is "required", "preferred" or "discouraged".
	// "required" makes the authenticator prove user presence and identity,
	// which is what makes a single WebAuthn factor sufficient.
	UserVerification string `toml:"user_verification"`

	// AttestationPreference is "none", "indirect" or "direct". "none" is the
	// default because verifying attestation requires either network access to
	// the FIDO Metadata Service or a bundled metadata blob, and this service
	// is meant to run offline.
	AttestationPreference string `toml:"attestation_preference"`

	// RequireAttestation refuses a registration whose attestation cannot be
	// verified. Enabling it without a metadata source configured is a
	// configuration error and Validate says so.
	RequireAttestation bool `toml:"require_attestation"`

	// MetadataPath is a FIDO Metadata Service BLOB on disk. Supplying it
	// locally rather than fetching it keeps attestation verification possible
	// without egress; refreshing it is an operator task.
	MetadataPath string `toml:"metadata_path"`

	// AllowedAAGUIDs restricts registration to named authenticator models.
	// Empty means any model. This is the offline-friendly alternative to full
	// attestation verification.
	AllowedAAGUIDs []string `toml:"allowed_aaguids"`

	// BlockedAAGUIDs refuses named models, for withdrawing a device whose
	// firmware has a published flaw.
	BlockedAAGUIDs []string `toml:"blocked_aaguids"`

	// MaxCredentialsPerSubject bounds enrolment, so a compromised API key
	// cannot quietly add an unbounded number of authenticators.
	MaxCredentialsPerSubject int `toml:"max_credentials_per_subject"`

	// CloneWarningAlerts raises an alert when an authenticator's signature
	// counter fails to advance. It does not refuse the assertion: many
	// authenticators legitimately report a constant zero.
	CloneWarningAlerts bool `toml:"clone_warning_alerts"`
}

// TOTP configures time-based one-time passwords, per RFC 6238.
type TOTP struct {
	Issuer string `toml:"issuer"`

	// Algorithm is "SHA1", "SHA256" or "SHA512". SHA1 is the default because
	// it is what authenticator applications actually implement; the HMAC
	// construction does not inherit SHA-1's collision weakness.
	Algorithm string `toml:"algorithm"`

	Digits      int      `toml:"digits"`
	Period      Duration `toml:"period"`
	SecretBytes int      `toml:"secret_bytes"`

	// Skew is the number of periods either side of the current one that are
	// accepted, to tolerate clock drift. Each extra period widens the window
	// an attacker may guess in, so this stays small.
	Skew int `toml:"skew"`

	// EnrolmentTTL bounds how long an unconfirmed secret remains usable.
	EnrolmentTTL Duration `toml:"enrolment_ttl"`
}

// Recovery configures single-use recovery codes.
type Recovery struct {
	// CodeCount is how many codes an issuance produces.
	CodeCount int `toml:"code_count"`

	// LowWatermark raises an alert once a subject has this many codes left,
	// so a user is prompted to reissue before running out entirely.
	LowWatermark int `toml:"low_watermark"`
}

// Assertion configures the signed result returned by a successful ceremony.
//
// The result is a detached signature the integrating application verifies
// offline against the public key served from the JWKS endpoint. Returning a
// bare status code instead would oblige that application to trust the network
// path between itself and this service.
type Assertion struct {
	// Issuer is the "iss" claim, and identifies this deployment.
	Issuer string `toml:"issuer"`

	// SigningKeyPath is an Ed25519 private key in PKCS#8 PEM form. Ed25519
	// avoids the parameter and padding choices that make RSA and ECDSA
	// signing easy to get wrong.
	SigningKeyPath string `toml:"signing_key_path"`

	// TTL is how long an assertion stays valid. It is short: the assertion
	// proves a ceremony just completed, and the application exchanges it
	// immediately for its own session.
	TTL Duration `toml:"ttl"`

	// AllowedClockSkew is tolerated when a verifier checks "nbf" and "exp".
	AllowedClockSkew Duration `toml:"allowed_clock_skew"`
}

// Throttle configures rate limiting.
//
// Limits are applied per subject, per source address and per API key at the
// same time. A single limit is always the wrong one: per-subject alone lets an
// attacker spray one attempt across many accounts, and per-address alone
// punishes every user behind one NAT.
type Throttle struct {
	Enabled bool `toml:"enabled"`

	Window Duration `toml:"window"`

	// MaxFailuresPerSubject and MaxFailuresPerIP trigger a lockout for
	// LockoutDuration once exceeded inside Window.
	MaxFailuresPerSubject int `toml:"max_failures_per_subject"`
	MaxFailuresPerIP      int `toml:"max_failures_per_ip"`

	// MaxRequestsPerKey caps total volume from one API key, which limits the
	// damage a leaked key can do before it is noticed.
	MaxRequestsPerKey int `toml:"max_requests_per_key"`

	LockoutDuration Duration `toml:"lockout_duration"`

	// AdminRevokeBurst is the number of revocations one administrator may
	// perform inside Window before the operation is refused. This is the
	// control that replaces the reversible revocation the specification
	// called for; see docs/adr/0010.
	AdminRevokeBurst int `toml:"admin_revoke_burst"`
}

// Audit configures the append-only log.
type Audit struct {
	// RetentionDays bounds growth. Zero keeps entries forever, which is the
	// default: silently discarding audit history is a decision an operator
	// must take explicitly.
	RetentionDays int `toml:"retention_days"`

	// VerifyOnStart recomputes the hash chain at startup. It is off by
	// default because the cost is linear in the size of the log.
	VerifyOnStart bool `toml:"verify_on_start"`

	// MaxQueryLimit caps a single audit query, because this is the one table
	// that grows without bound.
	MaxQueryLimit int `toml:"max_query_limit"`
}

// Admin configures the administration surface.
type Admin struct {
	// UIEnabled serves the server-rendered interface at /admin. Deployments
	// that administer the service purely through the API turn it off to
	// remove the surface.
	UIEnabled bool `toml:"ui_enabled"`

	// SessionTTL bounds an administrator's browser session.
	SessionTTL Duration `toml:"session_ttl"`

	// SessionCookieSecure marks the session cookie Secure. It is forced on
	// whenever TLS is terminated in-process or a trusted proxy is declared.
	SessionCookieSecure bool `toml:"session_cookie_secure"`

	// IPAllowList restricts the administration surface to named networks.
	// Empty means no restriction, which is why Validate warns when the UI is
	// enabled on a non-loopback listener without one.
	IPAllowList []string `toml:"ip_allow_list"`
}

// Logging configures structured output.
type Logging struct {
	// Level is "debug", "info", "warn" or "error".
	Level string `toml:"level"`

	// Format is "json" or "text". JSON is the default: logs are meant to be
	// ingested, not read.
	Format string `toml:"format"`

	// IncludeSourceIP records the client address on log lines. It is personal
	// data under GDPR, so it is a deliberate choice rather than a default.
	IncludeSourceIP bool `toml:"include_source_ip"`

	// RedactSubjectRefs keeps application-supplied subject references out of
	// logs, replacing them with a short prefix of their HMAC. These
	// references are frequently email addresses whatever the documentation
	// advises, so redaction is on by default.
	RedactSubjectRefs bool `toml:"redact_subject_refs"`
}

// Features gates the behaviour that distinguishes the lite deployment from the
// complete one. They are configuration rather than build tags, so one binary
// and one schema serve both and a deployment can adopt a feature without
// migrating.
type Features struct {
	// LiteMode is a shorthand that turns off AdminRBAC, DualApproval,
	// DeferredErasure and KEKRotationReminder together. Applied before
	// validation, so an explicit setting in the file still wins.
	LiteMode bool `toml:"lite_mode"`

	// AdminRBAC enforces the three administrative roles. With it off, every
	// administrative token has full authority.
	AdminRBAC bool `toml:"admin_rbac"`

	// DualApproval holds sensitive operations for a second administrator.
	DualApproval bool `toml:"dual_approval"`

	// DualApprovalOperations names the operations it applies to.
	DualApprovalOperations []string `toml:"dual_approval_operations"`

	// ApprovalTTL is how long a queued operation waits before expiring.
	ApprovalTTL Duration `toml:"approval_ttl"`

	// DeferredErasure blocks a subject immediately and purges the record
	// after ErasureRetention, instead of deleting at once. See
	// docs/adr/0007 for why the immediate delete the specification asked for
	// destroys the evidence that the erasure was legitimate.
	DeferredErasure  bool     `toml:"deferred_erasure"`
	ErasureRetention Duration `toml:"erasure_retention"`

	// KEKRotationReminder reports overdue rotation in the detailed health
	// report.
	KEKRotationReminder bool `toml:"kek_rotation_reminder"`

	// JanitorInterval is how often expired challenges, stale throttle
	// buckets, expired approvals and due erasures are swept.
	JanitorInterval Duration `toml:"janitor_interval"`
}

// Duration wraps time.Duration so TOML and environment variables can express
// it as a string such as "30s" or "15m".
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" {
		d.Duration = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// Default returns the built-in configuration.
//
// The defaults are chosen so that a deployment which sets only a database DSN,
// an rp_id, an origin and the two secrets is secure. Nothing that weakens the
// service is on by default.
func Default() Config {
	return Config{
		Tenant: Tenant{
			ID:   "default",
			Name: "n0passtemps",
		},
		Server: Server{
			Addr:               "127.0.0.1:8080",
			ReadTimeout:        Duration{15 * time.Second},
			WriteTimeout:       Duration{15 * time.Second},
			IdleTimeout:        Duration{60 * time.Second},
			ReadHeaderTimeout:  Duration{5 * time.Second},
			ShutdownGrace:      Duration{20 * time.Second},
			MaxBodyBytes:       256 << 10,
			CORSAllowedOrigins: nil,
		},
		Database: Database{
			Driver:          "sqlite",
			DSN:             "n0passtemps.db",
			DataDir:         "/var/lib/n0passtemps",
			MaxOpenConns:    8,
			MaxIdleConns:    4,
			ConnMaxLifetime: Duration{30 * time.Minute},
			BusyTimeout:     Duration{5 * time.Second},
			AutoMigrate:     true,
		},
		KEK: KEK{
			Provider:         "file",
			Path:             "/etc/n0passtemps/kek/keyring.json",
			EnvVar:           EnvPrefix + "KEK",
			RotationInterval: Duration{365 * 24 * time.Hour},
		},
		Subject: Subject{
			PepperEnv:     EnvPrefix + "SUBJECT_PEPPER",
			MaxRefLength:  256,
			SealReference: true,
		},
		WebAuthn: WebAuthn{
			RPDisplayName:            "n0passtemps",
			ChallengeTTL:             Duration{5 * time.Minute},
			CeremonyTimeout:          Duration{2 * time.Minute},
			UserVerification:         "required",
			AttestationPreference:    "none",
			RequireAttestation:       false,
			MaxCredentialsPerSubject: 10,
			CloneWarningAlerts:       true,
		},
		TOTP: TOTP{
			Issuer:       "n0passtemps",
			Algorithm:    "SHA1",
			Digits:       6,
			Period:       Duration{30 * time.Second},
			SecretBytes:  20,
			Skew:         1,
			EnrolmentTTL: Duration{15 * time.Minute},
		},
		Recovery: Recovery{
			CodeCount:    16,
			LowWatermark: 3,
		},
		Assertion: Assertion{
			Issuer:           "n0passtemps",
			SigningKeyPath:   "/etc/n0passtemps/kek/assertion-key.pem",
			TTL:              Duration{60 * time.Second},
			AllowedClockSkew: Duration{30 * time.Second},
		},
		Throttle: Throttle{
			Enabled:               true,
			Window:                Duration{15 * time.Minute},
			MaxFailuresPerSubject: 10,
			MaxFailuresPerIP:      50,
			MaxRequestsPerKey:     6000,
			LockoutDuration:       Duration{15 * time.Minute},
			AdminRevokeBurst:      10,
		},
		Audit: Audit{
			RetentionDays: 0,
			VerifyOnStart: false,
			MaxQueryLimit: 500,
		},
		Admin: Admin{
			UIEnabled:           true,
			SessionTTL:          Duration{30 * time.Minute},
			SessionCookieSecure: true,
		},
		Logging: Logging{
			Level:             "info",
			Format:            "json",
			IncludeSourceIP:   true,
			RedactSubjectRefs: true,
		},
		Features: Features{
			LiteMode:     false,
			AdminRBAC:    true,
			DualApproval: true,
			// Every operation listed here has a route that performs it. Queuing
			// one that nothing is mounted under would hold a request for approval
			// and then never execute it, which is worse than not offering it: the
			// operator believes the work is pending. A name added to this list
			// needs its route first.
			//
			// kek.rotate gates the rewrap of stored records onto the current key.
			// Adding a key version to the keyring file remains a command-line
			// operation and is not reachable through the API.
			DualApprovalOperations: []string{"credential.revoke_bulk", "subject.erase", "admin_token.create", "kek.rotate"},
			ApprovalTTL:            Duration{24 * time.Hour},
			DeferredErasure:        true,
			ErasureRetention:       Duration{30 * 24 * time.Hour},
			KEKRotationReminder:    true,
			JanitorInterval:        Duration{5 * time.Minute},
		},
	}
}

// Load reads the configuration from path, applies environment overrides and
// validates the result. An empty path skips the file.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %q: %w", path, err)
		}
		dec := toml.NewDecoder(strings.NewReader(string(raw)))
		// A typo in a key name must not be ignored: a misspelled
		// "require_attestation" would silently leave attestation unverified.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("config: parse %q: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return nil, err
	}
	if cfg.Features.LiteMode {
		applyLiteMode(&cfg, path)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyLiteMode turns off the governance features. It runs after the file and
// the environment have been read, but only relaxes settings the operator did
// not set explicitly, so lite_mode is a shorthand rather than an override.
func applyLiteMode(cfg *Config, path string) {
	explicit := explicitKeys(path)
	if !explicit["features.admin_rbac"] {
		cfg.Features.AdminRBAC = false
	}
	if !explicit["features.dual_approval"] {
		cfg.Features.DualApproval = false
	}
	if !explicit["features.deferred_erasure"] {
		cfg.Features.DeferredErasure = false
	}
	if !explicit["features.kek_rotation_reminder"] {
		cfg.Features.KEKRotationReminder = false
	}
	if !explicit["database.driver"] {
		cfg.Database.Driver = "sqlite"
	}
	if !explicit["recovery.code_count"] && cfg.Recovery.CodeCount == 16 {
		cfg.Recovery.CodeCount = 8
	}
}

// explicitKeys reports which dotted keys the file actually set, so lite mode
// does not undo a deliberate choice.
func explicitKeys(path string) map[string]bool {
	out := map[string]bool{}
	if path == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var generic map[string]any
	if err := toml.Unmarshal(raw, &generic); err != nil {
		return out
	}
	for section, v := range generic {
		table, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for key := range table {
			out[section+"."+key] = true
		}
	}
	return out
}

// Errors reported by Validate.
var (
	ErrMissingRPID    = errors.New("config: webauthn.rp_id is required")
	ErrMissingOrigins = errors.New("config: webauthn.origins must list at least one origin")
)

// Validate checks the configuration for internal consistency and for settings
// that would leave the service insecure. It returns every problem found rather
// than the first, so an operator fixes one round of errors instead of many.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	// Tenant.
	if c.Tenant.ID == "" {
		add("config: tenant.id is required")
	} else if c.Tenant.ID == SystemTenantID {
		add("config: tenant.id %q is reserved for records that cannot be attributed "+
			"to a tenant, such as a failed authentication", SystemTenantID)
	} else {
		for _, r := range c.Tenant.ID {
			if !(r == '-' || r == '_' ||
				(r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				add("config: tenant.id %q may contain only lowercase letters, digits, "+
					"hyphen and underscore", c.Tenant.ID)
				break
			}
		}
	}

	// Server.
	if c.Server.Addr == "" {
		add("config: server.addr is required")
	} else if _, _, err := net.SplitHostPort(c.Server.Addr); err != nil {
		add("config: server.addr %q is not host:port: %v", c.Server.Addr, err)
	}
	tlsEnabled := c.Server.TLSCertFile != "" || c.Server.TLSKeyFile != ""
	if tlsEnabled && (c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "") {
		add("config: server.tls_cert_file and server.tls_key_file must be set together")
	}
	if !tlsEnabled && !c.Server.TrustProxy && !c.Server.AllowPlaintext && !isLoopbackAddr(c.Server.Addr) {
		add("config: server.addr %q is not loopback but TLS is not configured and "+
			"server.trust_proxy is false; either terminate TLS here, set trust_proxy "+
			"with trusted_proxy_cidrs when a reverse proxy terminates it, or set "+
			"server.allow_plaintext when something outside this process already "+
			"constrains who can reach the port, such as a container published to "+
			"loopback", c.Server.Addr)
	}
	if c.Server.TrustProxy && len(c.Server.TrustedProxyCIDRs) == 0 {
		add("config: server.trust_proxy requires server.trusted_proxy_cidrs; accepting " +
			"a forwarded client address from any source lets a caller spoof the address " +
			"that rate limiting and audit entries are keyed on")
	}
	for _, cidr := range c.Server.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("config: server.trusted_proxy_cidrs entry %q is not a CIDR: %v", cidr, err)
		}
	}
	if c.Server.MaxBodyBytes <= 0 {
		add("config: server.max_body_bytes must be positive")
	}
	for _, o := range c.Server.CORSAllowedOrigins {
		if o == "*" {
			add("config: server.cors_allowed_origins must not contain \"*\"; these " +
				"endpoints are credentialed and a wildcard is both forbidden with " +
				"credentials and unsafe")
			continue
		}
		if err := validateOrigin(o); err != nil {
			add("config: server.cors_allowed_origins: %v", err)
		}
	}
	if c.Server.ReadHeaderTimeout.Duration <= 0 {
		add("config: server.read_header_timeout must be positive, it is the defence " +
			"against a slow-header denial of service")
	}

	// Database.
	switch c.Database.Driver {
	case "sqlite", "postgres":
	case "":
		add("config: database.driver is required")
	default:
		add("config: database.driver %q is not supported, use \"sqlite\" or \"postgres\"", c.Database.Driver)
	}
	if c.Database.DSN == "" {
		add("config: database.dsn is required")
	}
	if c.Database.Driver == "postgres" && c.Database.DSN != "" {
		if err := validatePostgresDSN(c.Database.DSN, c.Database.AllowPlaintext); err != nil {
			add("config: database.dsn: %v", err)
		}
	}
	if c.Database.MaxOpenConns <= 0 {
		add("config: database.max_open_conns must be positive")
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		add("config: database.max_idle_conns (%d) cannot exceed max_open_conns (%d)",
			c.Database.MaxIdleConns, c.Database.MaxOpenConns)
	}

	// KEK.
	switch c.KEK.Provider {
	case "file":
		if c.KEK.Path == "" {
			add("config: kek.path is required when kek.provider is \"file\"")
		} else if err := c.checkKEKOutsideDataDir(); err != nil {
			add("%v", err)
		}
	case "env":
		if c.KEK.EnvVar == "" {
			add("config: kek.env_var is required when kek.provider is \"env\"")
		}
	case "":
		add("config: kek.provider is required")
	default:
		add("config: kek.provider %q is not supported, use \"file\" or \"env\"", c.KEK.Provider)
	}

	// Subject.
	if c.Subject.PepperEnv == "" {
		add("config: subject.pepper_env is required")
	}
	if c.Subject.MaxRefLength < 1 || c.Subject.MaxRefLength > 4096 {
		add("config: subject.max_ref_length must be between 1 and 4096, got %d", c.Subject.MaxRefLength)
	}

	// WebAuthn.
	if c.WebAuthn.RPID == "" {
		errs = append(errs, ErrMissingRPID)
	} else if err := validateRPID(c.WebAuthn.RPID); err != nil {
		add("config: webauthn.rp_id: %v", err)
	}
	if len(c.WebAuthn.Origins) == 0 {
		errs = append(errs, ErrMissingOrigins)
	}
	for _, o := range c.WebAuthn.Origins {
		if err := validateOrigin(o); err != nil {
			add("config: webauthn.origins: %v", err)
			continue
		}
		if c.WebAuthn.RPID != "" {
			if err := originMatchesRPID(o, c.WebAuthn.RPID); err != nil {
				add("config: webauthn.origins: %v", err)
			}
		}
	}
	switch c.WebAuthn.UserVerification {
	case "required", "preferred", "discouraged":
	default:
		add("config: webauthn.user_verification %q is not valid, use \"required\", "+
			"\"preferred\" or \"discouraged\"", c.WebAuthn.UserVerification)
	}
	if c.WebAuthn.UserVerification == "discouraged" {
		add("config: webauthn.user_verification \"discouraged\" means the authenticator " +
			"proves possession only, so a WebAuthn assertion is no longer sufficient on " +
			"its own; set \"required\" or \"preferred\"")
	}
	switch c.WebAuthn.AttestationPreference {
	case "none", "indirect", "direct":
	default:
		add("config: webauthn.attestation_preference %q is not valid, use \"none\", "+
			"\"indirect\" or \"direct\"", c.WebAuthn.AttestationPreference)
	}
	if c.WebAuthn.RequireAttestation {
		if c.WebAuthn.AttestationPreference == "none" {
			add("config: webauthn.require_attestation needs attestation_preference " +
				"\"direct\" or \"indirect\", otherwise the authenticator is never asked " +
				"for a statement to verify")
		}
		if c.WebAuthn.MetadataPath == "" && len(c.WebAuthn.AllowedAAGUIDs) == 0 {
			add("config: webauthn.require_attestation needs either a metadata_path or " +
				"an allowed_aaguids list; with neither there is nothing to verify an " +
				"attestation statement against")
		}
	}
	if c.WebAuthn.MetadataPath != "" {
		if _, err := os.Stat(c.WebAuthn.MetadataPath); err != nil {
			add("config: webauthn.metadata_path %q is not readable: %v", c.WebAuthn.MetadataPath, err)
		}
	}
	for _, g := range c.WebAuthn.AllowedAAGUIDs {
		if err := validateAAGUID(g); err != nil {
			add("config: webauthn.allowed_aaguids: %v", err)
		}
	}
	for _, g := range c.WebAuthn.BlockedAAGUIDs {
		if err := validateAAGUID(g); err != nil {
			add("config: webauthn.blocked_aaguids: %v", err)
		}
	}
	if overlap := intersect(c.WebAuthn.AllowedAAGUIDs, c.WebAuthn.BlockedAAGUIDs); len(overlap) > 0 {
		add("config: AAGUID %s appears in both allowed_aaguids and blocked_aaguids", overlap[0])
	}
	if c.WebAuthn.ChallengeTTL.Duration < 30*time.Second || c.WebAuthn.ChallengeTTL.Duration > 15*time.Minute {
		add("config: webauthn.challenge_ttl must be between 30s and 15m, got %s",
			c.WebAuthn.ChallengeTTL.Duration)
	}
	if c.WebAuthn.MaxCredentialsPerSubject < 1 {
		add("config: webauthn.max_credentials_per_subject must be at least 1")
	}

	// TOTP.
	switch c.TOTP.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		add("config: totp.algorithm %q is not valid, use \"SHA1\", \"SHA256\" or \"SHA512\"",
			c.TOTP.Algorithm)
	}
	if c.TOTP.Digits != 6 && c.TOTP.Digits != 8 {
		add("config: totp.digits must be 6 or 8, got %d", c.TOTP.Digits)
	}
	if c.TOTP.Period.Duration < 15*time.Second || c.TOTP.Period.Duration > 120*time.Second {
		add("config: totp.period must be between 15s and 120s, got %s", c.TOTP.Period.Duration)
	}
	if c.TOTP.SecretBytes < 20 {
		add("config: totp.secret_bytes must be at least 20, RFC 4226 section 4 requires "+
			"a shared secret of at least 128 bits and recommends 160, got %d", c.TOTP.SecretBytes)
	}
	if c.TOTP.Skew < 0 || c.TOTP.Skew > 2 {
		add("config: totp.skew must be between 0 and 2; each additional period widens "+
			"the window an attacker may guess in, got %d", c.TOTP.Skew)
	}

	// Recovery.
	if c.Recovery.CodeCount < 1 || c.Recovery.CodeCount > 64 {
		add("config: recovery.code_count must be between 1 and 64, got %d", c.Recovery.CodeCount)
	}
	if c.Recovery.LowWatermark >= c.Recovery.CodeCount {
		add("config: recovery.low_watermark (%d) must be below code_count (%d), otherwise "+
			"a fresh batch is already in the warning state",
			c.Recovery.LowWatermark, c.Recovery.CodeCount)
	}

	// Assertion.
	if c.Assertion.Issuer == "" {
		add("config: assertion.issuer is required")
	}
	if c.Assertion.SigningKeyPath == "" {
		add("config: assertion.signing_key_path is required")
	}
	if c.Assertion.TTL.Duration <= 0 || c.Assertion.TTL.Duration > 5*time.Minute {
		add("config: assertion.ttl must be positive and at most 5m; the assertion "+
			"proves a ceremony just completed and is exchanged immediately, got %s",
			c.Assertion.TTL.Duration)
	}

	// Throttle.
	if c.Throttle.Enabled {
		if c.Throttle.Window.Duration <= 0 {
			add("config: throttle.window must be positive when throttling is enabled")
		}
		if c.Throttle.MaxFailuresPerSubject < 1 {
			add("config: throttle.max_failures_per_subject must be at least 1")
		}
		if c.Throttle.MaxFailuresPerIP < c.Throttle.MaxFailuresPerSubject {
			add("config: throttle.max_failures_per_ip (%d) below max_failures_per_subject "+
				"(%d) makes the per-subject limit unreachable",
				c.Throttle.MaxFailuresPerIP, c.Throttle.MaxFailuresPerSubject)
		}
		if c.Throttle.LockoutDuration.Duration <= 0 {
			add("config: throttle.lockout_duration must be positive when throttling is enabled")
		}
		if c.Throttle.AdminRevokeBurst < 1 {
			add("config: throttle.admin_revoke_burst must be at least 1")
		}
	}

	// Audit.
	if c.Audit.MaxQueryLimit < 1 || c.Audit.MaxQueryLimit > 10000 {
		add("config: audit.max_query_limit must be between 1 and 10000, got %d", c.Audit.MaxQueryLimit)
	}
	if c.Audit.RetentionDays < 0 {
		add("config: audit.retention_days cannot be negative")
	}

	// Admin.
	if c.Admin.UIEnabled {
		if c.Admin.SessionTTL.Duration <= 0 || c.Admin.SessionTTL.Duration > 12*time.Hour {
			add("config: admin.session_ttl must be positive and at most 12h, got %s",
				c.Admin.SessionTTL.Duration)
		}
		if !isLoopbackAddr(c.Server.Addr) && len(c.Admin.IPAllowList) == 0 {
			add("config: admin.ui_enabled on the non-loopback listener %q without "+
				"admin.ip_allow_list exposes the administration interface to every "+
				"network that can reach the service; set an allow list or disable the UI",
				c.Server.Addr)
		}
		if tlsEnabled || c.Server.TrustProxy {
			c.Admin.SessionCookieSecure = true
		}
	}
	for _, cidr := range c.Admin.IPAllowList {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("config: admin.ip_allow_list entry %q is not a CIDR: %v", cidr, err)
		}
	}

	// Logging.
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		add("config: logging.level %q is not valid, use \"debug\", \"info\", \"warn\" or \"error\"",
			c.Logging.Level)
	}
	switch c.Logging.Format {
	case "json", "text":
	default:
		add("config: logging.format %q is not valid, use \"json\" or \"text\"", c.Logging.Format)
	}

	// Features.
	if c.Features.DualApproval && len(c.Features.DualApprovalOperations) == 0 {
		add("config: features.dual_approval is on but dual_approval_operations is empty, " +
			"so nothing is actually held for a second administrator")
	}
	if c.Features.DualApproval && !c.Features.AdminRBAC {
		add("config: features.dual_approval requires features.admin_rbac; without " +
			"distinct roles there is no way to tell two administrators apart")
	}
	if c.Features.DualApproval && c.Features.ApprovalTTL.Duration <= 0 {
		add("config: features.approval_ttl must be positive when dual_approval is on")
	}
	if c.Features.DeferredErasure && c.Features.ErasureRetention.Duration <= 0 {
		add("config: features.erasure_retention must be positive when deferred_erasure is on")
	}
	if c.Features.JanitorInterval.Duration <= 0 {
		add("config: features.janitor_interval must be positive; expired challenges and " +
			"due erasures would otherwise never be swept")
	}

	return errors.Join(errs...)
}

// checkKEKOutsideDataDir mirrors the check the KEK provider performs at load
// time, so the error appears during configuration validation rather than after
// the service has begun starting up.
func (c *Config) checkKEKOutsideDataDir() error {
	kekAbs, err := filepath.Abs(c.KEK.Path)
	if err != nil {
		return fmt.Errorf("config: kek.path %q cannot be resolved: %w", c.KEK.Path, err)
	}
	kekAbs = resolveSymlinks(kekAbs)
	for _, dir := range c.dataDirs() {
		dirAbs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		dirAbs = resolveSymlinks(dirAbs)
		rel, err := filepath.Rel(dirAbs, kekAbs)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf(
				"config: kek.path %q is inside the data directory %q; a key stored "+
					"beside the ciphertext it protects gives no confidentiality if the "+
					"volume is copied, so mount it separately or use kek.provider \"env\"",
				kekAbs, dirAbs)
		}
	}
	return nil
}

// dataDirs lists the directories holding persistent state, which the KEK must
// not share.
func (c *Config) dataDirs() []string {
	dirs := []string{}
	if c.Database.DataDir != "" {
		dirs = append(dirs, c.Database.DataDir)
	}
	if c.Database.Driver == "sqlite" && c.Database.DSN != "" {
		if d := filepath.Dir(strings.TrimPrefix(sqlitePath(c.Database.DSN), "file:")); d != "" && d != "." {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// TenantID returns the identifier every row is written under.
func (c *Config) TenantID() string { return c.Tenant.ID }

// DataDirs exposes the directories the KEK must not live in, for the provider.
func (c *Config) DataDirs() []string { return c.dataDirs() }

// sqlitePath strips the query string from a SQLite DSN so the file path can be
// inspected.
func sqlitePath(dsn string) string {
	if i := strings.IndexByte(dsn, '?'); i >= 0 {
		return dsn[:i]
	}
	return dsn
}

// resolveSymlinks mirrors the resolution the KEK provider performs, so the
// configuration check and the load-time check agree on whether a path lies
// inside the data directory. A textual comparison alone is defeated by a
// symbolic link or a bind mount.
func resolveSymlinks(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		return path
	}
	if realDir, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		return filepath.Join(realDir, base)
	}
	return path
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// An empty host means every interface.
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateRPID checks that the relying party identifier is a bare registrable
// domain. WebAuthn requires an effective domain, not a URL and not a host with
// a port, and a mistake here fails at ceremony time with an error that is hard
// to trace back to configuration.
func validateRPID(id string) error {
	if strings.Contains(id, "://") {
		return fmt.Errorf("%q looks like a URL; rp_id is a bare domain such as \"example.com\"", id)
	}
	if strings.Contains(id, "/") {
		return fmt.Errorf("%q must not contain a path", id)
	}
	if strings.Contains(id, ":") {
		return fmt.Errorf("%q must not include a port", id)
	}
	if id == "localhost" {
		return nil
	}
	if net.ParseIP(id) != nil {
		return fmt.Errorf("%q is an IP address; WebAuthn requires a domain name", id)
	}
	if !strings.Contains(id, ".") {
		return fmt.Errorf("%q is not a domain name", id)
	}
	return nil
}

// validateOrigin checks that an origin is a scheme, host and optional port,
// with no path, as the fetch specification defines it.
func validateOrigin(o string) error {
	u, err := url.Parse(o)
	if err != nil {
		return fmt.Errorf("%q is not a valid origin: %w", o, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%q must use scheme https, or http for localhost only", o)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", o)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%q must not contain a path", o)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must not contain a query or fragment", o)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("%q uses plain http on a non-loopback host; WebAuthn "+
				"requires a secure context", o)
		}
	}
	return nil
}

// originMatchesRPID checks the relation WebAuthn actually enforces: the
// relying party identifier must equal the origin's effective domain or be a
// registrable suffix of it. Catching this at startup avoids a ceremony that
// fails in the browser for reasons the server logs cannot explain.
func originMatchesRPID(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return nil // already reported by validateOrigin
	}
	host := u.Hostname()
	if host == rpID {
		return nil
	}
	if strings.HasSuffix(host, "."+rpID) {
		return nil
	}
	return fmt.Errorf("origin %q is not covered by rp_id %q; the relying party "+
		"identifier must equal the origin's domain or be a parent of it", origin, rpID)
}

// validateAAGUID accepts the canonical 8-4-4-4-12 hexadecimal form.
func validateAAGUID(g string) error {
	s := strings.ToLower(strings.TrimSpace(g))
	if len(s) != 36 {
		return fmt.Errorf("%q is not a 36 character AAGUID", g)
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return fmt.Errorf("%q is malformed at position %d", g, i)
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", r) {
				return fmt.Errorf("%q contains a non-hexadecimal character at position %d", g, i)
			}
		}
	}
	return nil
}

// validatePostgresDSN rejects a connection string that does not guarantee
// transport encryption.
//
// libpq defaults sslmode to "prefer", which falls back to plaintext without
// reporting it, so an unset sslmode is an error rather than a default. Both DSN
// forms are parsed properly, the URL form and the keyword form; an earlier
// version searched the string for "host=localhost", which never matches a URL
// and so refused every loopback URL while claiming to accept them.
func validatePostgresDSN(dsn string, allowPlaintext bool) error {
	mode, host := postgresModeAndHost(dsn)

	switch mode {
	case "":
		return errors.New("no sslmode is set; libpq defaults to \"prefer\", which falls " +
			"back to an unencrypted connection without reporting it. Set sslmode=require " +
			"or stronger, or sslmode=disable explicitly for a loopback socket")
	case "require", "verify-ca", "verify-full":
		return nil
	case "disable":
		if isLocalDatabaseHost(host) || allowPlaintext {
			return nil
		}
		return fmt.Errorf("sslmode=disable towards %q sends credentials and secrets in "+
			"clear; use sslmode=require, verify-ca or verify-full, or set "+
			"database.allow_plaintext when the link is a private container network "+
			"that never leaves the host", host)
	default:
		return fmt.Errorf("sslmode=%s does not guarantee an encrypted connection; "+
			"use sslmode=require, verify-ca or verify-full", mode)
	}
}

// postgresModeAndHost extracts sslmode and the host from either DSN form.
func postgresModeAndHost(dsn string) (mode, host string) {
	trimmed := strings.TrimSpace(dsn)
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", ""
		}
		q := u.Query()
		host = u.Hostname()
		if h := q.Get("host"); h != "" {
			// libpq lets the query string override the authority, which is
			// how a unix socket directory is given in URL form.
			host = h
		}
		return strings.ToLower(q.Get("sslmode")), host
	}

	for _, field := range strings.Fields(trimmed) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "'")
		switch strings.ToLower(k) {
		case "sslmode":
			mode = strings.ToLower(v)
		case "host":
			host = v
		}
	}
	return mode, host
}

// isLocalDatabaseHost reports whether the connection stays on this machine: a
// unix socket directory, an empty host (libpq then uses the default socket), or
// a loopback name or address.
func isLocalDatabaseHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "/") || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[strings.ToLower(v)] = struct{}{}
	}
	var out []string
	for _, v := range b {
		if _, ok := set[strings.ToLower(v)]; ok {
			out = append(out, v)
		}
	}
	return out
}

// mustAtoi is used by applyEnv for fields already known to be numeric.
func parseInt(name, value string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", name, value)
	}
	return n, nil
}

func parseBool(name, value string) (bool, error) {
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("config: %s must be a boolean, got %q", name, value)
	}
	return b, nil
}

func parseList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
