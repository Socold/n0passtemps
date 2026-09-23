package config

import (
	"fmt"
	"os"
	"strings"
)

// Environment variables override the TOML file. Every name is the dotted
// configuration key uppercased with dots replaced by underscores, prefixed by
// EnvPrefix, so "webauthn.rp_id" is N0PASSTEMPS_WEBAUTHN_RP_ID.
//
// Only fields an operator has a reason to set per environment are wired up.
// Exposing every field would make the surface large without making it more
// useful, and would invite drift between this table and the struct.
//
// Secrets deliberately have no TOML counterpart at all. The keyring and the
// subject pepper are read from the environment by their own providers, and the
// database DSN, while it has a TOML field, is expected to come from here
// whenever it contains a password.
func applyEnv(cfg *Config) error {
	observedKeys = observedKeys[:0]

	var errs []string
	fail := func(err error) {
		errs = append(errs, err.Error())
	}

	str := func(key string, dst *string) {
		if v, ok := lookup(key); ok {
			*dst = v
		}
	}
	list := func(key string, dst *[]string) {
		if v, ok := lookup(key); ok {
			*dst = parseList(v)
		}
	}
	num := func(key string, dst *int) {
		if v, ok := lookup(key); ok {
			n, err := parseInt(key, v)
			if err != nil {
				fail(err)
				return
			}
			*dst = n
		}
	}
	num64 := func(key string, dst *int64) {
		if v, ok := lookup(key); ok {
			n, err := parseInt(key, v)
			if err != nil {
				fail(err)
				return
			}
			*dst = int64(n)
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := lookup(key); ok {
			b, err := parseBool(key, v)
			if err != nil {
				fail(err)
				return
			}
			*dst = b
		}
	}
	dur := func(key string, dst *Duration) {
		if v, ok := lookup(key); ok {
			if err := dst.UnmarshalText([]byte(v)); err != nil {
				fail(fmt.Errorf("config: %s: %w", key, err))
			}
		}
	}

	str("TENANT_ID", &cfg.Tenant.ID)
	str("TENANT_NAME", &cfg.Tenant.Name)

	str("SERVER_ADDR", &cfg.Server.Addr)
	str("SERVER_TLS_CERT_FILE", &cfg.Server.TLSCertFile)
	str("SERVER_TLS_KEY_FILE", &cfg.Server.TLSKeyFile)
	boolean("SERVER_ALLOW_PLAINTEXT", &cfg.Server.AllowPlaintext)
	boolean("SERVER_TRUST_PROXY", &cfg.Server.TrustProxy)
	list("SERVER_TRUSTED_PROXY_CIDRS", &cfg.Server.TrustedProxyCIDRs)
	dur("SERVER_READ_TIMEOUT", &cfg.Server.ReadTimeout)
	dur("SERVER_WRITE_TIMEOUT", &cfg.Server.WriteTimeout)
	dur("SERVER_IDLE_TIMEOUT", &cfg.Server.IdleTimeout)
	dur("SERVER_READ_HEADER_TIMEOUT", &cfg.Server.ReadHeaderTimeout)
	dur("SERVER_SHUTDOWN_GRACE", &cfg.Server.ShutdownGrace)
	num64("SERVER_MAX_BODY_BYTES", &cfg.Server.MaxBodyBytes)
	list("SERVER_CORS_ALLOWED_ORIGINS", &cfg.Server.CORSAllowedOrigins)

	str("DATABASE_DRIVER", &cfg.Database.Driver)
	str("DATABASE_DSN", &cfg.Database.DSN)
	str("DATABASE_DATA_DIR", &cfg.Database.DataDir)
	num("DATABASE_MAX_OPEN_CONNS", &cfg.Database.MaxOpenConns)
	num("DATABASE_MAX_IDLE_CONNS", &cfg.Database.MaxIdleConns)
	dur("DATABASE_CONN_MAX_LIFETIME", &cfg.Database.ConnMaxLifetime)
	dur("DATABASE_BUSY_TIMEOUT", &cfg.Database.BusyTimeout)
	boolean("DATABASE_ALLOW_PLAINTEXT", &cfg.Database.AllowPlaintext)
	boolean("DATABASE_AUTO_MIGRATE", &cfg.Database.AutoMigrate)

	str("KEK_PROVIDER", &cfg.KEK.Provider)
	str("KEK_PATH", &cfg.KEK.Path)
	str("KEK_ENV_VAR", &cfg.KEK.EnvVar)
	dur("KEK_ROTATION_INTERVAL", &cfg.KEK.RotationInterval)

	str("SUBJECT_PEPPER_ENV", &cfg.Subject.PepperEnv)
	num("SUBJECT_MAX_REF_LENGTH", &cfg.Subject.MaxRefLength)
	boolean("SUBJECT_SEAL_REFERENCE", &cfg.Subject.SealReference)

	str("WEBAUTHN_RP_ID", &cfg.WebAuthn.RPID)
	str("WEBAUTHN_RP_DISPLAY_NAME", &cfg.WebAuthn.RPDisplayName)
	list("WEBAUTHN_ORIGINS", &cfg.WebAuthn.Origins)
	dur("WEBAUTHN_CHALLENGE_TTL", &cfg.WebAuthn.ChallengeTTL)
	dur("WEBAUTHN_CEREMONY_TIMEOUT", &cfg.WebAuthn.CeremonyTimeout)
	str("WEBAUTHN_USER_VERIFICATION", &cfg.WebAuthn.UserVerification)
	str("WEBAUTHN_ATTESTATION_PREFERENCE", &cfg.WebAuthn.AttestationPreference)
	boolean("WEBAUTHN_REQUIRE_ATTESTATION", &cfg.WebAuthn.RequireAttestation)
	str("WEBAUTHN_METADATA_PATH", &cfg.WebAuthn.MetadataPath)
	list("WEBAUTHN_ALLOWED_AAGUIDS", &cfg.WebAuthn.AllowedAAGUIDs)
	list("WEBAUTHN_BLOCKED_AAGUIDS", &cfg.WebAuthn.BlockedAAGUIDs)
	num("WEBAUTHN_MAX_CREDENTIALS_PER_SUBJECT", &cfg.WebAuthn.MaxCredentialsPerSubject)
	boolean("WEBAUTHN_CLONE_WARNING_ALERTS", &cfg.WebAuthn.CloneWarningAlerts)

	str("TOTP_ISSUER", &cfg.TOTP.Issuer)
	str("TOTP_ALGORITHM", &cfg.TOTP.Algorithm)
	num("TOTP_DIGITS", &cfg.TOTP.Digits)
	dur("TOTP_PERIOD", &cfg.TOTP.Period)
	num("TOTP_SECRET_BYTES", &cfg.TOTP.SecretBytes)
	num("TOTP_SKEW", &cfg.TOTP.Skew)
	dur("TOTP_ENROLMENT_TTL", &cfg.TOTP.EnrolmentTTL)

	num("RECOVERY_CODE_COUNT", &cfg.Recovery.CodeCount)
	num("RECOVERY_LOW_WATERMARK", &cfg.Recovery.LowWatermark)

	dur("TICKETS_TTL", &cfg.Tickets.TTL)
	boolean("TICKETS_REQUIRE_EXISTING_FACTOR_DEFAULT", &cfg.Tickets.RequireExistingFactorDefault)

	str("ASSERTION_ISSUER", &cfg.Assertion.Issuer)
	str("ASSERTION_SIGNING_KEY_PATH", &cfg.Assertion.SigningKeyPath)
	dur("ASSERTION_TTL", &cfg.Assertion.TTL)
	dur("ASSERTION_ALLOWED_CLOCK_SKEW", &cfg.Assertion.AllowedClockSkew)

	boolean("THROTTLE_ENABLED", &cfg.Throttle.Enabled)
	dur("THROTTLE_WINDOW", &cfg.Throttle.Window)
	num("THROTTLE_MAX_FAILURES_PER_SUBJECT", &cfg.Throttle.MaxFailuresPerSubject)
	num("THROTTLE_MAX_FAILURES_PER_IP", &cfg.Throttle.MaxFailuresPerIP)
	num("THROTTLE_MAX_REQUESTS_PER_KEY", &cfg.Throttle.MaxRequestsPerKey)
	dur("THROTTLE_LOCKOUT_DURATION", &cfg.Throttle.LockoutDuration)
	num("THROTTLE_ADMIN_REVOKE_BURST", &cfg.Throttle.AdminRevokeBurst)

	// The scalars only. The per-reason weight table is file-only on purpose;
	// see the comment on config.Risk.Weights.
	boolean("RISK_ENABLED", &cfg.Risk.Enabled)
	num("RISK_ELEVATED_AT", &cfg.Risk.ElevatedAt)
	num("RISK_HIGH_AT", &cfg.Risk.HighAt)
	dur("RISK_DORMANT_AFTER", &cfg.Risk.DormantAfter)
	dur("RISK_NEW_CREDENTIAL_WITHIN", &cfg.Risk.NewCredentialWithin)

	num("AUDIT_RETENTION_DAYS", &cfg.Audit.RetentionDays)
	boolean("AUDIT_VERIFY_ON_START", &cfg.Audit.VerifyOnStart)
	num("AUDIT_MAX_QUERY_LIMIT", &cfg.Audit.MaxQueryLimit)

	// The external audit sink. The bearer credential is not here: like the
	// keyring and the pepper it is named through a variable rather than carried
	// by one this package reads, so it never ends up in a Config a test or a
	// diagnostic might print.
	str("AUDIT_SINK_ENDPOINT", &cfg.Audit.Sink.Endpoint)
	str("AUDIT_SINK_TOKEN_ENV", &cfg.Audit.Sink.TokenEnv)
	boolean("AUDIT_SINK_RECEIVER_OUTSIDE_OPERATOR_CONTROL", &cfg.Audit.Sink.ReceiverOutsideOperatorControl)
	num("AUDIT_SINK_BUFFER_SIZE", &cfg.Audit.Sink.BufferSize)
	num("AUDIT_SINK_BATCH_SIZE", &cfg.Audit.Sink.BatchSize)
	dur("AUDIT_SINK_FLUSH_INTERVAL", &cfg.Audit.Sink.FlushInterval)
	dur("AUDIT_SINK_TIMEOUT", &cfg.Audit.Sink.Timeout)
	dur("AUDIT_SINK_RETRY_BACKOFF", &cfg.Audit.Sink.RetryBackoff)
	dur("AUDIT_SINK_MAX_RETRY_BACKOFF", &cfg.Audit.Sink.MaxRetryBackoff)
	str("AUDIT_SINK_WATERMARK_PATH", &cfg.Audit.Sink.WatermarkPath)

	boolean("ADMIN_UI_ENABLED", &cfg.Admin.UIEnabled)
	dur("ADMIN_SESSION_TTL", &cfg.Admin.SessionTTL)
	boolean("ADMIN_SESSION_COOKIE_SECURE", &cfg.Admin.SessionCookieSecure)
	list("ADMIN_IP_ALLOW_LIST", &cfg.Admin.IPAllowList)
	boolean("ADMIN_PASSKEY_REQUIRED", &cfg.Admin.PasskeyRequired)

	str("LOGGING_LEVEL", &cfg.Logging.Level)
	str("LOGGING_FORMAT", &cfg.Logging.Format)
	boolean("LOGGING_INCLUDE_SOURCE_IP", &cfg.Logging.IncludeSourceIP)
	boolean("LOGGING_REDACT_SUBJECT_REFS", &cfg.Logging.RedactSubjectRefs)

	boolean("FEATURES_LITE_MODE", &cfg.Features.LiteMode)
	boolean("FEATURES_ADMIN_RBAC", &cfg.Features.AdminRBAC)
	boolean("FEATURES_DUAL_APPROVAL", &cfg.Features.DualApproval)
	list("FEATURES_DUAL_APPROVAL_OPERATIONS", &cfg.Features.DualApprovalOperations)
	dur("FEATURES_APPROVAL_TTL", &cfg.Features.ApprovalTTL)
	boolean("FEATURES_DEFERRED_ERASURE", &cfg.Features.DeferredErasure)
	dur("FEATURES_ERASURE_RETENTION", &cfg.Features.ErasureRetention)
	boolean("FEATURES_KEK_ROTATION_REMINDER", &cfg.Features.KEKRotationReminder)
	dur("FEATURES_JANITOR_INTERVAL", &cfg.Features.JanitorInterval)
	dur("FEATURES_ROTATION_GRACE", &cfg.Features.RotationGrace)

	// LITE_MODE is accepted without the prefix as well, because the published
	// quickstart uses the short form and changing it would break copied
	// commands.
	if v, ok := os.LookupEnv("LITE_MODE"); ok {
		b, err := parseBool("LITE_MODE", v)
		if err != nil {
			fail(err)
		} else {
			cfg.Features.LiteMode = b
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: invalid environment:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// observedKeys records every key applyEnv consults.
//
// It exists so a test can assert that the shipped .env.example names only
// variables this package actually reads. Deriving the set from the code path
// rather than from a hand-written list means the two cannot drift apart.
//
// Writes happen during applyEnv, which runs once at startup before any
// goroutine exists, so no synchronisation is needed.
var observedKeys []string

// recordedEnvKeys returns the keys consulted by the most recent applyEnv,
// without the prefix.
func recordedEnvKeys() []string {
	if observedKeys == nil {
		// Nothing has run applyEnv yet. Run it against a throwaway
		// configuration so the caller gets the full set.
		cfg := Default()
		_ = applyEnv(&cfg)
	}
	return observedKeys
}

// lookup reads a prefixed variable, treating an empty value as unset. An
// operator who exports a variable with no value in a shell script means "leave
// it alone", not "set it to the empty string", and the latter reading turns a
// stray line in an env file into a validation failure.
func lookup(key string) (string, bool) {
	observedKeys = append(observedKeys, key)

	v, ok := os.LookupEnv(EnvPrefix + key)
	if !ok {
		return "", false
	}
	if strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}
