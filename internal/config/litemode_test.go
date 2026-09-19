package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setMinimalEnv supplies the keys that have no default, the way a deployment
// configured purely through its environment would.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvPrefix+"SUBJECT_PEPPER",
		base64.StdEncoding.EncodeToString(make([]byte, MinPepperBytesForTest)))
	t.Setenv(EnvPrefix+"WEBAUTHN_RP_ID", "example.com")
	t.Setenv(EnvPrefix+"WEBAUTHN_ORIGINS", "https://example.com")
}

// TestLiteModeYieldsToTheEnvironment covers the shorthand against the source
// that outranks it.
//
// Lite mode relaxes only what the operator did not set. It used to look for
// that in the file alone, so a deployment configured through its environment
// had role enforcement turned off, and its PostgreSQL database swapped for a
// fresh SQLite file, by a shorthand it had explicitly overridden.
func TestLiteModeYieldsToTheEnvironment(t *testing.T) {
	const dsn = "postgres://n0passtemps:placeholder@db.internal:5432/n0passtemps?sslmode=verify-full"

	for _, tc := range []struct {
		name  string
		env   map[string]string
		check func(*testing.T, *Config)
	}{
		{
			name: "nothing else set, so the shorthand applies in full",
			env:  map[string]string{"LITE_MODE": "true"},
			check: func(t *testing.T, c *Config) {
				if c.Features.AdminRBAC || c.Features.DualApproval ||
					c.Features.DeferredErasure || c.Features.KEKRotationReminder {
					t.Errorf("lite mode left a governance feature on: %+v", c.Features)
				}
				if c.Recovery.CodeCount != 8 {
					t.Errorf("recovery.code_count = %d, want 8", c.Recovery.CodeCount)
				}
			},
		},
		{
			name: "role enforcement asked for through the environment",
			env: map[string]string{
				"LITE_MODE":                       "true",
				EnvPrefix + "FEATURES_ADMIN_RBAC": "true",
			},
			check: func(t *testing.T, c *Config) {
				if !c.Features.AdminRBAC {
					t.Error("lite mode turned off the features.admin_rbac the environment set")
				}
				if c.Features.DualApproval {
					t.Error("features.dual_approval was not set anywhere and lite mode left it on")
				}
			},
		},
		{
			name: "the prefixed form of the shorthand behaves the same",
			env: map[string]string{
				EnvPrefix + "FEATURES_LITE_MODE":        "true",
				EnvPrefix + "FEATURES_DEFERRED_ERASURE": "true",
			},
			check: func(t *testing.T, c *Config) {
				if !c.Features.DeferredErasure {
					t.Error("lite mode turned off the features.deferred_erasure the environment set")
				}
			},
		},
		{
			name: "a PostgreSQL driver named through the environment",
			env: map[string]string{
				"LITE_MODE":                   "true",
				EnvPrefix + "DATABASE_DRIVER": "postgres",
				EnvPrefix + "DATABASE_DSN":    dsn,
			},
			check: func(t *testing.T, c *Config) {
				if c.Database.Driver != "postgres" {
					t.Errorf("database.driver = %q, want the postgres the environment set", c.Database.Driver)
				}
			},
		},
		{
			name: "a recovery code count the environment set to the default on purpose",
			env: map[string]string{
				"LITE_MODE":                       "true",
				EnvPrefix + "RECOVERY_CODE_COUNT": "16",
			},
			check: func(t *testing.T, c *Config) {
				if c.Recovery.CodeCount != 16 {
					t.Errorf("recovery.code_count = %d, want the 16 the environment set", c.Recovery.CodeCount)
				}
			},
		},
		{
			name: "an exported but empty variable, which counts as unset",
			env: map[string]string{
				"LITE_MODE":                       "true",
				EnvPrefix + "FEATURES_ADMIN_RBAC": "",
			},
			check: func(t *testing.T, c *Config) {
				if c.Features.AdminRBAC {
					t.Error("an empty FEATURES_ADMIN_RBAC was read as an explicit choice")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setMinimalEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tc.check(t, cfg)
		})
	}
}

// TestLiteModeStillYieldsToTheFile guards the behaviour the environment rule
// was added beside.
func TestLiteModeStillYieldsToTheFile(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("LITE_MODE", "true")

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[features]\nadmin_rbac = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Features.AdminRBAC {
		t.Error("lite mode turned off the features.admin_rbac the file set")
	}
	if cfg.Features.DeferredErasure {
		t.Error("features.deferred_erasure was not set anywhere and lite mode left it on")
	}
}

// TestTheTwoNamesForLiteModeMustAgree covers the unprefixed alias.
//
// LITE_MODE used to win silently over N0PASSTEMPS_FEATURES_LITE_MODE, so a
// deployment that exported the long form as false could still start without
// role enforcement because the short form was inherited from somewhere.
func TestTheTwoNamesForLiteModeMustAgree(t *testing.T) {
	for _, tc := range []struct {
		name     string
		short    string
		prefixed string
		refuse   []string
		lite     bool
	}{
		{name: "both on", short: "true", prefixed: "true", lite: true},
		{name: "both off", short: "false", prefixed: "false", lite: false},
		{name: "the long form exported empty, which counts as unset", short: "true", prefixed: "", lite: true},
		{
			name: "short on, long off", short: "true", prefixed: "false",
			refuse: []string{
				"LITE_MODE is true but N0PASSTEMPS_FEATURES_LITE_MODE is false",
				"unset the one that was not meant",
			},
		},
		{
			name: "short off, long on", short: "false", prefixed: "true",
			refuse: []string{"LITE_MODE is false but N0PASSTEMPS_FEATURES_LITE_MODE is true"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setMinimalEnv(t)
			t.Setenv("LITE_MODE", tc.short)
			t.Setenv(EnvPrefix+"FEATURES_LITE_MODE", tc.prefixed)

			cfg, err := Load("")
			if len(tc.refuse) == 0 {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if cfg.Features.LiteMode != tc.lite {
					t.Errorf("features.lite_mode = %t, want %t", cfg.Features.LiteMode, tc.lite)
				}
				return
			}
			if err == nil {
				t.Fatal("two contradictory names for one setting were accepted")
			}
			for _, want := range tc.refuse {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %q:\n%v", want, err)
				}
			}
		})
	}
}
