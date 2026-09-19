package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// webAuthnConfig is a configuration that is valid apart from whatever the test
// changes, so a refusal is attributable to the setting under test.
func webAuthnConfig(origins ...string) Config {
	cfg := Default()
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.Origins = origins
	if len(origins) == 0 {
		cfg.WebAuthn.Origins = []string{"https://app.example.com"}
	}
	return cfg
}

// refusedFor reports whether validation failed and named the setting.
func refusedFor(t *testing.T, cfg Config, key string) (bool, error) {
	t.Helper()
	err := cfg.Validate()
	return err != nil && strings.Contains(err.Error(), key), err
}

// TestRequiringAttestationWithoutAMetadataBlobIsRefused closes the gap between
// what the setting promises and what it could check.
//
// Verifying an attestation statement means checking a certificate chain against
// trust anchors, and the only anchors this service has are the ones in a
// metadata BLOB. With none loaded the library's VerifyAttestation returns as
// soon as the statement is internally consistent, so software that mints its
// own attestation certificate and declares an allowed AAGUID in it registers
// successfully: the attestation check sees full basic attestation and the model
// check sees a permitted model. An allow list cannot stand in for the BLOB,
// because the AAGUID it matches on is a value the client declares.
func TestRequiringAttestationWithoutAMetadataBlobIsRefused(t *testing.T) {
	blob := filepath.Join(t.TempDir(), "blob.jwt")
	if err := os.WriteFile(blob, []byte("stand-in for a metadata blob"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		metadata string
		aaguids  []string
		wantOK   bool
	}{
		{
			name:     "with a metadata blob",
			metadata: blob,
			wantOK:   true,
		},
		{
			name:     "with a metadata blob and an allow list",
			metadata: blob,
			aaguids:  []string{"ee882879-721c-4913-9775-3dfcce97072a"},
			wantOK:   true,
		},
		{
			name:    "with an allow list and nothing to verify against",
			aaguids: []string{"ee882879-721c-4913-9775-3dfcce97072a"},
		},
		{
			name: "with neither",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := webAuthnConfig()
			cfg.WebAuthn.RequireAttestation = true
			cfg.WebAuthn.AttestationPreference = "direct"
			cfg.WebAuthn.MetadataPath = tc.metadata
			cfg.WebAuthn.AllowedAAGUIDs = tc.aaguids

			refused, err := refusedFor(t, cfg, "webauthn.require_attestation")
			if tc.wantOK && refused {
				t.Fatalf("a configuration with a metadata blob was refused: %v", err)
			}
			if !tc.wantOK && !refused {
				t.Fatalf("require_attestation was accepted with no metadata_path (err=%v): "+
					"the setting would report a check nobody made", err)
			}
			if !tc.wantOK && !strings.Contains(err.Error(), "metadata_path") {
				t.Errorf("the refusal reads %q and does not say what to set", err)
			}
		})
	}
}

// TestTheConsoleNeedsAnOriginOfItsOwnWhenThereIsMoreThanOne covers the
// ambiguity a multi-origin deployment leaves.
//
// The console and the integrating application share a relying party identifier,
// so an origin the application is served from can obtain an assertion valid
// under it. Unless the console is told which origin is its own, it would accept
// one collected anywhere the relying party serves, and the phishing resistance
// the passkey was chosen for would be absent from the surface that needs it
// most. One origin answers the question by itself; several do not.
func TestTheConsoleNeedsAnOriginOfItsOwnWhenThereIsMoreThanOne(t *testing.T) {
	const (
		app     = "https://app.example.com"
		console = "https://console.example.com"
	)

	for _, tc := range []struct {
		name      string
		origins   []string
		admin     []string
		uiEnabled bool
		wantOK    bool
	}{
		{
			name:      "one origin answers the question by itself",
			origins:   []string{app},
			uiEnabled: true,
			wantOK:    true,
		},
		{
			name:      "several origins with the console named",
			origins:   []string{app, console},
			admin:     []string{console},
			uiEnabled: true,
			wantOK:    true,
		},
		{
			name:      "several origins with the console unnamed",
			origins:   []string{app, console},
			uiEnabled: true,
		},
		{
			name:    "several origins with the interface off",
			origins: []string{app, console},
			wantOK:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := webAuthnConfig(tc.origins...)
			cfg.Admin.UIEnabled = tc.uiEnabled
			cfg.WebAuthn.AdminOrigins = tc.admin

			refused, err := refusedFor(t, cfg, "webauthn.admin_origins")
			if tc.wantOK && refused {
				t.Fatalf("a usable configuration was refused: %v", err)
			}
			if !tc.wantOK && !refused {
				t.Fatalf("the console was left with no origin of its own (err=%v)", err)
			}
		})
	}
}

// TestAConsoleOriginOutsideTheRelyingPartyIsRefused keeps the setting from
// being a way to widen the relying party rather than narrow it.
//
// An origin that does not match the relying party identifier could never
// produce a response this service accepts, so naming one here is a mistake the
// operator wants to hear about at start rather than at the first sign-in.
func TestAConsoleOriginOutsideTheRelyingPartyIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		wantOK bool
	}{
		{"an origin under the relying party", "https://console.example.com", true},
		{"the relying party itself", "https://example.com", true},
		{"a lookalike outside it", "https://example.com.evil.test", false},
		{"not an origin at all", "console.example.com/admin", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := webAuthnConfig("https://app.example.com", tc.origin)
			cfg.Admin.UIEnabled = true
			cfg.WebAuthn.AdminOrigins = []string{tc.origin}

			refused, err := refusedFor(t, cfg, "webauthn.admin_origins")
			if tc.wantOK && refused {
				t.Fatalf("console origin %q was refused: %v", tc.origin, err)
			}
			if !tc.wantOK && !refused {
				t.Fatalf("console origin %q was accepted (err=%v)", tc.origin, err)
			}
		})
	}
}

// TestSignCountRegressionRefusalIsOffByDefault pins the default, because the
// setting changes who can sign in and a deployment that did not ask for that
// must not get it.
func TestSignCountRegressionRefusalIsOffByDefault(t *testing.T) {
	if Default().WebAuthn.RefuseSignCountRegression {
		t.Error("webauthn.refuse_sign_count_regression is on by default, which locks out a " +
			"user whose authenticator was restored from a backup")
	}
}
