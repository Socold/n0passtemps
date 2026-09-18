package config

import (
	"strings"
	"testing"
)

// TestRetiredPublicKeyPathsAreChecked pins the mistakes that would leave a
// rotation half done.
//
// Each one is refused at startup rather than at the JWKS route, because the
// symptom there is a document holding one key fewer than the operator wrote,
// which nobody inspects until an assertion is refused somewhere else.
func TestRetiredPublicKeyPathsAreChecked(t *testing.T) {
	const signing = "/etc/n0passtemps/kek/assertion-key.pem"

	for _, tc := range []struct {
		name  string
		paths []string
		want  string
	}{
		{"none, which is the normal case", nil, ""},
		{"one retired key", []string{"/etc/n0passtemps/kek/assertion-key.prev.pub.pem"}, ""},
		{
			"two retired keys, which a second rotation inside one window produces",
			[]string{"/etc/n0passtemps/kek/a.pub.pem", "/etc/n0passtemps/kek/b.pub.pem"},
			"",
		},
		{"an empty entry", []string{""}, "retired_public_key_paths[0] is empty"},
		{
			"the signing key, which is the file rotated rather than the one retired",
			[]string{signing},
			"is the signing key path",
		},
		{
			"the same path twice",
			[]string{"/etc/n0passtemps/kek/a.pub.pem", "/etc/n0passtemps/kek/a.pub.pem"},
			"repeats",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WebAuthn.RPID = "example.com"
			cfg.WebAuthn.Origins = []string{"https://example.com"}
			cfg.Assertion.SigningKeyPath = signing
			cfg.Assertion.RetiredPublicKeyPaths = tc.paths

			err := cfg.Validate()
			mentioned := err != nil && strings.Contains(err.Error(), "retired_public_key_paths")
			if tc.want == "" {
				if mentioned {
					t.Fatalf("configuration was refused: %v", err)
				}
				return
			}
			if !mentioned {
				t.Fatalf("configuration was accepted, want a complaint about %q (err: %v)", tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestRetiredPublicKeyPathsComeFromTheEnvironment(t *testing.T) {
	if len(Default().Assertion.RetiredPublicKeyPaths) != 0 {
		t.Error("a default deployment publishes a retired key, which it must not")
	}
	if !knownEnvKeysForTest()[EnvPrefix+"ASSERTION_RETIRED_PUBLIC_KEY_PATHS"] {
		t.Errorf("%sASSERTION_RETIRED_PUBLIC_KEY_PATHS is not read from the environment", EnvPrefix)
	}
}
