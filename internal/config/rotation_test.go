package config

import (
	"strings"
	"testing"
	"time"
)

// TestRotationGraceIsBounded pins the limits on the default overlap.
//
// The bound is what keeps rotation from turning back into the problem it
// replaces: an operator who sets a month-long grace has two live credentials
// and a reminder nobody will act on, and should be told so at start rather
// than discover it in an incident.
func TestRotationGraceIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		grace  time.Duration
		wantOK bool
	}{
		{"the default", Default().Features.RotationGrace.Duration, true},
		{"zero stops the predecessor at once", 0, true},
		{"exactly the maximum", MaxRotationGrace, true},
		{"one second above the maximum", MaxRotationGrace + time.Second, false},
		{"negative", -time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WebAuthn.RPID = "example.com"
			cfg.WebAuthn.Origins = []string{"https://example.com"}
			cfg.Features.RotationGrace = Duration{tc.grace}

			err := cfg.Validate()
			refused := err != nil && strings.Contains(err.Error(), "features.rotation_grace")
			if tc.wantOK && refused {
				t.Errorf("rotation_grace %s was refused: %v", tc.grace, err)
			}
			if !tc.wantOK && !refused {
				t.Errorf("rotation_grace %s was accepted", tc.grace)
			}
		})
	}
}

func TestRotationGraceDefaultAndEnvironment(t *testing.T) {
	if got := Default().Features.RotationGrace.Duration; got != 24*time.Hour {
		t.Errorf("default rotation_grace = %s, want 24h", got)
	}
	if !knownEnvKeysForTest()[EnvPrefix+"FEATURES_ROTATION_GRACE"] {
		t.Errorf("%sFEATURES_ROTATION_GRACE is not read from the environment", EnvPrefix)
	}
}
