package config

import (
	"strings"
	"testing"
	"time"
)

// TestThrottleSettingsThatSwitchTheProtectionOffAreRefused pins the values that
// used to load and leave a limit not enforced, with nothing in the log to say
// so.
//
// A threshold of zero reads to the limiter as a dimension with no limit. An
// operator who typed it to mean "refuse everything", or who left the key out of
// a file that set the others, got a service that counted attempts and never
// acted on the count.
func TestThrottleSettingsThatSwitchTheProtectionOffAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*Throttle)
		want string
	}{
		{"no per-key ceiling", func(th *Throttle) { th.MaxRequestsPerKey = 0 }, "throttle.max_requests_per_key"},
		{"a negative per-key ceiling", func(th *Throttle) { th.MaxRequestsPerKey = -1 },
			"throttle.max_requests_per_key"},
		{"no per-subject limit", func(th *Throttle) { th.MaxFailuresPerSubject = 0 },
			"throttle.max_failures_per_subject"},
		{"no per-address limit", func(th *Throttle) { th.MaxFailuresPerIP = 0 }, "throttle.max_failures_per_ip"},
		{"no window", func(th *Throttle) { th.Window = Duration{} }, "throttle.window"},
		{"no lockout", func(th *Throttle) { th.LockoutDuration = Duration{} }, "throttle.lockout_duration"},
		{"a negative lockout", func(th *Throttle) { th.LockoutDuration = Duration{-time.Minute} },
			"throttle.lockout_duration"},
		{"a lockout that ends inside its window", func(th *Throttle) {
			th.Window = Duration{15 * time.Minute}
			th.LockoutDuration = Duration{time.Minute}
		}, "shorter than throttle.window"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WebAuthn.RPID = "example.com"
			cfg.WebAuthn.Origins = []string{"https://example.com"}
			tc.tune(&cfg.Throttle)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// TestThrottleDefaultsAndBoundaryValuesLoad checks that the validator refuses
// only what it means to.
func TestThrottleDefaultsAndBoundaryValuesLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*Throttle)
	}{
		{"the defaults", func(*Throttle) {}},
		{"a lockout exactly as long as the window", func(th *Throttle) {
			th.Window = Duration{5 * time.Minute}
			th.LockoutDuration = Duration{5 * time.Minute}
		}},
		{"a ceiling of one", func(th *Throttle) { th.MaxRequestsPerKey = 1 }},
		{"throttling off, where none of it is read", func(th *Throttle) {
			*th = Throttle{Enabled: false}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WebAuthn.RPID = "example.com"
			cfg.WebAuthn.Origins = []string{"https://example.com"}
			tc.tune(&cfg.Throttle)

			if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "throttle.") {
				t.Errorf("Validate refused it: %v", err)
			}
		})
	}
}
