package config

import (
	"strings"
	"testing"
	"time"
)

// TestTicketTTLIsBounded pins the limits on how long an enrolment ticket lives.
//
// The lifetime is the whole window in which whoever intercepts the delivery
// channel can enrol an authenticator of their own. An operator who sets a
// week-long ticket has turned a hand-off into a standing credential, and should
// be told so at start rather than discover it in an incident.
func TestTicketTTLIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ttl    time.Duration
		wantOK bool
	}{
		{"the default", Default().Tickets.TTL.Duration, true},
		{"a very short window", time.Minute, true},
		{"exactly the maximum", 24 * time.Hour, true},
		{"one second above the maximum", 24*time.Hour + time.Second, false},
		{"zero, which no ticket could be redeemed in", 0, false},
		{"negative", -time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WebAuthn.RPID = "example.com"
			cfg.WebAuthn.Origins = []string{"https://example.com"}
			cfg.Tickets.TTL = Duration{tc.ttl}

			err := cfg.Validate()
			refused := err != nil && strings.Contains(err.Error(), "tickets.ttl")
			if tc.wantOK && refused {
				t.Errorf("tickets.ttl %s was refused: %v", tc.ttl, err)
			}
			if !tc.wantOK && !refused {
				t.Errorf("tickets.ttl %s was accepted", tc.ttl)
			}
		})
	}
}

// TestTicketDefaultsAndEnvironment pins the two defaults and checks both keys
// are actually read from the environment.
//
// The factor guard defaults to on. A ticket issued silently for an account that
// already holds a factor is an account-takeover primitive for whoever controls
// delivery, so the safe reading has to be the one an operator gets by saying
// nothing.
func TestTicketDefaultsAndEnvironment(t *testing.T) {
	d := Default()
	if got := d.Tickets.TTL.Duration; got != time.Hour {
		t.Errorf("default tickets.ttl = %s, want 1h", got)
	}
	if !d.Tickets.RequireExistingFactorDefault {
		t.Error("tickets.require_existing_factor_default is off by default, which makes " +
			"every issuance over an existing factor an unremarked override")
	}

	known := knownEnvKeysForTest()
	for _, key := range []string{
		EnvPrefix + "TICKETS_TTL",
		EnvPrefix + "TICKETS_REQUIRE_EXISTING_FACTOR_DEFAULT",
	} {
		if !known[key] {
			t.Errorf("%s is not read from the environment", key)
		}
	}
}
