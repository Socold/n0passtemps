package config

import (
	"strings"
	"testing"
	"time"
)

// validRiskConfig is the shipped default with the two keys every Validate call
// needs, so that only the risk refusals show up in the error.
func validRiskConfig() Config {
	cfg := Default()
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.Origins = []string{"https://example.com"}
	return cfg
}

// TestRiskValidationRefusesAPolicyThatCannotWork covers every refusal in the
// section.
//
// A misconfigured risk policy cannot lock anyone out, since the service never
// refuses on risk, so every one of these would run quietly in production and
// report the wrong thing for as long as nobody checked. That is exactly why
// they are refused at startup instead.
func TestRiskValidationRefusesAPolicyThatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tune   func(*Config)
		refuse string
	}{
		{"the default", func(*Config) {}, ""},
		{
			name:   "thresholds the wrong way round",
			tune:   func(c *Config) { c.Risk.ElevatedAt, c.Risk.HighAt = 40, 20 },
			refuse: "must be below risk.high_at",
		},
		{
			name:   "thresholds equal, which leaves elevated unreachable",
			tune:   func(c *Config) { c.Risk.ElevatedAt, c.Risk.HighAt = 30, 30 },
			refuse: "must be below risk.high_at",
		},
		{
			name:   "elevated_at at zero, which reports a clean ceremony as elevated",
			tune:   func(c *Config) { c.Risk.ElevatedAt = 0 },
			refuse: "risk.elevated_at must be at least 1",
		},
		{
			name:   "a negative elevated_at",
			tune:   func(c *Config) { c.Risk.ElevatedAt = -5 },
			refuse: "risk.elevated_at must be at least 1",
		},
		{
			name:   "high_at at zero",
			tune:   func(c *Config) { c.Risk.HighAt = 0 },
			refuse: "risk.high_at must be at least 1",
		},
		{
			name:   "a zero dormancy window, which makes every credential dormant",
			tune:   func(c *Config) { c.Risk.DormantAfter = Duration{} },
			refuse: "risk.dormant_after must be positive",
		},
		{
			name:   "a negative dormancy window",
			tune:   func(c *Config) { c.Risk.DormantAfter = Duration{-time.Hour} },
			refuse: "risk.dormant_after must be positive",
		},
		{
			name:   "a zero newness window, which makes no credential new",
			tune:   func(c *Config) { c.Risk.NewCredentialWithin = Duration{} },
			refuse: "risk.new_credential_within must be positive",
		},
		{
			name: "a misspelled reason in the weight table",
			tune: func(c *Config) {
				c.Risk.Weights = map[string]int{"recovery_codes_used": 30}
			},
			refuse: `risk.weights has no reason "recovery_codes_used"`,
		},
		{
			name: "a reason that was never declared",
			tune: func(c *Config) {
				c.Risk.Weights = map[string]int{"impossible_travel": 30}
			},
			refuse: "risk.weights has no reason",
		},
		{
			name: "a negative weight",
			tune: func(c *Config) {
				c.Risk.Weights = map[string]int{"totp_only": -10}
			},
			refuse: "risk.weights.totp_only is -10",
		},
		{
			name: "a weight of zero, which silences one signal deliberately",
			tune: func(c *Config) {
				c.Risk.Weights = map[string]int{"credential_dormant": 0}
			},
			refuse: "",
		},
		{
			name: "every declared reason overridden",
			tune: func(c *Config) {
				c.Risk.Weights = map[string]int{}
				for _, reason := range RiskReasons {
					c.Risk.Weights[reason] = 7
				}
			},
			refuse: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validRiskConfig()
			tc.tune(&cfg)

			err := cfg.Validate()
			switch {
			case tc.refuse == "" && err != nil:
				t.Errorf("a workable policy was refused: %v", err)
			case tc.refuse == "":
			case err == nil:
				t.Errorf("the policy was accepted; expected a refusal mentioning %q", tc.refuse)
			case !strings.Contains(err.Error(), tc.refuse):
				t.Errorf("refusal does not mention %q: %v", tc.refuse, err)
			}
		})
	}
}

// TestRiskIsValidatedEvenWhenDisabled checks that turning reporting off does
// not park an unworkable policy in the file.
//
// Otherwise a file that loads today would refuse to load on the day somebody
// sets enabled = true, which is the worst moment to discover it.
func TestRiskIsValidatedEvenWhenDisabled(t *testing.T) {
	cfg := validRiskConfig()
	cfg.Risk.Enabled = false
	cfg.Risk.ElevatedAt, cfg.Risk.HighAt = 40, 20

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be below risk.high_at") {
		t.Errorf("an unworkable policy was accepted because reporting is off: %v", err)
	}
}

// TestRiskScalarsComeFromTheEnvironmentAndTheWeightsDoNot pins the split.
//
// The weights are the policy, so they belong in the reviewed file. A flat
// environment namespace would need one variable per reason, which is a second
// copy of a closed set and so a second place for it to drift.
func TestRiskScalarsComeFromTheEnvironmentAndTheWeightsDoNot(t *testing.T) {
	known := knownEnvKeysForTest()
	for _, key := range []string{
		EnvPrefix + "RISK_ENABLED",
		EnvPrefix + "RISK_ELEVATED_AT",
		EnvPrefix + "RISK_HIGH_AT",
		EnvPrefix + "RISK_DORMANT_AFTER",
		EnvPrefix + "RISK_NEW_CREDENTIAL_WITHIN",
	} {
		if !known[key] {
			t.Errorf("%s is not read from the environment", key)
		}
	}
	for _, reason := range RiskReasons {
		key := EnvPrefix + "RISK_WEIGHTS_" + strings.ToUpper(reason)
		if known[key] {
			t.Errorf("%s is read from the environment; the weight table is file-only", key)
		}
	}
}

// TestRiskEnvironmentOverridesApply checks the scalars actually land.
func TestRiskEnvironmentOverridesApply(t *testing.T) {
	t.Setenv(EnvPrefix+"SUBJECT_PEPPER", strings.Repeat("a", 44))
	t.Setenv(EnvPrefix+"RISK_ENABLED", "false")
	t.Setenv(EnvPrefix+"RISK_ELEVATED_AT", "15")
	t.Setenv(EnvPrefix+"RISK_HIGH_AT", "35")
	t.Setenv(EnvPrefix+"RISK_DORMANT_AFTER", "720h")
	t.Setenv(EnvPrefix+"RISK_NEW_CREDENTIAL_WITHIN", "30m")

	cfg := Default()
	if err := applyEnv(&cfg); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}
	if cfg.Risk.Enabled {
		t.Error("RISK_ENABLED=false did not turn reporting off")
	}
	if cfg.Risk.ElevatedAt != 15 || cfg.Risk.HighAt != 35 {
		t.Errorf("thresholds = %d and %d, want 15 and 35", cfg.Risk.ElevatedAt, cfg.Risk.HighAt)
	}
	if cfg.Risk.DormantAfter.Duration != 720*time.Hour {
		t.Errorf("dormant_after = %s, want 720h", cfg.Risk.DormantAfter.Duration)
	}
	if cfg.Risk.NewCredentialWithin.Duration != 30*time.Minute {
		t.Errorf("new_credential_within = %s, want 30m", cfg.Risk.NewCredentialWithin.Duration)
	}
}

// TestRiskReasonsIsANonEmptyClosedSet guards the list Validate checks against.
//
// It is the copy of internal/risk's reason set that this package needs in order
// to refuse an unknown weight key without importing the package that reads this
// configuration. internal/risk asserts the two are equal; this only checks the
// list here is usable at all, so that an accidentally emptied slice does not
// make the refusal above accept everything.
func TestRiskReasonsIsANonEmptyClosedSet(t *testing.T) {
	if len(RiskReasons) == 0 {
		t.Fatal("RiskReasons is empty, so every weight key would be refused")
	}
	seen := map[string]bool{}
	for _, reason := range RiskReasons {
		if reason == "" {
			t.Error("RiskReasons contains an empty entry")
		}
		if seen[reason] {
			t.Errorf("RiskReasons lists %q twice", reason)
		}
		seen[reason] = true
	}
}
