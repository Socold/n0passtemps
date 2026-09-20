package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validSinkBase is the shipped default with the two keys every Validate call
// needs, so that only the sink refusals show up in the error.
func validSinkBase() Config {
	cfg := Default()
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.Origins = []string{"https://example.com"}
	return cfg
}

// sinkConfig is that base with a valid external sink, so each case below
// changes one thing and asserts what that one thing costs.
func sinkConfig(t *testing.T) *Config {
	t.Helper()
	cfg := validSinkBase()
	cfg.Audit.Sink.Endpoint = "https://witness.example.org/v1/audit"
	cfg.Audit.Sink.ReceiverOutsideOperatorControl = true
	return &cfg
}

func TestTheSinkIsOffByDefault(t *testing.T) {
	// Offline by default is this product's whole argument, so the default
	// configuration must make no outbound connection possible at all.
	cfg := Default()
	if cfg.Audit.Sink.Enabled() {
		t.Error("the default configuration has an audit sink endpoint")
	}
	if got := cfg.Audit.Sink.Endpoint; got != "" {
		t.Errorf("default endpoint = %q, want empty", got)
	}
}

func TestAnUnconfiguredSinkIsNotValidated(t *testing.T) {
	// With no endpoint the section is never read, so refusing a deployment for
	// the shape of it would be refusing it for nothing.
	cfg := validSinkBase()
	cfg.Audit.Sink.BufferSize = 0
	cfg.Audit.Sink.BatchSize = -1
	cfg.Audit.Sink.FlushInterval = Duration{}
	if err := cfg.Validate(); err != nil {
		t.Errorf("an unconfigured sink was validated: %v", err)
	}
}

func TestAValidSinkIsAccepted(t *testing.T) {
	if err := sinkConfig(t).Validate(); err != nil {
		t.Errorf("a valid sink was refused: %v", err)
	}
}

func TestTheTrustAssumptionMustBeDeclared(t *testing.T) {
	// The declaration is the point of the section. A sink the operator can
	// rewrite falls to exactly the attacker the hash chain already fails to
	// stop, so it is worthless rather than merely weaker, and this service
	// cannot check which kind it has been given.
	cfg := sinkConfig(t)
	cfg.Audit.Sink.ReceiverOutsideOperatorControl = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("an endpoint was accepted without the trust declaration")
	}
	if !strings.Contains(err.Error(), "receiver_outside_operator_control") {
		t.Errorf("the error does not name the setting: %v", err)
	}
}

func TestACredentialVariableIsRequired(t *testing.T) {
	cfg := sinkConfig(t)
	cfg.Audit.Sink.TokenEnv = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Errorf("an endpoint with no credential variable gave %v", err)
	}
}

func TestPlainHTTPIsRefusedExceptTowardsLoopback(t *testing.T) {
	cases := []struct {
		endpoint string
		accepted bool
	}{
		{"https://witness.example.org/audit", true},
		{"http://127.0.0.1:9000/audit", true},
		{"http://localhost:9000/audit", true},
		{"http://[::1]:9000/audit", true},
		// A bearer credential and the shape of a deployment's audit history
		// must not cross a network in clear.
		{"http://witness.example.org/audit", false},
		{"ftp://witness.example.org/audit", false},
		{"https:///audit", false},
		{"not a url at all", false},
	}

	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			cfg := sinkConfig(t)
			cfg.Audit.Sink.Endpoint = tc.endpoint
			err := cfg.Validate()
			if tc.accepted && err != nil {
				t.Errorf("%s was refused: %v", tc.endpoint, err)
			}
			if !tc.accepted && err == nil {
				t.Errorf("%s was accepted", tc.endpoint)
			}
		})
	}
}

func TestTheSinkSizesAreBounded(t *testing.T) {
	cases := []struct {
		name string
		edit func(*AuditSink)
		want string
	}{
		{"a buffer of nothing", func(s *AuditSink) { s.BufferSize = 0 }, "buffer_size"},
		{"a batch of nothing", func(s *AuditSink) { s.BatchSize = 0 }, "batch_size"},
		{"a batch the buffer cannot hold", func(s *AuditSink) {
			s.BufferSize = 4
			s.BatchSize = 8
		}, "cannot exceed buffer_size"},
		{"no flush interval", func(s *AuditSink) { s.FlushInterval = Duration{} }, "flush_interval"},
		{"no timeout", func(s *AuditSink) { s.Timeout = Duration{} }, "timeout"},
		{"no backoff", func(s *AuditSink) { s.RetryBackoff = Duration{} }, "retry_backoff"},
		{"a ceiling below the first pause", func(s *AuditSink) {
			s.RetryBackoff = Duration{time.Minute}
			s.MaxRetryBackoff = Duration{time.Second}
		}, "max_retry_backoff"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sinkConfig(t)
			tc.edit(&cfg.Audit.Sink)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

func TestTheWatermarkDefaultsIntoTheDataDirectory(t *testing.T) {
	cfg := sinkConfig(t)
	cfg.Database.DataDir = filepath.Join("var", "lib", "n0passtemps")

	// It is state that has to survive a restart on the same volume, which is
	// what the data directory already is.
	want := filepath.Join("var", "lib", "n0passtemps", "audit-sink.watermark")
	if got := cfg.AuditSinkWatermarkPath(); got != want {
		t.Errorf("watermark path = %q, want %q", got, want)
	}

	cfg.Audit.Sink.WatermarkPath = filepath.Join("elsewhere", "mark")
	if got := cfg.AuditSinkWatermarkPath(); got != filepath.Join("elsewhere", "mark") {
		t.Errorf("an explicit watermark path was not honoured, got %q", got)
	}
}

func TestTheSinkReadsItsEnvironmentOverrides(t *testing.T) {
	t.Setenv(EnvPrefix+"AUDIT_SINK_ENDPOINT", "https://witness.example.org/audit")
	t.Setenv(EnvPrefix+"AUDIT_SINK_RECEIVER_OUTSIDE_OPERATOR_CONTROL", "true")
	t.Setenv(EnvPrefix+"AUDIT_SINK_TOKEN_ENV", "WITNESS_TOKEN")
	t.Setenv(EnvPrefix+"AUDIT_SINK_BUFFER_SIZE", "2048")
	t.Setenv(EnvPrefix+"AUDIT_SINK_BATCH_SIZE", "256")
	t.Setenv(EnvPrefix+"AUDIT_SINK_FLUSH_INTERVAL", "2s")
	t.Setenv(EnvPrefix+"AUDIT_SINK_TIMEOUT", "15s")
	t.Setenv(EnvPrefix+"AUDIT_SINK_RETRY_BACKOFF", "2s")
	t.Setenv(EnvPrefix+"AUDIT_SINK_MAX_RETRY_BACKOFF", "10m")
	t.Setenv(EnvPrefix+"AUDIT_SINK_WATERMARK_PATH", "/srv/state/mark")

	cfg := Default()
	if err := applyEnv(&cfg); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}

	s := cfg.Audit.Sink
	if s.Endpoint != "https://witness.example.org/audit" {
		t.Errorf("endpoint = %q", s.Endpoint)
	}
	if !s.ReceiverOutsideOperatorControl {
		t.Error("the trust declaration was not read from the environment")
	}
	if s.TokenEnv != "WITNESS_TOKEN" {
		t.Errorf("token_env = %q", s.TokenEnv)
	}
	if s.BufferSize != 2048 || s.BatchSize != 256 {
		t.Errorf("buffer_size = %d and batch_size = %d", s.BufferSize, s.BatchSize)
	}
	if s.FlushInterval.Duration != 2*time.Second || s.Timeout.Duration != 15*time.Second {
		t.Errorf("flush_interval = %s and timeout = %s", s.FlushInterval.Duration, s.Timeout.Duration)
	}
	if s.RetryBackoff.Duration != 2*time.Second || s.MaxRetryBackoff.Duration != 10*time.Minute {
		t.Errorf("retry_backoff = %s and max_retry_backoff = %s",
			s.RetryBackoff.Duration, s.MaxRetryBackoff.Duration)
	}
	if s.WatermarkPath != "/srv/state/mark" {
		t.Errorf("watermark_path = %q", s.WatermarkPath)
	}
}
