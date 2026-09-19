package logging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/config"
)

const (
	testRef = "alice@example.org"
	testIP  = "192.0.2.10"
)

// logLine runs fn against a JSON logger and returns the single record it
// produced, both parsed and raw. The raw form matters: a value can be absent
// from the key it belongs to and still present elsewhere on the line.
func logLine(t *testing.T, cfg config.Logging, fn func(l *slog.Logger)) (rec map[string]any, raw string) {
	t.Helper()
	var buf bytes.Buffer
	fn(New(cfg, &buf))

	raw = buf.String()
	if strings.Count(raw, "\n") != 1 {
		t.Fatalf("expected one log line, got %q", raw)
	}
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, raw)
	}
	return rec, raw
}

func TestSubjectRefRedaction(t *testing.T) {
	fingerprintRE := regexp.MustCompile(`^ref:[0-9a-f]{12}$`)

	t.Run("redacted when enabled", func(t *testing.T) {
		rec, raw := logLine(t, config.Logging{RedactSubjectRefs: true}, func(l *slog.Logger) {
			l.Info("assertion", slog.String(KeySubjectRef, testRef), slog.String(KeySubjectID, "sub-1"))
		})

		got, _ := rec[KeySubjectRef].(string)
		if !fingerprintRE.MatchString(got) {
			t.Errorf("subject_ref = %q, want a ref: fingerprint", got)
		}
		if got != Fingerprint(testRef) {
			t.Errorf("subject_ref = %q, want %q: two lines about one person must correlate", got, Fingerprint(testRef))
		}
		if strings.Contains(raw, testRef) || strings.Contains(raw, "alice") {
			t.Errorf("the reference reached the log line although redaction is on: %s", raw)
		}
		if rec[KeySubjectID] != "sub-1" {
			t.Errorf("subject_id = %v: redaction disturbed an unrelated attribute", rec[KeySubjectID])
		}
	})

	t.Run("left alone when disabled", func(t *testing.T) {
		rec, _ := logLine(t, config.Logging{RedactSubjectRefs: false}, func(l *slog.Logger) {
			l.Info("assertion", slog.String(KeySubjectRef, testRef))
		})
		if rec[KeySubjectRef] != testRef {
			t.Errorf("subject_ref = %v, want the reference unchanged: the operator chose to log it", rec[KeySubjectRef])
		}
	})

	// The policy lives in the handler so that no call site can bypass it by
	// the way it happens to attach the attribute.
	paths := []struct {
		name string
		log  func(l *slog.Logger)
	}{
		{"attribute bound with With", func(l *slog.Logger) {
			l.With(slog.String(KeySubjectRef, testRef)).Info("assertion")
		}},
		{"attribute inside a group", func(l *slog.Logger) {
			l.Info("assertion", slog.Group("request", slog.String(KeySubjectRef, testRef)))
		}},
		{"attribute under WithGroup", func(l *slog.Logger) {
			l.WithGroup("request").Info("assertion", slog.String(KeySubjectRef, testRef))
		}},
		{"loosely typed key and value", func(l *slog.Logger) {
			l.Info("assertion", KeySubjectRef, testRef)
		}},
		{"text format", nil},
	}
	for _, tc := range paths {
		t.Run("redacted: "+tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := config.Logging{RedactSubjectRefs: true}
			if tc.log == nil {
				cfg.Format = "text"
				New(cfg, &buf).Info("assertion", slog.String(KeySubjectRef, testRef))
			} else {
				tc.log(New(cfg, &buf))
			}
			if strings.Contains(buf.String(), testRef) {
				t.Errorf("the reference reached the log line: %s", buf.String())
			}
			if !strings.Contains(buf.String(), Fingerprint(testRef)) {
				t.Errorf("the fingerprint is missing, so the line cannot be correlated: %s", buf.String())
			}
		})
	}

	t.Run("empty reference stays empty", func(t *testing.T) {
		// A fingerprint of the empty string would look like a real subject.
		rec, _ := logLine(t, config.Logging{RedactSubjectRefs: true}, func(l *slog.Logger) {
			l.Info("assertion", slog.String(KeySubjectRef, ""))
		})
		if got := rec[KeySubjectRef]; got != "" {
			t.Errorf("subject_ref = %v, want empty", got)
		}
	})
}

func TestSourceIPPolicy(t *testing.T) {
	t.Run("dropped when not included", func(t *testing.T) {
		rec, raw := logLine(t, config.Logging{IncludeSourceIP: false}, func(l *slog.Logger) {
			l.Info("request", slog.String(KeySourceIP, testIP), slog.String(KeyRoute, "/v1/assert"))
		})
		if _, present := rec[KeySourceIP]; present {
			t.Errorf("source_ip key is present with value %v: an address is personal data and the operator did not opt in", rec[KeySourceIP])
		}
		if strings.Contains(raw, testIP) {
			t.Errorf("the address reached the log line: %s", raw)
		}
		if rec[KeyRoute] != "/v1/assert" {
			t.Errorf("route = %v: dropping the address disturbed an unrelated attribute", rec[KeyRoute])
		}
	})

	t.Run("dropped when bound with With", func(t *testing.T) {
		_, raw := logLine(t, config.Logging{IncludeSourceIP: false}, func(l *slog.Logger) {
			l.With(slog.String(KeySourceIP, testIP)).Info("request")
		})
		if strings.Contains(raw, testIP) {
			t.Errorf("the address reached the log line through With: %s", raw)
		}
	})

	t.Run("kept when included", func(t *testing.T) {
		rec, _ := logLine(t, config.Logging{IncludeSourceIP: true}, func(l *slog.Logger) {
			l.Info("request", slog.String(KeySourceIP, testIP))
		})
		if rec[KeySourceIP] != testIP {
			t.Errorf("source_ip = %v, want %s", rec[KeySourceIP], testIP)
		}
	})
}

func TestSecret(t *testing.T) {
	const value = "hunter2-do-not-log"
	s := Secret(value)

	t.Run("slog attribute", func(t *testing.T) {
		rec, raw := logLine(t, config.Logging{}, func(l *slog.Logger) {
			l.Info("config", slog.Any("token", s))
		})
		if rec["token"] != Redacted {
			t.Errorf("token = %v, want %s", rec["token"], Redacted)
		}
		if strings.Contains(raw, value) {
			t.Errorf("the secret reached the log line: %s", raw)
		}
	})

	t.Run("slog attribute inside a group", func(t *testing.T) {
		_, raw := logLine(t, config.Logging{}, func(l *slog.Logger) {
			l.Info("config", slog.Group("kek", slog.Any("token", s)))
		})
		if strings.Contains(raw, value) {
			t.Errorf("the secret reached the log line: %s", raw)
		}
		if !strings.Contains(raw, Redacted) {
			t.Errorf("the placeholder is missing: %s", raw)
		}
	})

	t.Run("slog text format", func(t *testing.T) {
		var buf bytes.Buffer
		New(config.Logging{Format: "text"}, &buf).Info("config", slog.Any("token", s))
		if strings.Contains(buf.String(), value) {
			t.Errorf("the secret reached the log line: %s", buf.String())
		}
	})

	verbs := []struct {
		format string
		want   string
	}{
		{"%s", Redacted},
		{"%v", Redacted},
		{"%+v", Redacted},
		{"%#v", Redacted},
		{"%q", `"` + Redacted + `"`},
	}
	for _, tc := range verbs {
		t.Run("fmt "+tc.format, func(t *testing.T) {
			got := fmt.Sprintf(tc.format, s)
			if got != tc.want {
				t.Errorf("Sprintf(%q) = %q, want %q", tc.format, got, tc.want)
			}
			if strings.Contains(got, value) {
				t.Errorf("Sprintf(%q) disclosed the secret", tc.format)
			}
		})
	}

	t.Run("fmt of a struct holding a secret", func(t *testing.T) {
		// This is the case the type exists for: a configuration struct
		// formatted wholesale into an error or a debug line.
		holder := struct {
			Name  string
			Token Secret
		}{"kek", s}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, holder); strings.Contains(got, value) {
				t.Errorf("Sprintf(%q) of a struct disclosed the secret: %s", format, got)
			}
		}
	})

	t.Run("fmt.Sprint of an interface value", func(t *testing.T) {
		var v any = s
		if got := fmt.Sprint(v); got != Redacted {
			t.Errorf("Sprint = %q, want %s", got, Redacted)
		}
	})

	t.Run("the value stays usable by code that needs it", func(t *testing.T) {
		if string(s) != value {
			t.Error("an explicit conversion no longer yields the secret, so nothing could ever use it")
		}
	})
}

func TestFingerprint(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		if Fingerprint(testRef) != Fingerprint(testRef) {
			t.Error("the same input gave two fingerprints: log lines about one person could not be correlated")
		}
	})

	t.Run("differs per input", func(t *testing.T) {
		inputs := []string{testRef, "bob@example.org", "Alice@example.org", testRef + " ", "a"}
		seen := map[string]string{}
		for _, in := range inputs {
			fp := Fingerprint(in)
			if prev, dup := seen[fp]; dup {
				t.Errorf("%q and %q share fingerprint %s", prev, in, fp)
			}
			seen[fp] = in
		}
	})

	t.Run("empty for empty input", func(t *testing.T) {
		if got := Fingerprint(""); got != "" {
			t.Errorf("Fingerprint(\"\") = %q, want empty: an absent reference must not look like a person", got)
		}
	})

	t.Run("shape", func(t *testing.T) {
		got := Fingerprint(testRef)
		if !regexp.MustCompile(`^ref:[0-9a-f]{12}$`).MatchString(got) {
			t.Errorf("fingerprint = %q, want ref: followed by 12 hex characters", got)
		}
		if strings.Contains(got, "alice") || strings.Contains(got, "example") {
			t.Errorf("fingerprint %q carries part of its input", got)
		}
	})

	t.Run("is domain separated", func(t *testing.T) {
		// A bare SHA-256 prefix could be looked up in any precomputed table of
		// hashed email addresses.
		sum := sha256.Sum256([]byte(testRef))
		bare := fmt.Sprintf("ref:%x", sum[:6])
		if Fingerprint(testRef) == bare {
			t.Error("the fingerprint is the bare SHA-256 prefix of the reference")
		}
	})
}

func TestFromContext(t *testing.T) {
	t.Run("returns the attached logger", func(t *testing.T) {
		l := slog.New(slog.NewJSONHandler(io.Discard, nil))
		if got := FromContext(WithLogger(context.Background(), l)); got != l {
			t.Error("FromContext did not return the logger that was attached: request-scoped attributes such as the request id would be lost")
		}
	})

	t.Run("falls back to the default", func(t *testing.T) {
		got := FromContext(context.Background())
		if got == nil {
			t.Fatal("FromContext returned nil: the first log call on the request path would panic")
		}
		if got != slog.Default() {
			t.Error("FromContext did not fall back to slog.Default")
		}
	})

	t.Run("a nil logger in the context falls back to the default", func(t *testing.T) {
		if got := FromContext(WithLogger(context.Background(), nil)); got == nil {
			t.Fatal("FromContext returned the nil logger it was given")
		}
	})
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"Warn", slog.LevelWarn},
		{"error", slog.LevelError},
		// An unrecognised value must not silence the log, nor turn on debug
		// output that the operator did not ask for.
		{"", slog.LevelInfo},
		{"verbose", slog.LevelInfo},
		{"warning", slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run("level "+tc.in, func(t *testing.T) {
			if got := parseLevel(tc.in); got != tc.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	t.Run("the level is enforced by the logger", func(t *testing.T) {
		var buf bytes.Buffer
		l := New(config.Logging{Level: "warn"}, &buf)
		l.Info("dropped")
		l.Debug("dropped")
		if buf.Len() != 0 {
			t.Errorf("records below the configured level were written: %s", buf.String())
		}
		l.Warn("kept")
		if !strings.Contains(buf.String(), "kept") {
			t.Error("a record at the configured level was not written")
		}
	})
}
