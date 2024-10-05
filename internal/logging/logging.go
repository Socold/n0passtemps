// Package logging configures structured output.
//
// Logs go to standard output as JSON by default, because they are meant to be
// ingested by whatever the operator already runs rather than read by a person.
// There is no log file and no rotation: writing to standard output and letting
// the supervisor handle the rest is what both systemd and every container
// runtime expect.
//
// # Redaction
//
// An authentication service handles two kinds of value that must not reach a
// log line. Secrets, which are never logged at all, and personal data, which is
// logged only when the operator has decided to.
//
// The reference an integrating application uses for its own user is treated as
// personal data. The documentation asks for an opaque identifier, and
// applications supply email addresses anyway, so redaction is on by default and
// the reference is replaced by a short prefix of its HMAC. That prefix is enough
// to correlate two log lines about the same person without disclosing who they
// are.
package logging

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/Socold/n0passtemps/internal/config"
)

// Attribute keys used across the service. They are constants so a query
// written against one log line works against all of them.
const (
	KeyRequestID  = "request_id"
	KeySubjectID  = "subject_id"
	KeySubjectRef = "subject_ref"
	KeyTenantID   = "tenant_id"
	KeyActorID    = "actor_id"
	KeyActorType  = "actor_type"
	KeySourceIP   = "source_ip"
	KeyEventType  = "event_type"
	KeyOutcome    = "outcome"
	KeyRoute      = "route"
	KeyMethod     = "method"
	KeyStatus     = "status"
	KeyDurationMS = "duration_ms"
	KeyCredential = "credential_id"
)

// New builds the root logger.
func New(cfg config.Logging, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:       parseLevel(cfg.Level),
		ReplaceAttr: replacer(cfg),
	}

	var h slog.Handler
	switch cfg.Format {
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// replacer enforces the redaction policy at the handler, not at the call site.
//
// Putting it here means a new call site cannot forget it. Relying on every
// caller to remember to redact is how personal data ends up in logs.
func replacer(cfg config.Logging) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case KeySubjectRef:
			if cfg.RedactSubjectRefs {
				return slog.String(KeySubjectRef, Fingerprint(a.Value.String()))
			}
		case KeySourceIP:
			if !cfg.IncludeSourceIP {
				return slog.Attr{}
			}
		}
		return a
	}
}

// Fingerprint renders a value as a short, stable, non-reversible token.
//
// It is not a security control: the input space for an email address is small
// enough that a determined holder of the logs could confirm a guess. It exists
// so that log lines about one person can be correlated without the logs
// themselves becoming a list of that service's users.
func Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := fingerprintHash(v)
	return "ref:" + hex.EncodeToString(sum[:6])
}

// Redacted is the placeholder written where a value must never appear.
const Redacted = "[redacted]"

// Secret wraps a value so that logging it yields the placeholder rather than
// the value. It exists for the cases where a struct containing a secret is
// logged wholesale.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String makes an accidental fmt.Sprintf of a Secret safe too.
func (Secret) String() string { return Redacted }

// GoString makes %#v safe.
func (Secret) GoString() string { return Redacted }

// MarshalText covers the case the type exists for: a struct holding a Secret
// logged as a whole. slog consults LogValue only for a top-level attribute
// value. A struct is handed to encoding/json by the JSON handler and rendered
// field by field by the text handler, and both honour this method, so without
// it the placeholder above protected every path except the likeliest one.
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON is explicit so the behaviour does not depend on encoding/json
// preferring MarshalText for string kinds.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

var _ fmt.Stringer = Secret("")

// contextKey is unexported so no other package can collide with it.
type contextKey struct{ name string }

var loggerKey = &contextKey{"logger"}

// WithLogger attaches a logger to the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the logger attached to the context, or the default.
//
// Returning the default rather than nil means a caller that forgets to attach
// one still logs somewhere, instead of panicking on the request path.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
