// Package alerts turns detected conditions into rows an operator can act on.
//
// There are exactly ten conditions. The list is deliberately short: an alert
// stream nobody reads is worse than no alert stream, because it creates the
// belief that someone would notice. Each condition here is either evidence of
// an attack in progress, evidence that a control has failed, or a state that
// will lock a user out if it is left alone.
//
// Repetition is collapsed by fingerprint rather than by rate limiting the
// engine. A brute-force attempt therefore produces one row with a rising
// occurrence count, which is what an operator needs to see, instead of one row
// per request, which is what buries it.
//
// Raising an alert is a side effect of a decision, never part of it. Every
// caller is expected to log the error this package returns and carry on: an
// authentication that has already been judged must not be reversed because the
// alert table refused a write.
package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/store"
)

// Type identifies one of the ten conditions.
//
// The values are dotted and match the audit event families, so an alert and the
// audit entries that explain it can be correlated by prefix.
type Type string

const (
	// TypeAuthFailureSubject reports repeated authentication failures against
	// one subject. This is the shape of a targeted guess.
	TypeAuthFailureSubject Type = "auth.failure_burst.subject"

	// TypeAuthFailureIP reports repeated authentication failures from one
	// source network, which is the shape of a spray across many accounts.
	TypeAuthFailureIP Type = "auth.failure_burst.ip"

	// TypeSignCountRegression reports an authenticator whose signature counter
	// failed to advance, the documented signal for a cloned device.
	TypeSignCountRegression Type = "webauthn.sign_count_regression"

	// TypeBulkRevocation reports revocations above the configured burst.
	// Revocation is final, so a run of them is either an incident response or
	// an attacker with an administrative token denying service.
	TypeBulkRevocation Type = "credential.bulk_revoked"

	// TypeRecoveryExhausted reports a subject with no recovery codes left.
	// They are the last way back in when every authenticator is lost.
	TypeRecoveryExhausted Type = "recovery.exhausted"

	// TypeRecoveryLow reports a subject below the configured low watermark,
	// early enough to reissue before the codes run out.
	TypeRecoveryLow Type = "recovery.low"

	// TypeAPIKeyRejected reports an unknown or revoked API key presented
	// repeatedly, which means either a leaked key being tried or a deployment
	// still running with a credential someone revoked.
	TypeAPIKeyRejected Type = "api_key.rejected"

	// TypeAdminDenied reports an administrative authorisation denial. A token
	// reaching for a permission its role does not hold is either a
	// misconfigured integration or a stolen token being explored.
	TypeAdminDenied Type = "admin.denied"

	// TypeAuditChainBroken reports the hash chain failing verification. The
	// audit log is the record every other investigation rests on, so this is
	// the one condition that is critical by itself.
	TypeAuditChainBroken Type = "audit.chain_broken"

	// TypeKEKRotationOverdue reports a key encryption key past its rotation
	// interval. Nothing is broken yet, which is why it is informational.
	TypeKEKRotationOverdue Type = "kek.rotation_overdue"
)

// spec is the fixed description of a condition.
type spec struct {
	severity store.Severity

	// summary is the default one-line summary. Convenience methods render a
	// more specific line carrying the counts; this is the fallback when a
	// caller raises the type directly without one.
	summary string
}

// specs holds the severity and summary of every condition.
//
// Severity is a property of the condition rather than of the occurrence, so it
// lives here and not in the Input. Letting a caller choose the severity would,
// over time, produce the same condition filed at three different levels.
var specs = map[Type]spec{
	TypeAuthFailureSubject: {
		severity: store.SeverityWarning,
		summary:  "Repeated authentication failures for one subject",
	},
	TypeAuthFailureIP: {
		severity: store.SeverityWarning,
		summary:  "Repeated authentication failures from one source network",
	},
	TypeSignCountRegression: {
		// A warning rather than critical: many authenticators legitimately
		// report a constant zero counter, so treating every regression as an
		// emergency would train an operator to ignore the type.
		severity: store.SeverityWarning,
		summary:  "Authenticator signature counter did not advance, the device may be cloned",
	},
	TypeBulkRevocation: {
		severity: store.SeverityWarning,
		summary:  "Credential revocations above the configured burst",
	},
	TypeRecoveryExhausted: {
		severity: store.SeverityWarning,
		summary:  "Subject has no recovery codes left",
	},
	TypeRecoveryLow: {
		severity: store.SeverityInfo,
		summary:  "Subject is running low on recovery codes",
	},
	TypeAPIKeyRejected: {
		severity: store.SeverityWarning,
		summary:  "An unknown or revoked API key is being presented repeatedly",
	},
	TypeAdminDenied: {
		severity: store.SeverityWarning,
		summary:  "An administrative token was denied a permission its role does not hold",
	},
	TypeAuditChainBroken: {
		severity: store.SeverityCritical,
		summary:  "The audit hash chain failed verification",
	},
	TypeKEKRotationOverdue: {
		severity: store.SeverityInfo,
		summary:  "The key encryption key is overdue for rotation",
	},
}

// AllTypes lists the ten conditions in the order they are declared, for the
// administrative interface and for the completeness tests.
var AllTypes = []Type{
	TypeAuthFailureSubject,
	TypeAuthFailureIP,
	TypeSignCountRegression,
	TypeBulkRevocation,
	TypeRecoveryExhausted,
	TypeRecoveryLow,
	TypeAPIKeyRejected,
	TypeAdminDenied,
	TypeAuditChainBroken,
	TypeKEKRotationOverdue,
}

// Severity returns the severity of the condition.
//
// An unknown type returns the empty severity, which no filter matches. Raise
// refuses such a type outright, so no row can ever carry it.
func (t Type) Severity() store.Severity { return specs[t].severity }

// Summary returns the default summary line for the condition.
func (t Type) Summary() string { return specs[t].summary }

// Valid reports whether t is one of the ten declared conditions.
func (t Type) Valid() bool {
	_, ok := specs[t]
	return ok
}

// String returns the type as it is persisted.
func (t Type) String() string { return string(t) }

// Input describes one occurrence.
//
// SubjectID and ResourceID are both optional, and which of them is set depends
// on the condition: a burst concerns a subject, a counter regression concerns a
// credential belonging to one, and a broken chain concerns neither.
type Input struct {
	TenantID  string
	Type      Type
	SubjectID string

	// ResourceID names the narrower thing the condition is about: a
	// credential, an API key selector, a source network, a key version.
	ResourceID string

	// Summary overrides the type's default line. Convenience methods use it to
	// carry the counts an operator would otherwise have to open the detail to
	// see.
	Summary string

	// Detail is stored as JSON for the administrative interface. It is
	// context, not identity: it takes no part in the fingerprint.
	Detail map[string]any
}

// Engine raises alerts against the store.
type Engine struct {
	store store.AlertStore
	log   *slog.Logger
	now   func() time.Time
}

// New returns an Engine.
//
// A nil logger falls back to slog.Default, and a nil clock to time.Now, which
// is the only place in this package that reads the wall clock.
func New(s store.AlertStore, log *slog.Logger, clock func() time.Time) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	return &Engine{store: s, log: log, now: clock}
}

const (
	// fingerprintDomain separates these digests from every other use of
	// SHA-256 in the service and carries a version, so the derivation can
	// change without two releases disagreeing about which rows are the same
	// condition.
	fingerprintDomain = "n0passtemps/alerts/fingerprint/v1"

	// fingerprintHexLen keeps 128 bits, enough that two distinct conditions
	// merging onto one row is not a practical concern.
	fingerprintHexLen = 32
)

// Fingerprint returns the deduplication key for in.
//
// It covers the type, the tenant and the identifiers, and nothing else.
// Including the timestamp would make every occurrence a new row, which is
// exactly the flood the fingerprint exists to collapse; including the detail
// payload would do the same, since the detail carries the counts and those
// change on every occurrence.
//
// Both identifiers take part rather than only the more specific one, so two
// credentials belonging to one subject stay two rows, and two subjects stay two
// rows even when the condition names the same resource.
func (e *Engine) Fingerprint(in Input) string {
	h := sha256.New()
	writeField(h, fingerprintDomain)
	writeField(h, string(in.Type))
	writeField(h, in.TenantID)
	writeField(h, in.SubjectID)
	writeField(h, in.ResourceID)
	return hex.EncodeToString(h.Sum(nil))[:fingerprintHexLen]
}

// writeField length-prefixes each component, so that the pair ("ab", "") and
// the pair ("a", "b") cannot produce the same digest.
func writeField(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

// Raise records one occurrence of a condition.
//
// The returned alert is the stored row, whose occurrence count and first_seen_at
// may predate this call when an unacknowledged row with the same fingerprint
// already existed.
//
// An error is both logged and returned. It is returned because a caller that
// wants to know may, and logged because most callers are on the authentication
// path and will only carry on: losing an alert must never change the decision
// that triggered it.
func (e *Engine) Raise(ctx context.Context, in Input) (*store.Alert, error) {
	if !in.Type.Valid() {
		// Refused rather than filed under an unknown type, because a row no
		// filter selects and no severity matches is invisible, and an
		// invisible alert is worse than a rejected call.
		err := fmt.Errorf("alerts: unknown alert type %q", in.Type)
		e.log.Error("alert rejected", "error", err)
		return nil, err
	}
	if in.TenantID == "" {
		err := fmt.Errorf("alerts: tenant id is required for alert type %q", in.Type)
		e.log.Error("alert rejected", "error", err)
		return nil, err
	}

	now := e.now()
	summary := in.Summary
	if summary == "" {
		summary = in.Type.Summary()
	}

	alert := &store.Alert{
		// Minted here rather than by the store. Both backends refuse an alert
		// with no identifier, and the row that wins the fingerprint conflict
		// keeps the one it already had, so this value is used only when this
		// call is the first occurrence.
		ID:          uuid.NewString(),
		TenantID:    in.TenantID,
		AlertType:   in.Type.String(),
		Severity:    in.Type.Severity(),
		SubjectID:   in.SubjectID,
		ResourceID:  in.ResourceID,
		Summary:     summary,
		Fingerprint: e.Fingerprint(in),
		Occurrences: 1,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if len(in.Detail) > 0 {
		raw, err := json.Marshal(in.Detail)
		if err != nil {
			// The detail is context, the alert is the point. A payload that
			// cannot be encoded is dropped with a note rather than allowed to
			// suppress the condition it describes.
			e.log.Warn("alert detail could not be encoded, raising without it",
				"alert_type", in.Type.String(), "error", err)
		} else {
			alert.Detail = json.RawMessage(raw)
		}
	}

	stored, err := e.store.RaiseAlert(ctx, alert)
	if err != nil {
		err = fmt.Errorf("alerts: raise %s: %w", in.Type, err)
		e.log.Error("alert could not be recorded",
			"alert_type", in.Type.String(),
			"fingerprint", alert.Fingerprint,
			"error", err)
		return nil, err
	}

	e.logRaised(stored, alert)
	return stored, nil
}

// logRaised emits the alert at the level its severity deserves, so that a
// deployment which ships logs but not the alert table still sees the critical
// ones.
func (e *Engine) logRaised(stored, submitted *store.Alert) {
	a := stored
	if a == nil {
		a = submitted
	}
	attrs := []any{
		"alert_type", a.AlertType,
		"severity", string(a.Severity),
		"fingerprint", a.Fingerprint,
		"occurrences", a.Occurrences,
	}
	if a.SubjectID != "" {
		attrs = append(attrs, "subject_id", a.SubjectID)
	}
	if a.ResourceID != "" {
		attrs = append(attrs, "resource_id", a.ResourceID)
	}

	switch a.Severity {
	case store.SeverityCritical:
		e.log.Error(a.Summary, attrs...)
	case store.SeverityWarning:
		e.log.Warn(a.Summary, attrs...)
	default:
		e.log.Info(a.Summary, attrs...)
	}
}

// AuthFailureBurst reports repeated authentication failures against one
// subject.
func (e *Engine) AuthFailureBurst(ctx context.Context, tenantID, subjectID string, count int) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:  tenantID,
		Type:      TypeAuthFailureSubject,
		SubjectID: subjectID,
		Summary:   fmt.Sprintf("%d authentication failures for one subject inside the throttle window", count),
		Detail:    map[string]any{"failures": count},
	})
}

// AuthFailureBurstFromNetwork reports repeated authentication failures from one
// source network.
//
// network is the value the limiter buckets on, which is a /64 for IPv6 rather
// than a single address, so the alert names the same thing the limit applied
// to.
func (e *Engine) AuthFailureBurstFromNetwork(ctx context.Context, tenantID, network string, count int) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeAuthFailureIP,
		ResourceID: network,
		Summary:    fmt.Sprintf("%d authentication failures from %s inside the throttle window", count, network),
		Detail:     map[string]any{"failures": count, "network": network},
	})
}

// SignCountRegression reports an authenticator whose signature counter did not
// advance.
//
// The assertion itself is not refused, so this alert is the only record that a
// device may have been cloned.
func (e *Engine) SignCountRegression(ctx context.Context, tenantID, subjectID, credentialID string, stored, presented uint32) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeSignCountRegression,
		SubjectID:  subjectID,
		ResourceID: credentialID,
		Summary:    fmt.Sprintf("Signature counter did not advance, stored %d and the assertion presented %d", stored, presented),
		Detail:     map[string]any{"stored_sign_count": stored, "presented_sign_count": presented},
	})
}

// BulkRevocation reports revocations above the configured burst.
func (e *Engine) BulkRevocation(ctx context.Context, tenantID, actorID string, revoked, burst int) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeBulkRevocation,
		ResourceID: actorID,
		Summary:    fmt.Sprintf("%d credentials revoked by one administrator, the configured burst is %d", revoked, burst),
		Detail:     map[string]any{"revoked": revoked, "burst": burst, "actor_id": actorID},
	})
}

// RecoveryExhausted reports a subject with no recovery codes left.
func (e *Engine) RecoveryExhausted(ctx context.Context, tenantID, subjectID string) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:  tenantID,
		Type:      TypeRecoveryExhausted,
		SubjectID: subjectID,
		Detail:    map[string]any{"remaining": 0},
	})
}

// RecoveryLow reports a subject below the configured low watermark.
func (e *Engine) RecoveryLow(ctx context.Context, tenantID, subjectID string, remaining, watermark int) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:  tenantID,
		Type:      TypeRecoveryLow,
		SubjectID: subjectID,
		Summary:   fmt.Sprintf("%d recovery codes left, the low watermark is %d", remaining, watermark),
		Detail:    map[string]any{"remaining": remaining, "low_watermark": watermark},
	})
}

// APIKeyRejected reports an unknown or revoked API key presented repeatedly.
//
// selector is the clear-text half of the presented key. The verifier half is
// never passed here: an alert row is read by people, and a secret in it is a
// secret in a screenshot.
func (e *Engine) APIKeyRejected(ctx context.Context, tenantID, selector string, count int) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeAPIKeyRejected,
		ResourceID: selector,
		Summary:    fmt.Sprintf("An unknown or revoked API key was presented %d times", count),
		Detail:     map[string]any{"attempts": count, "selector": selector},
	})
}

// AdminDenied reports an administrative authorisation denial.
//
// The reason string from an rbac decision is deliberately not carried into the
// summary: it names the role and the permission, and the summary is rendered in
// an interface a denied caller may eventually see.
func (e *Engine) AdminDenied(ctx context.Context, tenantID, tokenID, permission string) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeAdminDenied,
		ResourceID: tokenID,
		Summary:    fmt.Sprintf("An administrative token was denied %s", permission),
		Detail:     map[string]any{"permission": permission, "token_id": tokenID},
	})
}

// AuditChainBroken reports the hash chain failing verification at brokenAt.
func (e *Engine) AuditChainBroken(ctx context.Context, tenantID string, brokenAt int64) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID: tenantID,
		Type:     TypeAuditChainBroken,
		Summary:  fmt.Sprintf("The audit hash chain does not verify from sequence %d onwards", brokenAt),
		Detail:   map[string]any{"broken_at": brokenAt},
	})
}

// KEKRotationOverdue reports a key encryption key past its rotation interval.
func (e *Engine) KEKRotationOverdue(ctx context.Context, tenantID, keyVersion string, age, interval time.Duration) (*store.Alert, error) {
	return e.Raise(ctx, Input{
		TenantID:   tenantID,
		Type:       TypeKEKRotationOverdue,
		ResourceID: keyVersion,
		Summary:    fmt.Sprintf("Key version %s is %s old, the rotation interval is %s", keyVersion, age, interval),
		Detail:     map[string]any{"key_version": keyVersion, "age": age.String(), "interval": interval.String()},
	})
}
