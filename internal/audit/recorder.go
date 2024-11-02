package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// Recorder appends entries to the audit log.
//
// Appends are synchronous. Buffering them would make an authentication
// marginally faster at the cost of losing the record of it when the process
// dies, and the record is the point. Where the latency genuinely matters the
// answer is to append in the same transaction as the change, not to make the
// append unreliable.
type Recorder struct {
	store store.AuditStore
	log   *slog.Logger
	now   func() time.Time
}

// NewRecorder returns a Recorder backed by s.
func NewRecorder(s store.AuditStore, log *slog.Logger) *Recorder {
	return &Recorder{store: s, log: log, now: time.Now}
}

// Event describes one thing to record. It is a narrower struct than
// store.AuditEntry because the chain fields and the sequence number are filled
// in by the store, not by the caller.
type Event struct {
	TenantID     string
	EventType    string
	ActorType    store.ActorType
	ActorID      string
	SubjectID    string
	ResourceType string
	ResourceID   string
	Outcome      store.Outcome
	SourceIP     string
	RequestID    string
	Detail       map[string]any
}

// Record appends the event.
//
// A failure to append is returned so a caller inside a transaction can roll
// back, and is also logged at error level, because an audit log that has
// started silently dropping entries is itself a security incident.
func (r *Recorder) Record(ctx context.Context, ev Event) error {
	entry := &store.AuditEntry{
		TenantID:     ev.TenantID,
		OccurredAt:   r.now().UTC(),
		EventType:    ev.EventType,
		ActorType:    ev.ActorType,
		ActorID:      ev.ActorID,
		SubjectID:    ev.SubjectID,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Outcome:      ev.Outcome,
		SourceIP:     ev.SourceIP,
		RequestID:    ev.RequestID,
	}

	if len(ev.Detail) > 0 {
		raw, err := json.Marshal(ev.Detail)
		if err != nil {
			// Rather than drop the entry, record that the detail could not be
			// serialised. Losing context is better than losing the event.
			r.log.ErrorContext(ctx, "audit detail could not be serialised",
				slog.String("event_type", ev.EventType), slog.Any("error", err))
			raw = []byte(`{"detail_error":"not serialisable"}`)
		}
		entry.Detail = raw
	}

	if _, err := r.store.Append(ctx, entry); err != nil {
		r.log.ErrorContext(ctx, "audit append failed",
			slog.String("event_type", ev.EventType),
			slog.String("outcome", string(ev.Outcome)),
			slog.Any("error", err))
		return fmt.Errorf("audit: append %s: %w", ev.EventType, err)
	}
	return nil
}

// Success records a successful action.
func (r *Recorder) Success(ctx context.Context, ev Event) error {
	ev.Outcome = store.OutcomeSuccess
	return r.Record(ctx, ev)
}

// Failure records an action that was attempted and did not succeed, such as a
// rejected assertion. It is distinct from Denied, which is an authorisation
// refusal, and from Errored, which is a fault in the service.
func (r *Recorder) Failure(ctx context.Context, ev Event) error {
	ev.Outcome = store.OutcomeFailure
	return r.Record(ctx, ev)
}

// Denied records an authorisation refusal.
func (r *Recorder) Denied(ctx context.Context, ev Event) error {
	ev.Outcome = store.OutcomeDenied
	return r.Record(ctx, ev)
}

// Errored records a fault in the service rather than a rejected request.
func (r *Recorder) Errored(ctx context.Context, ev Event) error {
	ev.Outcome = store.OutcomeError
	return r.Record(ctx, ev)
}

// Verify walks the chain from fromSeq and reports the first broken sequence
// number, or zero when the range is intact. The result is itself recorded, so
// that a verification run and its outcome are part of the history.
func (r *Recorder) Verify(ctx context.Context, tenantID string, fromSeq int64) (checked int64, brokenAt int64, err error) {
	checked, brokenAt, err = r.store.VerifyChain(ctx, fromSeq)
	if err != nil {
		return checked, brokenAt, fmt.Errorf("audit: verify chain: %w", err)
	}

	ev := Event{
		TenantID:  tenantID,
		EventType: EventChainVerified,
		ActorType: store.ActorSystem,
		Detail:    map[string]any{"from_seq": fromSeq, "checked": checked},
	}
	if brokenAt != 0 {
		ev.EventType = EventChainBroken
		ev.Outcome = store.OutcomeError
		ev.Detail["broken_at"] = brokenAt
		r.log.ErrorContext(ctx, "audit chain verification failed",
			slog.Int64("broken_at", brokenAt), slog.Int64("checked", checked))
		if recErr := r.Record(ctx, ev); recErr != nil {
			return checked, brokenAt, recErr
		}
		return checked, brokenAt, nil
	}

	if recErr := r.Success(ctx, ev); recErr != nil {
		return checked, brokenAt, recErr
	}
	return checked, brokenAt, nil
}
