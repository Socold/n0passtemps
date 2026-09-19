package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// Sink takes a copy of an entry that has just been recorded, for delivery
// somewhere outside this deployment.
//
// The interface is declared here rather than in the implementing package so
// that the recorder does not depend on it, which keeps the dependency pointing
// one way: an audit entry is written whether or not anything is shipping it.
//
// Offer must not block, must not fail and must not panic. A destination that is
// slow, unreachable or misconfigured has to cost an authentication nothing,
// which means the decision about what to do with an entry the implementation
// cannot take right now belongs to the implementation. See internal/auditsink.
type Sink interface {
	Offer(entry *store.AuditEntry)
}

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

	// sink is the external witness, when one is configured. It is offered
	// entries that have already been committed, so nothing it does can change
	// whether the entry exists.
	sink Sink
}

// NewRecorder returns a Recorder backed by s.
func NewRecorder(s store.AuditStore, log *slog.Logger) *Recorder {
	return &Recorder{store: s, log: log, now: time.Now}
}

// SetSink wires in an external destination for recorded entries.
//
// It is a setter rather than a constructor argument because the recorder works
// without one and a deployment with no sink configured never calls it, which is
// the same arrangement as janitor.SetKEKProbe. It is called once during startup,
// before any request is served.
func (r *Recorder) SetSink(s Sink) { r.sink = s }

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

// appendTimeout bounds one append once it no longer ends with the request.
const appendTimeout = 5 * time.Second

// scrubNUL replaces an escaped U+0000 in a serialised detail with the escape
// for U+FFFD.
//
// PostgreSQL refuses U+0000 in a JSONB document and SQLite stores it, so a
// free-text field holding one, a reason or a note, made the append fail on one
// engine only, after the change it described had committed: an administrator
// could choose which of their actions were recorded. The character carries
// nothing worth keeping, and the replacement keeps the entry.
//
// raw is what json.Marshal produced, so a NUL can only appear as the six
// characters of its escape, and a backslash inside a value is itself escaped.
// Stepping over the character after every backslash is what tells the escape
// from the text of a value that happens to spell it.
func scrubNUL(raw []byte) []byte {
	const nul, replacement = `\u0000`, `\ufffd`
	if !bytes.Contains(raw, []byte(nul)) {
		return raw
	}
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			out = append(out, raw[i])
			continue
		}
		if bytes.HasPrefix(raw[i:], []byte(nul)) {
			out = append(out, replacement...)
			i += len(nul) - 1
			continue
		}
		out = append(out, raw[i], raw[i+1])
		i++
	}
	return out
}

// Record appends the event.
//
// A failure to append is returned so a caller inside a transaction can roll
// back, and is also logged at error level, because an audit log that has
// started silently dropping entries is itself a security incident.
func (r *Recorder) Record(ctx context.Context, ev Event) error {
	// The append outlives the request that caused it. Most events are recorded
	// after the change they describe has committed, on the request's context,
	// and a caller who hung up at that moment cancelled the context and with it
	// the record of what they had just done. The timeout is what bounds the
	// append now that the caller leaving does not.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()

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
		entry.Detail = scrubNUL(raw)
	}

	stored, err := r.store.Append(ctx, entry)
	if err != nil {
		r.log.ErrorContext(ctx, "audit append failed",
			slog.String("event_type", ev.EventType),
			slog.String("outcome", string(ev.Outcome)),
			slog.Any("error", err))
		return fmt.Errorf("audit: append %s: %w", ev.EventType, err)
	}

	// Only after the append has committed, and only as a hand-off. The entry is
	// already durable and already chained, so an offer that is dropped loses a
	// delivery rather than a record.
	if r.sink != nil && stored != nil {
		r.sink.Offer(stored)
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
func (r *Recorder) Verify(ctx context.Context, tenantID string, fromSeq int64) (checked int64, brokenAt int64,
	err error) {
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
