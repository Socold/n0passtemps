package audit

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/Socold/n0passtemps/internal/store"
)

// contextAuditStore fails an append the way a real store does when its context
// has ended, which is the only thing the test below needs from it.
type contextAuditStore struct {
	chainingAuditStore
}

func (c *contextAuditStore) Append(ctx context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.chainingAuditStore.Append(ctx, e)
}

// TestAnEventIsRecordedAfterTheCallerHasGone is the case of a client that hangs
// up between the change and the record of it. The change committed on the
// request's context a moment earlier; if the append ends with that context, the
// caller decides which of their actions leave a trace.
func TestAnEventIsRecordedAfterTheCallerHasGone(t *testing.T) {
	st := &contextAuditStore{}
	r := newTestRecorder(st, io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := r.Success(ctx, Event{
		TenantID: "tenant-a", EventType: EventAssertionCompleted, ActorType: store.ActorSubject,
	}); err != nil {
		t.Fatalf("Record on a cancelled context: %v", err)
	}
	if len(st.entries) != 1 {
		t.Fatalf("the store holds %d entries, want 1", len(st.entries))
	}
}

// TestANULInAFreeTextFieldDoesNotCostTheEntry holds the detail to what both
// engines accept. PostgreSQL refuses U+0000 in JSONB, so a reason carrying one
// failed the append there and nowhere else, after the action had been taken.
func TestANULInAFreeTextFieldDoesNotCostTheEntry(t *testing.T) {
	st := &chainingAuditStore{}
	r := newTestRecorder(st, io.Discard)

	// The second value spells the escape in its text without containing the
	// character, and has to come back as it went in.
	const spelled = `a backslash, then u0000: \u0000`
	if err := r.Success(context.Background(), Event{
		TenantID: "tenant-a", EventType: EventAssertionCompleted, ActorType: store.ActorAdmin,
		Detail: map[string]any{"reason": "before\x00after", "note": spelled},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var detail map[string]string
	if err := json.Unmarshal(st.entries[0].Detail, &detail); err != nil {
		t.Fatalf("the stored detail is not JSON: %v\n%s", err, st.entries[0].Detail)
	}
	if got, want := detail["reason"], "before�after"; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if detail["note"] != spelled {
		t.Errorf("note = %q, want it untouched: %q", detail["note"], spelled)
	}
}
