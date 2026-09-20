package audit

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Socold/n0passtemps/internal/store"
)

// chainingAuditStore is a store that assigns sequence numbers and chain hashes
// the way a real one does, so that what reaches a sink is what a sink would
// actually be given.
type chainingAuditStore struct {
	store.AuditStore
	entries []*store.AuditEntry
	err     error
}

func (c *chainingAuditStore) Append(_ context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if c.err != nil {
		return nil, c.err
	}
	prev := Genesis()
	if n := len(c.entries); n > 0 {
		prev = c.entries[n-1].EntryHash
	}
	if err := Prepare(e, int64(len(c.entries)+1), prev); err != nil {
		return nil, err
	}
	c.entries = append(c.entries, e)
	return e, nil
}

// recordingSink collects what it is offered.
type recordingSink struct {
	offered []*store.AuditEntry
}

func (s *recordingSink) Offer(e *store.AuditEntry) { s.offered = append(s.offered, e) }

func TestRecorderOffersCommittedEntriesToTheSink(t *testing.T) {
	st := &chainingAuditStore{}
	sink := &recordingSink{}
	r := newTestRecorder(st, io.Discard)
	r.SetSink(sink)

	for range 3 {
		if err := r.Success(context.Background(), Event{
			TenantID:  "tenant-a",
			EventType: EventAssertionCompleted,
			ActorType: store.ActorSubject,
			SubjectID: "subject-1",
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	if len(sink.offered) != 3 {
		t.Fatalf("sink was offered %d entries, want 3", len(sink.offered))
	}

	// What a sink receives has to be the committed entry, not the caller's
	// half-filled one: without the sequence number and the hashes there is
	// nothing for a receiver to verify or to detect a gap with.
	for i, e := range sink.offered {
		if e.Seq != int64(i+1) {
			t.Errorf("offered entry %d has seq %d, want %d", i, e.Seq, i+1)
		}
		if len(e.EntryHash) != HashSize || len(e.PrevHash) != HashSize {
			t.Errorf("offered entry %d carries no chain hashes", i)
		}
	}
	if !VerifyEntry(sink.offered[0], Genesis()) {
		t.Error("the first offered entry does not verify against the genesis hash")
	}
}

func TestRecorderOffersNothingWhenTheAppendFailed(t *testing.T) {
	st := &chainingAuditStore{err: errors.New("database is unreachable")}
	sink := &recordingSink{}
	r := newTestRecorder(st, io.Discard)
	r.SetSink(sink)

	err := r.Success(context.Background(), Event{
		TenantID:  "tenant-a",
		EventType: EventAssertionCompleted,
		ActorType: store.ActorSubject,
	})
	if err == nil {
		t.Fatal("Record returned no error although the append failed")
	}

	// An entry that was never committed must not reach the witness. A receiver
	// holding a sequence number the local chain does not have would report a
	// mismatch that never happened.
	if len(sink.offered) != 0 {
		t.Errorf("sink was offered %d entries after a failed append, want 0", len(sink.offered))
	}
}

func TestRecorderWorksWithNoSink(t *testing.T) {
	st := &chainingAuditStore{}
	r := newTestRecorder(st, io.Discard)

	if err := r.Success(context.Background(), Event{
		TenantID:  "tenant-a",
		EventType: EventServiceStarted,
		ActorType: store.ActorSystem,
	}); err != nil {
		t.Fatalf("Record without a sink: %v", err)
	}
	if len(st.entries) != 1 {
		t.Fatalf("store received %d entries, want 1", len(st.entries))
	}
}
