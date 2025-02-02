package sqlite

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{DSN: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func appendN(t *testing.T, s *Store, tenant string, n int) []*store.AuditEntry {
	t.Helper()
	ctx := context.Background()
	out := make([]*store.AuditEntry, 0, n)
	for i := 0; i < n; i++ {
		e, err := s.Append(ctx, &store.AuditEntry{
			TenantID:   tenant,
			EventType:  audit.EventAssertionCompleted,
			ActorType:  store.ActorSubject,
			SubjectID:  "subject-1",
			SourceIP:   "192.0.2.10",
			Outcome:    store.OutcomeSuccess,
			OccurredAt: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

func TestChainVerifies(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := appendN(t, s, "tenant-1", 25)

	// The first entry must chain onto the genesis value, not onto zero bytes.
	if got, want := entries[0].PrevHash, audit.Genesis(); string(got) != string(want) {
		t.Errorf("first PrevHash = %x, want genesis %x", got, want)
	}
	for i := 1; i < len(entries); i++ {
		if string(entries[i].PrevHash) != string(entries[i-1].EntryHash) {
			t.Fatalf("entry %d does not chain onto %d", i, i-1)
		}
	}

	checked, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain reported broken at %d", broken)
	}
	if checked != 25 {
		t.Errorf("checked %d entries, want 25", checked)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 10)

	// Rewrite one entry's event type the way an operator with the sqlite3
	// shell would. The trigger refuses an ordinary UPDATE, so reach past it to
	// prove the chain catches what the trigger cannot prevent.
	if _, err := s.write.ExecContext(ctx, `DROP TRIGGER audit_log_update_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.write.ExecContext(ctx,
		`UPDATE audit_log SET event_type = 'tampered' WHERE seq = 5`); err != nil {
		t.Fatal(err)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 5 {
		t.Fatalf("expected the chain to break at seq 5, got %d", broken)
	}
}

func TestChainSurvivesErasure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 12)

	erased, err := s.EraseSubjectAuditEntries(ctx, "tenant-1", "subject-1", "admin-7", time.Now())
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if erased != 12 {
		t.Fatalf("erased %d entries, want 12", erased)
	}

	// The chain must still verify after the personal fields are gone. That is
	// the whole point of committing to them through a salted digest.
	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d after erasure", broken)
	}

	// And the personal data must actually be gone.
	rows, err := s.QueryAudit(ctx, "tenant-1", store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.EventType == audit.EventSubjectRedacted {
			continue // the tombstone names the subject as a resource, not a subject
		}
		if e.SubjectID != "" || e.SourceIP != "" {
			t.Errorf("seq %d still carries personal data: subject=%q ip=%q",
				e.Seq, e.SubjectID, e.SourceIP)
		}
		if !audit.Erased(e) {
			t.Errorf("seq %d still has its salt", e.Seq)
		}
	}

	// A tombstone recording the erasure must exist.
	tomb, err := s.QueryAudit(ctx, "tenant-1", store.AuditFilter{
		EventType: audit.EventSubjectRedacted, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tomb) != 1 {
		t.Fatalf("expected one erasure tombstone, got %d", len(tomb))
	}
}

func TestPruneKeepsRemainderVerifiable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 20)

	// Everything was stamped in 2026-01-01; cut above the tenth entry.
	cut := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	removed, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 10 {
		t.Fatalf("removed %d entries, want 10", removed)
	}

	// Verification has to resume from the checkpoint hash rather than from
	// genesis, otherwise a trimmed log would look tampered with.
	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d after pruning", broken)
	}
}

func TestPruneRefusedWithoutCheckpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 3)

	// A direct delete, with no checkpoint recorded, must be refused.
	_, err := s.write.ExecContext(ctx, `DELETE FROM audit_log WHERE seq = 1`)
	if err == nil {
		t.Fatal("expected the delete guard to refuse an unattested deletion")
	}
	if got := mapError(err); got == nil {
		t.Fatal("expected a mapped error")
	}
}

func TestConcurrentAppendsChainCleanly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two appends racing must not chain onto the same predecessor. The write
	// pool holds one connection and every write transaction is IMMEDIATE, so
	// they serialise rather than interleave.
	const writers, each = 8, 15
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_, err := s.Append(ctx, &store.AuditEntry{
					TenantID:  "tenant-1",
					EventType: audit.EventAssertionCompleted,
					ActorType: store.ActorSystem,
					Outcome:   store.OutcomeSuccess,
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	checked, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d under concurrency", broken)
	}
	if want := int64(writers * each); checked != want {
		t.Errorf("checked %d entries, want %d", checked, want)
	}
}

func TestQueryAuditFamilyPrefix(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, et := range []string{
		audit.EventAssertionCompleted,
		audit.EventRegistrationCompleted,
		audit.EventTOTPVerified,
	} {
		if _, err := s.Append(ctx, &store.AuditEntry{
			TenantID: "t", EventType: et, ActorType: store.ActorSystem,
			Outcome: store.OutcomeSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.QueryAudit(ctx, "t", store.AuditFilter{EventType: "webauthn.", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefix query returned %d entries, want 2", len(got))
	}

	// A wildcard in the filter must not widen the match.
	got, err = s.QueryAudit(ctx, "t", store.AuditFilter{EventType: "%.", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a percent sign in the filter matched %d entries, want 0", len(got))
	}
}
