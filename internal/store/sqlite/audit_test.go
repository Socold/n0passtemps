package sqlite

import (
	"bytes"
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
	if got, want := entries[0].PrevHash, audit.Genesis(); !bytes.Equal(got, want) {
		t.Errorf("first PrevHash = %x, want genesis %x", got, want)
	}
	for i := 1; i < len(entries); i++ {
		if !bytes.Equal(entries[i].PrevHash, entries[i-1].EntryHash) {
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

// TestAPruneIsAttestedByTheChain covers what a checkpoint is worth.
//
// The marker the trim appends carries the hash of the entry it stopped at, and
// the chain covers the marker, so the boundary a checkpoint claims is a
// boundary the chain agrees with. Verification asks for exactly that, so the
// two have to be written to match.
func TestAPruneIsAttestedByTheChain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entries := appendN(t, s, "tenant-1", 20)
	boundary := entries[9]

	cut := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	if _, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var (
		prunedSeq  int64
		prunedHash []byte
		markerSeq  int64
	)
	if err := s.read.QueryRowContext(ctx, `
		SELECT pruned_through_seq, pruned_through_hash, audit_seq
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).
		Scan(&prunedSeq, &prunedHash, &markerSeq); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if prunedSeq != boundary.Seq || !bytes.Equal(prunedHash, boundary.EntryHash) {
		t.Fatalf("checkpoint names (%d, %x), want the tenth entry (%d, %x)",
			prunedSeq, prunedHash, boundary.Seq, boundary.EntryHash)
	}

	var detail string
	if err := s.read.QueryRowContext(ctx,
		`SELECT detail FROM audit_log WHERE seq = ?`, markerSeq).Scan(&detail); err != nil {
		t.Fatalf("read the retention marker: %v", err)
	}
	if !audit.MarkerAttestsCheckpoint([]byte(detail), prunedSeq, prunedHash) {
		t.Errorf("the marker at seq %d does not attest the checkpoint: %s", markerSeq, detail)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("an attested trim reported a break at %d", broken)
	}
}

// TestAForgedCheckpointAndATrimmedPrefixAreDetected is the attack the binding
// exists for.
//
// Whoever can write to the database inserts a checkpoint naming entry ten and
// its real hash, and then deletes entries one to ten, which the delete guard
// allows because a checkpoint now exists. Nothing in the chain ever said the
// log had been trimmed, and verification used to resume from the checkpoint and
// report a log in perfect order.
func TestAForgedCheckpointAndATrimmedPrefixAreDetected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entries := appendN(t, s, "tenant-1", 20)
	boundary := entries[9]

	forge := func() error {
		_, err := s.write.ExecContext(ctx, `
			INSERT INTO audit_checkpoints (
				id, tenant_id, pruned_through_seq, pruned_through_hash,
				entries_removed, audit_seq, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"forged-checkpoint", "tenant-1", boundary.Seq, boundary.EntryHash,
			10, entries[10].Seq, formatTime(time.Now()))
		return err
	}

	// The insert guard refuses it outright: the entry the row names is an
	// ordinary one and not the marker of a trim.
	if err := forge(); err == nil {
		t.Fatal("expected the insert guard to refuse a checkpoint no marker attests")
	}

	// A guard is a trigger and the attacker owns the database file, so the
	// interesting question is what verification says once the trigger is gone.
	if _, err := s.write.ExecContext(ctx, `DROP TRIGGER audit_checkpoints_marker_guard`); err != nil {
		t.Fatal(err)
	}
	if err := forge(); err != nil {
		t.Fatalf("insert the forged checkpoint: %v", err)
	}
	if _, err := s.write.ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= ?`, boundary.Seq); err != nil {
		t.Fatalf("the delete guard let the prefix go, as it does once a checkpoint exists: %v", err)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != boundary.Seq {
		t.Fatalf("a forged checkpoint and a deleted prefix reported a break at %d, want %d",
			broken, boundary.Seq)
	}
}

func TestPruneStopsAtTheFirstRecentEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Three old entries, a recent one, and then one written by a clock that had
	// fallen behind: old by its timestamp, newest by its position.
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	stamps := []time.Time{old, old.Add(time.Second), old.Add(2 * time.Second), recent, old.Add(3 * time.Second)}
	for i, at := range stamps {
		if _, err := s.Append(ctx, &store.AuditEntry{
			TenantID:   "tenant-1",
			EventType:  audit.EventAssertionCompleted,
			ActorType:  store.ActorSubject,
			SubjectID:  "subject-1",
			Outcome:    store.OutcomeSuccess,
			OccurredAt: at,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Timestamps come from the process clock and are not monotonic in the
	// sequence number. Cutting at the newest entry that looks old would take
	// the recent one with it, and the checkpoint would make the loss verify.
	cut := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	removed, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed %d entries, want only the 3 that precede the first recent one", removed)
	}

	left, err := s.ReadAuditRange(ctx, 1, 100)
	if err != nil {
		t.Fatalf("read what is left: %v", err)
	}
	if len(left) == 0 || left[0].Seq != 4 || !left[0].OccurredAt.Equal(recent) {
		t.Fatalf("the log no longer starts at the recent entry, seq 4: a backdated entry pruned it")
	}

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
		go func(int) {
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

// TestReadAuditRangeSpansEveryTenant is the property the external audit sink
// rests on.
//
// An entry recorded against the reserved system tenant, which is what a failed
// authentication produces, sits between two ordinary ones in the chain. A read
// that filtered by tenant would hand a witness a contiguous chain with holes in
// it, and the witness would report tampering that never happened.
func TestReadAuditRangeSpansEveryTenant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	appendN(t, s, "tenant-a", 2)
	appendN(t, s, store.SystemTenantID, 1)
	appendN(t, s, "tenant-a", 2)

	got, err := s.ReadAuditRange(ctx, 1, 100)
	if err != nil {
		t.Fatalf("ReadAuditRange: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("read %d entries, want all 5 regardless of tenant", len(got))
	}
	for i, e := range got {
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d has seq %d, want %d: the range must be contiguous", i, e.Seq, i+1)
		}
	}
	if broken := audit.VerifySequence(got, audit.Genesis()); broken != 0 {
		t.Errorf("the range does not verify as a chain, broken at %d", broken)
	}
}

// TestReadAuditRangeStartsAtTheSequenceAsked covers the difference from the
// chain walk: a caller here names the first entry it wants, not the last one it
// already has.
func TestReadAuditRangeStartsAtTheSequenceAsked(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-a", 6)

	got, err := s.ReadAuditRange(ctx, 4, 2)
	if err != nil {
		t.Fatalf("ReadAuditRange: %v", err)
	}
	if len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 5 {
		t.Fatalf("read %d entries starting at %d, want seq 4 and 5", len(got), got[0].Seq)
	}

	// Past the end of the log is an empty page and not an error: that is how
	// the shipper learns it is level with the log.
	got, err = s.ReadAuditRange(ctx, 99, 10)
	if err != nil {
		t.Fatalf("ReadAuditRange past the end: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("read %d entries past the end of the log, want none", len(got))
	}
}
