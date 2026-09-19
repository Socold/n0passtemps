//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// TestPurgeSubjectClearsTheIdentifiersItUsedToLeaveBehind is the PostgreSQL
// side of the residue a purge used to leave.
//
// The alerts raised about an erased subject named them for the life of the
// deployment, and every erasure request filed against them kept the reason an
// operator typed in prose. The argument for deleting the first and clearing the
// second, and for keeping the rest of the request as the proof that the erasure
// happened, is on PurgeSubject; the SQLite test of the same name is its twin.
// Both exist because the statements are written once per engine.
func TestPurgeSubjectClearsTheIdentifiersItUsedToLeaveBehind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	other := seedSubject(t, s, "tenant-a", "subject-2", "ref-2")
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	raise := func(id, subjectID, fingerprint string) {
		t.Helper()
		_, err := s.RaiseAlert(ctx, &store.Alert{
			ID:          id,
			TenantID:    "tenant-a",
			AlertType:   "recovery.codes_exhausted",
			Severity:    store.SeverityWarning,
			SubjectID:   subjectID,
			Summary:     "the subject has spent every recovery code",
			Detail:      json.RawMessage(`{"display_name":"a name that belongs to a person"}`),
			Fingerprint: fingerprint,
			FirstSeenAt: at,
		})
		if err != nil {
			t.Fatalf("raise alert %s: %v", id, err)
		}
	}
	raise("alert-1", sub.ID, "fp-1")
	raise("alert-2", sub.ID, "fp-2")
	raise("alert-3", other.ID, "fp-3")
	raise("alert-4", "", "fp-4")

	for _, r := range []*store.ErasureRequest{
		{
			ID: "er-old", TenantID: "tenant-a", SubjectID: sub.ID,
			Status: store.ErasureCancelled, Reason: "asked by telephone, caller said she had moved",
			RequestedBy: "admin-1", RequestedAt: at.Add(-90 * 24 * time.Hour),
			PurgeAfter: at.Add(-60 * 24 * time.Hour),
		},
		{
			ID: "er-due", TenantID: "tenant-a", SubjectID: sub.ID,
			Status: store.ErasurePending, Reason: "subject request received, verified by ticket 4711",
			RequestedBy: "admin-2", RequestedAt: at, PurgeAfter: at.Add(30 * 24 * time.Hour),
		},
	} {
		if err := s.CreateErasure(ctx, r); err != nil {
			t.Fatalf("create erasure %s: %v", r.ID, err)
		}
	}

	if err := s.SoftDeleteSubject(ctx, "tenant-a", sub.ID, at); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}

	count := func(where string, args ...any) int {
		t.Helper()
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE `+where, args...).Scan(&n); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		return n
	}
	if n := count(`subject_id = $1`, sub.ID); n != 0 {
		t.Errorf("%d alerts still name the erased subject", n)
	}
	if n := count(`subject_id = $1`, other.ID); n != 1 {
		t.Errorf("another subject's alert count is %d, want 1: the purge reached past the subject it was given", n)
	}
	if n := count(`subject_id IS NULL`); n != 1 {
		t.Errorf("alerts about the deployment count is %d, want 1", n)
	}

	for _, id := range []string{"er-old", "er-due"} {
		var reason *string
		var status, requestedBy string
		err := s.pool.QueryRow(ctx,
			`SELECT reason, status, requested_by FROM erasure_requests WHERE id = $1`,
			id).Scan(&reason, &status, &requestedBy)
		if err != nil {
			t.Fatalf("read erasure request %s: %v", id, err)
		}
		if text(reason) != "" {
			t.Errorf("erasure request %s still carries the reason %q", id, text(reason))
		}
		if requestedBy == "" {
			t.Errorf("erasure request %s no longer says who asked for it", id)
		}
		if status == "" {
			t.Errorf("erasure request %s no longer says what became of it", id)
		}
	}

	if err := s.MarkErasurePurged(ctx, "tenant-a", "er-due", at.Add(30*24*time.Hour)); err != nil {
		t.Errorf("mark purged after the purge cleared the reason: %v", err)
	}
}

// TestRestoreSubjectOnlyUndoesAnErasure checks the inverse of the soft delete.
//
// Cancelling an erasure has to bring the subject back, or the request is
// withdrawn while the user stays blocked. It must not double as a way to
// reactivate a subject an operator locked: a lock and an erasure are different
// decisions, and cancelling one must not undo the other.
func TestRestoreSubjectOnlyUndoesAnErasure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedSubject(t, s, "tenant-a", "subject-2", "ref-2")
	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	if err := s.SoftDeleteSubject(ctx, "tenant-a", "subject-1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSubject(ctx, "tenant-a", "subject-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a soft-deleted subject is still visible: %v", err)
	}

	// Another tenant must not be able to restore it.
	if err := s.RestoreSubject(ctx, "tenant-b", "subject-1", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("restore across tenants = %v, want ErrNotFound", err)
	}

	if err := s.RestoreSubject(ctx, "tenant-a", "subject-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	sub, err := s.GetSubject(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatalf("a restored subject is not visible: %v", err)
	}
	if !sub.Active() {
		t.Errorf("a restored subject has status %q and cannot authenticate", sub.Status)
	}

	// Restoring twice, or restoring a subject that was never deleted, is not
	// a restore.
	if err := s.RestoreSubject(ctx, "tenant-a", "subject-1", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second restore = %v, want ErrNotFound", err)
	}
	if err := s.SetSubjectStatus(ctx, "tenant-a", "subject-2", store.SubjectLocked); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreSubject(ctx, "tenant-a", "subject-2", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("restore reactivated a LOCKED subject: %v", err)
	}
	locked, err := s.GetSubject(ctx, "tenant-a", "subject-2")
	if err != nil || locked.Status != store.SubjectLocked {
		t.Errorf("the locked subject is now %v, %v", locked, err)
	}
}

// TestTouchCredentialRecordsUseWithoutMovingTheCounter covers authenticators
// that report a constant zero counter, which is most passkeys. Without it their
// last use was never recorded and a dormant-credential review listed them all.
func TestTouchCredentialRecordsUseWithoutMovingTheCounter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 0)
	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	if err := s.TouchCredential(ctx, "tenant-b", "cred-1", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("touch across tenants = %v, want ErrNotFound", err)
	}
	if err := s.TouchCredential(ctx, "tenant-a", "cred-1", now); err != nil {
		t.Fatalf("touch: %v", err)
	}
	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.LastUsedAt == nil || !c.LastUsedAt.Equal(now) {
		t.Errorf("last_used_at = %v, want %s", c.LastUsedAt, now)
	}
	if c.SignCount != 0 {
		t.Errorf("touching moved the signature counter to %d", c.SignCount)
	}

	// A revoked credential is not touched, so the ceremony layer can treat the
	// refusal as "revoked between listing and use".
	if err := s.RevokeCredential(ctx, "tenant-a", "cred-1", "test", now); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchCredential(ctx, "tenant-a", "cred-1", now.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("touch on a revoked credential = %v, want ErrNotFound", err)
	}
}
