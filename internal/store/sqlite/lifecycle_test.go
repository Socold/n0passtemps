package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// TestRestoreSubjectOnlyUndoesAnErasure checks the inverse of the soft delete.
//
// Cancelling an erasure has to bring the subject back, or the request is
// withdrawn while the user stays blocked. It must not double as a way to
// reactivate a subject an operator locked: a lock and an erasure are different
// decisions, and cancelling one must not undo the other.
func TestRestoreSubjectOnlyUndoesAnErasure(t *testing.T) {
	s := newStore(t)
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
	if err = s.RestoreSubject(ctx, "tenant-a", "subject-1", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second restore = %v, want ErrNotFound", err)
	}
	if err = s.SetSubjectStatus(ctx, "tenant-a", "subject-2", store.SubjectLocked); err != nil {
		t.Fatal(err)
	}
	if err = s.RestoreSubject(ctx, "tenant-a", "subject-2", now); !errors.Is(err, store.ErrNotFound) {
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
	s := newStore(t)
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
