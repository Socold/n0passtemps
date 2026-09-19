package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// TestDeleteConsumedRecoveryCodesLeavesTheUnusedOnes covers the sweep that
// bounds the recovery code table.
//
// Spent codes used to stay for the life of the account. The cost is not the
// storage: the selector half of a code is thirty bits and unique within the
// tenant, so a table that only ever grows is one whose next batch is steadily
// more likely to collide with something spent years ago and be refused.
//
// What the sweep must not touch is a code the user still holds. Removing one
// would leave them with a printed sheet that no longer works and no way to know
// which line failed.
func TestDeleteConsumedRecoveryCodesLeavesTheUnusedOnes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedSubject(t, s, "tenant-b", "subject-2", "ref-2")

	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	cutoff := now.Add(-90 * 24 * time.Hour)

	batch := func(tenantID, subjectID, batchID string, n int) []*store.RecoveryCode {
		codes := make([]*store.RecoveryCode, 0, n)
		for i := range n {
			codes = append(codes, &store.RecoveryCode{
				ID:           fmt.Sprintf("%s-code-%d", batchID, i),
				Selector:     fmt.Sprintf("%s%04d", batchID[:2], i),
				VerifierHash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA",
				CreatedAt:    now.Add(-365 * 24 * time.Hour),
			})
		}
		if err := s.ReplaceRecoveryCodes(ctx, tenantID, subjectID, batchID, codes); err != nil {
			t.Fatalf("replace recovery codes for %s: %v", subjectID, err)
		}
		return codes
	}

	a := batch("tenant-a", "subject-1", "batch-a", 3)
	b := batch("tenant-b", "subject-2", "batch-b", 2)

	// One code spent long ago, one spent this morning, one never used.
	if err := s.ConsumeRecoveryCode(ctx, "tenant-a", a[0].ID, cutoff.Add(-24*time.Hour)); err != nil {
		t.Fatalf("consume the old code: %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, "tenant-a", a[1].ID, now); err != nil {
		t.Fatalf("consume the recent code: %v", err)
	}
	// The sweep spans every tenant, because the janitor acts on behalf of none
	// of them.
	if err := s.ConsumeRecoveryCode(ctx, "tenant-b", b[0].ID, cutoff.Add(-time.Hour)); err != nil {
		t.Fatalf("consume the other tenant's code: %v", err)
	}

	removed, err := s.DeleteConsumedRecoveryCodes(ctx, cutoff)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 2 {
		t.Errorf("the sweep removed %d codes, want 2", removed)
	}

	if n := countRows(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE id = ?`, a[0].ID); n != 0 {
		t.Error("a code spent before the cutoff is still there")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE id = ?`, a[1].ID); n != 1 {
		t.Error("a code spent inside the retention window was removed; it is the evidence of an authentication")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE consumed_at IS NULL`); n != 2 {
		t.Errorf("%d unused codes remain, want 2: a sheet the user still holds must not lose lines", n)
	}

	// The count an exhaustion warning is drawn from still reads the same, since
	// nothing unused moved.
	left, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("the subject has %d unused codes, want 1", left)
	}

	// A second pass over the same window has nothing left to do, which is what
	// makes the sweep safe to run every interval.
	again, err := s.DeleteConsumedRecoveryCodes(ctx, cutoff)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if again != 0 {
		t.Errorf("the second sweep removed %d codes, want 0", again)
	}
}
