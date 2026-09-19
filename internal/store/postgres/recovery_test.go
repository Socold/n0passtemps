//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

// recoveryHash is a syntactically valid stored hash. Nothing here verifies a
// code, so the value only has to be accepted by the column.
const recoveryHash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"

func recoveryBatch(batchID string, n int) []*store.RecoveryCode {
	codes := make([]*store.RecoveryCode, 0, n)
	for i := range n {
		codes = append(codes, &store.RecoveryCode{
			ID:           fmt.Sprintf("%s-code-%d", batchID, i),
			Selector:     fmt.Sprintf("%s%04d", batchID[:2], i),
			VerifierHash: recoveryHash,
		})
	}
	return codes
}

// TestDeleteConsumedRecoveryCodesLeavesTheUnusedOnes is the PostgreSQL side of
// the sweep that bounds the recovery code table. The SQLite test of the same
// name carries the argument; this one exists because the statement is written
// twice, once per engine, and a sweep that removed the wrong rows here would
// not be caught there.
func TestDeleteConsumedRecoveryCodesLeavesTheUnusedOnes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedSubject(t, s, "tenant-b", "subject-2", "ref-2")

	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	cutoff := now.Add(-90 * 24 * time.Hour)

	a := recoveryBatch("batch-a", 3)
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-a", a); err != nil {
		t.Fatalf("replace codes for subject-1: %v", err)
	}
	b := recoveryBatch("batch-b", 2)
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-b", "subject-2", "batch-b", b); err != nil {
		t.Fatalf("replace codes for subject-2: %v", err)
	}

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

	if _, err := s.GetRecoveryCodeBySelector(ctx, "tenant-a", a[0].Selector); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a code spent before the cutoff is still there: %v", err)
	}
	if _, err := s.GetRecoveryCodeBySelector(ctx, "tenant-a", a[1].Selector); err != nil {
		t.Errorf("a code spent inside the retention window was removed: %v", err)
	}
	left, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("the subject has %d unused codes, want 1: a sheet they still hold must not lose lines", left)
	}
}

// TestConcurrentBatchReplacementsLeaveOneSheet is the test the SQLite side has
// no counterpart for, because the engines differ exactly here.
//
// SQLite admits one writer, so the transaction that retires the previous batch
// and inserts the new one excludes the other by construction. Under READ
// COMMITTED nothing excludes anything: each transaction deletes the unused
// codes it can see, which are the ones committed before it began, inserts its
// own batch, and commits. Both sheets are then live, the user has been told the
// first is dead, and it is not. The advisory lock in ReplaceRecoveryCodes is
// what closes that, and this is what would notice if it were removed.
func TestConcurrentBatchReplacementsLeaveOneSheet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-0",
		recoveryBatch("batch-0", 4)); err != nil {
		t.Fatalf("issue the first sheet: %v", err)
	}

	// Two reissues at once, which is what a user clicking twice, or two
	// administrators acting on one support request, produces.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i, batchID := range []string{"batch-1", "batch-2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", batchID,
				recoveryBatch(batchID, 4))
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("reissue %d failed: %v", i, err)
		}
	}

	// One sheet, whichever of the two won. Two would mean eight live codes for
	// a subject who holds one printed page.
	var batches int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT batch_id) FROM recovery_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL`,
		"tenant-a", "subject-1").Scan(&batches)
	if err != nil {
		t.Fatalf("count live batches: %v", err)
	}
	if batches != 1 {
		t.Errorf("%d batches of recovery codes are live, want 1: the user was told the earlier sheet was dead", batches)
	}

	live, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if live != 4 {
		t.Errorf("%d unused codes, want 4", live)
	}
}

// TestOnePendingTOTPSecretPerSubject covers the guard migration 0008 declares.
//
// It is the same race as the one above, on the other table: CreateTOTPSecret
// revokes the previous unconfirmed secret and inserts a new one, and under READ
// COMMITTED two concurrent enrolments revoke nothing of each other's and both
// end up pending, only one of which the user holds. There is no row to lock,
// because neither row exists when the other transaction reads, so the guard is
// the partial unique index rather than a statement; the enrolment tickets have
// had one since migration 0003 for the same reason.
//
// The test drives two transactions by hand rather than two goroutines, so that
// the interleaving is the one being argued about rather than whichever one the
// scheduler produces.
func TestOnePendingTOTPSecretPerSubject(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	if err := s.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID: "totp-1", TenantID: "tenant-a", SubjectID: "subject-1",
		SecretSealed: []byte("sealed-1"), Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}); err != nil {
		t.Fatalf("first enrolment: %v", err)
	}

	// A second pending secret for the same subject, inserted without the
	// revocation that CreateTOTPSecret performs, which is what a concurrent
	// enrolment amounts to.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO totp_secrets (id, tenant_id, subject_id, secret_sealed, algorithm,
			digits, period_seconds, last_timestep, created_at)
		VALUES ($1, $2, $3, $4, 'SHA1', 6, 30, 0, now())`,
		"totp-2", "tenant-a", "subject-1", []byte("sealed-2"))
	if err == nil {
		t.Fatal("a second pending secret was accepted: the subject now has two, and holds one")
	}
	if !errors.Is(mapError(err), store.ErrConflict) {
		t.Errorf("the refusal was %v, want a conflict", err)
	}

	// The guard is on pending secrets alone. A subject who confirms one and
	// then starts a fresh enrolment is the ordinary case and must still work.
	if _, err := s.pool.Exec(ctx,
		`UPDATE totp_secrets SET confirmed_at = now() WHERE id = $1`, "totp-1"); err != nil {
		t.Fatalf("confirm the first secret: %v", err)
	}
	if err := s.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID: "totp-3", TenantID: "tenant-a", SubjectID: "subject-1",
		SecretSealed: []byte("sealed-3"), Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}); err != nil {
		t.Errorf("a new enrolment beside a confirmed secret was refused: %v", err)
	}
}

// TestTransactionsDeclareTheirIsolationLevel checks that the level is the one
// the store is written against rather than the one the server was configured
// with.
//
// A cluster with default_transaction_isolation = repeatable read gives a
// transaction its snapshot at the first statement, and for the audit append
// that statement is the one waiting for the chain's advisory lock: the appender
// that waited would then read the head as it stood before the holder committed,
// and the two entries would claim the same predecessor.
func TestTransactionsDeclareTheirIsolationLevel(t *testing.T) {
	ctx := context.Background()

	// A second store on the same schema, holding exactly one connection, so
	// that the session the default is moved on is the session the transaction
	// below runs in. With the usual pool the two would be unrelated
	// connections and the test would prove nothing.
	single, err := Open(Options{DSN: newTestStore(t).dsn, MaxConns: 1})
	if err != nil {
		t.Fatalf("open a single-connection store: %v", err)
	}
	t.Cleanup(func() { _ = single.Close() })

	// The session default is moved out from under the store, which is what a
	// deployment's postgresql.conf does.
	if _, err := single.pool.Exec(ctx, `SET SESSION default_transaction_isolation = 'repeatable read'`); err != nil {
		t.Fatalf("move the session default: %v", err)
	}

	var level string
	if err := single.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&level)
	}); err != nil {
		t.Fatalf("read the level inside a transaction: %v", err)
	}
	if level != "read committed" {
		t.Errorf("transactions run at %q, want \"read committed\": the store's compare-and-swap "+
			"operations re-read what they are about to change, which a held snapshot defeats", level)
	}
}
