package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const recoveryColumns = `id, tenant_id, subject_id, batch_id, selector, verifier_hash,
	created_at, consumed_at`

// ReplaceRecoveryCodes implements store.RecoveryStore.
//
// Retiring the previous batch and inserting the new one happen in one
// transaction. Issuing a batch without retiring the old one leaves codes in
// circulation that the user has been told are dead, which is the worst of both
// outcomes: the user believes the printed sheet they threw away is worthless,
// and it is not.
//
// Unused codes from earlier batches are deleted rather than marked consumed.
// Marking them consumed would record a spend that never happened, and the
// counters and the audit trail would then disagree about how many codes the
// subject actually used. Codes that have genuinely been consumed are left in
// place: they are evidence of an authentication and belong in the trail.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, tenantID, subjectID, batchID string,
	codes []*store.RecoveryCode) error {
	if tenantID == "" || subjectID == "" || batchID == "" {
		return errors.New("sqlite: recovery batch requires a tenant, a subject and a batch id")
	}
	if len(codes) == 0 {
		return errors.New("sqlite: recovery batch requires at least one code")
	}
	for i, c := range codes {
		if c == nil {
			return fmt.Errorf("sqlite: recovery code %d is nil", i)
		}
		if c.ID == "" || c.Selector == "" || c.VerifierHash == "" {
			return fmt.Errorf("sqlite: recovery code %d requires an id, a selector and a verifier hash", i)
		}
	}

	now := time.Now().UTC()

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM recovery_codes
			WHERE tenant_id = ? AND subject_id = ? AND consumed_at IS NULL AND batch_id <> ?`,
			tenantID, subjectID, batchID); err != nil {
			return mapError(err)
		}

		for i, c := range codes {
			// The tenant, the subject and the batch come from the arguments
			// rather than from the code, so one mismatched element cannot scatter
			// a batch across two subjects.
			c.TenantID = tenantID
			c.SubjectID = subjectID
			c.BatchID = batchID
			if c.CreatedAt.IsZero() {
				c.CreatedAt = now
			}

			if _, err := tx.ExecContext(ctx, `
				INSERT INTO recovery_codes (`+recoveryColumns+`)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				c.ID, c.TenantID, c.SubjectID, c.BatchID, c.Selector, c.VerifierHash,
				formatTime(c.CreatedAt), formatTimePtr(c.ConsumedAt)); err != nil {
				return fmt.Errorf("code %d: %w", i, mapError(err))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sqlite: replace recovery codes: %w", err)
	}
	return nil
}

// GetRecoveryCodeBySelector implements store.RecoveryStore.
//
// The lookup is by selector so that verifying a presented code is one indexed
// probe plus one Argon2id evaluation. Matching on the verifier hash instead
// would mean evaluating Argon2id once per stored code, which is a
// denial-of-service vector aimed at the server's own CPU.
//
// A consumed code is still returned. The caller compares the verifier first and
// then decides, so that a code that is merely spent and a code that never
// existed take the same amount of work to reject.
func (s *Store) GetRecoveryCodeBySelector(ctx context.Context, tenantID, selector string) (*store.RecoveryCode, error) {
	if selector == "" {
		return nil, errors.New("sqlite: recovery code lookup requires a selector")
	}
	row := s.read.QueryRowContext(ctx, `
		SELECT `+recoveryColumns+` FROM recovery_codes
		WHERE tenant_id = ? AND selector = ?`,
		tenantID, selector)
	return scanRecoveryCode(row)
}

// ConsumeRecoveryCode implements store.RecoveryStore.
//
// The update is a compare-and-swap on consumed_at being NULL, in one statement,
// for the same reason as ConsumeTOTPStep: a single-use code that two concurrent
// requests both read as unused and both spend is not single-use at all. The
// database evaluates the condition while it holds the write lock, so exactly one
// of those requests can win.
//
// store.ErrStaleWrite is returned when the row exists and was already consumed.
// That is the losing side of the race, or a replay, and the correct response is
// a rejected authentication rather than a fault.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE recovery_codes SET consumed_at = ?
			WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL`,
			formatTime(at), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count recovery code update: %w", err)
		}
		if n == 1 {
			return nil
		}

		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM recovery_codes WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read recovery code: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: consume recovery code: %w", err)
	}
	return nil
}

// DeleteConsumedRecoveryCodes removes the codes spent before the given instant.
//
// It is the counterpart of the enrolment ticket sweep, and it exists for the
// same two reasons. A spent code is evidence of an authentication, so it is
// kept for long enough to answer a question about that authentication, and the
// durable record past that point is the audit log. And a code that stays
// keeps its selector, which is 30 bits and has to be unique within the tenant:
// a table nothing ever shrinks is one whose next batch is a little more likely
// to collide with something spent years ago and be refused. See
// internal/crypto/recovery on why the selector is that wide and why widening it
// is not the answer.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them, and the janitor is what chooses the retention window.
func (s *Store) DeleteConsumedRecoveryCodes(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM recovery_codes WHERE consumed_at IS NOT NULL AND consumed_at < ?`,
		formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete consumed recovery codes: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count deleted recovery codes: %w", err)
	}
	return n, nil
}

// CountUnusedRecoveryCodes implements store.RecoveryStore.
//
// The count drives the warning that tells a user to print a fresh sheet. A
// subject who reaches zero unused codes and holds no second factor has no route
// back into the account.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, tenantID, subjectID string) (int, error) {
	var n int
	err := s.read.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM recovery_codes
		WHERE tenant_id = ? AND subject_id = ? AND consumed_at IS NULL`,
		tenantID, subjectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("sqlite: count unused recovery codes: %w", err)
	}
	return n, nil
}

func scanRecoveryCode(sc rowScanner) (*store.RecoveryCode, error) {
	var (
		c          store.RecoveryCode
		createdAt  string
		consumedAt sql.NullString
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &c.SubjectID, &c.BatchID, &c.Selector, &c.VerifierHash,
		&createdAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if c.ConsumedAt, err = parseTimePtr(consumedAt); err != nil {
		return nil, err
	}
	return &c, nil
}
