package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

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
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, tenantID, subjectID, batchID string, codes []*store.RecoveryCode) error {
	if tenantID == "" || subjectID == "" || batchID == "" {
		return errors.New("postgres: recovery batch requires a tenant, a subject and a batch id")
	}
	if len(codes) == 0 {
		return errors.New("postgres: recovery batch requires at least one code")
	}
	for i, c := range codes {
		if c == nil {
			return fmt.Errorf("postgres: recovery code %d is nil", i)
		}
		if c.ID == "" || c.Selector == "" || c.VerifierHash == "" {
			return fmt.Errorf("postgres: recovery code %d requires an id, a selector and a verifier hash", i)
		}
	}

	now := time.Now().UTC()

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			DELETE FROM recovery_codes
			WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL AND batch_id <> $3`,
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

			if _, err := tx.Exec(ctx, `
				INSERT INTO recovery_codes (`+recoveryColumns+`)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				c.ID, c.TenantID, c.SubjectID, c.BatchID, c.Selector, c.VerifierHash,
				c.CreatedAt, c.ConsumedAt); err != nil {
				return fmt.Errorf("code %d: %w", i, mapError(err))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: replace recovery codes: %w", err)
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
		return nil, errors.New("postgres: recovery code lookup requires a selector")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+recoveryColumns+` FROM recovery_codes
		WHERE tenant_id = $1 AND selector = $2`,
		tenantID, selector)
	return scanRecoveryCode(row)
}

// ConsumeRecoveryCode implements store.RecoveryStore.
//
// The update is a compare-and-swap on consumed_at being NULL, in one statement,
// for the same reason as ConsumeTOTPStep: a single-use code that two concurrent
// requests both read as unused and both spend is not single-use at all. The
// database evaluates the condition while it holds the row, so exactly one of
// those requests can win. The second one blocks on the row lock, then re-tests
// consumed_at against the committed value and matches nothing, which is why no
// transaction and no raised isolation level are needed around it.
//
// store.ErrStaleWrite is returned when the row exists and was already consumed.
// That is the losing side of the race, or a replay, and the correct response is
// a rejected authentication rather than a fault.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, tenantID, id string, at time.Time) error {
	var consumed time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE recovery_codes SET consumed_at = $1
		WHERE tenant_id = $2 AND id = $3 AND consumed_at IS NULL
		RETURNING consumed_at`,
		at, tenantID, id).Scan(&consumed)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: consume recovery code: %w", mapError(err))
	}

	var exists int
	err = s.pool.QueryRow(ctx,
		`SELECT 1 FROM recovery_codes WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: consume recovery code: read code: %w", err)
	}
	return store.ErrStaleWrite
}

// CountUnusedRecoveryCodes implements store.RecoveryStore.
//
// The count drives the warning that tells a user to print a fresh sheet. A
// subject who reaches zero unused codes and holds no second factor has no route
// back into the account.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, tenantID, subjectID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM recovery_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL`,
		tenantID, subjectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count unused recovery codes: %w", err)
	}
	return n, nil
}

func scanRecoveryCode(sc rowScanner) (*store.RecoveryCode, error) {
	var (
		c          store.RecoveryCode
		createdAt  time.Time
		consumedAt *time.Time
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &c.SubjectID, &c.BatchID, &c.Selector, &c.VerifierHash,
		&createdAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	c.CreatedAt = utc(createdAt)
	c.ConsumedAt = utcPtr(consumedAt)
	return &c, nil
}
