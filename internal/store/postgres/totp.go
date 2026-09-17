package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const totpColumns = `id, tenant_id, subject_id, secret_sealed, algorithm, digits,
	period_seconds, last_timestep, label, created_at, confirmed_at, revoked_at`

// CreateTOTPSecret implements store.TOTPStore.
//
// An unconfirmed secret from a previous, abandoned enrolment is revoked in the
// same transaction. Leaving it in place would let a user who started enrolment
// twice end up with two live secrets, only one of which they hold.
func (s *Store) CreateTOTPSecret(ctx context.Context, sec *store.TOTPSecret) error {
	if sec.ID == "" || sec.TenantID == "" || sec.SubjectID == "" {
		return errors.New("postgres: totp secret requires id, tenant and subject")
	}
	if len(sec.SecretSealed) == 0 {
		return errors.New("postgres: totp secret must be sealed before storage")
	}
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = time.Now().UTC()
	}

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE totp_secrets SET revoked_at = $1
			WHERE tenant_id = $2 AND subject_id = $3
			  AND revoked_at IS NULL AND confirmed_at IS NULL`,
			sec.CreatedAt, sec.TenantID, sec.SubjectID); err != nil {
			return mapError(err)
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO totp_secrets (`+totpColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			sec.ID, sec.TenantID, sec.SubjectID, sec.SecretSealed, sec.Algorithm,
			sec.Digits, sec.PeriodSeconds, sec.LastTimestep, nullString(sec.Label),
			sec.CreatedAt, sec.ConfirmedAt, sec.RevokedAt)
		return mapError(err)
	})
	if err != nil {
		return fmt.Errorf("postgres: create totp secret: %w", err)
	}
	return nil
}

// GetActiveTOTPSecret implements store.TOTPStore.
//
// Only a confirmed, unrevoked secret is returned. An unconfirmed secret must
// not be usable for authentication: the user has been shown it but has not yet
// proved they can generate a code from it, so treating it as live would let a
// failed enrolment weaken the account.
func (s *Store) GetActiveTOTPSecret(ctx context.Context, tenantID, subjectID string) (*store.TOTPSecret, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+totpColumns+` FROM totp_secrets
		WHERE tenant_id = $1 AND subject_id = $2
		  AND revoked_at IS NULL AND confirmed_at IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, subjectID)
	return scanTOTPSecret(row)
}

// GetPendingTOTPSecret implements store.TOTPStore.
//
// It returns the most recent unconfirmed secret, which is what the enrolment
// confirmation step verifies against.
func (s *Store) GetPendingTOTPSecret(ctx context.Context, tenantID, subjectID string) (*store.TOTPSecret, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+totpColumns+` FROM totp_secrets
		WHERE tenant_id = $1 AND subject_id = $2
		  AND revoked_at IS NULL AND confirmed_at IS NULL
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, subjectID)
	return scanTOTPSecret(row)
}

// ConfirmTOTPSecret implements store.TOTPStore.
func (s *Store) ConfirmTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE totp_secrets SET confirmed_at = $1
		WHERE tenant_id = $2 AND id = $3 AND confirmed_at IS NULL AND revoked_at IS NULL`,
		at, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: confirm totp secret: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist, or it was already confirmed or revoked. The
		// three are not distinguished on purpose.
		return fmt.Errorf("postgres: confirm totp secret: %w", store.ErrNotFound)
	}
	return nil
}

// RevokeTOTPSecret implements store.TOTPStore.
func (s *Store) RevokeTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE totp_secrets SET revoked_at = $1
		WHERE tenant_id = $2 AND id = $3 AND revoked_at IS NULL`,
		at, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: revoke totp secret: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: revoke totp secret: %w", store.ErrNotFound)
	}
	return nil
}

// ConsumeTOTPStep implements store.TOTPStore.
//
// This is the anti-replay control.
//
// The update is conditional on two things at once: the stored high water mark
// is still what the caller read, and the step being consumed is strictly
// greater than it. Both conditions live in the WHERE clause, so the check and
// the write are one statement and one round trip, and RETURNING brings back the
// proof that this call is the one that moved the counter.
//
// The race this closes is concrete. A TOTP code stays valid for the whole
// period, typically thirty seconds. Two requests presenting the same code can
// both read last_timestep, both find the code valid, and both accept, which
// turns a one-time password into a password usable as many times as the window
// allows. Expressing the check as read-then-write in application code does not
// fix it; the condition has to be evaluated by the database while it holds the
// row.
//
// One statement is enough here, with no transaction and no raised isolation
// level. The UPDATE locks the row it matches until it commits, and a second
// UPDATE of the same row waits and then re-tests last_timestep against the
// committed value, so it matches nothing. The BEGIN IMMEDIATE the SQLite
// implementation depends on has no counterpart under MVCC.
//
// A false Accepted with a nil error is not a fault. It means the caller lost
// the race, or the step was already spent, and the correct response is to
// reject the authentication.
func (s *Store) ConsumeTOTPStep(ctx context.Context, tenantID, id string, expectedPrev,
	step int64) (store.TOTPConsumeResult, error) {
	var result store.TOTPConsumeResult

	if step <= expectedPrev {
		// The caller should not have got this far, but refusing here as well
		// means the invariant holds even if a caller forgets to check.
		result.PreviousStep = expectedPrev
		return result, nil
	}

	var written int64
	err := s.pool.QueryRow(ctx, `
		UPDATE totp_secrets
		SET last_timestep = $1
		WHERE tenant_id = $2 AND id = $3
		  AND last_timestep = $4
		  AND $1 > last_timestep
		  AND revoked_at IS NULL
		RETURNING last_timestep`,
		step, tenantID, id, expectedPrev).Scan(&written)
	if err == nil {
		result.Accepted = true
		result.PreviousStep = expectedPrev
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, fmt.Errorf("postgres: consume totp step: %w", mapError(err))
	}

	// The update matched nothing. Read the current value back so the caller can
	// tell a lost race from a missing row, and so the audit entry can record
	// what the counter actually was.
	var current int64
	err = s.pool.QueryRow(ctx,
		`SELECT last_timestep FROM totp_secrets WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, store.ErrNotFound
	}
	if err != nil {
		return result, fmt.Errorf("postgres: consume totp step: read timestep: %w", err)
	}
	result.PreviousStep = current
	return result, nil
}

func scanTOTPSecret(sc rowScanner) (*store.TOTPSecret, error) {
	var (
		sec         store.TOTPSecret
		label       *string
		createdAt   time.Time
		confirmedAt *time.Time
		revokedAt   *time.Time
	)
	if err := sc.Scan(
		&sec.ID, &sec.TenantID, &sec.SubjectID, &sec.SecretSealed, &sec.Algorithm,
		&sec.Digits, &sec.PeriodSeconds, &sec.LastTimestep, &label,
		&createdAt, &confirmedAt, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	sec.CreatedAt = utc(createdAt)
	sec.ConfirmedAt = utcPtr(confirmedAt)
	sec.RevokedAt = utcPtr(revokedAt)
	sec.Label = text(label)
	return &sec, nil
}
