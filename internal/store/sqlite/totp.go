package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
		return errors.New("sqlite: totp secret requires id, tenant and subject")
	}
	if len(sec.SecretSealed) == 0 {
		return errors.New("sqlite: totp secret must be sealed before storage")
	}
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = time.Now().UTC()
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE totp_secrets SET revoked_at = ?
			WHERE tenant_id = ? AND subject_id = ?
			  AND revoked_at IS NULL AND confirmed_at IS NULL`,
			formatTime(sec.CreatedAt), sec.TenantID, sec.SubjectID); err != nil {
			return mapError(err)
		}

		_, err := tx.ExecContext(ctx, `
			INSERT INTO totp_secrets (`+totpColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sec.ID, sec.TenantID, sec.SubjectID, sec.SecretSealed, sec.Algorithm,
			sec.Digits, sec.PeriodSeconds, sec.LastTimestep, nullString(sec.Label),
			formatTime(sec.CreatedAt), formatTimePtr(sec.ConfirmedAt),
			formatTimePtr(sec.RevokedAt))
		return mapError(err)
	})
	if err != nil {
		return fmt.Errorf("sqlite: create totp secret: %w", err)
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
	row := s.read.QueryRowContext(ctx, `
		SELECT `+totpColumns+` FROM totp_secrets
		WHERE tenant_id = ? AND subject_id = ?
		  AND revoked_at IS NULL AND confirmed_at IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, subjectID)
	return scanTOTPSecret(row)
}

// GetPendingTOTPSecret returns the most recent unconfirmed secret, which is
// what the enrolment confirmation step verifies against.
func (s *Store) GetPendingTOTPSecret(ctx context.Context, tenantID, subjectID string) (*store.TOTPSecret, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+totpColumns+` FROM totp_secrets
		WHERE tenant_id = ? AND subject_id = ?
		  AND revoked_at IS NULL AND confirmed_at IS NULL
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, subjectID)
	return scanTOTPSecret(row)
}

// ConfirmTOTPSecret implements store.TOTPStore.
func (s *Store) ConfirmTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE totp_secrets SET confirmed_at = ?
			WHERE tenant_id = ? AND id = ? AND confirmed_at IS NULL AND revoked_at IS NULL`,
			formatTime(at), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			// Either it does not exist, or it was already confirmed or
			// revoked. The three are not distinguished on purpose.
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sqlite: confirm totp secret: %w", err)
	}
	return nil
}

// RevokeTOTPSecret implements store.TOTPStore.
func (s *Store) RevokeTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE totp_secrets SET revoked_at = ?
			WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
			formatTime(at), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sqlite: revoke totp secret: %w", err)
	}
	return nil
}

// ConsumeTOTPStep implements store.TOTPStore.
//
// This is the anti-replay control, and it is the reason the write pool holds a
// single connection and every write transaction is IMMEDIATE.
//
// The update is conditional on two things at once: the stored high water mark
// is still what the caller read, and the step being consumed is strictly
// greater than it. Both conditions live in the WHERE clause, so the check and
// the write are one statement and one round trip.
//
// The race this closes is concrete. A TOTP code stays valid for the whole
// period, typically thirty seconds. Two requests presenting the same code can
// both read last_timestep, both find the code valid, and both accept, which
// turns a one-time password into a password usable as many times as the window
// allows. Expressing the check as read-then-write in application code does not
// fix it; the condition has to be evaluated by the database while it holds the
// write lock.
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

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE totp_secrets
			SET last_timestep = ?
			WHERE tenant_id = ? AND id = ?
			  AND last_timestep = ?
			  AND ? > last_timestep
			  AND revoked_at IS NULL`,
			step, tenantID, id, expectedPrev, step)
		if err != nil {
			return mapError(err)
		}

		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count totp update: %w", err)
		}
		if n == 1 {
			result.Accepted = true
			result.PreviousStep = expectedPrev
			return nil
		}

		// The update matched nothing. Read the current value back so the
		// caller can tell a lost race from a missing row, and so the audit
		// entry can record what the counter actually was.
		var current int64
		err = tx.QueryRowContext(ctx,
			`SELECT last_timestep FROM totp_secrets WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read totp timestep: %w", err)
		}
		result.PreviousStep = current
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return result, err
		}
		return result, fmt.Errorf("sqlite: consume totp step: %w", err)
	}
	return result, nil
}

func scanTOTPSecret(sc rowScanner) (*store.TOTPSecret, error) {
	var (
		sec         store.TOTPSecret
		label       sql.NullString
		createdAt   string
		confirmedAt sql.NullString
		revokedAt   sql.NullString
	)
	if err := sc.Scan(
		&sec.ID, &sec.TenantID, &sec.SubjectID, &sec.SecretSealed, &sec.Algorithm,
		&sec.Digits, &sec.PeriodSeconds, &sec.LastTimestep, &label,
		&createdAt, &confirmedAt, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if sec.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if sec.ConfirmedAt, err = parseTimePtr(confirmedAt); err != nil {
		return nil, err
	}
	if sec.RevokedAt, err = parseTimePtr(revokedAt); err != nil {
		return nil, err
	}
	sec.Label = stringOrEmpty(label)
	return &sec, nil
}
