package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const challengeColumns = `id, tenant_id, subject_id, ceremony, challenge, rp_id,
	session_data, created_at, expires_at, consumed_at`

// CreateChallenge implements store.ChallengeStore.
func (s *Store) CreateChallenge(ctx context.Context, c *store.Challenge) error {
	if c.ID == "" || c.TenantID == "" || len(c.Challenge) == 0 {
		return errors.New("sqlite: challenge requires id, tenant and challenge bytes")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("sqlite: challenge requires an expiry")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	_, err := s.write.ExecContext(ctx, `
		INSERT INTO webauthn_challenges (`+challengeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, nullString(c.SubjectID), string(c.Ceremony), c.Challenge,
		c.RPID, c.SessionData, formatTime(c.CreatedAt), formatTime(c.ExpiresAt),
		formatTimePtr(c.ConsumedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create challenge: %w", mapError(err))
	}
	return nil
}

// ConsumeChallenge implements store.ChallengeStore.
//
// The row is marked consumed and returned in one transaction, conditional on it
// not being consumed already and not having expired. A WebAuthn ceremony is two
// round trips, and without this a completion request could be replayed: the
// same signed assertion would be accepted twice, because nothing in the
// authenticator's response prevents a second submission.
//
// An unknown challenge, an expired one and an already consumed one all return
// ErrNotFound. Distinguishing them would tell an attacker whether a challenge
// they guessed ever existed.
func (s *Store) ConsumeChallenge(ctx context.Context, tenantID, id string, now time.Time) (*store.Challenge, error) {
	var out *store.Challenge

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE webauthn_challenges SET consumed_at = ?
			WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND expires_at > ?`,
			formatTime(now), tenantID, id, formatTime(now))
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count challenge update: %w", err)
		}
		if n != 1 {
			return store.ErrNotFound
		}

		row := tx.QueryRowContext(ctx,
			`SELECT `+challengeColumns+` FROM webauthn_challenges WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		out, err = scanChallenge(row)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("sqlite: consume challenge: %w", err)
	}
	return out, nil
}

// DeleteExpiredChallenges implements store.ChallengeStore.
//
// Consumed challenges are removed too, once they are past their expiry. They
// are kept until then so that a replayed completion arriving inside the
// original window is refused by ConsumeChallenge rather than by a missing row,
// which keeps the two cases indistinguishable to the caller.
func (s *Store) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM webauthn_challenges WHERE expires_at < ?`, formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired challenges: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count deleted challenges: %w", err)
	}
	return n, nil
}

func scanChallenge(sc rowScanner) (*store.Challenge, error) {
	var (
		c          store.Challenge
		subjectID  sql.NullString
		ceremony   string
		createdAt  string
		expiresAt  string
		consumedAt sql.NullString
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &subjectID, &ceremony, &c.Challenge, &c.RPID,
		&c.SessionData, &createdAt, &expiresAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if c.ConsumedAt, err = parseTimePtr(consumedAt); err != nil {
		return nil, err
	}
	c.SubjectID = stringOrEmpty(subjectID)
	c.Ceremony = store.Ceremony(ceremony)
	return &c, nil
}
