package postgres

import (
	"context"
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
		return errors.New("postgres: challenge requires id, tenant and challenge bytes")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("postgres: challenge requires an expiry")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO webauthn_challenges (`+challengeColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, c.TenantID, nullString(c.SubjectID), string(c.Ceremony), c.Challenge,
		c.RPID, c.SessionData, c.CreatedAt, c.ExpiresAt, c.ConsumedAt)
	if err != nil {
		return fmt.Errorf("postgres: create challenge: %w", mapError(err))
	}
	return nil
}

// ConsumeChallenge implements store.ChallengeStore.
//
// The row is marked consumed and returned by one statement, conditional on it
// not being consumed already and not having expired. A WebAuthn ceremony is two
// round trips, and without this a completion request could be replayed: the
// same signed assertion would be accepted twice, because nothing in the
// authenticator's response prevents a second submission.
//
// RETURNING hands back the whole row, so the mark and the read are a single
// statement rather than the update-then-select pair the SQLite implementation
// has to wrap in a transaction. There is nothing between them for a concurrent
// consumer to slip into.
//
// An unknown challenge, an expired one and an already consumed one all return
// ErrNotFound. Distinguishing them would tell an attacker whether a challenge
// they guessed ever existed.
func (s *Store) ConsumeChallenge(ctx context.Context, tenantID, id string, now time.Time) (*store.Challenge, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE webauthn_challenges SET consumed_at = $1
		WHERE tenant_id = $2 AND id = $3 AND consumed_at IS NULL AND expires_at > $1
		RETURNING `+challengeColumns,
		now, tenantID, id)

	out, err := scanChallenge(row)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: consume challenge: %w", err)
	}
	return out, nil
}

// DeleteExpiredChallenges implements store.ChallengeStore.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them and an expired challenge belongs to nobody.
//
// Consumed challenges are removed too, once they are past their expiry. They
// are kept until then so that a replayed completion arriving inside the
// original window is refused by ConsumeChallenge rather than by a missing row,
// which keeps the two cases indistinguishable to the caller.
//
// The console's ceremony state lives in its own table, so that neither ceremony
// can be completed through the other's route, and is collected here rather than
// by a sweep of its own. One statement covers both, so the count the janitor
// logs describes a state the database was actually in.
func (s *Store) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	err := s.pool.QueryRow(ctx, `
		WITH subject_rows AS (
			DELETE FROM webauthn_challenges WHERE expires_at < $1 RETURNING 1
		), admin_rows AS (
			DELETE FROM admin_webauthn_challenges WHERE expires_at < $1 RETURNING 1
		)
		SELECT (SELECT COUNT(*) FROM subject_rows) + (SELECT COUNT(*) FROM admin_rows)`,
		before).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired challenges: %w", mapError(err))
	}
	return total, nil
}

func scanChallenge(sc rowScanner) (*store.Challenge, error) {
	var (
		c          store.Challenge
		subjectID  *string
		ceremony   string
		createdAt  time.Time
		expiresAt  time.Time
		consumedAt *time.Time
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &subjectID, &ceremony, &c.Challenge, &c.RPID,
		&c.SessionData, &createdAt, &expiresAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	c.CreatedAt = utc(createdAt)
	c.ExpiresAt = utc(expiresAt)
	c.ConsumedAt = utcPtr(consumedAt)
	c.SubjectID = text(subjectID)
	c.Ceremony = store.Ceremony(ceremony)
	return &c, nil
}
