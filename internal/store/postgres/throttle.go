package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const throttleColumns = `bucket_key, tenant_id, subject_id, window_start, attempts,
	failures, blocked_until, updated_at`

// subjectBucketPredicate matches every bucket that names the subject. It is
// shared with PurgeSubject so that a purge and a reset agree on which buckets
// belong to a subject.
//
// It matches on the subject_id column rather than on the shape of the bucket
// key. The key is a SHA-256 digest by design, so it carries no recoverable
// structure and a LIKE pattern over it could never find a subject's rows.
//
// The placeholders are fixed at $1 and $2, so every statement that embeds the
// clause must bind the tenant first and the subject second and must have no
// other arguments.
const subjectBucketPredicate = `tenant_id = $1 AND subject_id = $2`

// Hit implements store.ThrottleStore.
//
// The window roll, the increment and the read back are one statement. Doing
// them as three round trips would let a burst slip through between the read and
// the write, which is precisely the burst the limiter exists to bound.
//
// The roll is expressed as a CASE over the stored window_start. When
// now - window_start has reached the window length the counters restart at this
// attempt; otherwise they increment. Both branches are evaluated by the engine
// against the row it is already holding, so no version of the row is ever read
// into Go and written back. Because it is one statement it needs neither a
// transaction nor a raised isolation level: a concurrent Hit on the same bucket
// waits on the row lock and then applies its own CASE to the committed counters.
//
// The bucket is addressed by (tenant_id, bucket_key), the table's composite
// primary key, and that pair is also the conflict target, so no tenant can
// reach another tenant's counter and two tenants deriving the same key hold two
// independent counters.
//
// subject_id is set with COALESCE so it is filled in on first sight and never
// overwritten afterwards. A bucket belongs to one subject for its whole life,
// and letting a later attempt rewrite the owner would detach the row from the
// subject a purge has to find.
//
// blocked_until is not mentioned in the DO UPDATE and therefore survives the
// roll. This is deliberate: a lockout runs on its own clock, and clearing it
// because the counting window happened to roll over would hand an attacker a
// way to shorten every lockout to one window.
//
// attempts always increments, because volume is what bounds a leaked API key.
// failures increments only when failure is true, because a user who
// authenticates successfully fifty times in an afternoon has done nothing that
// should count towards a lockout.
func (s *Store) Hit(ctx context.Context, tenantID, bucketKey, subjectID string, window time.Duration, now time.Time, failure bool) (*store.ThrottleState, error) {
	if tenantID == "" || bucketKey == "" {
		return nil, errors.New("postgres: throttle hit requires a tenant and a bucket key")
	}
	if window <= 0 {
		return nil, errors.New("postgres: throttle hit requires a positive window")
	}

	// rollBefore is the newest window_start that is still old enough to roll.
	// The comparison is between two TIMESTAMPTZ values, so it is an ordinary
	// instant comparison rather than the text comparison the SQLite
	// implementation relies on its fixed-width layout for.
	rollBefore := now.Add(-window)

	failInc := 0
	if failure {
		failInc = 1
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO throttle_buckets (`+throttleColumns+`)
		VALUES ($1, $2, $3, $4, 1, $5, NULL, $4)
		ON CONFLICT (tenant_id, bucket_key) DO UPDATE SET
			subject_id = COALESCE(throttle_buckets.subject_id, excluded.subject_id),
			window_start = CASE WHEN throttle_buckets.window_start <= $6
				THEN excluded.window_start ELSE throttle_buckets.window_start END,
			attempts = CASE WHEN throttle_buckets.window_start <= $6
				THEN 1 ELSE throttle_buckets.attempts + 1 END,
			failures = CASE WHEN throttle_buckets.window_start <= $6
				THEN $5 ELSE throttle_buckets.failures + $5 END,
			updated_at = excluded.updated_at
		RETURNING `+throttleColumns,
		bucketKey, tenantID, nullString(subjectID), now, failInc, rollBefore)

	out, err := scanThrottleState(row)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: throttle hit: %w", err)
	}
	return out, nil
}

// Block implements store.ThrottleStore.
//
// The bucket is created when it does not exist. A block can be applied by the
// administrative interface to a caller that has never been seen, and refusing
// that would mean an operator could not pre-emptively lock out an address.
//
// The bucket is addressed by the composite primary key, so a block applied
// under one tenant can never land on another tenant's counter. No tenant
// predicate is needed on the DO UPDATE for that reason, and its absence is what
// lets two tenants hold the same derived key independently.
//
// subject_id is left NULL on insert. A block created by this path is applied by
// an operator to a bucket that has never been seen, so the owner is not known;
// a later Hit fills it in through its COALESCE.
func (s *Store) Block(ctx context.Context, tenantID, bucketKey string, until time.Time) error {
	if tenantID == "" || bucketKey == "" {
		return errors.New("postgres: throttle block requires a tenant and a bucket key")
	}

	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO throttle_buckets (`+throttleColumns+`)
		VALUES ($1, $2, NULL, $3, 0, 0, $4, $3)
		ON CONFLICT (tenant_id, bucket_key) DO UPDATE SET
			blocked_until = excluded.blocked_until,
			updated_at = excluded.updated_at`,
		bucketKey, tenantID, now, until)
	if err != nil {
		return fmt.Errorf("postgres: throttle block: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		// Neither branch of the upsert applied, which should not be reachable.
		// A lockout that silently failed to apply is worse than one that is
		// reported, so it is an error rather than a no-op.
		return fmt.Errorf("postgres: throttle block: bucket %q was neither inserted nor updated", bucketKey)
	}
	return nil
}

// GetThrottle implements store.ThrottleStore.
//
// A bucket that has never been hit returns store.ErrNotFound, which the limiter
// reads as no constraint on this dimension.
func (s *Store) GetThrottle(ctx context.Context, tenantID, bucketKey string) (*store.ThrottleState, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+throttleColumns+` FROM throttle_buckets
		WHERE tenant_id = $1 AND bucket_key = $2`,
		tenantID, bucketKey)
	return scanThrottleState(row)
}

// ResetThrottle implements store.ThrottleStore.
//
// The row is deleted rather than zeroed, so the next attempt starts a fresh
// window instead of continuing in the one the lockout was served under. An
// absent bucket reports store.ErrNotFound; the administrative unlock treats
// that as success, since a bucket that does not exist imposes no limit.
func (s *Store) ResetThrottle(ctx context.Context, tenantID, bucketKey string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM throttle_buckets WHERE tenant_id = $1 AND bucket_key = $2`,
		tenantID, bucketKey)
	if err != nil {
		return fmt.Errorf("postgres: reset throttle: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ResetSubjectThrottles implements store.ThrottleStore.
//
// One subject is throttled under several keys at once, and a key derived by
// internal/throttle is a hash that no predicate can match, which is why
// throttle_buckets carries subject_id at all. Limiter.ResetSubject clears its
// own derived bucket through ResetThrottle and then calls this for whatever
// else the schema associates with the subject. Neither call is sufficient
// alone.
func (s *Store) ResetSubjectThrottles(ctx context.Context, tenantID, subjectID string) (int64, error) {
	if tenantID == "" || subjectID == "" {
		return 0, errors.New("postgres: reset requires a tenant and a subject")
	}

	tag, err := s.pool.Exec(ctx,
		`DELETE FROM throttle_buckets WHERE `+subjectBucketPredicate, tenantID, subjectID)
	if err != nil {
		return 0, fmt.Errorf("postgres: reset subject throttles: %w", mapError(err))
	}
	return tag.RowsAffected(), nil
}

// DeleteStaleThrottles implements store.ThrottleStore.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them.
//
// A bucket whose lockout has not yet expired is kept even when it has not been
// touched for a long time. Deleting it would end the lockout early, which turns
// the janitor into a way to unlock an account by waiting.
func (s *Store) DeleteStaleThrottles(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM throttle_buckets
		WHERE updated_at < $1 AND (blocked_until IS NULL OR blocked_until < $1)`,
		before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete stale throttles: %w", mapError(err))
	}
	return tag.RowsAffected(), nil
}

func scanThrottleState(sc rowScanner) (*store.ThrottleState, error) {
	var (
		st           store.ThrottleState
		subjectID    *string
		windowStart  time.Time
		blockedUntil *time.Time
		updatedAt    time.Time
	)
	if err := sc.Scan(
		&st.BucketKey, &st.TenantID, &subjectID, &windowStart, &st.Attempts,
		&st.Failures, &blockedUntil, &updatedAt,
	); err != nil {
		return nil, mapError(err)
	}

	st.SubjectID = text(subjectID)
	st.WindowStart = utc(windowStart)
	st.UpdatedAt = utc(updatedAt)
	st.BlockedUntil = utcPtr(blockedUntil)
	return &st, nil
}
