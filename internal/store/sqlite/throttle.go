package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const throttleColumns = `bucket_key, tenant_id, subject_id, window_start, attempts,
	failures, blocked_until, updated_at`

// Hit implements store.ThrottleStore.
//
// The window roll, the increment and the read back are one statement inside one
// transaction. Doing them as three round trips would let a burst slip through
// between the read and the write, which is precisely the burst the limiter
// exists to bound.
//
// The roll is expressed as a CASE over the stored window_start. When
// now - window_start has reached the window length the counters restart at this
// attempt; otherwise they increment. Both branches are evaluated by the engine
// against the row it is already holding, so no version of the row is ever read
// into Go and written back.
//
// The bucket is addressed by (tenant_id, bucket_key), the table's primary key,
// so no tenant can reach another tenant's counter.
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
func (s *Store) Hit(ctx context.Context, tenantID, bucketKey, subjectID string, window time.Duration, now time.Time,
	failure bool) (*store.ThrottleState, error) {
	if tenantID == "" || bucketKey == "" {
		return nil, errors.New("sqlite: throttle hit requires a tenant and a bucket key")
	}
	if window <= 0 {
		return nil, errors.New("sqlite: throttle hit requires a positive window")
	}

	var (
		nowStr = formatTime(now)
		// rollBefore is the newest window_start that is still old enough to
		// roll. Comparing the stored text against it is exact because the
		// timestamp layout is fixed width, so string order is time order.
		rollBefore = formatTime(now.Add(-window))
		failInc    = boolToInt(failure)
	)

	var out *store.ThrottleState
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// The conflict target is the composite primary key, so one tenant's
		// bucket can never be reached through another tenant's key. That is
		// what removes the cross-tenant collision the single-column key made
		// possible.
		//
		// subject_id is set with COALESCE so it is filled in on first sight and
		// never overwritten afterwards. A bucket belongs to one subject for its
		// whole life, and letting a later attempt rewrite the owner would
		// detach the row from the subject a purge has to find.
		row := tx.QueryRowContext(ctx, `
			INSERT INTO throttle_buckets (`+throttleColumns+`)
			VALUES (?, ?, ?, ?, 1, ?, NULL, ?)
			ON CONFLICT (tenant_id, bucket_key) DO UPDATE SET
				subject_id = COALESCE(throttle_buckets.subject_id, excluded.subject_id),
				window_start = CASE WHEN throttle_buckets.window_start <= ?
					THEN excluded.window_start ELSE throttle_buckets.window_start END,
				attempts = CASE WHEN throttle_buckets.window_start <= ?
					THEN 1 ELSE throttle_buckets.attempts + 1 END,
				failures = CASE WHEN throttle_buckets.window_start <= ?
					THEN ? ELSE throttle_buckets.failures + ? END,
				updated_at = excluded.updated_at
			RETURNING `+throttleColumns,
			bucketKey, tenantID, nullString(subjectID), nowStr, failInc, nowStr,
			rollBefore, rollBefore, rollBefore, failInc, failInc)

		st, err := scanThrottleState(row)
		if err != nil {
			return err
		}
		out = st
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("sqlite: throttle hit: %w", err)
	}
	return out, nil
}

// Block implements store.ThrottleStore.
//
// The bucket is created when it does not exist. A block can be applied by the
// administrative interface to a caller that has never been seen, and refusing
// that would mean an operator could not pre-emptively lock out an address.
func (s *Store) Block(ctx context.Context, tenantID, bucketKey string, until time.Time) error {
	if tenantID == "" || bucketKey == "" {
		return errors.New("sqlite: throttle block requires a tenant and a bucket key")
	}

	// The bucket is addressed by the composite primary key, so a block applied
	// under one tenant can never land on another tenant's counter. No tenant
	// predicate is needed on the DO UPDATE for that reason, and its absence is
	// what lets two tenants hold the same derived key independently.
	//
	// subject_id is left NULL on insert. A block created by this path is
	// applied by an operator to a bucket that has never been seen, so the
	// owner is not known; a later Hit fills it in through its COALESCE.
	now := formatTime(time.Now())
	res, err := s.write.ExecContext(ctx, `
		INSERT INTO throttle_buckets (`+throttleColumns+`)
		VALUES (?, ?, NULL, ?, 0, 0, ?, ?)
		ON CONFLICT (tenant_id, bucket_key) DO UPDATE SET
			blocked_until = excluded.blocked_until,
			updated_at = excluded.updated_at`,
		bucketKey, tenantID, now, formatTime(until), now)
	if err != nil {
		return fmt.Errorf("sqlite: throttle block: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: count throttle block: %w", err)
	}
	if n == 0 {
		// Neither branch of the upsert applied, which should not be reachable.
		// A lockout that silently failed to apply is worse than one that is
		// reported, so it is an error rather than a no-op.
		return fmt.Errorf("sqlite: throttle block: bucket %q was neither inserted nor updated", bucketKey)
	}
	return nil
}

// GetThrottle implements store.ThrottleStore.
//
// A bucket that has never been hit returns store.ErrNotFound, which the limiter
// reads as no constraint on this dimension.
func (s *Store) GetThrottle(ctx context.Context, tenantID, bucketKey string) (*store.ThrottleState, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+throttleColumns+` FROM throttle_buckets
		WHERE tenant_id = ? AND bucket_key = ?`,
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
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM throttle_buckets WHERE tenant_id = ? AND bucket_key = ?`,
		tenantID, bucketKey)
	if err != nil {
		return fmt.Errorf("sqlite: reset throttle: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: count reset throttle: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ResetSubjectThrottles implements store.ThrottleStore.
//
// The buckets are found through the subject_id column, not by inspecting the
// bucket key. The key is a SHA-256 digest by design, so it carries no
// recoverable structure and no pattern over it could locate a subject's rows.
//
// This is also what lets PurgeSubject remove a subject's throttle state, which
// is an erasure obligation rather than housekeeping: a counter keyed to a
// person is data about that person.
func (s *Store) ResetSubjectThrottles(ctx context.Context, tenantID, subjectID string) (int64, error) {
	if tenantID == "" || subjectID == "" {
		return 0, errors.New("sqlite: reset requires a tenant and a subject")
	}

	clause, args := subjectBucketPredicate(tenantID, subjectID)

	// #nosec G202 -- subjectBucketPredicate returns a fixed predicate string; the tenant and subject travel as ?
	// parameters
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM throttle_buckets WHERE `+clause, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlite: reset subject throttles: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count reset subject throttles: %w", err)
	}
	return n, nil
}

// DeleteStaleThrottles implements store.ThrottleStore.
//
// A bucket whose lockout has not yet expired is kept even when it has not been
// touched for a long time. Deleting it would end the lockout early, which turns
// the janitor into a way to unlock an account by waiting.
func (s *Store) DeleteStaleThrottles(ctx context.Context, before time.Time) (int64, error) {
	cut := formatTime(before)
	res, err := s.write.ExecContext(ctx, `
		DELETE FROM throttle_buckets
		WHERE updated_at < ? AND (blocked_until IS NULL OR blocked_until < ?)`,
		cut, cut)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete stale throttles: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count deleted throttles: %w", err)
	}
	return n, nil
}

// subjectBucketPredicate builds the clause matching every bucket that names the
// subject, together with its arguments. It is shared with PurgeSubject so that
// a purge and a reset agree on which buckets belong to a subject.
func subjectBucketPredicate(tenantID, subjectID string) (string, []any) {
	// Matching on the subject_id column rather than on the shape of the bucket
	// key. The key is a SHA-256 digest by design, so it carries no recoverable
	// structure and a LIKE pattern over it could never find a subject's rows.
	return `tenant_id = ? AND subject_id = ?`, []any{tenantID, subjectID}
}

func scanThrottleState(sc rowScanner) (*store.ThrottleState, error) {
	var (
		st           store.ThrottleState
		subjectID    sql.NullString
		windowStart  string
		blockedUntil sql.NullString
		updatedAt    string
	)
	if err := sc.Scan(
		&st.BucketKey, &st.TenantID, &subjectID, &windowStart, &st.Attempts,
		&st.Failures, &blockedUntil, &updatedAt,
	); err != nil {
		return nil, mapError(err)
	}
	st.SubjectID = stringOrEmpty(subjectID)

	var err error
	if st.WindowStart, err = parseTime(windowStart); err != nil {
		return nil, err
	}
	if st.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	if st.BlockedUntil, err = parseTimePtr(blockedUntil); err != nil {
		return nil, err
	}
	return &st, nil
}
