package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const erasureColumns = `id, tenant_id, subject_id, status, reason, requested_by,
	requested_at, purge_after, cancelled_by, cancelled_at, purged_at`

// CreateErasure implements store.ErasureStore.
//
// A second pending request for the same subject violates the partial unique
// index er_subject_uq and surfaces as store.ErrConflict. That is the wanted
// behaviour: two pending requests would mean two purge deadlines for one
// subject, and cancelling one of them would leave the other running.
func (s *Store) CreateErasure(ctx context.Context, r *store.ErasureRequest) error {
	if r.ID == "" || r.TenantID == "" || r.SubjectID == "" {
		return errors.New("postgres: erasure request requires an id, a tenant and a subject")
	}
	if r.RequestedBy == "" {
		return errors.New("postgres: erasure request requires a requester")
	}
	if r.Status == "" {
		r.Status = store.ErasurePending
	}
	if r.RequestedAt.IsZero() {
		r.RequestedAt = time.Now().UTC()
	}
	if r.PurgeAfter.IsZero() {
		// The retention window is the whole point of the two-phase design. A
		// request with no deadline would either purge at once, destroying the
		// trail that proves the erasure was legitimate, or never.
		return errors.New("postgres: erasure request requires a purge deadline")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO erasure_requests (`+erasureColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		r.ID, r.TenantID, r.SubjectID, string(r.Status), nullString(r.Reason),
		r.RequestedBy, r.RequestedAt, r.PurgeAfter,
		nullString(r.CancelledBy), r.CancelledAt, r.PurgedAt)
	if err != nil {
		return fmt.Errorf("postgres: create erasure request: %w", mapError(err))
	}
	return nil
}

// GetErasureBySubject implements store.ErasureStore.
//
// A pending request is preferred over anything else, because that is the one
// imposing a deadline on the subject, and the schema allows only one of them at
// a time. When none is pending the most recent request is returned instead, so
// that a caller can tell a subject that has been erased and reinstated from one
// that has never been the subject of a request. The status travels on the row,
// so the two cases are distinguishable without a second method.
func (s *Store) GetErasureBySubject(ctx context.Context, tenantID, subjectID string) (*store.ErasureRequest, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+erasureColumns+` FROM erasure_requests
		WHERE tenant_id = $1 AND subject_id = $2
		ORDER BY CASE WHEN status = 'pending' THEN 0 ELSE 1 END, requested_at DESC
		LIMIT 1`,
		tenantID, subjectID)
	return scanErasure(row)
}

// CancelErasure implements store.ErasureStore.
//
// Only a pending request can be cancelled. A purged request cannot: the data is
// gone, and recording the request as cancelled would claim otherwise. That case
// reports store.ErrStaleWrite rather than store.ErrNotFound, since the row is
// there and it is the state that refuses.
func (s *Store) CancelErasure(ctx context.Context, tenantID, id, by string, at time.Time) error {
	if by == "" {
		return errors.New("postgres: cancelling an erasure requires an actor")
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE erasure_requests
		SET status = 'cancelled', cancelled_by = $1, cancelled_at = $2
		WHERE tenant_id = $3 AND id = $4 AND status = 'pending'`,
		by, at, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: cancel erasure request: %w", mapError(err))
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if err := s.erasureStateError(ctx, tenantID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("postgres: cancel erasure request: %w", err)
	}
	return nil
}

// ListDueErasures implements store.ErasureStore.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them, and takes the oldest deadlines first so a backlog drains in the order
// the deadlines fell due.
func (s *Store) ListDueErasures(ctx context.Context, before time.Time, limit int) ([]*store.ErasureRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+erasureColumns+` FROM erasure_requests
		WHERE status = 'pending' AND purge_after <= $1
		ORDER BY purge_after ASC, id ASC LIMIT $2`,
		before, clampLimit(limit, 100, 1000))
	if err != nil {
		return nil, fmt.Errorf("postgres: list due erasures: %w", err)
	}
	defer rows.Close()

	var out []*store.ErasureRequest
	for rows.Next() {
		r, err := scanErasure(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate due erasures: %w", err)
	}
	return out, nil
}

// MarkErasurePurged implements store.ErasureStore.
//
// Conditional on the request still being pending, which is what stops a second
// janitor pass from marking an already purged request again and what stops a
// cancelled request from being recorded as carried out.
func (s *Store) MarkErasurePurged(ctx context.Context, tenantID, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE erasure_requests SET status = 'purged', purged_at = $1
		WHERE tenant_id = $2 AND id = $3 AND status = 'pending'`,
		at, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: mark erasure purged: %w", mapError(err))
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if err := s.erasureStateError(ctx, tenantID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("postgres: mark erasure purged: %w", err)
	}
	return nil
}

// erasureStateError separates a request that is not there from one whose status
// has moved on, because the two call for different responses: the first is a
// caller error, the second a race with the janitor or with another operator.
func (s *Store) erasureStateError(ctx context.Context, tenantID, id string) error {
	var status string
	err := s.pool.QueryRow(ctx,
		`SELECT status FROM erasure_requests WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: read erasure request: %w", err)
	}
	return fmt.Errorf("%w: request is %s, not pending", store.ErrStaleWrite, status)
}

func scanErasure(sc rowScanner) (*store.ErasureRequest, error) {
	var (
		r           store.ErasureRequest
		status      string
		reason      *string
		requestedAt time.Time
		purgeAfter  time.Time
		cancelledBy *string
		cancelledAt *time.Time
		purgedAt    *time.Time
	)
	if err := sc.Scan(
		&r.ID, &r.TenantID, &r.SubjectID, &status, &reason, &r.RequestedBy,
		&requestedAt, &purgeAfter, &cancelledBy, &cancelledAt, &purgedAt,
	); err != nil {
		return nil, mapError(err)
	}

	r.RequestedAt = utc(requestedAt)
	r.PurgeAfter = utc(purgeAfter)
	r.CancelledAt = utcPtr(cancelledAt)
	r.PurgedAt = utcPtr(purgedAt)
	r.Status = store.ErasureStatus(status)
	r.Reason = text(reason)
	r.CancelledBy = text(cancelledBy)
	return &r, nil
}
