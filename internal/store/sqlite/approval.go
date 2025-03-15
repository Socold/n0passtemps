package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const approvalColumns = `id, tenant_id, operation, payload, reason, status,
	requested_by, requested_at, expires_at, decided_by, decided_at, decision_note,
	executed_at, execution_error`

// CreateApproval implements store.ApprovalStore.
func (s *Store) CreateApproval(ctx context.Context, r *store.ApprovalRequest) error {
	if r.ID == "" || r.TenantID == "" {
		return errors.New("sqlite: approval request requires an id and a tenant")
	}
	if r.Operation == "" {
		return errors.New("sqlite: approval request requires an operation")
	}
	if strings.TrimSpace(r.RequestedBy) == "" {
		// Without a requester there is nobody for the second administrator to
		// differ from, and the dual-approval rule would be satisfied by anyone.
		return errors.New("sqlite: approval request requires a requester")
	}
	if r.Status == "" {
		r.Status = store.ApprovalPending
	}
	if r.RequestedAt.IsZero() {
		r.RequestedAt = time.Now().UTC()
	}
	if r.ExpiresAt.IsZero() {
		return errors.New("sqlite: approval request requires an expiry")
	}

	payload, err := encodeJSONObject(r.Payload)
	if err != nil {
		return err
	}

	_, err = s.write.ExecContext(ctx, `
		INSERT INTO approval_requests (`+approvalColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.TenantID, r.Operation, payload, nullString(r.Reason), string(r.Status),
		r.RequestedBy, formatTime(r.RequestedAt), formatTime(r.ExpiresAt),
		nullString(r.DecidedBy), formatTimePtr(r.DecidedAt), nullString(r.DecisionNote),
		formatTimePtr(r.ExecutedAt), nullString(r.ExecutionError))
	if err != nil {
		return fmt.Errorf("sqlite: create approval request: %w", mapError(err))
	}
	return nil
}

// GetApproval implements store.ApprovalStore.
func (s *Store) GetApproval(ctx context.Context, tenantID, id string) (*store.ApprovalRequest, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+approvalColumns+` FROM approval_requests
		WHERE tenant_id = ? AND id = ?`,
		tenantID, id)
	return scanApproval(row)
}

// ListApprovals implements store.ApprovalStore.
//
// Oldest first, because the queue is worked from the front and a request that
// sits long enough will expire unactioned.
func (s *Store) ListApprovals(ctx context.Context, tenantID string, status store.ApprovalStatus, limit int) ([]*store.ApprovalRequest, error) {
	where := []string{"tenant_id = ?"}
	args := []any{tenantID}

	if status != "" {
		where = append(where, "status = ?")
		args = append(args, string(status))
	}

	args = append(args, clampLimit(limit, 50, 500))

	query := `SELECT ` + approvalColumns + ` FROM approval_requests WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY requested_at ASC, id ASC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list approval requests: %w", err)
	}
	defer rows.Close()

	var out []*store.ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate approval requests: %w", err)
	}
	return out, nil
}

// DecideApproval implements store.ApprovalStore.
//
// The refusals are the point of the method, so they are checked inside the same
// transaction as the update.
//
// A decision by the requester is refused with store.ErrSelfApproval. A
// two-administrator rule that one administrator can satisfy alone is not a
// control, and the schema cannot express the comparison on an UPDATE without a
// trigger, so it is enforced here. The comparison ignores case and surrounding
// whitespace: a check an administrator defeats by capitalising their own
// identifier is not a check.
//
// A request that has expired is refused with store.ErrStaleWrite. The expiry
// exists so that a sensitive operation cannot be approved long after the
// circumstances that justified it, and an expired request is no more decidable
// than one already decided.
//
// A request that is not pending is refused with store.ErrStaleWrite, which is
// also how the losing side of two simultaneous decisions is told that the other
// one landed first. The conditional UPDATE is what makes that safe: both
// administrators can read a pending request, but only one write can move it.
func (s *Store) DecideApproval(ctx context.Context, tenantID, id, decidedBy string, approve bool, note string, at time.Time) (*store.ApprovalRequest, error) {
	if strings.TrimSpace(decidedBy) == "" {
		return nil, errors.New("sqlite: deciding an approval requires an administrator")
	}

	status := store.ApprovalRejected
	if approve {
		status = store.ApprovalApproved
	}

	var out *store.ApprovalRequest
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+approvalColumns+` FROM approval_requests WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		current, err := scanApproval(row)
		if err != nil {
			return err
		}

		if current.Status != store.ApprovalPending {
			return fmt.Errorf("%w: request is %s, not pending", store.ErrStaleWrite, current.Status)
		}
		if !at.Before(current.ExpiresAt) {
			return fmt.Errorf("%w: request expired at %s", store.ErrStaleWrite,
				current.ExpiresAt.Format(time.RFC3339))
		}
		if sameAdministrator(current.RequestedBy, decidedBy) {
			return store.ErrSelfApproval
		}

		res, err := tx.ExecContext(ctx, `
			UPDATE approval_requests
			SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?
			WHERE tenant_id = ? AND id = ? AND status = 'pending'`,
			string(status), decidedBy, formatTime(at), nullString(note), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count approval decision: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: request is no longer pending", store.ErrStaleWrite)
		}

		row = tx.QueryRowContext(ctx,
			`SELECT `+approvalColumns+` FROM approval_requests WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		out, err = scanApproval(row)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) ||
			errors.Is(err, store.ErrSelfApproval) {
			return nil, err
		}
		return nil, fmt.Errorf("sqlite: decide approval request: %w", err)
	}
	return out, nil
}

// MarkApprovalExecuted implements store.ApprovalStore.
//
// The update is conditional on the request being approved, so a rejected or
// already executed request cannot be marked as run. Without the condition, a
// retry of the executor would run a sensitive operation a second time and
// record it as if it had only happened once.
func (s *Store) MarkApprovalExecuted(ctx context.Context, tenantID, id string, execErr error, at time.Time) error {
	status := store.ApprovalExecuted
	var message string
	if execErr != nil {
		status = store.ApprovalFailed
		message = execErr.Error()
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE approval_requests
			SET status = ?, executed_at = ?, execution_error = ?
			WHERE tenant_id = ? AND id = ? AND status = 'approved'`,
			string(status), formatTime(at), nullString(message), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count approval execution: %w", err)
		}
		if n == 1 {
			return nil
		}

		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM approval_requests WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read approval request: %w", err)
		}
		return fmt.Errorf("%w: request is not approved", store.ErrStaleWrite)
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: mark approval executed: %w", err)
	}
	return nil
}

// ExpireApprovals implements store.ApprovalStore.
//
// The sweep runs across every tenant because the janitor is not acting on
// behalf of one, and the expiry of a request is not a decision anybody made.
// Only pending requests are touched, so a decision already recorded is never
// overwritten by the clock.
func (s *Store) ExpireApprovals(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.write.ExecContext(ctx, `
		UPDATE approval_requests SET status = 'expired'
		WHERE status = 'pending' AND expires_at < ?`,
		formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlite: expire approval requests: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count expired approval requests: %w", err)
	}
	return n, nil
}

// sameAdministrator reports whether two identifiers name one person, for the
// purpose of the dual-approval rule. See DecideApproval on why the comparison
// is not a byte equality.
func sameAdministrator(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func scanApproval(sc rowScanner) (*store.ApprovalRequest, error) {
	var (
		r              store.ApprovalRequest
		payload        sql.NullString
		reason         sql.NullString
		status         string
		requestedAt    string
		expiresAt      string
		decidedBy      sql.NullString
		decidedAt      sql.NullString
		decisionNote   sql.NullString
		executedAt     sql.NullString
		executionError sql.NullString
	)
	if err := sc.Scan(
		&r.ID, &r.TenantID, &r.Operation, &payload, &reason, &status, &r.RequestedBy,
		&requestedAt, &expiresAt, &decidedBy, &decidedAt, &decisionNote,
		&executedAt, &executionError,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if r.RequestedAt, err = parseTime(requestedAt); err != nil {
		return nil, err
	}
	if r.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if r.DecidedAt, err = parseTimePtr(decidedAt); err != nil {
		return nil, err
	}
	if r.ExecutedAt, err = parseTimePtr(executedAt); err != nil {
		return nil, err
	}
	var doc json.RawMessage
	if doc, err = decodeJSONObject(payload); err != nil {
		return nil, err
	}
	r.Payload = doc
	r.Status = store.ApprovalStatus(status)
	r.Reason = stringOrEmpty(reason)
	r.DecidedBy = stringOrEmpty(decidedBy)
	r.DecisionNote = stringOrEmpty(decisionNote)
	r.ExecutionError = stringOrEmpty(executionError)
	return &r, nil
}
