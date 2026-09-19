package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const approvalColumns = `id, tenant_id, operation, payload, reason, status,
	requested_by, requested_at, expires_at, decided_by, decided_at, decision_note,
	executed_at, execution_error`

// CreateApproval implements store.ApprovalStore.
func (s *Store) CreateApproval(ctx context.Context, r *store.ApprovalRequest) error {
	if r.ID == "" || r.TenantID == "" {
		return errors.New("postgres: approval request requires an id and a tenant")
	}
	if r.Operation == "" {
		return errors.New("postgres: approval request requires an operation")
	}
	if strings.TrimSpace(r.RequestedBy) == "" {
		// Without a requester there is nobody for the second administrator to
		// differ from, and the dual-approval rule would be satisfied by anyone.
		return errors.New("postgres: approval request requires a requester")
	}
	if r.Status == "" {
		r.Status = store.ApprovalPending
	}
	if r.RequestedAt.IsZero() {
		r.RequestedAt = time.Now().UTC()
	}
	if r.ExpiresAt.IsZero() {
		return errors.New("postgres: approval request requires an expiry")
	}

	payload, err := jsonObject(r.Payload)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO approval_requests (`+approvalColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		r.ID, r.TenantID, r.Operation, payload, nullString(r.Reason), string(r.Status),
		r.RequestedBy, r.RequestedAt, r.ExpiresAt,
		nullString(r.DecidedBy), r.DecidedAt, nullString(r.DecisionNote),
		r.ExecutedAt, nullString(r.ExecutionError))
	if err != nil {
		return fmt.Errorf("postgres: create approval request: %w", mapError(err))
	}
	return nil
}

// GetApproval implements store.ApprovalStore.
func (s *Store) GetApproval(ctx context.Context, tenantID, id string) (*store.ApprovalRequest, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+approvalColumns+` FROM approval_requests
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return scanApproval(row)
}

// ListApprovals implements store.ApprovalStore.
//
// Oldest first, because the queue is worked from the front and a request that
// sits long enough will expire unactioned.
func (s *Store) ListApprovals(ctx context.Context, tenantID string, status store.ApprovalStatus,
	limit int) ([]*store.ApprovalRequest, error) {
	var a argset
	where := []string{"tenant_id = " + a.add(tenantID)}

	if status != "" {
		where = append(where, "status = "+a.add(string(status)))
	}

	query := `SELECT ` + approvalColumns + ` FROM approval_requests WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY requested_at ASC, id ASC LIMIT ` +
		a.add(clampLimit(limit, 50, 500))

	rows, err := s.pool.Query(ctx, query, a.args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list approval requests: %w", err)
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
		return nil, fmt.Errorf("postgres: iterate approval requests: %w", err)
	}
	return out, nil
}

// DecideApproval implements store.ApprovalStore.
//
// The refusals are the point of the method.
//
// A decision by the requester is refused with store.ErrSelfApproval. A
// two-administrator rule that one administrator can satisfy alone is not a
// control, and although PostgreSQL could carry the comparison as a CHECK, the
// rule stays in the store for both backends: one invariant held in two places
// drifts, and a deployment would then reject a decision on Postgres that SQLite
// accepts. The comparison ignores case and surrounding whitespace: a check an
// administrator defeats by capitalising their own identifier is not a check.
//
// The two sides are compared as principals and not as token identifiers. A
// rotation leaves one administrator holding two live tokens for the grace
// period, and a rule that compared the tokens let them ask with one and approve
// with the other; see adminPrincipal.
//
// A request that has expired is refused with store.ErrStaleWrite. The expiry
// exists so that a sensitive operation cannot be approved long after the
// circumstances that justified it, and an expired request is no more decidable
// than one already decided.
//
// A request that is not pending is refused with store.ErrStaleWrite, which is
// also how the losing side of two simultaneous decisions is told that the other
// one landed first. The conditional UPDATE is what makes that safe: both
// administrators can read a pending request, but the WHERE status = 'pending'
// predicate is re-evaluated against the committed row, so only one write can
// move it.
//
// The read that classifies the refusal does not need to share a transaction
// with that update. requested_by and expires_at are written once at insert and
// never modified, so the two values the classification depends on cannot change
// under it, and the status is guarded by the update itself.
func (s *Store) DecideApproval(ctx context.Context, tenantID, id, decidedBy string, approve bool, note string,
	at time.Time) (*store.ApprovalRequest, error) {
	if strings.TrimSpace(decidedBy) == "" {
		return nil, errors.New("postgres: deciding an approval requires an administrator")
	}

	status := store.ApprovalRejected
	if approve {
		status = store.ApprovalApproved
	}

	current, err := s.GetApproval(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: decide approval request: %w", err)
	}

	if current.Status != store.ApprovalPending {
		return nil, fmt.Errorf("%w: request is %s, not pending", store.ErrStaleWrite, current.Status)
	}
	if !at.Before(current.ExpiresAt) {
		return nil, fmt.Errorf("%w: request expired at %s", store.ErrStaleWrite,
			current.ExpiresAt.Format(time.RFC3339))
	}
	requester, err := s.adminPrincipal(ctx, tenantID, current.RequestedBy)
	if err != nil {
		return nil, err
	}
	decider, err := s.adminPrincipal(ctx, tenantID, decidedBy)
	if err != nil {
		return nil, err
	}
	if sameAdministrator(requester, decider) {
		return nil, store.ErrSelfApproval
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE approval_requests
		SET status = $1, decided_by = $2, decided_at = $3, decision_note = $4
		WHERE tenant_id = $5 AND id = $6 AND status = 'pending'
		RETURNING `+approvalColumns,
		string(status), decidedBy, at, nullString(note), tenantID, id)

	out, err := scanApproval(row)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: request is no longer pending", store.ErrStaleWrite)
		}
		return nil, fmt.Errorf("postgres: decide approval request: %w", err)
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

	var moved string
	err := s.pool.QueryRow(ctx, `
		UPDATE approval_requests
		SET status = $1, executed_at = $2, execution_error = $3
		WHERE tenant_id = $4 AND id = $5 AND status = 'approved'
		RETURNING id`,
		string(status), at, nullString(message), tenantID, id).Scan(&moved)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: mark approval executed: %w", mapError(err))
	}

	var exists int
	err = s.pool.QueryRow(ctx,
		`SELECT 1 FROM approval_requests WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: mark approval executed: read request: %w", err)
	}
	return fmt.Errorf("%w: request is not approved", store.ErrStaleWrite)
}

// ExpireApprovals implements store.ApprovalStore.
//
// The sweep runs across every tenant because the janitor is not acting on
// behalf of one, and the expiry of a request is not a decision anybody made.
// Only pending requests are touched, so a decision already recorded is never
// overwritten by the clock.
func (s *Store) ExpireApprovals(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE approval_requests SET status = 'expired'
		WHERE status = 'pending' AND expires_at < $1`,
		before)
	if err != nil {
		return 0, fmt.Errorf("postgres: expire approval requests: %w", mapError(err))
	}
	return tag.RowsAffected(), nil
}

// sameAdministrator reports whether two identifiers name one person, for the
// purpose of the dual-approval rule. See DecideApproval on why the comparison
// is not a byte equality.
func sameAdministrator(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// adminPrincipal resolves an administrative token to the principal it belongs
// to, which is the identifier the dual-approval rule compares.
//
// A token that was issued is its own principal. A token minted by a rotation
// carries the principal of the one it replaced, however many rotations back
// that was, so the line of tokens one administrator has held resolves to one
// value.
//
// An identifier that names no token in the tenant is returned as it was given.
// The rule then compares what it compared before there were principals, which
// refuses no less than it did; failing the decision instead would make a request
// undecidable once its requester's row was gone.
//
// Like the read above it, this does not need the update's transaction: a
// principal is written in the transaction that inserts the token and is never
// modified afterwards.
func (s *Store) adminPrincipal(ctx context.Context, tenantID, tokenID string) (string, error) {
	var principal string
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(principal_id, id) FROM admin_tokens WHERE tenant_id = $1 AND id = $2`,
		tenantID, strings.TrimSpace(tokenID)).Scan(&principal)
	if errors.Is(err, pgx.ErrNoRows) {
		return tokenID, nil
	}
	if err != nil {
		return "", fmt.Errorf("postgres: resolve administrator: %w", mapError(err))
	}
	return principal, nil
}

func scanApproval(sc rowScanner) (*store.ApprovalRequest, error) {
	var (
		r              store.ApprovalRequest
		payload        []byte
		reason         *string
		status         string
		requestedAt    time.Time
		expiresAt      time.Time
		decidedBy      *string
		decidedAt      *time.Time
		decisionNote   *string
		executedAt     *time.Time
		executionError *string
	)
	if err := sc.Scan(
		&r.ID, &r.TenantID, &r.Operation, &payload, &reason, &status, &r.RequestedBy,
		&requestedAt, &expiresAt, &decidedBy, &decidedAt, &decisionNote,
		&executedAt, &executionError,
	); err != nil {
		return nil, mapError(err)
	}

	var doc json.RawMessage
	var err error
	if doc, err = decodeJSONObject(payload); err != nil {
		return nil, err
	}

	r.Payload = doc
	r.RequestedAt = utc(requestedAt)
	r.ExpiresAt = utc(expiresAt)
	r.DecidedAt = utcPtr(decidedAt)
	r.ExecutedAt = utcPtr(executedAt)
	r.Status = store.ApprovalStatus(status)
	r.Reason = text(reason)
	r.DecidedBy = text(decidedBy)
	r.DecisionNote = text(decisionNote)
	r.ExecutionError = text(executionError)
	return &r, nil
}
