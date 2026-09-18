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

const alertColumns = `id, tenant_id, alert_type, severity, subject_id, resource_id,
	summary, detail, fingerprint, occurrences, first_seen_at, last_seen_at,
	acknowledged_at, acknowledged_by`

// RaiseAlert implements store.AlertStore.
//
// Repeated instances of one condition collapse onto a single row by
// fingerprint. An alert list that grows one row per failed login is an alert
// list nobody reads, and an operator who stops reading the list is the real
// failure this prevents.
//
// The deduplicating index is partial, ON (tenant_id, fingerprint) WHERE
// acknowledged_at IS NULL, so an acknowledged alert no longer takes part in it
// and the next occurrence of the same condition opens a fresh row. That is the
// behaviour wanted: acknowledging means the operator has dealt with what has
// happened so far, not that they have agreed never to be told again.
//
// SQLite matches a conflict target against a partial index only when the
// statement repeats the index predicate, which is why WHERE acknowledged_at IS
// NULL appears in the ON CONFLICT clause. This is verified by
// TestRaiseAlertDeduplicates; without the predicate the statement fails rather
// than silently inserting a duplicate.
//
// Only the occurrence count and last_seen_at move. first_seen_at stays so the
// row keeps saying when the condition started, which is what an operator needs
// in order to judge it, and severity, summary and detail keep the first
// observation. Taking them from the repeat would let a later, milder instance
// lower the severity of an open alert, which is a way to bury a critical
// condition under a stream of harmless ones.
func (s *Store) RaiseAlert(ctx context.Context, a *store.Alert) (*store.Alert, error) {
	if a.ID == "" || a.TenantID == "" {
		return nil, errors.New("sqlite: alert requires an id and a tenant")
	}
	if a.AlertType == "" || a.Fingerprint == "" {
		return nil, errors.New("sqlite: alert requires a type and a fingerprint")
	}
	switch a.Severity {
	case store.SeverityInfo, store.SeverityWarning, store.SeverityCritical:
	case "":
		a.Severity = store.SeverityWarning
	default:
		return nil, fmt.Errorf("sqlite: alert severity %q is not one of the three levels", a.Severity)
	}
	if a.FirstSeenAt.IsZero() {
		a.FirstSeenAt = time.Now().UTC()
	}
	if a.LastSeenAt.IsZero() {
		a.LastSeenAt = a.FirstSeenAt
	}
	if a.Occurrences < 1 {
		a.Occurrences = 1
	}

	detail, encodeErr := encodeJSONObject(a.Detail)
	if encodeErr != nil {
		return nil, encodeErr
	}

	var out *store.Alert
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			INSERT INTO alerts (`+alertColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
			ON CONFLICT (tenant_id, fingerprint) WHERE acknowledged_at IS NULL
			DO UPDATE SET
				occurrences = alerts.occurrences + 1,
				last_seen_at = excluded.last_seen_at
			RETURNING `+alertColumns,
			a.ID, a.TenantID, a.AlertType, string(a.Severity), nullString(a.SubjectID),
			nullString(a.ResourceID), a.Summary, detail, a.Fingerprint, a.Occurrences,
			formatTime(a.FirstSeenAt), formatTime(a.LastSeenAt))

		var err error
		out, err = scanAlert(row)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sqlite: raise alert: %w", err)
	}
	return out, nil
}

// ListAlerts implements store.AlertStore.
//
// Unacknowledged alerts only, unless the caller asks for the rest. The default
// is the queue an operator works from, and burying it under everything already
// dealt with is how it stops being read.
func (s *Store) ListAlerts(ctx context.Context, tenantID string, f store.AlertFilter) ([]*store.Alert, error) {
	where := []string{"tenant_id = ?"}
	args := []any{tenantID}

	if !f.IncludeAcked {
		where = append(where, "acknowledged_at IS NULL")
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, string(f.Severity))
	}
	if f.AlertType != "" {
		where = append(where, "alert_type = ?")
		args = append(args, f.AlertType)
	}
	if f.SubjectID != "" {
		where = append(where, "subject_id = ?")
		args = append(args, f.SubjectID)
	}
	if f.AfterID != "" {
		// Keyset paging on the same tuple the ORDER BY uses. An offset would
		// re-read every skipped row, and would also skip or repeat entries
		// when an alert's last_seen_at moves between two pages, which on a
		// live alert list happens constantly.
		where = append(where, `(last_seen_at, id) < (
			SELECT last_seen_at, id FROM alerts WHERE tenant_id = ? AND id = ?
		)`)
		args = append(args, tenantID, f.AfterID)
	}

	args = append(args, clampLimit(f.Limit, 50, 500))

	// Newest activity first, with the identifier breaking ties so that two
	// alerts last seen in the same instant keep a stable order between calls.
	// #nosec G202 -- alertColumns is a package constant and every where entry is a literal above, including the
	// keyset subquery; the filter values travel as ? parameters
	query := `SELECT ` + alertColumns + ` FROM alerts WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY last_seen_at DESC, id DESC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list alerts: %w", err)
	}
	defer rows.Close()

	var out []*store.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate alerts: %w", err)
	}
	return out, nil
}

// AcknowledgeAlert implements store.AlertStore.
//
// Conditional on the alert not being acknowledged already, so the record keeps
// the name of the operator who first dealt with it.
func (s *Store) AcknowledgeAlert(ctx context.Context, tenantID, id, by string, at time.Time) error {
	if by == "" {
		return errors.New("sqlite: acknowledging an alert requires an operator")
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ?
			WHERE tenant_id = ? AND id = ? AND acknowledged_at IS NULL`,
			formatTime(at), by, tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count alert acknowledgement: %w", err)
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: acknowledge alert: %w", err)
	}
	return nil
}

// CountOpenAlerts implements store.AlertStore.
//
// All three severities are present in the result, at zero when nothing is open
// at that level. A caller rendering a summary or comparing against a threshold
// then reads the map directly instead of guarding every lookup, and a missing
// key cannot be mistaken for a level that was never counted.
func (s *Store) CountOpenAlerts(ctx context.Context, tenantID string) (map[store.Severity]int, error) {
	out := map[store.Severity]int{
		store.SeverityInfo:     0,
		store.SeverityWarning:  0,
		store.SeverityCritical: 0,
	}

	rows, err := s.read.QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM alerts
		WHERE tenant_id = ? AND acknowledged_at IS NULL
		GROUP BY severity`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: count open alerts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			severity string
			n        int
		)
		if err := rows.Scan(&severity, &n); err != nil {
			return nil, fmt.Errorf("sqlite: scan open alert count: %w", err)
		}
		out[store.Severity(severity)] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate open alert counts: %w", err)
	}
	return out, nil
}

func scanAlert(sc rowScanner) (*store.Alert, error) {
	var (
		a              store.Alert
		severity       string
		subjectID      sql.NullString
		resourceID     sql.NullString
		detail         sql.NullString
		firstSeenAt    string
		lastSeenAt     string
		acknowledgedAt sql.NullString
		acknowledgedBy sql.NullString
	)
	if err := sc.Scan(
		&a.ID, &a.TenantID, &a.AlertType, &severity, &subjectID, &resourceID,
		&a.Summary, &detail, &a.Fingerprint, &a.Occurrences, &firstSeenAt,
		&lastSeenAt, &acknowledgedAt, &acknowledgedBy,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if a.FirstSeenAt, err = parseTime(firstSeenAt); err != nil {
		return nil, err
	}
	if a.LastSeenAt, err = parseTime(lastSeenAt); err != nil {
		return nil, err
	}
	if a.AcknowledgedAt, err = parseTimePtr(acknowledgedAt); err != nil {
		return nil, err
	}
	var doc json.RawMessage
	if doc, err = decodeJSONObject(detail); err != nil {
		return nil, err
	}
	a.Detail = doc
	a.Severity = store.Severity(severity)
	a.SubjectID = stringOrEmpty(subjectID)
	a.ResourceID = stringOrEmpty(resourceID)
	a.AcknowledgedBy = stringOrEmpty(acknowledgedBy)
	return &a, nil
}
