package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const subjectColumns = `id, tenant_id, ref_hmac, ref_sealed, display_name, status,
	created_at, updated_at, deleted_at`

// UpsertSubject implements store.SubjectStore.
//
// The statement is an INSERT with a DO UPDATE on (tenant_id, ref_hmac), which
// is the unique index the schema declares. Idempotence matters because an
// integrating application is expected to call this on every login rather than
// probing for existence first, and a read followed by a conditional insert
// would let two concurrent first logins for the same reference both insert.
//
// Three columns are deliberately not overwritten on conflict.
//
// ref_sealed and display_name are refreshed only when the incoming value is
// non-empty. A caller that holds the reference HMAC but not the sealed original,
// which is the normal case once the subject exists, would otherwise blank the
// only copy of the encrypted reference and with it the ability to honour an
// access request.
//
// status is left alone, so a locked or pending-deletion subject cannot be
// returned to active service by the side effect of an ordinary login. Likewise
// deleted_at: resurrecting a soft-deleted subject is an administrative act, not
// something a login performs silently. The returned row carries deleted_at, so
// a caller can see that the subject it has upserted is not usable.
func (s *Store) UpsertSubject(ctx context.Context, sub *store.Subject) (*store.Subject, error) {
	if sub.ID == "" || sub.TenantID == "" {
		return nil, errors.New("sqlite: subject requires an id and a tenant")
	}
	if len(sub.RefHMAC) == 0 {
		return nil, errors.New("sqlite: subject requires a reference hmac")
	}
	if sub.Status == "" {
		sub.Status = store.SubjectActive
	}
	now := time.Now().UTC()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now

	var out *store.Subject
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			INSERT INTO subjects (`+subjectColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
			ON CONFLICT (tenant_id, ref_hmac) DO UPDATE SET
				ref_sealed = CASE
					WHEN excluded.ref_sealed IS NOT NULL AND length(excluded.ref_sealed) > 0
					THEN excluded.ref_sealed ELSE subjects.ref_sealed END,
				display_name = COALESCE(NULLIF(excluded.display_name, ''), subjects.display_name),
				updated_at = excluded.updated_at
			RETURNING `+subjectColumns,
			sub.ID, sub.TenantID, sub.RefHMAC, sub.RefSealed, nullString(sub.DisplayName),
			string(sub.Status), formatTime(sub.CreatedAt), formatTime(sub.UpdatedAt))

		var err error
		out, err = scanSubject(row)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sqlite: upsert subject: %w", err)
	}
	return out, nil
}

// GetSubject implements store.SubjectStore.
//
// A soft-deleted subject returns store.ErrNotFound. The row survives the
// erasure request's retention window so the audit trail stays meaningful, but
// it must be invisible to everything on the authentication path: a subject
// whose deletion is pending is not allowed to authenticate, and the safest way
// to guarantee that is for the store never to hand the row out.
func (s *Store) GetSubject(ctx context.Context, tenantID, id string) (*store.Subject, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+subjectColumns+` FROM subjects
		WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
		tenantID, id)
	return scanSubject(row)
}

// GetSubjectByRef implements store.SubjectStore.
//
// The lookup is by HMAC because that is the only form of the reference stored in
// the clear. Soft-deleted subjects are excluded for the reason given on
// GetSubject.
func (s *Store) GetSubjectByRef(ctx context.Context, tenantID string, refHMAC []byte) (*store.Subject, error) {
	if len(refHMAC) == 0 {
		return nil, errors.New("sqlite: subject lookup requires a reference hmac")
	}
	row := s.read.QueryRowContext(ctx, `
		SELECT `+subjectColumns+` FROM subjects
		WHERE tenant_id = ? AND ref_hmac = ? AND deleted_at IS NULL`,
		tenantID, refHMAC)
	return scanSubject(row)
}

// ListSubjects implements store.SubjectStore.
//
// Paging is by keyset on the primary key rather than by OFFSET. An offset scan
// re-reads every skipped row, so later pages get steadily slower, and a row
// inserted while an operator pages through the list shifts the window and hides
// a subject entirely.
//
// Soft-deleted subjects are excluded, matching the two getters.
func (s *Store) ListSubjects(ctx context.Context, tenantID string, f store.SubjectFilter) ([]*store.Subject, error) {
	where := []string{"tenant_id = ?", "deleted_at IS NULL"}
	args := []any{tenantID}

	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, string(f.Status))
	}
	if len(f.RefHMAC) > 0 {
		// Exact match only. The reference is stored encrypted precisely so that
		// it cannot be scanned, so there is no substring search to offer.
		where = append(where, "ref_hmac = ?")
		args = append(args, f.RefHMAC)
	}
	if f.AfterID != "" {
		where = append(where, "id > ?")
		args = append(args, f.AfterID)
	}

	args = append(args, clampLimit(f.Limit, 50, 500))

	query := `SELECT ` + subjectColumns + ` FROM subjects WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY id ASC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list subjects: %w", err)
	}
	defer rows.Close()

	var out []*store.Subject
	for rows.Next() {
		sub, err := scanSubject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate subjects: %w", err)
	}
	return out, nil
}

// SetSubjectStatus implements store.SubjectStore.
//
// The update refuses to touch a soft-deleted subject, so a status change cannot
// be used to bring one back into service by a route that bypasses the erasure
// workflow.
func (s *Store) SetSubjectStatus(ctx context.Context, tenantID, id string, status store.SubjectStatus) error {
	if status == "" {
		return errors.New("sqlite: subject status is required")
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE subjects SET status = ?, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
			string(status), formatTime(time.Now()), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count subject update: %w", err)
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
		return fmt.Errorf("sqlite: set subject status: %w", err)
	}
	return nil
}

// SoftDeleteSubject implements store.SubjectStore.
//
// The status is moved to pending_deletion and deleted_at is stamped in the same
// statement. Both are set because they answer different questions: the status
// is what an operator sees in the administration interface, and deleted_at is
// what every getter filters on, so a row that had only one of them would either
// stay visible or stay unexplained.
//
// It is idempotent. A second erasure request for the same subject is not an
// error, and returning one would make the retry of a partially failed workflow
// fail for the wrong reason.
func (s *Store) SoftDeleteSubject(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE subjects
			SET status = ?, deleted_at = ?, updated_at = ?
			WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
			string(store.SubjectPendingDeletion), formatTime(at), formatTime(at),
			tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count subject soft delete: %w", err)
		}
		if n == 1 {
			return nil
		}

		// Nothing was updated. Either the subject does not exist, or it is
		// already soft-deleted, and only the first is an error.
		var deleted sql.NullString
		err = tx.QueryRowContext(ctx,
			`SELECT deleted_at FROM subjects WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&deleted)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read subject deletion state: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: soft delete subject: %w", err)
	}
	return nil
}

// RestoreSubject implements store.SubjectStore.
//
// The update is conditional on the subject being pending deletion, so it cannot
// be used to reactivate a subject an operator locked: a lock and an erasure are
// different decisions, and cancelling one must not undo the other.
func (s *Store) RestoreSubject(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE subjects
			SET status = ?, deleted_at = NULL, updated_at = ?
			WHERE tenant_id = ? AND id = ?
			  AND deleted_at IS NOT NULL AND status = ?`,
			string(store.SubjectActive), formatTime(at), tenantID, id,
			string(store.SubjectPendingDeletion))
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count subject restore: %w", err)
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
		return fmt.Errorf("sqlite: restore subject: %w", err)
	}
	return nil
}

// PurgeSubject implements store.SubjectStore.
//
// This is the hard delete at the end of the erasure retention window, and it
// runs in one transaction so that a failure part way through cannot leave a
// subject whose credentials are gone but whose row remains, or the reverse.
//
// webauthn_credentials, totp_secrets and recovery_codes carry an ON DELETE
// CASCADE to subjects and are removed by the engine. The foreign_keys pragma is
// verified at open time, because without it those cascades are silently inert.
//
// webauthn_challenges and throttle_buckets have no foreign key, the first
// because a registration ceremony starts before the subject exists and the
// second because a bucket is addressed by an opaque key rather than by a row
// reference. Both are therefore deleted explicitly.
//
// audit_log is deliberately untouched. Erasure of audit entries rewrites them in
// place through EraseSubjectAuditEntries, which keeps the hash chain verifiable;
// deleting them here would break verification for every entry that follows.
func (s *Store) PurgeSubject(ctx context.Context, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return errors.New("sqlite: purge requires a tenant and a subject")
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// Confirm the subject belongs to this tenant before anything is
		// removed, so a purge aimed at another tenant's identifier deletes
		// nothing at all rather than the rows that happen to match on
		// subject_id alone.
		var found string
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM subjects WHERE tenant_id = ? AND id = ?`, tenantID, id).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read subject: %w", err)
		}

		if _, err := tx.ExecContext(ctx,
			`DELETE FROM webauthn_challenges WHERE tenant_id = ? AND subject_id = ?`,
			tenantID, id); err != nil {
			return mapError(err)
		}

		clause, args := subjectBucketPredicate(tenantID, id)
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM throttle_buckets WHERE `+clause, args...); err != nil {
			return mapError(err)
		}

		if _, err := tx.ExecContext(ctx,
			`DELETE FROM subjects WHERE tenant_id = ? AND id = ?`, tenantID, id); err != nil {
			return mapError(err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: purge subject: %w", err)
	}
	return nil
}

func scanSubject(sc rowScanner) (*store.Subject, error) {
	var (
		sub         store.Subject
		displayName sql.NullString
		status      string
		createdAt   string
		updatedAt   string
		deletedAt   sql.NullString
	)
	if err := sc.Scan(
		&sub.ID, &sub.TenantID, &sub.RefHMAC, &sub.RefSealed, &displayName,
		&status, &createdAt, &updatedAt, &deletedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if sub.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if sub.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	if sub.DeletedAt, err = parseTimePtr(deletedAt); err != nil {
		return nil, err
	}
	sub.DisplayName = stringOrEmpty(displayName)
	sub.Status = store.SubjectStatus(status)
	return &sub, nil
}
