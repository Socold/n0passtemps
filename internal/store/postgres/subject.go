package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
//
// The whole thing is one statement with RETURNING, so no transaction is opened
// around it. The SQLite implementation wraps it only to reach the write pool.
func (s *Store) UpsertSubject(ctx context.Context, sub *store.Subject) (*store.Subject, error) {
	if sub.ID == "" || sub.TenantID == "" {
		return nil, errors.New("postgres: subject requires an id and a tenant")
	}
	if len(sub.RefHMAC) == 0 {
		return nil, errors.New("postgres: subject requires a reference hmac")
	}
	if sub.Status == "" {
		sub.Status = store.SubjectActive
	}
	now := time.Now().UTC()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now

	row := s.pool.QueryRow(ctx, `
		INSERT INTO subjects (`+subjectColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)
		ON CONFLICT (tenant_id, ref_hmac) DO UPDATE SET
			ref_sealed = CASE
				WHEN excluded.ref_sealed IS NOT NULL AND length(excluded.ref_sealed) > 0
				THEN excluded.ref_sealed ELSE subjects.ref_sealed END,
			display_name = COALESCE(NULLIF(excluded.display_name, ''), subjects.display_name),
			updated_at = excluded.updated_at
		RETURNING `+subjectColumns,
		sub.ID, sub.TenantID, sub.RefHMAC, sub.RefSealed, nullString(sub.DisplayName),
		string(sub.Status), sub.CreatedAt, sub.UpdatedAt)

	out, err := scanSubject(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: upsert subject: %w", err)
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
	row := s.pool.QueryRow(ctx, `
		SELECT `+subjectColumns+` FROM subjects
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
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
		return nil, errors.New("postgres: subject lookup requires a reference hmac")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+subjectColumns+` FROM subjects
		WHERE tenant_id = $1 AND ref_hmac = $2 AND deleted_at IS NULL`,
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
	var a argset
	where := []string{"tenant_id = " + a.add(tenantID), "deleted_at IS NULL"}

	if f.Status != "" {
		where = append(where, "status = "+a.add(string(f.Status)))
	}
	if len(f.RefHMAC) > 0 {
		// Exact match only. The reference is stored encrypted precisely so that
		// it cannot be scanned, so there is no substring search to offer.
		where = append(where, "ref_hmac = "+a.add(f.RefHMAC))
	}
	if f.AfterID != "" {
		where = append(where, "id > "+a.add(f.AfterID))
	}

	query := `SELECT ` + subjectColumns + ` FROM subjects WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY id ASC LIMIT ` +
		a.add(clampLimit(f.Limit, 50, 500))

	rows, err := s.pool.Query(ctx, query, a.args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list subjects: %w", err)
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
		return nil, fmt.Errorf("postgres: iterate subjects: %w", err)
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
		return errors.New("postgres: subject status is required")
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE subjects SET status = $1, updated_at = $2
		WHERE tenant_id = $3 AND id = $4 AND deleted_at IS NULL`,
		string(status), time.Now().UTC(), tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: set subject status: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
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
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE subjects
			SET status = $1, deleted_at = $2, updated_at = $3
			WHERE tenant_id = $4 AND id = $5 AND deleted_at IS NULL`,
			string(store.SubjectPendingDeletion), at, at, tenantID, id)
		if err != nil {
			return mapError(err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		// Nothing was updated. Either the subject does not exist, or it is
		// already soft-deleted, and only the first is an error.
		var deleted *time.Time
		err = tx.QueryRow(ctx,
			`SELECT deleted_at FROM subjects WHERE tenant_id = $1 AND id = $2`,
			tenantID, id).Scan(&deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("postgres: read subject deletion state: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("postgres: soft delete subject: %w", err)
	}
	return nil
}

// RestoreSubject implements store.SubjectStore.
//
// The update is conditional on the subject being pending deletion, so it cannot
// be used to reactivate a subject an operator locked: a lock and an erasure are
// different decisions, and cancelling one must not undo the other.
func (s *Store) RestoreSubject(ctx context.Context, tenantID, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE subjects
		SET status = $1, deleted_at = NULL, updated_at = $2
		WHERE tenant_id = $3 AND id = $4
		  AND deleted_at IS NOT NULL AND status = $5`,
		string(store.SubjectActive), at, tenantID, id,
		string(store.SubjectPendingDeletion))
	if err != nil {
		return fmt.Errorf("postgres: restore subject: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
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
// CASCADE to subjects and are removed by the engine. Unlike SQLite, PostgreSQL
// enforces a foreign key unconditionally, so there is no pragma to verify at
// open time and no way for the cascade to be silently inert.
//
// webauthn_challenges and throttle_buckets have no foreign key, the first
// because a registration ceremony starts before the subject exists and the
// second because a bucket is addressed by an opaque key rather than by a row
// reference. Both are therefore deleted explicitly.
//
// alerts and erasure_requests are the two tables that name a subject and
// outlive it, and each is dealt with according to what it is for. An alert is
// an operational signal about something that happened to one account: it
// carries the subject's identifier, a summary written for an operator and a
// free-form detail document, none of which has any reason to survive the person
// it is about, so the alerts raised about this subject are deleted. An erasure
// request is the record that the erasure was asked for and carried out, so the
// row stays; what goes is the reason, the one field in it an operator fills in
// prose and the one that can therefore name the person, quote their message or
// give the ticket they wrote from. Every request ever filed against this
// subject is cleared, not only the one being completed, because a cancelled
// request from last year carries a reason written the same way.
//
// What is left of the request is the proof: who asked, when, when it fell due,
// and that it ended in a purge. The subject identifier stays with it. It is
// opaque, the row it referred to has just been deleted, and it is what makes
// the record answer the question the record exists for, which is which account
// this erasure was.
//
// audit_log is deliberately untouched. Erasure of audit entries rewrites them in
// place through EraseSubjectAuditEntries, which keeps the hash chain verifiable;
// deleting them here would break verification for every entry that follows, and
// the delete guard in the schema would refuse it in any case.
func (s *Store) PurgeSubject(ctx context.Context, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return errors.New("postgres: purge requires a tenant and a subject")
	}

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Confirm the subject belongs to this tenant before anything is
		// removed, so a purge aimed at another tenant's identifier deletes
		// nothing at all rather than the rows that happen to match on
		// subject_id alone.
		var pending bool
		err := tx.QueryRow(ctx,
			`SELECT deleted_at IS NOT NULL FROM subjects WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			tenantID, id).Scan(&pending)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("postgres: read subject: %w", err)
		}

		// A subject that is not pending deletion is not purged. Cancelling an
		// erasure restores the subject, and the sweep that purges works from a
		// list read earlier: without this, a subject restored in between was
		// purged all the same, factors and all, under a request marked
		// cancelled. Checked here, in the transaction that deletes, because
		// nowhere earlier can know.
		// The row is locked by the read above, so a restore cannot land between
		// this check and the delete.
		if !pending {
			return fmt.Errorf("%w: the subject is not pending deletion", store.ErrStaleWrite)
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM webauthn_challenges WHERE tenant_id = $1 AND subject_id = $2`,
			tenantID, id); err != nil {
			return mapError(err)
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM throttle_buckets WHERE `+subjectBucketPredicate,
			tenantID, id); err != nil {
			return mapError(err)
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM alerts WHERE tenant_id = $1 AND subject_id = $2`,
			tenantID, id); err != nil {
			return mapError(err)
		}

		// The request itself survives; only the operator's prose goes. See the
		// comment above this function.
		if _, err := tx.Exec(ctx, `
			UPDATE erasure_requests SET reason = NULL
			WHERE tenant_id = $1 AND subject_id = $2 AND reason IS NOT NULL`,
			tenantID, id); err != nil {
			return mapError(err)
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM subjects WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return mapError(err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("postgres: purge subject: %w", err)
	}
	return nil
}

func scanSubject(sc rowScanner) (*store.Subject, error) {
	var (
		sub         store.Subject
		displayName *string
		status      string
		createdAt   time.Time
		updatedAt   time.Time
		deletedAt   *time.Time
	)
	if err := sc.Scan(
		&sub.ID, &sub.TenantID, &sub.RefHMAC, &sub.RefSealed, &displayName,
		&status, &createdAt, &updatedAt, &deletedAt,
	); err != nil {
		return nil, mapError(err)
	}

	sub.CreatedAt = utc(createdAt)
	sub.UpdatedAt = utc(updatedAt)
	sub.DeletedAt = utcPtr(deletedAt)
	sub.DisplayName = text(displayName)
	sub.Status = store.SubjectStatus(status)
	return &sub, nil
}
