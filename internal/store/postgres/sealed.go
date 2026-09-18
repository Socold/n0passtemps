package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

// sealedPageDefault and sealedPageMax bound one page of a rewrap walk. The cap
// exists so that a caller passing a careless limit cannot pull every sealed
// secret in the database into memory at once.
const (
	sealedPageDefault = 200
	sealedPageMax     = 1000
)

// sealedStatements holds the two statements for one kind of sealed record.
type sealedStatements struct {
	list    string
	replace string
	exists  string
}

// sealedStatementsFor maps a kind to its statements.
//
// The table and column names are literals chosen by this switch and an unknown
// kind is an error. Building the statement from the kind's text instead would
// turn a typed constant into an injection point the day a caller derives one
// from a request.
func sealedStatementsFor(kind store.SealedKind) (sealedStatements, error) {
	switch kind {
	case store.SealedTOTP:
		return sealedStatements{
			list: `SELECT id, secret_sealed FROM totp_secrets
				WHERE revoked_at IS NULL AND id > $1
				ORDER BY id ASC LIMIT $2`,
			replace: `UPDATE totp_secrets SET secret_sealed = $1
				WHERE id = $2 AND secret_sealed = $3`,
			exists: `SELECT 1 FROM totp_secrets WHERE id = $1`,
		}, nil
	case store.SealedSubjectRef:
		// An empty value is treated as absent, as UpsertSubject does. It is
		// not an envelope, so listing it would report a failure on every pass
		// for a row that holds nothing to protect.
		return sealedStatements{
			list: `SELECT id, ref_sealed FROM subjects
				WHERE ref_sealed IS NOT NULL AND length(ref_sealed) > 0 AND id > $1
				ORDER BY id ASC LIMIT $2`,
			replace: `UPDATE subjects SET ref_sealed = $1
				WHERE id = $2 AND ref_sealed = $3`,
			exists: `SELECT 1 FROM subjects WHERE id = $1`,
		}, nil
	default:
		return sealedStatements{}, fmt.Errorf("postgres: unknown sealed record kind %q", string(kind))
	}
}

// ListSealed implements store.SealedStore.
//
// The walk spans every tenant, because the keyring it serves is shared by all
// of them; see the interface.
func (s *Store) ListSealed(ctx context.Context, kind store.SealedKind, afterID string, limit int) ([]store.SealedRecord,
	error) {
	stmts, err := sealedStatementsFor(kind)
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, stmts.list, afterID,
		clampLimit(limit, sealedPageDefault, sealedPageMax))
	if err != nil {
		return nil, fmt.Errorf("postgres: list sealed records: %w", err)
	}
	defer rows.Close()

	var out []store.SealedRecord
	for rows.Next() {
		var rec store.SealedRecord
		if err := rows.Scan(&rec.ID, &rec.Sealed); err != nil {
			return nil, fmt.Errorf("postgres: scan sealed record: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sealed records: %w", err)
	}
	return out, nil
}

// ReplaceSealed implements store.SealedStore.
//
// The comparison with the old bytes is part of the UPDATE, so it is evaluated
// under the row lock the UPDATE takes. Reading the row and comparing in Go would leave
// a gap in which an upsert could reseal a subject reference, and the write that
// followed would overwrite the newer value with a rewrap of the older one.
func (s *Store) ReplaceSealed(ctx context.Context, kind store.SealedKind, id string, old, replacement []byte) error {
	stmts, stmtErr := sealedStatementsFor(kind)
	if stmtErr != nil {
		return stmtErr
	}
	if id == "" || len(old) == 0 || len(replacement) == 0 {
		return errors.New("postgres: replacing a sealed record requires an id and both values")
	}

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, stmts.replace, replacement, id, old)
		if err != nil {
			return mapError(err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		// Nothing matched. Read the row back to separate a record that has
		// gone from one whose value moved, because the caller counts them
		// differently.
		var exists int
		err = tx.QueryRow(ctx, stmts.exists, id).Scan(&exists)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("postgres: read sealed record: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("postgres: replace sealed record: %w", err)
	}
	return nil
}
