package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// RotateAPIKey implements store.AuthnStore.
//
// The successor is validated before the transaction opens, so a malformed one
// is refused without the predecessor having been touched.
func (s *Store) RotateAPIKey(ctx context.Context, tenantID, predecessorID string, successor *store.APIKey, predecessorExpiresAt time.Time) error {
	if successor == nil {
		return errors.New("sqlite: rotate api key requires a successor")
	}
	if successor.ID == "" || successor.TenantID == "" || successor.Name == "" {
		return errors.New("sqlite: api key requires an id, a tenant and a name")
	}
	if successor.Selector == "" || successor.VerifierHash == "" {
		return errors.New("sqlite: api key requires a selector and a verifier hash")
	}
	if successor.TenantID != tenantID {
		// The predecessor is matched on tenantID and the successor is inserted
		// under its own. Letting the two differ would turn rotation into a way
		// to mint a credential in a tenant the caller was never checked
		// against.
		return errors.New("sqlite: rotate api key: the successor belongs to a different tenant")
	}
	if successor.CreatedAt.IsZero() {
		successor.CreatedAt = time.Now().UTC()
	}

	scopes, err := encodeJSONArray(successor.Scopes)
	if err != nil {
		return err
	}

	err = s.rotateAuthnRow(ctx, "api_keys", tenantID, predecessorID, predecessorExpiresAt,
		func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO api_keys (`+apiKeyColumns+`)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				successor.ID, successor.TenantID, successor.Name, successor.Selector,
				successor.VerifierHash, scopes, formatTime(successor.CreatedAt),
				nullString(successor.CreatedBy), formatTimePtr(successor.LastUsedAt),
				formatTimePtr(successor.ExpiresAt), formatTimePtr(successor.RevokedAt))
			return mapError(err)
		})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: rotate api key: %w", err)
	}
	return nil
}

// RotateAdminToken implements store.AuthnStore. See RotateAPIKey.
func (s *Store) RotateAdminToken(ctx context.Context, tenantID, predecessorID string, successor *store.AdminToken, predecessorExpiresAt time.Time) error {
	if successor == nil {
		return errors.New("sqlite: rotate admin token requires a successor")
	}
	if successor.ID == "" || successor.TenantID == "" || successor.Name == "" {
		return errors.New("sqlite: admin token requires an id, a tenant and a name")
	}
	if successor.Selector == "" || successor.VerifierHash == "" {
		return errors.New("sqlite: admin token requires a selector and a verifier hash")
	}
	if !successor.Role.Valid() {
		return fmt.Errorf("sqlite: admin token role %q is not one of the three roles", successor.Role)
	}
	if successor.TenantID != tenantID {
		return errors.New("sqlite: rotate admin token: the successor belongs to a different tenant")
	}
	if successor.CreatedAt.IsZero() {
		successor.CreatedAt = time.Now().UTC()
	}

	err := s.rotateAuthnRow(ctx, "admin_tokens", tenantID, predecessorID, predecessorExpiresAt,
		func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO admin_tokens (`+adminTokenColumns+`)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				successor.ID, successor.TenantID, successor.Name, successor.Selector,
				successor.VerifierHash, string(successor.Role), formatTime(successor.CreatedAt),
				nullString(successor.CreatedBy), formatTimePtr(successor.LastUsedAt),
				formatTimePtr(successor.ExpiresAt), formatTimePtr(successor.RevokedAt))
			return mapError(err)
		})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: rotate admin token: %w", err)
	}
	return nil
}

// rotateAuthnRow performs the rotation shared by the two tables: it bounds the
// predecessor's life and runs insert, in one transaction.
//
// The update is conditional on the expiry moving earlier. A predecessor that
// already expires sooner is left as it is, because a rotation that pushed an
// expiry later would be a way to keep a credential alive past the date it was
// issued to die on. Zero rows affected therefore has two meanings, and the
// second statement tells them apart: either the predecessor is live and keeps
// its earlier expiry, in which case the successor is still inserted, or it is
// missing, in another tenant or revoked, in which case nothing is.
//
// The predecessor is dealt with first and a refusal returns before the insert
// runs, so nothing is inserted for a predecessor that cannot be rotated.
//
// table is a package-level literal chosen by the two callers above, never a
// caller-supplied value, which is the only reason it can be concatenated into
// the statement at all.
func (s *Store) rotateAuthnRow(ctx context.Context, table, tenantID, predecessorID string, predecessorExpiresAt time.Time, insert func(*sql.Tx) error) error {
	if tenantID == "" || predecessorID == "" {
		return errors.New("rotation requires a tenant and a predecessor id")
	}
	if predecessorExpiresAt.IsZero() {
		// A zero instant would format as year one and cut the predecessor off
		// in the distant past. That is never what a caller meant, so it is
		// refused rather than interpreted.
		return errors.New("rotation requires the instant the predecessor stops")
	}
	at := formatTime(predecessorExpiresAt)

	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE `+table+` SET expires_at = ?
			WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > ?)`,
			at, tenantID, predecessorID, at)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("count rotation: %w", err)
		}
		if n == 0 {
			var live int
			err := tx.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM `+table+`
				WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
				tenantID, predecessorID).Scan(&live)
			if err != nil {
				return mapError(err)
			}
			if live == 0 {
				return store.ErrNotFound
			}
		}
		return insert(tx)
	})
}
