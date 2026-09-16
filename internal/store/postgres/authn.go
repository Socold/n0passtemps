package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

const apiKeyColumns = `id, tenant_id, name, selector, verifier_hash, scopes,
	created_at, created_by, last_used_at, expires_at, revoked_at`

const adminTokenColumns = `id, tenant_id, name, selector, verifier_hash, role,
	created_at, created_by, last_used_at, expires_at, revoked_at`

// maxAuthnListed caps the two listings. Neither interface method offers a page
// size; the number of keys and tokens in a deployment is small by design, and a
// deployment where it is not should still not be able to ask for all of them in
// one response.
const maxAuthnListed = 500

// CreateAPIKey implements store.AuthnStore.
func (s *Store) CreateAPIKey(ctx context.Context, k *store.APIKey) error {
	if k.ID == "" || k.TenantID == "" || k.Name == "" {
		return errors.New("postgres: api key requires an id, a tenant and a name")
	}
	if k.Selector == "" || k.VerifierHash == "" {
		return errors.New("postgres: api key requires a selector and a verifier hash")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}

	scopes, err := jsonArray(k.Scopes)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_keys (`+apiKeyColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		k.ID, k.TenantID, k.Name, k.Selector, k.VerifierHash, scopes,
		k.CreatedAt, nullString(k.CreatedBy), k.LastUsedAt, k.ExpiresAt, k.RevokedAt)
	if err != nil {
		return fmt.Errorf("postgres: create api key: %w", mapError(err))
	}
	return nil
}

// GetAPIKeyBySelector implements store.AuthnStore.
//
// There is no tenant predicate here, and there cannot be one: the selector is
// what the request presents, and the tenant is not known until the row has been
// read. The selector is globally unique for exactly that reason, and the caller
// takes the tenant from the returned key rather than from anything the request
// claimed.
//
// A revoked or expired key is still returned. Usable decides that, so the
// caller can record which key was presented in the audit entry for the refusal.
func (s *Store) GetAPIKeyBySelector(ctx context.Context, selector string) (*store.APIKey, error) {
	if selector == "" {
		return nil, errors.New("postgres: api key lookup requires a selector")
	}
	row := s.pool.QueryRow(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE selector = $1`, selector)
	return scanAPIKey(row)
}

// ListAPIKeys implements store.AuthnStore.
func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]*store.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys
		WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC LIMIT $2`,
		tenantID, clampLimit(0, maxAuthnListed, maxAuthnListed))
	if err != nil {
		return nil, fmt.Errorf("postgres: list api keys: %w", err)
	}
	defer rows.Close()

	var out []*store.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate api keys: %w", err)
	}
	return out, nil
}

// RevokeAPIKey implements store.AuthnStore.
//
// Conditional on the key not being revoked already, so the first revocation
// timestamp is the one kept.
func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := s.revokeAuthnRow(ctx, "api_keys", tenantID, id, at); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("postgres: revoke api key: %w", err)
	}
	return nil
}

// CreateAdminToken implements store.AuthnStore.
func (s *Store) CreateAdminToken(ctx context.Context, t *store.AdminToken) error {
	if t.ID == "" || t.TenantID == "" || t.Name == "" {
		return errors.New("postgres: admin token requires an id, a tenant and a name")
	}
	if t.Selector == "" || t.VerifierHash == "" {
		return errors.New("postgres: admin token requires a selector and a verifier hash")
	}
	if !t.Role.Valid() {
		// The schema carries the same CHECK, but refusing here names the
		// offending value instead of reporting a constraint name.
		return fmt.Errorf("postgres: admin token role %q is not one of the three roles", t.Role)
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_tokens (`+adminTokenColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		t.ID, t.TenantID, t.Name, t.Selector, t.VerifierHash, string(t.Role),
		t.CreatedAt, nullString(t.CreatedBy), t.LastUsedAt, t.ExpiresAt, t.RevokedAt)
	if err != nil {
		return fmt.Errorf("postgres: create admin token: %w", mapError(err))
	}
	return nil
}

// GetAdminTokenBySelector implements store.AuthnStore.
//
// As with GetAPIKeyBySelector, the tenant is a result of this lookup rather than
// an input to it, so there is no tenant predicate to add.
func (s *Store) GetAdminTokenBySelector(ctx context.Context, selector string) (*store.AdminToken, error) {
	if selector == "" {
		return nil, errors.New("postgres: admin token lookup requires a selector")
	}
	row := s.pool.QueryRow(ctx,
		`SELECT `+adminTokenColumns+` FROM admin_tokens WHERE selector = $1`, selector)
	return scanAdminToken(row)
}

// ListAdminTokens implements store.AuthnStore.
func (s *Store) ListAdminTokens(ctx context.Context, tenantID string) ([]*store.AdminToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+adminTokenColumns+` FROM admin_tokens
		WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC LIMIT $2`,
		tenantID, clampLimit(0, maxAuthnListed, maxAuthnListed))
	if err != nil {
		return nil, fmt.Errorf("postgres: list admin tokens: %w", err)
	}
	defer rows.Close()

	var out []*store.AdminToken
	for rows.Next() {
		t, err := scanAdminToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate admin tokens: %w", err)
	}
	return out, nil
}

// RevokeAdminToken implements store.AuthnStore.
func (s *Store) RevokeAdminToken(ctx context.Context, tenantID, id string, at time.Time) error {
	if err := s.revokeAuthnRow(ctx, "admin_tokens", tenantID, id, at); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("postgres: revoke admin token: %w", err)
	}
	return nil
}

// revokeAuthnRow performs the revocation shared by the two tables.
//
// table is a package-level literal chosen by the two callers above, never a
// caller-supplied value, which is the only reason it can be concatenated into
// the statement at all.
func (s *Store) revokeAuthnRow(ctx context.Context, table, tenantID, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE `+table+` SET revoked_at = $1
		WHERE tenant_id = $2 AND id = $3 AND revoked_at IS NULL`,
		at, tenantID, id)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// TouchAPIKey implements store.AuthnStore.
//
// This runs on the request path, so it takes no tenant argument and reports no
// error for a row that is not there. The identifier came from a key this process
// has already read and authenticated, and failing an authentication because a
// "last used" timestamp could not be recorded would trade a real property for a
// cosmetic one.
func (s *Store) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	return s.touchAuthnRow(ctx, "api_keys", id, at)
}

// TouchAdminToken implements store.AuthnStore. See TouchAPIKey, including on
// why there is no tenant predicate.
func (s *Store) TouchAdminToken(ctx context.Context, id string, at time.Time) error {
	return s.touchAuthnRow(ctx, "admin_tokens", id, at)
}

// touchAuthnRow records last use. The write is unconditional and its row count
// is ignored, for the reason given on TouchAPIKey.
func (s *Store) touchAuthnRow(ctx context.Context, table, id string, at time.Time) error {
	if id == "" {
		return errors.New("postgres: touch requires an id")
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE `+table+` SET last_used_at = $1 WHERE id = $2`, at, id)
	if err != nil {
		return fmt.Errorf("postgres: record last use on %s: %w", table, mapError(err))
	}
	return nil
}

// CountAdminTokensByRole implements store.AuthnStore.
//
// Only tokens that could authenticate right now are counted. Revoked and
// expired tokens are excluded because the count exists to stop an operator
// removing the last usable administrator of a role, and a count that included
// unusable tokens would report that a fallback exists when it does not.
func (s *Store) CountAdminTokensByRole(ctx context.Context, tenantID string, role store.Role, usableAt time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM admin_tokens
		WHERE tenant_id = $1 AND role = $2
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > $3)`,
		tenantID, string(role), usableAt).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count admin tokens by role: %w", err)
	}
	return n, nil
}

func scanAPIKey(sc rowScanner) (*store.APIKey, error) {
	var (
		k          store.APIKey
		scopes     []byte
		createdAt  time.Time
		createdBy  *string
		lastUsedAt *time.Time
		expiresAt  *time.Time
		revokedAt  *time.Time
	)
	if err := sc.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Selector, &k.VerifierHash, &scopes,
		&createdAt, &createdBy, &lastUsedAt, &expiresAt, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if k.Scopes, err = decodeJSONArray(scopes); err != nil {
		return nil, err
	}

	k.CreatedAt = utc(createdAt)
	k.LastUsedAt = utcPtr(lastUsedAt)
	k.ExpiresAt = utcPtr(expiresAt)
	k.RevokedAt = utcPtr(revokedAt)
	k.CreatedBy = text(createdBy)
	return &k, nil
}

func scanAdminToken(sc rowScanner) (*store.AdminToken, error) {
	var (
		t          store.AdminToken
		role       string
		createdAt  time.Time
		createdBy  *string
		lastUsedAt *time.Time
		expiresAt  *time.Time
		revokedAt  *time.Time
	)
	if err := sc.Scan(
		&t.ID, &t.TenantID, &t.Name, &t.Selector, &t.VerifierHash, &role,
		&createdAt, &createdBy, &lastUsedAt, &expiresAt, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	t.CreatedAt = utc(createdAt)
	t.LastUsedAt = utcPtr(lastUsedAt)
	t.ExpiresAt = utcPtr(expiresAt)
	t.RevokedAt = utcPtr(revokedAt)
	t.Role = store.Role(role)
	t.CreatedBy = text(createdBy)
	return &t, nil
}
