package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// Store must satisfy the whole contract rather than the parts each file in this
// package happens to implement. The assertion turns a method that is missing or
// whose signature has drifted into a compile failure here, instead of into a
// failure at the first call site that needs it.
var _ store.Store = (*Store)(nil)

const tenantColumns = `id, name, status, created_at, updated_at`

// maxTenantsListed caps ListTenants. The interface offers no page size, and v1
// provisions exactly one tenant, but an unbounded SELECT is not offered on any
// table in this package.
const maxTenantsListed = 1000

// CreateTenant implements store.TenantStore.
//
// A duplicate identifier surfaces as store.ErrConflict through mapError rather
// than as an upsert. Provisioning a tenant is an administrative act, and
// silently adopting an existing row would hide the fact that the name and
// status the caller asked for were not the ones stored.
func (s *Store) CreateTenant(ctx context.Context, t *store.Tenant) error {
	if t.ID == "" || t.Name == "" {
		return errors.New("postgres: tenant requires an id and a name")
	}
	if t.Status == "" {
		t.Status = "active"
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = t.CreatedAt
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenants (`+tenantColumns+`) VALUES ($1, $2, $3, $4, $5)`,
		t.ID, t.Name, t.Status, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("postgres: create tenant: %w", mapError(err))
	}
	return nil
}

// GetTenant implements store.TenantStore.
//
// The tenant identifier is the primary key, so this is the one read in the
// package with no tenant predicate to add: the argument is the tenant.
func (s *Store) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, id)
	return scanTenant(row)
}

// ListTenants implements store.TenantStore.
func (s *Store) ListTenants(ctx context.Context) ([]*store.Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+tenantColumns+` FROM tenants ORDER BY id ASC LIMIT $1`,
		clampLimit(0, maxTenantsListed, maxTenantsListed))
	if err != nil {
		return nil, fmt.Errorf("postgres: list tenants: %w", err)
	}
	defer rows.Close()

	var out []*store.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate tenants: %w", err)
	}
	return out, nil
}

func scanTenant(sc rowScanner) (*store.Tenant, error) {
	var (
		t         store.Tenant
		createdAt time.Time
		updatedAt time.Time
	)
	if err := sc.Scan(&t.ID, &t.Name, &t.Status, &createdAt, &updatedAt); err != nil {
		return nil, mapError(err)
	}
	t.CreatedAt = utc(createdAt)
	t.UpdatedAt = utc(updatedAt)
	return &t, nil
}
