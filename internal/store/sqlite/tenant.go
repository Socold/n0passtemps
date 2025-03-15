package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
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
		return errors.New("sqlite: tenant requires an id and a name")
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

	_, err := s.write.ExecContext(ctx, `
		INSERT INTO tenants (`+tenantColumns+`) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Status, formatTime(t.CreatedAt), formatTime(t.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create tenant: %w", mapError(err))
	}
	return nil
}

// GetTenant implements store.TenantStore.
func (s *Store) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	row := s.read.QueryRowContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id = ?`, id)
	return scanTenant(row)
}

// ListTenants implements store.TenantStore.
func (s *Store) ListTenants(ctx context.Context) ([]*store.Tenant, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants ORDER BY id ASC LIMIT ?`,
		clampLimit(0, maxTenantsListed, maxTenantsListed))
	if err != nil {
		return nil, fmt.Errorf("sqlite: list tenants: %w", err)
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
		return nil, fmt.Errorf("sqlite: iterate tenants: %w", err)
	}
	return out, nil
}

func scanTenant(sc rowScanner) (*store.Tenant, error) {
	var (
		t         store.Tenant
		createdAt string
		updatedAt string
	)
	if err := sc.Scan(&t.ID, &t.Name, &t.Status, &createdAt, &updatedAt); err != nil {
		return nil, mapError(err)
	}

	var err error
	if t.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if t.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// The helpers below are shared by the files in this package that carry JSON or
// boolean columns. They live here rather than being repeated per entity so that
// every table agrees on how an absent value is represented.

// encodeJSONArray renders a string slice for a TEXT column declared NOT NULL
// DEFAULT '[]'. A nil or empty slice becomes the empty array rather than a SQL
// NULL, which keeps the column readable without a null check on every scan.
func encodeJSONArray(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("sqlite: encode json array: %w", err)
	}
	return string(b), nil
}

// decodeJSONArray reads a JSON array column back.
//
// A NULL column, an empty string and a JSON null all yield an empty slice. The
// caller iterates the result without a nil check, and a row written by an
// operator with the sqlite3 shell cannot turn into a panic.
func decodeJSONArray(ns sql.NullString) ([]string, error) {
	raw := stringOrEmpty(ns)
	if raw == "" || raw == "null" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("sqlite: decode json array %q: %w", truncate(raw, 120), err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// encodeJSONObject renders a document for a TEXT column declared NOT NULL
// DEFAULT '{}'. The value is validated before storage: an invalid document
// accepted here would only fail much later, on the read that needs it.
func encodeJSONObject(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}
	if !json.Valid(raw) {
		return "", errors.New("sqlite: value is not valid json")
	}
	return string(raw), nil
}

// decodeJSONObject reads a JSON document column back through encoding/json, so
// a malformed value is reported rather than handed on to a caller that will
// unmarshal it later and blame the wrong layer.
func decodeJSONObject(ns sql.NullString) (json.RawMessage, error) {
	raw := stringOrEmpty(ns)
	if raw == "" || raw == "null" {
		return json.RawMessage("{}"), nil
	}
	var out json.RawMessage
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("sqlite: decode json document %q: %w", truncate(raw, 120), err)
	}
	if len(out) == 0 {
		out = json.RawMessage("{}")
	}
	return out, nil
}

// boolToInt renders a boolean for the INTEGER columns the schema constrains to
// IN (0, 1). The conversion is explicit because a STRICT table rejects whatever
// a driver might otherwise choose to bind for a Go bool.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
