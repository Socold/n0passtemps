package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateSmoke(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "smoke.db")
	s, err := Open(Options{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Idempotence.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	rows, err := s.read.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		names = append(names, n)
	}
	// Without this an iteration cut short reads as a schema with fewer tables
	// than it has, which is the failure this smoke test exists to notice.
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table names: %v", err)
	}
	t.Logf("tables: %v", names)

	// The append-only trigger must actually fire.
	_, err = s.write.ExecContext(ctx, `INSERT INTO audit_log
		(tenant_id, occurred_at, event_type, actor_type, outcome, detail, pii_digest, prev_hash, entry_hash)
		VALUES ('t','2026-01-01T00:00:00.000000000Z','x','system','success','{}',x'00',x'00',x'01')`)
	if err != nil {
		t.Fatalf("insert audit: %v", err)
	}
	_, err = s.write.ExecContext(ctx, `UPDATE audit_log SET event_type='y'`)
	if err == nil {
		t.Fatal("expected the append-only trigger to refuse an UPDATE")
	}
	t.Logf("update refused as expected: %v", mapError(err))
	_, err = s.write.ExecContext(ctx, `DELETE FROM audit_log`)
	if err == nil {
		t.Fatal("expected the append-only trigger to refuse a DELETE")
	}
	t.Logf("delete refused as expected: %v", mapError(err))
}
