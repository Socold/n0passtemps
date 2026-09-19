//go:build integration

// These tests need a live PostgreSQL cluster, so they sit behind the
// integration build tag and behind an environment variable. An ordinary
// go test ./... neither builds nor runs them.
//
// Each test gets its own schema in the target database, created and dropped
// around it, so nothing leaks between tests and the suite can be pointed at a
// cluster that holds other things. The connection puts that schema on the
// search path, which is what makes the unqualified table names in the
// migrations and in the store resolve to it.

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/auditsink"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/migrations"
)

// dsnEnv names the variable that points the suite at a cluster.
const dsnEnv = "N0PASSTEMPS_TEST_POSTGRES_DSN"

// schemaSeq keeps two tests in the same run from claiming one schema name when
// their names collapse to the same identifier.
var schemaSeq atomic.Int64

// requireDSN returns the connection string, or skips.
func requireDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skip("set " + dsnEnv + " to a PostgreSQL connection string to run the postgres store tests")
	}
	return dsn
}

// newTestStore opens a migrated store in a schema of its own.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := requireDSN(t)
	ctx := context.Background()

	schema := schemaName(t)

	// The schema is created over a plain connection rather than through the
	// store, because the store's pool is the thing being pointed at it.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for setup: %v", err)
	}
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("drop stale schema %s: %v", schema, err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema %s: %v", schema, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close setup connection: %v", err)
	}

	s, err := Open(Options{DSN: withSearchPath(dsn, schema)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		_ = s.Close()
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() {
		_ = s.Close()
		cleanup, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Logf("connect for teardown: %v", err)
			return
		}
		defer func() { _ = cleanup.Close(context.Background()) }()
		if _, err := cleanup.Exec(context.Background(),
			`DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	return s
}

// schemaName derives a legal, unique, unquoted identifier from a test name.
func schemaName(t *testing.T) string {
	var b strings.Builder
	b.WriteString("npt_")
	for _, r := range strings.ToLower(t.Name()) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if len(name) > 40 {
		name = name[:40]
	}
	return fmt.Sprintf("%s_%d", name, schemaSeq.Add(1))
}

// withSearchPath puts a schema on the connection's search path. pgx forwards a
// connection parameter it does not recognise to the server as a runtime
// parameter, which is what makes this work for both the URL and the
// keyword/value form of a connection string.
func withSearchPath(dsn, schema string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "search_path=" + schema
	}
	return dsn + " search_path=" + schema
}

func seedTenant(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.CreateTenant(context.Background(), &store.Tenant{ID: id, Name: id}); err != nil {
		t.Fatalf("create tenant %s: %v", id, err)
	}
}

func seedSubject(t *testing.T, s *Store, tenantID, id, ref string) *store.Subject {
	t.Helper()
	sub, err := s.UpsertSubject(context.Background(), &store.Subject{
		ID:          id,
		TenantID:    tenantID,
		RefHMAC:     []byte(ref),
		RefSealed:   []byte("sealed-" + ref),
		DisplayName: "display-" + ref,
	})
	if err != nil {
		t.Fatalf("upsert subject %s: %v", id, err)
	}
	return sub
}

func seedCredential(t *testing.T, s *Store, tenantID, subjectID, id string, signCount uint32) *store.Credential {
	t.Helper()
	c := &store.Credential{
		ID:           id,
		TenantID:     tenantID,
		SubjectID:    subjectID,
		CredentialID: []byte("cred-" + id),
		PublicKey:    []byte("cose-" + id),
		Transports:   []string{"internal", "hybrid"},
		SignCount:    signCount,
		RPID:         "example.test",
	}
	if err := s.CreateCredential(context.Background(), c); err != nil {
		t.Fatalf("create credential %s: %v", id, err)
	}
	return c
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// sameJSON reports whether a stored document matches what was handed in.
//
// The comparison is on the document rather than on the bytes. PostgreSQL keeps
// a JSONB column decomposed and renders it back in its own spelling, with the
// object keys reordered and a space after every colon, so the bytes that come
// out are not the bytes that went in even though the document is unchanged.
// This is the one place the two backends differ observably, and the assertions
// below are about the document.
func sameJSON(t *testing.T, got []byte, want string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("stored document is not json: %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatalf("expected document is not json: %q: %v", want, err)
	}
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ja, jb)
}

func appendN(t *testing.T, s *Store, tenant string, n int) []*store.AuditEntry {
	t.Helper()
	ctx := context.Background()
	out := make([]*store.AuditEntry, 0, n)
	for i := 0; i < n; i++ {
		e, err := s.Append(ctx, &store.AuditEntry{
			TenantID:   tenant,
			EventType:  audit.EventAssertionCompleted,
			ActorType:  store.ActorSubject,
			SubjectID:  "subject-1",
			SourceIP:   "192.0.2.10",
			Outcome:    store.OutcomeSuccess,
			OccurredAt: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// newTestStore already migrated once.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	// The expected count is read from the embedded set rather than written in
	// here, so adding a migration does not break this test for a reason that
	// has nothing to do with idempotence.
	embedded, err := migrations.Load("postgres")
	if err != nil {
		t.Fatal(err)
	}

	var applied int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(embedded) {
		t.Fatalf("schema_migrations holds %d rows, want the %d embedded migrations",
			applied, len(embedded))
	}

	// A recorded checksum that no longer matches the embedded file must stop
	// the run rather than let the database and the binary diverge quietly.
	if _, err := s.pool.Exec(ctx,
		`UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	err = s.Migrate(ctx)
	if err == nil {
		t.Fatal("expected Migrate to refuse a changed checksum")
	}
	if !strings.Contains(err.Error(), "disagree about the schema") {
		t.Errorf("checksum mismatch reported as %v", err)
	}
}

func TestAppendOnlyGuardsMapToErrAppendOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 3)

	// The guards are plpgsql functions that RAISE EXCEPTION, which arrives as
	// SQLSTATE P0001. mapError has to recognise it from the code and the
	// relation named in the message.
	_, err := s.pool.Exec(ctx, `UPDATE audit_log SET event_type = 'y' WHERE seq = 1`)
	if err == nil {
		t.Fatal("expected the update guard to refuse an ordinary UPDATE")
	}
	if got := mapError(err); !errors.Is(got, store.ErrAppendOnly) {
		t.Errorf("update guard mapped to %v, want store.ErrAppendOnly", got)
	}

	_, err = s.pool.Exec(ctx, `DELETE FROM audit_log WHERE seq = 1`)
	if err == nil {
		t.Fatal("expected the delete guard to refuse an unattested deletion")
	}
	if got := mapError(err); !errors.Is(got, store.ErrAppendOnly) {
		t.Errorf("delete guard mapped to %v, want store.ErrAppendOnly", got)
	}
}

func TestErrorMapping(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	// 23505, unique violation.
	if err := s.CreateTenant(ctx, &store.Tenant{ID: "tenant-a", Name: "again"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate tenant = %v, want store.ErrConflict", err)
	}

	// 23503, foreign key violation. subjects references tenants.
	_, err := s.UpsertSubject(ctx, &store.Subject{
		ID: "subject-x", TenantID: "no-such-tenant", RefHMAC: []byte("ref-x"),
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("subject under an unknown tenant = %v, want store.ErrConflict", err)
	}

	// 23514, check violation. The status CHECK admits three values.
	_, err = s.UpsertSubject(ctx, &store.Subject{
		ID: "subject-y", TenantID: "tenant-a", RefHMAC: []byte("ref-y"),
		Status: store.SubjectStatus("not-a-status"),
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("subject with an invalid status = %v, want store.ErrConflict", err)
	}

	// pgx.ErrNoRows.
	if _, err := s.GetTenant(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown tenant = %v, want store.ErrNotFound", err)
	}
}

func TestChainVerifies(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := appendN(t, s, "tenant-1", 25)

	// The first entry must chain onto the genesis value, not onto zero bytes.
	if got, want := entries[0].PrevHash, audit.Genesis(); !bytes.Equal(got, want) {
		t.Errorf("first PrevHash = %x, want genesis %x", got, want)
	}
	for i := 1; i < len(entries); i++ {
		if !bytes.Equal(entries[i].PrevHash, entries[i-1].EntryHash) {
			t.Fatalf("entry %d does not chain onto %d", i, i-1)
		}
	}

	checked, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain reported broken at %d", broken)
	}
	if checked != 25 {
		t.Errorf("checked %d entries, want 25", checked)
	}

	// The head the store reports must be the entry it last wrote.
	seq, hash, err := s.ChainHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if seq != last.Seq || !bytes.Equal(hash, last.EntryHash) {
		t.Errorf("ChainHead = (%d, %x), want (%d, %x)", seq, hash, last.Seq, last.EntryHash)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 10)

	// Rewrite one entry's event type the way an operator with psql would. The
	// trigger refuses an ordinary UPDATE, so reach past it to prove the chain
	// catches what the trigger cannot prevent.
	if _, err := s.pool.Exec(ctx, `DROP TRIGGER audit_log_update_guard ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_log SET event_type = 'tampered' WHERE seq = 5`); err != nil {
		t.Fatal(err)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 5 {
		t.Fatalf("expected the chain to break at seq 5, got %d", broken)
	}
}

func TestChainSurvivesErasure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 12)

	erased, err := s.EraseSubjectAuditEntries(ctx, "tenant-1", "subject-1", "admin-7", time.Now())
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if erased != 12 {
		t.Fatalf("erased %d entries, want 12", erased)
	}

	// The chain must still verify after the personal fields are gone. That is
	// the whole point of committing to them through a salted digest.
	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d after erasure", broken)
	}

	// And the personal data must actually be gone.
	rows, err := s.QueryAudit(ctx, "tenant-1", store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.EventType == audit.EventSubjectRedacted {
			continue // the tombstone names the subject as a resource, not a subject
		}
		if e.SubjectID != "" || e.SourceIP != "" {
			t.Errorf("seq %d still carries personal data: subject=%q ip=%q",
				e.Seq, e.SubjectID, e.SourceIP)
		}
		if !audit.Erased(e) {
			t.Errorf("seq %d still has its salt", e.Seq)
		}
	}

	// A tombstone recording the erasure must exist, and must say how many
	// entries it covered.
	tomb, err := s.QueryAudit(ctx, "tenant-1", store.AuditFilter{
		EventType: audit.EventSubjectRedacted, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tomb) != 1 {
		t.Fatalf("expected one erasure tombstone, got %d", len(tomb))
	}
	if !sameJSON(t, tomb[0].Detail, `{"erased_entries":12}`) {
		t.Errorf("tombstone detail = %s, want it to record 12 entries", tomb[0].Detail)
	}
}

func TestPruneKeepsRemainderVerifiable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 20)

	// Everything was stamped in 2026-01-01; cut above the tenth entry.
	cut := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	removed, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 10 {
		t.Fatalf("removed %d entries, want 10", removed)
	}

	// The checkpoint is what makes the trim attested and the remainder
	// verifiable, so it has to be there and has to name the boundary.
	var (
		prunedSeq int64
		count     int64
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT pruned_through_seq, entries_removed FROM audit_checkpoints
		ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&prunedSeq, &count); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if prunedSeq != 10 || count != 10 {
		t.Errorf("checkpoint = (seq %d, removed %d), want (10, 10)", prunedSeq, count)
	}

	// Verification has to resume from the checkpoint hash rather than from
	// genesis, otherwise a trimmed log would look tampered with.
	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d after pruning", broken)
	}
}

// TestAPruneIsAttestedByTheChain covers what a checkpoint is worth.
//
// The marker the trim appends carries the hash of the entry it stopped at, and
// the chain covers the marker, so the boundary a checkpoint claims is a
// boundary the chain agrees with. Verification asks for exactly that, so the
// two have to be written to match.
func TestAPruneIsAttestedByTheChain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entries := appendN(t, s, "tenant-1", 20)
	boundary := entries[9]

	cut := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	if _, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var (
		prunedSeq  int64
		prunedHash []byte
		markerSeq  int64
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT pruned_through_seq, pruned_through_hash, audit_seq
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).
		Scan(&prunedSeq, &prunedHash, &markerSeq); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if prunedSeq != boundary.Seq || !bytes.Equal(prunedHash, boundary.EntryHash) {
		t.Fatalf("checkpoint names (%d, %x), want the tenth entry (%d, %x)",
			prunedSeq, prunedHash, boundary.Seq, boundary.EntryHash)
	}

	// The document comes back in the server's own spelling, keys reordered and
	// a space after every colon, which is why the marker is parsed rather than
	// compared as text.
	var detail []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT detail FROM audit_log WHERE seq = $1`, markerSeq).Scan(&detail); err != nil {
		t.Fatalf("read the retention marker: %v", err)
	}
	if !audit.MarkerAttestsCheckpoint(detail, prunedSeq, prunedHash) {
		t.Errorf("the marker at seq %d does not attest the checkpoint: %s", markerSeq, detail)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("an attested trim reported a break at %d", broken)
	}
}

// TestAForgedCheckpointAndATrimmedPrefixAreDetected is the attack the binding
// exists for.
//
// Whoever can write to the database inserts a checkpoint naming entry ten and
// its real hash, and then deletes entries one to ten, which the delete guard
// allows because a checkpoint now exists. Nothing in the chain ever said the
// log had been trimmed, and verification used to resume from the checkpoint and
// report a log in perfect order.
func TestAForgedCheckpointAndATrimmedPrefixAreDetected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entries := appendN(t, s, "tenant-1", 20)
	boundary := entries[9]

	forge := func() error {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO audit_checkpoints (
				id, tenant_id, pruned_through_seq, pruned_through_hash,
				entries_removed, audit_seq, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			"forged-checkpoint", "tenant-1", boundary.Seq, boundary.EntryHash,
			10, entries[10].Seq, time.Now())
		return err
	}

	// The insert guard refuses it outright: the entry the row names is an
	// ordinary one and not the marker of a trim.
	if err := forge(); err == nil {
		t.Fatal("expected the insert guard to refuse a checkpoint no marker attests")
	}

	// A guard is a trigger and the attacker is inside the cluster, so the
	// interesting question is what verification says once the trigger is gone.
	if _, err := s.pool.Exec(ctx,
		`DROP TRIGGER audit_checkpoints_insert_guard ON audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	if err := forge(); err != nil {
		t.Fatalf("insert the forged checkpoint: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM audit_log WHERE seq <= $1`, boundary.Seq); err != nil {
		t.Fatalf("the delete guard let the prefix go, as it does once a checkpoint exists: %v", err)
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != boundary.Seq {
		t.Fatalf("a forged checkpoint and a deleted prefix reported a break at %d, want %d",
			broken, boundary.Seq)
	}
}

// TestASequenceGapDoesNotBreakTheChain is the engine difference the receiver
// contract turns on.
//
// seq comes from a sequence, so a rolled back append spends a number no entry
// will ever carry. The entries on either side chain onto each other, the log is
// whole, and nothing about it should read as tampering.
func TestASequenceGapDoesNotBreakTheChain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	appendN(t, s, "tenant-1", 3)

	// An append that fails after drawing its number, which is what a cancelled
	// request or a refused insert does.
	failed := s.inTx(ctx, func(tx pgx.Tx) error {
		e := &store.AuditEntry{
			TenantID:  "tenant-1",
			EventType: audit.EventAssertionCompleted,
			ActorType: store.ActorSubject,
			Outcome:   store.OutcomeSuccess,
		}
		if err := prepareAppend(ctx, tx, e); err != nil {
			return err
		}
		return errors.New("this transaction is rolled back on purpose")
	})
	if failed == nil {
		t.Fatal("the rolled back append reported success")
	}

	after := appendN(t, s, "tenant-1", 2)
	if after[0].Seq != 5 {
		t.Fatalf("the entry after the rolled back append has seq %d, want 5: the sequence must have skipped one",
			after[0].Seq)
	}

	checked, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("a gap the sequence left reported a break at %d", broken)
	}
	if checked != 5 {
		t.Errorf("checked %d entries, want the 5 that exist", checked)
	}

	// And the same run, seen as a receiver sees it: the numbering skips 4 and
	// the chain does not.
	entries, err := s.ReadAuditRange(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]auditsink.Record, 0, len(entries))
	for _, e := range entries {
		records = append(records, auditsink.Project(e))
	}
	if brokenAt := auditsink.CheckSequence(records, audit.Genesis()); brokenAt != 0 {
		t.Errorf("a receiver reported the delivered run as broken at %d", brokenAt)
	}
}

func TestPruneStopsAtTheFirstRecentEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Three old entries, a recent one, and then one written by a clock that had
	// fallen behind: old by its timestamp, newest by its position.
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	stamps := []time.Time{old, old.Add(time.Second), old.Add(2 * time.Second), recent, old.Add(3 * time.Second)}
	for i, at := range stamps {
		if _, err := s.Append(ctx, &store.AuditEntry{
			TenantID:   "tenant-1",
			EventType:  audit.EventAssertionCompleted,
			ActorType:  store.ActorSubject,
			SubjectID:  "subject-1",
			Outcome:    store.OutcomeSuccess,
			OccurredAt: at,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Timestamps come from the process clock and are not monotonic in the
	// sequence number. Cutting at the newest entry that looks old would take
	// the recent one with it, and the checkpoint would make the loss verify.
	cut := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	removed, err := s.PruneAuditLog(ctx, "tenant-1", cut, time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed %d entries, want only the 3 that precede the first recent one", removed)
	}

	left, err := s.ReadAuditRange(ctx, 1, 100)
	if err != nil {
		t.Fatalf("read what is left: %v", err)
	}
	if len(left) == 0 || left[0].Seq != 4 || !left[0].OccurredAt.Equal(recent) {
		t.Fatalf("the log no longer starts at the recent entry, seq 4: a backdated entry pruned it")
	}

	_, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d after pruning", broken)
	}
}

func TestConcurrentAppendsChainCleanly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two appends racing must not chain onto the same predecessor. There is no
	// single write connection here to serialise them, so the advisory lock in
	// prepareAppend is the only thing standing between this test and a forked
	// chain.
	const writers, each = 8, 15
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_, err := s.Append(ctx, &store.AuditEntry{
					TenantID:  "tenant-1",
					EventType: audit.EventAssertionCompleted,
					ActorType: store.ActorSystem,
					Outcome:   store.OutcomeSuccess,
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	checked, broken, err := s.VerifyChain(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broke at %d under concurrency", broken)
	}
	if want := int64(writers * each); checked != want {
		t.Errorf("checked %d entries, want %d", checked, want)
	}
}

func TestQueryAuditFamilyPrefix(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, et := range []string{
		audit.EventAssertionCompleted,
		audit.EventRegistrationCompleted,
		audit.EventTOTPVerified,
	} {
		if _, err := s.Append(ctx, &store.AuditEntry{
			TenantID: "t", EventType: et, ActorType: store.ActorSystem,
			Outcome: store.OutcomeSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.QueryAudit(ctx, "t", store.AuditFilter{EventType: "webauthn.", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("prefix query returned %d entries, want 2", len(got))
	}

	// A wildcard in the filter must not widen the match.
	got, err = s.QueryAudit(ctx, "t", store.AuditFilter{EventType: "%.", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a percent sign in the filter matched %d entries, want 0", len(got))
	}
}

func TestUpsertSubjectIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	first, err := s.UpsertSubject(ctx, &store.Subject{
		ID:          "subject-1",
		TenantID:    "tenant-a",
		RefHMAC:     []byte("ref-hmac-1"),
		RefSealed:   []byte("sealed-1"),
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// A second call with the same reference and a different identifier must
	// adopt the existing row rather than insert beside it. The empty display
	// name and the absent sealed reference must not blank what is stored: the
	// caller on the login path holds the HMAC and nothing else.
	second, err := s.UpsertSubject(ctx, &store.Subject{
		ID:       "subject-2",
		TenantID: "tenant-a",
		RefHMAC:  []byte("ref-hmac-1"),
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("second upsert returned id %q, want %q", second.ID, first.ID)
	}
	if second.DisplayName != "Alice" {
		t.Errorf("display name = %q, want it preserved as Alice", second.DisplayName)
	}
	if string(second.RefSealed) != "sealed-1" {
		t.Errorf("ref_sealed = %q, want it preserved", second.RefSealed)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at moved from %s to %s", first.CreatedAt, second.CreatedAt)
	}
	if second.UpdatedAt.Before(first.UpdatedAt) {
		t.Errorf("updated_at went backwards: %s then %s", first.UpdatedAt, second.UpdatedAt)
	}

	// Every instant must come back in UTC, so that a caller cannot tell the two
	// backends apart by the location on a time.Time.
	if loc := second.CreatedAt.Location(); loc != time.UTC {
		t.Errorf("created_at is in %s, want UTC", loc)
	}

	if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE tenant_id = $1`, "tenant-a"); n != 1 {
		t.Fatalf("subjects table holds %d rows, want 1", n)
	}
}

func TestAdvanceSignCount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 10)

	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	if err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 10, 11, now); err != nil {
		t.Fatalf("forward move refused: %v", err)
	}
	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 11 {
		t.Errorf("sign_count = %d, want 11", c.SignCount)
	}
	if c.LastUsedAt == nil || !c.LastUsedAt.Equal(now) {
		t.Errorf("last_used_at = %v, want %s", c.LastUsedAt, now)
	}

	// A stale premise: the caller read 10 but the counter is now 11.
	if err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 10, 12, now); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("stale expectedPrev = %v, want ErrStaleWrite", err)
	}

	// A replay: the counter is presented unchanged, which is either a repeat of
	// an assertion already seen or a clone.
	if err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 11, 11, now); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("replayed counter = %v, want ErrStaleWrite", err)
	}

	// A counter that moves backwards is refused the same way.
	if err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 11, 5, now); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("backwards counter = %v, want ErrStaleWrite", err)
	}

	if err := s.AdvanceSignCount(ctx, "tenant-a", "missing", 0, 1, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown credential = %v, want ErrNotFound", err)
	}

	after, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.SignCount != 11 {
		t.Errorf("sign_count moved to %d despite every refusal", after.SignCount)
	}
	// The transports array has to survive its JSONB round trip.
	if len(after.Transports) != 2 || after.Transports[0] != "internal" {
		t.Errorf("transports = %v, want the two stored values", after.Transports)
	}
}

// sign_count lives in a BIGINT column while the WebAuthn signature counter is a
// uint32, so a damaged or tampered row can hold a value the model cannot
// represent. Reading it must fail rather than narrow the value: a narrowed
// counter is a plausible counter, and it can only make the clone check pass
// where it should have failed.
func TestCredentialRejectsSignCountOutOfRange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 10)

	// wc_sign_count_ck keeps a negative counter out through SQL, so it is
	// dropped for this test. That is what makes the fabricated rows below
	// reachable at all: a real one would come from a restore without the
	// constraint, or from damage below SQL.
	if _, err := s.pool.Exec(ctx,
		`ALTER TABLE webauthn_credentials DROP CONSTRAINT wc_sign_count_ck`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		value int64
	}{
		// 2^32 narrows to 0, which would read as a fresh authenticator.
		{"above_uint32", int64(math.MaxUint32) + 1},
		// -1 narrows to MaxUint32, the largest counter there is, which would
		// refuse every genuine assertion that follows.
		{"negative", -1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.pool.Exec(ctx,
				`UPDATE webauthn_credentials SET sign_count = $1 WHERE id = $2`,
				c.value, "cred-1"); err != nil {
				t.Fatal(err)
			}

			if _, err := s.GetCredential(ctx, "tenant-a", "cred-1"); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("GetCredential = %v, want ErrCorruptRow", err)
			}
			if _, err := s.GetCredentialByID(ctx, "tenant-a", "example.test", []byte("cred-cred-1")); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("GetCredentialByID = %v, want ErrCorruptRow", err)
			}
			if _, err := s.ListCredentials(ctx, "tenant-a", "subject-1", true); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("ListCredentials = %v, want ErrCorruptRow", err)
			}
		})
	}

	// A counter at the top of the range is valid and must still be read.
	if _, err := s.pool.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1 WHERE id = $2`,
		int64(math.MaxUint32), "cred-1"); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatalf("GetCredential at MaxUint32: %v", err)
	}
	if c.SignCount != math.MaxUint32 {
		t.Errorf("sign_count = %d, want %d", c.SignCount, uint32(math.MaxUint32))
	}
}

func TestAdvanceSignCountRace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 0)

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		won    int
		stale  int
		others []error
	)
	start := make(chan struct{})
	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Every goroutine presents the same assertion: it read zero and
			// wants to write one. Exactly one may succeed.
			err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 0, 1, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrStaleWrite):
				stale++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if won != 1 {
		t.Errorf("%d goroutines advanced the counter, want exactly 1", won)
	}
	if stale != racers-1 {
		t.Errorf("%d goroutines were refused, want %d", stale, racers-1)
	}

	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 1 {
		t.Errorf("sign_count = %d, want 1", c.SignCount)
	}
}

func TestConsumeRecoveryCodeRace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	codes := []*store.RecoveryCode{{
		ID:           "code-1",
		Selector:     "sel-1",
		VerifierHash: "hash-1",
	}}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-1", codes); err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		won    int
		stale  int
		others []error
	)
	start := make(chan struct{})
	at := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.ConsumeRecoveryCode(ctx, "tenant-a", "code-1", at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrStaleWrite):
				stale++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if won != 1 {
		t.Errorf("%d goroutines spent the code, want exactly 1", won)
	}
	if stale != racers-1 {
		t.Errorf("%d goroutines were refused, want %d", stale, racers-1)
	}

	unused, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if unused != 0 {
		t.Errorf("%d unused codes remain, want 0", unused)
	}
}

func TestConsumeTOTPStepRace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	if err := s.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID: "totp-1", TenantID: "tenant-a", SubjectID: "subject-1",
		SecretSealed: []byte("sealed"), Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTPSecret(ctx, "tenant-a", "totp-1", time.Now()); err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
		others   []error
	)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Every goroutine presents the same still-valid code.
			res, err := s.ConsumeTOTPStep(ctx, "tenant-a", "totp-1", 0, 5820000)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				others = append(others, err)
			case res.Accepted:
				accepted++
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if accepted != 1 {
		t.Errorf("%d goroutines consumed the timestep, want exactly 1", accepted)
	}

	sec, err := s.GetActiveTOTPSecret(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if sec.LastTimestep != 5820000 {
		t.Errorf("last_timestep = %d, want 5820000", sec.LastTimestep)
	}
}

func TestThrottleHit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	const (
		key    = "bucket-1"
		window = time.Minute
	)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	st, err := s.Hit(ctx, "tenant-a", key, "", window, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 1 || st.Failures != 0 {
		t.Fatalf("first hit: attempts %d failures %d, want 1 and 0", st.Attempts, st.Failures)
	}

	// A success counts towards volume but not towards a lockout, so the two
	// counters have to move independently.
	st, err = s.Hit(ctx, "tenant-a", key, "", window, base.Add(time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 2 || st.Failures != 1 {
		t.Fatalf("second hit: attempts %d failures %d, want 2 and 1", st.Attempts, st.Failures)
	}
	st, err = s.Hit(ctx, "tenant-a", key, "", window, base.Add(2*time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 3 || st.Failures != 1 {
		t.Fatalf("third hit: attempts %d failures %d, want 3 and 1", st.Attempts, st.Failures)
	}
	if !st.WindowStart.Equal(base) {
		t.Errorf("window_start = %s, want it to stay at %s inside the window", st.WindowStart, base)
	}

	until := base.Add(time.Hour)
	if err := s.Block(ctx, "tenant-a", key, until); err != nil {
		t.Fatal(err)
	}

	// The window rolls, and the lockout must survive it. A lockout cleared by
	// the counting window rolling over would last one window instead of one
	// hour. blocked_until is absent from the DO UPDATE for exactly this reason.
	rolled := base.Add(window + time.Second)
	st, err = s.Hit(ctx, "tenant-a", key, "", window, rolled, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 1 || st.Failures != 0 {
		t.Errorf("after the roll: attempts %d failures %d, want 1 and 0", st.Attempts, st.Failures)
	}
	if !st.WindowStart.Equal(rolled) {
		t.Errorf("window_start = %s, want %s", st.WindowStart, rolled)
	}
	if st.BlockedUntil == nil || !st.BlockedUntil.Equal(until) {
		t.Fatalf("blocked_until = %v, want it preserved at %s", st.BlockedUntil, until)
	}
	if !st.Blocked(rolled) {
		t.Error("bucket reports itself unblocked during its own lockout")
	}

	read, err := s.GetThrottle(ctx, "tenant-a", key)
	if err != nil {
		t.Fatal(err)
	}
	if read.Attempts != st.Attempts || read.BlockedUntil == nil || !read.BlockedUntil.Equal(until) {
		t.Errorf("GetThrottle returned %+v, want it to agree with the Hit result", read)
	}

	// The janitor must not end a lockout early.
	removed, err := s.DeleteStaleThrottles(ctx, base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Errorf("the sweep removed %d buckets whose lockout had not expired", removed)
	}
	removed, err = s.DeleteStaleThrottles(ctx, base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("the sweep removed %d buckets, want 1 once the lockout had passed", removed)
	}
}

func TestRaiseAlertDeduplicates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	base := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	raise := func(id string, at time.Time) *store.Alert {
		t.Helper()
		a, err := s.RaiseAlert(ctx, &store.Alert{
			ID:          id,
			TenantID:    "tenant-a",
			AlertType:   "assertion.failed",
			Severity:    store.SeverityWarning,
			SubjectID:   "subject-1",
			Summary:     "repeated assertion failures",
			Detail:      []byte(`{"count":1}`),
			Fingerprint: "fp-1",
			FirstSeenAt: at,
			LastSeenAt:  at,
		})
		if err != nil {
			t.Fatalf("raise %s: %v", id, err)
		}
		return a
	}

	first := raise("alert-1", base)
	if first.Occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", first.Occurrences)
	}

	// The conflict target repeats the partial index predicate. Without it the
	// statement would fail rather than fold, so reaching here at all is part of
	// the assertion.
	second := raise("alert-2", base.Add(time.Minute))
	if second.ID != first.ID {
		t.Errorf("a second occurrence opened row %q instead of folding into %q", second.ID, first.ID)
	}
	if second.Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", second.Occurrences)
	}
	if !second.LastSeenAt.Equal(base.Add(time.Minute)) {
		t.Errorf("last_seen_at = %s, want it moved to %s", second.LastSeenAt, base.Add(time.Minute))
	}
	if !second.FirstSeenAt.Equal(base) {
		t.Errorf("first_seen_at = %s, want it left at %s", second.FirstSeenAt, base)
	}
	if !sameJSON(t, second.Detail, `{"count":1}`) {
		t.Errorf("detail = %s, want the json document round-tripped", second.Detail)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 1 {
		t.Fatalf("alerts table holds %d rows, want 1", n)
	}

	counts, err := s.CountOpenAlerts(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, sev := range []store.Severity{store.SeverityInfo, store.SeverityWarning, store.SeverityCritical} {
		if _, ok := counts[sev]; !ok {
			t.Errorf("severity %q is missing from the count; a caller would have to guard the lookup", sev)
		}
	}
	if counts[store.SeverityWarning] != 1 {
		t.Errorf("warning count = %d, want 1", counts[store.SeverityWarning])
	}
	if counts[store.SeverityCritical] != 0 {
		t.Errorf("critical count = %d, want 0", counts[store.SeverityCritical])
	}

	// Acknowledging takes the row out of the partial unique index, so the next
	// occurrence has to open a fresh alert rather than reviving a closed one.
	if err := s.AcknowledgeAlert(ctx, "tenant-a", first.ID, "operator-1", base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	third := raise("alert-3", base.Add(3*time.Minute))
	if third.ID == first.ID {
		t.Error("an occurrence after acknowledgement reopened the acknowledged row")
	}
	if third.Occurrences != 1 {
		t.Errorf("occurrences on the new alert = %d, want 1", third.Occurrences)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 2 {
		t.Fatalf("alerts table holds %d rows, want 2", n)
	}

	open, err := s.ListAlerts(ctx, "tenant-a", store.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].ID != third.ID {
		t.Errorf("the open list returned %d alerts, want only %s", len(open), third.ID)
	}
	all, err := s.ListAlerts(ctx, "tenant-a", store.AlertFilter{IncludeAcked: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("the full list returned %d alerts, want 2", len(all))
	}

	// A second acknowledgement must not overwrite the first operator's name.
	if err := s.AcknowledgeAlert(ctx, "tenant-a", first.ID, "operator-2", base); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("re-acknowledging = %v, want ErrNotFound", err)
	}
}

func TestDecideApprovalRefusesSelfApproval(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	create := func(id string, expires time.Time) {
		t.Helper()
		err := s.CreateApproval(ctx, &store.ApprovalRequest{
			ID:          id,
			TenantID:    "tenant-a",
			Operation:   "credential.revoke_all",
			Payload:     []byte(`{"subject_id":"subject-1"}`),
			Reason:      "suspected compromise",
			RequestedBy: "admin-one",
			RequestedAt: base,
			ExpiresAt:   expires,
		})
		if err != nil {
			t.Fatalf("create approval %s: %v", id, err)
		}
	}

	create("req-1", base.Add(time.Hour))

	// The requester cannot be the decider, whatever they do to the spelling of
	// their own identifier.
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-one", true, "fine by me", base.Add(time.Minute)); !errors.Is(err, store.ErrSelfApproval) {
		t.Errorf("self-approval = %v, want store.ErrSelfApproval", err)
	}
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", " ADMIN-One ", true, "", base.Add(time.Minute)); !errors.Is(err, store.ErrSelfApproval) {
		t.Errorf("self-approval under a different spelling = %v, want store.ErrSelfApproval", err)
	}
	if errors.Is(store.ErrSelfApproval, store.ErrStaleWrite) {
		t.Error("store.ErrSelfApproval must stay distinct from store.ErrStaleWrite")
	}

	pending, err := s.GetApproval(ctx, "tenant-a", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != store.ApprovalPending {
		t.Fatalf("status = %q after a refused self-approval, want pending", pending.Status)
	}

	decided, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-two", true, "verified with the user", base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second administrator refused: %v", err)
	}
	if decided.Status != store.ApprovalApproved {
		t.Errorf("status = %q, want approved", decided.Status)
	}
	if decided.DecidedBy != "admin-two" || decided.DecidedAt == nil {
		t.Errorf("decision not recorded: %+v", decided)
	}
	if !sameJSON(t, decided.Payload, `{"subject_id":"subject-1"}`) {
		t.Errorf("payload = %s, want the json document round-tripped", decided.Payload)
	}

	// A request already decided is no longer decidable, which is also how the
	// losing side of two simultaneous decisions is told.
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-three", false, "", base.Add(3*time.Minute)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("deciding twice = %v, want ErrStaleWrite", err)
	}

	// An expired request is refused even though it is still marked pending.
	create("req-2", base.Add(time.Minute))
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-2", "admin-two", true, "", base.Add(time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("deciding an expired request = %v, want ErrStaleWrite", err)
	}

	// Only an approved request may be marked executed.
	if err := s.MarkApprovalExecuted(ctx, "tenant-a", "req-2", nil, base.Add(time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("executing a request that was never approved = %v, want ErrStaleWrite", err)
	}
	if err := s.MarkApprovalExecuted(ctx, "tenant-a", "req-1", fmt.Errorf("upstream refused"), base.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	executed, err := s.GetApproval(ctx, "tenant-a", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if executed.Status != store.ApprovalFailed || executed.ExecutionError != "upstream refused" {
		t.Errorf("execution outcome not recorded: %+v", executed)
	}

	expired, err := s.ExpireApprovals(ctx, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if expired != 1 {
		t.Errorf("expired %d requests, want 1", expired)
	}
}

func TestTenantIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")

	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	cred := seedCredential(t, s, "tenant-a", sub.ID, "cred-1", 0)
	alert, err := s.RaiseAlert(ctx, &store.Alert{
		ID:          "alert-1",
		TenantID:    "tenant-a",
		AlertType:   "assertion.failed",
		Severity:    store.SeverityCritical,
		Summary:     "failures",
		Fingerprint: "fp-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("subjects", func(t *testing.T) {
		if _, err := s.GetSubject(ctx, "tenant-b", sub.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetSubject across tenants = %v, want ErrNotFound", err)
		}
		if _, err := s.GetSubjectByRef(ctx, "tenant-b", []byte("ref-1")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetSubjectByRef across tenants = %v, want ErrNotFound", err)
		}
		got, err := s.ListSubjects(ctx, "tenant-b", store.SubjectFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListSubjects under tenant-b returned %d rows", len(got))
		}
		if err := s.SetSubjectStatus(ctx, "tenant-b", sub.ID, store.SubjectLocked); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetSubjectStatus across tenants = %v, want ErrNotFound", err)
		}
		if err := s.PurgeSubject(ctx, "tenant-b", sub.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PurgeSubject across tenants = %v, want ErrNotFound", err)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE id = $1`, sub.ID); n != 1 {
			t.Error("a purge aimed at the wrong tenant removed the subject anyway")
		}
	})

	t.Run("credentials", func(t *testing.T) {
		if _, err := s.GetCredential(ctx, "tenant-b", cred.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetCredential across tenants = %v, want ErrNotFound", err)
		}
		if _, err := s.GetCredentialByID(ctx, "tenant-b", cred.RPID, cred.CredentialID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetCredentialByID across tenants = %v, want ErrNotFound", err)
		}
		got, err := s.ListCredentials(ctx, "tenant-b", sub.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListCredentials under tenant-b returned %d rows", len(got))
		}
		n, err := s.CountActiveCredentials(ctx, "tenant-b", sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("CountActiveCredentials under tenant-b = %d, want 0", n)
		}
		if err := s.RevokeCredential(ctx, "tenant-b", cred.ID, "wrong tenant", time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeCredential across tenants = %v, want ErrNotFound", err)
		}
		if err := s.AdvanceSignCount(ctx, "tenant-b", cred.ID, 0, 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AdvanceSignCount across tenants = %v, want ErrNotFound", err)
		}
	})

	t.Run("alerts", func(t *testing.T) {
		got, err := s.ListAlerts(ctx, "tenant-b", store.AlertFilter{IncludeAcked: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListAlerts under tenant-b returned %d rows", len(got))
		}
		counts, err := s.CountOpenAlerts(ctx, "tenant-b")
		if err != nil {
			t.Fatal(err)
		}
		if counts[store.SeverityCritical] != 0 {
			t.Errorf("critical count under tenant-b = %d, want 0", counts[store.SeverityCritical])
		}
		if err := s.AcknowledgeAlert(ctx, "tenant-b", alert.ID, "operator-b", time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AcknowledgeAlert across tenants = %v, want ErrNotFound", err)
		}

		// The fingerprint is unique per tenant, so tenant-b raising the same
		// condition gets its own row rather than incrementing tenant-a's.
		own, err := s.RaiseAlert(ctx, &store.Alert{
			ID:          "alert-b",
			TenantID:    "tenant-b",
			AlertType:   "assertion.failed",
			Severity:    store.SeverityCritical,
			Summary:     "failures",
			Fingerprint: "fp-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if own.ID != "alert-b" || own.Occurrences != 1 {
			t.Errorf("tenant-b folded into tenant-a's alert: %+v", own)
		}
	})

	t.Run("throttles", func(t *testing.T) {
		// The primary key is (tenant_id, bucket_key), so two tenants deriving
		// the same key hold two independent counters.
		if _, err := s.Hit(ctx, "tenant-a", "shared-bucket", "", time.Minute, time.Now(), true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Hit(ctx, "tenant-b", "shared-bucket", "", time.Minute, time.Now(), true); err != nil {
			t.Fatalf("tenant-b was refused its own bucket under the same key: %v", err)
		}
		if err := s.Block(ctx, "tenant-b", "shared-bucket", time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Block on tenant-b's own bucket: %v", err)
		}

		// tenant-b blocking and counting must leave tenant-a untouched.
		a, err := s.GetThrottle(ctx, "tenant-a", "shared-bucket")
		if err != nil {
			t.Fatal(err)
		}
		if a.Attempts != 1 {
			t.Errorf("tenant-a attempts = %d, want 1", a.Attempts)
		}
		if a.BlockedUntil != nil {
			t.Error("tenant-a's bucket was blocked by tenant-b")
		}

		b, err := s.GetThrottle(ctx, "tenant-b", "shared-bucket")
		if err != nil {
			t.Fatal(err)
		}
		if b.BlockedUntil == nil {
			t.Error("tenant-b's own block did not apply")
		}

		// Resetting one must not reach the other.
		if err := s.ResetThrottle(ctx, "tenant-b", "shared-bucket"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetThrottle(ctx, "tenant-b", "shared-bucket"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant-b's bucket after reset = %v, want ErrNotFound", err)
		}
		if _, err := s.GetThrottle(ctx, "tenant-a", "shared-bucket"); err != nil {
			t.Errorf("tenant-a's bucket was removed by tenant-b's reset: %v", err)
		}

		// A key that exists under no tenant is simply absent.
		if _, err := s.GetThrottle(ctx, "tenant-c", "shared-bucket"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetThrottle for an unrelated tenant = %v, want ErrNotFound", err)
		}
	})

	t.Run("audit", func(t *testing.T) {
		if _, err := s.Append(ctx, &store.AuditEntry{
			TenantID: "tenant-a", EventType: audit.EventAssertionCompleted,
			ActorType: store.ActorSystem, Outcome: store.OutcomeSuccess,
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.QueryAudit(ctx, "tenant-b", store.AuditFilter{Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("QueryAudit under tenant-b returned %d of tenant-a's entries", len(got))
		}
	})
}

func TestPurgeSubjectRemovesDependents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	other := seedSubject(t, s, "tenant-a", "subject-2", "ref-2")
	seedCredential(t, s, "tenant-a", sub.ID, "cred-1", 0)
	seedCredential(t, s, "tenant-a", other.ID, "cred-2", 0)

	if err := s.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID:            "totp-1",
		TenantID:      "tenant-a",
		SubjectID:     sub.ID,
		SecretSealed:  []byte("sealed"),
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", sub.ID, "batch-1", []*store.RecoveryCode{
		{ID: "code-1", Selector: "sel-1", VerifierHash: "h"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChallenge(ctx, &store.Challenge{
		ID:          "chal-1",
		TenantID:    "tenant-a",
		SubjectID:   sub.ID,
		Ceremony:    store.CeremonyAssertion,
		Challenge:   []byte("challenge-bytes"),
		RPID:        "example.test",
		SessionData: []byte("session"),
		ExpiresAt:   time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	// The bucket keys are deliberately opaque here, as the limiter's real keys
	// are: they are SHA-256 digests and carry no recoverable structure. The
	// purge therefore has to find them through the subject_id column, not by
	// pattern-matching the key. Two buckets belong to the purged subject, one
	// to another subject, and one to no subject at all, which is the shape of a
	// bucket keyed on a source address.
	for _, b := range []struct {
		key     string
		subject string
	}{
		{"e3b0c44298fc1c14", sub.ID},
		{"9f86d081884c7d65", sub.ID},
		{"2c26b46b68ffc68f", other.ID},
		{"fcde2b2edba56bf4", ""},
	} {
		if _, err := s.Hit(ctx, "tenant-a", b.key, b.subject, time.Minute, time.Now(), true); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.SoftDeleteSubject(ctx, "tenant-a", sub.ID, time.Now()); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}

	for _, c := range []struct {
		name  string
		query string
	}{
		{"subject", `SELECT COUNT(*) FROM subjects WHERE id = $1`},
		{"credentials", `SELECT COUNT(*) FROM webauthn_credentials WHERE subject_id = $1`},
		{"totp secrets", `SELECT COUNT(*) FROM totp_secrets WHERE subject_id = $1`},
		{"recovery codes", `SELECT COUNT(*) FROM recovery_codes WHERE subject_id = $1`},
		{"challenges", `SELECT COUNT(*) FROM webauthn_challenges WHERE subject_id = $1`},
	} {
		if n := countRows(t, s, c.query, sub.ID); n != 0 {
			t.Errorf("%s: %d rows survived the purge", c.name, n)
		}
	}
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id = $1`, sub.ID); n != 0 {
		t.Errorf("%d throttle buckets belonging to the subject survived the purge, "+
			"which leaves their throttle state behind after an erasure", n)
	}

	// The purge must not reach past its subject.
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id = $1`, other.ID); n != 1 {
		t.Errorf("another subject's throttle bucket count = %d, want 1", n)
	}
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id IS NULL`); n != 1 {
		t.Errorf("unowned throttle bucket count = %d, want 1; a bucket keyed on an "+
			"address bounds everyone's attempts and must survive one subject's purge", n)
	}

	// Everything belonging to the other subject is untouched.
	if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE id = $1`, other.ID); n != 1 {
		t.Error("the purge removed another subject")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM webauthn_credentials WHERE subject_id = $1`, other.ID); n != 1 {
		t.Error("the purge removed another subject's credential")
	}

	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("purging twice = %v, want ErrNotFound", err)
	}
}

func TestConsumeChallengeIsSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	now := time.Date(2026, 7, 1, 11, 0, 0, 0, time.UTC)
	if err := s.CreateChallenge(ctx, &store.Challenge{
		ID: "chal-1", TenantID: "tenant-a", Ceremony: store.CeremonyRegistration,
		Challenge: []byte("challenge-bytes"), RPID: "example.test",
		SessionData: []byte("session"), CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeChallenge(ctx, "tenant-a", "chal-1", now.Add(time.Second))
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if got.ConsumedAt == nil || string(got.SessionData) != "session" {
		t.Errorf("consumed challenge = %+v, want the session data and a consumed stamp", got)
	}

	// A replay, an expiry and an unknown identifier are indistinguishable.
	if _, err := s.ConsumeChallenge(ctx, "tenant-a", "chal-1", now.Add(2*time.Second)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("replayed challenge = %v, want ErrNotFound", err)
	}
	if _, err := s.ConsumeChallenge(ctx, "tenant-a", "missing", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown challenge = %v, want ErrNotFound", err)
	}
	if _, err := s.ConsumeChallenge(ctx, "tenant-b", "chal-1", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("challenge under the wrong tenant = %v, want ErrNotFound", err)
	}
}

func TestEngineAndPing(t *testing.T) {
	s := newTestStore(t)
	if got := s.Engine(); got != "postgres" {
		t.Errorf("Engine() = %q, want postgres", got)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// TestARestoredSubjectIsNotPurged is the erasure that was cancelled while the
// sweep that would have completed it was already running.
//
// The sweep purges from a list of due requests it read earlier. Cancelling
// restores the subject, and a purge that only asked whether the row existed
// removed the restored subject and every factor they had.
func TestARestoredSubjectIsNotPurged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); !errors.Is(err, store.ErrStaleWrite) {
		t.Fatalf("purging a live subject = %v, want store.ErrStaleWrite", err)
	}

	if err := s.SoftDeleteSubject(ctx, "tenant-a", sub.ID, at); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if err := s.RestoreSubject(ctx, "tenant-a", sub.ID, at.Add(time.Minute)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); !errors.Is(err, store.ErrStaleWrite) {
		t.Fatalf("purging a restored subject = %v, want store.ErrStaleWrite", err)
	}
	if _, err := s.GetSubject(ctx, "tenant-a", sub.ID); err != nil {
		t.Fatalf("the restored subject is gone: %v", err)
	}
}
