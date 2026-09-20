package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
)

// auditColumns is the projection used by every read, so the scan helper always
// matches.
const auditColumns = `seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
	subject_id, resource_type, resource_id, outcome, source_ip, request_id,
	detail, pii_salt, pii_digest, prev_hash, entry_hash`

// Append implements store.AuditStore.
//
// Reading the chain head, computing the hashes and inserting the row all happen
// inside one transaction opened with BEGIN IMMEDIATE. Computing the hashes
// outside it would let two concurrent appends read the same predecessor and
// chain onto it in parallel, producing two entries that each claim to follow
// the same one. The write pool holds a single connection, so the transaction
// also serialises appends across goroutines.
func (s *Store) Append(ctx context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if e.TenantID == "" {
		return nil, errors.New("sqlite: audit entry requires a tenant")
	}
	if e.EventType == "" {
		return nil, errors.New("sqlite: audit entry requires an event type")
	}
	if e.Outcome == "" {
		e.Outcome = store.OutcomeSuccess
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if len(e.Detail) == 0 {
		e.Detail = []byte("{}")
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		lastSeq, prevHash, err := chainHeadTx(ctx, tx)
		if err != nil {
			return err
		}

		// SQLite assigns the rowid on insert, so the sequence number the hash
		// commits to has to be known beforehand. Taking lastSeq+1 is exact
		// here because this transaction holds the write lock and the column is
		// AUTOINCREMENT, which never reuses a value.
		if err := audit.Prepare(e, lastSeq+1, prevHash); err != nil {
			return err
		}

		res, err := tx.ExecContext(ctx, `
			INSERT INTO audit_log (
				seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
				subject_id, resource_type, resource_id, outcome, source_ip,
				request_id, detail, pii_salt, pii_digest, prev_hash, entry_hash
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.Seq, e.TenantID, formatTime(e.OccurredAt), e.EventType,
			string(e.ActorType), nullString(e.ActorID), nullString(e.SubjectID),
			nullString(e.ResourceType), nullString(e.ResourceID), string(e.Outcome),
			nullString(e.SourceIP), nullString(e.RequestID), string(e.Detail),
			e.PIISalt, e.PIIDigest, e.PrevHash, e.EntryHash)
		if err != nil {
			return mapError(err)
		}
		if n, err := res.RowsAffected(); err == nil && n != 1 {
			return fmt.Errorf("sqlite: audit insert affected %d rows", n)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sqlite: append audit entry: %w", err)
	}
	return e, nil
}

// ChainHead implements store.AuditStore.
func (s *Store) ChainHead(ctx context.Context) (int64, []byte, error) {
	var seq sql.NullInt64
	var hash []byte
	err := s.read.QueryRowContext(ctx,
		`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// An empty log chains onto the genesis value, not onto zero bytes.
		return s.checkpointHead(ctx)
	case err != nil:
		return 0, nil, fmt.Errorf("sqlite: read chain head: %w", err)
	}
	return seq.Int64, hash, nil
}

// checkpointHead returns the head recorded by the most recent retention
// checkpoint, or the genesis value when the log has never been trimmed.
//
// Without this, trimming every entry would make the log look brand new and a
// verifier would accept a chain that started from nothing.
func (s *Store) checkpointHead(ctx context.Context) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := s.read.QueryRowContext(ctx, `
		SELECT pruned_through_seq, pruned_through_hash
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, audit.Genesis(), nil
	case err != nil:
		return 0, nil, fmt.Errorf("sqlite: read audit checkpoint: %w", err)
	}
	return seq, hash, nil
}

// chainHeadTx is the in-transaction form, reading through the same connection
// that holds the write lock.
func chainHeadTx(ctx context.Context, tx *sql.Tx) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := tx.QueryRowContext(ctx,
		`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if err == nil {
		return seq, hash, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, fmt.Errorf("sqlite: read chain head: %w", err)
	}

	err = tx.QueryRowContext(ctx, `
		SELECT pruned_through_seq, pruned_through_hash
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, audit.Genesis(), nil
	case err != nil:
		return 0, nil, fmt.Errorf("sqlite: read audit checkpoint: %w", err)
	}
	return seq, hash, nil
}

// QueryAudit implements store.AuditStore.
//
// The limit is always applied. An uncapped query over the one table that grows
// without bound is a denial-of-service vector, so a caller asking for
// everything gets a page instead.
func (s *Store) QueryAudit(ctx context.Context, tenantID string, f store.AuditFilter) ([]*store.AuditEntry, error) {
	var (
		where = []string{"tenant_id = ?"}
		args  = []any{tenantID}
	)

	if f.EventType != "" {
		// A trailing dot selects a family, so "webauthn." matches every
		// WebAuthn event without the caller needing to know the full list.
		if strings.HasSuffix(f.EventType, ".") {
			where = append(where, "event_type LIKE ? ESCAPE '\\'")
			args = append(args, escapeLike(f.EventType)+"%")
		} else {
			where = append(where, "event_type = ?")
			args = append(args, f.EventType)
		}
	}
	if f.SubjectID != "" {
		where = append(where, "subject_id = ?")
		args = append(args, f.SubjectID)
	}
	if f.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Outcome != "" {
		where = append(where, "outcome = ?")
		args = append(args, string(f.Outcome))
	}
	if !f.Since.IsZero() {
		where = append(where, "occurred_at >= ?")
		args = append(args, formatTime(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "occurred_at < ?")
		args = append(args, formatTime(f.Until))
	}
	if f.AfterSeq > 0 {
		// Keyset pagination rather than OFFSET: an offset scan re-reads every
		// skipped row, which on an audit log that only grows means later pages
		// get steadily slower.
		where = append(where, "seq > ?")
		args = append(args, f.AfterSeq)
	}

	limit := clampLimit(f.Limit, 100, 10000)
	args = append(args, limit)

	// #nosec G202 -- auditColumns is a package constant and every where entry is a literal above; the event-type
	// prefix is escaped by escapeLike and bound as a ? parameter like the rest of the filter
	query := `SELECT ` + auditColumns + ` FROM audit_log WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY seq ASC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query audit: %w", err)
	}
	defer rows.Close()

	var out []*store.AuditEntry
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate audit: %w", err)
	}
	return out, nil
}

// ReadAuditRange implements store.AuditStore.
//
// The read spans every tenant, for the reason VerifyChain does: an entry
// recorded against the reserved system tenant sits between two ordinary ones,
// and filtering it out would present a contiguous chain as one full of holes.
//
// The comparison is seq >= fromSeq rather than the seq > cursor that the chain
// walk uses, because the caller here names the first entry it wants rather than
// the last one it already has.
func (s *Store) ReadAuditRange(ctx context.Context, fromSeq int64, limit int) ([]*store.AuditEntry, error) {
	if fromSeq < 1 {
		fromSeq = 1
	}

	rows, err := s.read.QueryContext(ctx,
		`SELECT `+auditColumns+` FROM audit_log WHERE seq >= ? ORDER BY seq ASC LIMIT ?`,
		fromSeq, clampLimit(limit, 100, 10000))
	if err != nil {
		return nil, fmt.Errorf("sqlite: read audit range: %w", err)
	}
	defer rows.Close()

	var out []*store.AuditEntry
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate audit range: %w", err)
	}
	return out, nil
}

// VerifyChain implements store.AuditStore.
//
// Entries are walked in pages so that verifying a large log does not hold the
// whole thing in memory. Each page is checked against the hash carried over
// from the previous one, so the pages join up into a single walk.
func (s *Store) VerifyChain(ctx context.Context, fromSeq int64) (int64, int64, error) {
	prevHash, err := s.hashBefore(ctx, fromSeq)
	if err != nil {
		return 0, 0, err
	}

	const page = 1000
	var (
		checked int64
		cursor  = fromSeq - 1
	)
	if cursor < 0 {
		cursor = 0
	}

	for {
		rows, err := s.read.QueryContext(ctx,
			`SELECT `+auditColumns+` FROM audit_log WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
			cursor, page)
		if err != nil {
			return checked, 0, fmt.Errorf("sqlite: verify chain: %w", err)
		}

		var batch []*store.AuditEntry
		for rows.Next() {
			e, err := scanAuditEntry(rows)
			if err != nil {
				// The scan already failed, so a close error cannot change what
				// this call reports.
				_ = rows.Close()
				return checked, 0, err
			}
			batch = append(batch, e)
		}
		if err := rows.Err(); err != nil {
			// Reporting the iteration error, which is the one that says what
			// went wrong; a close error here would be the same fault twice.
			_ = rows.Close()
			return checked, 0, fmt.Errorf("sqlite: iterate chain: %w", err)
		}
		// rows.Err has just been checked, and Close reports the same error, so
		// there is nothing left for it to tell this walk.
		_ = rows.Close()

		if len(batch) == 0 {
			return checked, 0, nil
		}

		if broken := audit.VerifySequence(batch, prevHash); broken != 0 {
			return checked, broken, nil
		}

		checked += int64(len(batch))
		prevHash = batch[len(batch)-1].EntryHash
		cursor = batch[len(batch)-1].Seq

		if err := ctx.Err(); err != nil {
			return checked, 0, err
		}
	}
}

// hashBefore returns the hash the entry at fromSeq is expected to chain onto.
func (s *Store) hashBefore(ctx context.Context, fromSeq int64) ([]byte, error) {
	if fromSeq <= 1 {
		// Starting from the beginning. If the log has been trimmed, the walk
		// resumes from the checkpoint rather than from genesis.
		var hash []byte
		err := s.read.QueryRowContext(ctx, `
			SELECT pruned_through_hash FROM audit_checkpoints
			ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			return audit.Genesis(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("sqlite: read audit checkpoint: %w", err)
		}
		return hash, nil
	}

	var hash []byte
	err := s.read.QueryRowContext(ctx,
		`SELECT entry_hash FROM audit_log WHERE seq < ? ORDER BY seq DESC LIMIT 1`,
		fromSeq).Scan(&hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return audit.Genesis(), nil
	case err != nil:
		return nil, fmt.Errorf("sqlite: read predecessor hash: %w", err)
	}
	return hash, nil
}

// EraseSubjectAuditEntries clears the personal fields from every entry naming a
// subject, and appends a tombstone recording that it happened.
//
// This is how an erasure request is honoured without breaking the chain: the
// hashes cover a salted digest of the personal fields rather than the fields
// themselves, so destroying the salt removes the ability to recover them while
// leaving verification intact. See package audit.
func (s *Store) EraseSubjectAuditEntries(ctx context.Context, tenantID, subjectID, actorID string, now time.Time) (int64, error) {
	if tenantID == "" || subjectID == "" {
		return 0, errors.New("sqlite: erase requires a tenant and a subject")
	}

	var affected int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// The update guard permits exactly this shape and nothing else.
		res, err := tx.ExecContext(ctx, `
			UPDATE audit_log
			SET subject_id = NULL, source_ip = NULL, pii_salt = NULL, detail = '{}'
			WHERE tenant_id = ? AND subject_id = ? AND pii_salt IS NOT NULL`,
			tenantID, subjectID)
		if err != nil {
			return mapError(err)
		}
		affected, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count erased entries: %w", err)
		}

		tombstone := &store.AuditEntry{
			TenantID:     tenantID,
			OccurredAt:   now.UTC(),
			EventType:    audit.EventSubjectRedacted,
			ActorType:    store.ActorAdmin,
			ActorID:      actorID,
			ResourceType: "subject",
			ResourceID:   subjectID,
			Outcome:      store.OutcomeSuccess,
			Detail:       []byte(fmt.Sprintf(`{"erased_entries":%d}`, affected)),
		}

		lastSeq, prevHash, err := chainHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := audit.Prepare(tombstone, lastSeq+1, prevHash); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO audit_log (
				seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
				subject_id, resource_type, resource_id, outcome, source_ip,
				request_id, detail, pii_salt, pii_digest, prev_hash, entry_hash
			) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)`,
			tombstone.Seq, tombstone.TenantID, formatTime(tombstone.OccurredAt),
			tombstone.EventType, string(tombstone.ActorType), nullString(tombstone.ActorID),
			tombstone.ResourceType, tombstone.ResourceID, string(tombstone.Outcome),
			string(tombstone.Detail), tombstone.PIISalt, tombstone.PIIDigest,
			tombstone.PrevHash, tombstone.EntryHash)
		return mapError(err)
	})
	if err != nil {
		return 0, fmt.Errorf("sqlite: erase audit entries for subject: %w", err)
	}
	return affected, nil
}

// PruneAuditLog removes entries older than before, recording a checkpoint first
// so the remaining chain stays verifiable.
//
// The order matters and is enforced by the delete guard: the checkpoint has to
// exist before any row can be deleted. The checkpoint commits to the hash of
// the last entry removed, which is what a verifier resumes from.
func (s *Store) PruneAuditLog(ctx context.Context, tenantID string, before time.Time, now time.Time) (int64, error) {
	var removed int64

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// Find the newest entry that falls inside the retention cut. Pruning
		// is by sequence number rather than by timestamp so that the chain is
		// trimmed as a contiguous prefix; deleting a scattered set of entries
		// would break verification for everything after each gap.
		var lastSeq int64
		var lastHash []byte
		err := tx.QueryRowContext(ctx, `
			SELECT seq, entry_hash FROM audit_log
			WHERE occurred_at < ? ORDER BY seq DESC LIMIT 1`,
			formatTime(before)).Scan(&lastSeq, &lastHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // nothing old enough
		}
		if err != nil {
			return fmt.Errorf("sqlite: find prune boundary: %w", err)
		}

		var count int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE seq <= ?`, lastSeq).Scan(&count); err != nil {
			return fmt.Errorf("sqlite: count prunable entries: %w", err)
		}

		// Record the trim as an audited event before it happens, so a log that
		// is trimmed always carries the evidence of having been trimmed.
		marker := &store.AuditEntry{
			TenantID:     tenantID,
			OccurredAt:   now.UTC(),
			EventType:    audit.EventChainVerified,
			ActorType:    store.ActorSystem,
			ResourceType: "audit_log",
			Outcome:      store.OutcomeSuccess,
			Detail: []byte(fmt.Sprintf(
				`{"action":"retention_prune","pruned_through_seq":%d,"entries":%d}`,
				lastSeq, count)),
		}
		headSeq, prevHash, err := chainHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := audit.Prepare(marker, headSeq+1, prevHash); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_log (
				seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
				subject_id, resource_type, resource_id, outcome, source_ip,
				request_id, detail, pii_salt, pii_digest, prev_hash, entry_hash
			) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, NULL, NULL, ?, ?, ?, ?, ?)`,
			marker.Seq, marker.TenantID, formatTime(marker.OccurredAt), marker.EventType,
			string(marker.ActorType), marker.ResourceType, string(marker.Outcome),
			string(marker.Detail), marker.PIISalt, marker.PIIDigest,
			marker.PrevHash, marker.EntryHash); err != nil {
			return mapError(err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_checkpoints (
				id, tenant_id, pruned_through_seq, pruned_through_hash,
				entries_removed, audit_seq, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uuid.NewString(), tenantID, lastSeq, lastHash, count, marker.Seq,
			formatTime(now)); err != nil {
			return mapError(err)
		}

		res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= ?`, lastSeq)
		if err != nil {
			return mapError(err)
		}
		removed, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count removed entries: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune audit log: %w", err)
	}
	return removed, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuditEntry(sc rowScanner) (*store.AuditEntry, error) {
	var (
		e            store.AuditEntry
		occurredAt   string
		actorType    string
		outcome      string
		detail       string
		actorID      sql.NullString
		subjectID    sql.NullString
		resourceType sql.NullString
		resourceID   sql.NullString
		sourceIP     sql.NullString
		requestID    sql.NullString
	)
	if err := sc.Scan(
		&e.Seq, &e.TenantID, &occurredAt, &e.EventType, &actorType, &actorID,
		&subjectID, &resourceType, &resourceID, &outcome, &sourceIP, &requestID,
		&detail, &e.PIISalt, &e.PIIDigest, &e.PrevHash, &e.EntryHash,
	); err != nil {
		return nil, mapError(err)
	}

	t, err := parseTime(occurredAt)
	if err != nil {
		return nil, err
	}
	e.OccurredAt = t
	e.ActorType = store.ActorType(actorType)
	e.Outcome = store.Outcome(outcome)
	e.ActorID = stringOrEmpty(actorID)
	e.SubjectID = stringOrEmpty(subjectID)
	e.ResourceType = stringOrEmpty(resourceType)
	e.ResourceID = stringOrEmpty(resourceID)
	e.SourceIP = stringOrEmpty(sourceIP)
	e.RequestID = stringOrEmpty(requestID)

	// An erased entry stores "{}" for detail. Normalising it back to nil keeps
	// the hash input identical to what Erase produced in memory.
	if detail != "" && detail != "{}" {
		e.Detail = []byte(detail)
	} else if len(e.PIISalt) > 0 {
		e.Detail = []byte("{}")
	}
	return &e, nil
}

// escapeLike neutralises the wildcards in a value interpolated into a LIKE
// pattern, so a caller cannot widen the match by including a percent sign.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
