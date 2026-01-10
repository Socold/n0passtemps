package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
)

// auditColumns is the projection used by every read, so the scan helper always
// matches.
const auditColumns = `seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
	subject_id, resource_type, resource_id, outcome, source_ip, request_id,
	detail, pii_salt, pii_digest, prev_hash, entry_hash`

// auditAppendLockKey is the advisory lock every append to the chain takes.
//
// It is the FNV-1a 64-bit hash of "n0passtemps/audit_log", written out as a
// literal so that the value cannot drift if the derivation is ever reworded.
// Deriving it from the relation name keeps it from colliding with an advisory
// lock some other part of a deployment happens to take on the same connection.
const auditAppendLockKey int64 = 5261336707448738216

// Append implements store.AuditStore.
//
// Reading the chain head, computing the hashes and inserting the row all happen
// inside one transaction holding an advisory lock. Computing the hashes outside
// it would let two concurrent appends read the same predecessor and chain onto
// it in parallel, producing two entries that each claim to follow the same one.
//
// Unlike the SQLite implementation there is no single write connection doing
// that serialisation as a side effect, so the lock is explicit. See
// prepareAppend for why it is an advisory lock.
func (s *Store) Append(ctx context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if e.TenantID == "" {
		return nil, errors.New("postgres: audit entry requires a tenant")
	}
	if e.EventType == "" {
		return nil, errors.New("postgres: audit entry requires an event type")
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

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := prepareAppend(ctx, tx, e); err != nil {
			return err
		}
		return insertAuditEntry(ctx, tx, e)
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: append audit entry: %w", err)
	}
	return e, nil
}

// prepareAppend fills in the chain fields of an entry about to be inserted, and
// leaves the transaction holding the lock that makes the result unique.
//
// Three engine properties have to be reconciled here, and each one dictates one
// of the steps below.
//
// The lock. Under READ COMMITTED two transactions can both read the current
// chain head and both insert an entry naming it as their predecessor, which
// produces a fork the verifier reports as a break. A SELECT ... FOR UPDATE on
// the head row would not close it either, because the row a second appender
// needs to lock does not exist yet when the first one reads. The lock is
// therefore taken on the relation rather than on a row, and it is
// pg_advisory_xact_lock rather than LOCK TABLE audit_log because the advisory
// lock excludes only other appenders: LOCK TABLE at any level strong enough to
// serialise writers also blocks the readers that QueryAudit and VerifyChain
// issue, and verification walks the whole log. SERIALIZABLE with a retry is
// available and would also be correct, but a serialisation failure would land
// on the authentication path, and a retried transaction there is worse than the
// short wait this lock costs. The lock is released at commit, so it is held for
// one insert.
//
// The sequence number. seq is BIGSERIAL, so the value normally comes from the
// insert, but audit.Prepare needs it beforehand because the hash commits to it.
// The SQLite implementation takes lastSeq+1, which is exact there because
// AUTOINCREMENT never reuses a value and the transaction holds the write lock.
// It does not transfer: a sequence hands out values outside the transaction, so
// a rolled back insert leaves a gap and lastSeq+1 would name a number already
// spent. The value is drawn explicitly instead, inside the transaction that
// holds the lock, which is also what keeps seq order and chain order the same.
//
// The detail document. JSONB is stored decomposed and rendered back in the
// server's own spelling, so the bytes handed in are not the bytes read out:
// object keys are reordered and a space follows every colon. The chain commits
// to the detail bytes through the personal-field digest, so hashing what the
// caller supplied would make the entry fail verification the moment it is read
// back. The document is canonicalised through the server first, and the entry
// carries the canonical form afterwards.
//
// The timestamp is truncated for the same reason. TIMESTAMPTZ has microsecond
// resolution and the chain commits to a nanosecond count, so an entry stamped
// from time.Now would hash a value the database cannot store.
func prepareAppend(ctx context.Context, tx pgx.Tx, e *store.AuditEntry) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditAppendLockKey); err != nil {
		return fmt.Errorf("postgres: take audit append lock: %w", err)
	}

	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	if len(e.Detail) == 0 {
		e.Detail = []byte("{}")
	}

	var (
		seq       int64
		canonical []byte
	)
	if err := tx.QueryRow(ctx,
		`SELECT nextval(pg_get_serial_sequence('audit_log', 'seq')), $1::jsonb`,
		e.Detail).Scan(&seq, &canonical); err != nil {
		return fmt.Errorf("postgres: draw audit sequence number: %w", mapError(err))
	}
	e.Detail = canonical

	_, prevHash, err := chainHeadTx(ctx, tx)
	if err != nil {
		return err
	}
	return audit.Prepare(e, seq, prevHash)
}

// insertAuditEntry writes a prepared entry.
//
// The three append paths in this file share one statement rather than repeating
// the seventeen columns, so a column added to the projection cannot be wired
// into one insert and forgotten in another.
func insertAuditEntry(ctx context.Context, tx pgx.Tx, e *store.AuditEntry) error {
	tag, err := tx.Exec(ctx, `
		INSERT INTO audit_log (
			seq, tenant_id, occurred_at, event_type, actor_type, actor_id,
			subject_id, resource_type, resource_id, outcome, source_ip,
			request_id, detail, pii_salt, pii_digest, prev_hash, entry_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		e.Seq, e.TenantID, e.OccurredAt, e.EventType,
		string(e.ActorType), nullString(e.ActorID), nullString(e.SubjectID),
		nullString(e.ResourceType), nullString(e.ResourceID), string(e.Outcome),
		nullString(e.SourceIP), nullString(e.RequestID), e.Detail,
		e.PIISalt, e.PIIDigest, e.PrevHash, e.EntryHash)
	if err != nil {
		return mapError(err)
	}
	if n := tag.RowsAffected(); n != 1 {
		return fmt.Errorf("postgres: audit insert affected %d rows", n)
	}
	return nil
}

// ChainHead implements store.AuditStore.
func (s *Store) ChainHead(ctx context.Context) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := s.pool.QueryRow(ctx,
		`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// An empty log chains onto the genesis value, not onto zero bytes.
		return s.checkpointHead(ctx)
	case err != nil:
		return 0, nil, fmt.Errorf("postgres: read chain head: %w", err)
	}
	return seq, hash, nil
}

// checkpointHead returns the head recorded by the most recent retention
// checkpoint, or the genesis value when the log has never been trimmed.
//
// Without this, trimming every entry would make the log look brand new and a
// verifier would accept a chain that started from nothing.
func (s *Store) checkpointHead(ctx context.Context) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := s.pool.QueryRow(ctx, `
		SELECT pruned_through_seq, pruned_through_hash
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, audit.Genesis(), nil
	case err != nil:
		return 0, nil, fmt.Errorf("postgres: read audit checkpoint: %w", err)
	}
	return seq, hash, nil
}

// chainHeadTx is the in-transaction form, reading through the transaction that
// holds the append lock.
func chainHeadTx(ctx context.Context, tx pgx.Tx) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := tx.QueryRow(ctx,
		`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if err == nil {
		return seq, hash, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, fmt.Errorf("postgres: read chain head: %w", err)
	}

	err = tx.QueryRow(ctx, `
		SELECT pruned_through_seq, pruned_through_hash
		FROM audit_checkpoints ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, audit.Genesis(), nil
	case err != nil:
		return 0, nil, fmt.Errorf("postgres: read audit checkpoint: %w", err)
	}
	return seq, hash, nil
}

// QueryAudit implements store.AuditStore.
//
// The limit is always applied. An uncapped query over the one table that grows
// without bound is a denial-of-service vector, so a caller asking for
// everything gets a page instead.
func (s *Store) QueryAudit(ctx context.Context, tenantID string, f store.AuditFilter) ([]*store.AuditEntry, error) {
	var a argset
	where := []string{"tenant_id = " + a.add(tenantID)}

	if f.EventType != "" {
		// A trailing dot selects a family, so "webauthn." matches every
		// WebAuthn event without the caller needing to know the full list.
		if strings.HasSuffix(f.EventType, ".") {
			where = append(where, "event_type LIKE "+a.add(escapeLike(f.EventType)+"%")+` ESCAPE '\'`)
		} else {
			where = append(where, "event_type = "+a.add(f.EventType))
		}
	}
	if f.SubjectID != "" {
		where = append(where, "subject_id = "+a.add(f.SubjectID))
	}
	if f.ActorID != "" {
		where = append(where, "actor_id = "+a.add(f.ActorID))
	}
	if f.Outcome != "" {
		where = append(where, "outcome = "+a.add(string(f.Outcome)))
	}
	if !f.Since.IsZero() {
		where = append(where, "occurred_at >= "+a.add(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "occurred_at < "+a.add(f.Until))
	}
	if f.AfterSeq > 0 {
		// Keyset pagination rather than OFFSET: an offset scan re-reads every
		// skipped row, which on an audit log that only grows means later pages
		// get steadily slower.
		where = append(where, "seq > "+a.add(f.AfterSeq))
	}

	query := `SELECT ` + auditColumns + ` FROM audit_log WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY seq ASC LIMIT ` +
		a.add(clampLimit(f.Limit, 100, 10000))

	rows, err := s.pool.Query(ctx, query, a.args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: query audit: %w", err)
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
		return nil, fmt.Errorf("postgres: iterate audit: %w", err)
	}
	return out, nil
}

// VerifyChain implements store.AuditStore.
//
// Entries are walked in pages so that verifying a large log does not hold the
// whole thing in memory. Each page is checked against the hash carried over
// from the previous one, so the pages join up into a single walk.
//
// The walk spans every tenant, because the chain does: an entry recorded
// against the reserved system tenant sits between two ordinary ones, and
// verifying one tenant's entries alone would report a break at every such gap.
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
		rows, err := s.pool.Query(ctx,
			`SELECT `+auditColumns+` FROM audit_log WHERE seq > $1 ORDER BY seq ASC LIMIT $2`,
			cursor, page)
		if err != nil {
			return checked, 0, fmt.Errorf("postgres: verify chain: %w", err)
		}

		var batch []*store.AuditEntry
		for rows.Next() {
			e, err := scanAuditEntry(rows)
			if err != nil {
				rows.Close()
				return checked, 0, err
			}
			batch = append(batch, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return checked, 0, fmt.Errorf("postgres: iterate chain: %w", err)
		}
		rows.Close()

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
		err := s.pool.QueryRow(ctx, `
			SELECT pruned_through_hash FROM audit_checkpoints
			ORDER BY pruned_through_seq DESC LIMIT 1`).Scan(&hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return audit.Genesis(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("postgres: read audit checkpoint: %w", err)
		}
		return hash, nil
	}

	var hash []byte
	err := s.pool.QueryRow(ctx,
		`SELECT entry_hash FROM audit_log WHERE seq < $1 ORDER BY seq DESC LIMIT 1`,
		fromSeq).Scan(&hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return audit.Genesis(), nil
	case err != nil:
		return nil, fmt.Errorf("postgres: read predecessor hash: %w", err)
	}
	return hash, nil
}

// EraseSubjectAuditEntries implements store.AuditStore.
//
// It clears the personal fields from every entry naming a subject and appends a
// tombstone recording that it happened.
//
// This is how an erasure request is honoured without breaking the chain: the
// hashes cover a salted digest of the personal fields rather than the fields
// themselves, so destroying the salt removes the ability to recover them while
// leaving verification intact. See package audit.
func (s *Store) EraseSubjectAuditEntries(ctx context.Context, tenantID, subjectID, actorID string, now time.Time) (int64, error) {
	if tenantID == "" || subjectID == "" {
		return 0, errors.New("postgres: erase requires a tenant and a subject")
	}

	var affected int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// The update guard permits exactly this shape and nothing else. The
		// cast on the empty document is what makes it comparable to the
		// '{}'::jsonb the guard tests for.
		tag, err := tx.Exec(ctx, `
			UPDATE audit_log
			SET subject_id = NULL, source_ip = NULL, pii_salt = NULL, detail = '{}'::jsonb
			WHERE tenant_id = $1 AND subject_id = $2 AND pii_salt IS NOT NULL`,
			tenantID, subjectID)
		if err != nil {
			return mapError(err)
		}
		affected = tag.RowsAffected()

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

		if err := prepareAppend(ctx, tx, tombstone); err != nil {
			return err
		}
		return insertAuditEntry(ctx, tx, tombstone)
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: erase audit entries for subject: %w", err)
	}
	return affected, nil
}

// PruneAuditLog implements store.AuditStore.
//
// It removes entries older than before, recording a checkpoint first so the
// remaining chain stays verifiable.
//
// The order matters and is enforced by the delete guard: the checkpoint has to
// exist before any row can be deleted. The checkpoint commits to the hash of
// the last entry removed, which is what a verifier resumes from.
func (s *Store) PruneAuditLog(ctx context.Context, tenantID string, before time.Time, now time.Time) (int64, error) {
	var removed int64

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Find the newest entry that falls inside the retention cut. Pruning
		// is by sequence number rather than by timestamp so that the chain is
		// trimmed as a contiguous prefix; deleting a scattered set of entries
		// would break verification for everything after each gap.
		var lastSeq int64
		var lastHash []byte
		err := tx.QueryRow(ctx, `
			SELECT seq, entry_hash FROM audit_log
			WHERE occurred_at < $1 ORDER BY seq DESC LIMIT 1`,
			before).Scan(&lastSeq, &lastHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // nothing old enough
		}
		if err != nil {
			return fmt.Errorf("postgres: find prune boundary: %w", err)
		}

		var count int64
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE seq <= $1`, lastSeq).Scan(&count); err != nil {
			return fmt.Errorf("postgres: count prunable entries: %w", err)
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
		if err := prepareAppend(ctx, tx, marker); err != nil {
			return err
		}
		if err := insertAuditEntry(ctx, tx, marker); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_checkpoints (
				id, tenant_id, pruned_through_seq, pruned_through_hash,
				entries_removed, audit_seq, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			uuid.NewString(), tenantID, lastSeq, lastHash, count, marker.Seq,
			now); err != nil {
			return mapError(err)
		}

		tag, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE seq <= $1`, lastSeq)
		if err != nil {
			return mapError(err)
		}
		removed = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: prune audit log: %w", err)
	}
	return removed, nil
}

func scanAuditEntry(sc rowScanner) (*store.AuditEntry, error) {
	var (
		e            store.AuditEntry
		occurredAt   time.Time
		actorType    string
		outcome      string
		detail       []byte
		actorID      *string
		subjectID    *string
		resourceType *string
		resourceID   *string
		sourceIP     *string
		requestID    *string
	)
	if err := sc.Scan(
		&e.Seq, &e.TenantID, &occurredAt, &e.EventType, &actorType, &actorID,
		&subjectID, &resourceType, &resourceID, &outcome, &sourceIP, &requestID,
		&detail, &e.PIISalt, &e.PIIDigest, &e.PrevHash, &e.EntryHash,
	); err != nil {
		return nil, mapError(err)
	}

	e.OccurredAt = utc(occurredAt)
	e.ActorType = store.ActorType(actorType)
	e.Outcome = store.Outcome(outcome)
	e.ActorID = text(actorID)
	e.SubjectID = text(subjectID)
	e.ResourceType = text(resourceType)
	e.ResourceID = text(resourceID)
	e.SourceIP = text(sourceIP)
	e.RequestID = text(requestID)

	// An erased entry stores "{}" for detail. Normalising it back to nil keeps
	// the hash input identical to what Erase produced in memory.
	if len(detail) > 0 && string(detail) != "{}" {
		e.Detail = detail
	} else if len(e.PIISalt) > 0 {
		e.Detail = []byte("{}")
	}
	return &e, nil
}
