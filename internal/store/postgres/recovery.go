package postgres

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const recoveryColumns = `id, tenant_id, subject_id, batch_id, selector, verifier_hash,
	created_at, consumed_at`

// recoveryBatchLockKey derives the advisory key that one subject's batch
// replacement holds.
//
// The literal below is part of the derivation and must not be reworded: two
// replicas that hashed different strings would compute different keys for the
// same subject and would not exclude each other, which is the whole point of
// the lock. It names this project so the key cannot collide with an advisory
// lock some other part of a deployment takes, in the same way
// auditAppendLockKey does, and the tenant and the subject are separated by a
// NUL so that two different pairs cannot concatenate to the same string.
func recoveryBatchLockKey(tenantID, subjectID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("n0passtemps/recovery_codes\x00" + tenantID + "\x00" + subjectID))
	// #nosec G115 -- an advisory key is an opaque 64 bit value and the server's parameter is signed
	return int64(h.Sum64())
}

// ReplaceRecoveryCodes implements store.RecoveryStore.
//
// Retiring the previous batch and inserting the new one happen in one
// transaction. Issuing a batch without retiring the old one leaves codes in
// circulation that the user has been told are dead, which is the worst of both
// outcomes: the user believes the printed sheet they threw away is worthless,
// and it is not.
//
// Unused codes from earlier batches are deleted rather than marked consumed.
// Marking them consumed would record a spend that never happened, and the
// counters and the audit trail would then disagree about how many codes the
// subject actually used. Codes that have genuinely been consumed are left in
// place: they are evidence of an authentication and belong in the trail.
//
// The transaction opens by taking an advisory lock on the subject, and that is
// the one place this implementation needs more than the SQLite one. The
// statements above exclude nothing on their own: under READ COMMITTED each of
// two concurrent replacements deletes the codes it can see, which are the ones
// committed before it started, and then inserts a batch the other cannot see
// either. Both commit, and the subject is left holding two live sheets when
// they were told the first was dead. There is no row to lock, because the rows
// that would conflict have not been written yet, so the lock is taken on the
// subject's name instead. It is per subject rather than global, so two users
// reprinting their sheets at the same moment do not queue behind each other,
// and it is a transaction-level lock, so it is released at commit or rollback
// whatever happens next.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, tenantID, subjectID, batchID string,
	codes []*store.RecoveryCode) error {
	if tenantID == "" || subjectID == "" || batchID == "" {
		return errors.New("postgres: recovery batch requires a tenant, a subject and a batch id")
	}
	if len(codes) == 0 {
		return errors.New("postgres: recovery batch requires at least one code")
	}
	for i, c := range codes {
		if c == nil {
			return fmt.Errorf("postgres: recovery code %d is nil", i)
		}
		if c.ID == "" || c.Selector == "" || c.VerifierHash == "" {
			return fmt.Errorf("postgres: recovery code %d requires an id, a selector and a verifier hash", i)
		}
	}

	now := time.Now().UTC()

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`,
			recoveryBatchLockKey(tenantID, subjectID)); err != nil {
			return fmt.Errorf("take the recovery batch lock: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			DELETE FROM recovery_codes
			WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL AND batch_id <> $3`,
			tenantID, subjectID, batchID); err != nil {
			return mapError(err)
		}

		for i, c := range codes {
			// The tenant, the subject and the batch come from the arguments
			// rather than from the code, so one mismatched element cannot scatter
			// a batch across two subjects.
			c.TenantID = tenantID
			c.SubjectID = subjectID
			c.BatchID = batchID
			if c.CreatedAt.IsZero() {
				c.CreatedAt = now
			}

			if _, err := tx.Exec(ctx, `
				INSERT INTO recovery_codes (`+recoveryColumns+`)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				c.ID, c.TenantID, c.SubjectID, c.BatchID, c.Selector, c.VerifierHash,
				c.CreatedAt, c.ConsumedAt); err != nil {
				return fmt.Errorf("code %d: %w", i, mapError(err))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: replace recovery codes: %w", err)
	}
	return nil
}

// GetRecoveryCodeBySelector implements store.RecoveryStore.
//
// The lookup is by selector so that verifying a presented code is one indexed
// probe plus one Argon2id evaluation. Matching on the verifier hash instead
// would mean evaluating Argon2id once per stored code, which is a
// denial-of-service vector aimed at the server's own CPU.
//
// A consumed code is still returned. The caller compares the verifier first and
// then decides, so that a code that is merely spent and a code that never
// existed take the same amount of work to reject.
func (s *Store) GetRecoveryCodeBySelector(ctx context.Context, tenantID, selector string) (*store.RecoveryCode, error) {
	if selector == "" {
		return nil, errors.New("postgres: recovery code lookup requires a selector")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+recoveryColumns+` FROM recovery_codes
		WHERE tenant_id = $1 AND selector = $2`,
		tenantID, selector)
	return scanRecoveryCode(row)
}

// ConsumeRecoveryCode implements store.RecoveryStore.
//
// The update is a compare-and-swap on consumed_at being NULL, in one statement,
// for the same reason as ConsumeTOTPStep: a single-use code that two concurrent
// requests both read as unused and both spend is not single-use at all. The
// database evaluates the condition while it holds the row, so exactly one of
// those requests can win. The second one blocks on the row lock, then re-tests
// consumed_at against the committed value and matches nothing, which is why no
// transaction and no raised isolation level are needed around it.
//
// store.ErrStaleWrite is returned when the row exists and was already consumed.
// That is the losing side of the race, or a replay, and the correct response is
// a rejected authentication rather than a fault.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, tenantID, id string, at time.Time) error {
	var consumed time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE recovery_codes SET consumed_at = $1
		WHERE tenant_id = $2 AND id = $3 AND consumed_at IS NULL
		RETURNING consumed_at`,
		at, tenantID, id).Scan(&consumed)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: consume recovery code: %w", mapError(err))
	}

	var exists int
	err = s.pool.QueryRow(ctx,
		`SELECT 1 FROM recovery_codes WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: consume recovery code: read code: %w", err)
	}
	return store.ErrStaleWrite
}

// DeleteConsumedRecoveryCodes removes the codes spent before the given instant.
//
// It is the counterpart of the enrolment ticket sweep, and it exists for the
// same two reasons. A spent code is evidence of an authentication, so it is
// kept for long enough to answer a question about that authentication, and the
// durable record past that point is the audit log. And a code that stays
// keeps its selector, which is 30 bits and has to be unique within the tenant:
// a table nothing ever shrinks is one whose next batch is a little more likely
// to collide with something spent years ago and be refused. See
// internal/crypto/recovery on why the selector is that wide and why widening it
// is not the answer.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them, and the janitor is what chooses the retention window.
func (s *Store) DeleteConsumedRecoveryCodes(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM recovery_codes WHERE consumed_at IS NOT NULL AND consumed_at < $1`,
		before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete consumed recovery codes: %w", mapError(err))
	}
	return tag.RowsAffected(), nil
}

// CountUnusedRecoveryCodes implements store.RecoveryStore.
//
// The count drives the warning that tells a user to print a fresh sheet. A
// subject who reaches zero unused codes and holds no second factor has no route
// back into the account.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, tenantID, subjectID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM recovery_codes
		WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL`,
		tenantID, subjectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count unused recovery codes: %w", err)
	}
	return n, nil
}

func scanRecoveryCode(sc rowScanner) (*store.RecoveryCode, error) {
	var (
		c          store.RecoveryCode
		createdAt  time.Time
		consumedAt *time.Time
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &c.SubjectID, &c.BatchID, &c.Selector, &c.VerifierHash,
		&createdAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	c.CreatedAt = utc(createdAt)
	c.ConsumedAt = utcPtr(consumedAt)
	return &c, nil
}
