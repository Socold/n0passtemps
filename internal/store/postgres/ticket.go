package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const ticketColumns = `id, tenant_id, subject_id, selector, verifier_hash, issued_by,
	reason, created_at, expires_at, consumed_at, consumed_credential_id, revoked_at`

// ReplaceEnrolmentTicket implements store.TicketStore.
//
// Revoking whatever was live and inserting the replacement happen in one
// transaction. Issuing a second ticket without retiring the first doubles the
// window in which a stolen one can be redeemed, and the common reason to reissue
// is a delivery that failed, which is precisely when the first ticket is most
// likely to be in someone else's hands.
//
// The live ticket is revoked rather than deleted. A revoked row is the evidence
// that a ticket was issued and superseded, and a redemption attempt against it
// is then refused by the state of the row rather than by a missing one, which
// keeps the two cases indistinguishable to whoever presents it.
func (s *Store) ReplaceEnrolmentTicket(ctx context.Context, tenantID, subjectID string, t *store.EnrolmentTicket) error {
	if tenantID == "" || subjectID == "" {
		return errors.New("postgres: enrolment ticket requires a tenant and a subject")
	}
	if t == nil {
		return errors.New("postgres: enrolment ticket is nil")
	}
	if t.ID == "" || t.Selector == "" || t.VerifierHash == "" {
		return errors.New("postgres: enrolment ticket requires an id, a selector and a verifier hash")
	}
	if t.IssuedBy == "" {
		return errors.New("postgres: enrolment ticket requires the identifier of the credential that issued it")
	}
	if t.ExpiresAt.IsZero() {
		return errors.New("postgres: enrolment ticket requires an expiry")
	}

	// The tenant and the subject come from the arguments rather than from the
	// ticket, so a mismatched field cannot file a ticket against a subject the
	// caller did not name.
	t.TenantID = tenantID
	t.SubjectID = subjectID
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE enrolment_tickets SET revoked_at = $1
			WHERE tenant_id = $2 AND subject_id = $3
			  AND consumed_at IS NULL AND revoked_at IS NULL`,
			t.CreatedAt, tenantID, subjectID); err != nil {
			return mapError(err)
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO enrolment_tickets (`+ticketColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			t.ID, t.TenantID, t.SubjectID, t.Selector, t.VerifierHash, t.IssuedBy,
			nullString(t.Reason), t.CreatedAt, t.ExpiresAt,
			t.ConsumedAt, nullString(t.ConsumedCredentialID), t.RevokedAt)
		return mapError(err)
	})
	if err != nil {
		return fmt.Errorf("postgres: replace enrolment ticket: %w", err)
	}
	return nil
}

// GetEnrolmentTicketBySelector implements store.TicketStore.
//
// The lookup is by selector so that verifying a presented ticket is one indexed
// probe plus one Argon2id evaluation, exactly as for a recovery code. Matching
// on the verifier hash instead would mean one evaluation per stored ticket,
// which is a denial-of-service vector aimed at the server's own CPU.
//
// A consumed, revoked or expired ticket is still returned, so that the caller
// can verify the hashed half before deciding and a spent ticket costs the same
// to reject as one that never existed.
func (s *Store) GetEnrolmentTicketBySelector(ctx context.Context, tenantID, selector string) (*store.EnrolmentTicket, error) {
	if selector == "" {
		return nil, errors.New("postgres: enrolment ticket lookup requires a selector")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+ticketColumns+` FROM enrolment_tickets
		WHERE tenant_id = $1 AND selector = $2`,
		tenantID, selector)
	return scanEnrolmentTicket(row)
}

// ConsumeEnrolmentTicket implements store.TicketStore.
//
// The update is a compare-and-swap in one statement, for the same reason as
// ConsumeRecoveryCode: a single-use secret that two concurrent requests both
// read as unspent and both spend is not single use at all. The database
// evaluates the condition while it holds the row, so exactly one of them can
// win. The second blocks on the row lock, then re-tests the condition against
// the committed value and matches nothing, which is why no transaction and no
// raised isolation level are needed around it.
//
// The expiry is part of the condition rather than a separate check, so a ticket
// that lapses between the caller's read and this write cannot still be redeemed.
//
// store.ErrStaleWrite covers every way the condition can fail on an existing
// row: already consumed, revoked, or expired. The caller answers all three with
// the same coarse refusal, so there is nothing for the store to distinguish.
func (s *Store) ConsumeEnrolmentTicket(ctx context.Context, tenantID, id, credentialID string, at time.Time) error {
	if credentialID == "" {
		return errors.New("postgres: consuming an enrolment ticket requires the credential it produced")
	}

	var consumed time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE enrolment_tickets SET consumed_at = $1, consumed_credential_id = $2
		WHERE tenant_id = $3 AND id = $4
		  AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $1
		RETURNING consumed_at`,
		at, credentialID, tenantID, id).Scan(&consumed)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: consume enrolment ticket: %w", mapError(err))
	}
	return s.ticketMissOrStale(ctx, tenantID, id, "consume enrolment ticket")
}

// RevokeEnrolmentTicket implements store.TicketStore.
//
// The update is conditional on the ticket being neither consumed nor revoked, so
// a ticket that was already redeemed keeps its consumption record and the
// revocation does not overwrite the evidence of what it produced.
func (s *Store) RevokeEnrolmentTicket(ctx context.Context, tenantID, id string, at time.Time) error {
	var revoked time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE enrolment_tickets SET revoked_at = $1
		WHERE tenant_id = $2 AND id = $3 AND consumed_at IS NULL AND revoked_at IS NULL
		RETURNING revoked_at`,
		at, tenantID, id).Scan(&revoked)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: revoke enrolment ticket: %w", mapError(err))
	}
	return s.ticketMissOrStale(ctx, tenantID, id, "revoke enrolment ticket")
}

// ticketMissOrStale distinguishes a ticket that is not there from one whose
// state no longer satisfies a conditional update.
//
// Both conditional statements above match nothing in either case, and the two
// mean different things to a caller: nothing to act on, against an action that
// has already happened.
func (s *Store) ticketMissOrStale(ctx context.Context, tenantID, id, op string) error {
	var exists int
	err := s.pool.QueryRow(ctx,
		`SELECT 1 FROM enrolment_tickets WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: %s: read ticket: %w", op, err)
	}
	return store.ErrStaleWrite
}

// DeleteExpiredEnrolmentTickets implements store.TicketStore.
//
// The sweep spans every tenant, because the janitor acts on behalf of none of
// them and an expired ticket belongs to nobody.
//
// Consumed and revoked tickets are removed too, once they are past their expiry.
// They are kept until then so that a redemption arriving inside the original
// window is refused by ConsumeEnrolmentTicket rather than by a missing row,
// which keeps the two cases indistinguishable to the caller. The durable record
// of a redemption is the audit log.
func (s *Store) DeleteExpiredEnrolmentTickets(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM enrolment_tickets WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired enrolment tickets: %w", mapError(err))
	}
	return tag.RowsAffected(), nil
}

func scanEnrolmentTicket(sc rowScanner) (*store.EnrolmentTicket, error) {
	var (
		t            store.EnrolmentTicket
		reason       *string
		createdAt    time.Time
		expiresAt    time.Time
		consumedAt   *time.Time
		consumedCred *string
		revokedAt    *time.Time
	)
	if err := sc.Scan(
		&t.ID, &t.TenantID, &t.SubjectID, &t.Selector, &t.VerifierHash, &t.IssuedBy,
		&reason, &createdAt, &expiresAt, &consumedAt, &consumedCred, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	t.CreatedAt = utc(createdAt)
	t.ExpiresAt = utc(expiresAt)
	t.ConsumedAt = utcPtr(consumedAt)
	t.RevokedAt = utcPtr(revokedAt)
	t.Reason = text(reason)
	t.ConsumedCredentialID = text(consumedCred)
	return &t, nil
}
