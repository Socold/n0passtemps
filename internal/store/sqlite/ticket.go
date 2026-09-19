package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
		return errors.New("sqlite: enrolment ticket requires a tenant and a subject")
	}
	if t == nil {
		return errors.New("sqlite: enrolment ticket is nil")
	}
	if t.ID == "" || t.Selector == "" || t.VerifierHash == "" {
		return errors.New("sqlite: enrolment ticket requires an id, a selector and a verifier hash")
	}
	if t.IssuedBy == "" {
		return errors.New("sqlite: enrolment ticket requires the identifier of the credential that issued it")
	}
	if t.ExpiresAt.IsZero() {
		return errors.New("sqlite: enrolment ticket requires an expiry")
	}

	// The tenant and the subject come from the arguments rather than from the
	// ticket, so a mismatched field cannot file a ticket against a subject the
	// caller did not name.
	t.TenantID = tenantID
	t.SubjectID = subjectID
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE enrolment_tickets SET revoked_at = ?
			WHERE tenant_id = ? AND subject_id = ?
			  AND consumed_at IS NULL AND revoked_at IS NULL`,
			formatTime(t.CreatedAt), tenantID, subjectID); err != nil {
			return mapError(err)
		}

		_, err := tx.ExecContext(ctx, `
			INSERT INTO enrolment_tickets (`+ticketColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.TenantID, t.SubjectID, t.Selector, t.VerifierHash, t.IssuedBy,
			nullString(t.Reason), formatTime(t.CreatedAt), formatTime(t.ExpiresAt),
			formatTimePtr(t.ConsumedAt), nullString(t.ConsumedCredentialID),
			formatTimePtr(t.RevokedAt))
		return mapError(err)
	})
	if err != nil {
		return fmt.Errorf("sqlite: replace enrolment ticket: %w", err)
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
		return nil, errors.New("sqlite: enrolment ticket lookup requires a selector")
	}
	row := s.read.QueryRowContext(ctx, `
		SELECT `+ticketColumns+` FROM enrolment_tickets
		WHERE tenant_id = ? AND selector = ?`,
		tenantID, selector)
	return scanEnrolmentTicket(row)
}

// ConsumeEnrolmentTicket implements store.TicketStore.
//
// The update is a compare-and-swap in one statement, for the same reason as
// ConsumeRecoveryCode: a single-use secret that two concurrent requests both
// read as unspent and both spend is not single use at all. The database
// evaluates the condition while it holds the write lock, so exactly one of them
// can win.
//
// The expiry is part of the condition rather than a separate check, so a ticket
// that lapses between the caller's read and this write cannot still be redeemed.
//
// store.ErrStaleWrite covers every way the condition can fail on an existing
// row: already consumed, revoked, or expired. The caller answers all three with
// the same coarse refusal, so there is nothing for the store to distinguish.
func (s *Store) ConsumeEnrolmentTicket(ctx context.Context, tenantID, id, credentialID string, at time.Time) error {
	if credentialID == "" {
		return errors.New("sqlite: consuming an enrolment ticket requires the credential it produced")
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE enrolment_tickets SET consumed_at = ?, consumed_credential_id = ?
			WHERE tenant_id = ? AND id = ?
			  AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
			formatTime(at), credentialID, tenantID, id, formatTime(at))
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count enrolment ticket update: %w", err)
		}
		if n == 1 {
			return nil
		}

		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM enrolment_tickets WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read enrolment ticket: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: consume enrolment ticket: %w", err)
	}
	return nil
}

// RevokeEnrolmentTicket implements store.TicketStore.
//
// The update is conditional on the ticket being neither consumed nor revoked, so
// a ticket that was already redeemed keeps its consumption record and the
// revocation does not overwrite the evidence of what it produced.
func (s *Store) RevokeEnrolmentTicket(ctx context.Context, tenantID, id string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE enrolment_tickets SET revoked_at = ?
			WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND revoked_at IS NULL`,
			formatTime(at), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count enrolment ticket revocation: %w", err)
		}
		if n == 1 {
			return nil
		}

		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM enrolment_tickets WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read enrolment ticket: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: revoke enrolment ticket: %w", err)
	}
	return nil
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
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM enrolment_tickets WHERE expires_at < ?`, formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired enrolment tickets: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count deleted enrolment tickets: %w", err)
	}
	return n, nil
}

func scanEnrolmentTicket(sc rowScanner) (*store.EnrolmentTicket, error) {
	var (
		t            store.EnrolmentTicket
		reason       sql.NullString
		createdAt    string
		expiresAt    string
		consumedAt   sql.NullString
		consumedCred sql.NullString
		revokedAt    sql.NullString
	)
	if err := sc.Scan(
		&t.ID, &t.TenantID, &t.SubjectID, &t.Selector, &t.VerifierHash, &t.IssuedBy,
		&reason, &createdAt, &expiresAt, &consumedAt, &consumedCred, &revokedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if t.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if t.ConsumedAt, err = parseTimePtr(consumedAt); err != nil {
		return nil, err
	}
	if t.RevokedAt, err = parseTimePtr(revokedAt); err != nil {
		return nil, err
	}
	t.Reason = stringOrEmpty(reason)
	t.ConsumedCredentialID = stringOrEmpty(consumedCred)
	return &t, nil
}
