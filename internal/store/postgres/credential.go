package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Socold/n0passtemps/internal/store"
)

const credentialColumns = `id, tenant_id, subject_id, credential_id, public_key, aaguid,
	attestation_type, transports, sign_count, clone_warning, backup_eligible,
	backup_state, user_verified, binding_hash, label, rp_id, created_at,
	last_used_at, revoked_at, revoked_reason`

// maxCredentialsListed caps ListCredentials. The interface offers no page size
// because a subject holds a handful of authenticators, not a feed, but the cap
// is applied anyway so that a corrupted or hostile subject_id cannot turn one
// listing into a full table scan.
const maxCredentialsListed = 500

// CreateCredential implements store.CredentialStore.
//
// A second registration of the same credential ID under the same relying party
// violates wc_credential_uq and surfaces as store.ErrConflict. That uniqueness
// is per relying party rather than per subject on purpose: the same
// authenticator must not be registerable twice under two different subjects,
// because an assertion carries the credential ID and nothing else that would
// say which of the two it meant.
func (s *Store) CreateCredential(ctx context.Context, c *store.Credential) error {
	if c.ID == "" || c.TenantID == "" || c.SubjectID == "" {
		return errors.New("postgres: credential requires id, tenant and subject")
	}
	if len(c.CredentialID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("postgres: credential requires a credential id and a public key")
	}
	if c.RPID == "" {
		return errors.New("postgres: credential requires a relying party id")
	}
	if c.AttestationType == "" {
		c.AttestationType = store.AttestationNone
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	transports, err := jsonArray(c.Transports)
	if err != nil {
		return err
	}

	// The four flag columns are BOOLEAN, so the Go bool goes straight in. The
	// SQLite implementation converts them to 0 and 1 because its columns are
	// INTEGER with a CHECK constraining them to that pair.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO webauthn_credentials (`+credentialColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		c.ID, c.TenantID, c.SubjectID, c.CredentialID, c.PublicKey, c.AAGUID,
		string(c.AttestationType), transports, int64(c.SignCount),
		c.CloneWarning, c.BackupEligible, c.BackupState,
		c.UserVerified, c.BindingHash, nullString(c.Label), c.RPID,
		c.CreatedAt, c.LastUsedAt, c.RevokedAt, nullString(c.RevokedReason))
	if err != nil {
		return fmt.Errorf("postgres: create credential: %w", mapError(err))
	}
	return nil
}

// GetCredential implements store.CredentialStore.
//
// A revoked credential is still returned. The caller needs to be able to tell a
// revoked credential from an unknown one in order to record the right audit
// outcome, and the revocation state travels on the row.
func (s *Store) GetCredential(ctx context.Context, tenantID, id string) (*store.Credential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return scanCredential(row)
}

// GetCredentialByID implements store.CredentialStore.
//
// This is the assertion path lookup: the authenticator reports a credential ID
// and the relying party it was created for, and the pair addresses the unique
// index directly.
func (s *Store) GetCredentialByID(ctx context.Context, tenantID, rpID string, credentialID []byte) (*store.Credential,
	error) {
	if len(credentialID) == 0 {
		return nil, errors.New("postgres: credential lookup requires a credential id")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE tenant_id = $1 AND rp_id = $2 AND credential_id = $3`,
		tenantID, rpID, credentialID)
	return scanCredential(row)
}

// ListCredentials implements store.CredentialStore.
//
// Revoked credentials are excluded unless asked for, so the common case reads
// through the partial index the schema declares for it.
func (s *Store) ListCredentials(ctx context.Context, tenantID, subjectID string,
	includeRevoked bool) ([]*store.Credential, error) {
	query := `SELECT ` + credentialColumns + ` FROM webauthn_credentials
		WHERE tenant_id = $1 AND subject_id = $2`
	if !includeRevoked {
		query += ` AND revoked_at IS NULL`
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT $3`

	rows, err := s.pool.Query(ctx, query, tenantID, subjectID,
		clampLimit(0, maxCredentialsListed, maxCredentialsListed))
	if err != nil {
		return nil, fmt.Errorf("postgres: list credentials: %w", err)
	}
	defer rows.Close()

	var out []*store.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate credentials: %w", err)
	}
	return out, nil
}

// AdvanceSignCount implements store.CredentialStore.
//
// The update is a compare-and-swap expressed as one conditional statement, the
// same shape as ConsumeTOTPStep and for the same reason: the condition has to be
// evaluated by the database while it holds the row. Two conditions are checked
// at once, that the stored counter is still the value the caller read, and that
// the counter being written is strictly greater than it.
//
// The race is concrete. A WebAuthn assertion carries a signature counter, and
// two requests replaying one captured assertion can both read the stored
// counter, both find it acceptable and both succeed, which turns a single-use
// assertion into a reusable one. Expressing the check as read-then-write in Go
// does not close it.
//
// No transaction is opened and no isolation level is raised. The UPDATE takes a
// row lock for the duration of the statement, and a concurrent UPDATE of the
// same row waits for the first to commit and then re-evaluates its own WHERE
// clause against the committed row, so it finds sign_count no longer equal to
// expectedPrev and matches nothing. That is already exactly-once under READ
// COMMITTED, which is why the BEGIN IMMEDIATE the SQLite implementation needs
// has no counterpart here.
//
// store.ErrStaleWrite, not store.ErrNotFound, is returned when the row exists
// and the condition failed. That is how the losing side of two concurrent
// assertions is told to reject, and how a replay presenting a counter equal to
// the stored one is refused. A revoked credential reaches the same outcome: the
// caller's response is the same rejection either way, and distinguishing it here
// would only invite a caller to treat one of the two as recoverable.
func (s *Store) AdvanceSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32,
	usedAt time.Time) error {
	if next <= expectedPrev {
		// Refused before touching the database. A counter that does not move
		// forward has either been seen before or comes from a cloned
		// authenticator, and either way this call must not write it.
		return store.ErrStaleWrite
	}

	var written int64
	err := s.pool.QueryRow(ctx, `
		UPDATE webauthn_credentials
		SET sign_count = $1, last_used_at = $2
		WHERE tenant_id = $3 AND id = $4
		  AND sign_count = $5
		  AND $1 > sign_count
		  AND revoked_at IS NULL
		RETURNING sign_count`,
		int64(next), usedAt, tenantID, id, int64(expectedPrev)).Scan(&written)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: advance sign count: %w", mapError(err))
	}

	// Nothing matched. Read the row back to separate a credential that does not
	// exist from one whose counter moved under us, because the two call for
	// different audit entries. The probe only chooses between two error values,
	// so it does not need to share a snapshot with the update above.
	var exists int
	err = s.pool.QueryRow(ctx,
		`SELECT 1 FROM webauthn_credentials WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: advance sign count: read credential: %w", err)
	}
	return store.ErrStaleWrite
}

// TouchCredential implements store.CredentialStore.
func (s *Store) TouchCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webauthn_credentials SET last_used_at = $1
		WHERE tenant_id = $2 AND id = $3 AND revoked_at IS NULL`,
		usedAt, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: touch credential: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// MarkCloneWarning implements store.CredentialStore.
//
// The flag is recorded without refusing the assertion. A counter that fails to
// advance is the documented signal for a cloned authenticator, but a great many
// authenticators legitimately report a constant zero, so refusing on that
// signal alone would lock out users who have done nothing wrong. The condition
// is made visible to an operator instead.
func (s *Store) MarkCloneWarning(ctx context.Context, tenantID, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webauthn_credentials SET clone_warning = TRUE
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: mark clone warning: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// RevokeCredential implements store.CredentialStore.
//
// Revocation is final and the update is conditional on the credential not being
// revoked already, so a second revocation reports store.ErrNotFound rather than
// overwriting the reason and the timestamp of the first. The original reason is
// the one worth keeping: it records why the credential was first believed
// compromised.
func (s *Store) RevokeCredential(ctx context.Context, tenantID, id, reason string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webauthn_credentials SET revoked_at = $1, revoked_reason = $2
		WHERE tenant_id = $3 AND id = $4 AND revoked_at IS NULL`,
		at, nullString(reason), tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: revoke credential: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// RevokeAllCredentials implements store.CredentialStore.
//
// Both updates run in one transaction so that a failure between them cannot
// leave the subject with one factor revoked and the other live; see the
// interface for why that matters during an incident. Each update is conditional
// on revoked_at IS NULL, so a credential revoked earlier keeps its original
// reason and timestamp, which record why it was first believed compromised.
//
// The tenant predicate is on both statements. A subject identifier from another
// tenant matches nothing and yields two zero counts.
func (s *Store) RevokeAllCredentials(
	ctx context.Context, tenantID, subjectID, reason string, at time.Time,
) (credentials, totp int64, err error) {
	if tenantID == "" || subjectID == "" {
		return 0, 0, errors.New("postgres: revoking all credentials requires a tenant and a subject")
	}

	err = s.inTx(ctx, func(tx pgx.Tx) error {
		tag, txErr := tx.Exec(ctx, `
			UPDATE webauthn_credentials SET revoked_at = $1, revoked_reason = $2
			WHERE tenant_id = $3 AND subject_id = $4 AND revoked_at IS NULL`,
			at, nullString(reason), tenantID, subjectID)
		if txErr != nil {
			return mapError(txErr)
		}
		credentials = tag.RowsAffected()

		tag, txErr = tx.Exec(ctx, `
			UPDATE totp_secrets SET revoked_at = $1
			WHERE tenant_id = $2 AND subject_id = $3 AND revoked_at IS NULL`,
			at, tenantID, subjectID)
		if txErr != nil {
			return mapError(txErr)
		}
		totp = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: revoke all credentials: %w", err)
	}
	return credentials, totp, nil
}

// CountActiveCredentials implements store.CredentialStore.
//
// The count is what lets the service refuse to revoke a subject's last
// authenticator without an explicit override, since doing so locks the user out
// permanently and is an easy mistake for an operator working through a list.
func (s *Store) CountActiveCredentials(ctx context.Context, tenantID, subjectID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM webauthn_credentials
		WHERE tenant_id = $1 AND subject_id = $2 AND revoked_at IS NULL`,
		tenantID, subjectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count active credentials: %w", err)
	}
	return n, nil
}

func scanCredential(sc rowScanner) (*store.Credential, error) {
	var (
		c               store.Credential
		attestationType string
		transports      []byte
		signCount       int64
		label           *string
		createdAt       time.Time
		lastUsedAt      *time.Time
		revokedAt       *time.Time
		revokedReason   *string
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &c.SubjectID, &c.CredentialID, &c.PublicKey, &c.AAGUID,
		&attestationType, &transports, &signCount, &c.CloneWarning, &c.BackupEligible,
		&c.BackupState, &c.UserVerified, &c.BindingHash, &label, &c.RPID, &createdAt,
		&lastUsedAt, &revokedAt, &revokedReason,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if c.Transports, err = decodeJSONArray(transports); err != nil {
		return nil, err
	}

	c.CreatedAt = utc(createdAt)
	c.LastUsedAt = utcPtr(lastUsedAt)
	c.RevokedAt = utcPtr(revokedAt)
	// sign_count is a BIGINT column, so the database can hand back a value the
	// WebAuthn signature counter cannot hold. See store.ErrCorruptRow.
	if signCount < 0 || signCount > math.MaxUint32 {
		return nil, fmt.Errorf("%w: credential %s has sign_count %d", store.ErrCorruptRow, c.ID, signCount)
	}

	c.AttestationType = store.AttestationType(attestationType)
	c.SignCount = uint32(signCount)
	c.Label = text(label)
	c.RevokedReason = text(revokedReason)
	return &c, nil
}
