package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

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
		return errors.New("sqlite: credential requires id, tenant and subject")
	}
	if len(c.CredentialID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("sqlite: credential requires a credential id and a public key")
	}
	if c.RPID == "" {
		return errors.New("sqlite: credential requires a relying party id")
	}
	if c.AttestationType == "" {
		c.AttestationType = store.AttestationNone
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	transports, err := encodeJSONArray(c.Transports)
	if err != nil {
		return err
	}

	_, err = s.write.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (`+credentialColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, c.SubjectID, c.CredentialID, c.PublicKey, c.AAGUID,
		string(c.AttestationType), transports, int64(c.SignCount),
		boolToInt(c.CloneWarning), boolToInt(c.BackupEligible), boolToInt(c.BackupState),
		boolToInt(c.UserVerified), c.BindingHash, nullString(c.Label), c.RPID,
		formatTime(c.CreatedAt), formatTimePtr(c.LastUsedAt), formatTimePtr(c.RevokedAt),
		nullString(c.RevokedReason))
	if err != nil {
		return fmt.Errorf("sqlite: create credential: %w", mapError(err))
	}
	return nil
}

// GetCredential implements store.CredentialStore.
//
// A revoked credential is still returned. The caller needs to be able to tell a
// revoked credential from an unknown one in order to record the right audit
// outcome, and the revocation state travels on the row.
func (s *Store) GetCredential(ctx context.Context, tenantID, id string) (*store.Credential, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE tenant_id = ? AND id = ?`,
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
		return nil, errors.New("sqlite: credential lookup requires a credential id")
	}
	row := s.read.QueryRowContext(ctx, `
		SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE tenant_id = ? AND rp_id = ? AND credential_id = ?`,
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
		WHERE tenant_id = ? AND subject_id = ?`
	if !includeRevoked {
		query += ` AND revoked_at IS NULL`
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, tenantID, subjectID,
		clampLimit(0, maxCredentialsListed, maxCredentialsListed))
	if err != nil {
		return nil, fmt.Errorf("sqlite: list credentials: %w", err)
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
		return nil, fmt.Errorf("sqlite: iterate credentials: %w", err)
	}
	return out, nil
}

// AdvanceSignCount implements store.CredentialStore.
//
// The update is a compare-and-swap expressed as one conditional statement, the
// same shape as ConsumeTOTPStep and for the same reason: the condition has to be
// evaluated by the database while it holds the write lock. Two conditions are
// checked at once, that the stored counter is still the value the caller read,
// and that the counter being written is strictly greater than it.
//
// The race is concrete. A WebAuthn assertion carries a signature counter, and
// two requests replaying one captured assertion can both read the stored
// counter, both find it acceptable and both succeed, which turns a single-use
// assertion into a reusable one. Expressing the check as read-then-write in Go
// does not close it.
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

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE webauthn_credentials
			SET sign_count = ?, last_used_at = ?
			WHERE tenant_id = ? AND id = ?
			  AND sign_count = ?
			  AND ? > sign_count
			  AND revoked_at IS NULL`,
			int64(next), formatTime(usedAt), tenantID, id,
			int64(expectedPrev), int64(next))
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count credential update: %w", err)
		}
		if n == 1 {
			return nil
		}

		// Nothing matched. Read the row back to separate a credential that does
		// not exist from one whose counter moved under us, because the two call
		// for different audit entries.
		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM webauthn_credentials WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read credential: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: advance sign count: %w", err)
	}
	return nil
}

// TouchCredential implements store.CredentialStore.
func (s *Store) TouchCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error {
	res, err := s.write.ExecContext(ctx, `
		UPDATE webauthn_credentials SET last_used_at = ?
		WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
		formatTime(usedAt), tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlite: touch credential: %w", mapError(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
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
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE webauthn_credentials SET clone_warning = 1
			WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count clone warning update: %w", err)
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: mark clone warning: %w", err)
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
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE webauthn_credentials SET revoked_at = ?, revoked_reason = ?
			WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
			formatTime(at), nullString(reason), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count credential revocation: %w", err)
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("sqlite: revoke credential: %w", err)
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
		return 0, 0, errors.New("sqlite: revoking all credentials requires a tenant and a subject")
	}

	err = s.inTx(ctx, func(tx *sql.Tx) error {
		res, txErr := tx.ExecContext(ctx, `
			UPDATE webauthn_credentials SET revoked_at = ?, revoked_reason = ?
			WHERE tenant_id = ? AND subject_id = ? AND revoked_at IS NULL`,
			formatTime(at), nullString(reason), tenantID, subjectID)
		if txErr != nil {
			return mapError(txErr)
		}
		if credentials, txErr = res.RowsAffected(); txErr != nil {
			return fmt.Errorf("sqlite: count credential revocations: %w", txErr)
		}

		res, txErr = tx.ExecContext(ctx, `
			UPDATE totp_secrets SET revoked_at = ?
			WHERE tenant_id = ? AND subject_id = ? AND revoked_at IS NULL`,
			formatTime(at), tenantID, subjectID)
		if txErr != nil {
			return mapError(txErr)
		}
		if totp, txErr = res.RowsAffected(); txErr != nil {
			return fmt.Errorf("sqlite: count totp revocations: %w", txErr)
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("sqlite: revoke all credentials: %w", err)
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
	err := s.read.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM webauthn_credentials
		WHERE tenant_id = ? AND subject_id = ? AND revoked_at IS NULL`,
		tenantID, subjectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("sqlite: count active credentials: %w", err)
	}
	return n, nil
}

func scanCredential(sc rowScanner) (*store.Credential, error) {
	var (
		c               store.Credential
		attestationType string
		transports      sql.NullString
		signCount       int64
		cloneWarning    int64
		backupEligible  int64
		backupState     int64
		userVerified    int64
		label           sql.NullString
		createdAt       string
		lastUsedAt      sql.NullString
		revokedAt       sql.NullString
		revokedReason   sql.NullString
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &c.SubjectID, &c.CredentialID, &c.PublicKey, &c.AAGUID,
		&attestationType, &transports, &signCount, &cloneWarning, &backupEligible,
		&backupState, &userVerified, &c.BindingHash, &label, &c.RPID, &createdAt,
		&lastUsedAt, &revokedAt, &revokedReason,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if c.LastUsedAt, err = parseTimePtr(lastUsedAt); err != nil {
		return nil, err
	}
	if c.RevokedAt, err = parseTimePtr(revokedAt); err != nil {
		return nil, err
	}
	if c.Transports, err = decodeJSONArray(transports); err != nil {
		return nil, err
	}

	// sign_count is a BIGINT column, so the database can hand back a value the
	// WebAuthn signature counter cannot hold. See store.ErrCorruptRow.
	if signCount < 0 || signCount > math.MaxUint32 {
		return nil, fmt.Errorf("%w: credential %s has sign_count %d", store.ErrCorruptRow, c.ID, signCount)
	}

	c.AttestationType = store.AttestationType(attestationType)
	c.SignCount = uint32(signCount)
	c.CloneWarning = cloneWarning != 0
	c.BackupEligible = backupEligible != 0
	c.BackupState = backupState != 0
	c.UserVerified = userVerified != 0
	c.Label = stringOrEmpty(label)
	c.RevokedReason = stringOrEmpty(revokedReason)
	return &c, nil
}
