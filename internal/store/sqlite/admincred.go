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

const adminCredentialColumns = `id, tenant_id, admin_token_id, credential_id, public_key, aaguid,
	attestation_type, transports, sign_count, clone_warning, backup_eligible,
	backup_state, user_verified, binding_hash, label, rp_id, created_at,
	last_used_at, revoked_at, revoked_reason`

const adminChallengeColumns = `id, tenant_id, admin_token_id, ceremony, challenge, rp_id,
	session_data, created_at, expires_at, consumed_at`

// maxAdminCredentialsListed caps ListAdminCredentials, for the reason
// maxCredentialsListed caps the subject listing: an administrator holds a
// handful of authenticators, and the cap is applied anyway so that a corrupted
// identifier cannot turn one listing into a full table scan.
const maxAdminCredentialsListed = 100

// CreateAdminCredential implements store.AdminCredentialStore.
//
// A second enrolment of the same credential identifier under the same relying
// party violates adc_credential_uq and surfaces as store.ErrConflict. The
// uniqueness is per relying party rather than per administrative token for the
// reason it is on the subject side: an assertion carries the credential
// identifier and nothing else that would say which enrolment it meant.
func (s *Store) CreateAdminCredential(ctx context.Context, c *store.AdminCredential) error {
	if c.ID == "" || c.TenantID == "" || c.AdminTokenID == "" {
		return errors.New("sqlite: administrative credential requires id, tenant and token")
	}
	if len(c.CredentialID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("sqlite: administrative credential requires a credential id and a public key")
	}
	if c.RPID == "" {
		return errors.New("sqlite: administrative credential requires a relying party id")
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
		INSERT INTO admin_credentials (`+adminCredentialColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, c.AdminTokenID, c.CredentialID, c.PublicKey, c.AAGUID,
		string(c.AttestationType), transports, int64(c.SignCount),
		boolToInt(c.CloneWarning), boolToInt(c.BackupEligible), boolToInt(c.BackupState),
		boolToInt(c.UserVerified), c.BindingHash, nullString(c.Label), c.RPID,
		formatTime(c.CreatedAt), formatTimePtr(c.LastUsedAt), formatTimePtr(c.RevokedAt),
		nullString(c.RevokedReason))
	if err != nil {
		return fmt.Errorf("sqlite: create administrative credential: %w", mapError(err))
	}
	return nil
}

// GetAdminCredentialByID implements store.AdminCredentialStore.
func (s *Store) GetAdminCredentialByID(ctx context.Context, tenantID, rpID string,
	credentialID []byte) (*store.AdminCredential, error) {
	if len(credentialID) == 0 {
		return nil, errors.New("sqlite: administrative credential lookup requires a credential id")
	}
	row := s.read.QueryRowContext(ctx, `
		SELECT `+adminCredentialColumns+` FROM admin_credentials
		WHERE tenant_id = ? AND rp_id = ? AND credential_id = ?`,
		tenantID, rpID, credentialID)
	return scanAdminCredential(row)
}

// GetAdminCredential implements store.AdminCredentialStore.
//
// A withdrawn credential is still returned, so the withdrawal form can tell a
// credential that is already gone from one that never existed and answer each
// differently.
func (s *Store) GetAdminCredential(ctx context.Context, tenantID, id string) (*store.AdminCredential, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT `+adminCredentialColumns+` FROM admin_credentials
		WHERE tenant_id = ? AND id = ?`,
		tenantID, id)
	return scanAdminCredential(row)
}

// ListAdminCredentials implements store.AdminCredentialStore.
func (s *Store) ListAdminCredentials(ctx context.Context, tenantID, adminTokenID string,
	includeRevoked bool) ([]*store.AdminCredential, error) {
	query := `SELECT ` + adminCredentialColumns + ` FROM admin_credentials
		WHERE tenant_id = ? AND admin_token_id = ?`
	if !includeRevoked {
		query += ` AND revoked_at IS NULL`
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`

	rows, err := s.read.QueryContext(ctx, query, tenantID, adminTokenID,
		clampLimit(0, maxAdminCredentialsListed, maxAdminCredentialsListed))
	if err != nil {
		return nil, fmt.Errorf("sqlite: list administrative credentials: %w", err)
	}
	defer rows.Close()

	var out []*store.AdminCredential
	for rows.Next() {
		c, err := scanAdminCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate administrative credentials: %w", err)
	}
	return out, nil
}

// CountActiveAdminCredentials implements store.AdminCredentialStore.
func (s *Store) CountActiveAdminCredentials(ctx context.Context, tenantID, adminTokenID string) (int, error) {
	var n int
	err := s.read.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM admin_credentials
		WHERE tenant_id = ? AND admin_token_id = ? AND revoked_at IS NULL`,
		tenantID, adminTokenID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("sqlite: count active administrative credentials: %w", err)
	}
	return n, nil
}

// RevokeAdminCredential implements store.AdminCredentialStore.
//
// The update is conditional on the credential not being withdrawn already, so a
// second withdrawal reports store.ErrNotFound rather than overwriting the reason
// and the timestamp of the first. The original reason is the one worth keeping.
func (s *Store) RevokeAdminCredential(ctx context.Context, tenantID, id, reason string, at time.Time) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE admin_credentials SET revoked_at = ?, revoked_reason = ?
			WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
			formatTime(at), nullString(reason), tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count administrative credential withdrawal: %w", err)
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
		return fmt.Errorf("sqlite: withdraw administrative credential: %w", err)
	}
	return nil
}

// TouchAdminCredential implements store.AdminCredentialStore.
func (s *Store) TouchAdminCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error {
	res, err := s.write.ExecContext(ctx, `
		UPDATE admin_credentials SET last_used_at = ?
		WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
		formatTime(usedAt), tenantID, id)
	if err != nil {
		return fmt.Errorf("sqlite: touch administrative credential: %w", mapError(err))
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// MarkAdminCredentialCloneWarning implements store.AdminCredentialStore.
func (s *Store) MarkAdminCredentialCloneWarning(ctx context.Context, tenantID, id string) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE admin_credentials SET clone_warning = 1
			WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count administrative clone warning update: %w", err)
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
		return fmt.Errorf("sqlite: mark administrative clone warning: %w", err)
	}
	return nil
}

// AdvanceAdminCredentialSignCount implements store.AdminCredentialStore.
//
// It is AdvanceSignCount over the console's credential table, and the shape is
// the same one for the same reason: the condition has to be evaluated by the
// database while it holds the write lock, because two requests replaying one
// captured assertion would otherwise both read the stored counter, both find it
// acceptable and both succeed.
func (s *Store) AdvanceAdminCredentialSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32,
	usedAt time.Time) error {
	if next <= expectedPrev {
		// Refused before touching the database. A counter that does not move
		// forward has either been seen before or comes from a cloned
		// authenticator, and either way this call must not write it.
		return store.ErrStaleWrite
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE admin_credentials
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
			return fmt.Errorf("sqlite: count administrative credential update: %w", err)
		}
		if n == 1 {
			return nil
		}

		// Nothing matched. Read the row back to separate a credential that does
		// not exist from one whose counter moved under us, because the two call
		// for different audit entries.
		var exists int
		err = tx.QueryRowContext(ctx,
			`SELECT 1 FROM admin_credentials WHERE tenant_id = ? AND id = ?`,
			tenantID, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sqlite: read administrative credential: %w", err)
		}
		return store.ErrStaleWrite
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStaleWrite) {
			return err
		}
		return fmt.Errorf("sqlite: advance administrative sign count: %w", err)
	}
	return nil
}

// CreateAdminChallenge implements store.AdminCredentialStore.
func (s *Store) CreateAdminChallenge(ctx context.Context, c *store.AdminChallenge) error {
	if c.ID == "" || c.TenantID == "" || len(c.Challenge) == 0 {
		return errors.New("sqlite: administrative challenge requires id, tenant and challenge bytes")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("sqlite: administrative challenge requires an expiry")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	_, err := s.write.ExecContext(ctx, `
		INSERT INTO admin_webauthn_challenges (`+adminChallengeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, nullString(c.AdminTokenID), string(c.Ceremony), c.Challenge,
		c.RPID, c.SessionData, formatTime(c.CreatedAt), formatTime(c.ExpiresAt),
		formatTimePtr(c.ConsumedAt))
	if err != nil {
		return fmt.Errorf("sqlite: create administrative challenge: %w", mapError(err))
	}
	return nil
}

// ConsumeAdminChallenge implements store.AdminCredentialStore.
//
// It is ConsumeChallenge over the console's own table, with the same conditional
// update and the same refusal to distinguish an unknown challenge from an
// expired or already spent one.
func (s *Store) ConsumeAdminChallenge(ctx context.Context, tenantID, id string, now time.Time) (*store.AdminChallenge,
	error) {
	var out *store.AdminChallenge

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE admin_webauthn_challenges SET consumed_at = ?
			WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND expires_at > ?`,
			formatTime(now), tenantID, id, formatTime(now))
		if err != nil {
			return mapError(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite: count administrative challenge update: %w", err)
		}
		if n != 1 {
			return store.ErrNotFound
		}

		row := tx.QueryRowContext(ctx,
			`SELECT `+adminChallengeColumns+` FROM admin_webauthn_challenges
			WHERE tenant_id = ? AND id = ?`,
			tenantID, id)
		out, err = scanAdminChallenge(row)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("sqlite: consume administrative challenge: %w", err)
	}
	return out, nil
}

func scanAdminCredential(sc rowScanner) (*store.AdminCredential, error) {
	var (
		c               store.AdminCredential
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
		&c.ID, &c.TenantID, &c.AdminTokenID, &c.CredentialID, &c.PublicKey, &c.AAGUID,
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

	// sign_count is an INTEGER column, so the database can hand back a value
	// the WebAuthn signature counter cannot hold. See store.ErrCorruptRow.
	if signCount < 0 || signCount > math.MaxUint32 {
		return nil, fmt.Errorf("%w: administrative credential %s has sign_count %d",
			store.ErrCorruptRow, c.ID, signCount)
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

func scanAdminChallenge(sc rowScanner) (*store.AdminChallenge, error) {
	var (
		c            store.AdminChallenge
		adminTokenID sql.NullString
		ceremony     string
		createdAt    string
		expiresAt    string
		consumedAt   sql.NullString
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &adminTokenID, &ceremony, &c.Challenge, &c.RPID,
		&c.SessionData, &createdAt, &expiresAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if c.ConsumedAt, err = parseTimePtr(consumedAt); err != nil {
		return nil, err
	}
	c.AdminTokenID = stringOrEmpty(adminTokenID)
	c.Ceremony = store.Ceremony(ceremony)
	return &c, nil
}
