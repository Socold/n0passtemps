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
		return errors.New("postgres: administrative credential requires id, tenant and token")
	}
	if len(c.CredentialID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("postgres: administrative credential requires a credential id and a public key")
	}
	if c.RPID == "" {
		return errors.New("postgres: administrative credential requires a relying party id")
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
		INSERT INTO admin_credentials (`+adminCredentialColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		c.ID, c.TenantID, c.AdminTokenID, c.CredentialID, c.PublicKey, c.AAGUID,
		string(c.AttestationType), transports, int64(c.SignCount),
		c.CloneWarning, c.BackupEligible, c.BackupState,
		c.UserVerified, c.BindingHash, nullString(c.Label), c.RPID,
		c.CreatedAt, c.LastUsedAt, c.RevokedAt, nullString(c.RevokedReason))
	if err != nil {
		return fmt.Errorf("postgres: create administrative credential: %w", mapError(err))
	}
	return nil
}

// GetAdminCredentialByID implements store.AdminCredentialStore.
func (s *Store) GetAdminCredentialByID(ctx context.Context, tenantID, rpID string, credentialID []byte) (*store.AdminCredential, error) {
	if len(credentialID) == 0 {
		return nil, errors.New("postgres: administrative credential lookup requires a credential id")
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+adminCredentialColumns+` FROM admin_credentials
		WHERE tenant_id = $1 AND rp_id = $2 AND credential_id = $3`,
		tenantID, rpID, credentialID)
	return scanAdminCredential(row)
}

// GetAdminCredential implements store.AdminCredentialStore.
//
// A withdrawn credential is still returned, so the withdrawal form can tell a
// credential that is already gone from one that never existed and answer each
// differently.
func (s *Store) GetAdminCredential(ctx context.Context, tenantID, id string) (*store.AdminCredential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+adminCredentialColumns+` FROM admin_credentials
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return scanAdminCredential(row)
}

// ListAdminCredentials implements store.AdminCredentialStore.
func (s *Store) ListAdminCredentials(ctx context.Context, tenantID, adminTokenID string, includeRevoked bool) ([]*store.AdminCredential, error) {
	query := `SELECT ` + adminCredentialColumns + ` FROM admin_credentials
		WHERE tenant_id = $1 AND admin_token_id = $2`
	if !includeRevoked {
		query += ` AND revoked_at IS NULL`
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT $3`

	rows, err := s.pool.Query(ctx, query, tenantID, adminTokenID,
		clampLimit(0, maxAdminCredentialsListed, maxAdminCredentialsListed))
	if err != nil {
		return nil, fmt.Errorf("postgres: list administrative credentials: %w", err)
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
		return nil, fmt.Errorf("postgres: iterate administrative credentials: %w", err)
	}
	return out, nil
}

// CountActiveAdminCredentials implements store.AdminCredentialStore.
func (s *Store) CountActiveAdminCredentials(ctx context.Context, tenantID, adminTokenID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM admin_credentials
		WHERE tenant_id = $1 AND admin_token_id = $2 AND revoked_at IS NULL`,
		tenantID, adminTokenID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("postgres: count active administrative credentials: %w", err)
	}
	return n, nil
}

// RevokeAdminCredential implements store.AdminCredentialStore.
//
// The update is conditional on the credential not being withdrawn already, so a
// second withdrawal reports store.ErrNotFound rather than overwriting the reason
// and the timestamp of the first. The original reason is the one worth keeping.
func (s *Store) RevokeAdminCredential(ctx context.Context, tenantID, id, reason string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE admin_credentials SET revoked_at = $1, revoked_reason = $2
		WHERE tenant_id = $3 AND id = $4 AND revoked_at IS NULL`,
		at, nullString(reason), tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: withdraw administrative credential: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// TouchAdminCredential implements store.AdminCredentialStore.
func (s *Store) TouchAdminCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE admin_credentials SET last_used_at = $1
		WHERE tenant_id = $2 AND id = $3 AND revoked_at IS NULL`,
		usedAt, tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: touch administrative credential: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// MarkAdminCredentialCloneWarning implements store.AdminCredentialStore.
func (s *Store) MarkAdminCredentialCloneWarning(ctx context.Context, tenantID, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE admin_credentials SET clone_warning = TRUE
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("postgres: mark administrative clone warning: %w", mapError(err))
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// AdvanceAdminCredentialSignCount implements store.AdminCredentialStore.
//
// It is AdvanceSignCount over the console's credential table, and the reasoning
// there applies unchanged: the UPDATE takes a row lock for the duration of the
// statement, so a concurrent attempt re-evaluates its own WHERE clause against
// the committed row and matches nothing, which is exactly-once under READ
// COMMITTED without a transaction or a raised isolation level.
func (s *Store) AdvanceAdminCredentialSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32, usedAt time.Time) error {
	if next <= expectedPrev {
		// Refused before touching the database. A counter that does not move
		// forward has either been seen before or comes from a cloned
		// authenticator, and either way this call must not write it.
		return store.ErrStaleWrite
	}

	var written int64
	err := s.pool.QueryRow(ctx, `
		UPDATE admin_credentials
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
		return fmt.Errorf("postgres: advance administrative sign count: %w", mapError(err))
	}

	// Nothing matched. Read the row back to separate a credential that does not
	// exist from one whose counter moved under us, because the two call for
	// different audit entries.
	var exists int
	err = s.pool.QueryRow(ctx,
		`SELECT 1 FROM admin_credentials WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: advance administrative sign count: read credential: %w", err)
	}
	return store.ErrStaleWrite
}

// CreateAdminChallenge implements store.AdminCredentialStore.
func (s *Store) CreateAdminChallenge(ctx context.Context, c *store.AdminChallenge) error {
	if c.ID == "" || c.TenantID == "" || len(c.Challenge) == 0 {
		return errors.New("postgres: administrative challenge requires id, tenant and challenge bytes")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("postgres: administrative challenge requires an expiry")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_webauthn_challenges (`+adminChallengeColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, c.TenantID, nullString(c.AdminTokenID), string(c.Ceremony), c.Challenge,
		c.RPID, c.SessionData, c.CreatedAt, c.ExpiresAt, c.ConsumedAt)
	if err != nil {
		return fmt.Errorf("postgres: create administrative challenge: %w", mapError(err))
	}
	return nil
}

// ConsumeAdminChallenge implements store.AdminCredentialStore.
//
// It is ConsumeChallenge over the console's own table, including the RETURNING
// clause that makes the mark and the read one statement with nothing between
// them for a concurrent consumer to slip into.
func (s *Store) ConsumeAdminChallenge(ctx context.Context, tenantID, id string, now time.Time) (*store.AdminChallenge, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE admin_webauthn_challenges SET consumed_at = $1
		WHERE tenant_id = $2 AND id = $3 AND consumed_at IS NULL AND expires_at > $1
		RETURNING `+adminChallengeColumns,
		now, tenantID, id)

	out, err := scanAdminChallenge(row)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("postgres: consume administrative challenge: %w", err)
	}
	return out, nil
}

func scanAdminCredential(sc rowScanner) (*store.AdminCredential, error) {
	var (
		c               store.AdminCredential
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
		&c.ID, &c.TenantID, &c.AdminTokenID, &c.CredentialID, &c.PublicKey, &c.AAGUID,
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
		return nil, fmt.Errorf("%w: administrative credential %s has sign_count %d",
			store.ErrCorruptRow, c.ID, signCount)
	}

	c.AttestationType = store.AttestationType(attestationType)
	c.SignCount = uint32(signCount)
	c.Label = text(label)
	c.RevokedReason = text(revokedReason)
	return &c, nil
}

func scanAdminChallenge(sc rowScanner) (*store.AdminChallenge, error) {
	var (
		c            store.AdminChallenge
		adminTokenID *string
		ceremony     string
		createdAt    time.Time
		expiresAt    time.Time
		consumedAt   *time.Time
	)
	if err := sc.Scan(
		&c.ID, &c.TenantID, &adminTokenID, &ceremony, &c.Challenge, &c.RPID,
		&c.SessionData, &createdAt, &expiresAt, &consumedAt,
	); err != nil {
		return nil, mapError(err)
	}

	c.CreatedAt = utc(createdAt)
	c.ExpiresAt = utc(expiresAt)
	c.ConsumedAt = utcPtr(consumedAt)
	c.AdminTokenID = text(adminTokenID)
	c.Ceremony = store.Ceremony(ceremony)
	return &c, nil
}
