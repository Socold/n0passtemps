package store

import (
	"encoding/json"
	"time"
)

// Role is an administrative role. The three roles are cumulative in practice
// but are kept as distinct values rather than a numeric level, so that adding a
// role later does not renumber the existing ones.
type Role string

const (
	RoleFull     Role = "admin_full"
	RoleOperator Role = "admin_operator"
	RoleAuditor  Role = "admin_auditor"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleFull, RoleOperator, RoleAuditor:
		return true
	}
	return false
}

// SubjectStatus values mirror the subjects.status CHECK constraint.
type SubjectStatus string

const (
	SubjectActive          SubjectStatus = "active"
	SubjectLocked          SubjectStatus = "locked"
	SubjectPendingDeletion SubjectStatus = "pending_deletion"
)

// SystemTenantID labels records that cannot be attributed to a real tenant.
//
// An authentication failure is the case that needs it: the credential which
// would have named the tenant is precisely the one that did not verify, so the
// audit entry has no tenant to carry. A fixed reserved identifier keeps the
// entry insertable, and keeps the hash chain contiguous, without inventing a
// tenant or leaving the column empty.
const SystemTenantID = "system"

// Tenant owns every other record. v1 provisions exactly one.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Subject is an end user of the integrating application.
//
// RefHMAC is the deterministic HMAC of the reference supplied by that
// application, and is the only form used for lookups. RefSealed holds the
// envelope-encrypted original and is decrypted only to answer an access request
// or to render the admin interface.
type Subject struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	RefHMAC     []byte        `json:"-"`
	RefSealed   []byte        `json:"-"`
	DisplayName string        `json:"display_name,omitempty"`
	Status      SubjectStatus `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	DeletedAt   *time.Time    `json:"deleted_at,omitempty"`
}

// Active reports whether the subject may authenticate.
func (s *Subject) Active() bool {
	return s.Status == SubjectActive && s.DeletedAt == nil
}

// AttestationType mirrors the webauthn_credentials.attestation_type constraint.
type AttestationType string

const (
	AttestationNone     AttestationType = "none"
	AttestationSelf     AttestationType = "self"
	AttestationBasic    AttestationType = "basic"
	AttestationAttCA    AttestationType = "attca"
	AttestationAnonCA   AttestationType = "anonca"
	AttestationIndirect AttestationType = "indirect"
)

// Credential is a registered WebAuthn authenticator.
//
// PublicKey is COSE-encoded and stored in clear: it is a public key, so it
// needs integrity rather than confidentiality.
//
// SignCount is the authenticator's signature counter. A counter that fails to
// advance across two assertions is the documented signal for a cloned
// authenticator, but many authenticators legitimately report a constant zero,
// so the condition raises an alert instead of refusing the assertion.
//
// BindingHash commits to the authenticator characteristics observed at
// registration. A later assertion whose characteristics differ is not rejected
// either, because a firmware update or a transport change moves them
// legitimately; it is recorded so the change is visible in the audit trail.
type Credential struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	SubjectID       string          `json:"subject_id"`
	CredentialID    []byte          `json:"credential_id"`
	PublicKey       []byte          `json:"-"`
	AAGUID          []byte          `json:"aaguid,omitempty"`
	AttestationType AttestationType `json:"attestation_type"`
	Transports      []string        `json:"transports"`
	SignCount       uint32          `json:"sign_count"`
	CloneWarning    bool            `json:"clone_warning"`
	BackupEligible  bool            `json:"backup_eligible"`
	BackupState     bool            `json:"backup_state"`
	UserVerified    bool            `json:"user_verified"`
	BindingHash     []byte          `json:"-"`
	Label           string          `json:"label,omitempty"`
	RPID            string          `json:"rp_id"`
	CreatedAt       time.Time       `json:"created_at"`
	LastUsedAt      *time.Time      `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time      `json:"revoked_at,omitempty"`
	RevokedReason   string          `json:"revoked_reason,omitempty"`
}

// Revoked reports whether the credential has been revoked.
//
// Revocation is final. There is deliberately no un-revoke operation: a
// credential is revoked because it is believed compromised, and a window during
// which that decision can be reversed is a window during which the compromised
// credential can be restored. Protection against mistaken bulk revocation comes
// from rate limiting and alerting, not from reversibility.
func (c *Credential) Revoked() bool { return c.RevokedAt != nil }

// TOTPSecret is a subject's time-based one-time password seed.
//
// SecretSealed is envelope-encrypted: unlike a WebAuthn public key, this is a
// symmetric secret the server must be able to read.
//
// LastTimestep is the anti-replay high water mark. See Store.ConsumeTOTPStep.
type TOTPSecret struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	SubjectID     string     `json:"subject_id"`
	SecretSealed  []byte     `json:"-"`
	Algorithm     string     `json:"algorithm"`
	Digits        int        `json:"digits"`
	PeriodSeconds int        `json:"period_seconds"`
	LastTimestep  int64      `json:"-"`
	Label         string     `json:"label,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ConfirmedAt   *time.Time `json:"confirmed_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// RecoveryCode is one issued single-use code. The plaintext is never stored;
// see internal/crypto/recovery.
type RecoveryCode struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	SubjectID    string     `json:"subject_id"`
	BatchID      string     `json:"batch_id"`
	Selector     string     `json:"-"`
	VerifierHash string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	ConsumedAt   *time.Time `json:"consumed_at,omitempty"`
}

// EnrolmentTicket is a single-use, short-lived secret that permits one WebAuthn
// registration and nothing else.
//
// It is the way back in for a subject who holds no authenticator yet, or who has
// lost every one they had. Redeeming it never produces a signed assertion: a
// stolen ticket lets an attacker enrol a key of their own, which is audited and
// alertable, rather than hand them a session.
//
// Selector and VerifierHash follow the recovery-code construction exactly, and
// are marked json:"-" for the same reason: the plaintext is shown once in the
// issuing response and is not recoverable afterwards, and neither half of the
// stored form belongs in any later response.
//
// ConsumedCredentialID records what the redemption produced, so an operator can
// answer what a ticket was used for rather than only whether it was used.
type EnrolmentTicket struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	SubjectID    string `json:"subject_id"`
	Selector     string `json:"-"`
	VerifierHash string `json:"-"`

	// IssuedBy is the identifier of the API key or administrative token that
	// put the ticket into circulation.
	IssuedBy string `json:"issued_by"`

	Reason               string     `json:"reason,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ConsumedAt           *time.Time `json:"consumed_at,omitempty"`
	ConsumedCredentialID string     `json:"consumed_credential_id,omitempty"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
}

// Redeemable reports whether the ticket may still be redeemed at now.
//
// It is an early filter, not the enforcement. Single use is a property of
// ConsumeEnrolmentTicket's conditional update, because two concurrent
// redemptions would both pass a check made here.
func (t *EnrolmentTicket) Redeemable(now time.Time) bool {
	return t.ConsumedAt == nil && t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// Ceremony distinguishes the two WebAuthn flows.
type Ceremony string

const (
	CeremonyRegistration Ceremony = "registration"
	CeremonyAssertion    Ceremony = "assertion"
)

// Challenge is the server-side state of an in-flight WebAuthn ceremony.
//
// SessionData is the opaque marshalled session of the WebAuthn library. Keeping
// it server-side rather than handing it back to the caller means the caller
// cannot tamper with the expected challenge, the expected user handle or the
// user-verification requirement between the two round trips.
type Challenge struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	SubjectID   string     `json:"subject_id,omitempty"`
	Ceremony    Ceremony   `json:"ceremony"`
	Challenge   []byte     `json:"-"`
	RPID        string     `json:"rp_id"`
	SessionData []byte     `json:"-"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
}

// ActorType identifies who caused an audited event.
type ActorType string

const (
	ActorSystem  ActorType = "system"
	ActorAPIKey  ActorType = "api_key"
	ActorAdmin   ActorType = "admin"
	ActorSubject ActorType = "subject"
)

// Outcome is the result recorded on an audit entry.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
)

// AuditEntry is one immutable record in the hash-chained audit log.
//
// EntryHash commits to the entry's own fields and to PrevHash, so the log forms
// a chain. Verifying the chain detects any insertion, deletion or modification
// after the fact. It cannot prevent one: in an on-premise deployment the
// operator owns the database file.
//
// The personal fields are committed through PIIDigest rather than hashed
// directly, so that honouring an erasure request does not break verification
// for the rest of the log.
type AuditEntry struct {
	Seq          int64           `json:"seq"`
	TenantID     string          `json:"tenant_id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	EventType    string          `json:"event_type"`
	ActorType    ActorType       `json:"actor_type"`
	ActorID      string          `json:"actor_id,omitempty"`
	SubjectID    string          `json:"subject_id,omitempty"`
	ResourceType string          `json:"resource_type,omitempty"`
	ResourceID   string          `json:"resource_id,omitempty"`
	Outcome      Outcome         `json:"outcome"`
	SourceIP     string          `json:"source_ip,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	Detail       json.RawMessage `json:"detail,omitempty"`

	// PIISalt protects the personal fields. It is destroyed when an entry is
	// erased, which is what makes the digest below irreversible afterwards.
	PIISalt []byte `json:"-"`

	// PIIDigest is the salted commitment to SubjectID, SourceIP and Detail.
	// The chain covers this rather than those fields directly, so erasing them
	// does not break verification. See package audit.
	PIIDigest []byte `json:"-"`

	PrevHash  []byte `json:"prev_hash"`
	EntryHash []byte `json:"entry_hash"`
}

// APIKey authenticates an integrating application on the /v1 surface.
//
// The key is presented as "selector.verifier". Only the selector is stored in
// clear, which makes authentication one indexed lookup plus one hash rather
// than a scan that hashes every stored key.
//
// The hash is a single SHA-256, not Argon2id. The verifier carries 160 bits of
// generated entropy, so stretching buys nothing, and it would be paid on every
// request. See internal/crypto/token.
type APIKey struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Selector     string     `json:"-"`
	VerifierHash string     `json:"-"`
	Scopes       []string   `json:"scopes"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by,omitempty"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// AdminToken authenticates an operator on the /admin/v1 surface.
type AdminToken struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Selector     string     `json:"-"`
	VerifierHash string     `json:"-"`
	Role         Role       `json:"role"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by,omitempty"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Usable reports whether the token may authenticate right now.
func (t *AdminToken) Usable(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return false
	}
	return t.Role.Valid()
}

// Usable reports whether the key may authenticate right now.
func (k *APIKey) Usable(now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return false
	}
	return true
}

// ThrottleState is one fixed-window counter.
type ThrottleState struct {
	BucketKey string `json:"bucket_key"`
	TenantID  string `json:"tenant_id"`

	// SubjectID is set on a per-subject bucket and empty on one keyed by
	// address or API key. It exists because the bucket key is an opaque hash,
	// so it is the only way a purge can find a subject's throttle state.
	SubjectID string `json:"subject_id,omitempty"`

	WindowStart  time.Time  `json:"window_start"`
	Attempts     int        `json:"attempts"`
	Failures     int        `json:"failures"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Blocked reports whether the bucket is currently refusing attempts.
func (t *ThrottleState) Blocked(now time.Time) bool {
	return t.BlockedUntil != nil && now.Before(*t.BlockedUntil)
}

// Severity is an alert severity level.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert is a detected condition an operator should look at.
//
// Fingerprint collapses repeated instances of the same condition onto a single
// row, so a brute-force attempt produces one alert with a rising occurrence
// count rather than one alert per request.
type Alert struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	AlertType      string          `json:"alert_type"`
	Severity       Severity        `json:"severity"`
	SubjectID      string          `json:"subject_id,omitempty"`
	ResourceID     string          `json:"resource_id,omitempty"`
	Summary        string          `json:"summary"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	Fingerprint    string          `json:"-"`
	Occurrences    int             `json:"occurrences"`
	FirstSeenAt    time.Time       `json:"first_seen_at"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string          `json:"acknowledged_by,omitempty"`
}

// ApprovalStatus mirrors the approval_requests.status constraint.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
	ApprovalExecuted ApprovalStatus = "executed"
	ApprovalFailed   ApprovalStatus = "failed"
)

// ApprovalRequest is a sensitive operation held for a second administrator.
type ApprovalRequest struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	Operation      string          `json:"operation"`
	Payload        json.RawMessage `json:"payload"`
	Reason         string          `json:"reason,omitempty"`
	Status         ApprovalStatus  `json:"status"`
	RequestedBy    string          `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	DecidedBy      string          `json:"decided_by,omitempty"`
	DecidedAt      *time.Time      `json:"decided_at,omitempty"`
	DecisionNote   string          `json:"decision_note,omitempty"`
	ExecutedAt     *time.Time      `json:"executed_at,omitempty"`
	ExecutionError string          `json:"execution_error,omitempty"`
}

// ErasureStatus mirrors the erasure_requests.status constraint.
type ErasureStatus string

const (
	ErasurePending   ErasureStatus = "pending"
	ErasureCancelled ErasureStatus = "cancelled"
	ErasurePurged    ErasureStatus = "purged"
)

// ErasureRequest tracks a GDPR article 17 erasure through its retention window.
type ErasureRequest struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	SubjectID   string        `json:"subject_id"`
	Status      ErasureStatus `json:"status"`
	Reason      string        `json:"reason,omitempty"`
	RequestedBy string        `json:"requested_by"`
	RequestedAt time.Time     `json:"requested_at"`
	PurgeAfter  time.Time     `json:"purge_after"`
	CancelledBy string        `json:"cancelled_by,omitempty"`
	CancelledAt *time.Time    `json:"cancelled_at,omitempty"`
	PurgedAt    *time.Time    `json:"purged_at,omitempty"`
}
