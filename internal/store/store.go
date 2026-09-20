// Package store defines the persistence contract and the errors it reports.
//
// Two implementations satisfy it, one for SQLite and one for PostgreSQL. The
// interface is written so that neither can be told apart from the outside: any
// behaviour that differs between the engines, such as how a compare-and-swap is
// expressed or how a busy database is retried, is resolved inside the
// implementation rather than surfaced to callers.
package store

import (
	"context"
	"errors"
	"time"
)

// Errors every implementation must return for these conditions, so that
// handlers can map them to HTTP status codes without knowing the engine.
var (
	// ErrNotFound is returned when a record does not exist, or exists but is
	// soft-deleted and therefore invisible to the caller.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned on a unique constraint violation.
	ErrConflict = errors.New("store: conflict")

	// ErrStaleWrite is returned when a compare-and-swap found the row but the
	// expected value had already changed. It is not an error condition in the
	// usual sense: it is how a concurrent attempt loses the race, and callers
	// treat it as a rejected authentication rather than a fault.
	ErrStaleWrite = errors.New("store: stale write")

	// ErrAppendOnly is returned when something tries to modify the audit log.
	ErrAppendOnly = errors.New("store: relation is append-only")

	// ErrSelfApproval is returned when the administrator deciding an approval
	// request is the one who raised it.
	//
	// It is distinct from ErrStaleWrite, which means the request is no longer
	// pending. A two-administrator rule that one administrator can satisfy
	// alone is not a control, so this is a refusal on its own terms rather
	// than a lost race, and a handler maps it to a different response.
	ErrSelfApproval = errors.New("store: an approval requires a second administrator")

	// ErrCorruptRow is returned when a stored value cannot be represented in
	// the field it is read into, such as a WebAuthn signature counter outside
	// the uint32 that the specification gives it.
	//
	// Such a row has been damaged or tampered with, so it is reported rather
	// than narrowed to fit. A narrowed counter is still a plausible counter,
	// and the clone check compares counters: a value that wrapped into the
	// valid range can only make that check pass where it should have failed.
	ErrCorruptRow = errors.New("store: stored value out of range")

	// ErrLockHeld is returned when a lock could not be taken because somebody
	// else holds it.
	//
	// Like ErrStaleWrite it is not a fault. It is how the replica that lost the
	// race is told so, and the answer to it is to do nothing: a caller that
	// retried or reported a problem would turn the normal steady state of every
	// replica but one into noise.
	ErrLockHeld = errors.New("store: lock is held elsewhere")
)

// AuditFilter narrows an audit log query. Zero values mean "no constraint".
//
// Limit is always applied; an implementation must cap it rather than honour an
// unbounded request, because the audit log is the one table that grows without
// limit and an uncapped query over it is a denial-of-service vector.
type AuditFilter struct {
	EventType string
	SubjectID string
	ActorID   string
	Outcome   Outcome
	Since     time.Time
	Until     time.Time
	AfterSeq  int64
	Limit     int
}

// AlertFilter narrows an alert query.
type AlertFilter struct {
	Severity     Severity
	AlertType    string
	SubjectID    string
	IncludeAcked bool

	// AfterID continues a previous page. Keyset paging is used rather than an
	// offset because an offset scan re-reads every skipped row, so later pages
	// get steadily slower on a table that only grows.
	AfterID string

	Limit int
}

// SubjectFilter narrows a subject listing for the admin interface.
type SubjectFilter struct {
	Status SubjectStatus
	// RefHMAC matches one subject exactly. Substring search on the
	// application's own reference is not offered: the reference is stored
	// encrypted precisely so that it cannot be scanned.
	RefHMAC []byte
	AfterID string
	Limit   int
}

// TOTPConsumeResult reports the outcome of a compare-and-swap on a TOTP
// counter.
type TOTPConsumeResult struct {
	// Accepted is true when this call is the one that consumed the timestep.
	Accepted bool
	// PreviousStep is the high water mark that was in place before the call.
	PreviousStep int64
}

// Store is the full persistence contract.
//
// Methods take a context and must honour its cancellation. Implementations must
// be safe for concurrent use by multiple goroutines.
//
// # Where the backends are distinguishable
//
// One difference reaches callers and cannot be hidden. PostgreSQL stores JSON
// columns as JSONB, which is a decomposed representation: keys come back in the
// server's own order and with its own spacing. The JSON documents in
// AuditEntry.Detail, Alert.Detail and ApprovalRequest.Payload are therefore
// semantically stable but not byte stable, and only within one engine. Compare
// them as documents, never as strings.
//
// The audit chain is unaffected because the PostgreSQL implementation
// canonicalises a document through the server before hashing it, so the hash
// covers what is actually stored. A chain is valid within the database that
// produced it; moving a database between engines means rebuilding it.
type Store interface {
	// Migrate applies every pending migration and records it. It is
	// idempotent and safe to call on every start.
	Migrate(ctx context.Context) error

	// Ping reports whether the database is reachable, for the health check.
	Ping(ctx context.Context) error

	// Close releases the connection pool.
	Close() error

	// Engine names the backing engine, for diagnostics ("sqlite",
	// "postgres").
	Engine() string

	TenantStore
	SubjectStore
	CredentialStore
	TOTPStore
	RecoveryStore
	TicketStore
	ChallengeStore
	AuditStore
	AuthnStore
	ThrottleStore
	AlertStore
	ApprovalStore
	ErasureStore
	SealedStore
	JanitorLockStore
}

// TenantStore provisions and reads tenants.
type TenantStore interface {
	CreateTenant(ctx context.Context, t *Tenant) error
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]*Tenant, error)
}

// SubjectStore manages end users.
type SubjectStore interface {
	// UpsertSubject creates the subject or returns the existing one with the
	// same RefHMAC. It is idempotent so that an integrating application can
	// call it on every login without first checking for existence.
	UpsertSubject(ctx context.Context, s *Subject) (*Subject, error)
	GetSubject(ctx context.Context, tenantID, id string) (*Subject, error)
	GetSubjectByRef(ctx context.Context, tenantID string, refHMAC []byte) (*Subject, error)
	ListSubjects(ctx context.Context, tenantID string, f SubjectFilter) ([]*Subject, error)
	SetSubjectStatus(ctx context.Context, tenantID, id string, status SubjectStatus) error

	// SoftDeleteSubject marks the subject deleted without removing the row.
	//
	// This is the first phase of an erasure request. The subject stops being
	// visible to every getter and can no longer authenticate, while the record
	// survives until the retention window closes and PurgeSubject runs. It is
	// what makes erasure reversible during the window, and what keeps the
	// evidence that the erasure was legitimate.
	SoftDeleteSubject(ctx context.Context, tenantID, id string, at time.Time) error

	// RestoreSubject reverses SoftDeleteSubject, and is what cancelling an
	// erasure request calls.
	//
	// It succeeds only while the subject is pending deletion. SetSubjectStatus
	// cannot do this job: it deliberately refuses to touch a soft-deleted row,
	// so that no ordinary status change can bring a deleted subject back by
	// accident. Restoring is its own operation so that it is its own audit
	// event. Returns ErrNotFound once the row has been purged, since by then
	// there is nothing left to restore.
	RestoreSubject(ctx context.Context, tenantID, id string, at time.Time) error
	// PurgeSubject hard-deletes the subject and everything that cascades from
	// it. Audit entries are not deleted: they are rewritten with the subject
	// reference cleared, which preserves the hash chain.
	PurgeSubject(ctx context.Context, tenantID, id string) error
}

// CredentialStore manages registered WebAuthn authenticators.
type CredentialStore interface {
	CreateCredential(ctx context.Context, c *Credential) error
	GetCredential(ctx context.Context, tenantID, id string) (*Credential, error)
	GetCredentialByID(ctx context.Context, tenantID, rpID string, credentialID []byte) (*Credential, error)
	ListCredentials(ctx context.Context, tenantID, subjectID string, includeRevoked bool) ([]*Credential, error)

	// AdvanceSignCount records the counter reported by a successful assertion.
	//
	// The update is a compare-and-swap against expectedPrev. An assertion
	// whose counter does not exceed the stored one has already been seen, or
	// comes from a cloned authenticator, and must not be allowed to move the
	// counter. Returning ErrStaleWrite is how the losing side of two
	// concurrent assertions is told to reject.
	AdvanceSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32, usedAt time.Time) error

	// TouchCredential records that a credential was used, without moving its
	// signature counter.
	//
	// Most passkeys report a constant zero counter, so AdvanceSignCount, which
	// only accepts a strictly greater value, never runs for them. Without this
	// their last use would never be recorded, and a review of dormant
	// credentials would list every passkey in the deployment as never used.
	// Revoked credentials are not touched.
	TouchCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error

	// MarkCloneWarning records that the counter failed to advance, without
	// refusing the assertion. See the Credential doc comment.
	MarkCloneWarning(ctx context.Context, tenantID, id string) error

	// RevokeCredential is final. There is no matching un-revoke.
	RevokeCredential(ctx context.Context, tenantID, id, reason string, at time.Time) error

	// RevokeAllCredentials revokes every active WebAuthn credential of the
	// subject and every TOTP secret that is not already revoked, and reports
	// how many of each it touched.
	//
	// It is one transaction because it is the response to a suspected account
	// compromise. Revoking factor by factor can stop half way, on a timeout or
	// a restart, and a partial revocation during an incident leaves the
	// attacker one working factor while the operator believes the account is
	// closed. Either every factor is revoked or none is, and the caller can
	// retry.
	//
	// An unconfirmed TOTP secret is revoked as well: an attacker inside the
	// account may have started an enrolment, and leaving it pending would let
	// them confirm it after the revocation.
	//
	// Recovery codes are not touched. They are the user's way back in. Like
	// RevokeCredential this is final, and a subject with nothing left to
	// revoke yields two zero counts rather than an error.
	RevokeAllCredentials(ctx context.Context, tenantID, subjectID, reason string, at time.Time) (credentials int64, totp int64, err error)

	// CountActiveCredentials is used to refuse revoking a subject's last
	// credential without an explicit override, which would otherwise be an
	// easy way to lock a user out permanently.
	CountActiveCredentials(ctx context.Context, tenantID, subjectID string) (int, error)
}

// TOTPStore manages time-based one-time password seeds.
type TOTPStore interface {
	CreateTOTPSecret(ctx context.Context, s *TOTPSecret) error
	GetActiveTOTPSecret(ctx context.Context, tenantID, subjectID string) (*TOTPSecret, error)

	// GetPendingTOTPSecret returns the most recent unconfirmed secret.
	//
	// It is separate from GetActiveTOTPSecret because an unconfirmed secret
	// must never authenticate anyone: the user has been shown it but has not
	// proved they can generate a code from it. Only the enrolment confirmation
	// step reads it.
	GetPendingTOTPSecret(ctx context.Context, tenantID, subjectID string) (*TOTPSecret, error)
	ConfirmTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error
	RevokeTOTPSecret(ctx context.Context, tenantID, id string, at time.Time) error

	// ConsumeTOTPStep atomically advances the replay high water mark.
	//
	// It must succeed only if the stored last_timestep is still expectedPrev
	// and step is strictly greater than it. Expressed as a single conditional
	// UPDATE, this closes the race in which two requests presenting the same
	// still-valid code both read the old counter and both accept.
	//
	// A false Accepted with a nil error means the caller lost the race or the
	// code was already spent. That is a rejected authentication, not a fault.
	ConsumeTOTPStep(ctx context.Context, tenantID, id string, expectedPrev, step int64) (TOTPConsumeResult, error)
}

// RecoveryStore manages single-use recovery codes.
type RecoveryStore interface {
	// ReplaceRecoveryCodes issues a new batch and invalidates every unused
	// code from previous batches in one transaction. Issuing a batch without
	// retiring the old one would leave codes in circulation that the user
	// believes are dead.
	ReplaceRecoveryCodes(ctx context.Context, tenantID, subjectID, batchID string, codes []*RecoveryCode) error

	GetRecoveryCodeBySelector(ctx context.Context, tenantID, selector string) (*RecoveryCode, error)

	// ConsumeRecoveryCode marks the code spent, conditional on it not being
	// spent already. Returns ErrStaleWrite if another request got there first.
	ConsumeRecoveryCode(ctx context.Context, tenantID, id string, at time.Time) error

	CountUnusedRecoveryCodes(ctx context.Context, tenantID, subjectID string) (int, error)
}

// TicketStore manages single-use enrolment tickets.
//
// A ticket permits exactly one thing: starting and completing one WebAuthn
// registration for the subject it names. Nothing here issues an assertion, and
// nothing here reads a ticket back in plaintext, because only the selector and
// the Argon2id hash of the verifier are stored.
type TicketStore interface {
	// ReplaceEnrolmentTicket revokes any live ticket for the subject and
	// inserts t, in one transaction.
	//
	// The two writes belong together for the same reason as
	// ReplaceRecoveryCodes: a second ticket issued without the first being
	// retired doubles the window in which a stolen one can be redeemed, and an
	// operator reissuing after a failed delivery would leave the first one
	// working. The schema carries a partial unique index over live tickets per
	// subject as the backstop, so accumulation is impossible rather than merely
	// unlikely.
	ReplaceEnrolmentTicket(ctx context.Context, tenantID, subjectID string, t *EnrolmentTicket) error

	// GetEnrolmentTicketBySelector finds a ticket by the clear half of the
	// secret.
	//
	// A consumed, revoked or expired ticket is still returned. The caller
	// verifies the hashed half first and only then decides, so that a ticket
	// which is merely spent and one that never existed take the same amount of
	// work to reject.
	GetEnrolmentTicketBySelector(ctx context.Context, tenantID, selector string) (*EnrolmentTicket, error)

	// ConsumeEnrolmentTicket marks the ticket spent and records the credential
	// the redemption produced.
	//
	// The update is a compare-and-swap conditional on consumed_at IS NULL AND
	// revoked_at IS NULL AND expires_at > at, expressed as one statement.
	// Single use is that condition and not the caller's check: two concurrent
	// redemptions would both read an unspent ticket, and only one may win.
	//
	// It returns ErrStaleWrite when the row exists but the condition no longer
	// holds, which covers a replay, a revocation and an expiry alike, and
	// ErrNotFound when there is no such row.
	ConsumeEnrolmentTicket(ctx context.Context, tenantID, id, credentialID string, at time.Time) error

	// RevokeEnrolmentTicket withdraws a ticket that has not been redeemed.
	//
	// It is the answer to a mis-delivered ticket, which is the failure the
	// delivery channel makes likely. It returns ErrStaleWrite when the ticket
	// has already been consumed or revoked, and ErrNotFound when there is no
	// such row, so a caller can tell "nothing to withdraw" from "never
	// existed".
	RevokeEnrolmentTicket(ctx context.Context, tenantID, id string, at time.Time) error

	// DeleteExpiredEnrolmentTickets is called by the janitor.
	//
	// The sweep spans every tenant and takes no tenant argument, like the other
	// sweeps, because the janitor acts on behalf of none of them and an expired
	// ticket belongs to nobody. Consumed and revoked rows go the same way once
	// they are past their expiry: the durable record of a redemption is the
	// audit log, not this table.
	DeleteExpiredEnrolmentTickets(ctx context.Context, before time.Time) (int64, error)
}

// ChallengeStore holds in-flight WebAuthn ceremony state.
type ChallengeStore interface {
	CreateChallenge(ctx context.Context, c *Challenge) error

	// ConsumeChallenge fetches and marks the challenge used in one atomic
	// step, so a replayed completion request cannot reuse it. It returns
	// ErrNotFound for an unknown, expired or already consumed challenge: the
	// three cases are deliberately indistinguishable to the caller.
	ConsumeChallenge(ctx context.Context, tenantID, id string, now time.Time) (*Challenge, error)

	// DeleteExpiredChallenges is called by the janitor.
	DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error)
}

// AuditStore appends to and reads the hash-chained audit log.
type AuditStore interface {
	// Append writes one entry. The implementation is responsible for reading
	// the current chain head and computing PrevHash and EntryHash inside the
	// same transaction, because computing them outside would let two
	// concurrent appends chain onto the same predecessor.
	Append(ctx context.Context, e *AuditEntry) (*AuditEntry, error)

	QueryAudit(ctx context.Context, tenantID string, f AuditFilter) ([]*AuditEntry, error)

	// ChainHead returns the sequence number and hash of the newest entry, or
	// zero and the genesis hash when the log is empty.
	ChainHead(ctx context.Context) (seq int64, hash []byte, err error)

	// VerifyChain recomputes every hash from fromSeq onwards and reports the
	// first sequence number that does not match, or zero when the range is
	// intact.
	VerifyChain(ctx context.Context, fromSeq int64) (checked int64, brokenAt int64, err error)

	// ReadAuditRange returns up to limit entries with a sequence number of at
	// least fromSeq, in ascending sequence order.
	//
	// It spans every tenant and takes no tenant argument, for the reason
	// VerifyChain does: the chain is deployment-wide, an entry recorded against
	// the reserved system tenant sits between two ordinary ones, and a
	// tenant-scoped read would present a contiguous chain as one full of holes.
	// QueryAudit is the tenant-scoped read and is what an operator's queries go
	// through; this one exists for the parts of the service that follow the
	// chain itself, where a hole that is not really there would be reported as
	// tampering.
	//
	// A short page means the end of the log has been reached. An entry whose
	// sequence number is above fromSeq while nothing sits at fromSeq itself
	// means the prefix has been trimmed or removed, which the caller is
	// expected to notice rather than the implementation to hide.
	ReadAuditRange(ctx context.Context, fromSeq int64, limit int) ([]*AuditEntry, error)

	// EraseSubjectAuditEntries clears the personal fields from every entry
	// naming a subject and appends a tombstone recording that it happened.
	//
	// This is the only modification the audit table permits. It is possible
	// because the chain commits to a salted digest of the personal fields
	// rather than to the fields themselves, so destroying the salt removes the
	// ability to recover them while leaving verification intact.
	EraseSubjectAuditEntries(ctx context.Context, tenantID, subjectID, actorID string, now time.Time) (int64, error)

	// PruneAuditLog removes entries older than before, recording a checkpoint
	// first so the remaining chain stays verifiable.
	//
	// Entries are removed as a contiguous prefix by sequence number rather
	// than by timestamp. Deleting a scattered set would break verification
	// after every gap, whereas trimming a prefix only moves the point a
	// verifier starts from.
	PruneAuditLog(ctx context.Context, tenantID string, before, now time.Time) (int64, error)
}

// AuthnStore manages the credentials that authenticate callers of the service
// itself, as opposed to end users.
type AuthnStore interface {
	CreateAPIKey(ctx context.Context, k *APIKey) error
	GetAPIKeyBySelector(ctx context.Context, selector string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, tenantID string) ([]*APIKey, error)
	RevokeAPIKey(ctx context.Context, tenantID, id string, at time.Time) error

	CreateAdminToken(ctx context.Context, t *AdminToken) error
	GetAdminTokenBySelector(ctx context.Context, selector string) (*AdminToken, error)
	ListAdminTokens(ctx context.Context, tenantID string) ([]*AdminToken, error)
	RevokeAdminToken(ctx context.Context, tenantID, id string, at time.Time) error

	// RotateAPIKey inserts successor and bounds the predecessor's life at
	// predecessorExpiresAt, in one transaction.
	//
	// The two writes belong together. A successor minted without the
	// predecessor being bounded is the unbounded overlap rotation exists to
	// remove, and a predecessor bounded without a successor is an outage with
	// a timer on it.
	//
	// The predecessor's expiry only ever moves earlier. One that is already
	// due before predecessorExpiresAt keeps its own expiry, because rotating a
	// credential must never be a way to extend its life. A predecessor that is
	// missing, belongs to another tenant or is revoked yields ErrNotFound and
	// nothing is inserted. Whether an expired predecessor may be rotated is
	// the caller's decision, since the caller owns the clock.
	RotateAPIKey(ctx context.Context, tenantID, predecessorID string, successor *APIKey, predecessorExpiresAt time.Time) error

	// RotateAdminToken is RotateAPIKey for an administrative token, with the
	// same rules.
	RotateAdminToken(ctx context.Context, tenantID, predecessorID string, successor *AdminToken, predecessorExpiresAt time.Time) error

	// TouchAPIKey and TouchAdminToken record last use. They are called on the
	// request path, so an implementation may coalesce writes; losing a few
	// seconds of precision on a "last used" timestamp is acceptable, blocking
	// an authentication on a write to record it is not.
	TouchAPIKey(ctx context.Context, id string, at time.Time) error
	TouchAdminToken(ctx context.Context, id string, at time.Time) error

	// CountAdminTokensByRole counts the tokens of a role that are unrevoked
	// and still unexpired at usableAt.
	//
	// The instant is a parameter because the two callers ask different
	// questions. Bootstrap asks who can administer now. The guard against
	// revoking the last full administrator has to ask who will still be able
	// to once every rotation grace has run out: a rotated token keeps working
	// for its grace period, so counted at the present it looks like a second
	// administrator, the guard lets the successor be revoked, and when the
	// grace ends the deployment has nobody left.
	CountAdminTokensByRole(ctx context.Context, tenantID string, role Role, usableAt time.Time) (int, error)
}

// ThrottleStore backs the rate limiter.
type ThrottleStore interface {
	// Hit records one attempt against the bucket and returns the resulting
	// state. The read, the window roll and the increment happen in one
	// transaction; doing them in three calls would let a burst slip through
	// between the read and the write.
	//
	// subjectID names the subject a per-subject bucket belongs to, and is
	// empty for the buckets keyed on an address or an API key. It is recorded
	// because the bucket key is an opaque hash: without it, purging a subject
	// could not find their throttle state and would leave it behind.
	Hit(ctx context.Context, tenantID, bucketKey, subjectID string, window time.Duration, now time.Time, failure bool) (*ThrottleState, error)

	// Block sets blocked_until on the bucket.
	Block(ctx context.Context, tenantID, bucketKey string, until time.Time) error

	GetThrottle(ctx context.Context, tenantID, bucketKey string) (*ThrottleState, error)

	// ResetThrottle clears the bucket, which is what the admin unlock endpoint
	// calls.
	ResetThrottle(ctx context.Context, tenantID, bucketKey string) error

	// ResetSubjectThrottles clears every bucket belonging to a subject, since
	// one subject is throttled under several keys at once.
	ResetSubjectThrottles(ctx context.Context, tenantID, subjectID string) (int64, error)

	DeleteStaleThrottles(ctx context.Context, before time.Time) (int64, error)
}

// AlertStore records detected conditions.
type AlertStore interface {
	// RaiseAlert inserts the alert, or increments the occurrence count and
	// moves last_seen_at when an unacknowledged alert with the same
	// fingerprint already exists.
	RaiseAlert(ctx context.Context, a *Alert) (*Alert, error)

	ListAlerts(ctx context.Context, tenantID string, f AlertFilter) ([]*Alert, error)
	AcknowledgeAlert(ctx context.Context, tenantID, id, by string, at time.Time) error
	CountOpenAlerts(ctx context.Context, tenantID string) (map[Severity]int, error)
}

// ApprovalStore backs the dual-approval queue.
type ApprovalStore interface {
	CreateApproval(ctx context.Context, r *ApprovalRequest) error
	GetApproval(ctx context.Context, tenantID, id string) (*ApprovalRequest, error)
	ListApprovals(ctx context.Context, tenantID string, status ApprovalStatus, limit int) ([]*ApprovalRequest, error)

	// DecideApproval moves a pending request to approved or rejected.
	//
	// The implementation must refuse when decidedBy equals the requester: a
	// two-administrator rule that one administrator can satisfy alone is not a
	// control. It returns ErrStaleWrite when the request is no longer pending.
	DecideApproval(ctx context.Context, tenantID, id, decidedBy string, approve bool, note string, at time.Time) (*ApprovalRequest, error)

	MarkApprovalExecuted(ctx context.Context, tenantID, id string, execErr error, at time.Time) error
	ExpireApprovals(ctx context.Context, before time.Time) (int64, error)
}

// ErasureStore tracks GDPR erasure requests through the retention window.
type ErasureStore interface {
	CreateErasure(ctx context.Context, r *ErasureRequest) error
	GetErasureBySubject(ctx context.Context, tenantID, subjectID string) (*ErasureRequest, error)
	CancelErasure(ctx context.Context, tenantID, id, by string, at time.Time) error
	ListDueErasures(ctx context.Context, before time.Time, limit int) ([]*ErasureRequest, error)
	MarkErasurePurged(ctx context.Context, tenantID, id string, at time.Time) error
}

// SealedKind names one family of envelope-encrypted records.
//
// It is a closed set. An implementation maps each kind to a table and a column
// through a fixed switch, so nothing a caller supplies is ever spliced into a
// statement.
type SealedKind string

// The sealed record families a key rotation has to move.
const (
	// SealedTOTP is totp_secrets.secret_sealed, for secrets not yet revoked.
	// A revoked secret is never unsealed again, so it does not hold an old
	// key version in use.
	SealedTOTP SealedKind = "totp_secret"

	// SealedSubjectRef is subjects.ref_sealed where a reference was sealed.
	// Subjects pending erasure are included: cancelling the erasure brings
	// the row back, and its reference has to be readable when it does.
	SealedSubjectRef SealedKind = "subject_ref"
)

// SealedRecord is one sealed value and the identifier of the row holding it.
type SealedRecord struct {
	ID     string
	Sealed []byte
}

// SealedStore walks and rewrites sealed records for a key rotation.
//
// Both methods span every tenant and take no tenant argument, by design. The
// keyring is deployment-wide: one key encryption key wraps the records of all
// tenants, so retiring a key version is only safe once no row anywhere still
// references it. A per-tenant walk would report a version as unused while
// another tenant's rows still depended on it. This is the same reasoning as the
// janitor sweeps, which act on behalf of no tenant.
//
// Neither method interprets the bytes. Deciding which records need rewrapping
// belongs to the caller, which holds the keyring.
type SealedStore interface {
	// ListSealed returns up to limit records of the kind with an identifier
	// greater than afterID, in identifier order. An empty afterID starts from
	// the beginning. Keyset paging is used for the reason given on
	// AlertFilter.AfterID, and because rows rewritten during the walk keep
	// their identifier, so none is skipped or visited twice.
	ListSealed(ctx context.Context, kind SealedKind, afterID string, limit int) ([]SealedRecord, error)

	// ReplaceSealed writes replacement over the sealed value of one record,
	// conditional on the stored bytes still being old.
	//
	// It returns ErrStaleWrite when they are not. A subject reference can be
	// resealed by an upsert while a rewrap pass is running, and an
	// unconditional write would put back a value derived from the one that was
	// replaced. It returns ErrNotFound when the row has gone.
	ReplaceSealed(ctx context.Context, kind SealedKind, id string, old, replacement []byte) error
}

// JanitorLock is a held janitor lock. The only thing its holder can do with it
// is give it back.
//
// An implementation must also work when Release is never called, because a
// replica killed mid-sweep never calls it. See JanitorLockStore.
type JanitorLock interface {
	// Release gives the lock back, so that the next interval is free for
	// whichever replica gets there first rather than having to wait for a
	// holder that has already finished.
	Release(ctx context.Context) error
}

// JanitorLockStore coordinates the janitor sweeps across replicas.
//
// The janitor runs in process, so a deployment of several replicas performs
// every sweep once per replica. Each sweep is an idempotent conditional delete,
// so the duplication is waste and not damage, and this lock removes the waste
// and nothing else. Nothing a sweep does may come to depend on holding it:
// losing the race is a skipped pass, not an error, and two replicas that both
// sweep one interval still leave the same database behind.
//
// The two engines implement it with different primitives, because they offer
// different ones, and each difference is argued where it applies. What they
// agree on is that the lock is deployment-wide rather than per tenant, that an
// attempt which loses reports ErrLockHeld instead of waiting, and that a holder
// which dies without releasing it loses it within lease.
type JanitorLockStore interface {
	// TryAcquireJanitorLock takes the lock, or reports ErrLockHeld when
	// another replica holds it.
	//
	// It never blocks on the holder. Waiting would land this replica at the
	// start of a sweep the holder has just completed, which is the duplicated
	// work the lock exists to remove, and a wait bounded by somebody else's
	// sweep would hold this pass open past its own timeout.
	//
	// owner names the calling replica, for the operator reading the lock and
	// for Release. now is that replica's own clock, and lease is how long the
	// lock survives a holder that never releases it, which is what stops a
	// replica killed mid-sweep from holding it for ever. An implementation
	// whose primitive is bound to the connection rather than to a clock
	// ignores both, and says so.
	TryAcquireJanitorLock(ctx context.Context, owner string, now time.Time, lease time.Duration) (JanitorLock, error)
}
