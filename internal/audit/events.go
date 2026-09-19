package audit

// Event types.
//
// The names are dotted and hierarchical, so a query can select a whole family
// with a prefix match. They are string constants rather than an enumeration
// because they are written into a persisted, hash-covered record: renumbering
// an enumeration would silently change the meaning of history.
//
// Every administrative action has an event type. An administrative operation
// that does not produce an audit entry is a gap in the record, so handlers are
// written to append the entry in the same transaction as the change wherever
// the store allows it.
const (
	// Subject lifecycle.
	EventSubjectCreated       = "subject.created"
	EventSubjectStatusChanged = "subject.status_changed"
	EventSubjectLocked        = "subject.locked"
	EventSubjectUnlocked      = "subject.unlocked"

	// WebAuthn registration.
	EventRegistrationStarted   = "webauthn.registration.started"
	EventRegistrationCompleted = "webauthn.registration.completed"
	EventRegistrationRejected  = "webauthn.registration.rejected"

	// WebAuthn assertion.
	EventAssertionStarted   = "webauthn.assertion.started"
	EventAssertionCompleted = "webauthn.assertion.completed"
	EventAssertionRejected  = "webauthn.assertion.rejected"

	// Signals raised during an assertion that do not by themselves refuse it.
	EventSignCountRegression = "webauthn.sign_count_regression"
	EventBindingChanged      = "webauthn.binding_changed"

	// Credential administration.
	EventCredentialRevoked     = "credential.revoked"
	EventCredentialLabelled    = "credential.labelled"
	EventCredentialBulkRevoked = "credential.bulk_revoked"

	// TOTP.
	EventTOTPEnrolled  = "totp.enrolled"
	EventTOTPConfirmed = "totp.confirmed"
	EventTOTPVerified  = "totp.verified"
	EventTOTPRejected  = "totp.rejected"
	EventTOTPReplayed  = "totp.replay_detected"
	EventTOTPRevoked   = "totp.revoked"

	// Recovery codes.
	EventRecoveryIssued    = "recovery.issued"
	EventRecoveryConsumed  = "recovery.consumed"
	EventRecoveryRejected  = "recovery.rejected"
	EventRecoveryExhausted = "recovery.exhausted"

	// Enrolment tickets.
	//
	// Redemption has two audited steps rather than one, because the ceremony
	// has two round trips and an attacker who starts one but never finishes it
	// still proves they hold the ticket. The rejected event carries the reason
	// in its detail, which is the only place the reason appears: the caller is
	// told nothing beyond a refusal.
	EventTicketIssued   = "enrolment_ticket.issued"
	EventTicketRedeemed = "enrolment_ticket.redeemed"
	EventTicketRejected = "enrolment_ticket.rejected"
	EventTicketRevoked  = "enrolment_ticket.revoked"

	// Throttling.
	EventThrottleTripped = "throttle.tripped"
	EventThrottleReset   = "throttle.reset"

	// Caller credentials.
	//
	// A rotation has its own event rather than a created entry followed by a
	// revoked one. The predecessor is not revoked, it is given an expiry, and
	// an entry pair would leave a reader to work out that the two credentials
	// are the same integration. The detail names both identifiers and the
	// instant the predecessor stops, and never the token.
	EventAPIKeyCreated     = "api_key.created"
	EventAPIKeyRevoked     = "api_key.revoked"
	EventAPIKeyRotated     = "api_key.rotated"
	EventAPIKeyRejected    = "api_key.rejected"
	EventAdminTokenCreated = "admin_token.created"
	EventAdminTokenRevoked = "admin_token.revoked"
	EventAdminTokenRotated = "admin_token.rotated"
	EventAdminAuthFailed   = "admin.auth_failed"
	EventAdminAuthorised   = "admin.authorised"
	EventAdminDenied       = "admin.denied"

	// Dual approval.
	EventApprovalRequested = "approval.requested"
	EventApprovalGranted   = "approval.granted"
	EventApprovalRejected  = "approval.rejected"
	EventApprovalExpired   = "approval.expired"
	EventApprovalExecuted  = "approval.executed"

	// Erasure.
	EventErasureRequested = "erasure.requested"
	EventErasureCancelled = "erasure.cancelled"
	EventErasurePurged    = "erasure.purged"
	EventSubjectRedacted  = "erasure.entries_redacted"

	// Key management.
	EventKEKLoaded    = "kek.loaded"
	EventKEKRotated   = "kek.rotated"
	EventKEKRewrapped = "kek.rewrapped"

	// Service lifecycle.
	EventServiceStarted    = "service.started"
	EventServiceStopping   = "service.stopping"
	EventMigrationApplied  = "service.migration_applied"
	EventChainVerified     = "audit.chain_verified"
	EventChainBroken       = "audit.chain_broken"
	EventAlertRaised       = "alert.raised"
	EventAlertAcknowledged = "alert.acknowledged"
)
