package n0passtemps

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SubjectStatus is the lifecycle state of a subject.
type SubjectStatus string

// The states a subject can be in. Only an active subject can authenticate.
const (
	// SubjectActive is the normal state.
	SubjectActive SubjectStatus = "active"

	// SubjectLocked is an operator's decision and lasts until it is undone. It
	// is distinct from a throttle lockout, which expires by itself.
	SubjectLocked SubjectStatus = "locked"

	// SubjectPendingDeletion is a subject blocked while an erasure request
	// runs its retention window.
	SubjectPendingDeletion SubjectStatus = "pending_deletion"
)

// Subject is what the public routes disclose about a subject.
//
// It never carries the reference the application supplied: the caller already
// has it, and the server keeps it out of response bodies that an intermediary
// may cache or log.
type Subject struct {
	// SubjectID is the server's own identifier. It is the "sub" claim of every
	// assertion issued for this subject.
	SubjectID string        `json:"subject_id"`
	Status    SubjectStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`

	// CredentialCount is the number of active WebAuthn authenticators. Zero
	// means the subject needs a registration before it can assert.
	CredentialCount        int  `json:"credential_count"`
	TOTPEnrolled           bool `json:"totp_enrolled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// Ceremony is the first half of a WebAuthn ceremony.
type Ceremony struct {
	// ChallengeID identifies the ceremony and is presented again on
	// completion. The expected challenge itself stays on the server.
	ChallengeID string `json:"challenge_id"`

	// Options is sent to the browser untouched. It is an object with one
	// "publicKey" member, the shape navigator.credentials.create() and
	// navigator.credentials.get() take, in WebAuthn's JSON form: the page
	// turns the base64url members into buffers before the call. It is raw JSON
	// here because this package has no business interpreting it, and a struct
	// would drop whatever member it did not know.
	Options json.RawMessage `json:"options"`

	// ExpiresAt is when the challenge stops being accepted.
	ExpiresAt time.Time `json:"expires_at"`
}

// Credential is a registered WebAuthn authenticator.
type Credential struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	SubjectID string `json:"subject_id"`

	// CredentialID is the raw WebAuthn credential identifier. The server
	// renders it as padded base64, where a browser uses base64url: compare the
	// bytes, never the strings.
	CredentialID []byte `json:"credential_id"`

	// AAGUID identifies the authenticator model, when it supplied one.
	AAGUID          []byte   `json:"aaguid,omitempty"`
	AttestationType string   `json:"attestation_type"`
	Transports      []string `json:"transports"`
	SignCount       uint32   `json:"sign_count"`
	CloneWarning    bool     `json:"clone_warning"`
	BackupEligible  bool     `json:"backup_eligible"`
	BackupState     bool     `json:"backup_state"`

	// UserVerified describes the registration ceremony only. Whether a later
	// authentication was user verified is told by FactorWebAuthnUV in the
	// assertion, and must not be inferred from this field.
	UserVerified  bool       `json:"user_verified"`
	Label         string     `json:"label,omitempty"`
	RPID          string     `json:"rp_id"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
}

// Registration is the result of a completed registration ceremony.
type Registration struct {
	Credential Credential `json:"credential"`

	// RecoveryCodesRemaining is reported because a first authenticator is the
	// moment recovery codes become useful. The server does not issue them
	// unasked; call IssueRecoveryCodes.
	RecoveryCodesRemaining int `json:"recovery_codes_remaining"`
}

// AssertionResult is what a successful authentication returns.
//
// The fields beside Assertion are a convenience and are not signed. Decide
// nothing on them: pass Assertion to Verifier.Verify and act on the claims it
// returns.
type AssertionResult struct {
	SubjectID string `json:"subject_id"`

	// Assertion is the compact JWS to verify.
	Assertion string    `json:"assertion"`
	ExpiresAt time.Time `json:"expires_at"`
	Factors   []Factor  `json:"factors"`

	// Signals reports conditions that did not refuse the authentication but
	// may justify a step-up. Known members are "sign_count_regression" and
	// "binding_changed", both booleans.
	Signals map[string]any `json:"signals,omitempty"`
}

// TOTPEnrolment is a TOTP secret awaiting confirmation.
//
// The secret is disclosed by this one response and never again. It
// authenticates nothing until ConfirmTOTP succeeds.
type TOTPEnrolment struct {
	SecretID string `json:"secret_id"`

	// Secret is the unpadded base32 seed, for a user typing it by hand.
	Secret string `json:"secret"`

	// ProvisioningURI is the otpauth:// form, for rendering as a QR code.
	ProvisioningURI string `json:"provisioning_uri"`
	Algorithm       string `json:"algorithm"`
	Digits          int    `json:"digits"`
	PeriodSeconds   int    `json:"period_seconds"`

	// ExpiresAt is when the unconfirmed enrolment stops being usable.
	ExpiresAt time.Time `json:"expires_at"`
}

// TOTPConfirmation is the result of a confirmed TOTP enrolment.
type TOTPConfirmation struct {
	SecretID  string `json:"secret_id"`
	Confirmed bool   `json:"confirmed"`
}

// RecoveryCodes is a fresh batch of single-use recovery codes.
//
// The codes exist in this response and nowhere else: the server stores only
// their hashes. Issuing a batch retires every unused code of the previous one.
type RecoveryCodes struct {
	BatchID string   `json:"batch_id"`
	Codes   []string `json:"codes"`
	Count   int      `json:"count"`
	Warning string   `json:"warning"`
}

// RecoveryResult is what consuming a recovery code returns.
type RecoveryResult struct {
	AssertionResult

	// RecoveryCodesRemaining counts the codes still unused. At zero the
	// subject has no way back in if they lose their authenticator.
	RecoveryCodesRemaining int `json:"recovery_codes_remaining"`
}

// HealthStatus is the verdict of a health check.
type HealthStatus string

// The health verdicts, from best to worst.
const (
	// HealthOK means every check passed.
	HealthOK HealthStatus = "ok"

	// HealthDegraded means users still authenticate but something needs
	// attention, such as an overdue key rotation.
	HealthDegraded HealthStatus = "degraded"

	// HealthError means users cannot authenticate, which in practice means
	// the store is unreachable.
	HealthError HealthStatus = "error"
)

// Liveness is the anonymous health report. It carries a status and nothing
// else, by design of the server.
type Liveness struct {
	Status HealthStatus `json:"status"`
}

// HealthReport is the authenticated component report.
type HealthReport struct {
	Status        HealthStatus   `json:"status"`
	Version       VersionInfo    `json:"version"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Database      DatabaseHealth `json:"database"`
	KEK           KEKHealth      `json:"kek"`

	// TLS is nil when TLS is terminated by a reverse proxy, whose certificate
	// the server cannot see.
	TLS        *TLSHealth      `json:"tls,omitempty"`
	Audit      AuditHealth     `json:"audit"`
	OpenAlerts map[string]int  `json:"open_alerts"`
	Features   map[string]bool `json:"features"`
	Timestamp  time.Time       `json:"timestamp"`
	LastError  string          `json:"last_error,omitempty"`
}

// VersionInfo names the server build.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// DatabaseHealth is the state of the server's store.
type DatabaseHealth struct {
	Status    HealthStatus `json:"status"`
	Engine    string       `json:"engine"`
	LatencyMS int64        `json:"latency_ms"`
	Detail    string       `json:"detail,omitempty"`
}

// KEKHealth is the state of the key encryption keyring.
type KEKHealth struct {
	Status           HealthStatus `json:"status"`
	CurrentVersion   uint32       `json:"current_version"`
	RetainedVersions int          `json:"retained_versions"`
	RotationOverdue  bool         `json:"rotation_overdue"`
	Detail           string       `json:"detail,omitempty"`
}

// TLSHealth is the state of the certificate, when TLS is terminated in
// process.
type TLSHealth struct {
	Status        HealthStatus `json:"status"`
	NotAfter      time.Time    `json:"not_after"`
	ExpiresInDays int          `json:"expires_in_days"`
	Subject       string       `json:"subject,omitempty"`
	Detail        string       `json:"detail,omitempty"`
}

// AuditHealth is the state of the audit chain.
type AuditHealth struct {
	Status  HealthStatus `json:"status"`
	HeadSeq int64        `json:"head_seq"`
	Detail  string       `json:"detail,omitempty"`
}

type resolveSubjectRequest struct {
	SubjectRef  string `json:"subject_ref"`
	DisplayName string `json:"display_name,omitempty"`
}

type beginRegistrationRequest struct {
	Label string `json:"label,omitempty"`
}

// completeRequest is the body of both completion routes. Credential is raw
// JSON so that the browser's response reaches the server byte for byte.
type completeRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

type codeRequest struct {
	Code string `json:"code"`
}

// ResolveSubject returns the subject for subjectRef, creating it when it does
// not exist yet. displayName is optional and only shown to operators.
//
// The call is idempotent, so an application may make it on every login
// instead of tracking which users it has already declared. Prefer an opaque
// identifier to an email address as the reference: it travels in URL paths,
// which reverse proxies log.
func (c *Client) ResolveSubject(ctx context.Context, subjectRef, displayName string) (*Subject, error) {
	if subjectRef == "" {
		return nil, errors.New("n0passtemps: the subject reference is empty")
	}
	var out Subject
	err := c.do(ctx, call{
		method: http.MethodPost, route: "/v1/subjects", path: "/v1/subjects",
		body:       resolveSubjectRequest{SubjectRef: subjectRef, DisplayName: displayName},
		out:        &out,
		idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSubject reports which factors a subject has enrolled, to decide what to
// offer a returning user. An unknown subject is ErrNotFound: this is a lookup,
// not an authentication attempt, and the only route that tells the two apart.
func (c *Client) GetSubject(ctx context.Context, subjectRef string) (*Subject, error) {
	path, err := subjectPath("subjects", subjectRef, "")
	if err != nil {
		return nil, err
	}
	var out Subject
	err = c.do(ctx, call{
		method: http.MethodGet, route: "/v1/subjects/{subject_ref}", path: path,
		out: &out, idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// BeginRegistration starts a WebAuthn registration ceremony. label is optional
// and names the authenticator for the user and the operator.
//
// The subject must exist already; call ResolveSubject first. Hand
// Ceremony.Options to the browser as it is.
func (c *Client) BeginRegistration(ctx context.Context, subjectRef, label string) (*Ceremony, error) {
	path, err := subjectPath("webauthn", subjectRef, "/register")
	if err != nil {
		return nil, err
	}
	cl := call{method: http.MethodPost, route: "/v1/webauthn/{subject_ref}/register", path: path}
	if label != "" {
		cl.body = beginRegistrationRequest{Label: label}
	}
	return c.ceremony(ctx, cl)
}

// CompleteRegistration finishes a registration ceremony. credential is the
// PublicKeyCredential the browser produced, forwarded verbatim.
//
// A challenge is single use, so this call is never retried.
func (c *Client) CompleteRegistration(ctx context.Context, subjectRef, challengeID string, credential json.RawMessage) (*Registration, error) {
	path, err := subjectPath("webauthn", subjectRef, "/register/complete")
	if err != nil {
		return nil, err
	}
	if err := checkCompletion(challengeID, credential); err != nil {
		return nil, err
	}
	var out Registration
	err = c.do(ctx, call{
		method: http.MethodPost, route: "/v1/webauthn/{subject_ref}/register/complete", path: path,
		body: completeRequest{ChallengeID: challengeID, Credential: credential},
		out:  &out,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// BeginAssertion starts a WebAuthn authentication ceremony.
//
// An unknown subject, a locked one and one with no authenticator are all
// answered ErrAuthenticationFailed, so that the route cannot be used to test
// whether a person has an account. Use GetSubject to choose what to offer.
func (c *Client) BeginAssertion(ctx context.Context, subjectRef string) (*Ceremony, error) {
	path, err := subjectPath("webauthn", subjectRef, "/assert")
	if err != nil {
		return nil, err
	}
	return c.ceremony(ctx, call{method: http.MethodPost, route: "/v1/webauthn/{subject_ref}/assert", path: path})
}

// CompleteAssertion finishes an authentication ceremony. credential is the
// PublicKeyCredential the browser produced, forwarded verbatim.
//
// Verify the returned assertion before acting on it. A challenge is single
// use, so this call is never retried.
func (c *Client) CompleteAssertion(ctx context.Context, subjectRef, challengeID string, credential json.RawMessage) (*AssertionResult, error) {
	path, err := subjectPath("webauthn", subjectRef, "/assert/complete")
	if err != nil {
		return nil, err
	}
	if err := checkCompletion(challengeID, credential); err != nil {
		return nil, err
	}
	var out AssertionResult
	err = c.do(ctx, call{
		method: http.MethodPost, route: "/v1/webauthn/{subject_ref}/assert/complete", path: path,
		body: completeRequest{ChallengeID: challengeID, Credential: credential},
		out:  &out,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// EnrolTOTP issues a TOTP secret for the subject. The secret is pending until
// ConfirmTOTP proves the user can produce a code from it.
func (c *Client) EnrolTOTP(ctx context.Context, subjectRef string) (*TOTPEnrolment, error) {
	path, err := subjectPath("totp", subjectRef, "/enrol")
	if err != nil {
		return nil, err
	}
	var out TOTPEnrolment
	err = c.do(ctx, call{method: http.MethodPost, route: "/v1/totp/{subject_ref}/enrol", path: path, out: &out})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfirmTOTP activates the pending secret with one code from the user's
// authenticator application. An enrolment left unconfirmed past its window is
// ErrConflict, and needs a new EnrolTOTP.
func (c *Client) ConfirmTOTP(ctx context.Context, subjectRef, code string) (*TOTPConfirmation, error) {
	path, err := subjectPath("totp", subjectRef, "/enrol/confirm")
	if err != nil {
		return nil, err
	}
	var out TOTPConfirmation
	err = c.do(ctx, call{
		method: http.MethodPost, route: "/v1/totp/{subject_ref}/enrol/confirm", path: path,
		body: codeRequest{Code: code}, out: &out,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyTOTP authenticates the subject with a TOTP code. The assertion it
// returns carries FactorTOTP.
//
// A code is single use on the server, so this call is never retried.
func (c *Client) VerifyTOTP(ctx context.Context, subjectRef, code string) (*AssertionResult, error) {
	path, err := subjectPath("totp", subjectRef, "/verify")
	if err != nil {
		return nil, err
	}
	var out AssertionResult
	err = c.do(ctx, call{
		method: http.MethodPost, route: "/v1/totp/{subject_ref}/verify", path: path,
		body: codeRequest{Code: code}, out: &out,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueRecoveryCodes issues a fresh batch of recovery codes and retires the
// unused codes of the previous batch. Show the codes to the user at once: no
// later call can display them again.
func (c *Client) IssueRecoveryCodes(ctx context.Context, subjectRef string) (*RecoveryCodes, error) {
	path, err := subjectPath("recovery", subjectRef, "/issue")
	if err != nil {
		return nil, err
	}
	var out RecoveryCodes
	err = c.do(ctx, call{method: http.MethodPost, route: "/v1/recovery/{subject_ref}/issue", path: path, out: &out})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ConsumeRecoveryCode authenticates the subject with a recovery code and
// spends it. The assertion it returns carries FactorRecoveryCode, which most
// applications treat as lower assurance and follow with a re-enrolment.
func (c *Client) ConsumeRecoveryCode(ctx context.Context, subjectRef, code string) (*RecoveryResult, error) {
	path, err := subjectPath("recovery", subjectRef, "/consume")
	if err != nil {
		return nil, err
	}
	var out RecoveryResult
	err = c.do(ctx, call{
		method: http.MethodPost, route: "/v1/recovery/{subject_ref}/consume", path: path,
		body: codeRequest{Code: code}, out: &out,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Health calls the anonymous liveness probe. The API key is not sent.
//
// A server that cannot reach its store answers 503, which is returned as an
// *Error matching ErrUnavailable.
func (c *Client) Health(ctx context.Context) (*Liveness, error) {
	var out Liveness
	err := c.do(ctx, call{
		method: http.MethodGet, route: "/v1/health", path: "/v1/health",
		out: &out, anonymous: true, idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// HealthDetail returns the authenticated component report. It needs the
// "health" scope, or an unrestricted key.
func (c *Client) HealthDetail(ctx context.Context) (*HealthReport, error) {
	var out HealthReport
	err := c.do(ctx, call{
		method: http.MethodGet, route: "/v1/health/detail", path: "/v1/health/detail",
		out: &out, idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ceremony performs a begin call.
func (c *Client) ceremony(ctx context.Context, cl call) (*Ceremony, error) {
	var out Ceremony
	cl.out = &out
	if err := c.do(ctx, cl); err != nil {
		return nil, err
	}
	return &out, nil
}

// checkCompletion refuses the two mistakes the server would answer with a 400,
// before a request is spent on them.
func checkCompletion(challengeID string, credential json.RawMessage) error {
	if challengeID == "" {
		return errors.New("n0passtemps: the challenge identifier is empty")
	}
	if !json.Valid(credential) {
		return errors.New("n0passtemps: the credential is not valid JSON")
	}
	return nil
}
