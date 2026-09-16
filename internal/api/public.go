package api

import (
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/totp"
	wa "github.com/Socold/n0passtemps/internal/webauthn"
)

// decodeJSON reads a request body into v.
//
// Unknown fields are refused. A caller who misspells a field name would
// otherwise get the zero value silently, and for a security-relevant field such
// as a challenge identifier that failure is invisible until it matters.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return BadRequest("a JSON body is required", nil)
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &APIError{
				Status: http.StatusRequestEntityTooLarge, Type: TypePayloadTooLarge,
				Title: "the request body is too large", Internal: err,
			}
		}
		return BadRequest("the request body is not valid JSON: "+err.Error(), err)
	}

	// A body carrying a second JSON document would have its remainder ignored,
	// which is a way to smuggle content past a proxy that inspects only the
	// first.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return BadRequest("the request body must contain exactly one JSON document", nil)
	}
	return nil
}

// subjectRef reads the subject reference from the path.
//
// The reference is an identifier belonging to the integrating application. It
// appears in the path because that is the shape the API contract specifies;
// this service logs the route pattern rather than the concrete path so the
// value does not reach its own logs, but an intervening reverse proxy will log
// it unless configured otherwise. That is why the documentation asks for an
// opaque identifier rather than an email address, and why the reference is
// encrypted at rest regardless.
func (s *Server) subjectRef(r *http.Request) (string, error) {
	ref := r.PathValue("subject_ref")
	if ref == "" {
		return "", BadRequest("the subject reference is missing from the path", nil)
	}
	if err := s.deps.Subjects.ValidateRef(ref); err != nil {
		return "", BadRequest("the subject reference is not acceptable: "+err.Error(), err)
	}
	return ref, nil
}

// resolveSubject loads the subject for a request, without creating one.
//
// An unknown subject and an inactive one produce the same refusal as a failed
// ceremony. Returning a distinguishable "no such subject" would turn every
// authentication endpoint into a way to test whether a given person has an
// account.
func (s *Server) resolveSubject(r *http.Request, tenantID, ref string) (*store.Subject, error) {
	sub, err := s.deps.Subjects.Lookup(r.Context(), tenantID, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, CeremonyFailed(errors.New("subject is not enrolled"))
		}
		return nil, Internal(err)
	}
	if !sub.Active() {
		return nil, CeremonyFailed(fmt.Errorf("subject status is %s", sub.Status))
	}
	return sub, nil
}

// handler is the signature every route is written against.
//
// Returning an error rather than writing a response means the status code, the
// log line and the audit outcome are decided in one place, and a handler cannot
// forget one of the three.
type handler func(http.ResponseWriter, *http.Request) error

// wrap adapts a handler to http.Handler.
func wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			WriteProblem(w, r, err)
		}
	}
}

// createSubjectRequest is the body of POST /v1/subjects.
type createSubjectRequest struct {
	// SubjectRef is the identifier the calling application uses for its user.
	SubjectRef string `json:"subject_ref"`

	// DisplayName is optional and shown in the administration interface.
	DisplayName string `json:"display_name,omitempty"`
}

// subjectResponse is what the public routes disclose about a subject.
//
// It carries the internal identifier and the status, and never the reference
// the caller supplied: the caller already has that, and echoing it would put it
// into response bodies that intermediaries may cache or log.
type subjectResponse struct {
	SubjectID     string              `json:"subject_id"`
	Status        store.SubjectStatus `json:"status"`
	CreatedAt     time.Time           `json:"created_at"`
	Credentials   int                 `json:"credential_count"`
	TOTPEnrolled  bool                `json:"totp_enrolled"`
	RecoveryCodes int                 `json:"recovery_codes_remaining"`
}

// handleCreateSubject resolves a reference to a subject, creating it if needed.
//
// It is idempotent, so an integrating application may call it on every login
// rather than tracking whether it has registered the user here before.
func (s *Server) handleCreateSubject(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}

	var req createSubjectRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}

	sub, err := s.deps.Subjects.Resolve(r.Context(), tenantID, req.SubjectRef, req.DisplayName)
	if err != nil {
		return refErrorToAPI(err)
	}

	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventSubjectCreated,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "subject",
		ResourceID:   sub.ID,
		Outcome:      store.OutcomeSuccess,
	})

	resp, err := s.subjectSummary(r, tenantID, sub)
	if err != nil {
		return err
	}
	WriteJSON(w, r, http.StatusOK, resp)
	return nil
}

// handleGetSubject reports what factors a subject has enrolled.
//
// An integrating application uses this to decide what to offer: a subject with
// no credential needs registration, one with credentials needs assertion.
func (s *Server) handleGetSubject(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	sub, err := s.deps.Subjects.Lookup(r.Context(), tenantID, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	resp, err := s.subjectSummary(r, tenantID, sub)
	if err != nil {
		return err
	}
	WriteJSON(w, r, http.StatusOK, resp)
	return nil
}

// subjectSummary counts the enrolled factors.
func (s *Server) subjectSummary(r *http.Request, tenantID string, sub *store.Subject) (*subjectResponse, error) {
	ctx := r.Context()

	creds, err := s.deps.Store.ListCredentials(ctx, tenantID, sub.ID, false)
	if err != nil {
		return nil, Internal(err)
	}
	codes, err := s.deps.Store.CountUnusedRecoveryCodes(ctx, tenantID, sub.ID)
	if err != nil {
		return nil, Internal(err)
	}

	totpEnrolled := false
	if _, err := s.deps.Store.GetActiveTOTPSecret(ctx, tenantID, sub.ID); err == nil {
		totpEnrolled = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, Internal(err)
	}

	return &subjectResponse{
		SubjectID:     sub.ID,
		Status:        sub.Status,
		CreatedAt:     sub.CreatedAt,
		Credentials:   len(creds),
		TOTPEnrolled:  totpEnrolled,
		RecoveryCodes: codes,
	}, nil
}

// registerBeginRequest is the body of POST /v1/webauthn/{subject_ref}/register.
type registerBeginRequest struct {
	// Label is shown by the authenticator while the user confirms, and is
	// stored so an operator can tell one of a subject's keys from another. It
	// is not used for any decision.
	Label string `json:"label,omitempty"`
}

// handleRegisterBegin starts a WebAuthn registration ceremony.
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req registerBeginRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
	}

	// The subject must exist before an authenticator is enrolled against it.
	// Creating it here implicitly would let a caller with a valid key populate
	// the database with subjects by starting ceremonies it never finishes.
	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	result, err := s.deps.WebAuthn.BeginRegistration(r.Context(), sub, req.Label)
	if err != nil {
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventRegistrationStarted, err)
	}

	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventRegistrationStarted,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "challenge",
		ResourceID:   result.ChallengeID,
		Outcome:      store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, result)
	return nil
}

// ceremonyCompleteRequest is the body of both completion routes.
type ceremonyCompleteRequest struct {
	// ChallengeID is the value returned by the corresponding begin call.
	ChallengeID string `json:"challenge_id"`

	// Credential is the PublicKeyCredential the browser produced, forwarded
	// verbatim. It is kept as raw JSON so that this service parses it with the
	// WebAuthn library rather than through a struct that might drop a field
	// the library needs to verify.
	Credential json.RawMessage `json:"credential"`
}

func (req *ceremonyCompleteRequest) validate() error {
	if strings.TrimSpace(req.ChallengeID) == "" {
		return BadRequest("challenge_id is required", nil)
	}
	if _, err := uuid.Parse(req.ChallengeID); err != nil {
		// Rejecting a malformed identifier here keeps rubbish input from
		// reaching the database.
		return BadRequest("challenge_id is not a valid identifier", err)
	}
	if len(req.Credential) == 0 {
		return BadRequest("credential is required", nil)
	}
	return nil
}

// handleRegisterComplete finishes a registration ceremony.
func (s *Server) handleRegisterComplete(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req ceremonyCompleteRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if err := req.validate(); err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	cred, err := s.deps.WebAuthn.CompleteRegistration(r.Context(), sub,
		req.ChallengeID, req.Credential, "")
	if err != nil {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventRegistrationRejected, err)
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)
	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventRegistrationCompleted,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "credential",
		ResourceID:   cred.ID,
		Outcome:      store.OutcomeSuccess,
		Detail: map[string]any{
			"aaguid":           fmt.Sprintf("%x", cred.AAGUID),
			"attestation_type": string(cred.AttestationType),
			"user_verified":    cred.UserVerified,
			"backup_eligible":  cred.BackupEligible,
		},
	})

	// A first credential is the point at which recovery codes become useful,
	// so the response says whether the subject has any. Issuing them
	// automatically would mean returning them in a response the caller did not
	// ask for, and they can only be shown once.
	remaining, err := s.deps.Store.CountUnusedRecoveryCodes(r.Context(), tenantID, sub.ID)
	if err != nil {
		return Internal(err)
	}

	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"credential":               cred,
		"recovery_codes_remaining": remaining,
	})
	return nil
}

// handleAssertBegin starts an authentication ceremony.
func (s *Server) handleAssertBegin(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	result, err := s.deps.WebAuthn.BeginAssertion(r.Context(), sub)
	if err != nil {
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventAssertionStarted, err)
	}

	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventAssertionStarted,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "challenge",
		ResourceID:   result.ChallengeID,
		Outcome:      store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, result)
	return nil
}

// assertionResponse is what a successful ceremony returns.
//
// The signed assertion is the substance of it. A bare 200 would oblige the
// calling application to trust the network path between itself and this
// service; a detached signature it verifies against the published key does not.
// See docs/adr/0004.
type assertionResponse struct {
	SubjectID string `json:"subject_id"`

	// Assertion is a compact JWS. The caller verifies it against the key
	// served from /v1/.well-known/jwks.json and then issues its own session.
	Assertion string `json:"assertion"`

	// ExpiresAt is short by design. The assertion proves a ceremony completed
	// moments ago and is meant to be exchanged immediately.
	ExpiresAt time.Time `json:"expires_at"`

	// Factors names what actually authenticated the subject, so the caller can
	// apply its own policy. A WebAuthn assertion with user verification is a
	// different assurance from a recovery code.
	Factors []assertion.Factor `json:"factors"`

	// Signals are conditions worth surfacing that did not refuse the
	// authentication. They are reported so the caller may decide to step up,
	// not because this service considers the assertion invalid.
	Signals map[string]any `json:"signals,omitempty"`
}

// handleAssertComplete finishes an authentication ceremony.
func (s *Server) handleAssertComplete(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req ceremonyCompleteRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if err := req.validate(); err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	outcome, err := s.deps.WebAuthn.CompleteAssertion(r.Context(), sub,
		req.ChallengeID, req.Credential)
	if err != nil {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventAssertionRejected, err)
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)

	factors := []assertion.Factor{assertion.FactorWebAuthn}
	if outcome.UserVerified {
		factors = append(factors, assertion.FactorWebAuthnUV)
	}

	signals := map[string]any{}
	if outcome.CloneWarning {
		signals["sign_count_regression"] = true
		s.reportCloneWarning(r, tenantID, sub, outcome)
	}
	if outcome.BindingChanged {
		signals["binding_changed"] = true
		s.audited(r, audit.Event{
			TenantID:     tenantID,
			EventType:    audit.EventBindingChanged,
			ActorType:    caller.ActorType(),
			ActorID:      caller.ActorID(),
			SubjectID:    sub.ID,
			ResourceType: "credential",
			ResourceID:   outcome.Credential.ID,
			Outcome:      store.OutcomeSuccess,
		})
	}
	if len(signals) == 0 {
		signals = nil
	}

	token, claims, err := s.deps.Assertion.Issue(sub.ID, tenantID,
		caller.ActorID(), factors, outcome.Credential.CredentialID)
	if err != nil {
		return Internal(fmt.Errorf("issue assertion: %w", err))
	}

	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventAssertionCompleted,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "credential",
		ResourceID:   outcome.Credential.ID,
		Outcome:      store.OutcomeSuccess,
		Detail: map[string]any{
			"user_verified":  outcome.UserVerified,
			"sign_count":     outcome.NewSignCount,
			"previous_count": outcome.PreviousSignCount,
			"assertion_jti":  claims.ID,
		},
	})

	WriteJSON(w, r, http.StatusOK, assertionResponse{
		SubjectID: sub.ID,
		Assertion: token,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		Factors:   factors,
		Signals:   signals,
	})
	return nil
}

// reportCloneWarning records a signature counter that failed to advance.
//
// The assertion is not refused. The specification names a stalled counter as
// the signal for two copies of a credential private key in use, but many
// authenticators legitimately report a constant zero, and a platform
// authenticator synchronised across devices does the same. Refusing on this
// signal would lock out a large share of ordinary users.
func (s *Server) reportCloneWarning(r *http.Request, tenantID string, sub *store.Subject, outcome *wa.AssertionOutcome) {
	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventSignCountRegression,
		ActorType:    store.ActorSystem,
		SubjectID:    sub.ID,
		ResourceType: "credential",
		ResourceID:   outcome.Credential.ID,
		Outcome:      store.OutcomeFailure,
		Detail: map[string]any{
			"stored":    outcome.PreviousSignCount,
			"presented": outcome.NewSignCount,
		},
	})

	if s.deps.Alerts == nil {
		return
	}
	if _, err := s.deps.Alerts.SignCountRegression(r.Context(), tenantID, sub.ID,
		outcome.Credential.ID, outcome.PreviousSignCount, outcome.NewSignCount); err != nil {
		s.deps.Logger.WarnContext(r.Context(), "clone warning alert not raised")
	}
}

// ceremonyError maps a ceremony failure onto a response and audits it.
//
// Every ceremony failure returns the same body. The specific reason goes to the
// audit log, where an operator can read it, and not to the caller, who would
// otherwise be able to tell an expired challenge from a wrong signature from an
// unknown credential and probe the configuration accordingly.
func (s *Server) ceremonyError(r *http.Request, tenantID, subjectID string, caller *Caller, eventType string, err error) error {
	s.audited(r, audit.Event{
		TenantID:  tenantID,
		EventType: eventType,
		ActorType: caller.ActorType(),
		ActorID:   caller.ActorID(),
		SubjectID: subjectID,
		Outcome:   store.OutcomeFailure,
		Detail:    map[string]any{"reason": err.Error()},
	})

	switch {
	case errors.Is(err, wa.ErrTooManyCredentials):
		return Conflict("the subject has reached the credential limit", err)
	case errors.Is(err, wa.ErrCredentialExists):
		return Conflict("this authenticator is already registered", err)
	case errors.Is(err, wa.ErrAuthenticatorModel):
		// This one is disclosed, because a user holding an unsupported key
		// needs to be told to use a different one, and the policy is
		// configuration the operator publishes anyway.
		return &APIError{
			Status: http.StatusForbidden, Type: TypeForbidden,
			Title:    "this authenticator model is not permitted",
			Internal: err,
		}
	default:
		// This includes a subject with no registered authenticator. Answering
		// that case distinctly would tell a caller which of its users have
		// enrolled, through the one route that is supposed to say nothing but
		// yes or no. An application that needs to know what to offer reads
		// GET /v1/subjects/{subject_ref}, which exists for that purpose and is
		// an explicit, scoped, audited question rather than a side channel.
		return CeremonyFailed(err)
	}
}

// refErrorToAPI maps a subject reference validation failure.
func refErrorToAPI(err error) error {
	switch {
	case err == nil:
		return nil
	default:
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return apiErr
		}
		msg := err.Error()
		if strings.Contains(msg, "reference") {
			return BadRequest(msg, err)
		}
		return Internal(err)
	}
}

// totpEnrolResponse is returned by the enrolment route.
//
// The secret is disclosed exactly once, here, because the user has to transfer
// it into an authenticator application. Every later route reports only whether
// enrolment is confirmed.
type totpEnrolResponse struct {
	SecretID string `json:"secret_id"`

	// Secret is the base32 seed, for a user typing it in by hand.
	Secret string `json:"secret"`

	// ProvisioningURI is the otpauth:// form, for a QR code.
	ProvisioningURI string `json:"provisioning_uri"`

	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period_seconds"`

	// ExpiresAt is when an unconfirmed enrolment stops being usable.
	ExpiresAt time.Time `json:"expires_at"`
}

// handleTOTPEnrol issues a new TOTP secret.
//
// The secret is not usable for authentication until the user proves they can
// generate a code from it, which is what the confirm route is for. Treating an
// unconfirmed secret as live would let a failed enrolment weaken the account:
// the user would believe they had no second factor while one existed that they
// could not produce codes for.
func (s *Server) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}
	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	cfg := s.deps.Config.TOTP

	secret, err := totp.GenerateSecret(cfg.SecretBytes)
	if err != nil {
		return Internal(err)
	}
	defer zeroize.Bytes(secret)

	sealed, err := s.deps.Sealer.Seal(secret)
	if err != nil {
		return Internal(fmt.Errorf("seal totp secret: %w", err))
	}

	params := totp.Params{
		Algorithm: totp.Algorithm(cfg.Algorithm),
		Digits:    cfg.Digits,
		Period:    cfg.Period.Duration,
		Skew:      cfg.Skew,
	}

	now := s.now().UTC()
	rec := &store.TOTPSecret{
		ID:            uuid.NewString(),
		TenantID:      tenantID,
		SubjectID:     sub.ID,
		SecretSealed:  sealed,
		Algorithm:     cfg.Algorithm,
		Digits:        cfg.Digits,
		PeriodSeconds: int(cfg.Period.Duration.Seconds()),
		CreatedAt:     now,
	}
	if err := s.deps.Store.CreateTOTPSecret(r.Context(), rec); err != nil {
		return Internal(err)
	}

	// The account label is the internal subject identifier, not the reference
	// the application supplied. The provisioning URI ends up as a QR code and
	// in the user's authenticator application, so putting an email address in
	// it would publish the reference outside this service.
	uri, err := totp.ProvisioningURI(cfg.Issuer, sub.ID, secret, params)
	if err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID:     tenantID,
		EventType:    audit.EventTOTPEnrolled,
		ActorType:    caller.ActorType(),
		ActorID:      caller.ActorID(),
		SubjectID:    sub.ID,
		ResourceType: "totp_secret",
		ResourceID:   rec.ID,
		Outcome:      store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusCreated, totpEnrolResponse{
		SecretID:        rec.ID,
		Secret:          base32Secret(secret),
		ProvisioningURI: uri,
		Algorithm:       cfg.Algorithm,
		Digits:          cfg.Digits,
		Period:          rec.PeriodSeconds,
		ExpiresAt:       now.Add(cfg.EnrolmentTTL.Duration),
	})
	return nil
}

// totpCodeRequest is the body of the confirm and verify routes.
type totpCodeRequest struct {
	Code string `json:"code"`
}

// handleTOTPConfirm completes enrolment by checking one code.
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req totpCodeRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	pending, err := s.deps.Store.GetPendingTOTPSecret(r.Context(), tenantID, sub.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Conflict("there is no enrolment awaiting confirmation", err)
		}
		return Internal(err)
	}

	// An enrolment left unconfirmed past its window is refused rather than
	// accepted late, so a secret shown to a user long ago cannot be activated
	// by someone who later obtained it.
	if s.now().UTC().Sub(pending.CreatedAt) > s.deps.Config.TOTP.EnrolmentTTL.Duration {
		if err := s.deps.Store.RevokeTOTPSecret(r.Context(), tenantID, pending.ID, s.now().UTC()); err != nil {
			s.deps.Logger.WarnContext(r.Context(), "expired totp enrolment not revoked")
		}
		return Conflict("the enrolment has expired, start again", nil)
	}

	step, ok, err := s.verifyTOTP(r, tenantID, pending, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventTOTPRejected,
			ActorType: caller.ActorType(), ActorID: caller.ActorID(),
			SubjectID: sub.ID, ResourceType: "totp_secret", ResourceID: pending.ID,
			Outcome: store.OutcomeFailure,
		})
		return CeremonyFailed(errors.New("totp code did not verify"))
	}
	_ = step

	if err := s.deps.Store.ConfirmTOTPSecret(r.Context(), tenantID, pending.ID, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Conflict("the enrolment is no longer awaiting confirmation", err)
		}
		return Internal(err)
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTOTPConfirmed,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "totp_secret", ResourceID: pending.ID,
		Outcome: store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"secret_id": pending.ID,
		"confirmed": true,
	})
	return nil
}

// handleTOTPVerify authenticates a subject with a TOTP code.
func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req totpCodeRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	secret, err := s.deps.Store.GetActiveTOTPSecret(r.Context(), tenantID, sub.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Indistinguishable from a wrong code, so that this route cannot
			// be used to discover which subjects have TOTP enrolled.
			s.recordAttempt(r, tenantID, sub.ID, dims, true)
			return CeremonyFailed(errors.New("subject has no confirmed totp secret"))
		}
		return Internal(err)
	}

	_, ok, err := s.verifyTOTP(r, tenantID, secret, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventTOTPRejected,
			ActorType: caller.ActorType(), ActorID: caller.ActorID(),
			SubjectID: sub.ID, ResourceType: "totp_secret", ResourceID: secret.ID,
			Outcome: store.OutcomeFailure,
		})
		return CeremonyFailed(errors.New("totp code did not verify"))
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)

	factors := []assertion.Factor{assertion.FactorTOTP}
	tokenStr, claims, err := s.deps.Assertion.Issue(sub.ID, tenantID,
		caller.ActorID(), factors, nil)
	if err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTOTPVerified,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "totp_secret", ResourceID: secret.ID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"assertion_jti": claims.ID},
	})

	WriteJSON(w, r, http.StatusOK, assertionResponse{
		SubjectID: sub.ID,
		Assertion: tokenStr,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		Factors:   factors,
	})
	return nil
}

// verifyTOTP unseals the secret, checks the code and consumes the timestep.
//
// The compare-and-swap on the stored timestep is what makes a one-time password
// actually single use. A code stays valid for a whole period, so without it two
// requests presenting the same code inside that window would both read the old
// counter and both accept.
func (s *Server) verifyTOTP(r *http.Request, tenantID string, rec *store.TOTPSecret, code string) (int64, bool, error) {
	secret, err := s.deps.Sealer.Unseal(rec.SecretSealed)
	if err != nil {
		return 0, false, Internal(fmt.Errorf("unseal totp secret: %w", err))
	}
	defer zeroize.Bytes(secret)

	params := totp.Params{
		Algorithm: totp.Algorithm(rec.Algorithm),
		Digits:    rec.Digits,
		Period:    time.Duration(rec.PeriodSeconds) * time.Second,
		Skew:      s.deps.Config.TOTP.Skew,
	}

	step, ok := totp.Verify(secret, params, code, s.now().UTC(), rec.LastTimestep)
	if !ok {
		return 0, false, nil
	}

	result, err := s.deps.Store.ConsumeTOTPStep(r.Context(), tenantID, rec.ID,
		rec.LastTimestep, step)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, false, nil
		}
		return 0, false, Internal(err)
	}
	if !result.Accepted {
		// The code verified but the step was already spent, or a concurrent
		// request took it first. Either way this attempt must not succeed.
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventTOTPReplayed,
			ActorType: store.ActorSystem, SubjectID: rec.SubjectID,
			ResourceType: "totp_secret", ResourceID: rec.ID,
			Outcome: store.OutcomeDenied,
			Detail: map[string]any{
				"presented_step": step,
				"stored_step":    result.PreviousStep,
			},
		})
		return 0, false, nil
	}
	return step, true, nil
}

// recoveryIssueResponse carries a freshly issued batch.
//
// The codes appear here and nowhere else, ever. They are hashed before storage,
// so there is no operation that can show them again.
type recoveryIssueResponse struct {
	BatchID string   `json:"batch_id"`
	Codes   []string `json:"codes"`
	Count   int      `json:"count"`

	// Warning is returned alongside the codes because a caller that does not
	// present them to the user immediately has lost them.
	Warning string `json:"warning"`
}

// handleRecoveryIssue issues a batch of single-use recovery codes.
//
// Issuing retires every unused code from the previous batch in the same
// transaction. Leaving old codes live would put codes in circulation that the
// user believes are dead.
func (s *Server) handleRecoveryIssue(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}
	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	count := s.deps.Config.Recovery.CodeCount
	codes, err := recovery.Generate(count)
	if err != nil {
		return Internal(err)
	}

	batchID := uuid.NewString()
	now := s.now().UTC()

	records := make([]*store.RecoveryCode, 0, len(codes))
	display := make([]string, 0, len(codes))
	for _, c := range codes {
		records = append(records, &store.RecoveryCode{
			ID:           uuid.NewString(),
			TenantID:     tenantID,
			SubjectID:    sub.ID,
			BatchID:      batchID,
			Selector:     c.Selector,
			VerifierHash: c.Hash,
			CreatedAt:    now,
		})
		display = append(display, c.Display)
	}

	if err := s.deps.Store.ReplaceRecoveryCodes(r.Context(), tenantID, sub.ID, batchID, records); err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventRecoveryIssued,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "recovery_batch", ResourceID: batchID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"count": len(display)},
	})

	WriteJSON(w, r, http.StatusCreated, recoveryIssueResponse{
		BatchID: batchID,
		Codes:   display,
		Count:   len(display),
		Warning: "these codes are shown once and cannot be retrieved again; any " +
			"unused codes from a previous batch have been retired",
	})
	return nil
}

// recoveryConsumeRequest is the body of the consume route.
type recoveryConsumeRequest struct {
	Code string `json:"code"`
}

// handleRecoveryConsume authenticates a subject with a recovery code.
func (s *Server) handleRecoveryConsume(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}
	ref, err := s.subjectRef(r)
	if err != nil {
		return err
	}

	var req recoveryConsumeRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	dims := s.clientThrottleDims(r, caller, sub.ID)
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	rejected := func(reason string) error {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventRecoveryRejected,
			ActorType: caller.ActorType(), ActorID: caller.ActorID(),
			SubjectID: sub.ID, Outcome: store.OutcomeFailure,
			Detail: map[string]any{"reason": reason},
		})
		return CeremonyFailed(errors.New(reason))
	}

	selector, verifier, err := recovery.Split(req.Code)
	if err != nil {
		return rejected("code is malformed")
	}
	defer zeroize.Bytes(verifier)

	rec, err := s.deps.Store.GetRecoveryCodeBySelector(r.Context(), tenantID, selector)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return rejected("selector is unknown")
		}
		return Internal(err)
	}

	// A code issued to one subject must not authenticate another, even though
	// the selector is globally unique within the tenant.
	if rec.SubjectID != sub.ID {
		return rejected("code belongs to a different subject")
	}
	if rec.ConsumedAt != nil {
		return rejected("code was already used")
	}

	ok, err := recovery.Verify(verifier, rec.VerifierHash)
	if err != nil {
		// A malformed stored hash is an operational fault, not a failed
		// attempt, and must not be recorded as one.
		return Internal(err)
	}
	if !ok {
		return rejected("verifier did not match")
	}

	if err := s.deps.Store.ConsumeRecoveryCode(r.Context(), tenantID, rec.ID, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrStaleWrite) {
			// Another request consumed it first. Single use is enforced by the
			// store's conditional update, not by the check above.
			return rejected("code was consumed concurrently")
		}
		return Internal(err)
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)

	remaining, err := s.deps.Store.CountUnusedRecoveryCodes(r.Context(), tenantID, sub.ID)
	if err != nil {
		return Internal(err)
	}
	s.warnOnRecoveryDepletion(r, tenantID, sub.ID, remaining)

	factors := []assertion.Factor{assertion.FactorRecoveryCode}
	tokenStr, claims, err := s.deps.Assertion.Issue(sub.ID, tenantID,
		caller.ActorID(), factors, nil)
	if err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventRecoveryConsumed,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "recovery_code", ResourceID: rec.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"remaining":     remaining,
			"assertion_jti": claims.ID,
		},
	})

	WriteJSON(w, r, http.StatusOK, struct {
		assertionResponse
		Remaining int `json:"recovery_codes_remaining"`
	}{
		assertionResponse: assertionResponse{
			SubjectID: sub.ID,
			Assertion: tokenStr,
			ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
			Factors:   factors,
		},
		Remaining: remaining,
	})
	return nil
}

// warnOnRecoveryDepletion alerts when a subject is running out of codes.
//
// A subject with no codes left has no way back in if they lose their
// authenticator, so this is raised before that happens rather than after.
func (s *Server) warnOnRecoveryDepletion(r *http.Request, tenantID, subjectID string, remaining int) {
	if s.deps.Alerts == nil {
		return
	}
	watermark := s.deps.Config.Recovery.LowWatermark

	var err error
	switch {
	case remaining == 0:
		_, err = s.deps.Alerts.RecoveryExhausted(r.Context(), tenantID, subjectID)
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventRecoveryExhausted,
			ActorType: store.ActorSystem, SubjectID: subjectID,
			Outcome: store.OutcomeFailure,
		})
	case remaining <= watermark:
		_, err = s.deps.Alerts.RecoveryLow(r.Context(), tenantID, subjectID, remaining, watermark)
	default:
		return
	}
	if err != nil {
		s.deps.Logger.WarnContext(r.Context(), "recovery depletion alert not raised")
	}
}

// handleLiveness answers the unauthenticated probe.
//
// It reports liveness and nothing else. The version, the keyring state, whether
// rotation is overdue and the certificate expiry all moved behind
// authentication: handed to an unauthenticated caller, that set is a list of
// the software to look up advisories for and a statement of which maintenance
// has been neglected. See docs/adr/0008.
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) error {
	report := s.deps.Health.Liveness(r.Context())

	status := http.StatusOK
	if report.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	WriteJSON(w, r, status, report)
	return nil
}

// handleHealthDetail answers the authenticated report.
func (s *Server) handleHealthDetail(w http.ResponseWriter, r *http.Request) error {
	if _, err := requireCaller(r.Context()); err != nil {
		return err
	}
	WriteJSON(w, r, http.StatusOK, s.deps.Health.Report(r.Context()))
	return nil
}

// handleJWKS publishes the public key that verifies assertions.
//
// It is unauthenticated because the contents are public keys, and because an
// integrating application has to be able to fetch it in order to verify an
// assertion offline. That is the whole point of returning a detached signature
// rather than a bare status code.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) error {
	doc, err := s.deps.Assertion.JWKS()
	if err != nil {
		return Internal(err)
	}

	// A short cache is safe and useful: the key changes only on rotation, and
	// a verifier that re-fetches on every assertion would make this endpoint
	// the busiest route in the service.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(doc); err != nil {
		s.deps.Logger.WarnContext(r.Context(), "jwks response not written")
	}
	return nil
}

// base32Secret renders a TOTP seed for a user typing it by hand.
//
// The padding is stripped because several widely used authenticator
// applications refuse a padded secret. This matches what ProvisioningURI does,
// so the seed a user types matches the one a QR code carries.
func base32Secret(secret []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
}
