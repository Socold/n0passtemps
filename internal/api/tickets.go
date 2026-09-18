package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// Enrolment tickets: a single-use, short-lived secret that permits exactly one
// WebAuthn registration for one subject, and nothing else.
//
// # Why the ticket travels in the body and not in the path
//
// The routes that redeem a ticket are POST /v1/enrolment/register and
// POST /v1/enrolment/register/complete, and the secret arrives as a `ticket`
// field in the JSON body. A path segment would have been shorter to write and
// worse to operate.
//
// A URL path is the part of a request that leaks. This service logs the route
// pattern rather than the concrete path, but it is not the only thing in the
// chain: a reverse proxy writes the full path to its access log by default, so
// does every load balancer and every APM agent, and those logs are rotated,
// shipped and read by people who have no business holding an enrolment
// credential. The path also reaches a Referer header if the value is ever put in
// front of a browser, and browser history if a user is ever handed a link.
// Nothing equivalent happens to a body: it is not logged by default anywhere in
// a normal deployment, it is not indexed, and it does not survive in a header.
//
// The same reasoning already settled the same question once. A recovery code is
// presented in the body of POST /v1/recovery/{subject_ref}/consume, not in its
// path, and a ticket is the same kind of secret with the same lifetime problem.
// Two conventions for two secrets of one shape would only invite the wrong one
// to be copied.
//
// The routes are therefore named for what they do rather than for a path
// parameter they do not have. `subject_ref` is absent as well, deliberately: the
// ticket already names its subject, and accepting a second, caller-supplied
// answer to the same question would create a mismatch to resolve and a way to
// probe which references exist.
//
// # Where issuing lives
//
// Issuing is two operations with one mechanism, so it has two routes.
//
// POST /admin/v1/subjects/{subject_id}/enrolment-ticket is the operator case: a
// user has lost every authenticator and holds no recovery code, and somebody has
// to let them back in. It is guarded by enrolment_ticket.issue, which
// admin_operator and admin_full hold, and it takes the internal subject
// identifier because that is what an operator has in front of them in the
// administration interface.
//
// POST /v1/subjects/{subject_ref}/enrolment-ticket is the application case:
// onboarding a user who has no authenticator yet. It is on the public surface
// under the tickets scope and takes the application's own reference, like every
// other /v1 route.
//
// Redemption is only ever the application's business, because only the
// application is in front of the user's browser, so there is no administrative
// counterpart to it.
type ticketIssueRequest struct {
	// Reason is free text for the audit trail. An operator issuing a ticket
	// should say why; an application onboarding a user has nothing to add.
	Reason string `json:"reason,omitempty"`

	// RequireExistingFactor overrides tickets.require_existing_factor_default
	// for this request.
	//
	// It is a pointer so that absent and false are distinguishable. With the
	// guard on, issuing is refused for a subject who already holds an active
	// credential or a confirmed TOTP secret: that subject has a way in, and a
	// ticket issued anyway is an account-takeover primitive for whoever
	// controls the delivery channel. Sending false is the caller stating that
	// the existing factor is no longer usable, which is audited and raises an
	// alert.
	RequireExistingFactor *bool `json:"require_existing_factor,omitempty"`
}

// ticketIssueResponse carries a freshly issued ticket.
//
// The ticket appears here and nowhere else, ever. Only its selector and an
// Argon2id hash of its verifier are stored, so there is no operation that can
// show it again.
type ticketIssueResponse struct {
	TicketID  string `json:"ticket_id"`
	SubjectID string `json:"subject_id"`

	// Ticket is the secret, in the same grouped Crockford form a recovery code
	// takes.
	Ticket string `json:"ticket"`

	// ExpiresAt is when the ticket stops being redeemable. It is short by
	// design: the lifetime is the whole window in which an intercepted ticket
	// can be used.
	ExpiresAt time.Time `json:"expires_at"`

	// Warning is returned alongside the ticket because a caller that does not
	// deliver it immediately has lost it, and because delivery is the caller's
	// risk rather than this service's.
	Warning string `json:"warning"`
}

const ticketWarning = "this ticket is shown once and cannot be retrieved again; it " +
	"permits one WebAuthn registration and never produces a signed assertion; " +
	"deliver it over a channel you trust, because whoever holds it can enrol an " +
	"authenticator until it expires; any live ticket the subject already had has " +
	"been revoked"

// handleIssueEnrolmentTicket issues a ticket from the public surface.
//
// This is the onboarding case: an application enrolling a user who holds no
// authenticator yet. It takes the application's own subject reference, and the
// subject must already exist, for the same reason handleRegisterBegin insists on
// it: creating one here implicitly would let a caller populate the database with
// subjects by minting tickets it never delivers.
func (s *Server) handleIssueEnrolmentTicket(w http.ResponseWriter, r *http.Request) error {
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

	var req ticketIssueRequest
	if r.ContentLength > 0 {
		if err = decodeJSON(r, &req); err != nil {
			return err
		}
	}

	sub, err := s.resolveSubject(r, tenantID, ref)
	if err != nil {
		return err
	}

	resp, err := s.issueTicket(r, caller, tenantID, sub, req)
	if err != nil {
		return err
	}
	WriteJSON(w, r, http.StatusCreated, resp)
	return nil
}

// handleAdminIssueEnrolmentTicket issues a ticket from the administrative
// surface.
//
// This is the recovery case: a user has lost every authenticator and holds no
// recovery code, so an operator hands them one way back in. See
// docs/ADMIN-GUIDE.md for the procedure, including what to confirm about the
// person on the other end of the call before running it.
func (s *Server) handleAdminIssueEnrolmentTicket(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	var req ticketIssueRequest
	if r.ContentLength > 0 {
		if err = decodeJSON(r, &req); err != nil {
			return err
		}
	}

	sub, err := s.deps.Store.GetSubject(r.Context(), tenantID, subjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	// A locked subject or one pending erasure is refused here rather than at
	// redemption. Minting a ticket that cannot be redeemed would leave an
	// operator believing they had helped, and would put a live secret into a
	// delivery channel for no purpose.
	if !sub.Active() {
		return Conflict("the subject cannot authenticate, so a ticket would not be redeemable", nil)
	}

	resp, err := s.issueTicket(r, caller, tenantID, sub, req)
	if err != nil {
		return err
	}
	WriteJSON(w, r, http.StatusCreated, resp)
	return nil
}

// issueTicket applies the policy and writes the ticket.
//
// It is shared by both issuing routes, so the factor gate, the audit entry and
// the alert cannot differ between them. A route-specific copy of this logic is
// how the administrative surface would quietly end up with a weaker rule than
// the public one.
func (s *Server) issueTicket(r *http.Request, caller *Caller, tenantID string, sub *store.Subject,
	req ticketIssueRequest) (*ticketIssueResponse, error) {
	ctx := r.Context()

	credentials, totpConfirmed, err := s.subjectFactors(ctx, tenantID, sub.ID)
	if err != nil {
		return nil, err
	}
	hasFactor := credentials > 0 || totpConfirmed

	guard := s.deps.Config.Tickets.RequireExistingFactorDefault
	if req.RequireExistingFactor != nil {
		guard = *req.RequireExistingFactor
	}

	if hasFactor && guard {
		// Refused, and audited as a refusal. A ticket is a way in for someone
		// with no factor; issuing one for an account that has factors turns it
		// into an account-takeover primitive for whoever controls delivery. The
		// caller is told what to send to proceed, because the override is a
		// legitimate operator decision and hiding it would only produce support
		// tickets.
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventTicketRejected,
			ActorType: caller.ActorType(), ActorID: caller.ActorID(),
			SubjectID: sub.ID, ResourceType: "enrolment_ticket",
			Outcome: store.OutcomeDenied,
			Detail: map[string]any{
				"reason":             "subject already holds a factor",
				"active_credentials": credentials,
				"totp_confirmed":     totpConfirmed,
			},
		})
		return nil, Conflict("the subject already holds an authenticator or a confirmed "+
			"TOTP secret; send require_existing_factor=false to issue a ticket anyway", nil)
	}

	// recovery.Generate is reused rather than reimplemented. A ticket needs
	// exactly what a recovery code needs: a selector to find the row in one
	// indexed probe, an Argon2id hash of a verifier that is never stored in
	// clear, and the Crockford alphabet so a user can read it down a telephone
	// line without transcribing O for 0. The two secrets differ in what they
	// authorise and in their lifetime, not in their construction, so a second
	// implementation of the construction would only be a second place for it to
	// go wrong.
	codes, err := recovery.Generate(1)
	if err != nil {
		return nil, Internal(err)
	}
	code := codes[0]

	now := s.now().UTC()
	ticket := &store.EnrolmentTicket{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		SubjectID:    sub.ID,
		Selector:     code.Selector,
		VerifierHash: code.Hash,
		IssuedBy:     caller.ActorID(),
		Reason:       strings.TrimSpace(req.Reason),
		CreatedAt:    now,
		ExpiresAt:    now.Add(s.deps.Config.Tickets.TTL.Duration),
	}

	// The store revokes any live ticket for this subject in the same
	// transaction. Two live tickets double the window in which an intercepted
	// one can be redeemed, and reissuing after a failed delivery is exactly
	// when the first one is most likely to be in the wrong hands.
	if err := s.deps.Store.ReplaceEnrolmentTicket(ctx, tenantID, sub.ID, ticket); err != nil {
		return nil, Internal(err)
	}

	override := hasFactor && !guard
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTicketIssued,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "enrolment_ticket", ResourceID: ticket.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"expires_at":               ticket.ExpiresAt,
			"reason":                   ticket.Reason,
			"active_credentials":       credentials,
			"totp_confirmed":           totpConfirmed,
			"existing_factor_override": override,
		},
	})

	if override {
		s.alertTicketOverride(r, tenantID, sub.ID, ticket, credentials, totpConfirmed)
	}

	return &ticketIssueResponse{
		TicketID:  ticket.ID,
		SubjectID: sub.ID,
		Ticket:    code.Display,
		ExpiresAt: ticket.ExpiresAt,
		Warning:   ticketWarning,
	}, nil
}

// alertTicketOverride raises the alert for a ticket issued over an existing
// factor.
//
// It is a side effect of a decision already taken, so a failure to raise it is
// logged and the issuance stands. The audit entry carries the same facts, which
// is what keeps the record complete when the alert table refuses a write.
func (s *Server) alertTicketOverride(r *http.Request, tenantID, subjectID string, ticket *store.EnrolmentTicket,
	credentials int, totpConfirmed bool) {
	if s.deps.Alerts == nil {
		return
	}
	if _, err := s.deps.Alerts.TicketFactorOverride(r.Context(), tenantID, subjectID,
		ticket.ID, ticket.IssuedBy, credentials, totpConfirmed); err != nil {
		s.deps.Logger.WarnContext(r.Context(), "enrolment ticket override alert not raised")
	}
}

// subjectFactors reports what the subject can currently authenticate with.
//
// An unconfirmed TOTP secret does not count. The user has been shown it but has
// not proved they can produce codes from it, so treating it as a factor would
// refuse a ticket to somebody who has no way in at all, which is the one person
// the feature exists for.
func (s *Server) subjectFactors(ctx context.Context, tenantID, subjectID string) (credentials int, totpConfirmed bool,
	err error) {
	creds, err := s.deps.Store.ListCredentials(ctx, tenantID, subjectID, false)
	if err != nil {
		return 0, false, Internal(err)
	}
	if _, err := s.deps.Store.GetActiveTOTPSecret(ctx, tenantID, subjectID); err == nil {
		totpConfirmed = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, false, Internal(err)
	}
	return len(creds), totpConfirmed, nil
}

// handleAdminRevokeEnrolmentTicket withdraws a ticket that has not been
// redeemed.
//
// It exists because the failure a delivery channel makes likely is delivery to
// the wrong place, and the only useful answer to that is to kill the ticket
// before its expiry. Issuing a replacement also revokes the live one, so an
// operator has two ways out of a mis-delivery; this is the one that does not put
// a second secret into circulation to neutralise the first.
//
// It shares enrolment_ticket.issue rather than holding a permission of its own.
// Whoever may put a ticket into circulation must be able to take it out, and an
// operator who had to find a full administrator to withdraw their own mistake
// would in practice wait for the expiry instead.
//
// The path is /admin/v1/enrolment-tickets/{ticket_id}/revoke, matching the shape
// of the other revocation routes, and it names the ticket alone. The audit entry
// therefore carries no subject: the store addresses a revocation by ticket
// identifier, and reading the row first only to decorate the entry would add a
// query and a race for nothing. The issuance entry for the same resource
// identifier names the subject, which is where the two correlate.
func (s *Server) handleAdminRevokeEnrolmentTicket(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	ticketID, err := pathID(r, "ticket_id")
	if err != nil {
		return err
	}

	err = s.deps.Store.RevokeEnrolmentTicket(r.Context(), tenantID, ticketID, s.now().UTC())
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return NotFound(err)
	case errors.Is(err, store.ErrStaleWrite):
		// Already redeemed, already revoked, and there is nothing left to
		// withdraw. Saying so is safe here: the caller is an authenticated
		// administrator who could read the row anyway.
		return Conflict("the ticket has already been redeemed or revoked", err)
	default:
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTicketRevoked,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "enrolment_ticket", ResourceID: ticketID,
		Outcome: store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"ticket_id": ticketID,
		"revoked":   true,
	})
	return nil
}

// ticketRegisterBeginRequest is the body of POST /v1/enrolment/register.
type ticketRegisterBeginRequest struct {
	// Ticket is the secret, in the grouped or ungrouped Crockford form. It is
	// in the body rather than the path; see the file comment.
	Ticket string `json:"ticket"`

	// Label is shown by the authenticator while the user confirms, and is
	// stored so an operator can tell one of a subject's keys from another.
	Label string `json:"label,omitempty"`
}

// ticketRegisterCompleteRequest is the body of
// POST /v1/enrolment/register/complete.
type ticketRegisterCompleteRequest struct {
	Ticket      string `json:"ticket"`
	ChallengeID string `json:"challenge_id"`

	// Credential is the PublicKeyCredential the browser produced, forwarded
	// verbatim, exactly as on the ordinary completion route.
	Credential json.RawMessage `json:"credential"`
}

// handleTicketRegisterBegin starts the one registration a ticket permits.
//
// The ticket is not consumed here. Consumption records the credential the ticket
// produced, which does not exist until the ceremony completes, and burning the
// ticket on an abandoned ceremony would send the user back to the helpdesk
// because their browser refused a prompt. Single use is enforced at completion,
// by the store's compare-and-swap; what bounds this route instead is the rate
// limit, per source address and per ticket selector.
//
// The refusal is deliberately uniform. A ticket that never existed, one that
// expired, one already redeemed, one revoked, and one belonging to a subject who
// is locked or pending erasure all produce the same answer with no detail. The
// reason goes to the audit log. Anything more would turn the route into an
// oracle for which tickets exist and which accounts are in which state.
func (s *Server) handleTicketRegisterBegin(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}

	var req ticketRegisterBeginRequest
	if err = decodeJSON(r, &req); err != nil {
		return err
	}

	ticket, sub, dims, err := s.resolveTicket(r, caller, tenantID, req.Ticket)
	if err != nil {
		return err
	}

	result, err := s.deps.WebAuthn.BeginRegistration(r.Context(), sub, req.Label)
	if err != nil {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventRegistrationStarted, err)
	}

	// One entry for this step, in the registration family, with the ticket
	// named in the detail. A separate enrolment_ticket event here would make
	// the ticket look spent when it is not; enrolment_ticket.redeemed fires
	// exactly once, at the moment the ticket is actually consumed. Querying
	// webauthn.registration.started still finds this ceremony, which is what an
	// operator reviewing enrolments expects.
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventRegistrationStarted,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "challenge", ResourceID: result.ChallengeID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"via": "enrolment_ticket", "ticket_id": ticket.ID},
	})

	WriteJSON(w, r, http.StatusOK, result)
	return nil
}

// handleTicketRegisterComplete finishes the registration and spends the ticket.
//
// The response carries the credential and nothing else. There is deliberately no
// assertion: a ticket proves that whoever holds it was given it, not that the
// person in front of the browser is the subject, so signing an authentication on
// the strength of one would make an intercepted ticket a session rather than an
// enrolment. The application asks the user to authenticate with the key they
// have just enrolled, through the ordinary assertion routes, and gets a signed
// result from that.
func (s *Server) handleTicketRegisterComplete(w http.ResponseWriter, r *http.Request) error {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return err
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return err
	}

	var req ticketRegisterCompleteRequest
	if err = decodeJSON(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		return BadRequest("challenge_id is required", nil)
	}
	if _, err = uuid.Parse(req.ChallengeID); err != nil {
		return BadRequest("challenge_id is not a valid identifier", err)
	}
	if len(req.Credential) == 0 {
		return BadRequest("credential is required", nil)
	}

	ticket, sub, dims, err := s.resolveTicket(r, caller, tenantID, req.Ticket)
	if err != nil {
		return err
	}

	cred, err := s.deps.WebAuthn.CompleteRegistration(r.Context(), sub,
		req.ChallengeID, req.Credential, "")
	if err != nil {
		s.recordAttempt(r, tenantID, sub.ID, dims, true)
		return s.ceremonyError(r, tenantID, sub.ID, caller,
			audit.EventRegistrationRejected, err)
	}

	// The ticket is spent after the credential exists, because consumption
	// records which credential it produced and that identifier does not exist
	// before this point.
	//
	// The order leaves one case to handle honestly. If the compare-and-swap
	// loses, the ticket was spent, revoked or expired between the check in
	// resolveTicket and now, and this enrolment is therefore not authorised by
	// anything. The credential that was just created is revoked and the request
	// is refused. Leaving it in place would mean a ticket had produced two
	// credentials, which is exactly the property single use exists to deny.
	now := s.now().UTC()
	if err := s.deps.Store.ConsumeEnrolmentTicket(r.Context(), tenantID, ticket.ID, cred.ID, now); err != nil {
		if errors.Is(err, store.ErrStaleWrite) || errors.Is(err, store.ErrNotFound) {
			s.undoUnauthorisedEnrolment(r, tenantID, sub.ID, caller, ticket, cred)
			s.recordAttempt(r, tenantID, sub.ID, dims, true)
			return CeremonyFailed(errors.New("enrolment ticket was spent concurrently"))
		}
		return Internal(err)
	}

	s.recordAttempt(r, tenantID, sub.ID, dims, false)

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventRegistrationCompleted,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "credential", ResourceID: cred.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"via":              "enrolment_ticket",
			"ticket_id":        ticket.ID,
			"aaguid":           fmt.Sprintf("%x", cred.AAGUID),
			"attestation_type": string(cred.AttestationType),
			"user_verified":    cred.UserVerified,
			"backup_eligible":  cred.BackupEligible,
		},
	})
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTicketRedeemed,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "enrolment_ticket", ResourceID: ticket.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"credential_id": cred.ID,
			"issued_by":     ticket.IssuedBy,
		},
	})

	// The credential, and nothing else. No assertion; see the doc comment.
	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"credential": cred,
		"subject_id": sub.ID,
	})
	return nil
}

// undoUnauthorisedEnrolment revokes a credential created against a ticket that
// turned out to be spent.
//
// Both failures here are logged rather than returned. The caller is already
// being refused, and there is no better answer available: a revocation that
// cannot be written leaves a credential an operator has to remove by hand, which
// is why it is logged at error level and audited with the ticket named.
func (s *Server) undoUnauthorisedEnrolment(r *http.Request, tenantID, subjectID string, caller *Caller,
	ticket *store.EnrolmentTicket, cred *store.Credential) {
	ctx := r.Context()
	reason := "enrolment ticket was already spent"

	if err := s.deps.Store.RevokeCredential(ctx, tenantID, cred.ID, reason, s.now().UTC()); err != nil {
		s.deps.Logger.ErrorContext(ctx,
			"credential enrolled against a spent ticket could not be revoked",
			"credential_id", cred.ID, "ticket_id", ticket.ID)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventTicketRejected,
		ActorType: caller.ActorType(), ActorID: caller.ActorID(),
		SubjectID: subjectID, ResourceType: "enrolment_ticket", ResourceID: ticket.ID,
		Outcome: store.OutcomeDenied,
		Detail: map[string]any{
			"reason":             "ticket was consumed, revoked or expired concurrently",
			"credential_revoked": cred.ID,
		},
	})
}

// resolveTicket verifies a presented ticket and returns it with its subject.
//
// Every failure returns the same coarse refusal, records the attempt against the
// rate limiter and audits the reason. The order of work matters: the secret is
// split first, because that is free, then the rate limit is consulted, and only
// then is the Argon2id evaluation performed. Verifying before checking the limit
// would hand a locked-out attacker one hash evaluation per request out of the
// server's own CPU.
//
// The returned dimensions are handed back so the caller records the ceremony's
// own outcome against the same buckets. Without that, a ceremony that failed
// after the ticket verified would leave no trace in the limiter, and an attacker
// holding one valid ticket could hammer the completion route unbounded.
func (s *Server) resolveTicket(r *http.Request, caller *Caller, tenantID, presented string) (*store.EnrolmentTicket,
	*store.Subject, map[throttle.Dimension]string, error) {
	ctx := r.Context()

	selector, verifier, splitErr := recovery.Split(presented)
	if verifier != nil {
		defer zeroize.Bytes(verifier)
	}

	dims := make(map[throttle.Dimension]string, 2)
	if ip := SourceIPFrom(ctx); ip != "" {
		dims[throttle.DimIP] = ip
	}
	if selector != "" {
		// Bucketed on what the caller presented, not on the subject the ticket
		// resolves to, because a guessing campaign consists of selectors that
		// resolve to nothing at all.
		dims[throttle.DimEnrolmentTicket] = selector
	}

	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return nil, nil, dims, err
	}

	rejected := func(subjectID, reason string) error {
		s.recordAttempt(r, tenantID, subjectID, dims, true)
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventTicketRejected,
			ActorType: caller.ActorType(), ActorID: caller.ActorID(),
			SubjectID: subjectID, ResourceType: "enrolment_ticket",
			Outcome: store.OutcomeFailure,
			Detail:  map[string]any{"reason": reason},
		})
		return CeremonyFailed(errors.New(reason))
	}

	if splitErr != nil {
		return nil, nil, dims, rejected("", "ticket is malformed")
	}

	ticket, err := s.deps.Store.GetEnrolmentTicketBySelector(ctx, tenantID, selector)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, dims, rejected("", "selector is unknown")
		}
		return nil, nil, dims, Internal(err)
	}

	// The verifier is compared before the state is examined, so that a spent
	// ticket and a wrong guess at a live selector cost the same and answer the
	// same.
	ok, err := recovery.Verify(verifier, ticket.VerifierHash)
	if err != nil {
		// A malformed stored hash is an operational fault, not a failed
		// attempt, and must not be recorded as one.
		return nil, nil, dims, Internal(err)
	}
	if !ok {
		return nil, nil, dims, rejected("", "verifier did not match")
	}

	if !ticket.Redeemable(s.now().UTC()) {
		return nil, nil, dims, rejected(ticket.SubjectID,
			"ticket is expired, already redeemed or revoked")
	}

	sub, err := s.deps.Store.GetSubject(ctx, tenantID, ticket.SubjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A subject pending erasure is invisible to every getter, so this
			// is also the erasure case.
			return nil, nil, dims, rejected(ticket.SubjectID, "subject is not available")
		}
		return nil, nil, dims, Internal(err)
	}
	if !sub.Active() {
		return nil, nil, dims, rejected(sub.ID, "subject status is "+string(sub.Status))
	}

	return ticket, sub, dims, nil
}
