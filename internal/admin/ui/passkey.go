package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// The console's own passkeys.
//
// # Why these five routes answer JSON
//
// Every other form on this interface is a plain POST that renders a page.
// These cannot be: navigator.credentials runs in the browser between the two
// halves of a ceremony, so the page has to ask for the options, hand them to
// the authenticator and post the result. The request bodies are still ordinary
// form encodings, which is what lets the authenticated pair carry the same
// hidden request token every other form carries and be checked by the same
// checkCSRF. Only the responses are JSON, and only because the script has to
// read them.
//
// # Why the two sign-in routes carry no request token
//
// They cannot: a token is bound to a session, and the point of these is to
// establish one. They are rate limited per source address instead, through the
// same limiter and the same dimensions the pasted-token form uses, which is the
// control that makes repeated attempts expensive.
//
// A cross-site page cannot drive them either, and it is worth stating why,
// because the usual reasoning about forged form posts does not transfer. A
// forged form works because the attacker never needs to read the response. Here
// they do: the second call is refused without the challenge identifier the
// first returned, and the same-origin policy withholds that response body from a
// page on another origin. What remains is that such a page could cause the
// operator's authenticator to prompt. The prompt names this relying party and
// requires user verification, so an operator who did not just ask to sign in has
// something visible to refuse.

// passkeyLabelMax bounds the name an operator gives a key.
//
// It is rendered back to them on the dashboard and stored on the credential
// row. The bound is generous for a label and small enough that the field is not
// a way to put a paragraph into the database.
const passkeyLabelMax = 64

// signInData tells the sign-in screen whether to offer the passkey control.
//
// The control is rendered hidden and revealed by the script, so a browser with
// no WebAuthn support, or with the script blocked, never shows a button that
// would do nothing. PasskeyOffered is the server's half of the same question:
// with no relying party wired in there is nothing to reveal.
type signInData struct {
	PasskeyOffered bool
}

// passkeyView is the "your sign-in" section of the dashboard.
//
// It is a section rather than a screen. See the route registration in ui.go.
type passkeyView struct {
	Offered  bool
	Required bool
	Rows     []passkeyRow
	Active   int
}

type passkeyRow struct {
	ID                string
	Label             string
	AddedAt           time.Time
	LastUsedAt        *time.Time
	Withdrawn         bool
	WithdrawnAt       *time.Time
	MayHaveBeenCopied bool
}

// passkeysOffered reports whether the console can run a ceremony at all.
func (h *Handler) passkeysOffered() bool { return h.deps.WebAuthn != nil }

// writeJSON answers one of the ceremony routes.
//
// The body is built before anything is written, for the reason render buffers a
// page: a marshalling failure halfway through would otherwise leave a 200 and a
// truncated document, which the script would report as a browser fault.
func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: ceremony response not encoded",
			slog.Any("error", err))
		http.Error(w, `{"problem":"The service could not answer."}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

// jsonProblem is the only thing a refused ceremony route says.
//
// The sentence is the one the operator sees. It never names which check
// refused, for the reason the sign-in form never does.
type jsonProblem struct {
	Problem string `json:"problem"`
}

// jsonBegun carries the options a browser hands to navigator.credentials.
type jsonBegun struct {
	ChallengeID string    `json:"challenge_id"`
	Options     any       `json:"options"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// jsonDone tells the script where to go once a ceremony has finished.
//
// The target is chosen here and is always a literal, so the script never
// navigates to somewhere a response could be made to name.
type jsonDone struct {
	Redirect string `json:"redirect"`
}

// signInRefusal is the single sentence every refused console sign-in produces,
// whatever actually went wrong.
//
// An unknown credential, a withdrawn one, an administrative token that has
// expired and one that has been revoked are indistinguishable from outside, as
// they are on the subject routes. The audit entry carries which of them it was,
// because the operator reading the history is the defender.
const signInRefusal = "That passkey was not accepted."

// handlePasskeySignInBegin issues the options for a console sign-in.
//
// The rate limit is consulted before any work is done, so a caller that is
// already locked out gets none out of the service, and the request is then
// counted as an attempt even though it has not failed. Counting it is what
// bounds the volume of challenge rows one address can create; treating it as a
// failure would lock out an operator who merely reloaded the page.
func (h *Handler) handlePasskeySignInBegin(w http.ResponseWriter, r *http.Request) {
	ip := h.sourceIP(r)
	dims := h.signInDims(ip)

	if blocked, retryAfter := h.signInBlocked(r, dims); blocked {
		h.auditSignInFailure(w, r, ip, "the source address has made too many attempts")
		h.writeJSON(w, r, http.StatusTooManyRequests, jsonProblem{Problem: fmt.Sprintf(
			"Too many attempts from this network. Wait %d minutes and try again.",
			minutesAtLeastOne(retryAfter))})
		return
	}
	if !h.passkeysOffered() {
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This deployment does not offer passkey sign-in."})
		return
	}

	begun, err := h.deps.WebAuthn.BeginAdminAssertion(r.Context(), h.tenantID())
	if err != nil {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: passkey sign-in not started",
			slog.Any("error", err))
		h.writeJSON(w, r, http.StatusInternalServerError, jsonProblem{
			Problem: "The sign-in could not be started. Try again."})
		return
	}
	h.recordSignInAttempt(r, dims, false)

	h.writeJSON(w, r, http.StatusOK, jsonBegun{
		ChallengeID: begun.ChallengeID,
		Options:     begun.Options,
		ExpiresAt:   begun.ExpiresAt,
	})
}

// handlePasskeySignInComplete verifies an assertion and mints the session.
//
// The session is the one handleSignInSubmit mints, from the same store with the
// same two deadlines and the same cookie attributes. There is deliberately no
// second session mechanism: a passkey is another way to prove who you are, not
// another kind of being signed in.
func (h *Handler) handlePasskeySignInComplete(w http.ResponseWriter, r *http.Request) {
	now := h.now().UTC()
	ip := h.sourceIP(r)
	dims := h.signInDims(ip)

	if err := r.ParseForm(); err != nil {
		h.writeJSON(w, r, http.StatusBadRequest, jsonProblem{
			Problem: "The response could not be read. Try again."})
		return
	}
	if blocked, retryAfter := h.signInBlocked(r, dims); blocked {
		h.auditSignInFailure(w, r, ip, "the source address has made too many attempts")
		h.writeJSON(w, r, http.StatusTooManyRequests, jsonProblem{Problem: fmt.Sprintf(
			"Too many attempts from this network. Wait %d minutes and try again.",
			minutesAtLeastOne(retryAfter))})
		return
	}
	if !h.passkeysOffered() {
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This deployment does not offer passkey sign-in."})
		return
	}

	challengeID := strings.TrimSpace(r.PostFormValue("challenge_id"))
	credential := r.PostFormValue("credential")
	if challengeID == "" || credential == "" {
		h.recordSignInAttempt(r, dims, true)
		h.auditSignInFailure(w, r, ip, "the response was incomplete")
		h.writeJSON(w, r, http.StatusUnauthorized, jsonProblem{Problem: signInRefusal})
		return
	}

	// The tenant is a predicate of every lookup the ceremony makes rather than
	// a check afterwards, so a credential belonging to a token from another
	// deployment resolves to nothing rather than resolving and then being
	// rejected.
	result, err := h.deps.WebAuthn.CompleteAdminAssertion(r.Context(), h.tenantID(),
		challengeID, []byte(credential))
	if err != nil {
		h.recordSignInAttempt(r, dims, true)
		reason := err.Error()
		if errors.Is(err, webauthn.ErrChallengeNotFound) {
			reason = "the challenge is unknown, expired or already used"
		}
		h.auditSignInFailure(w, r, ip, reason)
		h.writeJSON(w, r, http.StatusUnauthorized, jsonProblem{Problem: signInRefusal})
		return
	}

	// A session the browser still holds ends here, before the new one exists.
	// Signing in again is what an operator does when they suspect the session
	// they have, and leaving the old one live in the store would keep whoever
	// captured its cookie signed in for the rest of the idle window.
	h.sessions.destroy(cookieValue(r))

	value, sess, err := h.sessions.mint(now, result.Token, h.idleTTL, h.absoluteTTL)
	if err != nil {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: session not created", slog.Any("error", err))
		h.writeJSON(w, r, http.StatusInternalServerError, jsonProblem{
			Problem: "The session could not be started. Try again."})
		return
	}

	// A successful attempt still counts towards the volume the address is
	// allowed, so a compromised key cannot be used without limit from one
	// address.
	h.recordSignInAttempt(r, dims, false)

	// Recording last use must not be able to fail the sign-in, for the reason
	// given in handleSignInSubmit.
	if err := h.deps.Store.TouchAdminToken(r.Context(), result.Token.ID, now); err != nil {
		h.deps.Logger.WarnContext(r.Context(), "adminui: token last-use timestamp not recorded",
			slog.Any("error", err))
	}

	// The clone and binding signals travel on the audit entry, where an
	// operator reading the history finds them beside the sign-in they belong
	// to. A counter that did not advance also raises the alert the public
	// surface raises for a subject's authenticator, because the entry says so
	// only to somebody already looking.
	h.audited(w, r, audit.Event{
		TenantID:     sess.TenantID,
		EventType:    audit.EventAdminAuthorised,
		ActorType:    store.ActorAdmin,
		ActorID:      sess.TokenID,
		ResourceType: "admin_credential",
		ResourceID:   result.Credential.ID,
		Outcome:      store.OutcomeSuccess,
		SourceIP:     ip,
		Detail: map[string]any{
			"role":            string(sess.Role),
			"surface":         "administration interface",
			"method":          "passkey",
			"user_verified":   result.Outcome.UserVerified,
			"clone_warning":   result.Outcome.CloneWarning,
			"binding_changed": result.Outcome.BindingChanged,
		},
	})

	h.alertCloneWarning(r, sess, result)

	h.setSessionCookie(w, value)
	h.writeJSON(w, r, http.StatusOK, jsonDone{Redirect: "/admin/"})
}

// alertCloneWarning raises the alert for a signature counter that did not
// advance.
//
// The assertion is not refused over it, here or on the public surface: many
// authenticators legitimately report a constant zero, so refusing would break
// those deployments and prove nothing about the rest. The alert is therefore
// the only thing that brings a possible copy of an administrator's passkey to
// anybody's attention while it is being used.
//
// The subject identifier is left empty on purpose. An administrative credential
// belongs to a token and to nobody in the subject table, and putting a token
// identifier in that column would file the alert under a person who does not
// exist.
func (h *Handler) alertCloneWarning(r *http.Request, sess *session, result *webauthn.AdminAssertionResult) {
	if h.deps.Alerts == nil || result.Outcome == nil || !result.Outcome.CloneWarning {
		return
	}
	if _, err := h.deps.Alerts.SignCountRegression(r.Context(), sess.TenantID, "", result.Credential.ID,
		result.Outcome.PreviousSignCount, result.Outcome.NewSignCount); err != nil {
		h.deps.Logger.WarnContext(r.Context(),
			"adminui: alert not raised for a passkey that may have been copied", slog.Any("error", err))
	}
}

// requireOwnToken resolves the administrative token the session was established
// with.
//
// Every passkey route below acts on the caller's own token and on nothing else.
// There is no route that names another administrator's token, for the reason
// internal/rbac offers no rotation of another administrator's credential: the
// ceremony produces something that signs in as that token, so enrolling one for
// somebody else is handing yourself their sign-in.
//
// The token is re-read here even though requireSession has just done so: these
// routes need the row itself, and a credential minted for a token that stopped
// being usable between the two reads would keep working after it.
func (h *Handler) requireOwnToken(w http.ResponseWriter, r *http.Request, sess *session) *store.AdminToken {
	tok, err := h.deps.Store.GetAdminTokenByID(r.Context(), h.tenantID(), sess.TokenID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.writeJSON(w, r, http.StatusForbidden, jsonProblem{
				Problem: "Your sign-in is no longer valid. Sign out and sign in again."})
			return nil
		}
		h.deps.Logger.ErrorContext(r.Context(), "adminui: read own administrative token",
			slog.Any("error", err))
		h.writeJSON(w, r, http.StatusInternalServerError, jsonProblem{
			Problem: "The service could not complete that. Try again."})
		return nil
	}
	if !tok.Usable(h.now().UTC()) {
		h.writeJSON(w, r, http.StatusForbidden, jsonProblem{
			Problem: "Your sign-in is no longer valid. Sign out and sign in again."})
		return nil
	}
	return tok
}

// handlePasskeyEnrolBegin issues the options for enrolling a passkey.
//
// Enrolment requires an existing authenticated administrator, and this is where
// that is enforced: there is no unauthenticated route that produces an
// administrative credential. It is not held for a second administrator either.
// A queue would weigh nothing, because the credential grants no authority its
// holder does not already have, and it would mean an administrator who has lost
// a key cannot enrol another until somebody else is awake. That is the argument
// docs/RBAC.md already makes for rotating your own token.
func (h *Handler) handlePasskeyEnrolBegin(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.checkCSRF(w, r, sess) {
		return
	}
	if !h.passkeysOffered() {
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This deployment does not offer passkey sign-in."})
		return
	}
	tok := h.requireOwnToken(w, r, sess)
	if tok == nil {
		return
	}

	begun, err := h.deps.WebAuthn.BeginAdminRegistration(r.Context(), tok)
	switch {
	case errors.Is(err, webauthn.ErrTooManyCredentials):
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This sign-in already has as many passkeys as it is allowed. " +
				"Withdraw one before adding another."})
		return
	case errors.Is(err, webauthn.ErrAdminTokenUnusable):
		h.writeJSON(w, r, http.StatusForbidden, jsonProblem{
			Problem: "Your sign-in is no longer valid. Sign out and sign in again."})
		return
	case err != nil:
		h.deps.Logger.ErrorContext(r.Context(), "adminui: passkey enrolment not started",
			slog.Any("error", err))
		h.writeJSON(w, r, http.StatusInternalServerError, jsonProblem{
			Problem: "The passkey could not be set up. Try again."})
		return
	}

	h.writeJSON(w, r, http.StatusOK, jsonBegun{
		ChallengeID: begun.ChallengeID,
		Options:     begun.Options,
		ExpiresAt:   begun.ExpiresAt,
	})
}

// handlePasskeyEnrolComplete stores a newly enrolled passkey.
func (h *Handler) handlePasskeyEnrolComplete(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.checkCSRF(w, r, sess) {
		return
	}
	if !h.passkeysOffered() {
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This deployment does not offer passkey sign-in."})
		return
	}
	tok := h.requireOwnToken(w, r, sess)
	if tok == nil {
		return
	}

	challengeID := strings.TrimSpace(r.PostFormValue("challenge_id"))
	credential := r.PostFormValue("credential")
	label := truncateLabel(strings.TrimSpace(r.PostFormValue("label")))
	if challengeID == "" || credential == "" {
		h.writeJSON(w, r, http.StatusBadRequest, jsonProblem{
			Problem: "The response from the security key could not be read. Try again."})
		return
	}

	rec, err := h.deps.WebAuthn.CompleteAdminRegistration(r.Context(), tok,
		challengeID, []byte(credential), label)
	switch {
	case errors.Is(err, webauthn.ErrCredentialExists):
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "That security key or passkey is already registered here."})
		return
	case errors.Is(err, webauthn.ErrAuthenticatorModel):
		h.writeJSON(w, r, http.StatusConflict, jsonProblem{
			Problem: "This deployment does not accept that model of security key."})
		return
	case err != nil:
		// The reason is logged and audited, never shown. A failed enrolment is
		// audited as a refused administrative action rather than as a refused
		// sign-in: the caller is an authenticated administrator, and filing it
		// under sign-in failures would put entries with a known actor into the
		// family an operator reads to find attempts with none.
		h.deps.Logger.WarnContext(r.Context(), "adminui: passkey enrolment refused",
			slog.Any("error", err))
		h.auditDenied(w, r, sess, "admin_credential", "", err.Error())
		h.writeJSON(w, r, http.StatusBadRequest, jsonProblem{
			Problem: "That passkey was not accepted. Try again."})
		return
	}

	h.audited(w, r, audit.Event{
		TenantID:     sess.TenantID,
		EventType:    audit.EventAdminCredentialEnrolled,
		ActorType:    store.ActorAdmin,
		ActorID:      sess.TokenID,
		ResourceType: "admin_credential",
		ResourceID:   rec.ID,
		Outcome:      store.OutcomeSuccess,
		Detail: map[string]any{
			"label":         rec.Label,
			"admin_token":   rec.AdminTokenID,
			"user_verified": rec.UserVerified,
			"surface":       "administration interface",
		},
	})

	h.writeJSON(w, r, http.StatusOK, jsonDone{Redirect: "/admin/?notice=passkey-added"})
}

// handlePasskeyWithdraw withdraws one of the caller's own passkeys.
//
// Withdrawal is final, as it is for a subject's authenticator and for the same
// reason: a key is withdrawn because it is believed to be in the wrong hands,
// and a window in which that can be undone is a window in which it can be put
// back. See docs/adr/0010.
//
// This is an ordinary form post rather than one of the ceremony routes, because
// no authenticator is involved, so it answers with a redirect like every other
// action on this interface.
func (h *Handler) handlePasskeyWithdraw(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.checkCSRF(w, r, sess) {
		return
	}
	id, ok := pathID(r, "credential_id")
	if !ok {
		h.renderMessage(w, r, sess, http.StatusNotFound, "That passkey does not exist",
			"The form named something this deployment does not hold.")
		return
	}

	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" {
		// A withdrawal with no stated reason is an entry in the history nobody
		// can act on later, which is why the subject form requires one too.
		h.renderMessage(w, r, sess, http.StatusBadRequest, "Say why you are withdrawing this passkey",
			"The reason is kept with the record. Go back and try again.")
		return
	}

	ctx := r.Context()
	tenantID := h.tenantID()

	cred, err := h.deps.Store.GetAdminCredential(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusNotFound, "That passkey does not exist",
				"It may have been withdrawn since the page was loaded.")
			return
		}
		h.serverFault(w, r, sess, "read passkey", err)
		return
	}
	if cred.AdminTokenID != sess.TokenID {
		// The credential exists but belongs to another administrator. Reported
		// as absent, so this form cannot be used to find out who holds one.
		h.renderMessage(w, r, sess, http.StatusNotFound, "That passkey does not exist",
			"It is not one of yours.")
		return
	}

	if err := h.deps.Store.RevokeAdminCredential(ctx, tenantID, id, reason, h.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusConflict, "That passkey has already been withdrawn",
				"Nothing has been changed.")
			return
		}
		h.serverFault(w, r, sess, "withdraw passkey", err)
		return
	}

	h.audited(w, r, audit.Event{
		TenantID:     sess.TenantID,
		EventType:    audit.EventAdminCredentialRevoked,
		ActorType:    store.ActorAdmin,
		ActorID:      sess.TokenID,
		ResourceType: "admin_credential",
		ResourceID:   id,
		Outcome:      store.OutcomeSuccess,
		Detail: map[string]any{
			"reason":      reason,
			"admin_token": cred.AdminTokenID,
			"surface":     "administration interface",
		},
	})

	http.Redirect(w, r, "/admin/?notice=passkey-withdrawn", http.StatusSeeOther)
}

// passkeySection builds the dashboard's view of the operator's own sign-in.
//
// A failure to read the list is not a failure of the dashboard. The rest of the
// screen answers whether people can sign in right now, and losing that because
// one section could not be filled would be the wrong trade; the section reports
// itself as unavailable and the fault is logged.
func (h *Handler) passkeySection(r *http.Request, sess *session) passkeyView {
	view := passkeyView{
		Offered:  h.passkeysOffered(),
		Required: h.deps.Config.Admin.PasskeyRequired,
	}
	if !view.Offered {
		return view
	}

	creds, err := h.deps.Store.ListAdminCredentials(r.Context(), h.tenantID(), sess.TokenID, true)
	if err != nil {
		h.deps.Logger.WarnContext(r.Context(), "adminui: passkeys not listed", slog.Any("error", err))
		view.Offered = false
		return view
	}

	view.Rows = make([]passkeyRow, 0, len(creds))
	for _, c := range creds {
		label := c.Label
		if strings.TrimSpace(label) == "" {
			label = "Security key or passkey"
		}
		row := passkeyRow{
			ID:                c.ID,
			Label:             label,
			AddedAt:           c.CreatedAt,
			LastUsedAt:        c.LastUsedAt,
			Withdrawn:         c.Revoked(),
			WithdrawnAt:       c.RevokedAt,
			MayHaveBeenCopied: c.CloneWarning,
		}
		if !row.Withdrawn {
			view.Active++
		}
		view.Rows = append(view.Rows, row)
	}
	return view
}

// passkeyRequiredFor reports whether the pasted token must be refused for this
// administrator.
//
// The requirement is scoped to a token that actually holds a usable passkey.
// A token with none signs in by being pasted whatever the setting says, and
// that floor is what stops the setting locking a deployment out: the bootstrap
// command mints a token, that token has no passkey, and so it is always a way
// back in. See docs/adr/0017.
//
// A failure to count is not a refusal. A database that cannot answer would
// otherwise turn a configuration preference into an administrative outage,
// which is the same judgement signInBlocked makes about an unavailable limiter.
func (h *Handler) passkeyRequiredFor(r *http.Request, tok *store.AdminToken) bool {
	if !h.deps.Config.Admin.PasskeyRequired || !h.passkeysOffered() {
		return false
	}
	n, err := h.deps.Store.CountActiveAdminCredentials(r.Context(), tok.TenantID, tok.ID)
	if err != nil {
		h.deps.Logger.WarnContext(r.Context(), "adminui: passkey count unavailable",
			slog.Any("error", err))
		return false
	}
	return n > 0
}

// truncateLabel bounds the name an operator gives a passkey.
//
// The cut is on runes rather than bytes, so a label ending in a multi-byte
// character is shortened rather than turned into invalid UTF-8 that a template
// would render as a replacement character.
func truncateLabel(s string) string {
	r := []rune(s)
	if len(r) <= passkeyLabelMax {
		return s
	}
	return string(r[:passkeyLabelMax])
}
