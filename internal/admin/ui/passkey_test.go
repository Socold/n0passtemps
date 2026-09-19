package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// The console's passkey routes as HTTP.
//
// A ceremony cannot be driven to a successful conclusion from this package: the
// virtual authenticator lives in internal/webauthn's test binary and a test
// binary's identifiers are not importable. The ceremony itself, including the
// two directions an administrative credential and a subject credential must not
// cross, the refusal of a withdrawn credential and the refusal of an
// administrative token that has expired or been revoked, is covered there. What
// is covered here is everything the ceremony is wrapped in: the request token on
// the authenticated pair, the rate limit on the unauthenticated pair, who may
// withdraw which key, and the configuration that stops a token being pasted.

// seedPasskey writes an administrative credential straight into the store.
//
// The ceremony is not exercised, deliberately: these tests are about what the
// interface does with a credential that exists, and a credential that exists is
// a row. The bytes are arbitrary because nothing on these paths verifies a
// signature.
func (h *harness) seedPasskey(tok *store.AdminToken, label string) *store.AdminCredential {
	h.t.Helper()

	id := uuid.NewString()
	cred := &store.AdminCredential{
		ID:              id,
		TenantID:        testTenantID,
		AdminTokenID:    tok.ID,
		CredentialID:    []byte("credential-" + id),
		PublicKey:       []byte("public-key-" + id),
		AttestationType: store.AttestationNone,
		Transports:      []string{"usb"},
		Label:           label,
		RPID:            h.cfg.WebAuthn.RPID,
		UserVerified:    true,
		CreatedAt:       h.clock.now(),
	}
	if err := h.store.CreateAdminCredential(context.Background(), cred); err != nil {
		h.t.Fatalf("seed passkey: %v", err)
	}
	return cred
}

// jsonBody reads the problem or the redirect out of a ceremony response.
func jsonBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("response is not JSON: %v, body %q", err, body)
	}
	return doc
}

// TestPasskeyFormsRefuseAPostWithoutTheRequestToken covers the case a forged
// cross-site form produces: a valid cookie the browser attached, and no token
// the attacker could have read.
//
// All three authenticated routes are checked, because a single one that forgot
// the check is a route on which an attacker can enrol a passkey of their own
// against the victim's administrative token.
func TestPasskeyFormsRefuseAPostWithoutTheRequestToken(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	cred := h.seedPasskey(tok, "the key on my keyring")

	for _, path := range []string{
		"/admin/passkeys/begin",
		"/admin/passkeys/complete",
		"/admin/passkeys/" + cred.ID + "/withdraw",
	} {
		w := h.post(path, url.Values{"reason": {"testing"}}, cookie)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s without a request token: status = %d, want %d",
				path, w.Code, http.StatusForbidden)
		}
	}

	after, err := h.store.GetAdminCredential(context.Background(), testTenantID, cred.ID)
	if err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	if after.Revoked() {
		t.Error("the passkey was withdrawn by a request carrying no request token")
	}
}

// TestPasskeyFormsRefuseAnotherSessionsRequestToken checks that the token is
// bound to one session rather than being a value any session accepts.
func TestPasskeyFormsRefuseAnotherSessionsRequestToken(t *testing.T) {
	h := newHarness(t)
	tokOne, displayOne := h.mintToken(store.RoleFull)
	_, displayTwo := h.mintToken(store.RoleFull)

	cookieOne := h.signIn(displayOne)
	cookieTwo := h.signIn(displayTwo)
	cred := h.seedPasskey(tokOne, "the key on my keyring")

	csrfTwo := h.csrfFor("/admin/", cookieTwo)

	w := h.post("/admin/passkeys/"+cred.ID+"/withdraw",
		url.Values{csrfFieldName: {csrfTwo}, "reason": {"testing"}}, cookieOne)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	after, err := h.store.GetAdminCredential(context.Background(), testTenantID, cred.ID)
	if err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	if after.Revoked() {
		t.Error("another session's request token was accepted")
	}
}

// TestPasskeyRoutesRefuseAnUnauthenticatedCaller is the other half: enrolment
// requires an existing administrator, so none of the three routes may be
// reached without a session.
func TestPasskeyRoutesRefuseAnUnauthenticatedCaller(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/admin/passkeys/begin",
		"/admin/passkeys/complete",
		"/admin/passkeys/" + uuid.NewString() + "/withdraw",
	} {
		w := h.post(path, url.Values{})
		if w.Code != http.StatusSeeOther {
			t.Errorf("POST %s: status = %d, want %d", path, w.Code, http.StatusSeeOther)
			continue
		}
		if got := w.Header().Get("Location"); got != "/admin/sign-in" {
			t.Errorf("POST %s redirected to %q, want %q", path, got, "/admin/sign-in")
		}
	}
}

// TestPasskeySignInRefusalSaysNothingAndIsAudited pins the oracle property.
//
// The response must not distinguish a malformed answer from an unknown
// credential, and the history must still record that something was refused,
// because a run of them from one address is the earliest sign of a key being
// probed.
func TestPasskeySignInRefusalSaysNothingAndIsAudited(t *testing.T) {
	h := newHarness(t)

	w := h.post("/admin/sign-in/passkey/complete", url.Values{
		"challenge_id": {uuid.NewString()},
		"credential":   {`{"id":"","rawId":"","type":"public-key","response":{}}`},
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if got := jsonBody(t, w.Body.String())["problem"]; got != signInRefusal {
		t.Errorf("problem = %q, want the one fixed sentence %q", got, signInRefusal)
	}
	if c := sessionCookieFrom(w.Result().Cookies()); c != nil {
		t.Fatal("a session cookie was set for a refused passkey")
	}
	if h.handler.sessions.count() != 0 {
		t.Errorf("live sessions = %d, want 0", h.handler.sessions.count())
	}

	entries := h.auditEntries(store.SystemTenantID, audit.EventAdminAuthFailed)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Outcome != store.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", entries[0].Outcome, store.OutcomeDenied)
	}
	// The reason belongs in the record and nowhere else. It is what tells the
	// operator which of the indistinguishable refusals actually happened.
	if !strings.Contains(string(entries[0].Detail), "reason") {
		t.Error("the refusal was recorded without a reason, so the log says less than the code knows")
	}
}

// TestPasskeySignInIsRateLimited bounds the console's one unauthenticated
// ceremony, the same way the pasted-token form is bounded.
//
// The limit is per source address, because a sign-in that has not succeeded has
// established no other identity to count against.
func TestPasskeySignInIsRateLimited(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.Throttle.Enabled = true
		cfg.Throttle.MaxFailuresPerIP = 3
	})

	attempt := func() int {
		return h.post("/admin/sign-in/passkey/complete", url.Values{
			"challenge_id": {uuid.NewString()},
			"credential":   {`{"id":"","rawId":"","type":"public-key","response":{}}`},
		}).Code
	}

	var blocked bool
	for i := 0; i < 12 && !blocked; i++ {
		blocked = attempt() == http.StatusTooManyRequests
	}
	if !blocked {
		t.Fatal("the passkey sign-in never refused a run of failures, so it is unbounded")
	}

	// The begin route shares the limit. A caller locked out of the completion
	// but free to keep asking for challenges would get unbounded work and an
	// unbounded number of challenge rows out of the service.
	if code := h.post("/admin/sign-in/passkey/begin", url.Values{}).Code; code != http.StatusTooManyRequests {
		t.Errorf("begin after the lockout: status = %d, want %d", code, http.StatusTooManyRequests)
	}
}

// TestPasskeyRequiredRefusesThePastedToken covers the configuration that closes
// the form field, and the floor that keeps it from locking a deployment out.
func TestPasskeyRequiredRefusesThePastedToken(t *testing.T) {
	require := func(cfg *config.Config) { cfg.Admin.PasskeyRequired = true }

	t.Run("a token with a passkey is refused", func(t *testing.T) {
		h := newHarness(t, require)
		tok, display := h.mintToken(store.RoleFull)
		h.seedPasskey(tok, "the key on my keyring")

		w := h.post("/admin/sign-in", url.Values{"token": {display}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
		if c := sessionCookieFrom(w.Result().Cookies()); c != nil {
			t.Fatal("a session was minted from a pasted token this deployment refuses")
		}
		if h.handler.sessions.count() != 0 {
			t.Errorf("live sessions = %d, want 0", h.handler.sessions.count())
		}
		if entries := h.auditEntries(store.SystemTenantID, audit.EventAdminAuthFailed); len(entries) != 1 {
			t.Errorf("audit entries = %d, want 1: the refusal has to be visible", len(entries))
		}
	})

	t.Run("a token with no passkey still signs in", func(t *testing.T) {
		h := newHarness(t, require)
		_, display := h.mintToken(store.RoleFull)

		// This is the way back in. A token minted by -bootstrap-admin has no
		// passkey, so the setting can never leave a deployment with nobody able
		// to sign in.
		w := h.post("/admin/sign-in", url.Values{"token": {display}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
		}
		if sessionCookieFrom(w.Result().Cookies()) == nil {
			t.Fatal("no session cookie was set")
		}
	})

	t.Run("a withdrawn passkey reopens the form", func(t *testing.T) {
		h := newHarness(t, require)
		tok, display := h.mintToken(store.RoleFull)
		cred := h.seedPasskey(tok, "the key on my keyring")

		if err := h.store.RevokeAdminCredential(context.Background(), testTenantID,
			cred.ID, "lost", h.clock.now()); err != nil {
			t.Fatalf("withdraw passkey: %v", err)
		}
		if w := h.post("/admin/sign-in", url.Values{"token": {display}}); w.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d: withdrawing the last passkey must reopen the form",
				w.Code, http.StatusSeeOther)
		}
	})
}

// TestWithdrawingAnotherAdministratorsPasskeyIsRefused keeps the routes scoped
// to the caller's own sign-in.
//
// It is reported as absent rather than as forbidden, so the form cannot be used
// to find out which keys another administrator holds.
func TestWithdrawingAnotherAdministratorsPasskeyIsRefused(t *testing.T) {
	h := newHarness(t)
	_, mineDisplay := h.mintToken(store.RoleFull)
	theirs, _ := h.mintToken(store.RoleFull)

	cookie := h.signIn(mineDisplay)
	cred := h.seedPasskey(theirs, "their key")

	csrf := h.csrfFor("/admin/", cookie)
	w := h.post("/admin/passkeys/"+cred.ID+"/withdraw",
		url.Values{csrfFieldName: {csrf}, "reason": {"testing"}}, cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	after, err := h.store.GetAdminCredential(context.Background(), testTenantID, cred.ID)
	if err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	if after.Revoked() {
		t.Error("one administrator withdrew another administrator's passkey")
	}
}

// TestWithdrawingYourOwnPasskeyIsRecordedAndFinal is the companion to the
// refusals above. Without it, a handler that refused everything would pass them.
func TestWithdrawingYourOwnPasskeyIsRecordedAndFinal(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	cred := h.seedPasskey(tok, "the key on my keyring")

	csrf := h.csrfFor("/admin/", cookie)
	w := h.post("/admin/passkeys/"+cred.ID+"/withdraw",
		url.Values{csrfFieldName: {csrf}, "reason": {"left it in a taxi"}}, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}

	after, err := h.store.GetAdminCredential(context.Background(), testTenantID, cred.ID)
	if err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	if !after.Revoked() {
		t.Fatal("the passkey is still in use")
	}
	if after.RevokedReason != "left it in a taxi" {
		t.Errorf("recorded reason = %q, want the one the operator gave", after.RevokedReason)
	}

	entries := h.auditEntries(testTenantID, audit.EventAdminCredentialRevoked)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].ActorID != tok.ID {
		t.Errorf("actor = %q, want %q", entries[0].ActorID, tok.ID)
	}

	// A second withdrawal is a conflict rather than a silent success, so the
	// original reason and instant are the ones that survive.
	again := h.post("/admin/passkeys/"+cred.ID+"/withdraw",
		url.Values{csrfFieldName: {csrf}, "reason": {"again"}}, cookie)
	if again.Code != http.StatusConflict {
		t.Errorf("second withdrawal: status = %d, want %d", again.Code, http.StatusConflict)
	}
}

// TestWithdrawingAPasskeyRequiresAReason keeps the history worth reading.
func TestWithdrawingAPasskeyRequiresAReason(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	cred := h.seedPasskey(tok, "the key on my keyring")

	csrf := h.csrfFor("/admin/", cookie)
	w := h.post("/admin/passkeys/"+cred.ID+"/withdraw", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	after, err := h.store.GetAdminCredential(context.Background(), testTenantID, cred.ID)
	if err != nil {
		t.Fatalf("read passkey: %v", err)
	}
	if after.Revoked() {
		t.Error("a withdrawal with no stated reason went through")
	}
}

// TestDashboardShowsTheOperatorsOwnPasskeysAndNobodyElses checks the section
// that replaced the seventh screen, and that it is scoped to the caller.
func TestDashboardShowsTheOperatorsOwnPasskeysAndNobodyElses(t *testing.T) {
	h := newHarness(t)
	mine, display := h.mintToken(store.RoleFull)
	theirs, _ := h.mintToken(store.RoleOperator)

	h.seedPasskey(mine, "the key on my keyring")
	h.seedPasskey(theirs, "the key on their keyring")

	cookie := h.signIn(display)
	w := h.get("/admin/", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "the key on my keyring") {
		t.Error("the dashboard does not list the operator's own passkey")
	}
	if strings.Contains(body, "the key on their keyring") {
		t.Error("the dashboard lists another administrator's passkey")
	}
}

// TestEveryRoleMayManageItsOwnPasskeys states the authorisation decision.
//
// Enrolling and withdrawing a passkey for your own sign-in carries no
// permission, because it is part of how you authenticate rather than something
// you do as an administrator, and the console's other authentication routes,
// signing in and signing out, carry none either. An auditor who could not enrol
// one would be an auditor who can never stop pasting a token.
func TestEveryRoleMayManageItsOwnPasskeys(t *testing.T) {
	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator, store.RoleFull} {
		t.Run(string(role), func(t *testing.T) {
			h := newHarness(t)
			tok, display := h.mintToken(role)
			cookie := h.signIn(display)
			cred := h.seedPasskey(tok, "the key on my keyring")

			csrf := h.csrfFor("/admin/", cookie)
			w := h.post("/admin/passkeys/"+cred.ID+"/withdraw",
				url.Values{csrfFieldName: {csrf}, "reason": {"replacing it"}}, cookie)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
			}
		})
	}
}

// TestASessionEndsWithTheTokenItWasMadeWith holds a session to the life of its
// credential.
//
// A session used to survive the revocation of its token, on the reasoning that
// checking the token on every request meant keeping it where the browser could
// send it back. It does not: the token is read by its identifier. What the old
// trade cost was the twelve hours in which a revoked administrator could still
// lock subjects, reissue recovery codes and decide approval requests.
func TestASessionEndsWithTheTokenItWasMadeWith(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	csrf := h.csrfFor("/admin/", cookie)

	if err := h.store.RevokeAdminToken(context.Background(), testTenantID, tok.ID, h.clock.now()); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Reading a screen and changing something are refused alike, and both are
	// sent to sign in.
	for name, w := range map[string]*httptest.ResponseRecorder{
		"reading the dashboard": h.get("/admin/", cookie),
		"enrolling a passkey":   h.post("/admin/passkeys/begin", url.Values{csrfFieldName: {csrf}}, cookie),
	} {
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/sign-in" {
			t.Errorf("%s = %d to %q, want %d to /admin/sign-in",
				name, w.Code, w.Header().Get("Location"), http.StatusSeeOther)
		}
	}
	if n := h.handler.sessions.count(); n != 0 {
		t.Errorf("%d sessions survive the revocation, want 0", n)
	}
}

// TestPasskeySignInIsOfferedOnlyWhenARelyingPartyIsWired checks the other
// branch of a nil service, which is a deployment that has not asked for this.
func TestPasskeySignInIsOfferedOnlyWhenARelyingPartyIsWired(t *testing.T) {
	h := newHarness(t)
	h.handler.deps.WebAuthn = nil

	page := h.get("/admin/sign-in")
	if page.Code != http.StatusOK {
		t.Fatalf("sign-in page: status = %d, want %d", page.Code, http.StatusOK)
	}
	if strings.Contains(page.Body.String(), "passkey-sign-in-button") {
		t.Error("the sign-in screen offered a control nothing can answer")
	}

	w := h.post("/admin/sign-in/passkey/begin", url.Values{})
	if w.Code != http.StatusConflict {
		t.Errorf("begin with no relying party: status = %d, want %d", w.Code, http.StatusConflict)
	}
}
