package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// The console raises what the API raises.
//
// Every action here has a counterpart on the API surface, and the two used to
// disagree about whether anybody was told. A withdrawal past the burst, an
// action refused to a role and a passkey whose counter did not advance all
// reached the history from this interface and the alerts screen from the other
// one, which is the wrong way round: the console is where a person acts, and
// the alerts screen is what an operator watches.

// raisedAlerts reads the alerts of one type.
func (h *harness) raisedAlerts(alertType alerts.Type) []*store.Alert {
	h.t.Helper()

	list, err := h.store.ListAlerts(context.Background(), testTenantID, store.AlertFilter{
		AlertType: string(alertType),
		Limit:     50,
	})
	if err != nil {
		h.t.Fatalf("list alerts: %v", err)
	}
	return list
}

// seedCredential writes one of a person's authenticators straight into the
// store, so that there is something to withdraw.
func (h *harness) seedCredential(sub *store.Subject) *store.Credential {
	h.t.Helper()

	id := uuid.NewString()
	cred := &store.Credential{
		ID:              id,
		TenantID:        testTenantID,
		SubjectID:       sub.ID,
		CredentialID:    []byte("credential-" + id),
		PublicKey:       []byte("public-key-" + id),
		AttestationType: store.AttestationNone,
		RPID:            h.cfg.WebAuthn.RPID,
		CreatedAt:       h.clock.now(),
	}
	if err := h.store.CreateCredential(context.Background(), cred); err != nil {
		h.t.Fatalf("seed authenticator: %v", err)
	}
	return cred
}

// TestARefusedActionRaisesTheAlertTheAPIRaises covers the operator probing for
// authority they do not hold.
//
// It looks exactly like an operator who followed a stale link, and only the
// pattern over time tells them apart. The history carried it from the first
// day; nothing put it where anybody looks.
func TestARefusedActionRaisesTheAlertTheAPIRaises(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleAuditor)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)
	w := h.post("/admin/subjects/"+sub.ID+"/lock", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an auditor blocking a sign-in = %d, want %d", w.Code, http.StatusForbidden)
	}

	raised := h.raisedAlerts(alerts.TypeAdminDenied)
	if len(raised) != 1 {
		t.Fatalf("a refused action raised %d alerts, want 1", len(raised))
	}
	if raised[0].ResourceID == "" {
		t.Error("the alert names no token, so an operator cannot tell whose sign-in was refused")
	}
}

// TestWithdrawalsPastTheBurstRaiseTheAlert covers the run of withdrawals.
//
// The burst limit already stopped the run. What it did not do from this
// surface was say so anywhere an operator would see it, so a script driving the
// console emptied a person's authenticators as quietly as the limit allowed.
func TestWithdrawalsPastTheBurstRaiseTheAlert(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.Enabled = true
		c.Throttle.AdminRevokeBurst = 2
	})
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	creds := []*store.Credential{h.seedCredential(sub), h.seedCredential(sub), h.seedCredential(sub)}
	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)

	for i, cred := range creds[:2] {
		form := url.Values{csrfFieldName: {csrf}, "reason": {"lost"}}
		w := h.post("/admin/subjects/"+sub.ID+"/authenticators/"+cred.ID+"/withdraw", form, cookie)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("withdrawal %d = %d, want %d", i+1, w.Code, http.StatusSeeOther)
		}
	}

	raised := h.raisedAlerts(alerts.TypeBulkRevocation)
	if len(raised) != 1 {
		t.Fatalf("withdrawing up to the burst of %d raised %d alerts, want 1",
			h.cfg.Throttle.AdminRevokeBurst, len(raised))
	}
	if raised[0].ResourceID == "" {
		t.Error("the alert names no sign-in, so an operator cannot tell who was withdrawing")
	}
}

// TestAPasskeyThatMayHaveBeenCopiedIsAlerted covers the signal that is recorded
// and never refused.
//
// A ceremony cannot be driven to a successful conclusion from this package, for
// the reason given at the top of passkey_test.go, so the signal is handed to
// the same function the completed sign-in hands it to. What is under test is
// that a counter which did not advance leaves the history and reaches the
// alerts, and that an administrative credential is not filed under a person who
// does not exist.
func TestAPasskeyThatMayHaveBeenCopiedIsAlerted(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	cred := h.seedPasskey(tok, "the one in my pocket")

	sess, ok := h.handler.sessions.get(h.clock.now(), cookie.Value, h.handler.idleTTL, h.handler.absoluteTTL)
	if !ok {
		t.Fatal("the session was not established")
	}

	r := httptest.NewRequest(http.MethodPost, "/admin/sign-in/passkey/complete", http.NoBody)
	h.handler.alertCloneWarning(r, sess, &webauthn.AdminAssertionResult{
		Token:      tok,
		Credential: cred,
		Outcome: &webauthn.AssertionOutcome{
			UserVerified:      true,
			CloneWarning:      true,
			PreviousSignCount: 12,
			NewSignCount:      12,
		},
	})

	raised := h.raisedAlerts(alerts.TypeSignCountRegression)
	if len(raised) != 1 {
		t.Fatalf("a counter that did not advance raised %d alerts, want 1", len(raised))
	}
	if raised[0].SubjectID != "" {
		t.Errorf("the alert is filed under subject %q; an administrative passkey belongs to a token "+
			"and to nobody in the subject table", raised[0].SubjectID)
	}
	if raised[0].ResourceID != cred.ID {
		t.Errorf("the alert names %q, want the passkey %q", raised[0].ResourceID, cred.ID)
	}
}

// TestAnAssertionWithNothingWrongRaisesNothing is the other half: the alert is
// for a counter that did not advance, not for every sign-in.
func TestAnAssertionWithNothingWrongRaisesNothing(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	cred := h.seedPasskey(tok, "the one in my pocket")

	sess, ok := h.handler.sessions.get(h.clock.now(), cookie.Value, h.handler.idleTTL, h.handler.absoluteTTL)
	if !ok {
		t.Fatal("the session was not established")
	}

	r := httptest.NewRequest(http.MethodPost, "/admin/sign-in/passkey/complete", http.NoBody)
	h.handler.alertCloneWarning(r, sess, &webauthn.AdminAssertionResult{
		Token:      tok,
		Credential: cred,
		Outcome: &webauthn.AssertionOutcome{
			UserVerified:      true,
			PreviousSignCount: 12,
			NewSignCount:      13,
		},
	})

	if raised := h.raisedAlerts(alerts.TypeSignCountRegression); len(raised) != 0 {
		t.Errorf("an ordinary sign-in raised %d alerts, want none", len(raised))
	}
}

// TestTheInterfaceWorksWithNoAlertEngine keeps the dependency optional.
//
// The main package builds these dependencies, and a deployment assembled
// without an engine must lose the alerts and nothing else. The same is true of
// the metrics observer in internal/api, and for the same reason: a nil
// collaborator that panics is a worse outage than the signal it carries.
func TestTheInterfaceWorksWithNoAlertEngine(t *testing.T) {
	h := newHarness(t)
	h.handler.deps.Alerts = nil

	_, display := h.mintToken(store.RoleAuditor)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)
	w := h.post("/admin/subjects/"+sub.ID+"/lock", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an auditor blocking a sign-in = %d, want %d", w.Code, http.StatusForbidden)
	}
	if entries := h.auditEntries(testTenantID, "admin.denied"); len(entries) == 0 {
		t.Error("the refusal was not recorded either")
	}
}

// TestSigningInAgainEndsTheSessionTheBrowserHeld is the test for a sign-in that
// left its predecessor live.
//
// An operator who suspects their session signs in again, and the session they
// were worried about went on working for the rest of the idle window, which on
// this interface is measured in minutes and not in seconds.
func TestSigningInAgainEndsTheSessionTheBrowserHeld(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)

	first := h.signIn(display)

	// The form redirects a live session to the dashboard, so the second sign-in
	// is posted with the cookie attached, which is what a browser does when the
	// form is submitted from somewhere else.
	w := h.post("/admin/sign-in", url.Values{"token": {display}}, first)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("signing in again = %d, want %d", w.Code, http.StatusSeeOther)
	}
	second := sessionCookieFrom(w.Result().Cookies())
	if second == nil {
		t.Fatal("signing in again set no session cookie")
	}
	if second.Value == first.Value {
		t.Fatal("the second sign-in handed back the first session, so there is nothing to test")
	}

	if got := h.get("/admin/", first); got.Code != http.StatusSeeOther {
		t.Errorf("the session held before signing in again = %d, want a redirect to the sign-in screen",
			got.Code)
	}
	if got := h.get("/admin/", second); got.Code != http.StatusOK {
		t.Errorf("the session just established = %d, want %d", got.Code, http.StatusOK)
	}
	if live := h.handler.sessions.count(); live != 1 {
		t.Errorf("%d sessions are live, want the one that was just established", live)
	}
}

// TestTheReferenceIsRecordedOnlyWhenItWasShown is the test for an entry written
// before the work it describes.
//
// The reveal was recorded, and then the record was read. A person deleted since
// the form was loaded, or one whose reference was never sealed, produced an
// entry saying somebody had seen a reference that was never on the page. That
// entry is the whole point of the operation, so a false one is worse than none.
func TestTheReferenceIsRecordedOnlyWhenItWasShown(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)
	missing := uuid.NewString()
	form := url.Values{csrfFieldName: {csrf}}

	if w := h.post("/admin/subjects/"+missing+"/reference", form, cookie); w.Code != http.StatusNotFound {
		t.Fatalf("revealing the reference of somebody who does not exist = %d, want %d",
			w.Code, http.StatusNotFound)
	}
	if entries := h.auditEntries(testTenantID, "admin.subject_ref_revealed"); len(entries) != 0 {
		t.Fatalf("%d entries say a reference was read, and none was shown", len(entries))
	}

	// The entry is still written when the reference does reach the page, which
	// is the behaviour the reordering must not have cost.
	if w := h.post("/admin/subjects/"+sub.ID+"/reference", form, cookie); w.Code != http.StatusOK {
		t.Fatalf("revealing a reference = %d, want %d", w.Code, http.StatusOK)
	}
	entries := h.auditEntries(testTenantID, "admin.subject_ref_revealed")
	if len(entries) != 1 {
		t.Fatalf("revealing a reference wrote %d entries, want 1", len(entries))
	}
	if entries[0].SubjectID != sub.ID {
		t.Errorf("the entry names subject %q, want %q", entries[0].SubjectID, sub.ID)
	}
}
