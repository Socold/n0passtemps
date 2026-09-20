package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/store"
)

// The console is the second place a dual-approval decision can be taken, the
// API being the first, and a two-administrator rule with a second code path
// around it is not a rule. decideApproval therefore takes no decision of its
// own: it hands the session's token to the store and renders whatever comes
// back, including the refusal when the decider is the requester.
//
// These tests are about that arrangement holding at the console boundary. The
// store's own half is tested against both engines; what is checked here is that
// the console asks it, with the right token, and shows the operator the answer
// rather than a stack trace.

// queueApproval puts a pending request in the store, raised by requestedBy, and
// returns its identifier.
//
// The identifier is a UUID because the console refuses a path segment that is
// not one, before it looks anything up: an identifier that cannot name a row is
// answered without a query.
func queueApproval(t *testing.T, h *harness, requestedBy string) string {
	t.Helper()
	id := uuid.NewString()
	req := &store.ApprovalRequest{
		ID:          id,
		TenantID:    h.cfg.TenantID(),
		Operation:   "subject.credentials.revoke_all",
		Payload:     json.RawMessage(`{"subject_id":"s-1"}`),
		Reason:      "offboarding",
		Status:      store.ApprovalPending,
		RequestedBy: requestedBy,
		RequestedAt: h.clock.now(),
		ExpiresAt:   h.clock.now().Add(24 * time.Hour),
	}
	if err := h.store.CreateApproval(context.Background(), req); err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	return id
}

// TestTheConsoleRefusesADecisionTakenByTheRequester is the two-person rule seen
// from the browser.
//
// The refusal comes from the store, in the same transaction as the state
// change. What the console owes is to ask with the session's own token, and to
// say plainly why nothing happened, because an operator who sees a silent
// no-op tries again rather than finding a colleague.
func TestTheConsoleRefusesADecisionTakenByTheRequester(t *testing.T) {
	h := newHarness(t)
	rec, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)

	// Raised by the very token that is about to decide it.
	id := queueApproval(t, h, rec.ID)

	csrf := h.csrfFor("/admin/approvals", cookie)
	w := h.post("/admin/approvals/"+id+"/approve",
		url.Values{csrfFieldName: {csrf}, "note": {"looks fine"}}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), "different administrator") {
		t.Errorf("the page does not say why the decision was refused:\n%s", w.Body.String())
	}

	got, err := h.store.GetApproval(context.Background(), h.cfg.TenantID(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Status != store.ApprovalPending {
		t.Errorf("status = %q after a refused decision, want %q", got.Status, store.ApprovalPending)
	}
}

// TestASecondAdministratorCanApproveAndReject covers the path that is supposed
// to work, in both directions.
func TestASecondAdministratorCanApproveAndReject(t *testing.T) {
	for name, approve := range map[string]bool{"approve": true, "reject": false} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			requester, _ := h.mintToken(store.RoleFull)
			_, deciderDisplay := h.mintToken(store.RoleFull)
			cookie := h.signIn(deciderDisplay)

			id := queueApproval(t, h, requester.ID)

			action := "approve"
			want := store.ApprovalApproved
			if !approve {
				action, want = "reject", store.ApprovalRejected
			}

			csrf := h.csrfFor("/admin/approvals", cookie)
			w := h.post("/admin/approvals/"+id+"/"+action,
				url.Values{csrfFieldName: {csrf}, "note": {"reviewed"}}, cookie)
			if w.Code != http.StatusSeeOther && w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}

			got, err := h.store.GetApproval(context.Background(), h.cfg.TenantID(), id)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if got.Status != want {
				t.Errorf("status = %q, want %q", got.Status, want)
			}
			if got.DecisionNote != "reviewed" {
				t.Errorf("decision_note = %q, want the note the operator typed", got.DecisionNote)
			}
		})
	}
}

// TestDecidingAnApprovalNeedsTheRightPermission keeps the console from being a
// way around the role table.
func TestDecidingAnApprovalNeedsTheRightPermission(t *testing.T) {
	h := newHarness(t)
	requester, _ := h.mintToken(store.RoleFull)
	_, auditorDisplay := h.mintToken(store.RoleAuditor)
	cookie := h.signIn(auditorDisplay)

	id := queueApproval(t, h, requester.ID)

	csrf := h.csrfFor("/admin/approvals", cookie)
	w := h.post("/admin/approvals/"+id+"/approve", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
		t.Fatalf("an auditor decided an approval: status = %d", w.Code)
	}

	got, err := h.store.GetApproval(context.Background(), h.cfg.TenantID(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Status != store.ApprovalPending {
		t.Errorf("status = %q, want it untouched", got.Status)
	}
}

// TestDecidingWithoutASessionIsRefused, because every other check rests on
// there being a session to read a token from.
func TestDecidingWithoutASessionIsRefused(t *testing.T) {
	h := newHarness(t)
	requester, _ := h.mintToken(store.RoleFull)
	id := queueApproval(t, h, requester.ID)

	w := h.post("/admin/approvals/"+id+"/approve", url.Values{})
	if w.Code == http.StatusSeeOther && w.Header().Get("Location") == "" {
		t.Fatal("an unauthenticated decision was accepted")
	}
	got, err := h.store.GetApproval(context.Background(), h.cfg.TenantID(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Status != store.ApprovalPending {
		t.Errorf("status = %q, want it untouched", got.Status)
	}
}

// TestAcknowledgingAnAlertRecordsWhoDidIt is the other console action that
// changes a row, and the one an operator uses most.
//
// Acknowledgement is not deletion: the row stays, with the name of whoever said
// they had looked. An acknowledgement that recorded nobody would turn the alert
// list into a list of things somebody may or may not have seen.
func TestAcknowledgingAnAlertRecordsWhoDidIt(t *testing.T) {
	h := newHarness(t)
	rec, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)

	raised, err := h.store.RaiseAlert(context.Background(), &store.Alert{
		ID: uuid.NewString(), TenantID: h.cfg.TenantID(),
		AlertType: "webauthn.sign_count_regression", Severity: store.SeverityWarning,
		Summary:     "Authenticator signature counter did not advance",
		Fingerprint: "fp-" + uuid.NewString(), Occurrences: 1,
		FirstSeenAt: h.clock.now(), LastSeenAt: h.clock.now(),
	})
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	id := raised.ID

	csrf := h.csrfFor("/admin/alerts", cookie)
	w := h.post("/admin/alerts/"+id+"/acknowledge", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	list, err := h.store.ListAlerts(context.Background(), h.cfg.TenantID(),
		store.AlertFilter{Limit: 10, IncludeAcked: true})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got *store.Alert
	for _, a := range list {
		if a.ID == id {
			got = a
		}
	}
	if got == nil {
		t.Fatal("the alert disappeared from the list")
	}
	if got.AcknowledgedAt == nil {
		t.Fatal("the alert was not acknowledged")
	}
	if got.AcknowledgedBy != rec.ID {
		t.Errorf("acknowledged_by = %q, want the session's token %q", got.AcknowledgedBy, rec.ID)
	}
}

// TestAcknowledgingAnAlertThatIsNotThereSaysSo covers the race with a colleague
// working the same list.
func TestAcknowledgingAnAlertThatIsNotThereSaysSo(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)

	csrf := h.csrfFor("/admin/alerts", cookie)
	w := h.post("/admin/alerts/"+uuid.NewString()+"/acknowledge",
		url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if !strings.Contains(w.Body.String(), "acknowledged by someone else") {
		t.Errorf("the page does not explain the likely cause:\n%s", w.Body.String())
	}
}
