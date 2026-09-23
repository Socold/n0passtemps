package api

import (
	"net/http"
	"sync"
	"testing"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// queueErasure files an erasure request and returns the approval identifier
// together with the body that was queued, since a redemption has to repeat it
// exactly.
func queueErasure(t *testing.T, h *harness, subjectID string) (string, map[string]any) {
	t.Helper()
	body := map[string]any{"reason": "user request"}
	res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/erasure", h.admin[store.RoleFull], body)
	if res.Status != http.StatusAccepted || res.Body["type"] != TypeApprovalRequired {
		t.Fatalf("queueing = %d %v; body: %s", res.Status, res.Body["type"], res.Raw)
	}
	queue := h.do(http.MethodGet, "/admin/v1/approvals", h.admin[store.RoleFull], nil)
	pending := queue.list(t, "approvals")
	if len(pending) != 1 {
		t.Fatalf("queue holds %d requests, want 1", len(pending))
	}
	return asString(t, asObject(t, pending[0], "pending[0]", "")["id"], "pending[0].id"), body
}

// TestApprovedOperationRunsWhenRedeemed is the test for the defect where an
// approved operation never ran at all.
//
// The queue used to hold the request, a second administrator approved it, and
// nothing happened: no code path executed an approved request. An approval is
// now a single-use capability the original requester redeems by repeating the
// identical request.
func TestApprovedOperationRunsWhenRedeemed(t *testing.T) {
	h := newHarness(t)
	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	subjectID := created.str(t, "subject_id")
	path := "/admin/v1/subjects/" + subjectID + "/erasure"
	requester := h.admin[store.RoleFull]

	approvalID, body := queueErasure(t, h, subjectID)
	hdr := map[string]string{ApprovalHeader: approvalID}

	// Redeeming before anyone approved must do nothing.
	if res := h.doWith(http.MethodPost, path, requester, body, hdr); res.Status != http.StatusForbidden {
		t.Fatalf("redeeming a pending approval = %d, want 403; body: %s", res.Status, res.Raw)
	}

	approver := h.mintAdminToken("approver", store.RoleFull)
	if res := h.do(http.MethodPost, "/admin/v1/approvals/"+approvalID+"/approve", approver, nil); res.Status != http.StatusOK {
		t.Fatalf("approve = %d; body: %s", res.Status, res.Raw)
	}

	// The approver cannot spend it. Otherwise the second administrator could
	// both authorise and perform, and the requester's intent would be moot.
	if res := h.doWith(http.MethodPost, path, approver, body, hdr); res.Status != http.StatusForbidden {
		t.Errorf("the approver redeemed the requester's approval: %d", res.Status)
	}

	// What runs must be what was approved. A changed reason is a changed
	// request.
	altered := map[string]any{"reason": "something else entirely"}
	if res := h.doWith(http.MethodPost, path, requester, altered, hdr); res.Status != http.StatusForbidden {
		t.Errorf("an approval was spent on a payload the approver never saw: %d", res.Status)
	}

	// An approval for one operation must not unlock another.
	if res := h.doWith(http.MethodPost, "/admin/v1/admin-tokens", requester,
		map[string]any{"name": "x", "role": "admin_full"}, hdr); res.Status != http.StatusForbidden {
		t.Errorf("an erasure approval was accepted for minting a token: %d; body: %s", res.Status, res.Raw)
	}

	// None of the refusals above may have consumed it.
	ok := h.doWith(http.MethodPost, path, requester, body, hdr)
	if ok.Status != http.StatusAccepted || ok.Body["type"] == TypeApprovalRequired {
		t.Fatalf("legitimate redemption = %d; body: %s", ok.Status, ok.Raw)
	}
	sub, err := h.store.GetSubject(t.Context(), h.cfg.TenantID(), subjectID)
	if err == nil && sub.Active() {
		t.Error("the erasure was redeemed but the subject can still authenticate")
	}

	// And it is spent. The subject is already pending erasure, so the second
	// attempt is turned away before it reaches the gate; what matters is that
	// it is not accepted, by whichever check gets there first.
	if res := h.doWith(http.MethodPost, path, requester, body, hdr); res.Status < 400 {
		t.Errorf("an approval was redeemed twice: %d", res.Status)
	}
	if len(h.auditEntries(audit.EventApprovalExecuted)) != 1 {
		t.Error("the redemption was not audited exactly once")
	}
}

// TestApprovalIsSpentOnceUnderConcurrency races redemptions of one approval.
//
// The claim is a conditional update from approved to executed, so exactly one
// request may pass the gate. Minting a token is used because a second success
// would be directly observable as a second credential.
func TestApprovalIsSpentOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	requester := h.admin[store.RoleFull]
	body := map[string]any{"name": "raced", "role": "admin_operator"}

	if res := h.do(http.MethodPost, "/admin/v1/admin-tokens", requester, body); res.Status != http.StatusAccepted {
		t.Fatalf("queueing = %d", res.Status)
	}
	queue := h.do(http.MethodGet, "/admin/v1/approvals", requester, nil)
	approvalID := asString(t, asObject(t, queue.list(t, "approvals")[0], "approvals[0]", queue.Raw)["id"], "approvals[0].id")
	approver := h.mintAdminToken("approver", store.RoleFull)
	h.do(http.MethodPost, "/admin/v1/approvals/"+approvalID+"/approve", approver, nil)

	const racers = 8
	var wg sync.WaitGroup
	statuses := make([]int, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.doWith(http.MethodPost, "/admin/v1/admin-tokens", requester, body,
				map[string]string{ApprovalHeader: approvalID})
			statuses[i] = res.Status
		}()
	}
	wg.Wait()

	created := 0
	for _, st := range statuses {
		if st == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d of %d concurrent redemptions minted a token, want exactly 1 (%v)", created, racers, statuses)
	}
}

// TestCancellingAnErasureRestoresTheSubject is the test for the defect where a
// cancelled erasure left the subject blocked.
//
// Nothing was erased and the user still could not sign in, which is the worst of
// both outcomes.
func TestCancellingAnErasureRestoresTheSubject(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Features.DualApproval = false })
	admin := h.admin[store.RoleFull]

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	subjectID := created.str(t, "subject_id")
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/erasure", admin,
		map[string]any{"reason": "mistake"}); res.Status != http.StatusAccepted {
		t.Fatalf("erasure = %d; body: %s", res.Status, res.Raw)
	}
	if res := h.do(http.MethodGet, "/v1/subjects/user-1", h.apiKey, nil); res.Status != http.StatusNotFound {
		t.Fatalf("a subject pending erasure is still visible: %d", res.Status)
	}

	if res := h.do(http.MethodDelete, "/admin/v1/subjects/"+subjectID+"/erasure", admin, nil); res.Status != http.StatusOK {
		t.Fatalf("cancel = %d; body: %s", res.Status, res.Raw)
	}

	after := h.do(http.MethodGet, "/v1/subjects/user-1", h.apiKey, nil)
	if after.Status != http.StatusOK || after.Body["status"] != "active" {
		t.Fatalf("after cancelling, the subject is %d %v; it must be active again", after.Status, after.Body["status"])
	}
	// The enrolled factors survive, which is the point of deferring the purge.
	if got := after.Body["recovery_codes_remaining"]; got != float64(h.cfg.Recovery.CodeCount) {
		t.Errorf("recovery codes after restore = %v, want %d", got, h.cfg.Recovery.CodeCount)
	}
}

// TestAPIKeyScopesAreEnforced checks least privilege for integrations.
//
// Scopes used to be stored and ignored, so an operator who issued a
// "totp only" key had in fact issued an unrestricted one.
func TestAPIKeyScopesAreEnforced(t *testing.T) {
	h := newHarness(t)
	admin := h.admin[store.RoleFull]

	minted := h.do(http.MethodPost, "/admin/v1/api-keys", admin,
		map[string]any{"name": "totp-only", "scopes": []string{"TOTP", "subjects"}})
	if minted.Status != http.StatusCreated {
		t.Fatalf("mint = %d; body: %s", minted.Status, minted.Raw)
	}
	if minted.Body["unrestricted"] != false {
		t.Error("a scoped key was reported as unrestricted")
	}
	key := minted.str(t, "token")

	if res := h.do(http.MethodPost, "/v1/subjects", key, map[string]any{"subject_ref": "user-1"}); res.Status != http.StatusOK {
		t.Fatalf("a call inside the key's scope was refused: %d", res.Status)
	}
	if res := h.do(http.MethodPost, "/v1/totp/user-1/enrol", key, nil); res.Status != http.StatusCreated {
		t.Errorf("totp enrol within scope = %d", res.Status)
	}
	for _, path := range []string{"/v1/recovery/user-1/issue", "/v1/webauthn/user-1/register"} {
		if res := h.do(http.MethodPost, path, key, nil); res.Status != http.StatusForbidden {
			t.Errorf("POST %s outside the key's scope = %d, want 403", path, res.Status)
		}
	}
	if res := h.do(http.MethodGet, "/v1/health/detail", key, nil); res.Status != http.StatusForbidden {
		t.Errorf("health detail outside scope = %d, want 403", res.Status)
	}

	// A misspelled scope must be refused at minting, not discovered as a 403
	// in production.
	bad := h.do(http.MethodPost, "/admin/v1/api-keys", admin,
		map[string]any{"name": "typo", "scopes": []string{"totpp"}})
	if bad.Status != http.StatusBadRequest {
		t.Errorf("an unknown scope was accepted: %d", bad.Status)
	}

	// The harness key has no scopes, which means every family.
	if res := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil); res.Status != http.StatusCreated {
		t.Errorf("an unrestricted key was refused: %d", res.Status)
	}
}

// TestKeyVolumeLimitCoversEveryRoute checks that the per-key ceiling meters
// the routes that record no authentication outcome.
//
// It used to count only completed ceremonies, so a leaked key could resolve
// subjects and start ceremonies without bound.
func TestKeyVolumeLimitCoversEveryRoute(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Throttle.MaxRequestsPerKey = 5 })

	var last response
	for range 8 {
		last = h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	}
	if last.Status != http.StatusTooManyRequests {
		t.Fatalf("after exceeding the per-key volume, status = %d, want 429", last.Status)
	}
	if last.Header.Get("Retry-After") == "" {
		t.Error("the refusal carries no Retry-After")
	}

	// A different key is unaffected: the ceiling is per key, not global.
	other := h.mintAPIKey("other")
	if res := h.do(http.MethodPost, "/v1/subjects", other, map[string]any{"subject_ref": "user-1"}); res.Status != http.StatusOK {
		t.Errorf("one key's volume limit refused a different key: %d", res.Status)
	}
}
