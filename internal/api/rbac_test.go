package api

import (
	"net/http"
	"testing"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// TestAuditorIsReadOnly exercises the role model over real HTTP.
//
// Hiding an action in the interface is not a control. The refusal has to happen
// server-side, which is why every write route is submitted directly here with
// an auditor's token rather than checked through a rendered page.
func TestAuditorIsReadOnly(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	id := created.str(t, "subject_id")
	auditor := h.admin[store.RoleAuditor]

	// Reading is permitted.
	for _, path := range []string{
		"/admin/v1/subjects",
		"/admin/v1/subjects/" + id,
		"/admin/v1/subjects/" + id + "/credentials",
		"/admin/v1/audit",
		"/admin/v1/alerts",
		"/admin/v1/approvals",
		"/admin/v1/health",
	} {
		if res := h.do(http.MethodGet, path, auditor, nil); res.Status != http.StatusOK {
			t.Errorf("GET %s as auditor = %d, want 200; body: %s", path, res.Status, res.Raw)
		}
	}

	// Writing is not, including acknowledging an alert, which is the smallest
	// write on the surface and the one most likely to be waved through.
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/admin/v1/subjects/" + id + "/lock", map[string]any{"reason": "x"}},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/unlock", nil},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/recovery/reissue", nil},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/throttle/reset", nil},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/erasure", map[string]any{"reason": "x"}},
		{http.MethodDelete, "/admin/v1/subjects/" + id + "/erasure", nil},
		{http.MethodPost, "/admin/v1/api-keys", map[string]any{"name": "x"}},
		{http.MethodPost, "/admin/v1/admin-tokens", map[string]any{"name": "x", "role": "admin_full"}},
		{http.MethodPost, "/admin/v1/alerts/00000000-0000-0000-0000-000000000000/acknowledge", nil},
		{http.MethodPost, "/admin/v1/approvals/00000000-0000-0000-0000-000000000000/approve", nil},
	} {
		res := h.do(tc.method, tc.path, auditor, tc.body)
		if res.Status != http.StatusForbidden {
			t.Errorf("%s %s as auditor = %d, want 403; body: %s",
				tc.method, tc.path, res.Status, res.Raw)
		}
		// The refusal must not name the permission it wanted. That tells a
		// caller probing the surface exactly what to look for next.
		if res.Body["detail"] != nil {
			t.Errorf("%s %s disclosed a detail: %v", tc.method, tc.path, res.Body["detail"])
		}
	}

	// Every denial is audited, which is how a probe becomes visible.
	if len(h.auditEntries(audit.EventAdminDenied)) == 0 {
		t.Error("authorisation denials were not audited")
	}
}

// TestOperatorCannotMintCredentials checks the boundary between the day-to-day
// support role and the one that grants authority.
func TestOperatorCannotMintCredentials(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	id := created.str(t, "subject_id")
	operator := h.admin[store.RoleOperator]

	// The operator handles user support.
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, "/admin/v1/subjects/" + id + "/throttle/reset", nil, http.StatusOK},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/recovery/reissue", nil, http.StatusCreated},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/lock", map[string]any{"reason": "x"}, http.StatusOK},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/unlock", nil, http.StatusOK},
	} {
		if res := h.do(tc.method, tc.path, operator, tc.body); res.Status != tc.want {
			t.Errorf("%s %s as operator = %d, want %d; body: %s",
				tc.method, tc.path, res.Status, tc.want, res.Raw)
		}
	}

	// But not the operations that grant authority or destroy data.
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/admin/v1/api-keys", map[string]any{"name": "x"}},
		{http.MethodPost, "/admin/v1/admin-tokens", map[string]any{"name": "x", "role": "admin_operator"}},
		{http.MethodPost, "/admin/v1/subjects/" + id + "/erasure", map[string]any{"reason": "x"}},
		{http.MethodPost, "/admin/v1/approvals/00000000-0000-0000-0000-000000000000/approve", nil},
	} {
		if res := h.do(tc.method, tc.path, operator, tc.body); res.Status != http.StatusForbidden {
			t.Errorf("%s %s as operator = %d, want 403; body: %s",
				tc.method, tc.path, res.Status, res.Raw)
		}
	}
}

// TestRBACDisabledGrantsEveryValidRole covers the lite deployment.
//
// With the role model off, one administrator holds full authority, which is
// what a single-operator deployment means. An unknown role must still be
// refused, because that is a corrupted row rather than a configuration choice.
func TestRBACDisabledGrantsEveryValidRole(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Features.AdminRBAC = false
		// Dual approval requires the role model, so the validator refuses the
		// pair. Lite mode turns both off together for the same reason.
		c.Features.DualApproval = false
	})

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	id := created.str(t, "subject_id")

	// An auditor now holds full authority.
	res := h.do(http.MethodPost, "/admin/v1/subjects/"+id+"/lock",
		h.admin[store.RoleAuditor], map[string]any{"reason": "rbac off"})
	if res.Status != http.StatusOK {
		t.Errorf("with the role model off, an auditor was refused: %d; body: %s", res.Status, res.Raw)
	}
}

// TestLastFullAdministratorCannotBeRevoked checks the lockout guard.
//
// A deployment with no administrator cannot mint one, so the recovery would be
// editing the database by hand.
func TestLastFullAdministratorCannotBeRevoked(t *testing.T) {
	// Minting an administrative token is a dual-approval operation by default,
	// which would queue the replacement rather than create it. The queue has
	// its own test; this one isolates the lockout guard.
	h := newHarness(t, func(c *config.Config) {
		c.Features.DualApproval = false
	})

	tokens := h.do(http.MethodGet, "/admin/v1/admin-tokens", h.admin[store.RoleFull], nil)
	if tokens.Status != http.StatusOK {
		t.Fatalf("list status = %d", tokens.Status)
	}

	list, ok := tokens.Body["admin_tokens"].([]any)
	if !ok {
		t.Fatalf("unexpected body: %s", tokens.Raw)
	}

	var fullID string
	for _, raw := range list {
		entry := asObject(t, raw, "entry", "")
		if entry["role"] == string(store.RoleFull) {
			fullID = asString(t, entry["id"], "entry.id")
			break
		}
	}
	if fullID == "" {
		t.Fatal("no full administrator found in the listing")
	}

	res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+fullID+"/revoke",
		h.admin[store.RoleFull], nil)
	if res.Status != http.StatusConflict {
		t.Errorf("revoking the last full administrator = %d, want 409; body: %s", res.Status, res.Raw)
	}

	// With a second one in place, the first can go.
	minted := h.do(http.MethodPost, "/admin/v1/admin-tokens", h.admin[store.RoleFull],
		map[string]any{"name": "replacement", "role": "admin_full"})
	if minted.Status != http.StatusCreated {
		t.Fatalf("minting a replacement = %d; body: %s", minted.Status, minted.Raw)
	}
	if res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+fullID+"/revoke",
		h.admin[store.RoleFull], nil); res.Status != http.StatusOK {
		t.Errorf("revoking with a replacement present = %d, want 200; body: %s", res.Status, res.Raw)
	}
}

// TestMintedTokenIsShownOnceAndWorks checks the credential lifecycle over HTTP.
func TestMintedTokenIsShownOnceAndWorks(t *testing.T) {
	h := newHarness(t)

	minted := h.do(http.MethodPost, "/admin/v1/api-keys", h.admin[store.RoleFull],
		map[string]any{"name": "minted-for-revocation", "expires_in_days": 30})
	if minted.Status != http.StatusCreated {
		t.Fatalf("mint status = %d; body: %s", minted.Status, minted.Raw)
	}
	newKey := minted.str(t, "token")

	// The new credential authenticates.
	if res := h.do(http.MethodPost, "/v1/subjects", newKey,
		map[string]any{"subject_ref": "user-1"}); res.Status != http.StatusOK {
		t.Fatalf("the minted key was refused: %d; body: %s", res.Status, res.Raw)
	}

	// The listing must not carry the secret. Only a selector and a digest are
	// stored, so there is nothing to disclose, and this proves it.
	listing := h.do(http.MethodGet, "/admin/v1/api-keys", h.admin[store.RoleFull], nil)
	if indexOf(listing.Raw, newKey) >= 0 {
		t.Fatal("the listing contains the token itself")
	}
	if indexOf(listing.Raw, "verifier_hash") >= 0 {
		t.Error("the listing exposes the stored verifier digest")
	}

	// Revoking it stops it working.
	keys := listing.list(t, "api_keys")
	// The harness mints its own key during setup, so the lookup is by the
	// distinctive name rather than by position.
	var keyID string
	for _, raw := range keys {
		entry := asObject(t, raw, "entry", "")
		if entry["name"] == "minted-for-revocation" {
			keyID = asString(t, entry["id"], "entry.id")
		}
	}
	if keyID == "" {
		t.Fatal("the minted key is not in the listing")
	}

	if res := h.do(http.MethodPost, "/admin/v1/api-keys/"+keyID+"/revoke",
		h.admin[store.RoleFull], nil); res.Status != http.StatusOK {
		t.Fatalf("revoke status = %d; body: %s", res.Status, res.Raw)
	}
	if res := h.do(http.MethodPost, "/v1/subjects", newKey,
		map[string]any{"subject_ref": "user-2"}); res.Status != http.StatusUnauthorized {
		t.Errorf("a revoked key still authenticates: %d", res.Status)
	}
}

// TestDualApprovalHoldsSensitiveOperations checks the queue.
func TestDualApprovalHoldsSensitiveOperations(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	id := created.str(t, "subject_id")

	// Erasure is one of the configured operations, so it is queued rather than
	// performed.
	res := h.do(http.MethodPost, "/admin/v1/subjects/"+id+"/erasure",
		h.admin[store.RoleFull], map[string]any{"reason": "user request"})
	if res.Status != http.StatusAccepted {
		t.Fatalf("erasure status = %d, want 202; body: %s", res.Status, res.Raw)
	}
	if res.Body["type"] != TypeApprovalRequired {
		t.Errorf("problem type = %v, want %s", res.Body["type"], TypeApprovalRequired)
	}

	// The subject must still be able to authenticate: nothing has happened yet.
	sub, err := h.store.GetSubject(t.Context(), h.cfg.TenantID(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !sub.Active() {
		t.Error("the subject was blocked before the operation was approved")
	}

	// The request is in the queue.
	queue := h.do(http.MethodGet, "/admin/v1/approvals", h.admin[store.RoleFull], nil)
	if queue.Status != http.StatusOK {
		t.Fatalf("queue status = %d", queue.Status)
	}
	pending := queue.list(t, "approvals")
	if len(pending) != 1 {
		t.Fatalf("queue holds %d requests, want 1: %s", len(pending), queue.Raw)
	}
	approvalID := asString(t, asObject(t, pending[0], "pending[0]", "")["id"], "pending[0].id")

	// The administrator who raised it cannot approve it. A two-administrator
	// rule one administrator can satisfy alone is not a control.
	self := h.do(http.MethodPost, "/admin/v1/approvals/"+approvalID+"/approve",
		h.admin[store.RoleFull], nil)
	if self.Status != http.StatusForbidden {
		t.Errorf("self-approval = %d, want 403; body: %s", self.Status, self.Raw)
	}

	// A second full administrator can.
	second := h.mintAdminToken("second", store.RoleFull)
	other := h.do(http.MethodPost, "/admin/v1/approvals/"+approvalID+"/approve",
		second, map[string]any{"note": "checked with the user"})
	if other.Status != http.StatusOK {
		t.Errorf("approval by a second administrator = %d, want 200; body: %s",
			other.Status, other.Raw)
	}

	if len(h.auditEntries(audit.EventApprovalRequested)) == 0 {
		t.Error("the queued request was not audited")
	}
	if len(h.auditEntries(audit.EventApprovalGranted)) == 0 {
		t.Error("the approval was not audited")
	}
}

// TestAuditChainVerificationRoute checks the operation that makes the chain
// worth having.
func TestAuditChainVerificationRoute(t *testing.T) {
	h := newHarness(t)

	// Produce some history.
	for i := 0; i < 5; i++ {
		h.do(http.MethodPost, "/v1/subjects", h.apiKey,
			map[string]any{"subject_ref": "user-" + string(rune('a'+i))})
	}

	res := h.do(http.MethodGet, "/admin/v1/audit/verify", h.admin[store.RoleFull], nil)
	if res.Status != http.StatusOK {
		t.Fatalf("verify status = %d; body: %s", res.Status, res.Raw)
	}
	if res.Body["intact"] != true {
		t.Errorf("the chain reported as not intact: %s", res.Raw)
	}

	// An auditor may verify, because it is a read.
	if res := h.do(http.MethodGet, "/admin/v1/audit/verify",
		h.admin[store.RoleAuditor], nil); res.Status != http.StatusOK {
		t.Errorf("an auditor was refused chain verification: %d", res.Status)
	}
}
