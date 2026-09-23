package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
)

const (
	selfRotatePath = "/admin/v1/admin-tokens/self/rotate"
	mintWarning    = "this token is shown once and cannot be retrieved again"
)

// mintKeyOverHTTP mints an API key through the route, so the test holds its
// identifier as well as its token. The harness helper writes to the store and
// returns only the token.
func mintKeyOverHTTP(t *testing.T, h *harness, body map[string]any) (id, tok string) {
	t.Helper()
	res := h.do(http.MethodPost, "/admin/v1/api-keys", h.admin[store.RoleFull], body)
	if res.Status != http.StatusCreated {
		t.Fatalf("mint = %d; body: %s", res.Status, res.Raw)
	}
	return asString(t, res.obj(t, "api_key")["id"], "api_key.id"), res.str(t, "token")
}

// mintExpiringAdminToken writes an administrative token with an expiry
// directly, because minting one over HTTP is held for approval by default and
// the queue is not what these tests are about.
func mintExpiringAdminToken(t *testing.T, h *harness, name string, role store.Role, expiresAt time.Time) string {
	t.Helper()
	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = h.store.CreateAdminToken(context.Background(), &store.AdminToken{
		ID: uuid.NewString(), TenantID: h.cfg.TenantID(), Name: name,
		Selector: tok.Selector, VerifierHash: tok.Hash, Role: role,
		CreatedAt: h.clock.now(), ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Display
}

// instant reads a timestamp out of a decoded body.
func instant(t *testing.T, body map[string]any, key string) time.Time {
	t.Helper()
	raw, ok := body[key].(string)
	if !ok {
		t.Fatalf("field %q is %T, not a timestamp", key, body[key])
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("field %q = %q: %v", key, raw, err)
	}
	return at
}

// keyWorks reports whether an API key authenticates on a route every scope
// used in these tests includes.
func keyWorks(h *harness, key string) int {
	return h.do(http.MethodPost, "/v1/subjects", key, map[string]any{"subject_ref": "user-1"}).Status
}

func adminWorks(h *harness, tok string) int {
	return h.do(http.MethodGet, "/admin/v1/alerts", tok, nil).Status
}

// rotationDetail decodes the detail of the single rotation entry of a type.
func rotationDetail(t *testing.T, h *harness, eventType string) (map[string]any, string) {
	t.Helper()
	entries := h.auditEntries(eventType)
	if len(entries) != 1 {
		t.Fatalf("%d %s entries, want exactly 1", len(entries), eventType)
	}
	var detail map[string]any
	if err := json.Unmarshal(entries[0].Detail, &detail); err != nil {
		t.Fatalf("detail of %s: %v", eventType, err)
	}
	return detail, string(entries[0].Detail)
}

// TestRotatedAPIKeyOverlapClosesItself is the behaviour the feature exists for.
//
// Both keys work during the grace window, so the integration can be redeployed
// without an outage, and the old one stops by itself at the end of it, so
// nobody has to remember to revoke it.
func TestRotatedAPIKeyOverlapClosesItself(t *testing.T) {
	h := newHarness(t)
	oldID, oldKey := mintKeyOverHTTP(t, h, map[string]any{
		"name": "billing", "scopes": []string{"subjects", "totp"},
	})
	start := h.clock.now()

	res := h.do(http.MethodPost, "/admin/v1/api-keys/"+oldID+"/rotate", h.admin[store.RoleFull], nil)
	if res.Status != http.StatusCreated {
		t.Fatalf("rotate = %d, want 201; body: %s", res.Status, res.Raw)
	}
	newKey := res.str(t, "token")
	successor := res.obj(t, "api_key")

	// Name and scopes carry over, and the successor is a different credential.
	if successor["name"] != "billing" {
		t.Errorf("successor name = %v, want billing", successor["name"])
	}
	scopes, _ := successor["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "subjects" || scopes[1] != "totp" {
		t.Errorf("successor scopes = %v, want [subjects totp]", successor["scopes"])
	}
	if successor["id"] == oldID || newKey == oldKey {
		t.Fatal("the successor is the predecessor")
	}
	if res.Body["predecessor_id"] != oldID {
		t.Errorf("predecessor_id = %v, want %s", res.Body["predecessor_id"], oldID)
	}
	if res.Body["warning"] != mintWarning {
		t.Errorf("warning = %v, want the same text as minting", res.Body["warning"])
	}
	// The successor does not inherit the cutoff that was put on the
	// predecessor, and the response says so as minting does.
	if res.Body["no_expiry"] != true || successor["expires_at"] != nil {
		t.Errorf("no_expiry = %v, expires_at = %v; the successor must carry no expiry",
			res.Body["no_expiry"], successor["expires_at"])
	}
	if res.Body["unrestricted"] != false {
		t.Errorf("unrestricted = %v for a scoped successor", res.Body["unrestricted"])
	}
	cutoff := start.Add(24 * time.Hour)
	if got := instant(t, res.Body, "predecessor_expires_at"); !got.Equal(cutoff) {
		t.Errorf("predecessor_expires_at = %v, want %v, the default grace", got, cutoff)
	}

	// Both work inside the window.
	if st := keyWorks(h, oldKey); st != http.StatusOK {
		t.Errorf("the predecessor was refused inside the grace window: %d", st)
	}
	if st := keyWorks(h, newKey); st != http.StatusOK {
		t.Errorf("the successor was refused: %d", st)
	}

	// A scoped successor is still a scoped key. Rotation must not be a way to
	// shed a restriction.
	if res := h.do(http.MethodGet, "/v1/health/detail", newKey, nil); res.Status != http.StatusForbidden {
		t.Errorf("the successor reached outside its scopes: %d; body: %s", res.Status, res.Raw)
	}

	// One second before the cutoff the predecessor still works; at the cutoff
	// it has stopped and the successor has not.
	h.clock.set(cutoff.Add(-time.Second))
	if st := keyWorks(h, oldKey); st != http.StatusOK {
		t.Errorf("the predecessor stopped before its expiry: %d", st)
	}
	h.clock.set(cutoff)
	if st := keyWorks(h, oldKey); st != http.StatusUnauthorized {
		t.Errorf("the predecessor still authenticates at its expiry: %d", st)
	}
	if st := keyWorks(h, newKey); st != http.StatusOK {
		t.Errorf("the successor stopped with the predecessor: %d", st)
	}

	// The listing shows both rows and neither secret.
	listing := h.do(http.MethodGet, "/admin/v1/api-keys", h.admin[store.RoleFull], nil)
	for _, secret := range []string{oldKey, newKey, "verifier_hash", "selector"} {
		if indexOf(listing.Raw, secret) >= 0 {
			t.Errorf("the api key listing contains %q", secret)
		}
	}

	detail, raw := rotationDetail(t, h, audit.EventAPIKeyRotated)
	if detail["predecessor_id"] != oldID || detail["successor_id"] != successor["id"] {
		t.Errorf("audit detail = %v, want both identifiers", detail)
	}
	if detail["grace"] != "24h0m0s" {
		t.Errorf("audited grace = %v, want 24h0m0s", detail["grace"])
	}
	if got := instant(t, detail, "predecessor_expires_at"); !got.Equal(cutoff) {
		t.Errorf("audited predecessor_expires_at = %v, want %v", got, cutoff)
	}
	// Neither the token nor either half of it: the selector alone would let a
	// reader of the log tell which stored row a captured token belongs to.
	for _, part := range append(strings.SplitN(newKey, ".", 2), newKey) {
		if indexOf(raw, part) >= 0 {
			t.Error("the audit entry contains the token or part of it")
		}
	}
}

// TestRotationWithNoGraceCutsThePredecessorAtOnce is the leaked-key case, where
// an overlap is the last thing wanted.
func TestRotationWithNoGraceCutsThePredecessorAtOnce(t *testing.T) {
	h := newHarness(t)
	oldID, oldKey := mintKeyOverHTTP(t, h, map[string]any{"name": "leaked"})

	res := h.do(http.MethodPost, "/admin/v1/api-keys/"+oldID+"/rotate", h.admin[store.RoleFull],
		map[string]any{"grace": "0s"})
	if res.Status != http.StatusCreated {
		t.Fatalf("rotate = %d; body: %s", res.Status, res.Raw)
	}
	if st := keyWorks(h, oldKey); st != http.StatusUnauthorized {
		t.Errorf("the predecessor survived a rotation with no grace: %d", st)
	}
	if st := keyWorks(h, res.str(t, "token")); st != http.StatusOK {
		t.Errorf("the successor was refused: %d", st)
	}
	if res.Body["unrestricted"] != true {
		t.Errorf("unrestricted = %v for the successor of an unscoped key", res.Body["unrestricted"])
	}
}

// TestRotationNeverExtendsTheKeyBeingRotated checks the expiry rule over HTTP.
//
// A key due to die tomorrow, rotated with three days of grace, still dies
// tomorrow, and the response reports the real instant rather than the one that
// was asked for.
func TestRotationNeverExtendsTheKeyBeingRotated(t *testing.T) {
	h := newHarness(t)
	oldID, oldKey := mintKeyOverHTTP(t, h, map[string]any{"name": "short-lived", "expires_in_days": 1})
	ownExpiry := h.clock.now().AddDate(0, 0, 1)

	res := h.do(http.MethodPost, "/admin/v1/api-keys/"+oldID+"/rotate", h.admin[store.RoleFull],
		map[string]any{"grace": "72h", "expires_in_days": 90})
	if res.Status != http.StatusCreated {
		t.Fatalf("rotate = %d; body: %s", res.Status, res.Raw)
	}
	if got := instant(t, res.Body, "predecessor_expires_at"); !got.Equal(ownExpiry) {
		t.Errorf("predecessor_expires_at = %v, want its own earlier expiry %v", got, ownExpiry)
	}

	// The successor takes its expiry from the request and from nowhere else.
	if res.Body["no_expiry"] != false {
		t.Error("no_expiry is true although expires_in_days was given")
	}
	successor := res.obj(t, "api_key")
	if got, want := instant(t, successor, "expires_at"), h.clock.now().AddDate(0, 0, 90); !got.Equal(want) {
		t.Errorf("successor expires_at = %v, want %v", got, want)
	}

	h.clock.set(ownExpiry)
	if st := keyWorks(h, oldKey); st != http.StatusUnauthorized {
		t.Errorf("rotation kept a key alive past its own expiry: %d", st)
	}
}

// TestRotationGraceIsBoundedPerRequest checks the bound the configuration
// validator cannot enforce, since the request body arrives after it has run.
func TestRotationGraceIsBoundedPerRequest(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Features.RotationGrace = config.Duration{Duration: time.Hour}
	})
	oldID, _ := mintKeyOverHTTP(t, h, map[string]any{"name": "bounded"})
	path := "/admin/v1/api-keys/" + oldID + "/rotate"
	full := h.admin[store.RoleFull]

	for _, grace := range []string{"169h", "168h0m1s", "8760h", "-1h", "soon", "1d"} {
		res := h.do(http.MethodPost, path, full, map[string]any{"grace": grace})
		if res.Status != http.StatusBadRequest {
			t.Errorf("grace %q = %d, want 400; body: %s", grace, res.Status, res.Raw)
		}
	}
	over := h.do(http.MethodPost, path, full, map[string]any{"grace": "169h"})
	if detail, _ := over.Body["detail"].(string); indexOf(detail, "two live credentials, not a rotation") < 0 {
		t.Errorf("the refusal does not give the reason: %q", detail)
	}
	if res := h.do(http.MethodPost, selfRotatePath, full, map[string]any{"grace": "169h"}); res.Status != http.StatusBadRequest {
		t.Errorf("self-rotation accepted a grace above the maximum: %d", res.Status)
	}
	// An unknown field is refused like everywhere else, so a misspelled
	// "grace" cannot fall back to the default unnoticed.
	if res := h.do(http.MethodPost, path, full, map[string]any{"grace_period": "0s"}); res.Status != http.StatusBadRequest {
		t.Errorf("a misspelled field = %d, want 400", res.Status)
	}

	// None of the refusals minted anything or touched the predecessor.
	listing := h.do(http.MethodGet, "/admin/v1/api-keys", full, nil)
	for _, raw := range listing.list(t, "api_keys") {
		entry := asObject(t, raw, "entry", "")
		if entry["id"] == oldID && entry["expires_at"] != nil {
			t.Errorf("a refused rotation bounded the predecessor: %v", entry["expires_at"])
		}
	}
	if n := len(listing.list(t, "api_keys")); n != 2 {
		t.Errorf("%d keys listed, want the harness key and the minted one", n)
	}
	if len(h.auditEntries(audit.EventAPIKeyRotated)) != 0 {
		t.Error("a refused rotation was audited as a rotation")
	}

	// The maximum itself is accepted, and an absent grace means the
	// configured default rather than the built-in one.
	start := h.clock.now()
	atMax := h.do(http.MethodPost, path, full, map[string]any{"grace": "168h"})
	if atMax.Status != http.StatusCreated {
		t.Fatalf("grace at the maximum = %d; body: %s", atMax.Status, atMax.Raw)
	}
	successorID := asString(t, atMax.obj(t, "api_key")["id"], "api_key.id")
	byDefault := h.do(http.MethodPost, "/admin/v1/api-keys/"+successorID+"/rotate", full, nil)
	if byDefault.Status != http.StatusCreated {
		t.Fatalf("rotate with the configured grace = %d; body: %s", byDefault.Status, byDefault.Raw)
	}
	if got, want := instant(t, byDefault.Body, "predecessor_expires_at"), start.Add(time.Hour); !got.Equal(want) {
		t.Errorf("predecessor_expires_at = %v, want %v from features.rotation_grace", got, want)
	}
}

// TestRevokedOrExpiredKeyCannotBeRotated guards against rotation bringing back
// an integration somebody switched off.
func TestRevokedOrExpiredKeyCannotBeRotated(t *testing.T) {
	h := newHarness(t)
	full := h.admin[store.RoleFull]

	revokedID, _ := mintKeyOverHTTP(t, h, map[string]any{"name": "revoked"})
	if res := h.do(http.MethodPost, "/admin/v1/api-keys/"+revokedID+"/revoke", full, nil); res.Status != http.StatusOK {
		t.Fatalf("revoke = %d", res.Status)
	}
	if res := h.do(http.MethodPost, "/admin/v1/api-keys/"+revokedID+"/rotate", full, nil); res.Status != http.StatusConflict {
		t.Errorf("rotating a revoked key = %d, want 409; body: %s", res.Status, res.Raw)
	}

	expiredID, _ := mintKeyOverHTTP(t, h, map[string]any{"name": "expired", "expires_in_days": 1})
	h.clock.add(25 * time.Hour)
	if res := h.do(http.MethodPost, "/admin/v1/api-keys/"+expiredID+"/rotate", full, nil); res.Status != http.StatusConflict {
		t.Errorf("rotating an expired key = %d, want 409; body: %s", res.Status, res.Raw)
	}

	if res := h.do(http.MethodPost, "/admin/v1/api-keys/"+uuid.NewString()+"/rotate", full, nil); res.Status != http.StatusNotFound {
		t.Errorf("rotating an unknown key = %d, want 404", res.Status)
	}
	if res := h.do(http.MethodPost, "/admin/v1/api-keys/not-an-id/rotate", full, nil); res.Status != http.StatusBadRequest {
		t.Errorf("rotating a malformed identifier = %d, want 400", res.Status)
	}
	if len(h.auditEntries(audit.EventAPIKeyRotated)) != 0 {
		t.Error("a refused rotation was audited as a rotation")
	}
}

// TestOnlyFullAdministratorRotatesAPIKeys checks the permission. The response
// carries a working credential for the public surface, so the route belongs
// with minting, not with user support.
func TestOnlyFullAdministratorRotatesAPIKeys(t *testing.T) {
	h := newHarness(t)
	oldID, oldKey := mintKeyOverHTTP(t, h, map[string]any{"name": "guarded"})

	for _, role := range []store.Role{store.RoleOperator, store.RoleAuditor} {
		res := h.do(http.MethodPost, "/admin/v1/api-keys/"+oldID+"/rotate", h.admin[role],
			map[string]any{"grace": "0s"})
		if res.Status != http.StatusForbidden {
			t.Errorf("%s rotating an api key = %d, want 403; body: %s", role, res.Status, res.Raw)
		}
		if res.Body["token"] != nil {
			t.Errorf("a refusal to %s carried a token", role)
		}
	}
	if st := keyWorks(h, oldKey); st != http.StatusOK {
		t.Errorf("a refused rotation cut the key off: %d", st)
	}
	if len(h.auditEntries(audit.EventAdminDenied)) < 2 {
		t.Error("the refusals were not audited")
	}
}

// TestEveryRoleRotatesItsOwnToken checks self-service rotation for all three
// roles, the auditor included.
//
// Dual approval is left on, as the harness default has it, so a 201 here also
// shows the rotation is not held for a second administrator.
func TestEveryRoleRotatesItsOwnToken(t *testing.T) {
	h := newHarness(t)

	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator, store.RoleFull} {
		oldTok := h.admin[role]
		start := h.clock.now()

		res := h.do(http.MethodPost, selfRotatePath, oldTok, nil)
		if res.Status != http.StatusCreated {
			t.Fatalf("%s rotating itself = %d, want 201; body: %s", role, res.Status, res.Raw)
		}
		newTok := res.str(t, "token")
		successor := res.obj(t, "admin_token")
		if successor["role"] != string(role) {
			t.Errorf("successor role = %v, want %s; rotation must change no authority", successor["role"], role)
		}
		if successor["name"] != string(role) {
			t.Errorf("successor name = %v, want %s", successor["name"], role)
		}
		if successor["created_by"] != res.Body["predecessor_id"] {
			t.Errorf("created_by = %v, want the predecessor %v", successor["created_by"], res.Body["predecessor_id"])
		}
		if res.Body["warning"] != mintWarning || res.Body["no_expiry"] != true {
			t.Errorf("warning = %v, no_expiry = %v", res.Body["warning"], res.Body["no_expiry"])
		}
		cutoff := start.Add(24 * time.Hour)
		if got := instant(t, res.Body, "predecessor_expires_at"); !got.Equal(cutoff) {
			t.Errorf("predecessor_expires_at = %v, want %v", got, cutoff)
		}

		if st := adminWorks(h, oldTok); st != http.StatusOK {
			t.Errorf("the old %s token was refused inside the grace window: %d", role, st)
		}
		if st := adminWorks(h, newTok); st != http.StatusOK {
			t.Errorf("the new %s token was refused: %d", role, st)
		}

		// The successor holds what the predecessor held and nothing more.
		mint := h.do(http.MethodPost, "/admin/v1/api-keys", newTok, map[string]any{"name": "probe-" + string(role)})
		wantMint := http.StatusForbidden
		if role == store.RoleFull {
			wantMint = http.StatusCreated
		}
		if mint.Status != wantMint {
			t.Errorf("successor of %s minting an api key = %d, want %d", role, mint.Status, wantMint)
		}

		h.clock.set(cutoff)
		if st := adminWorks(h, oldTok); st != http.StatusUnauthorized {
			t.Errorf("the old %s token still authenticates after its grace: %d", role, st)
		}
		if st := adminWorks(h, newTok); st != http.StatusOK {
			t.Errorf("the new %s token stopped with the old one: %d", role, st)
		}
		h.admin[role] = newTok

		listing := h.do(http.MethodGet, "/admin/v1/admin-tokens", newTok, nil)
		for _, secret := range []string{oldTok, newTok, "verifier_hash", "selector"} {
			if indexOf(listing.Raw, secret) >= 0 {
				t.Errorf("the admin token listing contains %q", secret)
			}
		}
	}

	entries := h.auditEntries(audit.EventAdminTokenRotated)
	if len(entries) != 3 {
		t.Fatalf("%d admin_token.rotated entries, want 3", len(entries))
	}
	for _, e := range entries {
		var detail map[string]any
		if err := json.Unmarshal(e.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"predecessor_id", "successor_id", "grace", "predecessor_expires_at", "role"} {
			if detail[key] == nil {
				t.Errorf("admin_token.rotated detail lacks %q: %s", key, e.Detail)
			}
		}
		if e.ActorID != detail["predecessor_id"] {
			t.Errorf("actor %q is not the predecessor %v; a token rotates only itself", e.ActorID, detail["predecessor_id"])
		}
		for _, tok := range h.admin {
			if indexOf(string(e.Detail), tok) >= 0 {
				t.Error("the audit entry contains a token")
			}
		}
	}
	if len(h.auditEntries(audit.EventApprovalRequested)) != 0 {
		t.Error("a self-rotation was queued for approval")
	}
}

// TestNobodyRotatesAnotherAdministratorsToken checks that the route which
// would hand out someone else's successor credential does not exist.
func TestNobodyRotatesAnotherAdministratorsToken(t *testing.T) {
	h := newHarness(t)
	full := h.admin[store.RoleFull]

	listing := h.do(http.MethodGet, "/admin/v1/admin-tokens", full, nil)
	var auditorID string
	for _, raw := range listing.list(t, "admin_tokens") {
		entry := asObject(t, raw, "entry", "")
		if entry["role"] == string(store.RoleAuditor) {
			auditorID = asString(t, entry["id"], "entry.id")
		}
	}
	if auditorID == "" {
		t.Fatal("no auditor token in the listing")
	}

	res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+auditorID+"/rotate", full, map[string]any{"grace": "0s"})
	if res.Status != http.StatusNotFound {
		t.Errorf("rotating another administrator's token = %d, want 404; body: %s", res.Status, res.Raw)
	}
	if res.Body["token"] != nil {
		t.Error("the response carried a token")
	}
	if st := adminWorks(h, h.admin[store.RoleAuditor]); st != http.StatusOK {
		t.Errorf("the auditor's token was affected: %d", st)
	}

	// The body cannot name a target either: it is an unknown field.
	named := h.do(http.MethodPost, selfRotatePath, full, map[string]any{"token_id": auditorID})
	if named.Status != http.StatusBadRequest {
		t.Errorf("naming a target in the body = %d, want 400", named.Status)
	}
	if len(h.auditEntries(audit.EventAdminTokenRotated)) != 0 {
		t.Error("something was rotated")
	}
}

// TestSelfRotationCannotOutliveTheTokenItReplaces checks that a time-boxed
// token cannot use self-service to escape its box.
func TestSelfRotationCannotOutliveTheTokenItReplaces(t *testing.T) {
	h := newHarness(t)
	ownExpiry := h.clock.now().AddDate(0, 0, 10)
	contractor := mintExpiringAdminToken(t, h, "contractor", store.RoleAuditor, ownExpiry)

	if res := h.do(http.MethodPost, selfRotatePath, contractor, map[string]any{"expires_in_days": 365}); res.Status != http.StatusBadRequest {
		t.Fatalf("asking for a longer life = %d, want 400; body: %s", res.Status, res.Raw)
	}

	res := h.do(http.MethodPost, selfRotatePath, contractor, map[string]any{"grace": "0s"})
	if res.Status != http.StatusCreated {
		t.Fatalf("rotate = %d; body: %s", res.Status, res.Raw)
	}
	successor := res.obj(t, "admin_token")
	if got := instant(t, successor, "expires_at"); !got.Equal(ownExpiry) {
		t.Errorf("successor expires_at = %v, want the inherited %v", got, ownExpiry)
	}
	if res.Body["no_expiry"] != false {
		t.Error("no_expiry is true for a successor that inherited an expiry")
	}
	if st := adminWorks(h, contractor); st != http.StatusUnauthorized {
		t.Errorf("the predecessor survived a rotation with no grace: %d", st)
	}

	// Shortening is allowed.
	shorter := h.do(http.MethodPost, selfRotatePath, res.str(t, "token"), map[string]any{"expires_in_days": 3})
	if shorter.Status != http.StatusCreated {
		t.Fatalf("rotating to a shorter life = %d; body: %s", shorter.Status, shorter.Raw)
	}
	got := instant(t, shorter.obj(t, "admin_token"), "expires_at")
	if want := h.clock.now().AddDate(0, 0, 3); !got.Equal(want) {
		t.Errorf("successor expires_at = %v, want %v", got, want)
	}

	h.clock.set(ownExpiry)
	if st := adminWorks(h, shorter.str(t, "token")); st != http.StatusUnauthorized {
		t.Errorf("a chain of rotations outlived the original expiry: %d", st)
	}
}

// TestRotationLeavesTheLastAdministratorGuardAlone checks the two directions in
// which rotation could have disturbed the guard.
//
// The sole full administrator can rotate itself, because the successor exists
// before the predecessor stops. And having done so with no grace, the successor
// is now the last usable full administrator and is protected as such.
func TestRotationLeavesTheLastAdministratorGuardAlone(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodPost, selfRotatePath, h.admin[store.RoleFull], map[string]any{"grace": "0s"})
	if res.Status != http.StatusCreated {
		t.Fatalf("the sole full administrator could not rotate itself: %d; body: %s", res.Status, res.Raw)
	}
	newTok := res.str(t, "token")
	successorID := asString(t, res.obj(t, "admin_token")["id"], "admin_token.id")

	if st := adminWorks(h, newTok); st != http.StatusOK {
		t.Fatalf("the deployment has no working full administrator: %d", st)
	}
	revoke := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+successorID+"/revoke", newTok, nil)
	if revoke.Status != http.StatusConflict {
		t.Errorf("revoking the last usable full administrator = %d, want 409; body: %s", revoke.Status, revoke.Raw)
	}
	if st := adminWorks(h, newTok); st != http.StatusOK {
		t.Errorf("the successor stopped working: %d", st)
	}
}

// TestLastAdministratorGuardLooksPastTheRotationGrace is the regression test
// for a guard that counted administrators at the present instant.
//
// A rotated token keeps working for its grace period, so counted today it looks
// like a second full administrator. The guard then let the successor be
// revoked, and when the grace ran out the deployment had no administrator at
// all, with no way to mint one short of host access.
func TestLastAdministratorGuardLooksPastTheRotationGrace(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Features.DualApproval = false })
	original := h.admin[store.RoleFull]

	rotated := h.do(http.MethodPost, "/admin/v1/admin-tokens/self/rotate", original,
		map[string]any{"grace": "24h"})
	if rotated.Status != http.StatusCreated {
		t.Fatalf("self rotation = %d; body: %s", rotated.Status, rotated.Raw)
	}
	successor := rotated.str(t, "token")

	listing := h.do(http.MethodGet, "/admin/v1/admin-tokens", successor, nil)
	var successorID, predecessorID string
	for _, raw := range listing.list(t, "admin_tokens") {
		e := asObject(t, raw, "entry", "")
		if e["role"] != string(store.RoleFull) {
			continue
		}
		if e["expires_at"] == nil {
			successorID = asString(t, e["id"], "e.id")
		} else {
			predecessorID = asString(t, e["id"], "e.id")
		}
	}
	if successorID == "" || predecessorID == "" {
		t.Fatalf("could not tell the two full administrators apart: %s", listing.Raw)
	}

	// The predecessor is still usable, and must not count: revoking the
	// successor would leave nobody once the grace ends.
	res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+successorID+"/revoke", original, nil)
	if res.Status != http.StatusConflict {
		t.Fatalf("revoking the only lasting full administrator = %d, want 409; a token "+
			"in its rotation grace was counted as an administrator; body: %s", res.Status, res.Raw)
	}

	// Tidying up the predecessor early, on the other hand, is harmless and
	// must be allowed.
	if res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+predecessorID+"/revoke", successor, nil); res.Status != http.StatusOK {
		t.Errorf("revoking the outgoing predecessor = %d, want 200; body: %s", res.Status, res.Raw)
	}
}

// TestAssertionBeginDoesNotRevealEnrolment checks that starting an assertion
// answers the same way for a subject with no authenticator as for any other
// failure, so the route cannot be used to learn who has enrolled.
func TestAssertionBeginDoesNotRevealEnrolment(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "no-key-yet"})

	none := h.do(http.MethodPost, "/v1/webauthn/no-key-yet/assert", h.apiKey, nil)
	unknown := h.do(http.MethodPost, "/v1/webauthn/nobody-at-all/assert", h.apiKey, nil)

	if none.Status != unknown.Status || none.Body["type"] != unknown.Body["type"] {
		t.Fatalf("a subject without an authenticator answers %d %v, an unknown subject %d %v; "+
			"the difference tells a caller who has enrolled",
			none.Status, none.Body["type"], unknown.Status, unknown.Body["type"])
	}
	if none.Body["detail"] != nil {
		t.Errorf("the refusal carries a detail: %v", none.Body["detail"])
	}
}
