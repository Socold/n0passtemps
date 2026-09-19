package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// detailOf decodes the detail document of an audit entry.
func detailOf(t *testing.T, entry *store.AuditEntry) map[string]any {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(entry.Detail, &doc); err != nil {
		t.Fatalf("entry %d carries a detail that is not JSON: %v", entry.Seq, err)
	}
	return doc
}

// latest returns the entry written last, which is the one a fold reports.
func latest(t *testing.T, entries []*store.AuditEntry) *store.AuditEntry {
	t.Helper()

	if len(entries) == 0 {
		t.Fatal("no entries were written")
	}
	newest := entries[0]
	for _, e := range entries {
		if e.Seq > newest.Seq {
			newest = e
		}
	}
	return newest
}

// systemEntries reads the history of the reserved tenant, which is where a
// refusal on the credential path is filed: the credential that would have named
// a real tenant is the one that did not verify.
func systemEntries(t *testing.T, h *harness, eventType string) []*store.AuditEntry {
	t.Helper()

	entries, err := h.store.QueryAudit(context.Background(), store.SystemTenantID, store.AuditFilter{
		EventType: eventType,
		Limit:     500,
	})
	if err != nil {
		t.Fatalf("query the history of the system tenant: %v", err)
	}
	return entries
}

// systemAlerts reads the alerts raised under the reserved tenant, for the
// reason systemEntries reads its history.
func systemAlerts(t *testing.T, h *harness, alertType alerts.Type) []*store.Alert {
	t.Helper()

	list, err := h.store.ListAlerts(context.Background(), store.SystemTenantID, store.AlertFilter{
		AlertType: string(alertType),
		Limit:     50,
	})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	return list
}

// fullAdminTokens returns the administrative tokens of the full role.
func fullAdminTokens(t *testing.T, h *harness) []*store.AdminToken {
	t.Helper()

	tokens, err := h.store.ListAdminTokens(context.Background(), h.cfg.TenantID())
	if err != nil {
		t.Fatalf("list admin tokens: %v", err)
	}
	var out []*store.AdminToken
	for _, tok := range tokens {
		if tok.Role == store.RoleFull && tok.RevokedAt == nil {
			out = append(out, tok)
		}
	}
	return out
}

// TestRefusedCredentialsAreFoldedIntoOneEntryPerWindow is the test for a
// refusal path that wrote once per request.
//
// Every refused request appended to the hash chain, which has a single writer,
// and upserted an alert, and neither needed a credential to happen. Anyone at
// all could therefore take the writer away from the ceremonies that need it and
// fill a table that carries no subject and is out of reach of an erasure
// request.
//
// What must not be lost is the operator's view of a run of attempts, so both
// halves are asserted here: one entry per window per address, and the number of
// refusals it covers on that entry.
func TestRefusedCredentialsAreFoldedIntoOneEntryPerWindow(t *testing.T) {
	h := newHarness(t)

	const attempts = 5
	for range attempts {
		res := h.do(http.MethodGet, "/admin/v1/subjects", "npt_a0000000000000000000000000.wrong", nil)
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("a credential that does not verify = %d, want 401; body: %s", res.Status, res.Raw)
		}
	}

	entries := systemEntries(t, h, audit.EventAdminAuthFailed)
	if len(entries) != 1 {
		t.Fatalf("%d refusals wrote %d entries, want 1: the refusal path is writing once per request",
			attempts, len(entries))
	}
	if got := detailOf(t, entries[0])["refusals"]; got != float64(1) {
		t.Errorf("the entry that opened the window reports %v refusals, want 1", got)
	}

	// The window rolls, and the next refusal reports everything folded into it,
	// so a run of attempts is visible with its volume rather than only its
	// first attempt.
	h.clock.add(rejectionWindow + time.Second)
	if res := h.do(http.MethodGet, "/admin/v1/subjects", "npt_a0000000000000000000000000.wrong",
		nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("a credential that does not verify = %d, want 401", res.Status)
	}

	entries = systemEntries(t, h, audit.EventAdminAuthFailed)
	if len(entries) != 2 {
		t.Fatalf("after the window rolled there are %d entries, want 2", len(entries))
	}
	if got := detailOf(t, latest(t, entries))["refusals"]; got != float64(attempts) {
		t.Errorf("the entry closing the window reports %v refusals, want %d; a run of attempts is "+
			"no longer visible in the history", got, attempts)
	}

	if len(systemAlerts(t, h, alerts.TypeAPIKeyRejected)) == 0 {
		t.Error("nothing was alerted about a run of refused credentials")
	}
}

// TestARequestWithNoCredentialIsNotAudited covers the caller that teaches an
// operator nothing.
//
// A request with no Authorization header names nobody, so an entry for it says
// only that the address space is being scanned, which is not a fact anybody
// acts on and not one anybody can erase. The alert still counts it, so a scan
// is visible as a number in the one place that aggregates by itself.
func TestARequestWithNoCredentialIsNotAudited(t *testing.T) {
	h := newHarness(t)

	for range 3 {
		if res := h.do(http.MethodGet, "/admin/v1/subjects", "", nil); res.Status != http.StatusUnauthorized {
			t.Fatalf("a request with no credential = %d, want 401; body: %s", res.Status, res.Raw)
		}
	}

	if entries := systemEntries(t, h, audit.EventAdminAuthFailed); len(entries) != 0 {
		t.Errorf("a caller presenting nothing wrote %d entries, want none", len(entries))
	}
	if len(systemAlerts(t, h, alerts.TypeAPIKeyRejected)) == 0 {
		t.Error("a caller presenting nothing was neither audited nor alerted, so the scan is invisible")
	}
}

// TestACallOutsideTheKeysScopesIsCountedAgainstItsVolume is the test for the
// middleware order in router.go.
//
// A refusal for a scope the key does not hold is audited. With the scope
// checked before the key was counted, a key that had been taken could write one
// entry per request by calling a route it was not entitled to, as fast as it
// liked. Metering first puts that behind the per-key ceiling.
func TestACallOutsideTheKeysScopesIsCountedAgainstItsVolume(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Throttle.MaxRequestsPerKey = 3 })

	minted := h.do(http.MethodPost, "/admin/v1/api-keys", h.admin[store.RoleFull],
		map[string]any{"name": "totp-only", "scopes": []string{"totp"}})
	if minted.Status != http.StatusCreated {
		t.Fatalf("mint = %d; body: %s", minted.Status, minted.Raw)
	}
	key := minted.str(t, "token")

	var last response
	for range 6 {
		last = h.do(http.MethodPost, "/v1/subjects", key, map[string]any{"subject_ref": "user-1"})
	}
	if last.Status != http.StatusTooManyRequests {
		t.Fatalf("calling outside the key's scopes without limit = %d, want 429; the scope refusal "+
			"is audited, so it has to be counted first; body: %s", last.Status, last.Raw)
	}
}

// TestTheLastFullAdministratorIsGuardedAtThePresentToo is the test for a guard
// that only looked at the far end of the rotation grace.
//
// A token due to expire inside that horizon was treated as somebody the
// deployment was not going to have anyway, and the guard was skipped
// altogether. The deployment still had it today, so revoking it emptied the
// deployment on the spot, with no administrator left to mint a replacement.
func TestTheLastFullAdministratorIsGuardedAtThePresentToo(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Features.DualApproval = false })

	// The only full administrator left is one whose token expires this
	// afternoon, well inside the longest rotation grace.
	onCall := mintExpiringAdminToken(t, h, "on call", store.RoleFull, h.clock.now().Add(6*time.Hour))
	ctx := context.Background()
	for _, tok := range fullAdminTokens(t, h) {
		if tok.ExpiresAt == nil {
			if err := h.store.RevokeAdminToken(ctx, h.cfg.TenantID(), tok.ID, h.clock.now()); err != nil {
				t.Fatalf("revoke the standing administrator: %v", err)
			}
		}
	}

	remaining := fullAdminTokens(t, h)
	if len(remaining) != 1 {
		t.Fatalf("the deployment has %d full administrators, want the one that expires today", len(remaining))
	}

	res := h.do(http.MethodPost, "/admin/v1/admin-tokens/"+remaining[0].ID+"/revoke", onCall, nil)
	if res.Status != http.StatusConflict {
		t.Fatalf("revoking the only administrator the deployment has now = %d, want 409; body: %s",
			res.Status, res.Raw)
	}
	if st := adminWorks(h, onCall); st != http.StatusOK {
		t.Errorf("the administrator stopped working: %d", st)
	}
}

// TestSelfRotationIsRefusedWhileTheTokenHoldsPasskeys is the test for the
// rotation that walked away from its own console credentials.
//
// A passkey names the token it signs in as, and no operation moves it onto the
// successor. Rotating regardless left the keys working until the predecessor's
// grace ran out and then not at all, and handed whoever held the token a
// successor that admin.passkey_required does not apply to, because the setting
// is scoped to a token that holds a passkey and the successor holds none.
func TestSelfRotationIsRefusedWhileTheTokenHoldsPasskeys(t *testing.T) {
	h := newHarness(t)

	admins := fullAdminTokens(t, h)
	if len(admins) == 0 {
		t.Fatal("the harness has no full administrator")
	}
	seedAdminPasskey(t, h, admins[0])

	res := h.do(http.MethodPost, "/admin/v1/admin-tokens/self/rotate", h.admin[store.RoleFull],
		map[string]any{"grace": "1h"})
	if res.Status != http.StatusConflict {
		t.Fatalf("rotating a token that holds a console passkey = %d, want 409; body: %s", res.Status, res.Raw)
	}
	if len(h.auditEntries(audit.EventAdminTokenRotated)) != 0 {
		t.Error("a successor was minted for a token whose passkeys cannot follow it")
	}

	// A token with no passkey rotates as it always did, which is what keeps the
	// refusal from being a rule about rotation rather than about passkeys.
	operator := h.do(http.MethodPost, "/admin/v1/admin-tokens/self/rotate", h.admin[store.RoleOperator],
		map[string]any{"grace": "1h"})
	if operator.Status != http.StatusCreated {
		t.Fatalf("rotating a token with no passkey = %d, want 201; body: %s", operator.Status, operator.Raw)
	}
}

// seedAdminPasskey writes a console credential for one administrative token.
//
// The ceremony is not exercised: what is under test is what the rotation route
// does about a credential that exists, and a credential that exists is a row.
func seedAdminPasskey(t *testing.T, h *harness, tok *store.AdminToken) *store.AdminCredential {
	t.Helper()

	id := uuid.NewString()
	cred := &store.AdminCredential{
		ID:              id,
		TenantID:        tok.TenantID,
		AdminTokenID:    tok.ID,
		CredentialID:    []byte("credential-" + id),
		PublicKey:       []byte("public-key-" + id),
		AttestationType: store.AttestationNone,
		RPID:            h.cfg.WebAuthn.RPID,
		UserVerified:    true,
		CreatedAt:       h.clock.now(),
	}
	if err := h.store.CreateAdminCredential(context.Background(), cred); err != nil {
		t.Fatalf("seed console passkey: %v", err)
	}
	return cred
}

// TestAnOverlongCredentialLifetimeIsRefused bounds what a caller may ask for.
//
// The field took any number at all, so a typed extra digit produced a
// credential that every screen reports as bounded and that expires after
// somebody's career. A negative one was quietly read as no expiry, which is a
// decision nobody took.
func TestAnOverlongCredentialLifetimeIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Features.DualApproval = false })
	admin := h.admin[store.RoleFull]

	for _, days := range []int{maxExpiresInDays + 1, 36500, -1} {
		body := map[string]any{"name": "integration", "expires_in_days": days}
		if res := h.do(http.MethodPost, "/admin/v1/api-keys", admin, body); res.Status != http.StatusBadRequest {
			t.Errorf("an api key asked to last %d days = %d, want 400; body: %s", days, res.Status, res.Raw)
		}

		body = map[string]any{"name": "desk", "role": string(store.RoleOperator), "expires_in_days": days}
		if res := h.do(http.MethodPost, "/admin/v1/admin-tokens", admin, body); res.Status != http.StatusBadRequest {
			t.Errorf("an admin token asked to last %d days = %d, want 400; body: %s", days, res.Status, res.Raw)
		}
	}

	// The bound itself is usable, and an absent field still means no expiry,
	// which the response reports rather than hides.
	at := h.do(http.MethodPost, "/admin/v1/api-keys", admin,
		map[string]any{"name": "integration", "expires_in_days": maxExpiresInDays})
	if at.Status != http.StatusCreated {
		t.Fatalf("an api key at the bound = %d, want 201; body: %s", at.Status, at.Raw)
	}
	none := h.do(http.MethodPost, "/admin/v1/api-keys", admin, map[string]any{"name": "forever"})
	if none.Status != http.StatusCreated || none.Body["no_expiry"] != true {
		t.Errorf("an api key with no stated lifetime = %d, no_expiry %v; want 201 and true",
			none.Status, none.Body["no_expiry"])
	}
}
