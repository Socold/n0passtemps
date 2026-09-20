package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
)

// bootstrapAdmin is the only way a deployment gets its first administrator, and
// its own comment explains why: with dual approval on, minting a token through
// the API is held for a second administrator, so a deployment with one
// administrator cannot create its second. The tempting fix, an exemption in the
// API for a sole administrator, is reachable by an attacker who revokes the
// others first and then approves their own requests for ever.
//
// So the exemption lives here instead, behind a command on the host. The tests
// below are about the two properties that keeps honest: it refuses when a
// usable administrator already exists, and it writes the audit entry before it
// prints the secret.

// bootstrapStore is a migrated store with the tenant already provisioned, which
// is what the command finds on a real first run.
func bootstrapStore(t *testing.T) (*audit.Recorder, store.Store) {
	t.Helper()
	st := newTestStore(t)
	rec := audit.NewRecorder(st, quietLogger())
	cfg := testConfig(t)
	if err := ensureTenant(context.Background(), cfg, st, rec, quietLogger()); err != nil {
		t.Fatalf("provision tenant: %v", err)
	}
	return rec, st
}

// TestBootstrapRefusesWhenAnAdministratorAlreadyExists is the guard that keeps
// the command from being a second, quieter way to mint authority.
func TestBootstrapRefusesWhenAnAdministratorAlreadyExists(t *testing.T) {
	cfg := testConfig(t)
	rec, st := bootstrapStore(t)
	ctx := context.Background()

	if err := bootstrapAdmin(ctx, cfg, st, rec, false, 1); err != nil {
		t.Fatalf("the first bootstrap failed: %v", err)
	}

	err := bootstrapAdmin(ctx, cfg, st, rec, false, 1)
	if err == nil {
		t.Fatal("a second bootstrap was allowed without -force")
	}
	if !strings.Contains(err.Error(), "-force") {
		t.Errorf("the refusal does not say how to proceed after losing every token:\n%v", err)
	}
	if !strings.Contains(err.Error(), "/admin/v1/admin-tokens") {
		t.Errorf("the refusal does not name the route for further tokens:\n%v", err)
	}
}

// TestBootstrapWithForceIsRecordedAsForced is what an operator who lost every
// token leaves behind, and it is the entry an investigation would look for.
func TestBootstrapWithForceIsRecordedAsForced(t *testing.T) {
	cfg := testConfig(t)
	rec, st := bootstrapStore(t)
	ctx := context.Background()

	if err := bootstrapAdmin(ctx, cfg, st, rec, false, 1); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if err := bootstrapAdmin(ctx, cfg, st, rec, true, 1); err != nil {
		t.Fatalf("forced bootstrap: %v", err)
	}

	entries := auditEntriesOfType(t, st, audit.EventAdminTokenCreated)
	if len(entries) != 2 {
		t.Fatalf("%d admin_token.created entries, want 2", len(entries))
	}
	// The first was not forced, the second was, and the detail says so.
	if !strings.Contains(string(entries[0].Detail), `"forced":false`) {
		t.Errorf("the first bootstrap was recorded as forced: %s", entries[0].Detail)
	}
	if !strings.Contains(string(entries[1].Detail), `"forced":true`) {
		t.Errorf("the forced bootstrap was not recorded as forced: %s", entries[1].Detail)
	}
	for _, e := range entries {
		if !strings.Contains(string(e.Detail), `"bootstrap":true`) {
			t.Errorf("an entry does not say it came from the bootstrap path: %s", e.Detail)
		}
	}
}

// TestBootstrapMintsTheQuorumItWasAskedFor covers the count and its bounds.
//
// Two is the number the wizard's closing instructions print for a complete
// deployment, because with dual approval on a single administrator cannot mint
// the second through the API.
func TestBootstrapMintsTheQuorumItWasAskedFor(t *testing.T) {
	cfg := testConfig(t)
	rec, st := bootstrapStore(t)
	ctx := context.Background()

	if err := bootstrapAdmin(ctx, cfg, st, rec, false, 2); err != nil {
		t.Fatalf("bootstrap two: %v", err)
	}
	n, err := st.CountAdminTokensByRole(ctx, cfg.TenantID(), store.RoleFull, time.Now().UTC())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("%d full administrators exist, want 2", n)
	}

	for _, count := range []int{0, -1, 1000} {
		if err := bootstrapAdmin(ctx, cfg, st, rec, true, count); err == nil {
			t.Errorf("-admins %d was accepted", count)
		}
	}
}

// TestEachBootstrapTokenIsStoredAsADigestOnly is the reason the command prints
// once and the reason a failed write is fatal.
func TestEachBootstrapTokenIsStoredAsADigestOnly(t *testing.T) {
	cfg := testConfig(t)
	_, st := bootstrapStore(t)
	ctx := context.Background()

	display, admin, err := mintBootstrapToken(ctx, cfg, st, "bootstrap-1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if display == "" {
		t.Fatal("the minted token has no displayable secret")
	}

	stored, err := st.GetAdminTokenByID(ctx, cfg.TenantID(), admin.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.VerifierHash == "" {
		t.Error("no verifier digest was stored")
	}
	if strings.Contains(display, stored.VerifierHash) || stored.VerifierHash == display {
		t.Error("the stored value is the secret rather than a digest of it")
	}
	if !strings.Contains(display, stored.Selector) {
		t.Error("the displayed token does not carry the selector the store keys on")
	}
	if stored.Role != store.RoleFull {
		t.Errorf("role = %q, want %q", stored.Role, store.RoleFull)
	}
}

// TestWarnIfNoAdministratorIsQuietOnceOneExists covers the startup notice.
//
// It runs on every start and writes to the log rather than failing, because a
// deployment mid-provisioning is not broken. What matters is that it stops
// saying it once the deployment has an administrator.
func TestWarnIfNoAdministratorIsQuietOnceOneExists(t *testing.T) {
	cfg := testConfig(t)
	rec, st := bootstrapStore(t)
	ctx := context.Background()

	var before strings.Builder
	warnIfNoAdministrator(ctx, cfg, st, testLogger(&before))
	if before.Len() == 0 {
		t.Error("a deployment with no administrator produced no warning")
	}

	if err := bootstrapAdmin(ctx, cfg, st, rec, false, 1); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	var after strings.Builder
	warnIfNoAdministrator(ctx, cfg, st, testLogger(&after))
	if after.Len() != 0 {
		t.Errorf("the warning is still printed once an administrator exists: %s", after.String())
	}
}

// TestKeyringAnchorFallsBackWhenNothingWasRotated covers the value the health
// report ages the keyring against.
func TestKeyringAnchorFallsBackWhenNothingWasRotated(t *testing.T) {
	cfg := testConfig(t)
	_, st := bootstrapStore(t)

	at := keyringAnchor(context.Background(), cfg, st, quietLogger())
	if at.IsZero() {
		t.Error("the anchor is the zero time, so the keyring would read as infinitely overdue")
	}
	if at.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("the anchor is in the future: %s", at)
	}
}

// TestServeStopsWhenItsContextIsCancelled is the shutdown path.
//
// A listener that outlived its context would keep a terminating process alive
// and, in a container, turn a rolling deploy into a hang that ends in SIGKILL.
func TestServeStopsWhenItsContextIsCancelled(t *testing.T) {
	cfg := testConfig(t)
	cfg.Server.Addr = "127.0.0.1:0"
	_, st := bootstrapStore(t)
	rec := audit.NewRecorder(st, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), rec, quietLogger())
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve reported %v on a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return within ten seconds of its context being cancelled")
	}
}

// TestServeRefusesAnAddressItCannotBind reports rather than hanging.
func TestServeRefusesAnAddressItCannotBind(t *testing.T) {
	// Hold a port, then ask serve for the same one.
	held := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer held.Close()

	cfg := testConfig(t)
	cfg.Server.Addr = strings.TrimPrefix(held.URL, "http://")
	_, st := bootstrapStore(t)
	rec := audit.NewRecorder(st, quietLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := serve(ctx, cfg, http.NotFoundHandler(), rec, quietLogger()); err == nil {
		t.Error("serve bound an address that was already taken")
	}
}
