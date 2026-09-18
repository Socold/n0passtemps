package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// rotationNow is the instant the rotation tests treat as the present. The store
// takes every instant as an argument, so nothing here depends on the wall
// clock.
var rotationNow = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func seedAPIKey(t *testing.T, s *Store, tenantID, id string, expiresAt *time.Time) {
	t.Helper()
	err := s.CreateAPIKey(context.Background(), &store.APIKey{
		ID: id, TenantID: tenantID, Name: "billing", Selector: "sel-" + id,
		VerifierHash: "digest-" + id, Scopes: []string{"totp", "webauthn"},
		CreatedAt: rotationNow.Add(-90 * 24 * time.Hour), ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("create api key %s: %v", id, err)
	}
}

func seedAdminToken(t *testing.T, s *Store, tenantID, id string, role store.Role, expiresAt *time.Time) {
	t.Helper()
	err := s.CreateAdminToken(context.Background(), &store.AdminToken{
		ID: id, TenantID: tenantID, Name: "on-call", Selector: "sel-" + id,
		VerifierHash: "digest-" + id, Role: role,
		CreatedAt: rotationNow.Add(-90 * 24 * time.Hour), ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("create admin token %s: %v", id, err)
	}
}

func apiKeySuccessor(tenantID, id string) *store.APIKey {
	return &store.APIKey{
		ID: id, TenantID: tenantID, Name: "billing", Selector: "sel-" + id,
		VerifierHash: "digest-" + id, Scopes: []string{"totp", "webauthn"},
		CreatedAt: rotationNow, CreatedBy: "admin-1",
	}
}

func adminTokenSuccessor(tenantID, id string, role store.Role) *store.AdminToken {
	return &store.AdminToken{
		ID: id, TenantID: tenantID, Name: "on-call", Selector: "sel-" + id,
		VerifierHash: "digest-" + id, Role: role,
		CreatedAt: rotationNow, CreatedBy: "old-token",
	}
}

func mustAPIKey(t *testing.T, s *Store, id string) *store.APIKey {
	t.Helper()
	k, err := s.GetAPIKeyBySelector(context.Background(), "sel-"+id)
	if err != nil {
		t.Fatalf("read api key %s: %v", id, err)
	}
	return k
}

func mustAdminToken(t *testing.T, s *Store, id string) *store.AdminToken {
	t.Helper()
	tok, err := s.GetAdminTokenBySelector(context.Background(), "sel-"+id)
	if err != nil {
		t.Fatalf("read admin token %s: %v", id, err)
	}
	return tok
}

// TestRotateAPIKeyBoundsThePredecessor is the ordinary case: a key with no
// expiry gains one, and the successor exists beside it.
func TestRotateAPIKeyBoundsThePredecessor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedAPIKey(t, s, "tenant-a", "old", nil)

	cutoff := rotationNow.Add(24 * time.Hour)
	if err := s.RotateAPIKey(ctx, "tenant-a", "old", apiKeySuccessor("tenant-a", "new"), cutoff); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	old := mustAPIKey(t, s, "old")
	if old.ExpiresAt == nil || !old.ExpiresAt.Equal(cutoff) {
		t.Errorf("predecessor expires_at = %v, want %v", old.ExpiresAt, cutoff)
	}
	if old.RevokedAt != nil {
		t.Error("the predecessor was revoked; rotation bounds it, and revocation is a separate act")
	}
	// Both work inside the window and only the successor after it.
	if !old.Usable(cutoff.Add(-time.Second)) || old.Usable(cutoff) {
		t.Error("the predecessor is not usable exactly up to the cutoff")
	}

	fresh := mustAPIKey(t, s, "new")
	if fresh.Name != "billing" || len(fresh.Scopes) != 2 || fresh.CreatedBy != "admin-1" {
		t.Errorf("successor = %+v, want the name, scopes and creator it was given", fresh)
	}
	if fresh.ExpiresAt != nil {
		t.Errorf("successor expires_at = %v, want none; it must not inherit the cutoff", fresh.ExpiresAt)
	}
	if !fresh.Usable(cutoff.Add(365 * 24 * time.Hour)) {
		t.Error("the successor stopped working")
	}
}

// TestRotateNeverExtendsACredential checks both directions of the expiry rule.
//
// Rotating a key that is due to die in an hour must not give it a day. That
// would make rotation a way to outlive an expiry, available to anyone holding
// the rotate permission and nothing else.
func TestRotateNeverExtendsACredential(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	sooner := rotationNow.Add(time.Hour)
	later := rotationNow.Add(30 * 24 * time.Hour)
	seedAPIKey(t, s, "tenant-a", "dies-soon", &sooner)
	seedAPIKey(t, s, "tenant-a", "dies-late", &later)
	cutoff := rotationNow.Add(24 * time.Hour)

	if err := s.RotateAPIKey(ctx, "tenant-a", "dies-soon", apiKeySuccessor("tenant-a", "new-1"), cutoff); err != nil {
		t.Fatalf("rotate a key that expires sooner: %v", err)
	}
	if got := mustAPIKey(t, s, "dies-soon").ExpiresAt; got == nil || !got.Equal(sooner) {
		t.Errorf("expires_at = %v, want the earlier %v kept", got, sooner)
	}
	// The successor is still minted: the rotation happened, the predecessor
	// merely had less time left than the grace offered.
	mustAPIKey(t, s, "new-1")

	if err := s.RotateAPIKey(ctx, "tenant-a", "dies-late", apiKeySuccessor("tenant-a", "new-2"), cutoff); err != nil {
		t.Fatalf("rotate a key that expires later: %v", err)
	}
	if got := mustAPIKey(t, s, "dies-late").ExpiresAt; got == nil || !got.Equal(cutoff) {
		t.Errorf("expires_at = %v, want it brought forward to %v", got, cutoff)
	}
}

// TestRotateRefusesAPredecessorThatCannotBeRotated covers the three ways a
// predecessor is not there, and that none of them leaves a successor behind.
func TestRotateRefusesAPredecessorThatCannotBeRotated(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")
	seedAPIKey(t, s, "tenant-a", "revoked", nil)
	seedAPIKey(t, s, "tenant-b", "foreign", nil)
	if err := s.RevokeAPIKey(ctx, "tenant-a", "revoked", rotationNow); err != nil {
		t.Fatal(err)
	}
	cutoff := rotationNow.Add(24 * time.Hour)

	for _, id := range []string{"revoked", "foreign", "never-existed"} {
		err := s.RotateAPIKey(ctx, "tenant-a", id, apiKeySuccessor("tenant-a", "new-for-"+id), cutoff)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("rotating %s = %v, want ErrNotFound", id, err)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM api_keys`); n != 2 {
		t.Errorf("%d api keys stored, want the 2 that were seeded; a refused rotation minted one", n)
	}
	// The other tenant's key must not have been touched by the attempt.
	if got := mustAPIKey(t, s, "foreign").ExpiresAt; got != nil {
		t.Errorf("a rotation in tenant-a set expires_at = %v on a key in tenant-b", got)
	}

	// A successor filed under another tenant is refused outright.
	seedAPIKey(t, s, "tenant-a", "live", nil)
	if err := s.RotateAPIKey(ctx, "tenant-a", "live", apiKeySuccessor("tenant-b", "smuggled"), cutoff); err == nil {
		t.Error("a successor in a different tenant was accepted")
	}
	if got := mustAPIKey(t, s, "live").ExpiresAt; got != nil {
		t.Errorf("the refused rotation still bounded the predecessor: %v", got)
	}
}

// TestRotateIsOneTransaction makes the insert fail after the update succeeded.
//
// If the two were separate statements the predecessor would now carry an
// expiry with no successor to take over, which is an outage with a timer on it.
func TestRotateIsOneTransaction(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedAPIKey(t, s, "tenant-a", "old", nil)
	seedAPIKey(t, s, "tenant-a", "bystander", nil)

	clash := apiKeySuccessor("tenant-a", "new")
	clash.Selector = "sel-bystander"
	err := s.RotateAPIKey(ctx, "tenant-a", "old", clash, rotationNow.Add(24*time.Hour))
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rotate with a clashing selector = %v, want ErrConflict", err)
	}
	if got := mustAPIKey(t, s, "old").ExpiresAt; got != nil {
		t.Errorf("predecessor expires_at = %v after a failed rotation, want it rolled back", got)
	}
}

// TestRotateAPIKeyWithNoGrace passes the present as the cutoff, which is what
// a grace of zero means.
func TestRotateAPIKeyWithNoGrace(t *testing.T) {
	s := newStore(t)
	seedTenant(t, s, "tenant-a")
	seedAPIKey(t, s, "tenant-a", "old", nil)

	if err := s.RotateAPIKey(context.Background(), "tenant-a", "old",
		apiKeySuccessor("tenant-a", "new"), rotationNow); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if mustAPIKey(t, s, "old").Usable(rotationNow) {
		t.Error("the predecessor still works at the instant of a rotation with no grace")
	}
	if !mustAPIKey(t, s, "new").Usable(rotationNow) {
		t.Error("the successor does not work")
	}

	if err := s.RotateAPIKey(context.Background(), "tenant-a", "new",
		apiKeySuccessor("tenant-a", "newer"), time.Time{}); err == nil {
		t.Error("a zero cutoff was accepted; it would expire the predecessor in year one")
	}
}

// TestRotateAdminToken mirrors the API key cases on the other table.
func TestRotateAdminToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sooner := rotationNow.Add(time.Hour)
	seedAdminToken(t, s, "tenant-a", "old", store.RoleAuditor, nil)
	seedAdminToken(t, s, "tenant-a", "dies-soon", store.RoleOperator, &sooner)
	seedAdminToken(t, s, "tenant-a", "revoked", store.RoleFull, nil)
	if err := s.RevokeAdminToken(ctx, "tenant-a", "revoked", rotationNow); err != nil {
		t.Fatal(err)
	}
	cutoff := rotationNow.Add(24 * time.Hour)

	if err := s.RotateAdminToken(ctx, "tenant-a", "old",
		adminTokenSuccessor("tenant-a", "new", store.RoleAuditor), cutoff); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := mustAdminToken(t, s, "old").ExpiresAt; got == nil || !got.Equal(cutoff) {
		t.Errorf("predecessor expires_at = %v, want %v", got, cutoff)
	}
	fresh := mustAdminToken(t, s, "new")
	if fresh.Role != store.RoleAuditor || fresh.ExpiresAt != nil || fresh.CreatedBy != "old-token" {
		t.Errorf("successor = %+v, want the same role, no expiry and the recorded creator", fresh)
	}

	if err := s.RotateAdminToken(ctx, "tenant-a", "dies-soon",
		adminTokenSuccessor("tenant-a", "new-2", store.RoleOperator), cutoff); err != nil {
		t.Fatalf("rotate a token that expires sooner: %v", err)
	}
	if got := mustAdminToken(t, s, "dies-soon").ExpiresAt; got == nil || !got.Equal(sooner) {
		t.Errorf("expires_at = %v, want the earlier %v kept", got, sooner)
	}

	before := countRows(t, s, `SELECT COUNT(*) FROM admin_tokens`)
	err := s.RotateAdminToken(ctx, "tenant-a", "revoked",
		adminTokenSuccessor("tenant-a", "new-3", store.RoleFull), cutoff)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("rotating a revoked token = %v, want ErrNotFound", err)
	}
	if err = s.RotateAdminToken(ctx, "tenant-a", "old",
		adminTokenSuccessor("tenant-a", "new-4", store.Role("admin_root")), cutoff); err == nil {
		t.Error("a successor with an unknown role was accepted")
	}
	if after := countRows(t, s, `SELECT COUNT(*) FROM admin_tokens`); after != before {
		t.Errorf("admin tokens went from %d to %d across two refused rotations", before, after)
	}

	// The count that guards the last administrator sees the successor at
	// once, so a rotation can never be the thing that leaves a role empty.
	n, err := s.CountAdminTokensByRole(ctx, "tenant-a", store.RoleAuditor, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("usable auditors after rotation = %d, want at least the successor", n)
	}
}
