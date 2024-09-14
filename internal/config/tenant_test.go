package config

import (
	"testing"

	"github.com/Socold/n0passtemps/internal/store"
)

// TestSystemTenantIDMatchesStore guards the duplicated constant.
//
// config cannot import store without making the dependency circular, so the
// reserved identifier is declared in both. If they ever diverge, a failed
// authentication would be audited under a tenant that configuration considers
// usable, and the reservation would stop meaning anything.
func TestSystemTenantIDMatchesStore(t *testing.T) {
	if SystemTenantID != store.SystemTenantID {
		t.Fatalf("config.SystemTenantID = %q but store.SystemTenantID = %q",
			SystemTenantID, store.SystemTenantID)
	}
}

func TestValidateRefusesReservedTenant(t *testing.T) {
	cfg := Default()
	cfg.Tenant.ID = SystemTenantID
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.Origins = []string{"https://example.com"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected the reserved tenant identifier to be refused")
	}
}

func TestValidateRefusesMalformedTenant(t *testing.T) {
	for _, id := range []string{"Default", "with space", "with/slash", "café"} {
		cfg := Default()
		cfg.Tenant.ID = id
		cfg.WebAuthn.RPID = "example.com"
		cfg.WebAuthn.Origins = []string{"https://example.com"}
		if err := cfg.Validate(); err == nil {
			t.Errorf("tenant.id %q was accepted", id)
		}
	}
}
