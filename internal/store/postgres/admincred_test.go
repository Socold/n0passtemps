//go:build integration

// The PostgreSQL half of the administrative credential store, asserting the
// same behaviour as internal/store/sqlite/admincred_test.go asserts of the
// other engine.
//
// It is a deliberate near-copy rather than a shared table of cases. make
// migrate-check already holds the two schemas to each other, and this holds the
// two implementations to each other, which is the pairing that matters: the
// statements differ between the engines -- one takes a lease and the other an
// advisory lock, one counts RowsAffected and the other a command tag -- so a
// behaviour that is identical here is identical because both were written to
// be, not because one file ran twice.

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// The administrative credential table is the one that separates an operator's
// authenticator from a subject's. ADR 0017 makes the point that getting that
// separation wrong in one direction turns every enrolled user into an
// administrator, and this file is the store half of holding it: the table has
// its own uniqueness, its own challenges, and a counter that advances under the
// same compare-and-swap as the subject side.

const (
	adminCredTenant = "acme"
	adminCredToken  = "tok-console"
)

var adminCredNow = time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

// newAdminCredStore opens a migrated database holding one tenant and one
// administrative token for the credentials to hang from.
func newAdminCredStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	seedTenant(t, s, adminCredTenant)
	seedAdminToken(t, s, adminCredTenant, adminCredToken, store.RoleFull, nil)
	return s
}

// adminCred builds a credential with the required fields filled in.
func adminCred(id string, credentialID []byte, createdAt time.Time) *store.AdminCredential {
	return &store.AdminCredential{
		ID:           id,
		TenantID:     adminCredTenant,
		AdminTokenID: adminCredToken,
		CredentialID: credentialID,
		PublicKey:    []byte("public-key-" + id),
		RPID:         "console.example",
		CreatedAt:    createdAt,
	}
}

func mustCreateAdminCred(t *testing.T, s *Store, c *store.AdminCredential) {
	t.Helper()
	if err := s.CreateAdminCredential(context.Background(), c); err != nil {
		t.Fatalf("create administrative credential %s: %v", c.ID, err)
	}
}

// TestCreateAdminCredentialRequiresItsIdentifiers checks the refusals that
// happen before any statement runs.
//
// They are worth a test because each one is a row the table would otherwise
// accept and nothing downstream could interpret: a credential with no public
// key verifies no assertion, and one with no relying party matches no ceremony.
func TestCreateAdminCredentialRequiresItsIdentifiers(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()

	for name, mutate := range map[string]func(*store.AdminCredential){
		"no id":            func(c *store.AdminCredential) { c.ID = "" },
		"no tenant":        func(c *store.AdminCredential) { c.TenantID = "" },
		"no token":         func(c *store.AdminCredential) { c.AdminTokenID = "" },
		"no credential id": func(c *store.AdminCredential) { c.CredentialID = nil },
		"no public key":    func(c *store.AdminCredential) { c.PublicKey = nil },
		"no relying party": func(c *store.AdminCredential) { c.RPID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := adminCred("cred-1", []byte("cid-1"), adminCredNow)
			mutate(c)
			if err := s.CreateAdminCredential(ctx, c); err == nil {
				t.Fatal("accepted a credential with a required field missing")
			}
		})
	}
}

// TestCreateAdminCredentialFillsTheDefaults pins the two fields the store
// completes rather than demands.
func TestCreateAdminCredentialFillsTheDefaults(t *testing.T) {
	s := newAdminCredStore(t)

	c := adminCred("cred-1", []byte("cid-1"), time.Time{})
	mustCreateAdminCred(t, s, c)

	if c.AttestationType != store.AttestationNone {
		t.Errorf("attestation_type = %q, want %q", c.AttestationType, store.AttestationNone)
	}
	if c.CreatedAt.IsZero() {
		t.Error("created_at was left zero; the row would sort before every other")
	}
}

// TestOneCredentialIdentifierPerRelyingParty is the uniqueness the comment on
// CreateAdminCredential describes.
//
// An assertion carries the credential identifier and nothing that says which
// enrolment it meant, so a second row under the same relying party would make
// the lookup ambiguous at exactly the moment it decides who is signing in.
func TestOneCredentialIdentifierPerRelyingParty(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()

	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-shared"), adminCredNow))

	dup := adminCred("cred-2", []byte("cid-shared"), adminCredNow)
	err := s.CreateAdminCredential(ctx, dup)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second enrolment of the same credential id = %v, want ErrConflict", err)
	}

	// The same identifier under a different relying party is a different
	// deployment's authenticator and is allowed.
	other := adminCred("cred-3", []byte("cid-shared"), adminCredNow)
	other.RPID = "other.example"
	mustCreateAdminCred(t, s, other)
}

// TestGetAdminCredentialByIDIsScopedToTenantAndRelyingParty checks the lookup
// the assertion path uses.
func TestGetAdminCredentialByIDIsScopedToTenantAndRelyingParty(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))

	got, err := s.GetAdminCredentialByID(ctx, adminCredTenant, "console.example", []byte("cid-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.ID != "cred-1" {
		t.Errorf("id = %q, want cred-1", got.ID)
	}

	if _, err := s.GetAdminCredentialByID(ctx, "other-tenant", "console.example", []byte("cid-1")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant's lookup = %v, want ErrNotFound", err)
	}
	if _, err := s.GetAdminCredentialByID(ctx, adminCredTenant, "other.example", []byte("cid-1")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another relying party's lookup = %v, want ErrNotFound", err)
	}
	if _, err := s.GetAdminCredentialByID(ctx, adminCredTenant, "console.example", nil); err == nil {
		t.Error("an empty credential id was accepted as a lookup key")
	}
}

// TestGetAdminCredentialStillReturnsAWithdrawnOne is the behaviour its comment
// promises: the withdrawal form has to tell a credential that is already gone
// from one that never existed.
func TestGetAdminCredentialStillReturnsAWithdrawnOne(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))

	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "lost", adminCredNow); err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back a withdrawn credential: %v", err)
	}
	if !got.Revoked() {
		t.Error("the credential reads as active after withdrawal")
	}
	if got.RevokedReason != "lost" {
		t.Errorf("revoked_reason = %q, want \"lost\"", got.RevokedReason)
	}
	if _, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-absent"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown credential = %v, want ErrNotFound", err)
	}
}

// TestListAdminCredentialsOrdersAndFilters covers the listing the console draws
// from.
func TestListAdminCredentialsOrdersAndFilters(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()

	mustCreateAdminCred(t, s, adminCred("cred-b", []byte("cid-b"), adminCredNow.Add(time.Hour)))
	mustCreateAdminCred(t, s, adminCred("cred-a", []byte("cid-a"), adminCredNow))
	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-b", "rotated", adminCredNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	active, err := s.ListAdminCredentials(ctx, adminCredTenant, adminCredToken, false)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 1 || active[0].ID != "cred-a" {
		t.Fatalf("active listing = %v, want only cred-a", ids(active))
	}

	all, err := s.ListAdminCredentials(ctx, adminCredTenant, adminCredToken, true)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	// Ordered by creation, so the earlier credential comes first whichever
	// order the rows were written in.
	if got := ids(all); len(got) != 2 || got[0] != "cred-a" || got[1] != "cred-b" {
		t.Errorf("full listing = %v, want [cred-a cred-b]", got)
	}

	none, err := s.ListAdminCredentials(ctx, "other-tenant", adminCredToken, true)
	if err != nil {
		t.Fatalf("list for another tenant: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("another tenant sees %d credentials", len(none))
	}
}

// TestCountActiveAdminCredentialsExcludesWithdrawn is what stands between an
// operator and withdrawing their own last authenticator.
func TestCountActiveAdminCredentialsExcludesWithdrawn(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))
	mustCreateAdminCred(t, s, adminCred("cred-2", []byte("cid-2"), adminCredNow))

	n, err := s.CountActiveAdminCredentials(ctx, adminCredTenant, adminCredToken)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}

	if err = s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "lost", adminCredNow); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if n, err = s.CountActiveAdminCredentials(ctx, adminCredTenant, adminCredToken); err != nil || n != 1 {
		t.Fatalf("count after withdrawal = %d (%v), want 1", n, err)
	}
}

// TestWithdrawalKeepsTheFirstReason is the conditional update its comment
// describes.
//
// A second withdrawal overwriting the first would replace the reason somebody
// wrote at the time with whatever the repeat said, and the original is the one
// worth keeping.
func TestWithdrawalKeepsTheFirstReason(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))

	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "stolen at the conference", adminCredNow); err != nil {
		t.Fatalf("first withdrawal: %v", err)
	}
	err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "tidying up", adminCredNow.Add(time.Hour))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second withdrawal = %v, want ErrNotFound", err)
	}

	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.RevokedReason != "stolen at the conference" {
		t.Errorf("revoked_reason = %q; the repeat overwrote the original", got.RevokedReason)
	}
	if !got.RevokedAt.Equal(adminCredNow) {
		t.Errorf("revoked_at = %s, want the first withdrawal's time", got.RevokedAt)
	}

	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-absent", "x", adminCredNow); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("withdrawing an unknown credential = %v, want ErrNotFound", err)
	}
}

// TestTouchAdminCredentialRefusesAWithdrawnOne keeps last_used_at meaning what
// it says.
func TestTouchAdminCredentialRefusesAWithdrawnOne(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))

	used := adminCredNow.Add(time.Minute)
	if err := s.TouchAdminCredential(ctx, adminCredTenant, "cred-1", used); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Fatalf("last_used_at = %v, want %s", got.LastUsedAt, used)
	}

	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "lost", adminCredNow); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if err := s.TouchAdminCredential(ctx, adminCredTenant, "cred-1", used.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("touching a withdrawn credential = %v, want ErrNotFound", err)
	}
}

// TestCloneWarningIsRecordedEvenOnAWithdrawnCredential is deliberate and worth
// pinning, because it is the one update here that does not filter on
// revoked_at.
//
// The warning is evidence that two copies of a private key were in use. An
// assertion that arrives after the credential was withdrawn is exactly when
// that evidence matters most, and a filter would drop it.
func TestCloneWarningIsRecordedEvenOnAWithdrawnCredential(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))
	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "lost", adminCredNow); err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	if err := s.MarkAdminCredentialCloneWarning(ctx, adminCredTenant, "cred-1"); err != nil {
		t.Fatalf("mark clone warning: %v", err)
	}
	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.CloneWarning {
		t.Error("clone_warning was not recorded on a withdrawn credential")
	}

	if err := s.MarkAdminCredentialCloneWarning(ctx, adminCredTenant, "cred-absent"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("marking an unknown credential = %v, want ErrNotFound", err)
	}
}

// TestAdvanceAdminSignCountIsACompareAndSwap is the replay protection.
//
// The comment on the method says the condition has to be evaluated by the
// database while it holds the write lock, because two requests replaying one
// captured assertion would otherwise both read the stored counter, both find it
// acceptable and both succeed. These are the cases that would make that true.
func TestAdvanceAdminSignCountIsACompareAndSwap(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))

	used := adminCredNow.Add(time.Minute)
	if err := s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-1", 0, 1, used); err != nil {
		t.Fatalf("first advance: %v", err)
	}

	// The same call again: the stored counter has moved, so the expected
	// predecessor no longer matches. This is the replay.
	err := s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-1", 0, 1, used)
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("replayed advance = %v, want ErrStaleWrite", err)
	}

	// A counter that does not move forward is refused before the database is
	// touched at all.
	if err = s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-1", 1, 1, used); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("non-advancing counter = %v, want ErrStaleWrite", err)
	}
	if err = s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-1", 5, 4, used); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("decreasing counter = %v, want ErrStaleWrite", err)
	}

	// An unknown credential is distinguished from a stale one, because the two
	// call for different audit entries.
	if err = s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-absent", 0, 1, used); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown credential = %v, want ErrNotFound", err)
	}

	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.SignCount != 1 {
		t.Errorf("sign_count = %d after one accepted advance and three refusals, want 1", got.SignCount)
	}
}

// TestAdvanceAdminSignCountRefusesAWithdrawnCredential closes the route a
// withdrawal is supposed to close.
func TestAdvanceAdminSignCountRefusesAWithdrawnCredential(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	mustCreateAdminCred(t, s, adminCred("cred-1", []byte("cid-1"), adminCredNow))
	if err := s.RevokeAdminCredential(ctx, adminCredTenant, "cred-1", "lost", adminCredNow); err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	err := s.AdvanceAdminCredentialSignCount(ctx, adminCredTenant, "cred-1", 0, 1, adminCredNow)
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Fatalf("advance on a withdrawn credential = %v, want ErrStaleWrite", err)
	}
	got, err := s.GetAdminCredential(ctx, adminCredTenant, "cred-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.SignCount != 0 {
		t.Errorf("sign_count = %d; a withdrawn credential's counter moved", got.SignCount)
	}
}

// TestCreateAdminChallengeRequiresItsFields covers the refusals before the
// insert.
func TestCreateAdminChallengeRequiresItsFields(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()

	for name, mutate := range map[string]func(*store.AdminChallenge){
		"no id":        func(c *store.AdminChallenge) { c.ID = "" },
		"no tenant":    func(c *store.AdminChallenge) { c.TenantID = "" },
		"no challenge": func(c *store.AdminChallenge) { c.Challenge = nil },
		"no expiry":    func(c *store.AdminChallenge) { c.ExpiresAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := adminChallenge("chal-1", adminCredNow)
			mutate(c)
			if err := s.CreateAdminChallenge(ctx, c); err == nil {
				t.Fatal("accepted a challenge with a required field missing")
			}
		})
	}
}

// TestConsumeAdminChallengeIsSingleUse is the anti-replay on the ceremony
// itself.
func TestConsumeAdminChallengeIsSingleUse(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	if err := s.CreateAdminChallenge(ctx, adminChallenge("chal-1", adminCredNow)); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	at := adminCredNow.Add(time.Minute)
	got, err := s.ConsumeAdminChallenge(ctx, adminCredTenant, "chal-1", at)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ConsumedAt == nil || !got.ConsumedAt.Equal(at) {
		t.Errorf("consumed_at = %v, want %s", got.ConsumedAt, at)
	}
	if got.Ceremony != store.CeremonyAssertion {
		t.Errorf("ceremony = %q, want %q", got.Ceremony, store.CeremonyAssertion)
	}

	if _, err := s.ConsumeAdminChallenge(ctx, adminCredTenant, "chal-1", at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second consumption = %v, want ErrNotFound", err)
	}
}

// TestConsumeAdminChallengeRefusesAnExpiredOne, and refuses it the same way it
// refuses an unknown one.
//
// The method's comment says it does not distinguish an unknown challenge from
// an expired or already spent one, which is the same refusal the subject side
// gives, and this pins that they stay indistinguishable.
func TestConsumeAdminChallengeRefusesAnExpiredOne(t *testing.T) {
	s := newAdminCredStore(t)
	ctx := context.Background()
	if err := s.CreateAdminChallenge(ctx, adminChallenge("chal-1", adminCredNow)); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	tooLate := adminCredNow.Add(2 * time.Hour)
	_, expired := s.ConsumeAdminChallenge(ctx, adminCredTenant, "chal-1", tooLate)
	_, unknown := s.ConsumeAdminChallenge(ctx, adminCredTenant, "chal-absent", adminCredNow)
	_, otherTenant := s.ConsumeAdminChallenge(ctx, "other-tenant", "chal-1", adminCredNow)

	for name, err := range map[string]error{
		"expired": expired, "unknown": unknown, "another tenant": otherTenant,
	} {
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s challenge = %v, want ErrNotFound", name, err)
		}
	}
}

// adminChallenge builds an assertion challenge valid for an hour.
func adminChallenge(id string, createdAt time.Time) *store.AdminChallenge {
	return &store.AdminChallenge{
		ID:           id,
		TenantID:     adminCredTenant,
		AdminTokenID: adminCredToken,
		Ceremony:     store.CeremonyAssertion,
		Challenge:    []byte("challenge-bytes-" + id),
		RPID:         "console.example",
		SessionData:  []byte(`{"session":"data"}`),
		CreatedAt:    createdAt,
		ExpiresAt:    createdAt.Add(time.Hour),
	}
}

// ids reduces a listing to the identifiers, so a failure prints something
// readable instead of a slice of pointers.
func ids(creds []*store.AdminCredential) []string {
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.ID)
	}
	return out
}
