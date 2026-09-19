package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// ticketNow is the instant the ticket tests treat as the present. Every store
// method takes its instant as an argument, so nothing here depends on the wall
// clock.
var ticketNow = time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)

func ticket(tenantID, subjectID, id, selector string, createdAt time.Time, ttl time.Duration) *store.EnrolmentTicket {
	return &store.EnrolmentTicket{
		ID:           id,
		TenantID:     tenantID,
		SubjectID:    subjectID,
		Selector:     selector,
		VerifierHash: "$argon2id$hash-for-" + id,
		IssuedBy:     "key-1",
		Reason:       "lost every authenticator",
		CreatedAt:    createdAt,
		ExpiresAt:    createdAt.Add(ttl),
	}
}

func mustTicket(t *testing.T, s *Store, tenantID, selector string) *store.EnrolmentTicket {
	t.Helper()
	got, err := s.GetEnrolmentTicketBySelector(context.Background(), tenantID, selector)
	if err != nil {
		t.Fatalf("get ticket by selector %s: %v", selector, err)
	}
	return got
}

func TestEnrolmentTicketRoundTrips(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	want := ticket("tenant-a", "subject-1", "ticket-1", "AAAAAA", ticketNow, time.Hour)
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1", want); err != nil {
		t.Fatalf("replace: %v", err)
	}

	got := mustTicket(t, s, "tenant-a", "AAAAAA")
	if got.ID != want.ID || got.SubjectID != "subject-1" || got.VerifierHash != want.VerifierHash {
		t.Fatalf("round trip lost a field: %+v", got)
	}
	if got.IssuedBy != "key-1" {
		t.Errorf("issued_by = %q, want key-1; without it nobody can be asked why a ticket exists", got.IssuedBy)
	}
	if got.Reason != "lost every authenticator" {
		t.Errorf("reason = %q", got.Reason)
	}
	if !got.ExpiresAt.Equal(ticketNow.Add(time.Hour)) {
		t.Errorf("expires_at = %s, want %s", got.ExpiresAt, ticketNow.Add(time.Hour))
	}
	if got.ConsumedAt != nil || got.RevokedAt != nil || got.ConsumedCredentialID != "" {
		t.Errorf("a fresh ticket is not clean: %+v", got)
	}
	if !got.Redeemable(ticketNow) {
		t.Error("a fresh ticket is not redeemable")
	}
}

// TestIssuingASecondTicketRevokesTheFirst is the one-live-ticket invariant.
//
// Two live tickets double the window in which an intercepted one can be
// redeemed, and reissuing after a failed delivery is exactly when the first is
// most likely to be in the wrong hands.
func TestIssuingASecondTicketRevokesTheFirst(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	first := ticket("tenant-a", "subject-1", "ticket-1", "AAAAAA", ticketNow, time.Hour)
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1", first); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := ticket("tenant-a", "subject-1", "ticket-2", "BBBBBB", ticketNow.Add(time.Minute), time.Hour)
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1", second); err != nil {
		t.Fatalf("second: %v", err)
	}

	old := mustTicket(t, s, "tenant-a", "AAAAAA")
	if old.RevokedAt == nil {
		t.Fatal("the superseded ticket is still live, so the subject has two ways in")
	}
	if old.Redeemable(ticketNow.Add(2 * time.Minute)) {
		t.Error("the superseded ticket reports itself redeemable")
	}
	if fresh := mustTicket(t, s, "tenant-a", "BBBBBB"); fresh.RevokedAt != nil {
		t.Error("the replacement was revoked along with the one it replaced")
	}

	// The superseded row survives. It is the evidence that a ticket was issued
	// and withdrawn, and a redemption against it is then refused by its state
	// rather than by a missing row.
	if n := countRows(t, s, `SELECT COUNT(*) FROM enrolment_tickets WHERE tenant_id = ?`, "tenant-a"); n != 2 {
		t.Errorf("%d ticket rows, want 2; the superseded one must not be deleted", n)
	}

	// A consumed ticket is not live either, so a third issuance leaves the
	// consumed record untouched.
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "ticket-2", "cred-1", ticketNow.Add(2*time.Minute)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	third := ticket("tenant-a", "subject-1", "ticket-3", "CCCCCC", ticketNow.Add(3*time.Minute), time.Hour)
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1", third); err != nil {
		t.Fatalf("third: %v", err)
	}
	consumed := mustTicket(t, s, "tenant-a", "BBBBBB")
	if consumed.RevokedAt != nil {
		t.Error("issuing overwrote the record of a consumed ticket")
	}
	if consumed.ConsumedCredentialID != "cred-1" {
		t.Errorf("consumed_credential_id = %q, want cred-1", consumed.ConsumedCredentialID)
	}
}

func TestConsumeEnrolmentTicketRecordsTheCredential(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1",
		ticket("tenant-a", "subject-1", "ticket-1", "AAAAAA", ticketNow, time.Hour)); err != nil {
		t.Fatal(err)
	}

	at := ticketNow.Add(5 * time.Minute)
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "ticket-1", "cred-7", at); err != nil {
		t.Fatalf("consume: %v", err)
	}

	got := mustTicket(t, s, "tenant-a", "AAAAAA")
	if got.ConsumedAt == nil || !got.ConsumedAt.Equal(at) {
		t.Fatalf("consumed_at = %v, want %s", got.ConsumedAt, at)
	}
	if got.ConsumedCredentialID != "cred-7" {
		t.Errorf("consumed_credential_id = %q, want cred-7; an operator cannot otherwise "+
			"see what a ticket was used for", got.ConsumedCredentialID)
	}

	// A second consumption is the losing side of a race or a replay.
	err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "ticket-1", "cred-8", at.Add(time.Second))
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Fatalf("second consumption = %v, want ErrStaleWrite", err)
	}
	if again := mustTicket(t, s, "tenant-a", "AAAAAA"); again.ConsumedCredentialID != "cred-7" {
		t.Error("a losing consumption overwrote the winner's credential")
	}
}

// TestConsumeEnrolmentTicketRefusesAfterExpiryAndRevocation checks that the
// conditional update carries the whole policy, not only single use.
func TestConsumeEnrolmentTicketRefusesAfterExpiryAndRevocation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedSubject(t, s, "tenant-a", "subject-2", "ref-2")

	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1",
		ticket("tenant-a", "subject-1", "expired", "AAAAAA", ticketNow, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "expired", "cred-1",
		ticketNow.Add(time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		// The condition is expires_at > at, so the expiry instant itself is
		// already too late.
		t.Errorf("consuming at the expiry = %v, want ErrStaleWrite", err)
	}
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "expired", "cred-1",
		ticketNow.Add(2*time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("consuming an expired ticket = %v, want ErrStaleWrite", err)
	}

	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-2",
		ticket("tenant-a", "subject-2", "revoked", "BBBBBB", ticketNow, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrolmentTicket(ctx, "tenant-a", "revoked", ticketNow.Add(time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "revoked", "cred-1",
		ticketNow.Add(2*time.Minute)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("consuming a revoked ticket = %v, want ErrStaleWrite", err)
	}

	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "no-such-ticket", "cred-1", ticketNow); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("consuming an unknown ticket = %v, want ErrNotFound", err)
	}

	// Consuming without naming the credential is refused, because the row would
	// then record a redemption nobody can account for. The schema's pairing
	// check says the same thing; this is the earlier of the two refusals.
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "revoked", "", ticketNow); err == nil {
		t.Error("a consumption with no credential was accepted")
	}
}

func TestRevokeEnrolmentTicketIsConditional(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1",
		ticket("tenant-a", "subject-1", "ticket-1", "AAAAAA", ticketNow, time.Hour)); err != nil {
		t.Fatal(err)
	}

	at := ticketNow.Add(time.Minute)
	if err := s.RevokeEnrolmentTicket(ctx, "tenant-a", "ticket-1", at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got := mustTicket(t, s, "tenant-a", "AAAAAA")
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
		t.Fatalf("revoked_at = %v, want %s", got.RevokedAt, at)
	}

	if err := s.RevokeEnrolmentTicket(ctx, "tenant-a", "ticket-1", at.Add(time.Minute)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("revoking twice = %v, want ErrStaleWrite", err)
	}
	if again := mustTicket(t, s, "tenant-a", "AAAAAA"); !again.RevokedAt.Equal(at) {
		t.Error("the second revocation moved the timestamp of the first")
	}
	if err := s.RevokeEnrolmentTicket(ctx, "tenant-a", "no-such-ticket", at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoking an unknown ticket = %v, want ErrNotFound", err)
	}

	// A consumed ticket keeps the evidence of what it produced; revocation must
	// not overwrite it.
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1",
		ticket("tenant-a", "subject-1", "ticket-2", "BBBBBB", at, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "ticket-2", "cred-2", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrolmentTicket(ctx, "tenant-a", "ticket-2", at.Add(2*time.Minute)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("revoking a consumed ticket = %v, want ErrStaleWrite", err)
	}
	if consumed := mustTicket(t, s, "tenant-a", "BBBBBB"); consumed.RevokedAt != nil {
		t.Error("revoking a consumed ticket overwrote its consumption record")
	}
}

// TestEnrolmentTicketsAreTenantIsolated checks that a selector resolves only
// inside the tenant that issued it, and that neither conditional update reaches
// across.
func TestEnrolmentTicketsAreTenantIsolated(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		seedTenant(t, s, tenant)
		seedSubject(t, s, tenant, "subject-"+tenant, "ref-"+tenant)
	}

	// The same selector in both tenants, which the per-tenant unique index
	// permits and a global one would not.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		err := s.ReplaceEnrolmentTicket(ctx, tenant, "subject-"+tenant,
			ticket(tenant, "subject-"+tenant, "ticket-"+tenant, "AAAAAA", ticketNow, time.Hour))
		if err != nil {
			t.Fatalf("%s: %v", tenant, err)
		}
	}

	a := mustTicket(t, s, "tenant-a", "AAAAAA")
	if a.ID != "ticket-tenant-a" {
		t.Fatalf("tenant-a resolved %q", a.ID)
	}
	b := mustTicket(t, s, "tenant-b", "AAAAAA")
	if b.ID != "ticket-tenant-b" {
		t.Fatalf("tenant-b resolved %q", b.ID)
	}

	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-b", "ticket-tenant-a", "cred-1", ticketNow); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("one tenant consumed another's ticket: %v", err)
	}
	if err := s.RevokeEnrolmentTicket(ctx, "tenant-b", "ticket-tenant-a", ticketNow); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("one tenant revoked another's ticket: %v", err)
	}
	if still := mustTicket(t, s, "tenant-a", "AAAAAA"); !still.Redeemable(ticketNow) {
		t.Error("tenant-a's ticket was disturbed by tenant-b")
	}

	// Replacing in one tenant must not revoke the other's live ticket, even
	// though the two subjects share nothing but a selector.
	err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-tenant-a",
		ticket("tenant-a", "subject-tenant-a", "ticket-a2", "CCCCCC", ticketNow, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if other := mustTicket(t, s, "tenant-b", "AAAAAA"); other.RevokedAt != nil {
		t.Error("issuing in one tenant revoked another tenant's ticket")
	}
}

func TestDeleteExpiredEnrolmentTicketsSweepsEveryTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		seedTenant(t, s, tenant)
		seedSubject(t, s, tenant, "subject-"+tenant, "ref-"+tenant)
	}

	// One short-lived ticket per tenant, plus a long-lived one that must
	// survive the sweep.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if err := s.ReplaceEnrolmentTicket(ctx, tenant, "subject-"+tenant,
			ticket(tenant, "subject-"+tenant, "short-"+tenant, "S"+tenant, ticketNow, time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	seedSubject(t, s, "tenant-a", "subject-long", "ref-long")
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-long",
		ticket("tenant-a", "subject-long", "long", "LLLLLL", ticketNow, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A consumed ticket is swept once it is past its expiry, like everything
	// else: the durable record of a redemption is the audit log.
	if err := s.ConsumeEnrolmentTicket(ctx, "tenant-a", "short-tenant-a", "cred-1", ticketNow); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteExpiredEnrolmentTickets(ctx, ticketNow.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("sweep removed %d tickets, want 2 across both tenants", n)
	}
	if got := countRows(t, s, `SELECT COUNT(*) FROM enrolment_tickets`); got != 1 {
		t.Errorf("%d tickets left, want only the long-lived one", got)
	}
	if _, err := s.GetEnrolmentTicketBySelector(ctx, "tenant-a", "LLLLLL"); err != nil {
		t.Errorf("the unexpired ticket was swept: %v", err)
	}
}

// TestPurgingASubjectRemovesItsTickets checks the cascade. A ticket left behind
// after an erasure would be a live secret for an account that no longer exists.
func TestPurgingASubjectRemovesItsTickets(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	if err := s.ReplaceEnrolmentTicket(ctx, "tenant-a", "subject-1",
		ticket("tenant-a", "subject-1", "ticket-1", "AAAAAA", ticketNow, time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := s.PurgeSubject(ctx, "tenant-a", "subject-1"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := countRows(t, s, `SELECT COUNT(*) FROM enrolment_tickets`); got != 0 {
		t.Errorf("%d tickets survived the purge of their subject", got)
	}
}
