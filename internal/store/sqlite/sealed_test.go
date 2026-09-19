package sqlite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

func seedTOTP(t *testing.T, s *Store, tenantID, subjectID, id string, sealed []byte, confirmed bool) {
	t.Helper()
	sec := &store.TOTPSecret{
		ID: id, TenantID: tenantID, SubjectID: subjectID,
		SecretSealed: sealed, Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}
	if confirmed {
		at := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
		sec.ConfirmedAt = &at
	}
	if err := s.CreateTOTPSecret(context.Background(), sec); err != nil {
		t.Fatalf("create totp secret %s: %v", id, err)
	}
}

// TestListSealedPages walks the subject references a few at a time.
//
// The walk has to visit every record exactly once across tenants. A page
// boundary that dropped or repeated a row would leave a record on the old key
// while the pass reported the version as unused, and the operator would then
// delete a key something still depends on.
func TestListSealedPages(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")

	want := map[string]string{}
	for i := 0; i < 7; i++ {
		tenant := "tenant-a"
		if i%2 == 1 {
			tenant = "tenant-b"
		}
		id := fmt.Sprintf("subject-%02d", i)
		seedSubject(t, s, tenant, id, fmt.Sprintf("ref-%02d", i))
		want[id] = tenant
	}

	// A subject with no sealed reference holds nothing to rewrap and must not
	// be listed.
	if _, err := s.UpsertSubject(ctx, &store.Subject{
		ID: "subject-unsealed", TenantID: "tenant-a", RefHMAC: []byte("ref-unsealed"),
	}); err != nil {
		t.Fatal(err)
	}

	// A subject pending erasure is listed: cancelling the erasure restores it,
	// and its reference has to be readable when that happens.
	if err := s.SoftDeleteSubject(ctx, "tenant-a", "subject-00", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	after, pages := "", 0
	for {
		page, err := s.ListSealed(ctx, store.SealedSubjectRef, after, 3)
		if err != nil {
			t.Fatalf("ListSealed: %v", err)
		}
		if len(page) == 0 {
			break
		}
		pages++
		for _, rec := range page {
			if seen[rec.ID] {
				t.Errorf("record %s was listed twice", rec.ID)
			}
			if rec.ID <= after {
				t.Errorf("record %s is not after the cursor %q", rec.ID, after)
			}
			seen[rec.ID] = true
			if len(rec.Sealed) == 0 {
				t.Errorf("record %s was listed with no sealed value", rec.ID)
			}
			// The caller rebuilds the binding context from these, so a walk
			// that returned the bytes without them could not open a thing.
			if rec.TenantID != want[rec.ID] {
				t.Errorf("record %s is listed under tenant %q, want %q", rec.ID, rec.TenantID, want[rec.ID])
			}
			if rec.SubjectID != "" {
				t.Errorf("record %s names subject %q; a subject is its own subject", rec.ID, rec.SubjectID)
			}
		}
		after = page[len(page)-1].ID
	}

	if pages != 3 {
		t.Errorf("walked %d pages, want 3 for seven records three at a time", pages)
	}
	if len(seen) != len(want) {
		t.Errorf("listed %d records, want %d: %v", len(seen), len(want), seen)
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("record %s was never listed", id)
		}
	}
}

// TestListSealedCarriesTheBindingIdentifiers checks the columns a rewrap pass
// needs to open a TOTP secret. Without the subject the record is bound to, the
// pass could read the bytes and never authenticate them.
func TestListSealedCarriesTheBindingIdentifiers(t *testing.T) {
	s := newStore(t)
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedTOTP(t, s, "tenant-a", "subject-1", "totp-1", []byte("sealed-live"), true)

	page, err := s.ListSealed(context.Background(), store.SealedTOTP, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 {
		t.Fatalf("ListSealed returned %d records, want 1", len(page))
	}
	if page[0].TenantID != "tenant-a" || page[0].SubjectID != "subject-1" {
		t.Errorf("record is listed under tenant %q subject %q, want tenant-a and subject-1",
			page[0].TenantID, page[0].SubjectID)
	}
}

// TestListSealedSkipsRevokedTOTP checks the one filter the TOTP walk applies. A
// revoked secret is never unsealed again, so it must not hold a key version in
// use for ever.
func TestListSealedSkipsRevokedTOTP(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedSubject(t, s, "tenant-a", "subject-2", "ref-2")

	seedTOTP(t, s, "tenant-a", "subject-1", "totp-live", []byte("sealed-live"), true)
	seedTOTP(t, s, "tenant-a", "subject-2", "totp-dead", []byte("sealed-dead"), true)
	if err := s.RevokeTOTPSecret(ctx, "tenant-a", "totp-dead", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	page, err := s.ListSealed(ctx, store.SealedTOTP, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "totp-live" {
		t.Fatalf("ListSealed = %+v, want only totp-live", page)
	}
	if !bytes.Equal(page[0].Sealed, []byte("sealed-live")) {
		t.Errorf("sealed value = %q", page[0].Sealed)
	}
}

// TestSealedKindIsAClosedSet guards the mapping from kind to table. The kind is
// a string underneath, and a value that did not come from the constants must
// be refused rather than find its way into a statement.
func TestSealedKindIsAClosedSet(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	hostile := store.SealedKind("subjects; DROP TABLE subjects")
	if _, err := s.ListSealed(ctx, hostile, "", 10); err == nil {
		t.Error("ListSealed accepted an unknown kind")
	}
	if err := s.ReplaceSealed(ctx, hostile, "id", []byte("a"), []byte("b")); err == nil {
		t.Error("ReplaceSealed accepted an unknown kind")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM subjects`); n != 0 {
		t.Errorf("subjects holds %d rows after a refused call", n)
	}
}

// TestReplaceSealedIsCompareAndSwap covers the race a rewrap pass runs against:
// the value it read being replaced before it writes.
func TestReplaceSealedIsCompareAndSwap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedTOTP(t, s, "tenant-a", "subject-1", "totp-1", []byte("old-totp"), true)

	for _, tc := range []struct {
		kind store.SealedKind
		id   string
		old  []byte
	}{
		{store.SealedSubjectRef, "subject-1", []byte("sealed-ref-1")},
		{store.SealedTOTP, "totp-1", []byte("old-totp")},
	} {
		if err := s.ReplaceSealed(ctx, tc.kind, tc.id, tc.old, []byte("new-value")); err != nil {
			t.Fatalf("%s: first replace: %v", tc.kind, err)
		}

		// The same call again presents bytes that are no longer stored. It
		// must lose rather than write over the newer value.
		err := s.ReplaceSealed(ctx, tc.kind, tc.id, tc.old, []byte("clobbered"))
		if !errors.Is(err, store.ErrStaleWrite) {
			t.Errorf("%s: replace with stale bytes = %v, want ErrStaleWrite", tc.kind, err)
		}

		page, err := s.ListSealed(ctx, tc.kind, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) != 1 || !bytes.Equal(page[0].Sealed, []byte("new-value")) {
			t.Errorf("%s: stored value = %+v, want new-value", tc.kind, page)
		}

		err = s.ReplaceSealed(ctx, tc.kind, "no-such-row", tc.old, []byte("x"))
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: replace on a missing row = %v, want ErrNotFound", tc.kind, err)
		}
	}
}

// TestRevokeAllCredentials checks the counts, that the revocation covers both
// factors, and that it stays inside the tenant and the subject it names.
func TestRevokeAllCredentials(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")

	seedSubject(t, s, "tenant-a", "victim", "ref-victim")
	seedSubject(t, s, "tenant-a", "bystander", "ref-bystander")
	seedSubject(t, s, "tenant-b", "foreign", "ref-foreign")

	seedCredential(t, s, "tenant-a", "victim", "cred-1", 0)
	seedCredential(t, s, "tenant-a", "victim", "cred-2", 0)
	seedCredential(t, s, "tenant-a", "victim", "cred-3", 0)
	seedCredential(t, s, "tenant-a", "bystander", "cred-4", 0)
	seedCredential(t, s, "tenant-b", "foreign", "cred-5", 0)
	seedTOTP(t, s, "tenant-a", "victim", "totp-victim", []byte("sealed-1"), true)
	seedTOTP(t, s, "tenant-a", "bystander", "totp-bystander", []byte("sealed-2"), true)
	seedTOTP(t, s, "tenant-b", "foreign", "totp-foreign", []byte("sealed-3"), true)

	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "victim", "batch-1", []*store.RecoveryCode{
		{ID: "code-1", Selector: "sel-1", VerifierHash: "h"},
		{ID: "code-2", Selector: "sel-2", VerifierHash: "h"},
	}); err != nil {
		t.Fatal(err)
	}

	// One credential was revoked earlier, for its own reason. The bulk
	// revocation must neither count it nor overwrite why it was revoked.
	first := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	if err := s.RevokeCredential(ctx, "tenant-a", "cred-1", "lost device", first); err != nil {
		t.Fatal(err)
	}

	// The right subject under the wrong tenant matches nothing.
	at := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	creds, totp, err := s.RevokeAllCredentials(ctx, "tenant-b", "victim", "incident", at)
	if err != nil {
		t.Fatalf("revoke across tenants: %v", err)
	}
	if creds != 0 || totp != 0 {
		t.Fatalf("revoke across tenants touched %d credentials and %d secrets, want none", creds, totp)
	}

	creds, totp, err = s.RevokeAllCredentials(ctx, "tenant-a", "victim", "incident", at)
	if err != nil {
		t.Fatalf("RevokeAllCredentials: %v", err)
	}
	if creds != 2 || totp != 1 {
		t.Errorf("revoked %d credentials and %d secrets, want 2 and 1", creds, totp)
	}

	n, err := s.CountActiveCredentials(ctx, "tenant-a", "victim")
	if err != nil || n != 0 {
		t.Errorf("victim has %d active credentials (%v), want 0", n, err)
	}
	if _, err = s.GetActiveTOTPSecret(ctx, "tenant-a", "victim"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("victim's totp secret after revocation = %v, want ErrNotFound", err)
	}

	earlier, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if earlier.RevokedReason != "lost device" || earlier.RevokedAt == nil || !earlier.RevokedAt.Equal(first) {
		t.Errorf("earlier revocation was overwritten: reason %q at %v", earlier.RevokedReason, earlier.RevokedAt)
	}
	latest, err := s.GetCredential(ctx, "tenant-a", "cred-2")
	if err != nil {
		t.Fatal(err)
	}
	if latest.RevokedReason != "incident" || latest.RevokedAt == nil || !latest.RevokedAt.Equal(at) {
		t.Errorf("bulk revocation recorded reason %q at %v", latest.RevokedReason, latest.RevokedAt)
	}

	// Everyone else is untouched.
	n, _ = s.CountActiveCredentials(ctx, "tenant-a", "bystander")
	if n != 1 {
		t.Errorf("bystander has %d active credentials, want 1", n)
	}
	if _, err = s.GetActiveTOTPSecret(ctx, "tenant-a", "bystander"); err != nil {
		t.Errorf("bystander's totp secret: %v", err)
	}
	n, _ = s.CountActiveCredentials(ctx, "tenant-b", "foreign")
	if n != 1 {
		t.Errorf("foreign subject has %d active credentials, want 1", n)
	}
	if _, err = s.GetActiveTOTPSecret(ctx, "tenant-b", "foreign"); err != nil {
		t.Errorf("foreign subject's totp secret: %v", err)
	}

	// Recovery codes are the way back in and are left alone.
	n, err = s.CountUnusedRecoveryCodes(ctx, "tenant-a", "victim")
	if err != nil || n != 2 {
		t.Errorf("victim has %d unused recovery codes (%v), want 2", n, err)
	}

	// A second call finds nothing left, and says so without failing.
	creds, totp, err = s.RevokeAllCredentials(ctx, "tenant-a", "victim", "again", at.Add(time.Minute))
	if err != nil || creds != 0 || totp != 0 {
		t.Errorf("second call = %d, %d, %v; want 0, 0, nil", creds, totp, err)
	}
}

// TestRevokeAllCredentialsCoversPendingTOTP covers an enrolment started from
// inside a compromised account. Left pending, it could be confirmed after the
// revocation and the attacker would hold a fresh factor.
func TestRevokeAllCredentialsCoversPendingTOTP(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "victim", "ref-victim")
	seedTOTP(t, s, "tenant-a", "victim", "totp-pending", []byte("sealed"), false)

	_, totp, err := s.RevokeAllCredentials(ctx, "tenant-a", "victim", "incident", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if totp != 1 {
		t.Errorf("revoked %d secrets, want the pending one", totp)
	}
	if _, err := s.GetPendingTOTPSecret(ctx, "tenant-a", "victim"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("pending secret after revocation = %v, want ErrNotFound", err)
	}
}
