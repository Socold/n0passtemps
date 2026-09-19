package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
)

// withoutDualApproval is the harness tuning for the tests that exercise an
// operation itself rather than the queue in front of it.
func withoutDualApproval(c *config.Config) { c.Features.DualApproval = false }

// seedFactors gives a subject two WebAuthn credentials and a confirmed TOTP
// secret, written straight through the store. Driving a real registration
// ceremony would need an authenticator, and nothing under test here depends on
// how the factors came to exist.
func seedFactors(t *testing.T, h *harness, subjectID string) {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		id := uuid.NewString()
		err := h.store.CreateCredential(ctx, &store.Credential{
			ID:           id,
			TenantID:     h.cfg.TenantID(),
			SubjectID:    subjectID,
			CredentialID: []byte("cred-" + id),
			PublicKey:    []byte("cose-" + id),
			Transports:   []string{"internal"},
			RPID:         h.cfg.WebAuthn.RPID,
			CreatedAt:    h.clock.now(),
		})
		if err != nil {
			t.Fatalf("create credential: %v", err)
		}
	}

	confirmed := h.clock.now()
	err := h.store.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID: uuid.NewString(), TenantID: h.cfg.TenantID(), SubjectID: subjectID,
		SecretSealed: []byte("sealed-for-the-test"), Algorithm: "SHA1", Digits: 6,
		PeriodSeconds: 30, CreatedAt: confirmed, ConfirmedAt: &confirmed,
	})
	if err != nil {
		t.Fatalf("create totp secret: %v", err)
	}
}

// activeFactors reports what a subject can still authenticate with.
func activeFactors(t *testing.T, h *harness, subjectID string) (credentials int, totp bool) {
	t.Helper()
	ctx := context.Background()
	n, err := h.store.CountActiveCredentials(ctx, h.cfg.TenantID(), subjectID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.store.GetActiveTOTPSecret(ctx, h.cfg.TenantID(), subjectID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return n, err == nil
}

func newSubject(t *testing.T, h *harness, ref string) string {
	t.Helper()
	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": ref})
	return created.str(t, "subject_id")
}

// TestRevokeAllRevokesEveryFactor is the incident-response path with the
// approval queue off.
func TestRevokeAllRevokesEveryFactor(t *testing.T) {
	h := newHarness(t, withoutDualApproval)
	subjectID := newSubject(t, h, "user-1")
	seedFactors(t, h, subjectID)
	path := "/admin/v1/subjects/" + subjectID + "/credentials/revoke-all"
	full := h.admin[store.RoleFull]

	issued := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/recovery/reissue", full, nil)
	if issued.Status != http.StatusCreated {
		t.Fatalf("reissue = %d; body: %s", issued.Status, issued.Raw)
	}
	codes := int(issued.num(t, "count"))
	if codes == 0 {
		t.Fatal("no recovery codes were issued, so the test would prove nothing about them")
	}

	// A bulk revocation nobody can explain afterwards is refused, with or
	// without a body.
	for _, body := range []any{nil, map[string]any{"reason": "   "}} {
		if res := h.do(http.MethodPost, path, full, body); res.Status != http.StatusBadRequest {
			t.Errorf("revoke-all with body %v = %d, want 400; body: %s", body, res.Status, res.Raw)
		}
	}
	if n, totp := activeFactors(t, h, subjectID); n != 2 || !totp {
		t.Fatalf("a refused request changed the factors: %d credentials, totp %v", n, totp)
	}

	res := h.do(http.MethodPost, path, full, map[string]any{"reason": "phished on 4 March"})
	if res.Status != http.StatusOK {
		t.Fatalf("revoke-all = %d; body: %s", res.Status, res.Raw)
	}
	if got := res.Body["credentials_revoked"]; got != float64(2) {
		t.Errorf("credentials_revoked = %v, want 2", got)
	}
	if got := res.Body["totp_revoked"]; got != float64(1) {
		t.Errorf("totp_revoked = %v, want 1", got)
	}
	if n, totp := activeFactors(t, h, subjectID); n != 0 || totp {
		t.Errorf("after revoke-all: %d active credentials, totp %v; want none", n, totp)
	}

	// Revoked, not deleted: the record of what the subject held survives.
	all, err := h.store.ListCredentials(context.Background(), h.cfg.TenantID(), subjectID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("subject has %d credential rows, want 2", len(all))
	}
	for _, c := range all {
		if !c.Revoked() || c.RevokedReason != "phished on 4 March" {
			t.Errorf("credential %s: revoked %v, reason %q", c.ID, c.Revoked(), c.RevokedReason)
		}
	}

	// The recovery codes are the user's way back in. They are untouched,
	// reported, and no lockout warning is raised while some remain.
	left, err := h.store.CountUnusedRecoveryCodes(context.Background(), h.cfg.TenantID(), subjectID)
	if err != nil {
		t.Fatal(err)
	}
	if left != codes {
		t.Errorf("%d recovery codes remain, want all %d", left, codes)
	}
	if got := res.Body["recovery_codes_remaining"]; got != float64(codes) {
		t.Errorf("recovery_codes_remaining = %v, want %d", got, codes)
	}
	if res.Body["warning"] != nil {
		t.Errorf("warned about a lockout while codes remain: %v", res.Body["warning"])
	}

	entries := h.auditEntries(audit.EventCredentialBulkRevoked)
	if len(entries) != 1 {
		t.Fatalf("%d bulk revocation audit entries, want 1", len(entries))
	}
	if entries[0].SubjectID != subjectID || entries[0].Outcome != store.OutcomeSuccess {
		t.Errorf("audit entry names subject %q with outcome %q", entries[0].SubjectID, entries[0].Outcome)
	}
	if !bytes.Contains(entries[0].Detail, []byte(`"credentials_revoked":2`)) {
		t.Errorf("audit detail lacks the counts: %s", entries[0].Detail)
	}
}

// TestRevokeAllWarnsWhenNoRecoveryCodesRemain covers the case the operator most
// needs telling about: the subject now has no way to sign in at all.
func TestRevokeAllWarnsWhenNoRecoveryCodesRemain(t *testing.T) {
	h := newHarness(t, withoutDualApproval)
	subjectID := newSubject(t, h, "user-1")
	seedFactors(t, h, subjectID)

	res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/credentials/revoke-all",
		h.admin[store.RoleFull], map[string]any{"reason": "stolen laptop"})
	if res.Status != http.StatusOK {
		t.Fatalf("revoke-all = %d; body: %s", res.Status, res.Raw)
	}
	if got := res.Body["recovery_codes_remaining"]; got != float64(0) {
		t.Errorf("recovery_codes_remaining = %v, want 0", got)
	}
	if w, _ := res.Body["warning"].(string); w == "" {
		t.Errorf("no lockout warning with zero recovery codes: %s", res.Raw)
	}
}

// TestRevokeAllIsRefusedBelowFullAdministrator submits the request directly
// with each lesser role, because hiding the button is not a control.
func TestRevokeAllIsRefusedBelowFullAdministrator(t *testing.T) {
	h := newHarness(t, withoutDualApproval)
	subjectID := newSubject(t, h, "user-1")
	seedFactors(t, h, subjectID)
	path := "/admin/v1/subjects/" + subjectID + "/credentials/revoke-all"

	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator} {
		res := h.do(http.MethodPost, path, h.admin[role], map[string]any{"reason": "x"})
		if res.Status != http.StatusForbidden {
			t.Errorf("revoke-all as %s = %d, want 403; body: %s", role, res.Status, res.Raw)
		}
	}
	if n, totp := activeFactors(t, h, subjectID); n != 2 || !totp {
		t.Errorf("a refused role changed the factors: %d credentials, totp %v", n, totp)
	}
}

// TestRevokeAllIsHeldForASecondAdministrator runs with the default
// configuration, in which the operation is on the dual-approval list.
//
// The first call must queue and change nothing. A route that revoked first and
// asked afterwards would make the second administrator a formality.
func TestRevokeAllIsHeldForASecondAdministrator(t *testing.T) {
	h := newHarness(t)
	subjectID := newSubject(t, h, "user-1")
	seedFactors(t, h, subjectID)
	path := "/admin/v1/subjects/" + subjectID + "/credentials/revoke-all"
	requester := h.admin[store.RoleFull]
	body := map[string]any{"reason": "suspected compromise"}

	res := h.do(http.MethodPost, path, requester, body)
	if res.Status != http.StatusAccepted || res.Body["type"] != TypeApprovalRequired {
		t.Fatalf("first call = %d %v, want 202 approval required; body: %s",
			res.Status, res.Body["type"], res.Raw)
	}
	if n, totp := activeFactors(t, h, subjectID); n != 2 || !totp {
		t.Fatalf("a queued request changed the factors: %d credentials, totp %v", n, totp)
	}
	if n := len(h.auditEntries(audit.EventCredentialBulkRevoked)); n != 0 {
		t.Errorf("a queued request was audited as %d revocations", n)
	}

	queue := h.do(http.MethodGet, "/admin/v1/approvals", requester, nil)
	pending := queue.list(t, "approvals")
	if len(pending) != 1 {
		t.Fatalf("queue holds %d requests, want 1", len(pending))
	}
	queued := asObject(t, pending[0], "pending[0]", "")
	if queued["operation"] != "credential.revoke_bulk" {
		t.Errorf("queued operation = %v", queued["operation"])
	}
	approvalID := asString(t, queued["id"], "queued.id")

	approver := h.mintAdminToken("approver", store.RoleFull)
	if res = h.do(http.MethodPost, "/admin/v1/approvals/"+approvalID+"/approve", approver, nil); res.Status != http.StatusOK {
		t.Fatalf("approve = %d; body: %s", res.Status, res.Raw)
	}

	// The approval is bound to the subject and the reason the approver read.
	hdr := map[string]string{ApprovalHeader: approvalID}
	altered := map[string]any{"reason": "something else"}
	if res = h.doWith(http.MethodPost, path, requester, altered, hdr); res.Status != http.StatusForbidden {
		t.Errorf("redeeming with a different reason = %d, want 403", res.Status)
	}
	if n, _ := activeFactors(t, h, subjectID); n != 2 {
		t.Fatalf("a refused redemption revoked credentials: %d remain", n)
	}

	res = h.doWith(http.MethodPost, path, requester, body, hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("redeeming = %d; body: %s", res.Status, res.Raw)
	}
	if n, totp := activeFactors(t, h, subjectID); n != 0 || totp {
		t.Errorf("after redemption: %d active credentials, totp %v; want none", n, totp)
	}
}

// TestRewrapRouteAuthorisationAndReport covers the HTTP surface of the rewrap.
// The harness keyring holds one version, so the pass has nothing to move; the
// movement itself is covered by TestRewrapAll.
func TestRewrapRouteAuthorisationAndReport(t *testing.T) {
	h := newHarness(t, withoutDualApproval)
	newSubject(t, h, "user-1")
	newSubject(t, h, "user-2")

	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator} {
		if res := h.do(http.MethodPost, "/admin/v1/kek/rewrap", h.admin[role], nil); res.Status != http.StatusForbidden {
			t.Errorf("rewrap as %s = %d, want 403; body: %s", role, res.Status, res.Raw)
		}
	}

	res := h.do(http.MethodPost, "/admin/v1/kek/rewrap", h.admin[store.RoleFull], nil)
	if res.Status != http.StatusOK {
		t.Fatalf("rewrap = %d; body: %s", res.Status, res.Raw)
	}
	for key, want := range map[string]any{
		"current_version": float64(1),
		"examined":        float64(2),
		"rewrapped":       float64(0),
		"already_current": float64(2),
		"failed":          float64(0),
		"versions_in_use": []any{float64(1)},
	} {
		if got := res.Body[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if n := len(h.auditEntries(audit.EventKEKRewrapped)); n != 1 {
		t.Errorf("%d rewrap audit entries, want 1", n)
	}
}

// TestRewrapIsHeldForASecondAdministrator checks the default configuration
// queues the pass instead of running it.
func TestRewrapIsHeldForASecondAdministrator(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodPost, "/admin/v1/kek/rewrap", h.admin[store.RoleFull], nil)
	if res.Status != http.StatusAccepted || res.Body["type"] != TypeApprovalRequired {
		t.Fatalf("rewrap = %d %v, want 202 approval required; body: %s",
			res.Status, res.Body["type"], res.Raw)
	}
	if n := len(h.auditEntries(audit.EventKEKRewrapped)); n != 0 {
		t.Errorf("a queued rewrap was audited as %d passes", n)
	}
}

// fakeKEK is a keyring held in memory. It hands out copies, because the
// envelope package zeroizes every key it is given and the provider contract
// says the caller owns the slice.
type fakeKEK struct {
	current uint32
	keys    map[uint32][]byte
}

func (f *fakeKEK) Current() (version uint32, key []byte, err error) {
	key, err = f.ByVersion(f.current)
	return f.current, key, err
}

func (f *fakeKEK) ByVersion(v uint32) ([]byte, error) {
	key, ok := f.keys[v]
	if !ok {
		return nil, fmt.Errorf("fake keyring holds no version %d", v)
	}
	return append([]byte(nil), key...), nil
}

func testKey(fill byte) []byte { return bytes.Repeat([]byte{fill}, 32) }

// rewrapFixture is a Server over a real SQLite store, with nothing else wired.
// rewrapAll touches the store and the logger and nothing more.
func rewrapFixture(t *testing.T) (*Server, store.Store) {
	t.Helper()
	st, err := sqlite.Open(sqlite.Options{
		DSN: filepath.Join(t.TempDir(), "rewrap.db"), Logger: discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	seedTenant(t, st, testTenant, now)
	seedTenant(t, st, "second-tenant", now)

	cfg := config.Default()
	srv := NewServer(Deps{Config: &cfg, Store: st, Logger: discardLogger(),
		Clock: func() time.Time { return now }})
	return srv, st
}

// TestRewrapAll follows a rotation from version 1 to version 2.
//
// It seeds more subjects than one page holds so that the keyset paging is
// exercised, spreads them over two tenants because the keyring is shared by
// every tenant, and checks the property an operator relies on: once the pass
// reports only the current version in use, every record really is readable
// without the old key.
func TestRewrapAll(t *testing.T) {
	srv, st := rewrapFixture(t)
	ctx := context.Background()

	v1 := envelope.NewSealer(&fakeKEK{current: 1, keys: map[uint32][]byte{1: testKey(0x11)}})
	v2 := envelope.NewSealer(&fakeKEK{current: 2, keys: map[uint32][]byte{
		1: testKey(0x11), 2: testKey(0x22),
	}})
	// What the keyring looks like once the operator has retired version 1.
	v2only := envelope.NewSealer(&fakeKEK{current: 2, keys: map[uint32][]byte{2: testKey(0x22)}})

	const subjects = rewrapPageSize + 5
	const secrets = 5
	plaintexts := map[string][]byte{}

	for i := 0; i < subjects; i++ {
		tenant := testTenant
		if i%2 == 1 {
			tenant = "second-tenant"
		}
		id := uuid.NewString()
		ref := []byte(fmt.Sprintf("user-%03d@example.test", i))
		sealed, err := v1.Seal(ref, envelope.SubjectRef(tenant, id))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertSubject(ctx, &store.Subject{
			ID: id, TenantID: tenant, RefHMAC: []byte(fmt.Sprintf("hmac-%03d", i)), RefSealed: sealed,
		}); err != nil {
			t.Fatal(err)
		}
		plaintexts[id] = ref

		if i < secrets {
			totpID := uuid.NewString()
			secret := []byte(fmt.Sprintf("totp-seed-%03d", i))
			sealed, err := v1.Seal(secret, envelope.TOTPSecret(tenant, id, totpID))
			if err != nil {
				t.Fatal(err)
			}
			confirmed := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
			if err := st.CreateTOTPSecret(ctx, &store.TOTPSecret{
				ID: totpID, TenantID: tenant, SubjectID: id, SecretSealed: sealed,
				Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30, ConfirmedAt: &confirmed,
			}); err != nil {
				t.Fatal(err)
			}
			plaintexts[totpID] = secret
		}
	}
	total := subjects + secrets

	// Before the restart that loads the new key, version 1 is still current
	// and there is nothing to move.
	report, err := srv.rewrapAll(ctx, v1)
	if err != nil {
		t.Fatal(err)
	}
	if report.CurrentVersion != 1 || report.AlreadyCurrent != total || report.Rewrapped != 0 {
		t.Fatalf("pass under the old keyring = %+v", report)
	}

	report, err = srv.rewrapAll(ctx, v2)
	if err != nil {
		t.Fatal(err)
	}
	want := rewrapReport{
		CurrentVersion: 2, Examined: total, Rewrapped: total,
		VersionsInUse: []uint32{2},
	}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("first pass = %+v, want %+v", report, want)
	}

	// Every record now names version 2 and opens without version 1, to the
	// plaintext it held before.
	checked := 0
	for _, kind := range []store.SealedKind{store.SealedTOTP, store.SealedSubjectRef} {
		after := ""
		for {
			var page []store.SealedRecord
			page, err = st.ListSealed(ctx, kind, after, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			for _, rec := range page {
				var version uint32
				version, err = envelope.KEKVersion(rec.Sealed)
				if err != nil || version != 2 {
					t.Errorf("%s %s reports version %d (%v), want 2", kind, rec.ID, version, err)
				}
				var bind envelope.Context
				bind, err = bindingFor(kind, rec)
				if err != nil {
					t.Fatal(err)
				}
				var plain []byte
				plain, err = v2only.Unseal(rec.Sealed, bind)
				if err != nil {
					t.Errorf("%s %s does not unseal without the old key: %v", kind, rec.ID, err)
					continue
				}
				if !bytes.Equal(plain, plaintexts[rec.ID]) {
					t.Errorf("%s %s unseals to %q, want %q", kind, rec.ID, plain, plaintexts[rec.ID])
				}
				checked++
			}
			after = page[len(page)-1].ID
		}
	}
	if checked != total {
		t.Errorf("checked %d records, want %d", checked, total)
	}

	// A second pass has nothing to do and says so.
	report, err = srv.rewrapAll(ctx, v2)
	if err != nil {
		t.Fatal(err)
	}
	want = rewrapReport{
		CurrentVersion: 2, Examined: total, AlreadyCurrent: total,
		VersionsInUse: []uint32{2},
	}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("second pass = %+v, want %+v", report, want)
	}

	// A record sealed under a version the keyring no longer holds cannot be
	// moved. It sorts before every other subject, so a pass that gave up on
	// the first failure would never reach the late record sealed under
	// version 1, which sorts last.
	orphanSealer := envelope.NewSealer(&fakeKEK{current: 9, keys: map[uint32][]byte{9: testKey(0x99)}})
	orphan, err := orphanSealer.Seal([]byte("orphan"), envelope.SubjectRef(testTenant, "!orphan"))
	if err != nil {
		t.Fatal(err)
	}
	late, err := v1.Seal([]byte("late"), envelope.SubjectRef(testTenant, "~late"))
	if err != nil {
		t.Fatal(err)
	}
	for id, sealed := range map[string][]byte{"!orphan": orphan, "~late": late} {
		if _, err = st.UpsertSubject(ctx, &store.Subject{
			ID: id, TenantID: testTenant, RefHMAC: []byte("hmac-" + id), RefSealed: sealed,
		}); err != nil {
			t.Fatal(err)
		}
	}

	report, err = srv.rewrapAll(ctx, v2)
	if err != nil {
		t.Fatalf("a record that cannot be rewrapped aborted the pass: %v", err)
	}
	want = rewrapReport{
		CurrentVersion: 2, Examined: total + 2, Rewrapped: 1, AlreadyCurrent: total, Failed: 1,
		// Version 9 is still referenced, which is what tells the operator
		// the keyring is missing a key rather than holding a spare one.
		VersionsInUse: []uint32{2, 9},
	}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("pass with an orphan = %+v, want %+v", report, want)
	}

	page, err := st.ListSealed(ctx, store.SealedSubjectRef, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "!orphan" || !bytes.Equal(page[0].Sealed, orphan) {
		t.Errorf("the orphan was altered by a pass that could not read it: %+v", page)
	}
}

// TestARecordAlreadyOnTheCurrentKeyIsStillAuthenticated covers the flaw that
// sat beside the missing binding. The pass used to take a record's header as
// proof that the record was sound and move on, so the one job that reads every
// sealed value in the deployment reported a corrupted row as healthy and the
// damage surfaced months later as a user who could not sign in.
func TestARecordAlreadyOnTheCurrentKeyIsStillAuthenticated(t *testing.T) {
	srv, st := rewrapFixture(t)
	ctx := context.Background()
	v1 := envelope.NewSealer(&fakeKEK{current: 1, keys: map[uint32][]byte{1: testKey(0x11)}})

	id := uuid.NewString()
	sealed, err := v1.Seal([]byte("user@example.test"), envelope.SubjectRef(testTenant, id))
	if err != nil {
		t.Fatal(err)
	}
	// One bit of the payload, as a restored backup or a half-written page
	// would leave it. The header is untouched and still names version 1.
	sealed[len(sealed)-1] ^= 0x01
	if _, err = st.UpsertSubject(ctx, &store.Subject{
		ID: id, TenantID: testTenant, RefHMAC: []byte("hmac"), RefSealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}

	report, err := srv.rewrapAll(ctx, v1)
	if err != nil {
		t.Fatal(err)
	}
	want := rewrapReport{CurrentVersion: 1, Examined: 1, Failed: 1, VersionsInUse: []uint32{1}}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("pass over a corrupted record on the current key = %+v, want %+v", report, want)
	}
}

// TestARecordSealedForAnotherSubjectIsReportedAsFailed is the substitution seen
// from the rotation pass. The bytes are a valid envelope under the current key;
// what makes them wrong is the row they were found in, and the pass only knows
// that because it rebuilds the binding from the row rather than from the bytes.
func TestARecordSealedForAnotherSubjectIsReportedAsFailed(t *testing.T) {
	srv, st := rewrapFixture(t)
	ctx := context.Background()
	v1 := envelope.NewSealer(&fakeKEK{current: 1, keys: map[uint32][]byte{1: testKey(0x11)}})

	victim, attacker := uuid.NewString(), uuid.NewString()
	sealed, err := v1.Seal([]byte("attacker@example.test"), envelope.SubjectRef(testTenant, attacker))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpsertSubject(ctx, &store.Subject{
		ID: victim, TenantID: testTenant, RefHMAC: []byte("hmac-victim"), RefSealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}

	report, err := srv.rewrapAll(ctx, v1)
	if err != nil {
		t.Fatal(err)
	}
	want := rewrapReport{CurrentVersion: 1, Examined: 1, Failed: 1, VersionsInUse: []uint32{1}}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("pass over a record sealed for another subject = %+v, want %+v", report, want)
	}

	// The pass reports and leaves it alone, so an operator sees the row as it
	// was found rather than as the pass rewrote it.
	page, err := st.ListSealed(ctx, store.SealedSubjectRef, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || !bytes.Equal(page[0].Sealed, sealed) {
		t.Errorf("the record was altered by a pass that could not authenticate it: %+v", page)
	}
}

// TestRewrapAllHonoursCancellation checks a pass stops for a caller who has
// gone away, instead of walking the whole database on their behalf.
func TestRewrapAllHonoursCancellation(t *testing.T) {
	srv, st := rewrapFixture(t)
	v1 := envelope.NewSealer(&fakeKEK{current: 1, keys: map[uint32][]byte{1: testKey(0x11)}})
	v2 := envelope.NewSealer(&fakeKEK{current: 2, keys: map[uint32][]byte{
		1: testKey(0x11), 2: testKey(0x22),
	}})

	subjectID := uuid.NewString()
	sealed, err := v1.Seal([]byte("user@example.test"), envelope.SubjectRef(testTenant, subjectID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpsertSubject(context.Background(), &store.Subject{
		ID: subjectID, TenantID: testTenant, RefHMAC: []byte("hmac"), RefSealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := srv.rewrapAll(ctx, v2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("rewrapAll on a cancelled context = %v, want context.Canceled", err)
	}
	if report.Examined != 0 || report.Rewrapped != 0 {
		t.Errorf("a cancelled pass still did work: %+v", report)
	}
}
