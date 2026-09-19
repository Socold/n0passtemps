package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
)

// The software authenticator that drives a full WebAuthn ceremony lives in
// internal/webauthn/authenticator_test.go, in package webauthn_test. A test
// binary's identifiers are not importable from another package, so these tests
// cannot complete a real registration through the HTTP surface. They therefore
// take the redemption as far as the options response, which is the last point a
// caller reaches without an authenticator, and exercise consumption and the
// single-use property at the store level, where the compare-and-swap that
// actually enforces it lives. Copying four hundred lines of CTAP encoding into
// this package would test the copy rather than the service.

// createSubject resolves a reference to a subject and returns its identifier.
func createSubject(t *testing.T, h *harness, ref string) string {
	t.Helper()
	res := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": ref})
	if res.Status != http.StatusOK {
		t.Fatalf("create subject %s = %d; body: %s", ref, res.Status, res.Raw)
	}
	return res.str(t, "subject_id")
}

// issueTicketVia issues a ticket through the public route and returns the
// secret.
func issueTicketVia(t *testing.T, h *harness, ref string, body any) response {
	t.Helper()
	return h.do(http.MethodPost, "/v1/subjects/"+ref+"/enrolment-ticket", h.apiKey, body)
}

func mustIssueTicket(t *testing.T, h *harness, ref string) (secret, ticketID string) {
	t.Helper()
	res := issueTicketVia(t, h, ref, nil)
	if res.Status != http.StatusCreated {
		t.Fatalf("issue = %d; body: %s", res.Status, res.Raw)
	}
	return res.str(t, "ticket"), res.str(t, "ticket_id")
}

// ticketBySelector reads a ticket row straight out of the store, for the
// assertions that concern state the API deliberately never discloses.
func ticketBySelector(t *testing.T, h *harness, secret string) *store.EnrolmentTicket {
	t.Helper()
	rec, err := h.store.GetEnrolmentTicketBySelector(t.Context(), h.cfg.TenantID(),
		ticketSelector(t, secret))
	if err != nil {
		t.Fatalf("read ticket: %v", err)
	}
	return rec
}

// ticketSelector splits a displayed ticket the way the handler does, so a test
// never hard-codes the layout of the secret.
func ticketSelector(t *testing.T, secret string) string {
	t.Helper()
	sel, _, err := recovery.Split(secret)
	if err != nil {
		t.Fatalf("split ticket: %v", err)
	}
	return sel
}

// wrongVerifierFor keeps a ticket's selector and replaces its verifier.
//
// It is built from the split rather than by slicing the displayed form, because
// the display carries group separators and a slice at a fixed offset would
// silently change the selector as well, which is a different test.
func wrongVerifierFor(t *testing.T, secret string) string {
	t.Helper()
	selector := ticketSelector(t, secret)
	return selector + strings.Repeat("0", recovery.CodeLen-len(selector))
}

// seedTicketCredential inserts an active WebAuthn credential for a subject.
//
// A real registration needs an authenticator, which this package cannot drive;
// the row is what the factor guard reads, so inserting it exercises the same
// path. It is keyed on the subject identifier rather than on the application's
// reference, because the administrative tests have only the identifier.
func seedTicketCredential(t *testing.T, h *harness, subjectID, label string) string {
	t.Helper()
	cred := &store.Credential{
		ID:              uuid.NewString(),
		TenantID:        h.cfg.TenantID(),
		SubjectID:       subjectID,
		CredentialID:    []byte(uuid.NewString()),
		PublicKey:       []byte{0x01},
		AttestationType: store.AttestationNone,
		Transports:      []string{"usb"},
		Label:           label,
		RPID:            h.cfg.WebAuthn.RPID,
		CreatedAt:       h.clock.now().UTC(),
	}
	if err := h.store.CreateCredential(t.Context(), cred); err != nil {
		t.Fatal(err)
	}
	return cred.ID
}

// seedTOTPSecret inserts a TOTP secret, confirmed or not.
//
// The ceremony is not run because the guard reads the row rather than the
// ceremony, and the distinction under test is exactly confirmed against
// pending.
func seedTOTPSecret(t *testing.T, h *harness, subjectID string, confirmed bool) {
	t.Helper()
	secretID := uuid.NewString()
	sealed, err := h.sealer.Seal([]byte("0123456789012345678901234567890123456789"),
		envelope.TOTPSecret(h.cfg.TenantID(), subjectID, secretID))
	if err != nil {
		t.Fatal(err)
	}
	rec := &store.TOTPSecret{
		ID:            secretID,
		TenantID:      h.cfg.TenantID(),
		SubjectID:     subjectID,
		SecretSealed:  sealed,
		Algorithm:     h.cfg.TOTP.Algorithm,
		Digits:        h.cfg.TOTP.Digits,
		PeriodSeconds: int(h.cfg.TOTP.Period.Duration.Seconds()),
		CreatedAt:     h.clock.now().UTC(),
	}
	if err := h.store.CreateTOTPSecret(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if err := h.store.ConfirmTOTPSecret(t.Context(), h.cfg.TenantID(), rec.ID,
			h.clock.now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
}

// openAlerts reads the alerts of one type.
func openAlerts(t *testing.T, h *harness, ty alerts.Type) []*store.Alert {
	t.Helper()
	got, err := h.store.ListAlerts(t.Context(), h.cfg.TenantID(),
		store.AlertFilter{AlertType: ty.String(), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// mintForeignAPIKey provisions a second tenant and a key inside it.
//
// The tenant row has to exist, because api_keys carries a foreign key to it.
func mintForeignAPIKey(t *testing.T, h *harness, tenantID string) string {
	t.Helper()
	ctx := context.Background()
	err := h.store.CreateTenant(ctx, &store.Tenant{
		ID: tenantID, Name: tenantID, Status: "active",
		CreatedAt: h.clock.now(), UpdatedAt: h.clock.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := token.Generate(token.KindAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	err = h.store.CreateAPIKey(ctx, &store.APIKey{
		ID: uuid.NewString(), TenantID: tenantID, Name: "foreign",
		Selector: tok.Selector, VerifierHash: tok.Hash, CreatedAt: h.clock.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Display
}

// TestIssuedTicketIsShownOnceWithItsExpiry covers the shape of the issuing
// response.
func TestIssuedTicketIsShownOnceWithItsExpiry(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")

	res := issueTicketVia(t, h, "user-1", map[string]any{"reason": "onboarding"})
	if res.Status != http.StatusCreated {
		t.Fatalf("issue = %d; body: %s", res.Status, res.Raw)
	}
	secret := res.str(t, "ticket")
	if secret == "" {
		t.Fatal("the response carries no ticket, so there is nothing to deliver")
	}
	if res.str(t, "warning") == "" {
		t.Error("the ticket is shown once and the response says nothing about it")
	}
	expiry := res.str(t, "expires_at")
	if expiry == "" {
		t.Fatal("the response carries no expires_at")
	}
	want := h.clock.now().UTC().Add(h.cfg.Tickets.TTL.Duration)
	got, err := time.Parse(time.RFC3339Nano, expiry)
	if err != nil {
		t.Fatalf("expires_at is not a timestamp: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("expires_at = %s, want %s from the injected clock", got, want)
	}

	// Nothing in the stored row or in any later response can show the secret
	// again.
	rec := ticketBySelector(t, h, secret)
	if rec.VerifierHash == "" {
		t.Error("the stored ticket has no verifier hash")
	}
	if rec.Reason != "onboarding" {
		t.Errorf("reason = %q, want onboarding", rec.Reason)
	}
	if len(h.auditEntries(audit.EventTicketIssued)) != 1 {
		t.Error("the issuance was not audited exactly once")
	}
}

// TestTicketRedemptionStartsARegistrationAndNothingElse is the core guarantee.
//
// A ticket permits one WebAuthn registration. It must never yield a signed
// assertion, because a ticket proves that whoever holds it was given it, not
// that the person in front of the browser is the subject.
func TestTicketRedemptionStartsARegistrationAndNothingElse(t *testing.T) {
	h := newHarness(t)
	subjectID := createSubject(t, h, "user-1")
	secret, ticketID := mustIssueTicket(t, h, "user-1")

	res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
		map[string]any{"ticket": secret, "label": "replacement key"})
	if res.Status != http.StatusOK {
		t.Fatalf("redeem = %d; body: %s", res.Status, res.Raw)
	}
	if res.Body["challenge_id"] == nil || res.Body["options"] == nil {
		t.Fatalf("the redemption returned no ceremony to run: %s", res.Raw)
	}
	if _, ok := res.Body["assertion"]; ok {
		t.Error("redeeming a ticket returned a signed assertion")
	}

	// Starting the ceremony must not spend the ticket. A browser that refuses
	// the prompt would otherwise send the user back to the helpdesk.
	if rec := ticketBySelector(t, h, secret); !rec.Redeemable(h.clock.now().UTC()) {
		t.Error("the ticket was spent by the begin step alone")
	}

	started := h.auditEntries(audit.EventRegistrationStarted)
	if len(started) != 1 {
		t.Fatalf("%d registration.started entries, want 1", len(started))
	}
	if started[0].SubjectID != subjectID {
		t.Errorf("the audited registration names subject %q, want %q", started[0].SubjectID, subjectID)
	}

	// Completion is exercised at the store level, because the software
	// authenticator is not importable here; see the file comment. What matters
	// is that consumption records the credential and that it happens once.
	cred := seedTicketCredential(t, h, subjectID, "cred-1")
	if err := h.store.ConsumeEnrolmentTicket(t.Context(), h.cfg.TenantID(),
		ticketID, cred, h.clock.now().UTC()); err != nil {
		t.Fatalf("consume: %v", err)
	}
	spent := ticketBySelector(t, h, secret)
	if spent.ConsumedCredentialID != cred {
		t.Errorf("consumed_credential_id = %q, want %q", spent.ConsumedCredentialID, cred)
	}

	// And the route refuses it afterwards, with the same coarse body as a
	// ticket that never existed.
	after := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
	assertCoarseTicketRefusal(t, after, "a consumed ticket")
}

// TestTicketIsRefusedInEveryDeadState covers expiry, consumption, revocation, a
// wrong secret, and a subject that cannot authenticate.
//
// Every refusal has to be the same body with no detail. A caller that could
// tell an expired ticket from an unknown one could enumerate which tickets
// exist, and one that could tell a locked subject from an active one could
// enumerate account states through the one route a user with no factor reaches.
func TestTicketIsRefusedInEveryDeadState(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		h := newHarness(t)
		createSubject(t, h, "user-1")
		secret, _ := mustIssueTicket(t, h, "user-1")

		h.clock.add(h.cfg.Tickets.TTL.Duration + time.Second)
		res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
		assertCoarseTicketRefusal(t, res, "an expired ticket")
	})

	t.Run("consumed", func(t *testing.T) {
		h := newHarness(t)
		subjectID := createSubject(t, h, "user-1")
		secret, ticketID := mustIssueTicket(t, h, "user-1")
		cred := seedTicketCredential(t, h, subjectID, "cred-1")
		if err := h.store.ConsumeEnrolmentTicket(t.Context(), h.cfg.TenantID(),
			ticketID, cred, h.clock.now().UTC()); err != nil {
			t.Fatal(err)
		}
		res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
		assertCoarseTicketRefusal(t, res, "a consumed ticket")
	})

	t.Run("revoked", func(t *testing.T) {
		h := newHarness(t)
		createSubject(t, h, "user-1")
		secret, ticketID := mustIssueTicket(t, h, "user-1")
		if res := h.do(http.MethodPost, "/admin/v1/enrolment-tickets/"+ticketID+"/revoke",
			h.admin[store.RoleOperator], nil); res.Status != http.StatusOK {
			t.Fatalf("revoke = %d; body: %s", res.Status, res.Raw)
		}
		res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
		assertCoarseTicketRefusal(t, res, "a revoked ticket")
		if len(h.auditEntries(audit.EventTicketRevoked)) != 1 {
			t.Error("the revocation was not audited")
		}
	})

	t.Run("superseded by a reissue", func(t *testing.T) {
		h := newHarness(t)
		createSubject(t, h, "user-1")
		first, _ := mustIssueTicket(t, h, "user-1")
		second, _ := mustIssueTicket(t, h, "user-1")
		if first == second {
			t.Fatal("two issuances produced the same secret")
		}
		assertCoarseTicketRefusal(t,
			h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": first}),
			"a superseded ticket")
		if res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
			map[string]any{"ticket": second}); res.Status != http.StatusOK {
			t.Errorf("the replacement ticket was refused: %d; body: %s", res.Status, res.Raw)
		}
	})

	t.Run("locked subject", func(t *testing.T) {
		h := newHarness(t)
		subjectID := createSubject(t, h, "user-1")
		secret, _ := mustIssueTicket(t, h, "user-1")
		if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/lock",
			h.admin[store.RoleFull], map[string]any{"reason": "investigation"}); res.Status != http.StatusOK {
			t.Fatalf("lock = %d; body: %s", res.Status, res.Raw)
		}
		res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
		assertCoarseTicketRefusal(t, res, "a ticket for a locked subject")
	})

	t.Run("subject pending erasure", func(t *testing.T) {
		h := newHarness(t, func(c *config.Config) { c.Features.DualApproval = false })
		subjectID := createSubject(t, h, "user-1")
		secret, _ := mustIssueTicket(t, h, "user-1")
		if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/erasure",
			h.admin[store.RoleFull], map[string]any{"reason": "user request"}); res.Status != http.StatusAccepted {
			t.Fatalf("erasure = %d; body: %s", res.Status, res.Raw)
		}
		res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})
		assertCoarseTicketRefusal(t, res, "a ticket for a subject pending erasure")
	})

	t.Run("wrong and malformed secrets", func(t *testing.T) {
		h := newHarness(t)
		createSubject(t, h, "user-1")
		secret, _ := mustIssueTicket(t, h, "user-1")

		// A valid selector with a wrong verifier, an entirely unknown ticket,
		// and rubbish. All three answer exactly as an expired one does.
		for name, presented := range map[string]string{
			"wrong verifier": wrongVerifierFor(t, secret),
			"unknown ticket": "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ",
			"not a ticket":   "hello",
			"empty":          "",
		} {
			res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
				map[string]any{"ticket": presented})
			assertCoarseTicketRefusal(t, res, name)
		}

		// The live ticket still works, so none of the refusals above spent it.
		if res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
			map[string]any{"ticket": secret}); res.Status != http.StatusOK {
			t.Errorf("a failed guess invalidated the real ticket: %d", res.Status)
		}
	})
}

// assertCoarseTicketRefusal checks that a refusal says nothing beyond "no".
func assertCoarseTicketRefusal(t *testing.T, res response, what string) {
	t.Helper()
	if res.Status != http.StatusUnauthorized {
		t.Errorf("%s = %d, want 401; body: %s", what, res.Status, res.Raw)
		return
	}
	if res.Body["type"] != TypeCeremonyFailed {
		t.Errorf("%s produced type %v, want %s", what, res.Body["type"], TypeCeremonyFailed)
	}
	if detail, ok := res.Body["detail"]; ok && detail != "" {
		t.Errorf("%s disclosed a detail: %v", what, detail)
	}
}

// TestEveryTicketRefusalIsAuditedWithItsReason is the other half of the coarse
// refusal: the reason has to exist somewhere, and that somewhere is the log an
// operator can read and an attacker cannot.
func TestEveryTicketRefusalIsAuditedWithItsReason(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")
	secret, _ := mustIssueTicket(t, h, "user-1")

	h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": "hello"})
	h.clock.add(h.cfg.Tickets.TTL.Duration + time.Second)
	h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": secret})

	entries := h.auditEntries(audit.EventTicketRejected)
	if len(entries) != 2 {
		t.Fatalf("%d rejection entries, want 2", len(entries))
	}
	for _, e := range entries {
		if len(e.Detail) == 0 {
			t.Errorf("a rejection was audited without a reason: %+v", e)
		}
	}
}

// TestIssuingOverAnExistingFactorNeedsAnOverride is the account-takeover guard.
//
// A ticket is a way in for someone with no factor. Issued silently for an
// account that already has one, it is an account-takeover primitive for whoever
// controls the delivery channel.
func TestIssuingOverAnExistingFactorNeedsAnOverride(t *testing.T) {
	h := newHarness(t)
	subjectID := createSubject(t, h, "user-1")
	seedTicketCredential(t, h, subjectID, "cred-1")

	refused := issueTicketVia(t, h, "user-1", nil)
	if refused.Status != http.StatusConflict {
		t.Fatalf("issuing over an active credential = %d, want 409; body: %s", refused.Status, refused.Raw)
	}
	if _, ok := refused.Body["ticket"]; ok {
		t.Fatal("a refused issuance still returned a ticket")
	}

	// The refusal is audited, so a run of them is visible.
	rejected := h.auditEntries(audit.EventTicketRejected)
	if len(rejected) != 1 || rejected[0].Outcome != store.OutcomeDenied {
		t.Errorf("the refusal was not audited as a denial: %+v", rejected)
	}
	if len(openAlerts(t, h, alerts.TypeTicketFactorOverride)) != 0 {
		t.Error("a refusal raised the override alert")
	}

	// The override proceeds, is audited, and raises the alert.
	ok := issueTicketVia(t, h, "user-1", map[string]any{
		"require_existing_factor": false,
		"reason":                  "user lost the key and the phone",
	})
	if ok.Status != http.StatusCreated {
		t.Fatalf("the override was refused: %d; body: %s", ok.Status, ok.Raw)
	}

	issued := h.auditEntries(audit.EventTicketIssued)
	if len(issued) != 1 {
		t.Fatalf("%d issuance entries, want 1", len(issued))
	}
	if !strings.Contains(string(issued[0].Detail), `"existing_factor_override":true`) {
		t.Errorf("the override is not marked in the audit detail: %s", issued[0].Detail)
	}

	raised := openAlerts(t, h, alerts.TypeTicketFactorOverride)
	if len(raised) != 1 {
		t.Fatalf("%d override alerts, want 1", len(raised))
	}
	if raised[0].Severity != store.SeverityWarning {
		t.Errorf("override alert severity = %q, want warning", raised[0].Severity)
	}
	if raised[0].SubjectID != subjectID {
		t.Errorf("the alert names subject %q, want %q", raised[0].SubjectID, subjectID)
	}
}

// TestConfirmedTOTPCountsAsAnExistingFactorButPendingDoesNot draws the line
// where the guard has to draw it.
//
// An unconfirmed secret is not a factor: the user has been shown it but has not
// proved they can produce codes from it, so treating it as one would refuse a
// ticket to the one person the feature exists for.
func TestConfirmedTOTPCountsAsAnExistingFactorButPendingDoesNot(t *testing.T) {
	h := newHarness(t)
	pending := createSubject(t, h, "user-1")
	seedTOTPSecret(t, h, pending, false)
	if res := issueTicketVia(t, h, "user-1", nil); res.Status != http.StatusCreated {
		t.Fatalf("an unconfirmed totp secret blocked a ticket: %d; body: %s", res.Status, res.Raw)
	}

	confirmed := createSubject(t, h, "user-2")
	seedTOTPSecret(t, h, confirmed, true)
	if res := issueTicketVia(t, h, "user-2", nil); res.Status != http.StatusConflict {
		t.Errorf("a confirmed totp secret did not block a ticket: %d; body: %s", res.Status, res.Raw)
	}
	if res := issueTicketVia(t, h, "user-2",
		map[string]any{"require_existing_factor": false}); res.Status != http.StatusCreated {
		t.Errorf("the override was refused over a confirmed totp secret: %d", res.Status)
	}
}

// TestTicketGuardFollowsTheConfiguredDefault checks that the deployment-wide
// setting is what a request with no opinion means.
func TestTicketGuardFollowsTheConfiguredDefault(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Tickets.RequireExistingFactorDefault = false
	})
	subjectID := createSubject(t, h, "user-1")
	seedTicketCredential(t, h, subjectID, "cred-1")

	if res := issueTicketVia(t, h, "user-1", nil); res.Status != http.StatusCreated {
		t.Fatalf("with the guard off by default, issuing = %d; body: %s", res.Status, res.Raw)
	}
	// It is still an override, so it is still alerted. Turning the guard off
	// deployment-wide makes every such issuance an override rather than making
	// them invisible.
	if len(openAlerts(t, h, alerts.TypeTicketFactorOverride)) != 1 {
		t.Error("with the guard off by default, the override was not alerted")
	}

	// And the request may put the guard back on for itself.
	if res := issueTicketVia(t, h, "user-1",
		map[string]any{"require_existing_factor": true}); res.Status != http.StatusConflict {
		t.Errorf("a request asking for the guard was not given it: %d", res.Status)
	}
}

// TestTicketRedemptionIsRateLimitedPerSelectorAndAddress bounds guessing.
//
// The per-selector limit is what makes guessing one ticket expensive; the
// per-address limit is what makes spraying across many expensive. Without the
// first, an attacker who knows a selector has unlimited attempts at its
// verifier from a rotating address pool.
func TestTicketRedemptionIsRateLimitedPerSelectorAndAddress(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
	})
	createSubject(t, h, "user-1")
	secret, _ := mustIssueTicket(t, h, "user-1")

	// Wrong verifiers against the real selector, which is the shape of a guess
	// at a ticket somebody knows the first half of.
	wrong := wrongVerifierFor(t, secret)
	var last response
	for range 6 {
		last = h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey, map[string]any{"ticket": wrong})
	}
	if last.Status != http.StatusTooManyRequests {
		t.Fatalf("after repeated guesses, status = %d, want 429; body: %s", last.Status, last.Raw)
	}
	if last.Header.Get("Retry-After") == "" {
		t.Error("the refusal carries no Retry-After")
	}

	// The correct secret shares the selector, so it is locked out too. That is
	// the point: the bucket belongs to the ticket, not to the guess.
	if res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
		map[string]any{"ticket": secret}); res.Status != http.StatusTooManyRequests {
		t.Errorf("the selector lockout did not cover the real ticket: %d", res.Status)
	}

	// A different subject's ticket is unaffected: the limit is per selector,
	// not global.
	createSubject(t, h, "user-2")
	other, _ := mustIssueTicket(t, h, "user-2")
	if res := h.do(http.MethodPost, "/v1/enrolment/register", h.apiKey,
		map[string]any{"ticket": other}); res.Status != http.StatusOK {
		t.Errorf("one ticket's lockout refused another: %d; body: %s", res.Status, res.Raw)
	}
}

// TestTicketRedemptionNeedsTheTicketsScope checks least privilege.
//
// A key that only runs ceremonies must not acquire the ability to mint a secret
// that enrols an authenticator later, through a channel the key does not
// control.
func TestTicketRedemptionNeedsTheTicketsScope(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")

	minted := h.do(http.MethodPost, "/admin/v1/api-keys", h.admin[store.RoleFull],
		map[string]any{"name": "ceremonies-only", "scopes": []string{"webauthn", "subjects"}})
	if minted.Status != http.StatusCreated {
		t.Fatalf("mint = %d; body: %s", minted.Status, minted.Raw)
	}
	key := minted.str(t, "token")

	for _, tc := range []struct {
		path string
		body any
	}{
		{"/v1/subjects/user-1/enrolment-ticket", nil},
		{"/v1/enrolment/register", map[string]any{"ticket": "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ"}},
		{"/v1/enrolment/register/complete", map[string]any{
			"ticket": "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "challenge_id": "x", "credential": map[string]any{},
		}},
	} {
		if res := h.do(http.MethodPost, tc.path, key, tc.body); res.Status != http.StatusForbidden {
			t.Errorf("POST %s without the tickets scope = %d, want 403", tc.path, res.Status)
		}
	}

	// The scope is a known one, so a key may be minted with it.
	scoped := h.do(http.MethodPost, "/admin/v1/api-keys", h.admin[store.RoleFull],
		map[string]any{"name": "tickets", "scopes": []string{"tickets"}})
	if scoped.Status != http.StatusCreated {
		t.Fatalf("minting a tickets-scoped key = %d; body: %s", scoped.Status, scoped.Raw)
	}
	if res := h.do(http.MethodPost, "/v1/subjects/user-1/enrolment-ticket",
		scoped.str(t, "token"), nil); res.Status != http.StatusCreated {
		t.Errorf("a tickets-scoped key was refused its own route: %d", res.Status)
	}
}

// TestAdminTicketIssuanceNeedsThePermission checks the administrative side.
func TestAdminTicketIssuanceNeedsThePermission(t *testing.T) {
	h := newHarness(t)
	subjectID := createSubject(t, h, "user-1")
	path := "/admin/v1/subjects/" + subjectID + "/enrolment-ticket"

	// An auditor changes nothing, including this.
	if res := h.do(http.MethodPost, path, h.admin[store.RoleAuditor], nil); res.Status != http.StatusForbidden {
		t.Errorf("an auditor issued a ticket: %d; body: %s", res.Status, res.Raw)
	}

	// An operator may, because a user who has lost every authenticator is
	// exactly what the role exists for.
	res := h.do(http.MethodPost, path, h.admin[store.RoleOperator],
		map[string]any{"reason": "telephone identity check passed"})
	if res.Status != http.StatusCreated {
		t.Fatalf("an operator was refused: %d; body: %s", res.Status, res.Raw)
	}
	if res.str(t, "ticket") == "" {
		t.Error("the administrative response carries no ticket")
	}

	issued := h.auditEntries(audit.EventTicketIssued)
	if len(issued) != 1 {
		t.Fatalf("%d issuance entries, want 1", len(issued))
	}
	if issued[0].ActorType != store.ActorAdmin {
		t.Errorf("actor type = %q, want %q", issued[0].ActorType, store.ActorAdmin)
	}

	// An API key is not an administrative credential, whichever surface it is
	// presented on.
	if r := h.do(http.MethodPost, path, h.apiKey, nil); r.Status != http.StatusUnauthorized && r.Status != http.StatusForbidden {
		t.Errorf("an api key reached the administrative route: %d", r.Status)
	}
}

// TestAdminTicketIssuanceRefusesAnUnusableSubject stops an operator putting a
// secret into a delivery channel for no purpose.
func TestAdminTicketIssuanceRefusesAnUnusableSubject(t *testing.T) {
	h := newHarness(t)
	subjectID := createSubject(t, h, "user-1")
	if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/lock",
		h.admin[store.RoleFull], map[string]any{"reason": "investigation"}); res.Status != http.StatusOK {
		t.Fatalf("lock = %d", res.Status)
	}

	res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/enrolment-ticket",
		h.admin[store.RoleOperator], nil)
	if res.Status != http.StatusConflict {
		t.Errorf("issuing for a locked subject = %d, want 409; body: %s", res.Status, res.Raw)
	}
	if len(h.auditEntries(audit.EventTicketIssued)) != 0 {
		t.Error("a refused administrative issuance was audited as an issuance")
	}
}

// TestTicketsAreTenantIsolated checks that a ticket cannot be redeemed by a
// credential belonging to another deployment's tenant.
func TestTicketsAreTenantIsolated(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")
	secret, ticketID := mustIssueTicket(t, h, "user-1")

	// A key minted under a different tenant is refused before it reaches any
	// row, so the ticket is untouched.
	foreign := mintForeignAPIKey(t, h, "other-tenant")
	if res := h.do(http.MethodPost, "/v1/enrolment/register", foreign,
		map[string]any{"ticket": secret}); res.Status != http.StatusForbidden {
		t.Errorf("a foreign tenant's key reached the redemption route: %d; body: %s", res.Status, res.Raw)
	}
	if rec := ticketBySelector(t, h, secret); !rec.Redeemable(h.clock.now().UTC()) {
		t.Error("a foreign tenant's attempt disturbed the ticket")
	}

	// And the store refuses directly, which is what protects the row if a
	// handler ever forgot the tenant.
	if err := h.store.ConsumeEnrolmentTicket(t.Context(), "other-tenant", ticketID,
		"cred-1", h.clock.now().UTC()); err == nil {
		t.Error("another tenant consumed the ticket")
	}
}

// TestOnlyOneConcurrentRedemptionSpendsATicket races the compare-and-swap.
//
// The ceremony cannot be completed from this package, so the race is run
// against the store method the handler calls, which is where single use is
// enforced. A second winner would mean one ticket had produced two credentials.
func TestOnlyOneConcurrentRedemptionSpendsATicket(t *testing.T) {
	h := newHarness(t)
	subjectID := createSubject(t, h, "user-1")
	_, ticketID := mustIssueTicket(t, h, "user-1")

	const racers = 8
	creds := make([]string, racers)
	for i := range racers {
		creds[i] = seedTicketCredential(t, h, subjectID, "cred-"+string(rune('a'+i)))
	}

	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = h.store.ConsumeEnrolmentTicket(t.Context(), h.cfg.TenantID(),
				ticketID, creds[i], h.clock.now().UTC())
		}()
	}
	wg.Wait()

	won := 0
	for _, err := range errs {
		if err == nil {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent redemptions spent the ticket, want exactly 1 (%v)", won, racers, errs)
	}
}

// TestJanitorSweepsExpiredTickets checks that abandoned tickets do not
// accumulate.
func TestJanitorSweepsExpiredTickets(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")
	secret, _ := mustIssueTicket(t, h, "user-1")

	if _, err := h.store.GetEnrolmentTicketBySelector(t.Context(), h.cfg.TenantID(),
		ticketSelector(t, secret)); err != nil {
		t.Fatalf("the ticket is not there to begin with: %v", err)
	}

	n, err := h.store.DeleteExpiredEnrolmentTickets(t.Context(),
		h.clock.now().UTC().Add(h.cfg.Tickets.TTL.Duration+time.Minute))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("sweep removed %d tickets, want 1", n)
	}
	if _, err := h.store.GetEnrolmentTicketBySelector(t.Context(), h.cfg.TenantID(),
		ticketSelector(t, secret)); err == nil {
		t.Error("the expired ticket survived the sweep")
	}
}
