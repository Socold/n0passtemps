package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/risk"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/totp"
)

// enrolTOTP takes a subject through enrolment and confirmation and returns a
// function that produces a fresh code, advancing the clock one period each
// time so no code is ever presented twice.
func enrolTOTP(t *testing.T, h *harness, ref string) func() string {
	t.Helper()

	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": ref})
	enrol := h.do(http.MethodPost, "/v1/totp/"+ref+"/enrol", h.apiKey, nil)
	if enrol.Status != http.StatusCreated {
		t.Fatalf("enrol = %d; body: %s", enrol.Status, enrol.Raw)
	}
	secret := decodeBase32(t, enrol.str(t, "secret"))
	params := totp.Params{
		Algorithm: totp.Algorithm(h.cfg.TOTP.Algorithm),
		Digits:    h.cfg.TOTP.Digits,
		Period:    h.cfg.TOTP.Period.Duration,
		Skew:      h.cfg.TOTP.Skew,
	}

	next := func() string {
		h.t.Helper()
		code, err := totp.Code(secret, params, h.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		h.clock.add(h.cfg.TOTP.Period.Duration)
		return code
	}

	if res := h.do(http.MethodPost, "/v1/totp/"+ref+"/enrol/confirm", h.apiKey,
		map[string]any{"code": next()}); res.Status != http.StatusOK {
		t.Fatalf("confirm = %d; body: %s", res.Status, res.Raw)
	}
	return next
}

// verifiedClaims verifies an assertion against the published key and returns
// its claims.
//
// It goes through the real Verifier rather than reading the payload, because
// the claim only means anything if the signature over it checks out. The
// issuer reads the wall clock rather than the harness clock, which is why no
// clock has to be arranged here.
func verifiedClaims(t *testing.T, h *harness, token string) *assertion.Claims {
	t.Helper()

	doc := h.do(http.MethodGet, "/v1/.well-known/jwks.json", "", nil)
	if doc.Status != http.StatusOK {
		t.Fatalf("jwks = %d; body: %s", doc.Status, doc.Raw)
	}
	keys, ok := doc.Body["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("the jwks document carries no key: %s", doc.Raw)
	}
	jwk := asObject(t, keys[0], "keys[0]", "")
	raw, err := base64.RawURLEncoding.DecodeString(asString(t, jwk["x"], "jwk.x"))
	if err != nil {
		t.Fatalf("decode jwk: %v", err)
	}

	verifier := assertion.NewVerifier(
		map[string]ed25519.PublicKey{asString(t, jwk["kid"], "jwk.kid"): raw},
		h.cfg.Assertion.Issuer, h.cfg.Assertion.AllowedClockSkew.Duration)

	claims, err := verifier.Verify(token, h.harnessAPIKeyID(t))
	if err != nil {
		t.Fatalf("the assertion does not verify: %v", err)
	}
	return claims
}

// harnessAPIKeyID returns the identifier of the harness API key, which is the
// audience a verifier has to pin.
func (h *harness) harnessAPIKeyID(t *testing.T) string {
	t.Helper()
	keys, err := h.store.ListAPIKeys(t.Context(), h.cfg.TenantID())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Name == "integration" {
			return k.ID
		}
	}
	t.Fatal("the harness api key is not in the store")
	return ""
}

// auditRisk pulls the risk object out of the newest audit entry of a type.
//
// The second return value reports whether the detail had a risk key at all,
// which is what the disabled case asserts the absence of.
func auditRisk(t *testing.T, h *harness, eventType string) (map[string]any, bool) {
	t.Helper()
	entries := h.auditEntries(eventType)
	if len(entries) == 0 {
		t.Fatalf("no %s entry was recorded", eventType)
	}
	var detail map[string]any
	if err := json.Unmarshal(entries[0].Detail, &detail); err != nil {
		t.Fatalf("decode audit detail: %v", err)
	}
	value, ok := detail["risk"]
	if !ok {
		return nil, false
	}
	obj, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("the audit detail risk key is %T, not an object: %s", value, entries[0].Detail)
	}
	return obj, true
}

// reasonsOf reads the reasons out of a decoded response body or audit detail.
func reasonsOf(t *testing.T, value any) []string {
	t.Helper()
	if value == nil {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("reasons are %T, not a list", value)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, asString(t, v, "reason"))
	}
	return out
}

func hasReason(reasons []string, want risk.Reason) bool {
	for _, r := range reasons {
		if r == string(want) {
			return true
		}
	}
	return false
}

// TestCleanTOTPVerificationIsLow checks the ordinary case.
//
// The subject holds a WebAuthn credential as well, so totp_only does not fire
// and the assessment has nothing at all to report. That is the shape most
// authentications have, and a feature that reports something about every one
// of them would be reporting noise.
func TestCleanTOTPVerificationIsLow(t *testing.T) {
	h := newHarness(t)
	next := enrolTOTP(t, h, "user-1")
	seedCredential(t, h, "user-1", h.clock.now().Add(-40*24*time.Hour), ago(h, 30*24*time.Hour))

	res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
		map[string]any{"code": next()})
	if res.Status != http.StatusOK {
		t.Fatalf("verify = %d; body: %s", res.Status, res.Raw)
	}
	if got := res.Body["risk_level"]; got != string(risk.LevelLow) {
		t.Errorf("risk_level = %v, want %q; body: %s", got, risk.LevelLow, res.Raw)
	}
	if reasons := reasonsOf(t, res.Body["risk_reasons"]); len(reasons) != 0 {
		t.Errorf("a clean verification reported %v", reasons)
	}

	claims := verifiedClaims(t, h, res.str(t, "assertion"))
	if claims.Risk == nil {
		t.Fatal("the verified assertion carries no risk claim")
	}
	if claims.Risk.Level != risk.LevelLow || claims.Risk.Score != 0 {
		t.Errorf("the signed claim says %+v, want low at 0", *claims.Risk)
	}
}

// seedCredential inserts a WebAuthn credential directly into the store.
//
// A real registration needs an authenticator, which a test does not have. The
// stored row is what the risk gathering reads, so inserting it exercises the
// same path. registered and lastUsed are both given because they drive
// different rules: credential_new looks at the registration and
// credential_dormant at the last use. A nil lastUsed is a credential that was
// enrolled and never used.
func seedCredential(t *testing.T, h *harness, ref string, registered time.Time, lastUsed *time.Time) *store.Credential {
	t.Helper()

	sub := h.do(http.MethodGet, "/v1/subjects/"+ref, h.apiKey, nil)
	if sub.Status != http.StatusOK {
		t.Fatalf("subject %s = %d; body: %s", ref, sub.Status, sub.Raw)
	}

	cred := &store.Credential{
		ID:              uuid.NewString(),
		TenantID:        h.cfg.TenantID(),
		SubjectID:       sub.str(t, "subject_id"),
		CredentialID:    []byte(uuid.NewString()),
		PublicKey:       []byte{0x01},
		AttestationType: store.AttestationNone,
		Transports:      []string{"usb"},
		RPID:            h.cfg.WebAuthn.RPID,
		CreatedAt:       registered,
		LastUsedAt:      lastUsed,
	}
	if err := h.store.CreateCredential(t.Context(), cred); err != nil {
		t.Fatal(err)
	}
	return cred
}

// ago is a pointer to an instant d before the harness clock, for a seeded
// credential's last use.
func ago(h *harness, d time.Duration) *time.Time {
	at := h.clock.now().Add(-d)
	return &at
}

// TestRecoveryRedemptionCarriesItsReason checks the signal that matters most.
//
// A recovery code is the weakest factor the service offers and the one an
// attacker reaches for, so its redemption must always be visible, in the
// claim and in the audit entry alike.
func TestRecoveryRedemptionCarriesItsReason(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	code := asString(t, issued.list(t, "codes")[0], "codes[0]")

	res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": code})
	if res.Status != http.StatusOK {
		t.Fatalf("consume = %d; body: %s", res.Status, res.Raw)
	}

	reasons := reasonsOf(t, res.Body["risk_reasons"])
	if !hasReason(reasons, risk.ReasonRecoveryCodeUsed) {
		t.Errorf("a recovery redemption reported %v, want %s among them",
			reasons, risk.ReasonRecoveryCodeUsed)
	}
	if got := res.Body["risk_level"]; got != string(risk.LevelElevated) {
		t.Errorf("risk_level = %v, want %q", got, risk.LevelElevated)
	}

	// The claim and the audit entry must agree, from the same value, so that
	// an operator reading the entry sees what the application was told.
	claims := verifiedClaims(t, h, res.str(t, "assertion"))
	if claims.Risk == nil {
		t.Fatal("the verified assertion carries no risk claim")
	}
	logged, ok := auditRisk(t, h, audit.EventRecoveryConsumed)
	if !ok {
		t.Fatal("the audit entry carries no risk")
	}
	if logged["level"] != string(claims.Risk.Level) {
		t.Errorf("the audit entry says %v and the claim says %s", logged["level"], claims.Risk.Level)
	}
	if int(asNumber(t, logged["score"], "risk.score")) != claims.Risk.Score {
		t.Errorf("the audit entry scores %v and the claim %d", logged["score"], claims.Risk.Score)
	}
	if got := reasonsOf(t, logged["reasons"]); len(got) != len(claims.Risk.Reasons) {
		t.Errorf("the audit entry lists %v and the claim %v", got, claims.Risk.Reasons)
	}
}

// TestFailuresBeforeASuccessAreReported checks the throttle-derived reasons.
//
// The counters come from the limiter's own result, so this also checks that
// the gathering reads them rather than silently reporting zero.
func TestFailuresBeforeASuccessAreReported(t *testing.T) {
	h := newHarness(t)
	next := enrolTOTP(t, h, "user-1")

	for range 2 {
		if res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
			map[string]any{"code": "000000"}); res.Status != http.StatusUnauthorized {
			t.Fatalf("a wrong code = %d, want 401", res.Status)
		}
	}

	res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
		map[string]any{"code": next()})
	if res.Status != http.StatusOK {
		t.Fatalf("verify after two failures = %d; body: %s", res.Status, res.Raw)
	}

	reasons := reasonsOf(t, res.Body["risk_reasons"])
	for _, want := range []risk.Reason{
		risk.ReasonRecentFailuresSubject,
		risk.ReasonRecentFailuresNetwork,
		// The subject holds no WebAuthn credential, so the factor that let
		// them in is a phishable one with nothing stronger behind it.
		risk.ReasonTOTPOnly,
	} {
		if !hasReason(reasons, want) {
			t.Errorf("reasons = %v, want %s among them", reasons, want)
		}
	}
	if got := res.Body["risk_level"]; got != string(risk.LevelElevated) {
		t.Errorf("risk_level = %v, want %q; reasons %v", got, risk.LevelElevated, reasons)
	}
}

// TestDormantAndNewCredentialsAreReported checks the two credential rules on
// the path where they cost a query.
func TestDormantAndNewCredentialsAreReported(t *testing.T) {
	t.Run("dormant", func(t *testing.T) {
		h := newHarness(t)
		next := enrolTOTP(t, h, "user-1")
		seedCredential(t, h, "user-1", h.clock.now().Add(-400*24*time.Hour), ago(h, 120*24*time.Hour))

		res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
			map[string]any{"code": next()})
		if res.Status != http.StatusOK {
			t.Fatalf("verify = %d; body: %s", res.Status, res.Raw)
		}
		reasons := reasonsOf(t, res.Body["risk_reasons"])
		if !hasReason(reasons, risk.ReasonCredentialDormant) {
			t.Errorf("reasons = %v, want %s", reasons, risk.ReasonCredentialDormant)
		}
		// A subject who holds a key is not totp_only, even when they signed in
		// with a code.
		if hasReason(reasons, risk.ReasonTOTPOnly) {
			t.Errorf("reasons = %v; the subject holds a WebAuthn credential", reasons)
		}
	})

	t.Run("new", func(t *testing.T) {
		h := newHarness(t)
		next := enrolTOTP(t, h, "user-1")
		seedCredential(t, h, "user-1", h.clock.now().Add(-time.Minute), nil)

		res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
			map[string]any{"code": next()})
		if res.Status != http.StatusOK {
			t.Fatalf("verify = %d; body: %s", res.Status, res.Raw)
		}
		if reasons := reasonsOf(t, res.Body["risk_reasons"]); !hasReason(reasons, risk.ReasonCredentialNew) {
			t.Errorf("reasons = %v, want %s", reasons, risk.ReasonCredentialNew)
		}
	})
}

// TestRiskDisabledLeavesNoTraceAtAll is the compatibility guarantee at the
// service level.
//
// With reporting off there must be no risk claim, no risk key in the audit
// detail and no risk field in the body: an application integrated against such
// a deployment sees exactly what it saw before the feature existed.
func TestRiskDisabledLeavesNoTraceAtAll(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Risk.Enabled = false })
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	code := asString(t, issued.list(t, "codes")[0], "codes[0]")

	res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": code})
	if res.Status != http.StatusOK {
		t.Fatalf("consume = %d; body: %s", res.Status, res.Raw)
	}
	if _, present := res.Body["risk_level"]; present {
		t.Errorf("the body carries risk_level although reporting is off: %s", res.Raw)
	}
	if _, present := res.Body["risk_reasons"]; present {
		t.Errorf("the body carries risk_reasons although reporting is off: %s", res.Raw)
	}

	if claims := verifiedClaims(t, h, res.str(t, "assertion")); claims.Risk != nil {
		t.Errorf("the assertion carries a risk claim although reporting is off: %+v", *claims.Risk)
	}
	if _, present := auditRisk(t, h, audit.EventRecoveryConsumed); present {
		t.Error("the audit detail carries a risk key although reporting is off")
	}
}

// TestRiskNeverRefusesAnAuthentication is the property the whole design rests
// on.
//
// A maximally risky ceremony still succeeds and still returns a signed
// assertion. The only thing risk changes is what the claim and the audit entry
// say. If this test ever fails, the feature has become an enforcement
// mechanism, which is not what was agreed and not what is documented.
func TestRiskNeverRefusesAnAuthentication(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		// Every reason weighted far above the high threshold, so no
		// combination of them can come out at anything but high.
		c.Risk.Weights = map[string]int{}
		for _, reason := range config.RiskReasons {
			c.Risk.Weights[reason] = 1000
		}
	})

	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	codes := issued.list(t, "codes")

	// Failures against both the subject and the network first, and a dormant
	// credential, so that as many reasons as this path can reach do reach.
	seedCredential(t, h, "user-1", h.clock.now().Add(-500*24*time.Hour), ago(h, 400*24*time.Hour))
	for range 3 {
		h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": "AAAAA-AAAAA-AAAAA"})
	}

	res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": asString(t, codes[0], "codes[0]")})
	if res.Status != http.StatusOK {
		t.Fatalf("a high-risk redemption was refused with %d; the service must report "+
			"risk and never refuse on it. Body: %s", res.Status, res.Raw)
	}

	token := res.str(t, "assertion")
	if token == "" {
		t.Fatal("a high-risk redemption returned no signed assertion")
	}
	claims := verifiedClaims(t, h, token)
	if claims.Risk == nil {
		t.Fatal("the assertion carries no risk claim")
	}
	if claims.Risk.Level != risk.LevelHigh {
		t.Fatalf("the assessment came out %s at score %d with %v; the case is meant to "+
			"be maximal", claims.Risk.Level, claims.Risk.Score, claims.Risk.Reasons)
	}
	if len(claims.Risk.Reasons) < 3 {
		t.Errorf("only %v fired; the case is meant to be maximal", claims.Risk.Reasons)
	}
}

// TestHighRiskRaisesAnAlert checks that an operator finds out.
//
// The service let the subject in, so the alert row is the only thing that
// brings a high assessment to anyone's attention. Repetition collapses onto
// one row by fingerprint, which is checked here too: a subject under attack
// must not produce one row per attempt.
func TestHighRiskRaisesAnAlert(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	codes := issued.list(t, "codes")

	// recovery_code_used together with failures against the subject and the
	// network reaches the high threshold on the shipped defaults. This is the
	// account-takeover shape the defaults are chosen for.
	for range 2 {
		h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": "AAAAA-AAAAA-AAAAA"})
	}

	for i := range 2 {
		res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": asString(t, codes[i], "codes[i]")})
		if res.Status != http.StatusOK {
			t.Fatalf("consume %d = %d; body: %s", i, res.Status, res.Raw)
		}
		if got := res.Body["risk_level"]; got != string(risk.LevelHigh) {
			t.Fatalf("risk_level = %v, want %q; reasons %v", got, risk.LevelHigh,
				reasonsOf(t, res.Body["risk_reasons"]))
		}
	}

	raised, err := h.store.ListAlerts(t.Context(), h.cfg.TenantID(),
		store.AlertFilter{AlertType: "risk.high", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(raised) != 1 {
		t.Fatalf("%d risk.high alerts, want 1 collapsed row", len(raised))
	}
	if raised[0].Occurrences != 2 {
		t.Errorf("the collapsed row counts %d occurrences, want 2", raised[0].Occurrences)
	}
	if raised[0].Severity != store.SeverityWarning {
		t.Errorf("severity = %q, want %q", raised[0].Severity, store.SeverityWarning)
	}

	// An elevated assessment must not raise anything: alerting on the common
	// case is how an alert stream stops being read.
	other := newHarness(t)
	other.do(http.MethodPost, "/v1/subjects", other.apiKey, map[string]any{"subject_ref": "user-2"})
	batch := other.do(http.MethodPost, "/v1/recovery/user-2/issue", other.apiKey, nil)
	clean := other.do(http.MethodPost, "/v1/recovery/user-2/consume", other.apiKey,
		map[string]any{"code": asString(t, batch.list(t, "codes")[0], "codes[0]")})
	if got := clean.Body["risk_level"]; got != string(risk.LevelElevated) {
		t.Fatalf("a lone redemption = %v, want %q", got, risk.LevelElevated)
	}
	quiet, err := other.store.ListAlerts(t.Context(), other.cfg.TenantID(),
		store.AlertFilter{AlertType: "risk.high", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(quiet) != 0 {
		t.Errorf("an elevated assessment raised %d alerts", len(quiet))
	}
}
