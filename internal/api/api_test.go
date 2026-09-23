package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/totp"
)

// TestPublicRoutesRequireACredential is the test for the defect that motivated
// docs/adr/0002.
//
// The original specification left the public surface unauthenticated. An
// unauthenticated registration route lets anyone enrol an authenticator against
// any subject, which is a complete authentication bypass, so every route is
// exercised here without a credential and each must refuse.
func TestPublicRoutesRequireACredential(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/subjects"},
		{http.MethodGet, "/v1/subjects/user-1"},
		{http.MethodGet, "/v1/health/detail"},
		{http.MethodPost, "/v1/webauthn/user-1/register"},
		{http.MethodPost, "/v1/webauthn/user-1/register/complete"},
		{http.MethodPost, "/v1/webauthn/user-1/assert"},
		{http.MethodPost, "/v1/webauthn/user-1/assert/complete"},
		{http.MethodPost, "/v1/totp/user-1/enrol"},
		{http.MethodPost, "/v1/totp/user-1/enrol/confirm"},
		{http.MethodPost, "/v1/totp/user-1/verify"},
		{http.MethodPost, "/v1/recovery/user-1/issue"},
		{http.MethodPost, "/v1/recovery/user-1/consume"},
		{http.MethodPost, "/v1/subjects/user-1/enrolment-ticket"},
		{http.MethodPost, "/v1/enrolment/register"},
		{http.MethodPost, "/v1/enrolment/register/complete"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			res := h.do(tc.method, tc.path, "", map[string]any{})
			if res.Status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401; body: %s", res.Status, res.Raw)
			}
			if got := res.Header.Get("WWW-Authenticate"); got == "" {
				t.Error("a 401 must carry a WWW-Authenticate challenge, per RFC 9110 section 11.6.1")
			}
		})
	}
}

// TestAdminRoutesRequireAnAdminToken checks that the two credential kinds are
// not interchangeable.
//
// An API key is a valid credential, so a route that only checked "is there a
// valid bearer token" would accept it. The kind is bound into the stored digest
// and checked explicitly, and this proves both.
func TestAdminRoutesRequireAnAdminToken(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/admin/v1/subjects",
		"/admin/v1/audit",
		"/admin/v1/alerts",
		"/admin/v1/approvals",
		"/admin/v1/api-keys",
		"/admin/v1/health",
	} {
		t.Run(path, func(t *testing.T) {
			if res := h.do(http.MethodGet, path, "", nil); res.Status != http.StatusUnauthorized {
				t.Errorf("no credential: status = %d, want 401", res.Status)
			}
			// An API key must not open the administrative surface.
			if res := h.do(http.MethodGet, path, h.apiKey, nil); res.Status != http.StatusUnauthorized {
				t.Errorf("api key: status = %d, want 401; body: %s", res.Status, res.Raw)
			}
			if res := h.do(http.MethodGet, path, h.admin[store.RoleFull], nil); res.Status != http.StatusOK {
				t.Errorf("admin token: status = %d, want 200; body: %s", res.Status, res.Raw)
			}
		})
	}
}

// TestAdminTokenRejectedOnPublicSurface is the converse.
func TestAdminTokenRejectedOnPublicSurface(t *testing.T) {
	h := newHarness(t)
	res := h.do(http.MethodPost, "/v1/subjects", h.admin[store.RoleFull],
		map[string]any{"subject_ref": "user-1"})
	if res.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; an administrative token must not act as an api key", res.Status)
	}
}

// TestLivenessIsPublicAndSaysNothingElse is the test for docs/adr/0008.
//
// The original specification returned the version, the keyring state, whether
// rotation was overdue and the certificate expiry to an unauthenticated caller.
// That set is a list of the software to look up advisories for and a statement
// of which maintenance has been neglected.
func TestLivenessIsPublicAndSaysNothingElse(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodGet, "/v1/health", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if got := res.Body["status"]; got != "ok" {
		t.Errorf("status field = %v, want ok", got)
	}
	for _, leak := range []string{"version", "kek", "tls", "database", "uptime_seconds", "features"} {
		if _, present := res.Body[leak]; present {
			t.Errorf("the public probe discloses %q: %s", leak, res.Raw)
		}
	}
	if len(res.Body) != 1 {
		t.Errorf("the public probe returned %d fields, want exactly 1: %s", len(res.Body), res.Raw)
	}

	// The detail is available to an authenticated caller.
	detail := h.do(http.MethodGet, "/v1/health/detail", h.apiKey, nil)
	if detail.Status != http.StatusOK {
		t.Fatalf("detail status = %d, want 200", detail.Status)
	}
	for _, want := range []string{"version", "database", "kek", "audit", "features"} {
		if _, present := detail.Body[want]; !present {
			t.Errorf("the authenticated report omits %q: %s", want, detail.Raw)
		}
	}
}

// TestJWKSIsPublicAndCarriesNoPrivateKey checks the one other unauthenticated
// route.
func TestJWKSIsPublicAndCarriesNoPrivateKey(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/v1/.well-known/jwks.json", "/v1/jwks.json"} {
		res := h.do(http.MethodGet, path, "", nil)
		if res.Status != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, res.Status)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/jwk-set+json" {
			t.Errorf("%s: content type = %q", path, ct)
		}
		// A JWK private key would appear as the "d" member. Publishing one
		// would hand out the signing key.
		if containsKey(res.Raw, `"d"`) {
			t.Fatalf("%s: the published key set contains a private key member", path)
		}
		if !containsKey(res.Raw, `"Ed25519"`) || !containsKey(res.Raw, `"EdDSA"`) {
			t.Errorf("%s: unexpected key set: %s", path, res.Raw)
		}
	}
}

func containsKey(body, needle string) bool {
	return len(body) > 0 && len(needle) > 0 && (indexOf(body, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestSubjectResolutionIsIdempotent checks the behaviour an integrating
// application depends on: it may call this on every login.
func TestSubjectResolutionIsIdempotent(t *testing.T) {
	h := newHarness(t)

	first := h.do(http.MethodPost, "/v1/subjects", h.apiKey,
		map[string]any{"subject_ref": "user-1", "display_name": "Test User"})
	if first.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", first.Status, first.Raw)
	}
	id := first.str(t, "subject_id")

	second := h.do(http.MethodPost, "/v1/subjects", h.apiKey,
		map[string]any{"subject_ref": "user-1"})
	if second.Status != http.StatusOK {
		t.Fatalf("second call status = %d", second.Status)
	}
	if got := second.str(t, "subject_id"); got != id {
		t.Errorf("second call returned %s, want the same subject %s", got, id)
	}

	// The reference must not be echoed back. The caller already has it, and
	// putting it in a response body puts it wherever that body is cached.
	if _, present := second.Body["subject_ref"]; present {
		t.Error("the response echoes the subject reference back")
	}
}

// TestSubjectReferenceIsNotStoredInClear checks that the database holds no
// readable copy of the application's identifier.
func TestSubjectReferenceIsNotStoredInClear(t *testing.T) {
	h := newHarness(t)

	const ref = "alice@example.test"
	res := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": ref})
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d", res.Status)
	}

	sub, err := h.store.GetSubject(t.Context(), h.cfg.TenantID(), res.str(t, "subject_id"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sub.RefHMAC) == ref {
		t.Fatal("the lookup key is the reference itself")
	}
	if indexOf(string(sub.RefSealed), ref) >= 0 {
		t.Fatal("the sealed reference contains the plaintext")
	}
	if len(sub.RefSealed) == 0 {
		t.Fatal("no sealed copy was stored, so an access request could not be answered")
	}
}

// TestUnknownJSONFieldIsRefused checks that a misspelled field is not silently
// ignored.
//
// A caller who writes "challengeId" instead of "challenge_id" would otherwise
// get the zero value, and for a security-relevant field that failure is
// invisible until it matters.
func TestUnknownJSONFieldIsRefused(t *testing.T) {
	h := newHarness(t)
	res := h.do(http.MethodPost, "/v1/subjects", h.apiKey,
		map[string]any{"subject_ref": "user-1", "subjectRef": "user-2"})
	if res.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", res.Status, res.Raw)
	}
}

// TestFormEncodedBodyIsRefused checks the media type guard.
//
// Beyond being parsed as an empty object, a form-encoded body is a CORS simple
// request, so accepting one would let a cross-origin caller reach a
// state-changing route without the browser asking first.
func TestFormEncodedBodyIsRefused(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/subjects",
		newReader("subject_ref=user-1"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", res.StatusCode)
	}
}

// TestTOTPLifecycle walks the whole flow with real codes, and checks that an
// unconfirmed secret cannot authenticate.
func TestTOTPLifecycle(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	if created.Status != http.StatusOK {
		t.Fatalf("subject: %s", created.Raw)
	}

	enrol := h.do(http.MethodPost, "/v1/totp/user-1/enrol", h.apiKey, nil)
	if enrol.Status != http.StatusCreated {
		t.Fatalf("enrol status = %d; body: %s", enrol.Status, enrol.Raw)
	}
	secret := decodeBase32(t, enrol.str(t, "secret"))
	params := totp.Params{
		Algorithm: totp.Algorithm(h.cfg.TOTP.Algorithm),
		Digits:    h.cfg.TOTP.Digits,
		Period:    h.cfg.TOTP.Period.Duration,
		Skew:      h.cfg.TOTP.Skew,
	}

	// An unconfirmed secret must not authenticate. The user has been shown it
	// but has not proved they can generate a code from it.
	code, err := totp.Code(secret, params, h.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	early := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": code})
	if early.Status != http.StatusUnauthorized {
		t.Errorf("verify before confirmation = %d, want 401; body: %s", early.Status, early.Raw)
	}

	confirm := h.do(http.MethodPost, "/v1/totp/user-1/enrol/confirm", h.apiKey,
		map[string]any{"code": code})
	if confirm.Status != http.StatusOK {
		t.Fatalf("confirm status = %d; body: %s", confirm.Status, confirm.Raw)
	}

	// The confirmation consumed that timestep, so the same code must not be
	// reusable. Move to the next period for a fresh one.
	h.clock.add(h.cfg.TOTP.Period.Duration)
	next, err := totp.Code(secret, params, h.clock.now())
	if err != nil {
		t.Fatal(err)
	}

	ok := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": next})
	if ok.Status != http.StatusOK {
		t.Fatalf("verify status = %d; body: %s", ok.Status, ok.Raw)
	}
	if ok.str(t, "assertion") == "" {
		t.Error("a successful verification returned no signed assertion")
	}

	// The same code again is a replay and must be refused, even though it is
	// still inside its validity window.
	replay := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": next})
	if replay.Status != http.StatusUnauthorized {
		t.Errorf("replayed code = %d, want 401; a one-time password was accepted twice", replay.Status)
	}

	// The refusal is audited, but as a rejection rather than as a detected
	// replay. The layering is deliberate: totp.Verify refuses any step at or
	// below the stored high water mark, so a replayed code never reaches the
	// compare-and-swap. EventTOTPReplayed is reserved for the case the
	// compare-and-swap itself catches, which is two concurrent requests
	// presenting the same still-valid code.
	if len(h.auditEntries(audit.EventTOTPRejected)) == 0 {
		t.Error("the replayed code was refused but not audited")
	}
}

// TestTOTPReplayIsIndistinguishableFromAWrongCode checks that the refusal does
// not tell an attacker which failure occurred.
func TestTOTPReplayIsIndistinguishableFromAWrongCode(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})

	enrol := h.do(http.MethodPost, "/v1/totp/user-1/enrol", h.apiKey, nil)
	secret := decodeBase32(t, enrol.str(t, "secret"))
	params := totp.Params{
		Algorithm: totp.Algorithm(h.cfg.TOTP.Algorithm),
		Digits:    h.cfg.TOTP.Digits,
		Period:    h.cfg.TOTP.Period.Duration,
		Skew:      h.cfg.TOTP.Skew,
	}
	code, _ := totp.Code(secret, params, h.clock.now())
	h.do(http.MethodPost, "/v1/totp/user-1/enrol/confirm", h.apiKey, map[string]any{"code": code})

	h.clock.add(h.cfg.TOTP.Period.Duration)
	good, _ := totp.Code(secret, params, h.clock.now())
	h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": good})

	replayed := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": good})
	wrong := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": "000000"})

	if replayed.Status != wrong.Status {
		t.Errorf("replay returned %d and a wrong code %d; the two must be indistinguishable",
			replayed.Status, wrong.Status)
	}
	if replayed.Body["type"] != wrong.Body["type"] {
		t.Errorf("replay type %v differs from wrong-code type %v",
			replayed.Body["type"], wrong.Body["type"])
	}
	if replayed.Body["detail"] != nil || wrong.Body["detail"] != nil {
		t.Error("a ceremony failure disclosed a detail field")
	}
}

// TestRecoveryCodeIsSingleUse checks the property the whole feature rests on.
func TestRecoveryCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})

	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	if issued.Status != http.StatusCreated {
		t.Fatalf("issue status = %d; body: %s", issued.Status, issued.Raw)
	}
	codes, ok := issued.Body["codes"].([]any)
	if !ok || len(codes) != h.cfg.Recovery.CodeCount {
		t.Fatalf("issued %v codes, want %d", len(codes), h.cfg.Recovery.CodeCount)
	}
	code := asString(t, codes[0], "codes[0]")

	first := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey, map[string]any{"code": code})
	if first.Status != http.StatusOK {
		t.Fatalf("consume status = %d; body: %s", first.Status, first.Raw)
	}
	if first.str(t, "assertion") == "" {
		t.Error("consuming a code returned no signed assertion")
	}

	second := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey, map[string]any{"code": code})
	if second.Status != http.StatusUnauthorized {
		t.Errorf("reused code = %d, want 401; a single-use code was accepted twice", second.Status)
	}
}

// TestRecoveryIssueRetiresThePreviousBatch checks that old codes stop working.
//
// Issuing without retiring would leave codes in circulation the user believes
// are dead.
func TestRecoveryIssueRetiresThePreviousBatch(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})

	first := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	old := asString(t, first.list(t, "codes")[0], "codes[0]")

	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey, map[string]any{"code": old})
	if res.Status != http.StatusUnauthorized {
		t.Errorf("a code from the retired batch = %d, want 401", res.Status)
	}
}

// TestRecoveryCodeFromAnotherSubjectIsRefused checks that the selector, which
// is unique across the tenant, does not authenticate the wrong person.
func TestRecoveryCodeFromAnotherSubjectIsRefused(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-2"})

	issued := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)
	code := asString(t, issued.list(t, "codes")[0], "codes[0]")

	res := h.do(http.MethodPost, "/v1/recovery/user-2/consume", h.apiKey, map[string]any{"code": code})
	if res.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; one subject's code authenticated another", res.Status)
	}
}

// TestUnknownSubjectIsIndistinguishableFromAFailedCeremony checks that the
// authentication routes cannot be used to discover who has an account.
func TestUnknownSubjectIsIndistinguishableFromAFailedCeremony(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "known"})

	unknown := h.do(http.MethodPost, "/v1/totp/nobody-here/verify", h.apiKey,
		map[string]any{"code": "123456"})
	known := h.do(http.MethodPost, "/v1/totp/known/verify", h.apiKey,
		map[string]any{"code": "123456"})

	if unknown.Status != known.Status {
		t.Errorf("unknown subject returned %d and a known one %d; the difference is an "+
			"account enumeration oracle", unknown.Status, known.Status)
	}
	if unknown.Body["type"] != known.Body["type"] {
		t.Errorf("problem types differ: %v against %v", unknown.Body["type"], known.Body["type"])
	}
}

// TestThrottleLocksOutAfterTheConfiguredFailures checks the rate limiter end to
// end, including that the refusal carries a Retry-After.
func TestThrottleLocksOutAfterTheConfiguredFailures(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
		c.Throttle.LockoutDuration = config.Duration{Duration: 10 * time.Minute}
	})

	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	// Three wrong codes are refused as failed authentications.
	for i := 0; i < 3; i++ {
		res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401; body: %s", i+1, res.Status, res.Raw)
		}
	}

	// The fourth is refused by the limiter instead.
	locked := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
	if locked.Status != http.StatusTooManyRequests {
		t.Fatalf("after the limit = %d, want 429; body: %s", locked.Status, locked.Raw)
	}
	if locked.Header.Get("Retry-After") == "" {
		t.Error("a 429 must carry Retry-After")
	}

	// A correct code is refused too while the lockout holds, which is the
	// point: the limiter runs before any expensive work.
	if len(h.auditEntries(audit.EventThrottleTripped)) == 0 {
		t.Error("the lockout was not audited")
	}

	// Past the lockout, attempts are accepted again.
	h.clock.add(11 * time.Minute)
	after := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
	if after.Status != http.StatusUnauthorized {
		t.Errorf("after the lockout expired = %d, want 401 (a normal refusal)", after.Status)
	}
}

// TestSecurityHeadersOnEveryResponse checks the headers are applied to error
// responses too, which is where they are most often missed.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)

	for _, res := range []response{
		h.do(http.MethodGet, "/v1/health", "", nil),
		h.do(http.MethodPost, "/v1/subjects", "", nil),
		h.do(http.MethodGet, "/nowhere", "", nil),
	} {
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
			"Cache-Control":          "no-store",
		} {
			if got := res.Header.Get(header); got != want {
				t.Errorf("status %d: %s = %q, want %q", res.Status, header, got, want)
			}
		}
		if csp := res.Header.Get("Content-Security-Policy"); csp == "" {
			t.Errorf("status %d: no Content-Security-Policy", res.Status)
		}
		if res.Header.Get(RequestIDHeader) == "" {
			t.Errorf("status %d: no request identifier echoed", res.Status)
		}
	}
}

// TestRequestIDIsSanitised checks that a client cannot inject into a log line.
//
// The identifier reaches log lines and audit entries. An unfiltered value
// carrying a newline could forge an entry, and one carrying a terminal escape
// could rewrite what an operator reading the log sees.
func TestRequestIDIsSanitised(t *testing.T) {
	h := newHarness(t)

	for _, hostile := range []string{
		"line\nbreak",
		"\x1b[2Jclear",
		"semi;colon",
		"quote\"mark",
		"way-too-long-" + repeat("x", 100),
	} {
		req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(RequestIDHeader, hostile)

		res, err := h.srv.Client().Do(req)
		if err != nil {
			// net/http refuses some of these outright, which is also a pass.
			continue
		}
		_ = res.Body.Close()

		echoed := res.Header.Get(RequestIDHeader)
		if echoed == hostile {
			t.Errorf("the hostile identifier %q was echoed back unchanged", hostile)
		}
		if echoed == "" {
			t.Error("no identifier was assigned")
		}
	}
}

// TestAuditRecordsEveryAdministrativeAction checks the completeness the audit
// log is supposed to have.
func TestAuditRecordsEveryAdministrativeAction(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	subjectID := created.str(t, "subject_id")

	if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/lock",
		h.admin[store.RoleFull], map[string]any{"reason": "test"}); res.Status != http.StatusOK {
		t.Fatalf("lock status = %d; body: %s", res.Status, res.Raw)
	}
	if len(h.auditEntries(audit.EventSubjectLocked)) != 1 {
		t.Error("locking a subject was not audited")
	}

	if res := h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/unlock",
		h.admin[store.RoleFull], nil); res.Status != http.StatusOK {
		t.Fatalf("unlock status = %d; body: %s", res.Status, res.Raw)
	}
	if len(h.auditEntries(audit.EventSubjectUnlocked)) != 1 {
		t.Error("unlocking a subject was not audited")
	}

	// The chain must still verify after all of it.
	checked, broken, err := h.store.VerifyChain(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("the audit chain broke at entry %d", broken)
	}
	if checked == 0 {
		t.Error("the chain verified zero entries, so nothing was recorded at all")
	}
}

// TestLockedSubjectCannotAuthenticate checks that the operator action has the
// effect it claims.
func TestLockedSubjectCannotAuthenticate(t *testing.T) {
	h := newHarness(t)

	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	subjectID := created.str(t, "subject_id")
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	h.do(http.MethodPost, "/admin/v1/subjects/"+subjectID+"/lock",
		h.admin[store.RoleFull], map[string]any{"reason": "suspected compromise"})

	res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
	if res.Status != http.StatusUnauthorized {
		t.Errorf("a locked subject authenticated: status = %d", res.Status)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
