package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/webauthn/virtual"
)

// The four ceremony routes are the product. Everything else in this package
// exists to let an operator look at what they produced or take it away again.
//
// They were nonetheless the least covered handlers here, and for a reason worth
// stating: the tests that drove a real ceremony lived in internal/webauthn and
// called the service directly, so they proved the relying party correct and
// proved nothing about the HTTP surface in front of it. The path between a JSON
// body and that service, the throttle scope, the audit entry, the risk
// assessment and the signed assertion at the end, had no test that ran it from
// end to end.
//
// These do, with the same software authenticator internal/webauthn uses. That
// shared authenticator is the point: a ceremony both packages accept means
// something only when the same keys, the same CBOR and the same signatures
// produced it.

// harnessOrigin is what the harness configures as the relying party's origin.
// The authenticator has to name it or the library refuses the ceremony, which
// is the check a test with a canned fixture would skip.
const harnessOrigin = "http://localhost:8080"

// ceremonyOptions is the shape both begin routes answer with.
type ceremonyOptions struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

// decodeOptions reads a begin response, failing the test with the body when the
// status is not 200.
func decodeOptions(t *testing.T, res response, what string) ceremonyOptions {
	t.Helper()
	if res.Status != http.StatusOK {
		t.Fatalf("%s = %d; body: %s", what, res.Status, res.Raw)
	}
	var out ceremonyOptions
	if err := json.Unmarshal([]byte(res.Raw), &out); err != nil {
		t.Fatalf("%s: %v\nbody: %s", what, err, res.Raw)
	}
	if out.ChallengeID == "" || len(out.Options) == 0 {
		t.Fatalf("%s carries no challenge or no options: %s", what, res.Raw)
	}
	return out
}

// ceremonySubject creates a subject and returns the reference the ceremony
// routes take in their path, which is not the identifier newSubject returns.
func ceremonySubject(t *testing.T, h *harness, ref string) string {
	t.Helper()
	newSubject(t, h, ref)
	return ref
}

// enrol runs the registration ceremony over HTTP and returns the authenticator
// that now holds the credential.
func enrol(t *testing.T, h *harness, ref string) *virtual.Authenticator {
	t.Helper()
	auth := virtual.New(harnessOrigin, [16]byte{1, 2, 3, 4})

	begin := decodeOptions(t,
		h.do(http.MethodPost, "/v1/webauthn/"+ref+"/register", h.apiKey,
			map[string]any{"label": "a yubikey"}),
		"register begin")

	credential, err := auth.Create(begin.Options)
	if err != nil {
		t.Fatalf("the authenticator refused the creation options: %v", err)
	}

	res := h.do(http.MethodPost, "/v1/webauthn/"+ref+"/register/complete", h.apiKey,
		map[string]any{
			"challenge_id": begin.ChallengeID,
			"credential":   json.RawMessage(credential),
			"label":        "a yubikey",
		})
	if res.Status != http.StatusCreated && res.Status != http.StatusOK {
		t.Fatalf("register complete = %d; body: %s", res.Status, res.Raw)
	}
	return auth
}

// TestAWebAuthnCeremonyRunsEndToEndOverHTTP is the path a browser takes, with
// nothing stubbed between the JSON body and the signature.
func TestAWebAuthnCeremonyRunsEndToEndOverHTTP(t *testing.T) {
	h := newHarness(t)
	ref := ceremonySubject(t, h, "ceremony-user")
	auth := enrol(t, h, ref)

	begin := decodeOptions(t,
		h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert", h.apiKey, nil),
		"assert begin")

	signed, err := auth.Get(begin.Options)
	if err != nil {
		t.Fatalf("the authenticator refused the request options: %v", err)
	}

	res := h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert/complete", h.apiKey,
		map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(signed)})
	if res.Status != http.StatusOK {
		t.Fatalf("assert complete = %d; body: %s", res.Status, res.Raw)
	}

	token := res.str(t, "assertion")
	claims := verifiedClaims(t, h, token)

	// The assertion is the product's output, so the claims are checked rather
	// than the status code. A ceremony that returned 200 with an assertion
	// naming the wrong subject would pass every other assertion in this file.
	if claims.Subject != res.str(t, "subject_id") {
		t.Errorf("the assertion names subject %q and the body %q",
			claims.Subject, res.str(t, "subject_id"))
	}

	var carriesWebAuthn bool
	for _, f := range claims.AMR {
		if f == assertion.FactorWebAuthn {
			carriesWebAuthn = true
		}
	}
	if !carriesWebAuthn {
		t.Errorf("amr = %v, want one of them to be %q", claims.AMR, assertion.FactorWebAuthn)
	}

	// The begin call and the completion are both audited, and the audit log is
	// what an operator has afterwards.
	for _, event := range []string{"webauthn.registration.started", "webauthn.assertion.completed"} {
		if len(h.auditEntries(event)) == 0 {
			t.Errorf("no %s entry was recorded", event)
		}
	}
}

// TestTheSignatureCounterAdvancesAcrossAssertions is the replay protection seen
// from outside, where an integrator would meet it.
func TestTheSignatureCounterAdvancesAcrossAssertions(t *testing.T) {
	h := newHarness(t)
	ref := ceremonySubject(t, h, "counter-user")
	auth := enrol(t, h, ref)

	assertOnce := func() {
		t.Helper()
		begin := decodeOptions(t,
			h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert", h.apiKey, nil),
			"assert begin")
		signed, err := auth.Get(begin.Options)
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		res := h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert/complete", h.apiKey,
			map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(signed)})
		if res.Status != http.StatusOK {
			t.Fatalf("assert complete = %d; body: %s", res.Status, res.Raw)
		}
	}

	assertOnce()
	assertOnce()

	// A counter that never moved is the signal a cloned authenticator gives,
	// and the service records it rather than refusing. Nothing should have
	// recorded one here.
	if n := len(openAlerts(t, h, alerts.TypeSignCountRegression)); n != 0 {
		t.Errorf("%d sign count alerts after two honest assertions", n)
	}
}

// TestAStalledCounterIsRecordedNotRefused pins the decision the service made
// about cloned authenticators, at the HTTP boundary.
//
// The assertion still succeeds: refusing it would lock out every user of a
// synchronised passkey, which reports a constant zero by design. What the
// service does instead is leave a durable record, and that record is the only
// thing an operator ever sees.
func TestAStalledCounterIsRecordedNotRefused(t *testing.T) {
	h := newHarness(t)
	ref := ceremonySubject(t, h, "clone-user")
	auth := enrol(t, h, ref)

	// One honest assertion, so the stored counter is above zero and a stall is
	// distinguishable from a fresh credential.
	begin := decodeOptions(t,
		h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert", h.apiKey, nil), "assert begin")
	signed, err := auth.Get(begin.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if res := h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert/complete", h.apiKey,
		map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(signed)}); res.Status != http.StatusOK {
		t.Fatalf("first assertion = %d; body: %s", res.Status, res.Raw)
	}

	// Now hold the counter where it is, which is what a clone does.
	auth.ForceCounter(1)

	begin = decodeOptions(t,
		h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert", h.apiKey, nil), "assert begin")
	if signed, err = auth.Get(begin.Options); err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	res := h.do(http.MethodPost, "/v1/webauthn/"+ref+"/assert/complete", h.apiKey,
		map[string]any{"challenge_id": begin.ChallengeID, "credential": json.RawMessage(signed)})
	if res.Status != http.StatusOK {
		t.Fatalf("a stalled counter was refused with %d; body: %s", res.Status, res.Raw)
	}
	if len(openAlerts(t, h, alerts.TypeSignCountRegression)) == 0 {
		t.Error("a stalled counter raised no alert, which is the only thing an operator would see")
	}
}

// TestRegisterBeginRefusesBeforeItStartsACeremony covers the checks that run
// ahead of the relying party.
//
// Each of them is a reason not to mint a challenge at all, and a challenge
// minted for a caller who should not have one is a row in the database that an
// unauthenticated party caused to exist.
func TestRegisterBeginRefusesBeforeItStartsACeremony(t *testing.T) {
	h := newHarness(t)
	ref := ceremonySubject(t, h, "guarded-user")

	// An unknown subject is answered 401 with the same body a failed ceremony
	// gets, not 404. That is deliberate: a route that distinguished the two
	// would answer whether a given person has an account here, to anyone
	// holding any valid key, which is the enumeration oracle the whole subject
	// reference design exists to close.
	for name, tc := range map[string]struct {
		path   string
		bearer string
		want   int
	}{
		"no credential":    {"/v1/webauthn/" + ref + "/register", "", http.StatusUnauthorized},
		"unknown key":      {"/v1/webauthn/" + ref + "/register", "npa_nope.nope", http.StatusUnauthorized},
		"unknown subject":  {"/v1/webauthn/nobody-here/register", h.apiKey, http.StatusUnauthorized},
		"auditor token":    {"/v1/webauthn/" + ref + "/register", h.admin[store.RoleAuditor], http.StatusUnauthorized},
		"empty subjectref": {"/v1/webauthn//register", h.apiKey, http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			res := h.do(http.MethodPost, tc.path, tc.bearer, map[string]any{"label": "x"})
			if res.Status != tc.want {
				t.Errorf("status = %d, want %d; body: %s", res.Status, tc.want, res.Raw)
			}
		})
	}
}
