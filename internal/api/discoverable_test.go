package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
)

// The usernameless routes cannot be driven to a successful ceremony from this
// package: the virtual authenticator lives in internal/webauthn's test binary
// and a test binary's identifiers are not importable. The whole ceremony,
// including the subject resolution, the user-handle comparison and the refusal
// of a revoked credential, is covered there. What is covered here is everything
// the ceremony is wrapped in, which is where this route differs from the named
// one: no subject in the path, a different rate-limit shape, and an audit entry
// that has nobody to name yet.

const discoverableBegin = "/v1/webauthn/assert/discoverable"
const discoverableComplete = "/v1/webauthn/assert/discoverable/complete"

func TestDiscoverableBeginOffersNoAllowList(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodPost, discoverableBegin, h.apiKey, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("begin = %d, want 200; body: %s", res.Status, res.Raw)
	}

	options, ok := res.Body["options"].(map[string]any)
	if !ok {
		t.Fatalf("no options in the response: %s", res.Raw)
	}
	pk, ok := options["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("no publicKey in the options: %s", res.Raw)
	}

	// An allow list would defeat the purpose twice over: the caller would have
	// had to name the subject to build it, and the browser would learn which
	// credentials that subject holds before anything was proved.
	if got, present := pk["allowCredentials"]; present && got != nil {
		t.Errorf("allowCredentials = %v, want absent", got)
	}

	// Required rather than configured. A usernameless ceremony is scoped to
	// nothing, so a possession-only response would let a found passkey sign in
	// as its owner with nothing else needed.
	if got := pk["userVerification"]; got != "required" {
		t.Errorf("userVerification = %v, want \"required\"", got)
	}
	if res.Body["challenge_id"] == "" || res.Body["challenge_id"] == nil {
		t.Error("no challenge identifier was returned")
	}
}

func TestDiscoverableBeginIsAuditedWithNoSubject(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodPost, discoverableBegin, h.apiKey, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("begin = %d; body: %s", res.Status, res.Raw)
	}

	entries := h.auditEntries(audit.EventAssertionStarted)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	// The honest record. At this point the service does not know who is
	// signing in, and inventing a subject would make the log claim something
	// the ceremony had not established. The completion entry names the subject
	// and repeats the challenge identifier, which is what joins the two.
	if entries[0].SubjectID != "" {
		t.Errorf("audit entry names subject %q, want none", entries[0].SubjectID)
	}
	if entries[0].ResourceID != res.str(t, "challenge_id") {
		t.Errorf("audit entry resource = %q, want the challenge identifier", entries[0].ResourceID)
	}
}

func TestDiscoverableRoutesNeedTheWebAuthnScope(t *testing.T) {
	h := newHarness(t)

	_, limited := mintKeyOverHTTP(t, h, map[string]any{
		"name":   "totp-only",
		"scopes": []string{"totp"},
	})

	for _, path := range []string{discoverableBegin, discoverableComplete} {
		res := h.do(http.MethodPost, path, limited, map[string]any{
			"challenge_id": "00000000-0000-4000-8000-000000000000",
			"credential":   map[string]any{"id": "AQID"},
		})
		if res.Status != http.StatusForbidden {
			t.Errorf("%s with a totp-only key = %d, want 403; body: %s", path, res.Status, res.Raw)
		}
	}
}

func TestDiscoverableCompleteRefusesAnUnknownChallengeWithoutDetail(t *testing.T) {
	h := newHarness(t)

	res := h.do(http.MethodPost, discoverableComplete, h.apiKey, map[string]any{
		"challenge_id": "00000000-0000-4000-8000-000000000000",
		"credential":   map[string]any{"id": "AQID", "type": "public-key"},
	})
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("unknown challenge = %d, want 401; body: %s", res.Status, res.Raw)
	}
	// Carries no detail, for the same reason the named route carries none: an
	// unknown challenge, an expired one and a credential this deployment has
	// never seen must be one answer.
	if detail, present := res.Body["detail"]; present {
		t.Errorf("the refusal carries detail %q, which says which check failed", detail)
	}
}

// TestDiscoverableFailureCannotLockOutASubject is the reason the two rate-limit
// dimensions are applied at different points in the handler.
//
// A failed usernameless ceremony has not established which subject it was for.
// Recording it against whichever subject the response claimed would hand an
// attacker a lockout primitive against any account they could name a credential
// for, through a route that needs no knowledge of that account at all.
func TestDiscoverableFailureCannotLockOutASubject(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 500
		c.Throttle.LockoutDuration = config.Duration{Duration: 15 * time.Minute}
	})

	h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	// Well past the per-subject limit, through the route that names nobody.
	for i := 0; i < 10; i++ {
		res := h.do(http.MethodPost, discoverableComplete, h.apiKey, map[string]any{
			"challenge_id": "00000000-0000-4000-8000-000000000000",
			"credential":   map[string]any{"id": "AQID", "type": "public-key"},
		})
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("usernameless attempt %d = %d, want 401; body: %s", i+1, res.Status, res.Raw)
		}
	}

	// The subject's own budget must be untouched: three refusals, then the
	// limiter, exactly as if the ten above had never happened.
	for i := 0; i < 3; i++ {
		res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("subject attempt %d = %d, want 401: the usernameless failures consumed "+
				"this subject's budget; body: %s", i+1, res.Status, res.Raw)
		}
	}
	locked := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
	if locked.Status != http.StatusTooManyRequests {
		t.Errorf("fourth subject attempt = %d, want 429", locked.Status)
	}
}

func TestDiscoverableBeginIsBoundedByTheNetworkLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerIP = 100
		c.Throttle.MaxRequestsPerKey = 5
		c.Throttle.LockoutDuration = config.Duration{Duration: 15 * time.Minute}
	})

	// The route mints a challenge for anyone with the scope and names no
	// subject, so the per-key request limit is what stops it being used to
	// generate work without bound.
	var throttled bool
	for i := 0; i < 12; i++ {
		res := h.do(http.MethodPost, discoverableBegin, h.apiKey, nil)
		if res.Status == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Error("the usernameless begin route was never throttled: it can be used to mint " +
			"challenges without bound")
	}
}
