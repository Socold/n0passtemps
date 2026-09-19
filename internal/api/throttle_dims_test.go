package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// wrongRecoveryCode is well formed and matches no selector that was issued.
const wrongRecoveryCode = "AAAAA-BBBBB-CCCCC-DDDDD"

// from builds the header an integrating application declares its end user's
// address in.
func from(ip string) map[string]string { return map[string]string{EndUserIPHeader: ip} }

// auditDetail decodes the detail of one audit entry.
func auditDetail(t *testing.T, e *store.AuditEntry) map[string]any {
	t.Helper()
	detail := map[string]any{}
	if len(e.Detail) == 0 {
		return detail
	}
	if err := json.Unmarshal(e.Detail, &detail); err != nil {
		t.Fatalf("audit detail of %s is not an object: %v", e.EventType, err)
	}
	return detail
}

// TestFailuresAcrossSubjectsCannotLockEverybodyOut is the outage this file is
// named after.
//
// /v1 is called from server to server, so every request arrives from the
// address of the application's backend. That address used to be the network
// dimension, which put every user of the application in one bucket: an
// anonymous visitor of its sign-in page sent wrong codes for a handful of
// accounts and everybody, on every factor, got 429 for the length of a lockout.
func TestFailuresAcrossSubjectsCannotLockEverybodyOut(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 10
		c.Throttle.MaxFailuresPerIP = 50
	})

	// Fifty failures, the whole per-network budget, spread so that no subject
	// reaches its own limit. None of them declares an end-user address.
	for i := range 10 {
		ref := "victim-" + string(rune('a'+i))
		createSubject(t, h, ref)
		for range 5 {
			if res := h.do(http.MethodPost, "/v1/recovery/"+ref+"/consume", h.apiKey,
				map[string]any{"code": wrongRecoveryCode}); res.Status != http.StatusUnauthorized {
				t.Fatalf("a wrong code for %s = %d, want 401; body: %s", ref, res.Status, res.Raw)
			}
		}
	}

	// Somebody who had no part in any of that signs in.
	next := enrolTOTP(t, h, "bystander")
	if res := h.do(http.MethodPost, "/v1/totp/bystander/verify", h.apiKey,
		map[string]any{"code": next()}); res.Status != http.StatusOK {
		t.Fatalf("a subject who never failed = %d, want 200: the failures of other subjects were "+
			"counted against the address of the calling backend; body: %s", res.Status, res.Raw)
	}
	// The route that names nobody has only the network dimension to be refused
	// on, so it is the first to go when that dimension is the wrong one.
	if res := h.do(http.MethodPost, discoverableBegin, h.apiKey, nil); res.Status != http.StatusOK {
		t.Errorf("the usernameless begin = %d, want 200; body: %s", res.Status, res.Raw)
	}
	if n := len(h.auditEntries(audit.EventThrottleTripped)); n != 0 {
		t.Errorf("%d lockouts were applied, want none", n)
	}
}

// TestTheDeclaredAddressIsTheOneLimited checks the network dimension once the
// application says who it is calling for.
func TestTheDeclaredAddressIsTheOneLimited(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 4
	})
	const attacker, bystander = "203.0.113.50", "198.51.100.7"

	// Spread across subjects so that the network limit is the one that trips.
	for i := range 4 {
		ref := "user-" + string(rune('a'+i))
		createSubject(t, h, ref)
		if res := h.doWith(http.MethodPost, "/v1/recovery/"+ref+"/consume", h.apiKey,
			map[string]any{"code": wrongRecoveryCode}, from(attacker)); res.Status != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401; body: %s", i+1, res.Status, res.Raw)
		}
	}

	createSubject(t, h, "user-z")
	locked := h.doWith(http.MethodPost, "/v1/recovery/user-z/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode}, from(attacker))
	if locked.Status != http.StatusTooManyRequests {
		t.Fatalf("the declared address past its budget = %d, want 429; body: %s", locked.Status, locked.Raw)
	}
	if locked.Header.Get("Retry-After") == "" {
		t.Error("the refusal carries no Retry-After")
	}

	// The same subject from another address, and with no address declared.
	for name, headers := range map[string]map[string]string{
		"another address": from(bystander),
		"no address":      nil,
	} {
		if res := h.doWith(http.MethodPost, "/v1/recovery/user-z/consume", h.apiKey,
			map[string]any{"code": wrongRecoveryCode}, headers); res.Status != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401: the lockout of one declared address refused it; body: %s",
				name, res.Status, res.Raw)
		}
	}

	// IPv6 is limited by /64, as everywhere else: a neighbour in the prefix is
	// the same party, and the blocked IPv4 address is not.
	for i := range 4 {
		ref := "user-" + string(rune('a'+i))
		h.doWith(http.MethodPost, "/v1/recovery/"+ref+"/consume", h.apiKey,
			map[string]any{"code": wrongRecoveryCode}, from("2001:db8:1:2::"+string(rune('1'+i))))
	}
	if res := h.doWith(http.MethodPost, "/v1/recovery/user-z/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode}, from("2001:db8:1:2:ffff::9")); res.Status !=
		http.StatusTooManyRequests {
		t.Errorf("a neighbour in a locked-out /64 = %d, want 429; body: %s", res.Status, res.Raw)
	}
}

// TestTheDeclaredAddressIsAuditedNextToThePeer checks that the claim never
// replaces the observation.
func TestTheDeclaredAddressIsAuditedNextToThePeer(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")

	h.doWith(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode}, from("203.0.113.50"))
	h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode})

	entries := h.auditEntries(audit.EventRecoveryRejected)
	if len(entries) != 2 {
		t.Fatalf("%d rejections audited, want 2", len(entries))
	}
	var declared, silent int
	for _, e := range entries {
		if e.SourceIP == "203.0.113.50" {
			t.Errorf("source_ip = %q: the declared address replaced the observed peer", e.SourceIP)
		}
		if e.SourceIP == "" {
			t.Error("source_ip is empty: the observed peer was dropped")
		}
		switch got := auditDetail(t, e)[auditKeyEndUserIP]; got {
		case "203.0.113.50":
			declared++
		case nil:
			silent++
		default:
			t.Errorf("%s = %v", auditKeyEndUserIP, got)
		}
	}
	if declared != 1 || silent != 1 {
		t.Errorf("%d entries carry the declared address and %d carry none, want 1 and 1", declared, silent)
	}
}

// TestAnUnusableEndUserAddressIsRefused checks that a bad header is a 400.
//
// Falling back to no address would switch the network limit off for that
// request in silence, and for every request of an integration that always
// sends the same bad value.
func TestAnUnusableEndUserAddressIsRefused(t *testing.T) {
	h := newHarness(t)
	createSubject(t, h, "user-1")

	for _, value := range []string{
		"unknown", "203.0.113.50:443", "[2001:db8::1]:443", "203.0.113.0/24", "fe80::1%eth0",
		"203.0.113.50, 198.51.100.7", "0.0.0.0", "::", "example.com",
	} {
		res := h.doWith(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": wrongRecoveryCode}, from(value))
		if res.Status != http.StatusBadRequest {
			t.Errorf("%s: %q = %d, want 400; body: %s", EndUserIPHeader, value, res.Status, res.Raw)
			continue
		}
		if detail, _ := res.Body["detail"].(string); !strings.Contains(detail, EndUserIPHeader) {
			t.Errorf("%q: the refusal does not name the header: %s", value, res.Raw)
		}
	}
	if n := len(h.auditEntries(audit.EventRecoveryRejected)); n != 0 {
		t.Errorf("%d of the refused requests went on to be evaluated", n)
	}

	// An IPv4-mapped address is the IPv4 address, not a member of some /64.
	if res := h.doWith(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode}, from("::ffff:203.0.113.50")); res.Status !=
		http.StatusUnauthorized {
		t.Errorf("an IPv4-mapped address = %d, want 401; body: %s", res.Status, res.Raw)
	}
}

// TestWrongCodesDoNotLockTheSubjectOutOfWebAuthn checks that the per-subject
// budget is kept per factor.
//
// A subject reference is not a secret. With one bucket for every factor,
// anybody who knew it sent ten wrong TOTP codes and the subject could not use
// their passkey for a quarter of an hour, which is the factor no amount of
// guessing threatens.
func TestWrongCodesDoNotLockTheSubjectOutOfWebAuthn(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 10
		c.Throttle.MaxFailuresPerIP = 100
	})
	enrolTOTP(t, h, "user-1")
	seedCredential(t, h, "user-1", h.clock.now().Add(-24*time.Hour), nil)

	for i := range 10 {
		if res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
			map[string]any{"code": "000000"}); res.Status != http.StatusUnauthorized {
			t.Fatalf("wrong code %d = %d, want 401; body: %s", i+1, res.Status, res.Raw)
		}
	}
	if res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
		map[string]any{"code": "000000"}); res.Status != http.StatusTooManyRequests {
		t.Fatalf("the TOTP factor after its budget = %d, want 429; body: %s", res.Status, res.Raw)
	}

	if res := h.do(http.MethodPost, "/v1/webauthn/user-1/assert", h.apiKey, nil); res.Status != http.StatusOK {
		t.Errorf("WebAuthn assertion = %d, want 200: wrong TOTP codes locked the subject out of "+
			"their passkey; body: %s", res.Status, res.Raw)
	}
	// The recovery factor is a third budget, so the way back in stays open.
	if res := h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
		map[string]any{"code": wrongRecoveryCode}); res.Status != http.StatusUnauthorized {
		t.Errorf("recovery consume = %d, want 401, which is an evaluated attempt; body: %s", res.Status, res.Raw)
	}

	// The audit entry says which factor, or an operator reading it cannot tell
	// what the subject is locked out of.
	tripped := h.auditEntries(audit.EventThrottleTripped)
	if len(tripped) != 1 {
		t.Fatalf("%d lockouts audited, want 1", len(tripped))
	}
	if got := auditDetail(t, tripped[0])["factor"]; got != "totp" {
		t.Errorf("the lockout names the factor %v, want totp", got)
	}
}

// TestAnAdministrativeResetLiftsEveryFactor checks the unlock an operator
// performs for a user on the telephone.
func TestAnAdministrativeResetLiftsEveryFactor(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 2
		c.Throttle.MaxFailuresPerIP = 100
	})
	enrolTOTP(t, h, "user-1")
	id := createSubject(t, h, "user-1")

	for range 2 {
		h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": "000000"})
		h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey, map[string]any{"code": wrongRecoveryCode})
	}
	for _, path := range []string{"/v1/totp/user-1/verify", "/v1/recovery/user-1/consume"} {
		if res := h.do(http.MethodPost, path, h.apiKey,
			map[string]any{"code": "000000"}); res.Status != http.StatusTooManyRequests {
			t.Fatalf("%s before the reset = %d, want 429", path, res.Status)
		}
	}

	admin := h.mintAdminToken("operator", store.RoleFull)
	if res := h.do(http.MethodPost, "/admin/v1/subjects/"+id+"/throttle/reset", admin, nil); res.Status !=
		http.StatusOK {
		t.Fatalf("reset = %d; body: %s", res.Status, res.Raw)
	}
	for _, path := range []string{"/v1/totp/user-1/verify", "/v1/recovery/user-1/consume"} {
		if res := h.do(http.MethodPost, path, h.apiKey,
			map[string]any{"code": "000000"}); res.Status != http.StatusUnauthorized {
			t.Errorf("%s after the reset = %d, want 401: the reset left a factor locked", path, res.Status)
		}
	}
}

// TestAParallelBurstOfGuessesIsHeldToTheBudget checks the reservation end to
// end, against the real store.
//
// The limit used to be checked before the code was compared and the failure
// written after, so every request of a burst passed the check before any had
// recorded anything: sixty parallel guesses at a six-digit code got about
// thirty of them evaluated against a budget of ten.
//
// The assertion holds for every interleaving and not only for a likely one. An
// attempt is evaluated only when the store's atomic increment handed it a count
// inside the budget, and a wrong code never gives a count back, so the number
// of 401 responses cannot exceed the budget however the requests are scheduled.
func TestAParallelBurstOfGuessesIsHeldToTheBudget(t *testing.T) {
	const budget, burst = 10, 60
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = budget
		c.Throttle.MaxFailuresPerIP = 1000
	})
	enrolTOTP(t, h, "user-1")

	var (
		start   = make(chan struct{})
		wg      sync.WaitGroup
		mu      sync.Mutex
		outcome = map[int]int{}
		failed  []error
	)
	for range burst {
		wg.Go(func() {
			<-start
			status, err := postStatus(h, "/v1/totp/user-1/verify", `{"code":"000000"}`)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, err)
				return
			}
			outcome[status]++
		})
	}
	close(start)
	wg.Wait()

	if len(failed) > 0 {
		t.Fatalf("%d requests did not complete, the first with: %v", len(failed), failed[0])
	}
	evaluated, refused := outcome[http.StatusUnauthorized], outcome[http.StatusTooManyRequests]
	if evaluated+refused != burst {
		t.Fatalf("outcomes = %v, want only 401 and 429", outcome)
	}
	if evaluated > budget {
		t.Errorf("%d guesses were evaluated in one burst against a budget of %d", evaluated, budget)
	}
	if evaluated == 0 {
		t.Error("no guess was evaluated at all, so the test proved nothing about the budget")
	}
}

// postStatus sends one request without touching testing.T, so that it may be
// called from a goroutine other than the test's own.
func postStatus(h *harness, path, body string) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+path,
		strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := h.srv.Client().Do(req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, res.Body.Close()
}

// TestTheRightCodeAfterWrongOnesLocksNothing checks the success path on a
// bucket that is one failure short of its limit.
//
// Recording a success used to judge the failure threshold as well, so a user
// whose count already stood at the limit was locked out by the request that
// proved who they were. A success now clears the count for the factor instead.
func TestTheRightCodeAfterWrongOnesLocksNothing(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
	})
	next := enrolTOTP(t, h, "user-1")

	// Twice over, so that the second round shows the first success cleared the
	// count: without that, its second wrong code would be the fourth failure.
	for round := range 2 {
		for range 2 {
			h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": "000000"})
		}
		// The third attempt is the last the budget allows, and it is right.
		if res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
			map[string]any{"code": next()}); res.Status != http.StatusOK {
			t.Fatalf("round %d: the right code = %d, want 200; body: %s", round+1, res.Status, res.Raw)
		}
	}
	if res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey,
		map[string]any{"code": next()}); res.Status != http.StatusOK {
		t.Errorf("a further right code = %d, want 200; body: %s", res.Status, res.Raw)
	}
	if n := len(h.auditEntries(audit.EventThrottleTripped)); n != 0 {
		t.Errorf("%d lockouts were applied to a user who kept getting in", n)
	}
}

// TestThePerKeyCeilingDoesNotOutlastItsWindow checks that an application which
// ran hot is served again as soon as the window rolls.
//
// Crossing the ceiling used to block the key for lockout_duration. The key is
// the whole application, so that was an outage for all of its users.
func TestThePerKeyCeilingDoesNotOutlastItsWindow(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxRequestsPerKey = 5
		c.Throttle.Window = config.Duration{Duration: 5 * time.Minute}
		c.Throttle.LockoutDuration = config.Duration{Duration: time.Hour}
	})

	var last response
	for range 8 {
		last = h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "user-1"})
	}
	if last.Status != http.StatusTooManyRequests {
		t.Fatalf("past the ceiling = %d, want 429", last.Status)
	}
	if got := last.num(t, "retry_after_seconds"); got <= 0 || got > 300 {
		t.Errorf("retry_after_seconds = %v, want what is left of a five-minute window", got)
	}

	h.clock.add(5*time.Minute + time.Second)
	if res := h.do(http.MethodPost, "/v1/subjects", h.apiKey,
		map[string]any{"subject_ref": "user-1"}); res.Status != http.StatusOK {
		t.Errorf("once the window rolled = %d, want 200: the ceiling applied a lockout; body: %s",
			res.Status, res.Raw)
	}
}

// TestIssuingRecoveryCodesHonoursTheFactorLockout checks that the most
// expensive route is behind the limiter like the others.
func TestIssuingRecoveryCodesHonoursTheFactorLockout(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 2
		c.Throttle.MaxFailuresPerIP = 100
	})
	createSubject(t, h, "user-1")

	if res := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil); res.Status != http.StatusCreated {
		t.Fatalf("issue = %d; body: %s", res.Status, res.Raw)
	}
	for range 2 {
		h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey, map[string]any{"code": wrongRecoveryCode})
	}
	if res := h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil); res.Status !=
		http.StatusTooManyRequests {
		t.Errorf("issue while the recovery factor is locked out = %d, want 429; body: %s", res.Status, res.Raw)
	}
}

// TestKeyDerivationSlotsAreBounded checks the semaphore around Argon2id.
func TestKeyDerivationSlotsAreBounded(t *testing.T) {
	if n := cap(kdfSlots); n < 2 || n > 8 {
		t.Fatalf("%d slots, want between 2 and 8", n)
	}

	// Every slot taken, as under a burst of issuing requests.
	var held []func()
	for range cap(kdfSlots) {
		release, err := acquireKDFWithin(t.Context(), time.Minute)
		if err != nil {
			t.Fatalf("a free slot was refused: %v", err)
		}
		held = append(held, release)
	}
	defer func() {
		for _, release := range held {
			release()
		}
	}()

	_, err := acquireKDFWithin(t.Context(), 10*time.Millisecond)
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Status != http.StatusServiceUnavailable {
		t.Fatalf("waiting past the patience = %v, want a 503", err)
	}
	if refusal.RetryAfterSeconds <= 0 {
		t.Error("the 503 carries no Retry-After, so a client can only guess when to come back")
	}

	// A request whose client has gone away gives up its place at once.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = acquireKDFWithin(ctx, time.Minute); !errors.As(err, &refusal) ||
		!errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled request = %v, want a refusal wrapping context.Canceled", err)
	}

	// And a slot given back is a slot the next request gets.
	held[0]()
	held = held[1:]
	release, err := acquireKDFWithin(t.Context(), time.Second)
	if err != nil {
		t.Fatalf("a released slot was not handed on: %v", err)
	}
	release()
}

// TestAStrangerCannotTakeAwayAPasskey is the budget that is reported and not
// enforced.
//
// Beginning an assertion for a subject needs nothing but their reference, and
// completing it with rubbish is a failure charged to them. Enforcing the
// per-subject budget there let anybody who knew a reference lock that person
// out of the factor they use every day, from a page they do not control. The
// failures are still counted and still audited, because an operator wants to
// know it is happening; what is withheld is the refusal.
func TestAStrangerCannotTakeAwayAPasskey(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
	})
	enrolTOTP(t, h, "user-1")
	seedCredential(t, h, "user-1", h.clock.now().Add(-24*time.Hour), nil)

	// Well past the budget, each one a completion that verifies against
	// nothing.
	for i := range 8 {
		begin := h.do(http.MethodPost, "/v1/webauthn/user-1/assert", h.apiKey, nil)
		if begin.Status != http.StatusOK {
			t.Fatalf("assertion %d refused at begin = %d: the subject was locked out; body: %s",
				i+1, begin.Status, begin.Raw)
		}
		done := h.do(http.MethodPost, "/v1/webauthn/user-1/assert/complete", h.apiKey,
			map[string]any{"challenge_id": begin.str(t, "challenge_id"), "credential": json.RawMessage(`{}`)})
		if done.Status == http.StatusTooManyRequests {
			t.Fatalf("completion %d = 429: a stranger locked the subject out of their passkey", i+1)
		}
	}

	// The genuine owner is still able to start a ceremony.
	if res := h.do(http.MethodPost, "/v1/webauthn/user-1/assert", h.apiKey, nil); res.Status != http.StatusOK {
		t.Fatalf("the subject's own assertion = %d, want 200; body: %s", res.Status, res.Raw)
	}

	// Reported, and honest about having refused nothing.
	tripped := h.auditEntries(audit.EventThrottleTripped)
	if len(tripped) == 0 {
		t.Fatal("nothing was audited: an operator has no way to see the attempts")
	}
	detail := auditDetail(t, tripped[0])
	if detail["factor"] != "webauthn" {
		t.Errorf("the entry names the factor %v, want webauthn", detail["factor"])
	}
	if detail["enforced"] != false {
		t.Errorf("the entry says enforced = %v, want false: nothing was refused", detail["enforced"])
	}

	// The factors where a wrong answer is a guess still lock out.
	for i := range 4 {
		res := h.do(http.MethodPost, "/v1/totp/user-1/verify", h.apiKey, map[string]any{"code": "000000"})
		if i == 3 && res.Status != http.StatusTooManyRequests {
			t.Errorf("the TOTP budget after %d wrong codes = %d, want 429", i+1, res.Status)
		}
	}
}

// TestTheCompletionRouteAcceptsTheNameForTheKey guards the field that carries
// it.
//
// The begin call has always taken a label and the completion passed an empty
// string to the store, so the column an operator reads to tell one of a
// subject's keys from another was empty for every credential ever enrolled.
// This package completes no real ceremony, so what is held here is the part
// that broke: the completion body carries the label. decodeJSON refuses an
// unknown field, so a body naming one the route has stopped reading is a 400,
// and this test fails rather than the column quietly emptying again.
func TestTheCompletionRouteAcceptsTheNameForTheKey(t *testing.T) {
	h := newHarness(t)
	enrolTOTP(t, h, "user-1")

	for _, tc := range []struct {
		name string
		path string
		body map[string]any
	}{
		{
			name: "ordinary registration",
			path: "/v1/webauthn/user-1/register/complete",
			body: map[string]any{
				"challenge_id": uuid.NewString(),
				"credential":   json.RawMessage(`{}`),
				"label":        "the key on my keyring",
			},
		},
		{
			name: "enrolment ticket",
			path: "/v1/enrolment/register/complete",
			body: map[string]any{
				"ticket":       "npt_not_a_real_ticket",
				"challenge_id": uuid.NewString(),
				"credential":   json.RawMessage(`{}`),
				"label":        "the key the helpdesk sent me",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := h.do(http.MethodPost, tc.path, h.apiKey, tc.body)
			if res.Status == http.StatusBadRequest {
				t.Fatalf("the label was refused by the route: %s", res.Raw)
			}
		})
	}
}
