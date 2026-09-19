package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// The alert engine has its own unit tests against an in-memory double, and the
// two store backends have theirs against a real database. Nothing tested the
// seam, and a defect lived there: the engine built its row without an
// identifier, both backends require one, so every alert the service raised was
// logged as undeliverable and dropped. The engine's tests stayed green because
// the double minted the identifier itself.
//
// These tests cross the seam. They provoke a condition through the HTTP surface
// and then read the alert back out of the real store, so an alert that cannot
// be written fails a test rather than a log line nobody reads.

// TestAlertFromARequestReachesTheStore is the regression test for that defect.
func TestAlertFromARequestReachesTheStore(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
		c.Throttle.LockoutDuration = config.Duration{Duration: 15 * time.Minute}
	})

	subjectID := newSubject(t, h, "user-1")
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	// One attempt past the subject limit, which is what trips the lockout and
	// raises the alert.
	for i := 0; i < 4; i++ {
		h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
			map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
	}

	raised := listAlerts(t, h.store, store.AlertFilter{})
	if len(raised) != 1 {
		t.Fatalf("alerts in the store = %d, want 1; the lockout raised nothing that was persisted", len(raised))
	}

	got := raised[0]
	if got.ID == "" {
		t.Error("the stored alert has no identifier, so nothing can acknowledge it")
	}
	if got.AlertType != alerts.TypeAuthFailureSubject.String() {
		t.Errorf("alert type = %q, want %q", got.AlertType, alerts.TypeAuthFailureSubject)
	}
	if got.SubjectID != subjectID {
		t.Errorf("alert subject = %q, want the locked-out subject", got.SubjectID)
	}
	if got.Occurrences != 1 {
		t.Errorf("occurrences = %d, want 1 on a first sighting", got.Occurrences)
	}
}

// TestRepeatedConditionAccumulatesOnOneRow checks that the fingerprint
// deduplicates against the real database and not merely against the double.
// Without it a subject under sustained attack would produce one row per
// attempt, which buries the operator in exactly the case they need to see.
func TestRepeatedConditionAccumulatesOnOneRow(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Throttle.MaxFailuresPerSubject = 3
		c.Throttle.MaxFailuresPerIP = 100
		// Equal to the window. The validator refuses a shorter lockout, which
		// would be reapplied by the first attempt after it without any new
		// failure having been evaluated.
		c.Throttle.LockoutDuration = config.Duration{Duration: 15 * time.Minute}
	})

	newSubject(t, h, "user-1")
	h.do(http.MethodPost, "/v1/recovery/user-1/issue", h.apiKey, nil)

	// Two separate lockouts, the clock moved past the first so the limiter
	// admits attempts again and the condition genuinely recurs.
	for round := 0; round < 2; round++ {
		for i := 0; i < 4; i++ {
			h.do(http.MethodPost, "/v1/recovery/user-1/consume", h.apiKey,
				map[string]any{"code": "AAAAA-BBBBB-CCCCC-DDDDD"})
		}
		h.clock.add(16 * time.Minute)
	}

	raised := listAlerts(t, h.store, store.AlertFilter{})
	if len(raised) != 1 {
		t.Fatalf("alerts in the store = %d, want 1 row carrying both sightings", len(raised))
	}
	if raised[0].Occurrences < 2 {
		t.Errorf("occurrences = %d, want at least 2; the second lockout opened a new row instead of counting",
			raised[0].Occurrences)
	}
}

func listAlerts(t *testing.T, st store.Store, f store.AlertFilter) []*store.Alert {
	t.Helper()
	got, err := st.ListAlerts(context.Background(), testTenant, f)
	if err != nil {
		t.Fatalf("listing alerts: %v", err)
	}
	return got
}
