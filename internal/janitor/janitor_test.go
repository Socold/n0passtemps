package janitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

var testNow = time.Date(2026, 6, 15, 4, 0, 0, 0, time.UTC)

// fakeStore embeds the interface so that only the methods a sweep uses need a
// body. Anything else panics on the nil embedded value, which is the right
// outcome if the janitor starts reaching for parts of the store it has no
// business with.
type fakeStore struct {
	store.Store

	// calls records every store call in order, as "method" or
	// "method:subject", so a test can assert sequencing.
	calls []string

	// errs maps a call string to the error it returns.
	errs map[string]error

	due []*store.ErasureRequest

	challengesBefore time.Time
	ticketsBefore    time.Time
	throttlesBefore  time.Time
	approvalsBefore  time.Time
	dueBefore        time.Time
	dueLimit         int

	pruneTenant string
	pruneBefore time.Time
	pruneNow    time.Time
	pruned      int64

	eraseActors []string
	eraseTimes  []time.Time
	markedAt    []time.Time
	appended    []*store.AuditEntry
}

func (f *fakeStore) note(call string) error {
	f.calls = append(f.calls, call)
	return f.errs[call]
}

func (f *fakeStore) called(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if c == prefix || strings.HasPrefix(c, prefix+":") {
			n++
		}
	}
	return n
}

func (f *fakeStore) DeleteExpiredChallenges(_ context.Context, before time.Time) (int64, error) {
	f.challengesBefore = before
	return 3, f.note("challenges")
}

func (f *fakeStore) DeleteExpiredEnrolmentTickets(_ context.Context, before time.Time) (int64, error) {
	f.ticketsBefore = before
	return 4, f.note("tickets")
}

func (f *fakeStore) DeleteStaleThrottles(_ context.Context, before time.Time) (int64, error) {
	f.throttlesBefore = before
	return 5, f.note("throttles")
}

func (f *fakeStore) ExpireApprovals(_ context.Context, before time.Time) (int64, error) {
	f.approvalsBefore = before
	return 2, f.note("approvals")
}

func (f *fakeStore) ListDueErasures(_ context.Context, before time.Time, limit int) ([]*store.ErasureRequest, error) {
	f.dueBefore, f.dueLimit = before, limit
	if err := f.note("list-erasures"); err != nil {
		return nil, err
	}
	return f.due, nil
}

func (f *fakeStore) EraseSubjectAuditEntries(_ context.Context, _, subjectID, actorID string, now time.Time) (int64, error) {
	f.eraseActors = append(f.eraseActors, actorID)
	f.eraseTimes = append(f.eraseTimes, now)
	return 4, f.note("erase-audit:" + subjectID)
}

func (f *fakeStore) PurgeSubject(_ context.Context, _, id string) error {
	return f.note("purge-subject:" + id)
}

func (f *fakeStore) MarkErasurePurged(_ context.Context, _, id string, at time.Time) error {
	f.markedAt = append(f.markedAt, at)
	return f.note("mark-purged:" + id)
}

func (f *fakeStore) PruneAuditLog(_ context.Context, tenantID string, before, now time.Time) (int64, error) {
	f.pruneTenant, f.pruneBefore, f.pruneNow = tenantID, before, now
	return f.pruned, f.note("prune-audit")
}

func (f *fakeStore) Append(_ context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if err := f.note("audit-append:" + e.ResourceID); err != nil {
		return nil, err
	}
	f.appended = append(f.appended, e)
	return e, nil
}

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Tenant.ID = "tenant-a"
	cfg.Throttle.Window = config.Duration{Duration: 15 * time.Minute}
	cfg.Features.DualApproval = true
	return cfg
}

func newJanitor(cfg *config.Config, st *fakeStore) *Janitor {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return New(cfg, st, audit.NewRecorder(st, log), nil, log, func() time.Time { return testNow })
}

func erasure(id, subjectID string) *store.ErasureRequest {
	return &store.ErasureRequest{
		ID:          id,
		TenantID:    "tenant-a",
		SubjectID:   subjectID,
		Status:      "pending",
		RequestedBy: "admin-1",
		RequestedAt: testNow.Add(-31 * 24 * time.Hour),
		PurgeAfter:  testNow.Add(-24 * time.Hour),
	}
}

func TestSweepCounts(t *testing.T) {
	st := &fakeStore{due: []*store.ErasureRequest{erasure("er-1", "sub-1")}, pruned: 7}
	cfg := testConfig()
	cfg.Audit.RetentionDays = 30

	res := newJanitor(cfg, st).Sweep(context.Background())

	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}
	want := Result{Challenges: 3, Tickets: 4, Throttles: 5, Approvals: 2, Erasures: 1, AuditPruned: 7}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("result = %+v, want %+v", res, want)
	}

	if !st.challengesBefore.Equal(testNow) {
		t.Errorf("challenges were deleted before %v, want the injected clock: a later cutoff would remove a ceremony still in progress", st.challengesBefore)
	}
	if !st.ticketsBefore.Equal(testNow) {
		t.Errorf("tickets were deleted before %v, want the injected clock: a later cutoff would remove a ticket a user is still redeeming", st.ticketsBefore)
	}
	if !st.approvalsBefore.Equal(testNow) {
		t.Errorf("approvals were expired before %v, want the injected clock", st.approvalsBefore)
	}
	if !st.dueBefore.Equal(testNow) {
		t.Errorf("erasures were listed as due before %v, want the injected clock: a later cutoff purges a subject inside their retention window", st.dueBefore)
	}
	if st.dueLimit <= 0 {
		t.Errorf("erasures were listed with limit %d: an unbounded batch can outlast the sweep timeout", st.dueLimit)
	}

	// Buckets stay for four windows past expiry so that a lockout which has
	// only now ended is still there when an operator asks about it.
	if wantCutoff := testNow.Add(-time.Hour); !st.throttlesBefore.Equal(wantCutoff) {
		t.Errorf("throttle cutoff = %v, want %v (four windows back)", st.throttlesBefore, wantCutoff)
	}
}

func TestSweepRunsEverySweepDespiteErrors(t *testing.T) {
	errChallenges := errors.New("challenges failed")
	errTickets := errors.New("tickets failed")
	errThrottles := errors.New("throttles failed")
	errApprovals := errors.New("approvals failed")
	errList := errors.New("list failed")
	errPrune := errors.New("prune failed")

	t.Run("first sweep fails", func(t *testing.T) {
		st := &fakeStore{
			errs:   map[string]error{"challenges": errChallenges},
			due:    []*store.ErasureRequest{erasure("er-1", "sub-1")},
			pruned: 7,
		}
		cfg := testConfig()
		cfg.Audit.RetentionDays = 30

		res := newJanitor(cfg, st).Sweep(context.Background())

		for _, call := range []string{"challenges", "tickets", "throttles", "approvals", "list-erasures", "erase-audit", "prune-audit"} {
			if st.called(call) != 1 {
				t.Errorf("%s ran %d times, want 1: a janitor that stops at its first error has silently given up its other duties", call, st.called(call))
			}
		}
		if len(res.Errors) != 1 || !errors.Is(res.Errors[0], errChallenges) {
			t.Errorf("errors = %v, want only the challenges failure", res.Errors)
		}
		if res.Challenges != 0 {
			t.Errorf("challenges = %d for a sweep that failed", res.Challenges)
		}
		if res.Tickets != 4 || res.Throttles != 5 || res.Approvals != 2 || res.Erasures != 1 || res.AuditPruned != 7 {
			t.Errorf("result = %+v: the sweeps after the failure did not report their work", res)
		}
	})

	t.Run("every sweep fails", func(t *testing.T) {
		st := &fakeStore{errs: map[string]error{
			"challenges":    errChallenges,
			"tickets":       errTickets,
			"throttles":     errThrottles,
			"approvals":     errApprovals,
			"list-erasures": errList,
			"prune-audit":   errPrune,
		}}
		cfg := testConfig()
		cfg.Audit.RetentionDays = 30

		res := newJanitor(cfg, st).Sweep(context.Background())

		wantCalls := []string{"challenges", "tickets", "throttles", "approvals", "list-erasures", "prune-audit"}
		if !reflect.DeepEqual(st.calls, wantCalls) {
			t.Errorf("calls = %v, want %v", st.calls, wantCalls)
		}
		if len(res.Errors) != 6 {
			t.Fatalf("collected %d errors, want 6: the operator must see every problem from one pass, not only the first", len(res.Errors))
		}
		for _, want := range []error{errChallenges, errTickets, errThrottles, errApprovals, errList, errPrune} {
			if !errors.Is(errors.Join(res.Errors...), want) {
				t.Errorf("%q is missing from the collected errors", want)
			}
		}
		if res.Challenges+res.Tickets+res.Throttles+res.Approvals+res.Erasures+res.AuditPruned != 0 {
			t.Errorf("result = %+v: failed sweeps reported work", res)
		}
	})
}

func TestErasureOrder(t *testing.T) {
	st := &fakeStore{due: []*store.ErasureRequest{erasure("er-1", "sub-1")}}
	res := newJanitor(testConfig(), st).Sweep(context.Background())

	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v", res.Errors)
	}

	var got []string
	for _, c := range st.calls {
		if strings.Contains(c, "sub-1") || strings.Contains(c, "er-1") {
			got = append(got, c)
		}
	}
	// Audit entries first: once the subject row is gone nothing can find the
	// entries that still name them, and their personal fields stay for ever.
	// Marked last: a request marked purged before the purge happened is never
	// retried if the purge then fails.
	want := []string{"erase-audit:sub-1", "purge-subject:sub-1", "mark-purged:er-1", "audit-append:er-1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("erasure steps ran as %v, want %v: the order is what keeps a half-finished erasure retryable", got, want)
	}

	if len(st.eraseActors) != 1 || st.eraseActors[0] != "system:janitor" {
		t.Errorf("audit entries were erased as %v, want system:janitor", st.eraseActors)
	}
	if !st.eraseTimes[0].Equal(testNow) || !st.markedAt[0].Equal(testNow) {
		t.Errorf("erasure stamped %v and %v, want the injected clock", st.eraseTimes[0], st.markedAt[0])
	}

	if len(st.appended) != 1 {
		t.Fatalf("%d audit entries recorded, want 1: a completed erasure must itself be on the record", len(st.appended))
	}
	entry := st.appended[0]
	if entry.EventType != audit.EventErasurePurged || entry.Outcome != store.OutcomeSuccess ||
		entry.ActorType != store.ActorSystem || entry.ResourceType != "erasure_request" || entry.ResourceID != "er-1" {
		t.Errorf("audit entry = %+v", entry)
	}
	// The entry recording an erasure must not reintroduce what was erased.
	if entry.SubjectID != "" {
		t.Errorf("the erasure entry names subject %q: it would become a fresh personal record about the person who was erased", entry.SubjectID)
	}
	if strings.Contains(string(entry.Detail), "sub-1") {
		t.Errorf("the erasure entry detail names the erased subject: %s", entry.Detail)
	}
}

func TestErasureFailureDoesNotStopTheNext(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name      string
		failAt    string
		wantCalls []string
	}{
		{
			name:   "audit erasure fails",
			failAt: "erase-audit:sub-1",
			// The subject must survive: purging them now would orphan audit
			// entries that still carry their personal fields.
			wantCalls: []string{"erase-audit:sub-1"},
		},
		{
			name:   "subject purge fails",
			failAt: "purge-subject:sub-1",
			// Not marked purged, so the next pass tries again.
			wantCalls: []string{"erase-audit:sub-1", "purge-subject:sub-1"},
		},
		{
			name:      "marking fails",
			failAt:    "mark-purged:er-1",
			wantCalls: []string{"erase-audit:sub-1", "purge-subject:sub-1", "mark-purged:er-1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{
				errs: map[string]error{tc.failAt: boom},
				due: []*store.ErasureRequest{
					erasure("er-1", "sub-1"),
					erasure("er-2", "sub-2"),
					erasure("er-3", "sub-3"),
				},
			}
			cfg := testConfig()
			cfg.Audit.RetentionDays = 30
			res := newJanitor(cfg, st).Sweep(context.Background())

			var first []string
			for _, c := range st.calls {
				if strings.HasSuffix(c, ":sub-1") || strings.HasSuffix(c, ":er-1") {
					first = append(first, c)
				}
			}
			if !reflect.DeepEqual(first, tc.wantCalls) {
				t.Errorf("steps for the failing erasure = %v, want %v", first, tc.wantCalls)
			}

			for _, n := range []string{"2", "3"} {
				for _, call := range []string{"erase-audit:sub-" + n, "purge-subject:sub-" + n, "mark-purged:er-" + n} {
					if st.called(call) != 1 {
						t.Errorf("%s ran %d times, want 1: one subject's failure must not leave another's erasure request unanswered", call, st.called(call))
					}
				}
			}

			if len(res.Errors) != 1 || !errors.Is(res.Errors[0], boom) {
				t.Errorf("errors = %v, want the one failure reported", res.Errors)
			}
			if st.called("prune-audit") != 1 {
				t.Error("audit pruning was skipped after a failed erasure")
			}
		})
	}

	t.Run("a subject already gone still completes", func(t *testing.T) {
		// A previous pass purged the subject and then failed to mark the
		// request. Treating not-found as a failure would leave that request
		// pending for ever.
		st := &fakeStore{
			errs: map[string]error{"purge-subject:sub-1": fmt.Errorf("sqlite: %w", store.ErrNotFound)},
			due:  []*store.ErasureRequest{erasure("er-1", "sub-1")},
		}
		res := newJanitor(testConfig(), st).Sweep(context.Background())

		if len(res.Errors) != 0 {
			t.Errorf("errors = %v, want none", res.Errors)
		}
		if st.called("mark-purged:er-1") != 1 {
			t.Error("the request was not marked purged although its subject no longer exists")
		}
		if res.Erasures != 1 {
			t.Errorf("erasures = %d, want 1", res.Erasures)
		}
	})

	t.Run("a failed audit append is reported", func(t *testing.T) {
		st := &fakeStore{
			errs: map[string]error{"audit-append:er-1": boom},
			due:  []*store.ErasureRequest{erasure("er-1", "sub-1"), erasure("er-2", "sub-2")},
		}
		res := newJanitor(testConfig(), st).Sweep(context.Background())

		if len(res.Errors) != 1 || !errors.Is(res.Errors[0], boom) {
			t.Errorf("errors = %v: an erasure that left no audit entry must not pass silently", res.Errors)
		}
		if st.called("mark-purged:er-2") != 1 {
			t.Error("the second erasure was abandoned after the first failed to record its audit entry")
		}
	})
}

func TestAuditPruning(t *testing.T) {
	t.Run("skipped when retention is zero", func(t *testing.T) {
		// Discarding audit history has to be a deliberate decision. The
		// default must never remove an entry.
		for _, days := range []int{0, -1} {
			st := &fakeStore{pruned: 9}
			cfg := testConfig()
			cfg.Audit.RetentionDays = days

			res := newJanitor(cfg, st).Sweep(context.Background())

			if st.called("prune-audit") != 0 {
				t.Errorf("retention_days = %d: the audit log was pruned although no retention is configured", days)
			}
			if res.AuditPruned != 0 {
				t.Errorf("retention_days = %d: audit_pruned = %d", days, res.AuditPruned)
			}
		}
	})

	tests := []struct {
		days       int
		wantCutoff time.Time
	}{
		{1, time.Date(2026, 6, 14, 4, 0, 0, 0, time.UTC)},
		{30, time.Date(2026, 5, 16, 4, 0, 0, 0, time.UTC)},
		{365, time.Date(2025, 6, 15, 4, 0, 0, 0, time.UTC)},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("retention of %d days", tc.days), func(t *testing.T) {
			st := &fakeStore{pruned: 9}
			cfg := testConfig()
			cfg.Audit.RetentionDays = tc.days

			res := newJanitor(cfg, st).Sweep(context.Background())

			if st.called("prune-audit") != 1 {
				t.Fatalf("prune ran %d times, want 1", st.called("prune-audit"))
			}
			if !st.pruneBefore.Equal(tc.wantCutoff) {
				t.Errorf("cutoff = %v, want %v: a later cutoff destroys audit history the operator asked to keep", st.pruneBefore, tc.wantCutoff)
			}
			if !st.pruneNow.Equal(testNow) {
				t.Errorf("prune was stamped %v, want the injected clock", st.pruneNow)
			}
			if st.pruneTenant != "tenant-a" {
				t.Errorf("pruned tenant %q, want tenant-a", st.pruneTenant)
			}
			if res.AuditPruned != 9 {
				t.Errorf("audit_pruned = %d, want 9", res.AuditPruned)
			}
		})
	}
}

func TestApprovalsSweepFollowsFeature(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		wantCalls int
		wantCount int64
	}{
		{"dual approval on", true, 1, 2},
		{"dual approval off", false, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{}
			cfg := testConfig()
			cfg.Features.DualApproval = tc.enabled

			res := newJanitor(cfg, st).Sweep(context.Background())

			if got := st.called("approvals"); got != tc.wantCalls {
				t.Errorf("approvals sweep ran %d times, want %d", got, tc.wantCalls)
			}
			if res.Approvals != tc.wantCount {
				t.Errorf("approvals = %d, want %d", res.Approvals, tc.wantCount)
			}
			// The remaining sweeps do not depend on the feature.
			if st.called("challenges") != 1 || st.called("throttles") != 1 || st.called("list-erasures") != 1 {
				t.Errorf("calls = %v: the other sweeps must run whatever the feature setting", st.calls)
			}
		})
	}
}

func TestOnceIsOnePass(t *testing.T) {
	st := &fakeStore{}
	res := newJanitor(testConfig(), st).Once(context.Background())
	if st.called("challenges") != 1 {
		t.Errorf("Once ran the challenge sweep %d times, want 1", st.called("challenges"))
	}
	if len(res.Errors) != 0 {
		t.Errorf("errors = %v", res.Errors)
	}
}

func TestRunDisabledReturns(t *testing.T) {
	// A non-positive interval would make time.NewTicker panic. Run has to
	// return instead, and must not sweep.
	st := &fakeStore{}
	cfg := testConfig()
	cfg.Features.JanitorInterval = config.Duration{}

	newJanitor(cfg, st).Run(context.Background())

	if len(st.calls) != 0 {
		t.Errorf("a disabled janitor touched the store: %v", st.calls)
	}
}

func TestStarterSweepsImmediatelyAndStops(t *testing.T) {
	// The first pass must not wait for an interval, so a restart clears what
	// built up while the process was down. The interval here is an hour, so
	// any sweep observed is the immediate one.
	swept := make(chan struct{}, 1)
	st := &signallingStore{fakeStore: &fakeStore{}, swept: swept}
	cfg := testConfig()
	cfg.Features.JanitorInterval = config.Duration{Duration: time.Hour}

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	j := New(cfg, st, audit.NewRecorder(st, log), nil, log, func() time.Time { return testNow })

	s := Start(context.Background(), j)
	<-swept
	s.Stop()

	if got := st.called("challenges"); got != 1 {
		t.Errorf("challenge sweep ran %d times before Stop, want exactly the immediate pass", got)
	}
}

// signallingStore reports the end of a pass. PruneAuditLog is not reached with
// retention at zero, so the erasure listing is the last call of a pass.
type signallingStore struct {
	*fakeStore
	swept chan struct{}
}

func (s *signallingStore) ListDueErasures(ctx context.Context, before time.Time, limit int) ([]*store.ErasureRequest, error) {
	out, err := s.fakeStore.ListDueErasures(ctx, before, limit)
	select {
	case s.swept <- struct{}{}:
	default:
	}
	return out, err
}
