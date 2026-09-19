package janitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
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

	// mu guards the call record, because the contention tests run two passes
	// at once against one store.
	mu sync.Mutex

	// calls records every store call in order, as "method" or
	// "method:subject", so a test can assert sequencing.
	calls []string

	// lock is the sweep lock. The tests that contend share one explicitly; the
	// others get one on first use, so a test written before the lock existed
	// still sweeps.
	lock *leaseTable

	// errs maps a call string to the error it returns.
	errs map[string]error

	due []*store.ErasureRequest

	challengesBefore time.Time
	ticketsBefore    time.Time
	throttlesBefore  time.Time
	approvalsBefore  time.Time
	recoveryBefore   time.Time
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return f.errs[call]
}

func (f *fakeStore) called(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == prefix || strings.HasPrefix(c, prefix+":") {
			n++
		}
	}
	return n
}

// recorded returns a copy of the call record, for the assertions that compare
// the whole sequence.
func (f *fakeStore) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// TryAcquireJanitorLock implements the sweep lock.
func (f *fakeStore) TryAcquireJanitorLock(_ context.Context, owner string, now time.Time, lease time.Duration) (store.JanitorLock, error) {
	if f.lock == nil {
		f.lock = &leaseTable{}
	}
	return f.lock.acquire(owner, now, lease)
}

// leaseTable is the sweep lock the tests contend for: an owner and an expiry,
// which is the SQLite mechanism in miniature. The PostgreSQL one lives on a
// connection and cannot be modelled without one, so it is exercised against a
// live cluster in internal/store/postgres instead.
type leaseTable struct {
	mu sync.Mutex

	owner   string
	expires time.Time

	// err is returned in place of a verdict, for the pass whose database will
	// not answer at all.
	err error

	granted  int
	refused  int
	released int
}

func (l *leaseTable) acquire(owner string, now time.Time, lease time.Duration) (store.JanitorLock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.err != nil {
		return nil, l.err
	}
	if l.owner != "" && now.Before(l.expires) {
		l.refused++
		return nil, fmt.Errorf("%w: held by %s", store.ErrLockHeld, l.owner)
	}
	l.owner, l.expires = owner, now.Add(lease)
	l.granted++
	return &fakeLease{table: l, owner: owner}, nil
}

func (l *leaseTable) counts() (granted, refused, released int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.granted, l.refused, l.released
}

func (l *leaseTable) heldBy() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.owner
}

type fakeLease struct {
	table *leaseTable
	owner string
}

func (f *fakeLease) Release(context.Context) error {
	f.table.mu.Lock()
	defer f.table.mu.Unlock()
	if f.table.owner != f.owner {
		return fmt.Errorf("the lease of %q had already been taken over", f.owner)
	}
	f.table.owner, f.table.expires = "", time.Time{}
	f.table.released++
	return nil
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

// DeleteConsumedRecoveryCodes satisfies the optional interface the sweep looks
// for. It is optional because it is a maintenance capability rather than part
// of the store contract, and TestSweepWithoutARecoveryCodePruner covers the
// store that does not offer it.
func (f *fakeStore) DeleteConsumedRecoveryCodes(_ context.Context, before time.Time) (int64, error) {
	f.recoveryBefore = before
	return 6, f.note("recovery-codes")
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
	want := Result{
		Challenges: 3, Tickets: 4, Throttles: 5, Approvals: 2, Erasures: 1,
		RecoveryCodes: 6, AuditPruned: 7,
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("result = %+v, want %+v", res, want)
	}

	// Spent recovery codes are swept behind a retention window rather than at
	// the pass's own instant: a code spent this morning is still the evidence
	// of that authentication, and only a code nobody will ask about again is
	// worth removing. What the sweep buys is a bounded table, since the
	// selector is unique per tenant and a table that only grows eventually
	// refuses a reissue.
	if wantCutoff := testNow.Add(-consumedRecoveryCodeRetention); !st.recoveryBefore.Equal(wantCutoff) {
		t.Errorf("spent recovery codes were removed before %v, want %v", st.recoveryBefore, wantCutoff)
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

// withoutPruner presents a store through the contract alone, so that the
// optional sweep is not visible on it. Embedding the interface rather than the
// concrete type is what hides the extra method, and every other call forwards.
type withoutPruner struct {
	store.Store
}

// TestSweepWithoutARecoveryCodePruner covers a store that does not offer the
// recovery code sweep.
//
// The capability is looked for on the store rather than declared in the
// contract, so the pass has to go on without it rather than fail or panic. Both
// engines do offer it; this is about the shape of the arrangement, and about
// any store a test or an embedder hands the janitor.
func TestSweepWithoutARecoveryCodePruner(t *testing.T) {
	st := &fakeStore{}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	j := New(testConfig(), withoutPruner{Store: st}, audit.NewRecorder(st, log), nil, log,
		func() time.Time { return testNow })

	res := j.Sweep(context.Background())

	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none: a store without the sweep is not a broken store", res.Errors)
	}
	if res.RecoveryCodes != 0 {
		t.Errorf("recovery codes removed = %d, want 0", res.RecoveryCodes)
	}
	if n := st.called("recovery-codes"); n != 0 {
		t.Errorf("the sweep reached the store %d times through an interface that does not offer it", n)
	}
	if n := st.called("challenges"); n != 1 {
		t.Errorf("challenges swept %d times, want 1: the rest of the pass must be unaffected", n)
	}
}

// TestReplicaOwnerSeparatesTwoProcessesThatLookAlike covers the name a replica
// gives itself in the sweep lock.
//
// The name used to be the hostname and the process identifier. Two containers
// started from one image are routinely given the same hostname and both run
// their service as process 1, so on that deployment every replica called itself
// the same thing. Releasing a lease is conditional on the owner, so two
// replicas answering to one name each delete the lease the other is holding and
// both sweep the same interval, which is the situation the lock exists to
// prevent.
func TestReplicaOwnerSeparatesTwoProcessesThatLookAlike(t *testing.T) {
	first, second := replicaOwner(), replicaOwner()

	if first == second {
		t.Errorf("two owners are both %q: a replica cannot tell its own lease from another's", first)
	}

	// Still readable, and still says where to look. The owner is a label for an
	// operator and the condition on a release, never a credential.
	host, err := os.Hostname()
	if err == nil && host != "" {
		if !strings.HasPrefix(first, host+"/"+strconv.Itoa(os.Getpid())+"/") {
			t.Errorf("owner = %q, want it to start with the host and the process identifier", first)
		}
	}
}

func TestSweepRunsEverySweepDespiteErrors(t *testing.T) {
	errChallenges := errors.New("challenges failed")
	errTickets := errors.New("tickets failed")
	errThrottles := errors.New("throttles failed")
	errApprovals := errors.New("approvals failed")
	errList := errors.New("list failed")
	errRecovery := errors.New("recovery codes failed")
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

		for _, call := range []string{"challenges", "tickets", "throttles", "approvals", "list-erasures", "erase-audit", "recovery-codes", "prune-audit"} {
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
		if res.Tickets != 4 || res.Throttles != 5 || res.Approvals != 2 || res.Erasures != 1 ||
			res.RecoveryCodes != 6 || res.AuditPruned != 7 {
			t.Errorf("result = %+v: the sweeps after the failure did not report their work", res)
		}
	})

	t.Run("every sweep fails", func(t *testing.T) {
		st := &fakeStore{errs: map[string]error{
			"challenges":     errChallenges,
			"tickets":        errTickets,
			"throttles":      errThrottles,
			"approvals":      errApprovals,
			"list-erasures":  errList,
			"recovery-codes": errRecovery,
			"prune-audit":    errPrune,
		}}
		cfg := testConfig()
		cfg.Audit.RetentionDays = 30

		res := newJanitor(cfg, st).Sweep(context.Background())

		wantCalls := []string{
			"challenges", "tickets", "throttles", "approvals", "list-erasures",
			"recovery-codes", "prune-audit",
		}
		if !reflect.DeepEqual(st.calls, wantCalls) {
			t.Errorf("calls = %v, want %v", st.calls, wantCalls)
		}
		if len(res.Errors) != 7 {
			t.Fatalf("collected %d errors, want 7: the operator must see every problem from one pass, not only the first", len(res.Errors))
		}
		for _, want := range []error{errChallenges, errTickets, errThrottles, errApprovals, errList, errRecovery, errPrune} {
			if !errors.Is(errors.Join(res.Errors...), want) {
				t.Errorf("%q is missing from the collected errors", want)
			}
		}
		if res.Challenges+res.Tickets+res.Throttles+res.Approvals+res.Erasures+
			res.RecoveryCodes+res.AuditPruned != 0 {
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

// newLoggingJanitor builds a janitor whose log can be read back, for the
// assertions about what an operator sees. The handler is at debug level so that
// a line demoted to debug still turns up and can be checked for its level.
func newLoggingJanitor(cfg *config.Config, st store.Store, owner string, clock func() time.Time) (*Janitor, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	j := New(cfg, st, audit.NewRecorder(st, log), nil, log, clock)
	j.owner = owner
	return j, buf
}

// levelsOf returns the level of every log line whose message is msg.
func levelsOf(t *testing.T, buf *bytes.Buffer, msg string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q is not json: %v", line, err)
		}
		if rec["msg"] == msg {
			level, _ := rec["level"].(string)
			out = append(out, level)
		}
	}
	return out
}

func TestSweepLock(t *testing.T) {
	const skipped = "janitor pass skipped: another replica holds the sweep lock"

	t.Run("a lock held elsewhere skips the pass without an error", func(t *testing.T) {
		lock := &leaseTable{}
		st := &fakeStore{lock: lock, due: []*store.ErasureRequest{erasure("er-1", "sub-1")}}
		cfg := testConfig()
		cfg.Audit.RetentionDays = 30

		j, logs := newLoggingJanitor(cfg, st, "replica-a", func() time.Time { return testNow })

		// Another replica took the lock a moment ago and is sweeping now.
		if _, err := lock.acquire("replica-b", testNow, j.sweepTimeout); err != nil {
			t.Fatalf("seed the lock: %v", err)
		}

		res := j.Sweep(context.Background())

		if !res.Skipped {
			t.Error("the pass was not reported as skipped, so a caller cannot tell it from a pass that found nothing to do")
		}
		if len(res.Errors) != 0 {
			t.Errorf("errors = %v, want none: losing the lock is the normal outcome on every replica but one, not a fault", res.Errors)
		}
		if got := st.recorded(); len(got) != 0 {
			t.Errorf("the skipped pass touched the store: %v", got)
		}
		if owner := lock.heldBy(); owner != "replica-b" {
			t.Errorf("the lock is held by %q, want replica-b: the losing pass took it or cleared it", owner)
		}

		// An operator looking at a replica that does nothing must find the
		// reason in the log, so the first skipped pass is not at debug.
		if levels := levelsOf(t, logs, skipped); len(levels) != 1 || levels[0] != "INFO" {
			t.Errorf("the first skipped pass logged %v, want one INFO line: a silent replica cannot be told from a broken one", levels)
		}
	})

	t.Run("a repeated skip is demoted and taking the lock again is announced", func(t *testing.T) {
		lock := &leaseTable{}
		st := &fakeStore{lock: lock}
		j, logs := newLoggingJanitor(testConfig(), st, "replica-a", func() time.Time { return testNow })

		held, err := lock.acquire("replica-b", testNow, j.sweepTimeout)
		if err != nil {
			t.Fatalf("seed the lock: %v", err)
		}
		for i := 0; i < 3; i++ {
			if res := j.Sweep(context.Background()); !res.Skipped {
				t.Fatalf("pass %d swept although the lock was held elsewhere", i)
			}
		}

		// One line per interval per idle replica would be noise, so only the
		// transition is at info.
		want := []string{"INFO", "DEBUG", "DEBUG"}
		if levels := levelsOf(t, logs, skipped); !reflect.DeepEqual(levels, want) {
			t.Errorf("three skipped passes logged %v, want %v", levels, want)
		}

		// The holder finishes, and this replica takes over. The transition back
		// is worth a line of its own: it is how an operator sees which replica
		// is now doing the work.
		if err := held.Release(context.Background()); err != nil {
			t.Fatalf("release the seeded lock: %v", err)
		}
		if res := j.Sweep(context.Background()); res.Skipped {
			t.Fatal("the pass was skipped although the lock had been given back")
		}
		if levels := levelsOf(t, logs, "janitor sweep lock taken after a skipped pass"); !reflect.DeepEqual(levels, []string{"INFO"}) {
			t.Errorf("taking the lock again logged %v, want one INFO line", levels)
		}
		if st.called("challenges") != 1 {
			t.Errorf("the challenge sweep ran %d times, want 1", st.called("challenges"))
		}
	})

	t.Run("a lock that cannot be taken at all is reported", func(t *testing.T) {
		// Not a busy sibling but an unreachable database. The pass is still
		// skipped, and the difference from a lost race is that this one is on
		// the record as a fault.
		boom := errors.New("database is unreachable")
		st := &fakeStore{lock: &leaseTable{err: boom}}
		j, logs := newLoggingJanitor(testConfig(), st, "replica-a", func() time.Time { return testNow })

		res := j.Sweep(context.Background())

		if !res.Skipped {
			t.Error("the pass was not reported as skipped")
		}
		if len(res.Errors) != 1 || !errors.Is(res.Errors[0], boom) {
			t.Errorf("errors = %v, want the lock failure: a janitor that cannot reach its database must not look healthy", res.Errors)
		}
		if got := st.recorded(); len(got) != 0 {
			t.Errorf("the pass swept although the lock failed: %v", got)
		}
		if levels := levelsOf(t, logs, "janitor pass skipped: the sweep lock could not be taken"); !reflect.DeepEqual(levels, []string{"ERROR"}) {
			t.Errorf("the failed lock logged %v, want one ERROR line", levels)
		}
	})

	t.Run("the lock is given back after the pass", func(t *testing.T) {
		lock := &leaseTable{}
		st := &fakeStore{lock: lock}
		j, _ := newLoggingJanitor(testConfig(), st, "replica-a", func() time.Time { return testNow })

		if res := j.Sweep(context.Background()); res.Skipped {
			t.Fatal("the first pass was skipped although nothing held the lock")
		}
		if owner := lock.heldBy(); owner != "" {
			t.Errorf("the lock is still held by %q after the pass: the next interval would wait out a lease nobody holds", owner)
		}
		if _, _, released := lock.counts(); released != 1 {
			t.Errorf("the lock was released %d times, want 1", released)
		}
	})

	t.Run("a release still runs when the caller is cancelled", func(t *testing.T) {
		// A pass usually ends at a shutdown, and a release that inherited the
		// cancelled context would never run, leaving the lock to expire.
		lock := &leaseTable{}
		st := &fakeStore{lock: lock}
		j, _ := newLoggingJanitor(testConfig(), st, "replica-a", func() time.Time { return testNow })

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		j.Sweep(ctx)

		if owner := lock.heldBy(); owner != "" {
			t.Errorf("the lock is still held by %q after a cancelled pass", owner)
		}
	})

	t.Run("a lease left by a dead holder stops the sweep for one lease and no longer", func(t *testing.T) {
		// The holder was killed mid-sweep, so it never released anything and
		// never will. Only the expiry can free the lock.
		lock := &leaseTable{}
		st := &fakeStore{lock: lock}
		now := testNow
		j, _ := newLoggingJanitor(testConfig(), st, "replica-a", func() time.Time { return now })

		if _, err := lock.acquire("replica-dead", now, j.sweepTimeout); err != nil {
			t.Fatalf("seed the lock: %v", err)
		}

		if res := j.Sweep(context.Background()); !res.Skipped {
			t.Error("the pass ran while the dead holder's lease was still live")
		}

		now = testNow.Add(j.sweepTimeout)
		res := j.Sweep(context.Background())

		if res.Skipped {
			t.Error("a replica killed mid-sweep wedged the deployment: the lease outlived the holder without ever expiring")
		}
		if st.called("challenges") != 1 {
			t.Errorf("the challenge sweep ran %d times after the lease expired, want 1", st.called("challenges"))
		}
		// The lease is exactly as long as one pass may run, so on the default
		// five-minute interval a killed holder costs no pass at all.
		if j.sweepTimeout != 2*time.Minute {
			t.Errorf("the sweep timeout is %v: the lease is taken for that long, and the value is what an operator is told a dead holder costs", j.sweepTimeout)
		}
	})
}

// gateStore holds a pass inside the store until the test lets it out, so that a
// second janitor meets the lock while the first genuinely holds it. Two
// sequential passes would not: the first gives the lock back before the second
// asks for it.
type gateStore struct {
	*fakeStore
	entered chan struct{}
	release chan struct{}
}

func (g *gateStore) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	g.entered <- struct{}{}
	<-g.release
	return g.fakeStore.DeleteExpiredChallenges(ctx, before)
}

func TestSweepLockUnderContention(t *testing.T) {
	lock := &leaseTable{}
	shared := &fakeStore{lock: lock}
	gated := &gateStore{
		fakeStore: shared,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}

	a, _ := newLoggingJanitor(testConfig(), gated, "replica-a", func() time.Time { return testNow })
	b, _ := newLoggingJanitor(testConfig(), shared, "replica-b", func() time.Time { return testNow })

	done := make(chan Result, 1)
	go func() { done <- a.Sweep(context.Background()) }()

	<-gated.entered
	resB := b.Sweep(context.Background())
	close(gated.release)
	resA := <-done

	if resA.Skipped {
		t.Error("the replica holding the lock skipped its own pass")
	}
	if !resB.Skipped || len(resB.Errors) != 0 {
		t.Errorf("the second replica returned %+v, want a skipped pass with no error", resB)
	}
	if got := shared.called("challenges"); got != 1 {
		t.Errorf("the challenge sweep ran %d times for one interval, want 1: both replicas swept it", got)
	}
	if granted, refused, _ := lock.counts(); granted != 1 || refused != 1 {
		t.Errorf("the lock was granted %d times and refused %d, want 1 and 1", granted, refused)
	}

	// The lock returns to the deployment rather than to the replica that held
	// it, so the next interval goes to whichever replica asks first.
	if res := b.Sweep(context.Background()); res.Skipped {
		t.Error("the second replica was skipped again after the first had finished: the lock was not handed on")
	}
	if got := shared.called("challenges"); got != 2 {
		t.Errorf("the challenge sweep ran %d times over two intervals, want 2", got)
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

// TestARestoredSubjectIsSkippedAndNotMarkedPurged is an erasure cancelled after
// the sweep read its list. The store refuses the purge, and the sweep must
// neither report a failure nor record a purge that did not happen.
func TestARestoredSubjectIsSkippedAndNotMarkedPurged(t *testing.T) {
	st := &fakeStore{
		errs: map[string]error{"purge-subject:sub-1": fmt.Errorf("sqlite: %w", store.ErrStaleWrite)},
		due: []*store.ErasureRequest{
			erasure("er-1", "sub-1"),
			erasure("er-2", "sub-2"),
		},
	}
	res := newJanitor(testConfig(), st).Sweep(context.Background())

	if len(res.Errors) != 0 {
		t.Errorf("errors = %v, want none: a cancelled erasure is not a failed sweep", res.Errors)
	}
	if st.called("mark-purged:er-1") != 0 {
		t.Error("the cancelled request was marked purged")
	}
	if st.called("purge-subject:sub-2") != 1 || st.called("mark-purged:er-2") != 1 {
		t.Error("the request after it was not completed")
	}
}
