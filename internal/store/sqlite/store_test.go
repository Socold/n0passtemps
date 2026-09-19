package sqlite

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// newStore opens a migrated database in a temporary directory.
//
// audit_test.go already provides newTestStore for the audit tests; this one is
// separate so the two can diverge without either having to be rewritten. Every
// test here gets its own file, so nothing leaks between them.
func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{DSN: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// seedTenant provisions a tenant. Subjects, API keys and admin tokens carry a
// foreign key to it, and the foreign_keys pragma is on, so the row has to exist
// before anything else can be inserted.
func seedTenant(t *testing.T, s *Store, id string) {
	t.Helper()
	err := s.CreateTenant(context.Background(), &store.Tenant{ID: id, Name: id})
	if err != nil {
		t.Fatalf("create tenant %s: %v", id, err)
	}
}

func seedSubject(t *testing.T, s *Store, tenantID, id, ref string) *store.Subject {
	t.Helper()
	sub, err := s.UpsertSubject(context.Background(), &store.Subject{
		ID:          id,
		TenantID:    tenantID,
		RefHMAC:     []byte(ref),
		RefSealed:   []byte("sealed-" + ref),
		DisplayName: "display-" + ref,
	})
	if err != nil {
		t.Fatalf("upsert subject %s: %v", id, err)
	}
	return sub
}

func seedCredential(t *testing.T, s *Store, tenantID, subjectID, id string, signCount uint32) *store.Credential {
	t.Helper()
	c := &store.Credential{
		ID:           id,
		TenantID:     tenantID,
		SubjectID:    subjectID,
		CredentialID: []byte("cred-" + id),
		PublicKey:    []byte("cose-" + id),
		Transports:   []string{"internal", "hybrid"},
		SignCount:    signCount,
		RPID:         "example.test",
	}
	if err := s.CreateCredential(context.Background(), c); err != nil {
		t.Fatalf("create credential %s: %v", id, err)
	}
	return c
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.read.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestUpsertSubjectIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	first, err := s.UpsertSubject(ctx, &store.Subject{
		ID:          "subject-1",
		TenantID:    "tenant-a",
		RefHMAC:     []byte("ref-hmac-1"),
		RefSealed:   []byte("sealed-1"),
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// A second call with the same reference and a different identifier must
	// adopt the existing row rather than insert beside it. The empty display
	// name and the absent sealed reference must not blank what is stored: the
	// caller on the login path holds the HMAC and nothing else.
	second, err := s.UpsertSubject(ctx, &store.Subject{
		ID:       "subject-2",
		TenantID: "tenant-a",
		RefHMAC:  []byte("ref-hmac-1"),
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("second upsert returned id %q, want %q", second.ID, first.ID)
	}
	if second.DisplayName != "Alice" {
		t.Errorf("display name = %q, want it preserved as Alice", second.DisplayName)
	}
	if string(second.RefSealed) != "sealed-1" {
		t.Errorf("ref_sealed = %q, want it preserved", second.RefSealed)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at moved from %s to %s", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) && !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("updated_at went backwards: %s then %s", first.UpdatedAt, second.UpdatedAt)
	}

	if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE tenant_id = ?`, "tenant-a"); n != 1 {
		t.Fatalf("subjects table holds %d rows, want 1", n)
	}

	subjects, err := s.ListSubjects(ctx, "tenant-a", store.SubjectFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 1 {
		t.Fatalf("list returned %d subjects, want 1", len(subjects))
	}
}

func TestSoftDeletedSubjectIsInvisible(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	// Nothing in the store interface sets deleted_at: the column is written by
	// the erasure workflow. The test sets it directly so the three read paths
	// can be checked against it.
	if _, err := s.write.ExecContext(ctx,
		`UPDATE subjects SET deleted_at = ? WHERE id = ?`,
		formatTime(time.Now()), sub.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSubject(ctx, "tenant-a", sub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSubject on a soft-deleted subject = %v, want ErrNotFound", err)
	}
	if _, err := s.GetSubjectByRef(ctx, "tenant-a", []byte("ref-1")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSubjectByRef on a soft-deleted subject = %v, want ErrNotFound", err)
	}
	subjects, err := s.ListSubjects(ctx, "tenant-a", store.SubjectFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 0 {
		t.Errorf("ListSubjects returned %d soft-deleted subjects, want none", len(subjects))
	}
	if err := s.SetSubjectStatus(ctx, "tenant-a", sub.ID, store.SubjectLocked); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetSubjectStatus on a soft-deleted subject = %v, want ErrNotFound", err)
	}
}

func TestAdvanceSignCount(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 10)

	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	if err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 10, 11, now); err != nil {
		t.Fatalf("forward move refused: %v", err)
	}
	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 11 {
		t.Errorf("sign_count = %d, want 11", c.SignCount)
	}
	if c.LastUsedAt == nil || !c.LastUsedAt.Equal(now) {
		t.Errorf("last_used_at = %v, want %s", c.LastUsedAt, now)
	}

	// A stale premise: the caller read 10 but the counter is now 11.
	err = s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 10, 12, now)
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("stale expectedPrev = %v, want ErrStaleWrite", err)
	}

	// A replay: the counter is presented unchanged, which is either a repeat of
	// an assertion already seen or a clone.
	err = s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 11, 11, now)
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("replayed counter = %v, want ErrStaleWrite", err)
	}

	// A counter that moves backwards is refused the same way.
	err = s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 11, 5, now)
	if !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("backwards counter = %v, want ErrStaleWrite", err)
	}

	if err := s.AdvanceSignCount(ctx, "tenant-a", "missing", 0, 1, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown credential = %v, want ErrNotFound", err)
	}

	after, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.SignCount != 11 {
		t.Errorf("sign_count moved to %d despite every refusal", after.SignCount)
	}
}

// sign_count lives in a BIGINT column while the WebAuthn signature counter is a
// uint32, so a damaged or tampered row can hold a value the model cannot
// represent. Reading it must fail rather than narrow the value: a narrowed
// counter is a plausible counter, and it can only make the clone check pass
// where it should have failed.
func TestCredentialRejectsSignCountOutOfRange(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 10)

	cases := []struct {
		name  string
		value int64
	}{
		// 2^32 narrows to 0, which would read as a fresh authenticator.
		{"above_uint32", int64(math.MaxUint32) + 1},
		// -1 narrows to MaxUint32, the largest counter there is, which would
		// refuse every genuine assertion that follows.
		{"negative", -1},
	}

	// wc_sign_count_ck keeps a negative counter out through SQL, so the check
	// constraints are suspended for the duration of this test. That is what
	// makes the fabricated rows below reachable at all: a real one would come
	// from a restore without the constraint, or from damage below SQL.
	if _, err := s.write.ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.write.ExecContext(ctx, `PRAGMA ignore_check_constraints = OFF`)
	})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Nothing in the store interface can write these values, so the
			// row is written directly.
			if _, err := s.write.ExecContext(ctx,
				`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`,
				c.value, "cred-1"); err != nil {
				t.Fatal(err)
			}

			if _, err := s.GetCredential(ctx, "tenant-a", "cred-1"); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("GetCredential = %v, want ErrCorruptRow", err)
			}
			if _, err := s.GetCredentialByID(ctx, "tenant-a", "example.test", []byte("cred-cred-1")); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("GetCredentialByID = %v, want ErrCorruptRow", err)
			}
			if _, err := s.ListCredentials(ctx, "tenant-a", "subject-1", true); !errors.Is(err, store.ErrCorruptRow) {
				t.Errorf("ListCredentials = %v, want ErrCorruptRow", err)
			}
		})
	}

	// A counter at the top of the range is valid and must still be read.
	if _, err := s.write.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`,
		int64(math.MaxUint32), "cred-1"); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatalf("GetCredential at MaxUint32: %v", err)
	}
	if c.SignCount != math.MaxUint32 {
		t.Errorf("sign_count = %d, want %d", c.SignCount, uint32(math.MaxUint32))
	}
}

func TestAdvanceSignCountRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	seedCredential(t, s, "tenant-a", "subject-1", "cred-1", 0)

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		won    int
		stale  int
		others []error
	)
	start := make(chan struct{})
	now := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Every goroutine presents the same assertion: it read zero and
			// wants to write one. Exactly one may succeed.
			err := s.AdvanceSignCount(ctx, "tenant-a", "cred-1", 0, 1, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrStaleWrite):
				stale++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if won != 1 {
		t.Errorf("%d goroutines advanced the counter, want exactly 1", won)
	}
	if stale != racers-1 {
		t.Errorf("%d goroutines were refused, want %d", stale, racers-1)
	}

	c, err := s.GetCredential(ctx, "tenant-a", "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 1 {
		t.Errorf("sign_count = %d, want 1", c.SignCount)
	}
}

func TestConsumeRecoveryCodeRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	codes := []*store.RecoveryCode{{
		ID:           "code-1",
		Selector:     "sel-1",
		VerifierHash: "hash-1",
	}}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-1", codes); err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		won    int
		stale  int
		others []error
	)
	start := make(chan struct{})
	at := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.ConsumeRecoveryCode(ctx, "tenant-a", "code-1", at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrStaleWrite):
				stale++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if won != 1 {
		t.Errorf("%d goroutines spent the code, want exactly 1", won)
	}
	if stale != racers-1 {
		t.Errorf("%d goroutines were refused, want %d", stale, racers-1)
	}

	unused, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if unused != 0 {
		t.Errorf("%d unused codes remain, want 0", unused)
	}
}

func TestReplaceRecoveryCodesRetiresPreviousBatch(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	first := []*store.RecoveryCode{
		{ID: "a1", Selector: "sel-a1", VerifierHash: "h"},
		{ID: "a2", Selector: "sel-a2", VerifierHash: "h"},
		{ID: "a3", Selector: "sel-a3", VerifierHash: "h"},
	}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-a", first); err != nil {
		t.Fatal(err)
	}

	// One code from the first batch is spent, so the test can check that a
	// consumed code survives the replacement while unused ones do not.
	at := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	if err := s.ConsumeRecoveryCode(ctx, "tenant-a", "a1", at); err != nil {
		t.Fatal(err)
	}

	second := []*store.RecoveryCode{
		{ID: "b1", Selector: "sel-b1", VerifierHash: "h"},
		{ID: "b2", Selector: "sel-b2", VerifierHash: "h"},
	}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", "subject-1", "batch-b", second); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"a2", "a3"} {
		if n := countRows(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE id = ?`, id); n != 0 {
			t.Errorf("unused code %s from the retired batch is still present", id)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE id = 'a1'`); n != 1 {
		t.Error("the consumed code was removed; it is evidence of an authentication")
	}

	unused, err := s.CountUnusedRecoveryCodes(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if unused != 2 {
		t.Errorf("%d unused codes, want the 2 from the new batch", unused)
	}

	// A selector from the retired batch must no longer authenticate anything.
	if _, err := s.GetRecoveryCodeBySelector(ctx, "tenant-a", "sel-a2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("retired selector still resolves: %v", err)
	}
	got, err := s.GetRecoveryCodeBySelector(ctx, "tenant-a", "sel-b1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BatchID != "batch-b" {
		t.Errorf("batch_id = %q, want batch-b", got.BatchID)
	}
}

func TestThrottleHit(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	const (
		key    = "bucket-1"
		window = time.Minute
	)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	st, err := s.Hit(ctx, "tenant-a", key, "", window, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 1 || st.Failures != 0 {
		t.Fatalf("first hit: attempts %d failures %d, want 1 and 0", st.Attempts, st.Failures)
	}

	// A success counts towards volume but not towards a lockout, so the two
	// counters have to move independently.
	st, err = s.Hit(ctx, "tenant-a", key, "", window, base.Add(time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 2 || st.Failures != 1 {
		t.Fatalf("second hit: attempts %d failures %d, want 2 and 1", st.Attempts, st.Failures)
	}
	st, err = s.Hit(ctx, "tenant-a", key, "", window, base.Add(2*time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 3 || st.Failures != 1 {
		t.Fatalf("third hit: attempts %d failures %d, want 3 and 1", st.Attempts, st.Failures)
	}
	if !st.WindowStart.Equal(base) {
		t.Errorf("window_start = %s, want it to stay at %s inside the window", st.WindowStart, base)
	}

	until := base.Add(time.Hour)
	if err := s.Block(ctx, "tenant-a", key, until); err != nil {
		t.Fatal(err)
	}

	// The window rolls, and the lockout must survive it. A lockout cleared by
	// the counting window rolling over would last one window instead of one
	// hour.
	rolled := base.Add(window + time.Second)
	st, err = s.Hit(ctx, "tenant-a", key, "", window, rolled, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 1 || st.Failures != 0 {
		t.Errorf("after the roll: attempts %d failures %d, want 1 and 0", st.Attempts, st.Failures)
	}
	if !st.WindowStart.Equal(rolled) {
		t.Errorf("window_start = %s, want %s", st.WindowStart, rolled)
	}
	if st.BlockedUntil == nil || !st.BlockedUntil.Equal(until) {
		t.Fatalf("blocked_until = %v, want it preserved at %s", st.BlockedUntil, until)
	}
	if !st.Blocked(rolled) {
		t.Error("bucket reports itself unblocked during its own lockout")
	}

	read, err := s.GetThrottle(ctx, "tenant-a", key)
	if err != nil {
		t.Fatal(err)
	}
	if read.Attempts != st.Attempts || read.BlockedUntil == nil || !read.BlockedUntil.Equal(until) {
		t.Errorf("GetThrottle returned %+v, want it to agree with the Hit result", read)
	}

	// The janitor must not end a lockout early.
	removed, err := s.DeleteStaleThrottles(ctx, base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Errorf("the sweep removed %d buckets whose lockout had not expired", removed)
	}
	removed, err = s.DeleteStaleThrottles(ctx, base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("the sweep removed %d buckets, want 1 once the lockout had passed", removed)
	}
}

func TestRaiseAlertDeduplicates(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	base := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	raise := func(id string, at time.Time) *store.Alert {
		t.Helper()
		a, err := s.RaiseAlert(ctx, &store.Alert{
			ID:          id,
			TenantID:    "tenant-a",
			AlertType:   "assertion.failed",
			Severity:    store.SeverityWarning,
			SubjectID:   "subject-1",
			Summary:     "repeated assertion failures",
			Detail:      []byte(`{"count":1}`),
			Fingerprint: "fp-1",
			FirstSeenAt: at,
			LastSeenAt:  at,
		})
		if err != nil {
			t.Fatalf("raise %s: %v", id, err)
		}
		return a
	}

	first := raise("alert-1", base)
	if first.Occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", first.Occurrences)
	}

	second := raise("alert-2", base.Add(time.Minute))
	if second.ID != first.ID {
		t.Errorf("a second occurrence opened row %q instead of folding into %q", second.ID, first.ID)
	}
	if second.Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", second.Occurrences)
	}
	if !second.LastSeenAt.Equal(base.Add(time.Minute)) {
		t.Errorf("last_seen_at = %s, want it moved to %s", second.LastSeenAt, base.Add(time.Minute))
	}
	if !second.FirstSeenAt.Equal(base) {
		t.Errorf("first_seen_at = %s, want it left at %s", second.FirstSeenAt, base)
	}
	if string(second.Detail) != `{"count":1}` {
		t.Errorf("detail = %s, want the json document round-tripped", second.Detail)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 1 {
		t.Fatalf("alerts table holds %d rows, want 1", n)
	}

	counts, err := s.CountOpenAlerts(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, sev := range []store.Severity{store.SeverityInfo, store.SeverityWarning, store.SeverityCritical} {
		if _, ok := counts[sev]; !ok {
			t.Errorf("severity %q is missing from the count; a caller would have to guard the lookup", sev)
		}
	}
	if counts[store.SeverityWarning] != 1 {
		t.Errorf("warning count = %d, want 1", counts[store.SeverityWarning])
	}
	if counts[store.SeverityCritical] != 0 {
		t.Errorf("critical count = %d, want 0", counts[store.SeverityCritical])
	}

	// Acknowledging takes the row out of the partial unique index, so the next
	// occurrence has to open a fresh alert rather than reviving a closed one.
	if err := s.AcknowledgeAlert(ctx, "tenant-a", first.ID, "operator-1", base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	third := raise("alert-3", base.Add(3*time.Minute))
	if third.ID == first.ID {
		t.Error("an occurrence after acknowledgement reopened the acknowledged row")
	}
	if third.Occurrences != 1 {
		t.Errorf("occurrences on the new alert = %d, want 1", third.Occurrences)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 2 {
		t.Fatalf("alerts table holds %d rows, want 2", n)
	}

	open, err := s.ListAlerts(ctx, "tenant-a", store.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].ID != third.ID {
		t.Errorf("the open list returned %d alerts, want only %s", len(open), third.ID)
	}
	all, err := s.ListAlerts(ctx, "tenant-a", store.AlertFilter{IncludeAcked: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("the full list returned %d alerts, want 2", len(all))
	}

	// A second acknowledgement must not overwrite the first operator's name.
	if err := s.AcknowledgeAlert(ctx, "tenant-a", first.ID, "operator-2", base); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("re-acknowledging = %v, want ErrNotFound", err)
	}
}

func TestDecideApprovalRefusesSelfApproval(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	create := func(id string, expires time.Time) {
		t.Helper()
		err := s.CreateApproval(ctx, &store.ApprovalRequest{
			ID:          id,
			TenantID:    "tenant-a",
			Operation:   "credential.revoke_all",
			Payload:     []byte(`{"subject_id":"subject-1"}`),
			Reason:      "suspected compromise",
			RequestedBy: "admin-one",
			RequestedAt: base,
			ExpiresAt:   expires,
		})
		if err != nil {
			t.Fatalf("create approval %s: %v", id, err)
		}
	}

	create("req-1", base.Add(time.Hour))

	// The requester cannot be the decider, whatever they do to the spelling of
	// their own identifier.
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-one", true, "fine by me", base.Add(time.Minute)); !errors.Is(err, store.ErrSelfApproval) {
		t.Errorf("self-approval = %v, want store.ErrSelfApproval", err)
	}
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", " ADMIN-One ", true, "", base.Add(time.Minute)); !errors.Is(err, store.ErrSelfApproval) {
		t.Errorf("self-approval under a different spelling = %v, want store.ErrSelfApproval", err)
	}
	if errors.Is(store.ErrSelfApproval, store.ErrStaleWrite) {
		t.Error("store.ErrSelfApproval must stay distinct from store.ErrStaleWrite")
	}

	pending, err := s.GetApproval(ctx, "tenant-a", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != store.ApprovalPending {
		t.Fatalf("status = %q after a refused self-approval, want pending", pending.Status)
	}

	decided, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-two", true, "verified with the user", base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second administrator refused: %v", err)
	}
	if decided.Status != store.ApprovalApproved {
		t.Errorf("status = %q, want approved", decided.Status)
	}
	if decided.DecidedBy != "admin-two" || decided.DecidedAt == nil {
		t.Errorf("decision not recorded: %+v", decided)
	}
	if string(decided.Payload) != `{"subject_id":"subject-1"}` {
		t.Errorf("payload = %s, want the json document round-tripped", decided.Payload)
	}

	// A request already decided is no longer decidable, which is also how the
	// losing side of two simultaneous decisions is told.
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-1", "admin-three", false, "", base.Add(3*time.Minute)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("deciding twice = %v, want ErrStaleWrite", err)
	}

	// An expired request is refused even though it is still marked pending.
	create("req-2", base.Add(time.Minute))
	if _, err := s.DecideApproval(ctx, "tenant-a", "req-2", "admin-two", true, "", base.Add(time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("deciding an expired request = %v, want ErrStaleWrite", err)
	}

	// Only an approved request may be marked executed.
	if err := s.MarkApprovalExecuted(ctx, "tenant-a", "req-2", nil, base.Add(time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("executing a request that was never approved = %v, want ErrStaleWrite", err)
	}
	if err := s.MarkApprovalExecuted(ctx, "tenant-a", "req-1", fmt.Errorf("upstream refused"), base.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	executed, err := s.GetApproval(ctx, "tenant-a", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if executed.Status != store.ApprovalFailed || executed.ExecutionError != "upstream refused" {
		t.Errorf("execution outcome not recorded: %+v", executed)
	}

	expired, err := s.ExpireApprovals(ctx, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if expired != 1 {
		t.Errorf("expired %d requests, want 1", expired)
	}
}

func TestTenantIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedTenant(t, s, "tenant-b")

	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	cred := seedCredential(t, s, "tenant-a", sub.ID, "cred-1", 0)
	alert, err := s.RaiseAlert(ctx, &store.Alert{
		ID:          "alert-1",
		TenantID:    "tenant-a",
		AlertType:   "assertion.failed",
		Severity:    store.SeverityCritical,
		Summary:     "failures",
		Fingerprint: "fp-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("subjects", func(t *testing.T) {
		if _, err := s.GetSubject(ctx, "tenant-b", sub.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetSubject across tenants = %v, want ErrNotFound", err)
		}
		if _, err := s.GetSubjectByRef(ctx, "tenant-b", []byte("ref-1")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetSubjectByRef across tenants = %v, want ErrNotFound", err)
		}
		got, err := s.ListSubjects(ctx, "tenant-b", store.SubjectFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListSubjects under tenant-b returned %d rows", len(got))
		}
		if err := s.SetSubjectStatus(ctx, "tenant-b", sub.ID, store.SubjectLocked); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetSubjectStatus across tenants = %v, want ErrNotFound", err)
		}
		if err := s.PurgeSubject(ctx, "tenant-b", sub.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PurgeSubject across tenants = %v, want ErrNotFound", err)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE id = ?`, sub.ID); n != 1 {
			t.Error("a purge aimed at the wrong tenant removed the subject anyway")
		}
	})

	t.Run("credentials", func(t *testing.T) {
		if _, err := s.GetCredential(ctx, "tenant-b", cred.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetCredential across tenants = %v, want ErrNotFound", err)
		}
		if _, err := s.GetCredentialByID(ctx, "tenant-b", cred.RPID, cred.CredentialID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetCredentialByID across tenants = %v, want ErrNotFound", err)
		}
		got, err := s.ListCredentials(ctx, "tenant-b", sub.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListCredentials under tenant-b returned %d rows", len(got))
		}
		n, err := s.CountActiveCredentials(ctx, "tenant-b", sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("CountActiveCredentials under tenant-b = %d, want 0", n)
		}
		if err := s.RevokeCredential(ctx, "tenant-b", cred.ID, "wrong tenant", time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeCredential across tenants = %v, want ErrNotFound", err)
		}
		if err := s.AdvanceSignCount(ctx, "tenant-b", cred.ID, 0, 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AdvanceSignCount across tenants = %v, want ErrNotFound", err)
		}
	})

	t.Run("alerts", func(t *testing.T) {
		got, err := s.ListAlerts(ctx, "tenant-b", store.AlertFilter{IncludeAcked: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("ListAlerts under tenant-b returned %d rows", len(got))
		}
		counts, err := s.CountOpenAlerts(ctx, "tenant-b")
		if err != nil {
			t.Fatal(err)
		}
		if counts[store.SeverityCritical] != 0 {
			t.Errorf("critical count under tenant-b = %d, want 0", counts[store.SeverityCritical])
		}
		if err := s.AcknowledgeAlert(ctx, "tenant-b", alert.ID, "operator-b", time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AcknowledgeAlert across tenants = %v, want ErrNotFound", err)
		}

		// The fingerprint is unique per tenant, so tenant-b raising the same
		// condition gets its own row rather than incrementing tenant-a's.
		own, err := s.RaiseAlert(ctx, &store.Alert{
			ID:          "alert-b",
			TenantID:    "tenant-b",
			AlertType:   "assertion.failed",
			Severity:    store.SeverityCritical,
			Summary:     "failures",
			Fingerprint: "fp-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if own.ID != "alert-b" || own.Occurrences != 1 {
			t.Errorf("tenant-b folded into tenant-a's alert: %+v", own)
		}
	})

	t.Run("throttles", func(t *testing.T) {
		// The primary key is (tenant_id, bucket_key), so two tenants deriving
		// the same key hold two independent counters. The earlier
		// single-column key made that a collision one tenant had to be refused
		// out of; isolating them is the behaviour that should have held all
		// along.
		if _, err := s.Hit(ctx, "tenant-a", "shared-bucket", "", time.Minute, time.Now(), true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Hit(ctx, "tenant-b", "shared-bucket", "", time.Minute, time.Now(), true); err != nil {
			t.Fatalf("tenant-b was refused its own bucket under the same key: %v", err)
		}
		if err := s.Block(ctx, "tenant-b", "shared-bucket", time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Block on tenant-b's own bucket: %v", err)
		}

		// tenant-b blocking and counting must leave tenant-a untouched.
		a, err := s.GetThrottle(ctx, "tenant-a", "shared-bucket")
		if err != nil {
			t.Fatal(err)
		}
		if a.Attempts != 1 {
			t.Errorf("tenant-a attempts = %d, want 1", a.Attempts)
		}
		if a.BlockedUntil != nil {
			t.Error("tenant-a's bucket was blocked by tenant-b")
		}

		b, err := s.GetThrottle(ctx, "tenant-b", "shared-bucket")
		if err != nil {
			t.Fatal(err)
		}
		if b.BlockedUntil == nil {
			t.Error("tenant-b's own block did not apply")
		}

		// Resetting one must not reach the other.
		if err := s.ResetThrottle(ctx, "tenant-b", "shared-bucket"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetThrottle(ctx, "tenant-b", "shared-bucket"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant-b's bucket after reset = %v, want ErrNotFound", err)
		}
		if _, err := s.GetThrottle(ctx, "tenant-a", "shared-bucket"); err != nil {
			t.Errorf("tenant-a's bucket was removed by tenant-b's reset: %v", err)
		}

		// A key that exists under no tenant is simply absent.
		if _, err := s.GetThrottle(ctx, "tenant-c", "shared-bucket"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetThrottle for an unrelated tenant = %v, want ErrNotFound", err)
		}
	})
}

func TestPurgeSubjectRemovesDependents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	sub := seedSubject(t, s, "tenant-a", "subject-1", "ref-1")
	other := seedSubject(t, s, "tenant-a", "subject-2", "ref-2")
	seedCredential(t, s, "tenant-a", sub.ID, "cred-1", 0)
	seedCredential(t, s, "tenant-a", other.ID, "cred-2", 0)

	if err := s.CreateTOTPSecret(ctx, &store.TOTPSecret{
		ID:            "totp-1",
		TenantID:      "tenant-a",
		SubjectID:     sub.ID,
		SecretSealed:  []byte("sealed"),
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceRecoveryCodes(ctx, "tenant-a", sub.ID, "batch-1", []*store.RecoveryCode{
		{ID: "code-1", Selector: "sel-1", VerifierHash: "h"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateChallenge(ctx, &store.Challenge{
		ID:          "chal-1",
		TenantID:    "tenant-a",
		SubjectID:   sub.ID,
		Ceremony:    store.CeremonyAssertion,
		Challenge:   []byte("challenge-bytes"),
		RPID:        "example.test",
		SessionData: []byte("session"),
		ExpiresAt:   time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	// The bucket keys are deliberately opaque here, as the limiter's real
	// keys are: they are SHA-256 digests and carry no recoverable structure.
	// The purge therefore has to find them through the subject_id column, not
	// by pattern-matching the key. Two buckets belong to the purged subject,
	// one to another subject, and one to no subject at all, which is the shape
	// of a bucket keyed on a source address.
	for _, b := range []struct {
		key     string
		subject string
	}{
		{"e3b0c44298fc1c14", sub.ID},
		{"9f86d081884c7d65", sub.ID},
		{"2c26b46b68ffc68f", other.ID},
		{"fcde2b2edba56bf4", ""},
	} {
		if _, err := s.Hit(ctx, "tenant-a", b.key, b.subject, time.Minute, time.Now(), true); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}

	for _, c := range []struct {
		name  string
		query string
	}{
		{"subject", `SELECT COUNT(*) FROM subjects WHERE id = ?`},
		{"credentials", `SELECT COUNT(*) FROM webauthn_credentials WHERE subject_id = ?`},
		{"totp secrets", `SELECT COUNT(*) FROM totp_secrets WHERE subject_id = ?`},
		{"recovery codes", `SELECT COUNT(*) FROM recovery_codes WHERE subject_id = ?`},
		{"challenges", `SELECT COUNT(*) FROM webauthn_challenges WHERE subject_id = ?`},
	} {
		if n := countRows(t, s, c.query, sub.ID); n != 0 {
			t.Errorf("%s: %d rows survived the purge", c.name, n)
		}
	}
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id = ?`, sub.ID); n != 0 {
		t.Errorf("%d throttle buckets belonging to the subject survived the purge, "+
			"which leaves their throttle state behind after an erasure", n)
	}

	// The purge must not reach past its subject.
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id = ?`, other.ID); n != 1 {
		t.Errorf("another subject's throttle bucket count = %d, want 1", n)
	}
	if n := countRows(t, s,
		`SELECT COUNT(*) FROM throttle_buckets WHERE subject_id IS NULL`); n != 1 {
		t.Errorf("unowned throttle bucket count = %d, want 1; a bucket keyed on an "+
			"address bounds everyone's attempts and must survive one subject's purge", n)
	}

	// Everything belonging to the other subject is untouched.
	if n := countRows(t, s, `SELECT COUNT(*) FROM subjects WHERE id = ?`, other.ID); n != 1 {
		t.Error("the purge removed another subject")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM webauthn_credentials WHERE subject_id = ?`, other.ID); n != 1 {
		t.Error("the purge removed another subject's credential")
	}

	if err := s.PurgeSubject(ctx, "tenant-a", sub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("purging twice = %v, want ErrNotFound", err)
	}
}

func TestAuthnRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")

	if err := s.CreateAPIKey(ctx, &store.APIKey{
		ID:           "key-1",
		TenantID:     "tenant-a",
		Name:         "integration",
		Selector:     "sel-key-1",
		VerifierHash: "argon2id$...",
		Scopes:       []string{"webauthn:register", "webauthn:assert"},
	}); err != nil {
		t.Fatal(err)
	}

	key, err := s.GetAPIKeyBySelector(ctx, "sel-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Scopes) != 2 || key.Scopes[0] != "webauthn:register" {
		t.Errorf("scopes = %v, want the stored json array", key.Scopes)
	}

	// A key stored with no scopes must read back as an empty slice, not nil, so
	// a caller can range over it without a guard.
	if err := s.CreateAPIKey(ctx, &store.APIKey{
		ID: "key-2", TenantID: "tenant-a", Name: "scopeless",
		Selector: "sel-key-2", VerifierHash: "argon2id$...",
	}); err != nil {
		t.Fatal(err)
	}
	scopeless, err := s.GetAPIKeyBySelector(ctx, "sel-key-2")
	if err != nil {
		t.Fatal(err)
	}
	if scopeless.Scopes == nil {
		t.Error("scopes came back nil, want an empty slice")
	}
	if len(scopeless.Scopes) != 0 {
		t.Errorf("scopes = %v, want empty", scopeless.Scopes)
	}

	at := time.Date(2026, 7, 1, 7, 0, 0, 0, time.UTC)
	if err := s.TouchAPIKey(ctx, "key-1", at); err != nil {
		t.Fatal(err)
	}
	// Touching a key that is not there is not an error: nothing on the request
	// path should fail because a last-use timestamp could not be written.
	if err := s.TouchAPIKey(ctx, "missing", at); err != nil {
		t.Errorf("touching an unknown key = %v, want nil", err)
	}

	if err := s.RevokeAPIKey(ctx, "tenant-a", "key-1", at); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAPIKey(ctx, "tenant-a", "key-1", at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoking twice = %v, want ErrNotFound", err)
	}
	if err := s.RevokeAPIKey(ctx, "tenant-b", "key-2", at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoking across tenants = %v, want ErrNotFound", err)
	}

	tokens := []struct {
		id      string
		role    store.Role
		expires *time.Time
	}{
		{"token-1", store.RoleFull, nil},
		{"token-2", store.RoleFull, &at},
		{"token-3", store.RoleAuditor, nil},
	}
	for _, spec := range tokens {
		if err := s.CreateAdminToken(ctx, &store.AdminToken{
			ID: spec.id, TenantID: "tenant-a", Name: spec.id,
			Selector: "sel-" + spec.id, VerifierHash: "argon2id$...",
			Role: spec.role, ExpiresAt: spec.expires,
		}); err != nil {
			t.Fatalf("create %s: %v", spec.id, err)
		}
	}

	// token-2 expired in the past, so it is not a fallback administrator and
	// must not be counted as one.
	n, err := s.CountAdminTokensByRole(ctx, "tenant-a", store.RoleFull, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("usable admin_full tokens = %d, want 1", n)
	}
	if n, err = s.CountAdminTokensByRole(ctx, "tenant-b", store.RoleFull, time.Now()); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Errorf("admin_full tokens under tenant-b = %d, want 0", n)
	}

	if err := s.CreateAdminToken(ctx, &store.AdminToken{
		ID: "token-4", TenantID: "tenant-a", Name: "bad",
		Selector: "sel-token-4", VerifierHash: "argon2id$...", Role: "root",
	}); err == nil {
		t.Error("an unknown role was accepted")
	}

	listed, err := s.ListAdminTokens(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 {
		t.Errorf("listed %d admin tokens, want 3", len(listed))
	}
}

func TestErasureLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	base := time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)
	req := &store.ErasureRequest{
		ID:          "erasure-1",
		TenantID:    "tenant-a",
		SubjectID:   "subject-1",
		Reason:      "article 17 request",
		RequestedBy: "admin-one",
		RequestedAt: base,
		PurgeAfter:  base.Add(30 * 24 * time.Hour),
	}
	if err := s.CreateErasure(ctx, req); err != nil {
		t.Fatal(err)
	}

	// The partial unique index allows one pending request per subject.
	err := s.CreateErasure(ctx, &store.ErasureRequest{
		ID: "erasure-2", TenantID: "tenant-a", SubjectID: "subject-1",
		RequestedBy: "admin-two", RequestedAt: base, PurgeAfter: base.Add(time.Hour),
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("a second pending request = %v, want ErrConflict", err)
	}

	got, err := s.GetErasureBySubject(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "erasure-1" || got.Status != store.ErasurePending {
		t.Errorf("got %+v, want the pending request", got)
	}
	if _, err := s.GetErasureBySubject(ctx, "tenant-b", "subject-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetErasureBySubject across tenants = %v, want ErrNotFound", err)
	}

	due, err := s.ListDueErasures(ctx, base.Add(29*24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Errorf("%d erasures reported due before the deadline", len(due))
	}
	due, err = s.ListDueErasures(ctx, base.Add(31*24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("%d erasures reported due after the deadline, want 1", len(due))
	}

	if err := s.MarkErasurePurged(ctx, "tenant-a", "erasure-1", base.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A purged request cannot be cancelled: the data is gone, and saying
	// otherwise would be a false record.
	if err := s.CancelErasure(ctx, "tenant-a", "erasure-1", "admin-two", base.Add(32*24*time.Hour)); !errors.Is(err, store.ErrStaleWrite) {
		t.Errorf("cancelling a purged request = %v, want ErrStaleWrite", err)
	}
	if err := s.MarkErasurePurged(ctx, "tenant-a", "missing", base); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("purging an unknown request = %v, want ErrNotFound", err)
	}
}
