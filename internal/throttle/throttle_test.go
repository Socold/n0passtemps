package throttle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// fakeStore is a minimal in-memory ThrottleStore with fixed-window semantics.
//
// It counts every call so a test can assert that a disabled limiter does not
// touch persistence at all, and it hands out copies of its rows so that a bug
// in the limiter cannot mutate the fake into agreeing with it.
type fakeStore struct {
	lastSubjectID string
	calls         int
	buckets       map[string]*store.ThrottleState
	err           error
}

func newFakeStore() *fakeStore {
	return &fakeStore{buckets: map[string]*store.ThrottleState{}}
}

func (f *fakeStore) Hit(_ context.Context, tenantID, bucketKey, subjectID string, window time.Duration, now time.Time, failure bool) (*store.ThrottleState, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	f.lastSubjectID = subjectID
	st, ok := f.buckets[bucketKey]
	if !ok {
		st = &store.ThrottleState{BucketKey: bucketKey, TenantID: tenantID, WindowStart: now}
		f.buckets[bucketKey] = st
	}
	if !now.Before(st.WindowStart.Add(window)) {
		// The window has rolled: counters restart, a block in force does not.
		st.WindowStart = now
		st.Attempts = 0
		st.Failures = 0
	}
	st.Attempts++
	if failure {
		st.Failures++
	}
	st.UpdatedAt = now
	cp := *st
	return &cp, nil
}

func (f *fakeStore) Block(_ context.Context, tenantID, bucketKey string, until time.Time) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	st, ok := f.buckets[bucketKey]
	if !ok {
		st = &store.ThrottleState{BucketKey: bucketKey, TenantID: tenantID}
		f.buckets[bucketKey] = st
	}
	u := until
	st.BlockedUntil = &u
	return nil
}

func (f *fakeStore) GetThrottle(_ context.Context, _, bucketKey string) (*store.ThrottleState, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	st, ok := f.buckets[bucketKey]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *st
	return &cp, nil
}

func (f *fakeStore) ResetThrottle(_ context.Context, _, bucketKey string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	delete(f.buckets, bucketKey)
	return nil
}

// ResetSubjectThrottles mirrors the schema, which carries no subject column on
// throttle_buckets, so the fake finds nothing to clear by subject.
func (f *fakeStore) ResetSubjectThrottles(_ context.Context, _, _ string) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	return 0, nil
}

func (f *fakeStore) DeleteStaleThrottles(_ context.Context, before time.Time) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	var n int64
	for k, st := range f.buckets {
		if st.UpdatedAt.Before(before) {
			delete(f.buckets, k)
			n++
		}
	}
	return n, nil
}

// testConfig is deliberately small so a test can reach a threshold in a few
// calls and the expected counts stay readable.
func testConfig() config.Throttle {
	return config.Throttle{
		Enabled:               true,
		Window:                config.Duration{Duration: 10 * time.Minute},
		MaxFailuresPerSubject: 3,
		MaxFailuresPerIP:      5,
		MaxRequestsPerKey:     4,
		LockoutDuration:       config.Duration{Duration: 15 * time.Minute},
		AdminRevokeBurst:      2,
	}
}

// clock is a manually advanced time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newLimiter(t *testing.T, cfg config.Throttle) (*Limiter, *fakeStore, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	s := newFakeStore()
	return New(s, cfg, c.now), s, c
}

const tenant = "tenant-1"

func TestRecordAllowsUnderTheLimit(t *testing.T) {
	l, _, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 1; i <= 2; i++ {
		res, err := l.Record(context.Background(), tenant, dims, true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if !res.Allowed || res.Blocked {
			t.Fatalf("failure %d was refused: %+v", i, res)
		}
		if res.RetryAfter != 0 {
			t.Errorf("failure %d reported RetryAfter %s while allowed", i, res.RetryAfter)
		}
		if res.Failures != i {
			t.Errorf("failure %d reported %d failures, want %d", i, res.Failures, i)
		}
	}
}

func TestRecordBlocksAtExactlyTheConfiguredFailureCount(t *testing.T) {
	cfg := testConfig()
	l, s, c := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	var res Result
	for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
		var err error
		res, err = l.Record(context.Background(), tenant, dims, true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	if res.Allowed || !res.Blocked {
		t.Fatalf("attempt %d was allowed: %+v", cfg.MaxFailuresPerSubject, res)
	}
	if res.Dimension != DimSubject {
		t.Errorf("blocked on dimension %q, want %q", res.Dimension, DimSubject)
	}
	if res.Failures != cfg.MaxFailuresPerSubject {
		t.Errorf("reported %d failures, want %d", res.Failures, cfg.MaxFailuresPerSubject)
	}
	if res.RetryAfter != cfg.LockoutDuration.Duration {
		t.Errorf("RetryAfter = %s, want %s", res.RetryAfter, cfg.LockoutDuration.Duration)
	}

	// The block is persisted, so Check refuses the next request before any
	// expensive work happens.
	chk, err := l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if chk.Allowed || !chk.Blocked {
		t.Fatalf("Check allowed a blocked subject: %+v", chk)
	}
	if chk.RetryAfter <= 0 || chk.RetryAfter > cfg.LockoutDuration.Duration {
		t.Errorf("Check RetryAfter = %s, want between 0 and %s", chk.RetryAfter, cfg.LockoutDuration.Duration)
	}

	// Once the lockout has elapsed the bucket stops refusing.
	c.add(cfg.LockoutDuration.Duration + time.Second)
	chk, err = l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check after lockout: %v", err)
	}
	if !chk.Allowed || chk.Blocked {
		t.Fatalf("Check still refuses after the lockout elapsed: %+v", chk)
	}
	if chk.RetryAfter != 0 {
		t.Errorf("RetryAfter = %s while allowed, want 0", chk.RetryAfter)
	}
	if s.calls == 0 {
		t.Error("the enabled limiter never reached the store")
	}
}

func TestSuccessesDoNotTripTheFailureLimit(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject*4; i++ {
		res, err := l.Record(context.Background(), tenant, dims, false)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("success %d was refused: %+v", i+1, res)
		}
		if res.Failures != 0 {
			t.Fatalf("success %d counted %d failures", i+1, res.Failures)
		}
	}
}

func TestSuccessesCountTowardsThePerKeyVolumeLimit(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimAPIKey: "key-1"}

	// A ceiling of N serves N requests and refuses the one after.
	var res Result
	for i := 0; i <= cfg.MaxRequestsPerKey; i++ {
		var err error
		res, err = l.Record(context.Background(), tenant, dims, false)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if i < cfg.MaxRequestsPerKey && !res.Allowed {
			t.Fatalf("request %d of %d was refused: %+v", i+1, cfg.MaxRequestsPerKey, res)
		}
	}
	if res.Allowed {
		t.Fatalf("request %d was allowed: %+v", cfg.MaxRequestsPerKey+1, res)
	}
	if res.Dimension != DimAPIKey {
		t.Errorf("refused on dimension %q, want %q", res.Dimension, DimAPIKey)
	}
	if res.Attempts != cfg.MaxRequestsPerKey+1 {
		t.Errorf("reported %d attempts, want %d", res.Attempts, cfg.MaxRequestsPerKey+1)
	}
}

// TestThePerKeyCeilingRefusesWithoutLockingOut checks that the volume limit is
// a rate limit.
//
// It used to block the key for lockout_duration once crossed. The key belongs
// to an integrating application, so that turned one hot minute into an outage
// for every user of the application, lasting well past the window that had been
// exceeded.
func TestThePerKeyCeilingRefusesWithoutLockingOut(t *testing.T) {
	cfg := testConfig()
	l, s, c := newLimiter(t, cfg)
	dims := map[Dimension]string{DimAPIKey: "key-1"}

	// Four minutes into the window, so that what is left of it is known.
	if _, err := l.Record(context.Background(), tenant, dims, false); err != nil {
		t.Fatalf("Record: %v", err)
	}
	c.add(4 * time.Minute)

	var res Result
	for i := 0; i < cfg.MaxRequestsPerKey; i++ {
		var err error
		if res, err = l.Record(context.Background(), tenant, dims, false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if res.Allowed {
		t.Fatalf("the request past the ceiling was allowed: %+v", res)
	}
	if res.Blocked {
		t.Errorf("the refusal reports a block: %+v", res)
	}
	if want := cfg.Window.Duration - 4*time.Minute; res.RetryAfter != want {
		t.Errorf("RetryAfter = %s, want %s, which is what is left of the window", res.RetryAfter, want)
	}
	if st := s.buckets[l.BucketKey(DimAPIKey, tenant, "key-1")]; st.BlockedUntil != nil {
		t.Errorf("the bucket carries a block until %s", st.BlockedUntil)
	}

	// The window rolls and the key is served again at once, although the
	// lockout duration is longer than the window.
	c.add(cfg.Window.Duration - 4*time.Minute)
	res, err := l.Record(context.Background(), tenant, dims, false)
	if err != nil {
		t.Fatalf("Record after the roll: %v", err)
	}
	if !res.Allowed {
		t.Errorf("the key is still refused once the window has rolled: %+v", res)
	}
}

func TestAdminRevokeBurstIsCappedOnVolume(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimAdminRevoke: "admin-1"}

	var res Result
	for i := 0; i < cfg.AdminRevokeBurst; i++ {
		var err error
		res, err = l.Record(context.Background(), tenant, dims, false)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if !res.Blocked || res.Dimension != DimAdminRevoke {
		t.Fatalf("revocation %d was not capped: %+v", cfg.AdminRevokeBurst, res)
	}
}

func TestWindowRolls(t *testing.T) {
	cfg := testConfig()
	l, _, c := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject-1; i++ {
		if _, err := l.Record(context.Background(), tenant, dims, true); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	c.add(cfg.Window.Duration + time.Second)

	for i := 0; i < cfg.MaxFailuresPerSubject-1; i++ {
		res, err := l.Record(context.Background(), tenant, dims, true)
		if err != nil {
			t.Fatalf("Record after roll: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("failure %d after the window rolled was refused: %+v", i+1, res)
		}
		if res.Failures != i+1 {
			t.Errorf("failure %d after the roll reported %d failures, want %d", i+1, res.Failures, i+1)
		}
	}
}

func TestDimensionsAreEvaluatedSimultaneously(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)

	// One address spreading failures across many subjects trips the address
	// limit even though no single subject comes close to its own.
	var res Result
	for i := 0; i < cfg.MaxFailuresPerIP; i++ {
		dims := map[Dimension]string{
			DimSubject: "subject-" + string(rune('a'+i)),
			DimIP:      "198.51.100.7",
		}
		var err error
		res, err = l.Record(context.Background(), tenant, dims, true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if res.Allowed || res.Dimension != DimIP {
		t.Fatalf("spreading failures across subjects escaped the address limit: %+v", res)
	}
}

func TestDisabledLimiterNeverReachesTheStore(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	l, s, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{
		DimSubject: "subject-1",
		DimIP:      "198.51.100.7",
		DimAPIKey:  "key-1",
	}

	for i := 0; i < 100; i++ {
		res, err := l.Record(context.Background(), tenant, dims, true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if !res.Allowed || res.Blocked {
			t.Fatalf("disabled limiter refused an attempt: %+v", res)
		}
	}
	res, err := l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("disabled limiter refused a check: %+v", res)
	}
	if s.calls != 0 {
		t.Errorf("disabled limiter made %d store calls, want 0", s.calls)
	}
}

func TestUnknownDimensionIsRefusedBeforeTheStoreIsTouched(t *testing.T) {
	l, s, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{Dimension("hostname"): "example.com"}

	if _, err := l.Check(context.Background(), tenant, dims); err == nil {
		t.Error("Check accepted an unknown dimension")
	}
	if _, err := l.Record(context.Background(), tenant, dims, true); err == nil {
		t.Error("Record accepted an unknown dimension")
	}
	if s.calls != 0 {
		t.Errorf("store was called %d times for an unknown dimension, want 0", s.calls)
	}
}

func TestStoreErrorIsWrapped(t *testing.T) {
	l, s, _ := newLimiter(t, testConfig())
	sentinel := errors.New("database is closed")
	s.err = sentinel
	dims := map[Dimension]string{DimSubject: "subject-1"}

	_, err := l.Record(context.Background(), tenant, dims, true)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Record error = %v, want it to wrap %v", err, sentinel)
	}
	_, err = l.Check(context.Background(), tenant, dims)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Check error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestCheckDoesNotRecordAnAttempt(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject*3; i++ {
		res, err := l.Check(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("Check %d refused an untouched subject: %+v", i+1, res)
		}
	}
}

func TestResetSubjectClearsTheDerivedBucket(t *testing.T) {
	cfg := testConfig()
	l, s, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
		if _, err := l.Record(context.Background(), tenant, dims, true); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if _, ok := s.buckets[l.BucketKey(DimSubject, tenant, "subject-1")]; !ok {
		t.Fatal("no bucket was written for the subject")
	}

	if err := l.ResetSubject(context.Background(), tenant, "subject-1"); err != nil {
		t.Fatalf("ResetSubject: %v", err)
	}
	if _, ok := s.buckets[l.BucketKey(DimSubject, tenant, "subject-1")]; ok {
		t.Error("the subject bucket survived the reset")
	}

	res, err := l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check after reset: %v", err)
	}
	if !res.Allowed {
		t.Errorf("subject is still blocked after the reset: %+v", res)
	}
}

func TestResetSubjectRequiresASubject(t *testing.T) {
	l, s, _ := newLimiter(t, testConfig())
	if err := l.ResetSubject(context.Background(), tenant, ""); err == nil {
		t.Error("ResetSubject accepted an empty subject id")
	}
	if s.calls != 0 {
		t.Errorf("store was called %d times, want 0", s.calls)
	}
}

func TestNormaliseIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.7", "192.0.2.7"},
		{"192.0.2.7:443", "192.0.2.7"},
		{"2001:db8::1", "2001:db8::/64"},
		{"[2001:db8::1]:443", "2001:db8::/64"},
		{"::ffff:192.0.2.7", "192.0.2.7"},
		{"", unknownIP},
		{"garbage", unknownIP},
		{"  192.0.2.7  ", "192.0.2.7"},
		{"2001:db8:0:0:dead:beef:1:2", "2001:db8::/64"},
		{"2001:db8:1::1", "2001:db8:1::/64"},
	}
	for _, tc := range cases {
		if got := NormaliseIP(tc.in); got != tc.want {
			t.Errorf("NormaliseIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormaliseIPIsIdempotent(t *testing.T) {
	for _, in := range []string{"192.0.2.7:443", "2001:db8::1", "[2001:db8::1]:443", "garbage", ""} {
		once := NormaliseIP(in)
		if twice := NormaliseIP(once); twice != once {
			t.Errorf("NormaliseIP(%q) = %q, then %q; derivation must be stable", in, once, twice)
		}
	}
}

func TestAddressesInOneIPv6PrefixShareABucket(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)

	// Every address below sits in 2001:db8:: /64, which a single host is
	// routinely delegated, so the failures must accumulate in one bucket.
	addrs := []string{"2001:db8::1", "2001:db8::2", "[2001:db8::dead:beef]:443", "2001:db8:0:0:1:2:3:4", "2001:db8::5"}
	var res Result
	for i := 0; i < cfg.MaxFailuresPerIP; i++ {
		var err error
		res, err = l.Record(context.Background(), tenant, map[Dimension]string{DimIP: addrs[i]}, true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if res.Allowed || res.Dimension != DimIP {
		t.Fatalf("a single /64 escaped the address limit: %+v", res)
	}
}

func TestBucketKeysDoNotCollide(t *testing.T) {
	l, _, _ := newLimiter(t, testConfig())

	// Two subjects are two buckets.
	if a, b := l.BucketKey(DimSubject, tenant, "subject-1"), l.BucketKey(DimSubject, tenant, "subject-2"); a == b {
		t.Errorf("two subjects share the bucket key %q", a)
	}

	// The same value under two dimensions is two buckets, so a caller who
	// controls a subject reference cannot have their failures counted in the
	// address bucket instead.
	if a, b := l.BucketKey(DimSubject, tenant, "198.51.100.7"), l.BucketKey(DimIP, tenant, "198.51.100.7"); a == b {
		t.Errorf("dimensions %s and %s share the bucket key %q", DimSubject, DimIP, a)
	}

	// A subject reference crafted to imitate another dimension's key does not
	// reach it.
	crafted := []string{
		"ip:198.51.100.7",
		string(DimIP) + "\x00198.51.100.7",
		tenant + ":198.51.100.7",
		l.BucketKey(DimIP, tenant, "198.51.100.7"),
	}
	target := l.BucketKey(DimIP, tenant, "198.51.100.7")
	for _, id := range crafted {
		if got := l.BucketKey(DimSubject, tenant, id); got == target {
			t.Errorf("subject id %q collided with the address bucket", id)
		}
	}

	// Length prefixing means a field boundary cannot be moved: these two
	// tuples concatenate to the same bytes and must still differ.
	if a, b := l.BucketKey(DimSubject, "tenant", "aa"), l.BucketKey(DimSubject, "tenanta", "a"); a == b {
		t.Errorf("tuple boundary is ambiguous, both derive %q", a)
	}

	// Tenants are isolated from each other.
	if a, b := l.BucketKey(DimSubject, "tenant-1", "subject-1"), l.BucketKey(DimSubject, "tenant-2", "subject-1"); a == b {
		t.Errorf("two tenants share the bucket key %q", a)
	}
}

func TestBucketKeyIsStableAndOpaque(t *testing.T) {
	l, _, _ := newLimiter(t, testConfig())

	key := l.BucketKey(DimSubject, tenant, "subject-1")
	if again := l.BucketKey(DimSubject, tenant, "subject-1"); again != key {
		t.Errorf("BucketKey is not deterministic: %q then %q", key, again)
	}
	if len(key) != bucketKeyHexLen {
		t.Errorf("BucketKey length = %d, want %d", len(key), bucketKeyHexLen)
	}
	// The key is what appears in logs and in the admin interface, so it must
	// not carry the identifier it was derived from.
	if got := l.BucketKey(DimSubject, tenant, "subject-1"); got == "subject-1" || got == "" {
		t.Errorf("BucketKey leaked or dropped its input: %q", got)
	}
	// The address dimension keys on the normalised network, so a port does not
	// create a second bucket.
	if a, b := l.BucketKey(DimIP, tenant, "2001:db8::1"), l.BucketKey(DimIP, tenant, "[2001:db8::99]:443"); a != b {
		t.Errorf("one /64 produced two bucket keys, %q and %q", a, b)
	}
}

func TestEmptyValueIsNotCounted(t *testing.T) {
	l, s, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{DimSubject: "", DimAPIKey: "   "}

	res, err := l.Record(context.Background(), tenant, dims, true)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("an unidentified attempt was refused: %+v", res)
	}
	if s.calls != 0 {
		t.Errorf("store was called %d times for values identifying nobody, want 0", s.calls)
	}
}

// TestRecordAttributesOnlySubjectBuckets checks which buckets carry an owner.
//
// A bucket keyed on an address or an API key belongs to no single subject.
// Attributing one to a subject would make purging that subject delete a counter
// that still bounds other people's attempts, so only the per-subject dimension
// passes an owner through to the store.
func TestRecordAttributesOnlySubjectBuckets(t *testing.T) {
	for _, tc := range []struct {
		name string
		dim  Dimension
		want string
	}{
		{"subject carries its owner", DimSubject, "subject-42"},
		{"address carries none", DimIP, ""},
		{"api key carries none", DimAPIKey, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, fake, _ := newLimiter(t, testConfig())

			value := "subject-42"
			if tc.dim != DimSubject {
				value = "203.0.113.9"
			}
			if _, err := l.Record(context.Background(), "tenant-1",
				map[Dimension]string{tc.dim: value}, true); err != nil {
				t.Fatalf("Record: %v", err)
			}
			if fake.lastSubjectID != tc.want {
				t.Errorf("subject passed to the store = %q, want %q", fake.lastSubjectID, tc.want)
			}
		})
	}
}

// TestResultCarriesEveryDimensionsCounters checks the per-dimension snapshot.
//
// Dimension, Attempts and Failures name one bucket, which is the right answer
// for a refusal. Risk reporting needs two at once, and it gets them from here
// rather than from a second round trip to the store, since Record has already
// read every bucket it was given.
func TestResultCarriesEveryDimensionsCounters(t *testing.T) {
	l, _, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{
		DimSubject: "subject-1",
		DimIP:      "198.51.100.7",
	}

	// Two failures against the subject, one of which is also the network's.
	if _, err := l.Record(context.Background(), tenant, dims, true); err != nil {
		t.Fatalf("Record: %v", err)
	}
	res, err := l.Record(context.Background(), tenant,
		map[Dimension]string{DimSubject: "subject-1"}, true)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := res.Counters[DimSubject].Failures; got != 2 {
		t.Errorf("subject failures = %d, want 2", got)
	}
	// A dimension the call did not supply is absent rather than zero, so a
	// caller cannot mistake "not asked" for "no failures".
	if _, present := res.Counters[DimIP]; present {
		t.Error("a dimension that was not supplied appears in the counters")
	}

	both, err := l.Record(context.Background(), tenant, dims, false)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := both.Counters[DimSubject].Failures; got != 2 {
		t.Errorf("subject failures = %d, want 2; a success must not count as one", got)
	}
	if got := both.Counters[DimIP].Failures; got != 1 {
		t.Errorf("network failures = %d, want 1", got)
	}
	if got := both.Counters[DimSubject].Attempts; got != 3 {
		t.Errorf("subject attempts = %d, want 3", got)
	}

	// Check reports the same snapshot without recording anything. The success
	// above cleared the subject's bucket, so that dimension is now absent; the
	// network's is shared with other people and keeps its count.
	seen, err := l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if c, present := seen.Counters[DimSubject]; present {
		t.Errorf("Check reports %+v for the subject, whose bucket the success cleared", c)
	}
	if got := seen.Counters[DimIP].Failures; got != 1 {
		t.Errorf("Check reports %d network failures, want 1", got)
	}
}

// TestDisabledLimiterReportsNoCounters checks that a deployment with limiting
// off reports no failures rather than a zeroed map.
//
// Risk reporting reads these counters, and a deployment that counts nothing
// must report no failure reasons, which is what it truthfully observed.
func TestDisabledLimiterReportsNoCounters(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	res, err := l.Record(context.Background(), tenant, dims, true)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if res.Counters != nil {
		t.Errorf("a disabled limiter reported counters: %v", res.Counters)
	}
	if got := res.Counters[DimSubject].Failures; got != 0 {
		t.Errorf("reading an absent dimension gave %d, want the zero value", got)
	}
}

// TestASuccessNeverAppliesALockout checks the success path against a bucket
// that already stands at its failure limit.
//
// Record used to judge the failure threshold whatever the outcome, so the
// request that finally presented the right code was the one that applied the
// block. The bucket here is brought to the limit behind the limiter's back,
// which is the state a lockout shorter than the window used to leave behind.
func TestASuccessNeverAppliesALockout(t *testing.T) {
	cfg := testConfig()
	for _, dim := range []Dimension{DimSubject, DimIP} {
		t.Run(string(dim), func(t *testing.T) {
			l, s, c := newLimiter(t, cfg)
			value := "198.51.100.7"
			key := l.BucketKey(dim, tenant, value)
			s.buckets[key] = &store.ThrottleState{
				BucketKey: key, TenantID: tenant, WindowStart: c.now(),
				Attempts: cfg.MaxFailuresPerIP, Failures: cfg.MaxFailuresPerIP,
			}

			res, err := l.Record(context.Background(), tenant, map[Dimension]string{dim: value}, false)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if !res.Allowed || res.Blocked {
				t.Fatalf("a success was refused: %+v", res)
			}
			if st, ok := s.buckets[key]; ok && st.BlockedUntil != nil {
				t.Errorf("a success blocked the bucket until %s", st.BlockedUntil)
			}
		})
	}
}

// TestASuccessClearsOnlyTheBucketsOfTheOneWhoSucceeded checks which failures a
// success forgets.
func TestASuccessClearsOnlyTheBucketsOfTheOneWhoSucceeded(t *testing.T) {
	l, _, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{DimSubject: "subject-1", DimIP: "198.51.100.7"}

	for range 2 {
		if _, err := l.Record(context.Background(), tenant, dims, true); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if _, err := l.Record(context.Background(), tenant, dims, false); err != nil {
		t.Fatalf("Record: %v", err)
	}

	res, err := l.Record(context.Background(), tenant, dims, true)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := res.Counters[DimSubject].Failures; got != 1 {
		t.Errorf("subject failures = %d, want 1: the success should have cleared the two before it", got)
	}
	// An attacker with one working account must not be able to wipe the count
	// of the network they are guessing from.
	if got := res.Counters[DimIP].Failures; got != 3 {
		t.Errorf("network failures = %d, want 3: a success must not clear a shared bucket", got)
	}
}

// TestFactorsHoldSeparateBudgets checks that exhausting one factor leaves the
// others usable.
//
// The subject reference is not a secret. With one bucket per subject, anybody
// who knew it could send wrong TOTP codes and lock the subject out of the
// passkey nobody can forge.
func TestFactorsHoldSeparateBudgets(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
		if _, err := l.ForFactor(FactorTOTP).Record(context.Background(), tenant, dims, true); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	res, err := l.ForFactor(FactorTOTP).Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Allowed {
		t.Fatal("the TOTP factor is not locked out after its budget was spent")
	}
	for _, other := range []Factor{FactorWebAuthn, FactorRecovery} {
		res, err = l.ForFactor(other).Check(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !res.Allowed {
			t.Errorf("TOTP failures locked the subject out of %s: %+v", other, res)
		}
	}

	// Distinct keys, and none of them the key the factor-less Limiter derives.
	seen := map[string]Factor{l.BucketKey(DimSubject, tenant, "subject-1"): ""}
	for _, f := range []Factor{FactorWebAuthn, FactorTOTP, FactorRecovery} {
		key := l.ForFactor(f).BucketKey(DimSubject, tenant, "subject-1")
		if prev, dup := seen[key]; dup {
			t.Errorf("factors %q and %q share the bucket key %s", prev, f, key)
		}
		seen[key] = f
	}
	// The factor is a property of the subject dimension only.
	if l.ForFactor(FactorTOTP).BucketKey(DimIP, tenant, "198.51.100.7") != l.BucketKey(DimIP, tenant, "198.51.100.7") {
		t.Error("the factor changed the key of a dimension it does not apply to")
	}
}

// TestFactorBucketsStillNameTheirSubject checks that the factor went into the
// hashed key and not in place of the owner.
//
// Erasing a subject finds their throttle state through the subject_id column,
// so a per-factor bucket that stopped carrying it would survive the purge.
func TestFactorBucketsStillNameTheirSubject(t *testing.T) {
	l, s, _ := newLimiter(t, testConfig())
	dims := map[Dimension]string{DimSubject: "subject-42"}

	if _, err := l.ForFactor(FactorRecovery).Record(context.Background(), tenant, dims, true); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if s.lastSubjectID != "subject-42" {
		t.Errorf("Record passed the owner %q to the store, want %q", s.lastSubjectID, "subject-42")
	}

	s.lastSubjectID = ""
	if _, _, err := l.ForFactor(FactorTOTP).Reserve(context.Background(), tenant, dims); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if s.lastSubjectID != "subject-42" {
		t.Errorf("Reserve passed the owner %q to the store, want %q", s.lastSubjectID, "subject-42")
	}
}

// TestResetSubjectClearsEveryFactor checks the administrative unlock.
func TestResetSubjectClearsEveryFactor(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1"}
	all := []Factor{"", FactorWebAuthn, FactorTOTP, FactorRecovery}

	for _, f := range all {
		for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
			if _, err := l.ForFactor(f).Record(context.Background(), tenant, dims, true); err != nil {
				t.Fatalf("Record: %v", err)
			}
		}
	}

	// Called on one view, as a caller holding the wrong one might.
	if err := l.ForFactor(FactorTOTP).ResetSubject(context.Background(), tenant, "subject-1"); err != nil {
		t.Fatalf("ResetSubject: %v", err)
	}
	for _, f := range all {
		res, err := l.ForFactor(f).Check(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !res.Allowed {
			t.Errorf("factor %q is still locked out after the reset: %+v", f, res)
		}
	}
}

// TestReservationsNeverGrantMoreThanTheBudget is the property the reservation
// exists for, with the interleaving written out.
//
// Every attempt is reserved before any of them reports its outcome, which is
// what a parallel burst looks like to the limiter. Check followed by Record let
// all of them through, since none had recorded a failure when the last one was
// checked.
func TestReservationsNeverGrantMoreThanTheBudget(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	dims := map[Dimension]string{DimSubject: "subject-1", DimIP: "198.51.100.7"}

	var granted []*Reservation
	for i := 0; i < cfg.MaxFailuresPerSubject*4; i++ {
		rv, res, err := l.ForFactor(FactorTOTP).Reserve(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if res.Allowed != (rv != nil) {
			t.Fatalf("reservation %d: allowed is %v and the reservation is %v", i+1, res.Allowed, rv)
		}
		if rv != nil {
			granted = append(granted, rv)
			continue
		}
		if res.Dimension != DimSubject || res.RetryAfter <= 0 {
			t.Errorf("refusal %d = %+v, want the subject dimension and a Retry-After", i+1, res)
		}
	}
	if len(granted) != cfg.MaxFailuresPerSubject {
		t.Fatalf("%d attempts were let through to evaluation, want %d", len(granted), cfg.MaxFailuresPerSubject)
	}

	// The failure that used up the budget reports the lockout, so that it is
	// alerted on and audited exactly as it was before reservations existed.
	var tripped int
	for _, rv := range granted {
		res, err := rv.Fail(context.Background())
		if err != nil {
			t.Fatalf("Fail: %v", err)
		}
		if !res.Allowed {
			tripped++
		}
	}
	if tripped != 1 {
		t.Errorf("%d of the failures reported a lockout, want exactly 1", tripped)
	}
}

// TestASucceededReservationLeavesNoFailureBehind checks that the pessimistic
// count is taken back, and what the result reports meanwhile.
func TestASucceededReservationLeavesNoFailureBehind(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	view := l.ForFactor(FactorTOTP)
	dims := map[Dimension]string{DimSubject: "subject-1", DimIP: "198.51.100.7"}

	for range 2 {
		rv, _, err := view.Reserve(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if _, err = rv.Fail(context.Background()); err != nil {
			t.Fatalf("Fail: %v", err)
		}
	}

	rv, _, err := view.Reserve(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	res, err := rv.Succeed(context.Background())
	if err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	if !res.Allowed || res.Blocked {
		t.Fatalf("a success was refused: %+v", res)
	}
	// What preceded the success, without the reservation itself.
	if got := res.Counters[DimSubject].Failures; got != 2 {
		t.Errorf("the success reports %d earlier subject failures, want 2", got)
	}
	if got := res.Counters[DimIP].Failures; got != 2 {
		t.Errorf("the success reports %d earlier network failures, want 2", got)
	}

	// Far more successes than the budget, none of which may lock anything.
	for i := 0; i < cfg.MaxFailuresPerSubject*4; i++ {
		rv, granted, reserveErr := view.Reserve(context.Background(), tenant, dims)
		if reserveErr != nil {
			t.Fatalf("Reserve: %v", reserveErr)
		}
		if !granted.Allowed {
			t.Fatalf("success %d was refused: reservations that succeeded were left counted: %+v", i+1, granted)
		}
		if _, err = rv.Succeed(context.Background()); err != nil {
			t.Fatalf("Succeed: %v", err)
		}
	}
}

// TestAnAttemptDuringALockoutIsNotCounted checks that a lockout cannot be
// extended by sending requests into it.
func TestAnAttemptDuringALockoutIsNotCounted(t *testing.T) {
	cfg := testConfig()
	l, s, c := newLimiter(t, cfg)
	view := l.ForFactor(FactorTOTP)
	dims := map[Dimension]string{DimSubject: "subject-1"}

	for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
		rv, _, err := view.Reserve(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if _, err = rv.Fail(context.Background()); err != nil {
			t.Fatalf("Fail: %v", err)
		}
	}

	// Hammered for the whole lockout, by somebody who wants it to last.
	key := view.BucketKey(DimSubject, tenant, "subject-1")
	before := s.buckets[key].Attempts
	for i := 0; i < 50; i++ {
		c.add(10 * time.Second)
		rv, res, err := view.Reserve(context.Background(), tenant, dims)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if rv != nil || res.Allowed {
			t.Fatalf("a locked-out attempt was let through: %+v", res)
		}
	}
	if got := s.buckets[key].Attempts; got != before {
		t.Errorf("the bucket counted %d attempts made during the lockout", got-before)
	}

	c.add(cfg.LockoutDuration.Duration)
	rv, res, err := view.Reserve(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Reserve after the lockout: %v", err)
	}
	if rv == nil {
		t.Fatalf("the subject is still refused once the lockout has been served: %+v", res)
	}
}

// TestTheWebAuthnSubjectBudgetCountsWithoutLockingOut is the one budget that is
// reported and not enforced.
//
// A wrong assertion is not a guess: it is a signature that does not verify, and
// anybody who knows a subject reference can send ten of them. Enforcing the
// budget there gave a stranger a way to take somebody's passkey away for the
// lockout duration, over and over, so the crossing is counted, reported and
// allowed. Every other factor still locks out.
func TestTheWebAuthnSubjectBudgetCountsWithoutLockingOut(t *testing.T) {
	cfg := testConfig()
	l, _, _ := newLimiter(t, cfg)
	ctx := context.Background()
	dims := map[Dimension]string{DimSubject: "subject-1"}

	var last Result
	for i := 0; i < cfg.MaxFailuresPerSubject+3; i++ {
		res, err := l.ForFactor(FactorWebAuthn).Record(ctx, tenant, dims, true)
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
		if !res.Allowed || res.Blocked {
			t.Fatalf("failure %d was refused: allowed=%v blocked=%v", i+1, res.Allowed, res.Blocked)
		}
		last = res
	}

	// Allowed, and still reported: the operator hears about it through the same
	// path a lockout takes.
	if !last.Advisory {
		t.Error("crossing the webauthn budget reported nothing for an operator to see")
	}
	if last.Failures <= cfg.MaxFailuresPerSubject {
		t.Errorf("failures = %d, want more than the budget of %d: the attempts must still be counted",
			last.Failures, cfg.MaxFailuresPerSubject)
	}

	// A check made afterwards is not refused either, which is what an attacker
	// was previously able to arrange for somebody else.
	res, err := l.ForFactor(FactorWebAuthn).Check(ctx, tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Allowed {
		t.Error("the subject is locked out of webauthn after failures they did not make")
	}

	// The same count on another factor locks out, because there a wrong answer
	// is a guess at a secret.
	for i := 0; i < cfg.MaxFailuresPerSubject; i++ {
		if _, rerr := l.ForFactor(FactorTOTP).Record(ctx, tenant, dims, true); rerr != nil {
			t.Fatalf("Record totp %d: %v", i, rerr)
		}
	}
	totp, err := l.ForFactor(FactorTOTP).Check(ctx, tenant, dims)
	if err != nil {
		t.Fatalf("Check totp: %v", err)
	}
	if totp.Allowed {
		t.Error("the totp budget no longer locks out, and a six digit code is guessable")
	}
}
