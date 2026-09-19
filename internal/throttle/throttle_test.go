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

	var res Result
	for i := 0; i < cfg.MaxRequestsPerKey; i++ {
		var err error
		res, err = l.Record(context.Background(), tenant, dims, false)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if res.Allowed || !res.Blocked {
		t.Fatalf("request %d was allowed: %+v", cfg.MaxRequestsPerKey, res)
	}
	if res.Dimension != DimAPIKey {
		t.Errorf("blocked on dimension %q, want %q", res.Dimension, DimAPIKey)
	}
	if res.Attempts != cfg.MaxRequestsPerKey {
		t.Errorf("reported %d attempts, want %d", res.Attempts, cfg.MaxRequestsPerKey)
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
	if got := l.BucketKey(DimSubject, tenant, "subject-1"); got == "subject-1" || len(got) == 0 {
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

	// Check reports the same snapshot without recording anything.
	seen, err := l.Check(context.Background(), tenant, dims)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := seen.Counters[DimSubject].Failures; got != 2 {
		t.Errorf("Check reports %d subject failures, want 2", got)
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
