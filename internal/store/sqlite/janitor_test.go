package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// leaseNow is the instant the tests hand to the store, and the store ignores
// it: the expiry and the comparison against it are computed by the engine, so
// that a caller whose clock is wrong cannot write a lease that outlives the
// deployment. The tests keep passing an instant because the interface takes
// one, and one of them below passes an absurd one on purpose.
var leaseNow = time.Date(2026, 6, 15, 4, 0, 0, 0, time.UTC)

// leaseLease is how long the janitor takes a lease for, which is its own sweep
// timeout. The tests use the same value so that what they assert about a live
// lease is what a deployment would see.
const leaseLease = 2 * time.Minute

// shortLease is what the tests that need an expired lease ask for, and
// afterShortLease is how long they wait for it to run out.
//
// They wait rather than move a clock, because there is no longer a clock to
// move: that is the point of the change these tests cover. The margin is
// generous enough that a loaded machine does not turn a passing test into a
// failing one, and the whole wait happens twice in this file.
const (
	shortLease      = 100 * time.Millisecond
	afterShortLease = shortLease + 150*time.Millisecond
)

// secondProcess opens another store on the same file.
//
// It is the two-process arrangement the lease exists for: unsupported, as
// docs/DEPLOYMENT.md says, and not prevented by anything, so the only way to
// test the lease under contention is to build it deliberately.
func secondProcess(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(Options{DSN: path})
	if err != nil {
		t.Fatalf("open a second store on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestJanitorLeaseUnderContention(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	held, err := first.TryAcquireJanitorLock(ctx, "replica-a", leaseNow, leaseLease)
	if err != nil {
		t.Fatalf("the first holder was refused the lease: %v", err)
	}

	// The second process asks a moment later, inside the lease.
	if _, err = second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow.Add(time.Second), leaseLease); !errors.Is(err, store.ErrLockHeld) {
		t.Fatalf("the second holder got %v, want store.ErrLockHeld: two processes would sweep the same interval", err)
	}

	if err = held.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}

	// A released lease is free at once, rather than making the next pass wait
	// out an expiry nobody is relying on.
	next, err := second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow.Add(2*time.Second), leaseLease)
	if err != nil {
		t.Fatalf("the second holder was refused a released lease: %v", err)
	}
	if err := next.Release(ctx); err != nil {
		t.Fatalf("release the second lease: %v", err)
	}
}

// TestJanitorLeaseOutlivesADeadHolder is the same test it was before the expiry
// moved to the database clock, with one change: the lease is taken for a tenth
// of a second and the survivor waits it out, where the earlier version took it
// for two minutes and handed the store an instant two minutes later. There is
// no longer a caller instant that can expire a lease, which is what the test
// below this one is about, so the only way left to reach an expired lease is
// for it to expire.
func TestJanitorLeaseOutlivesADeadHolder(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	// The holder is killed mid-sweep: it never releases, and nothing will ever
	// release on its behalf. Only the expiry can free the lease.
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-killed", leaseNow, shortLease); err != nil {
		t.Fatalf("the first holder was refused the lease: %v", err)
	}

	if _, err := second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow, shortLease); !errors.Is(err, store.ErrLockHeld) {
		t.Fatalf("the survivor got %v inside the lease, want store.ErrLockHeld", err)
	}

	time.Sleep(afterShortLease)

	lock, err := second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow, shortLease)
	if err != nil {
		t.Fatalf("the survivor got %v after the lease ran out, want the lease: one that never "+
			"expires wedges the sweep for the life of the deployment", err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Errorf("release after a takeover: %v", err)
	}
}

// TestJanitorLeaseIgnoresTheCallerClock is the regression test for a host whose
// clock is hours ahead.
//
// The expiry used to be the caller's instant plus the lease, so one such
// replica wrote a lease that ran until tomorrow. No pass anywhere in the
// deployment ran until then, the erasures due in between were not carried out,
// and the only sign of it was a line saying a pass had been skipped. The instant
// now decides nothing, so the lease is as long as it was asked to be and no
// longer.
func TestJanitorLeaseIgnoresTheCallerClock(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	ahead := time.Now().UTC().Add(72 * time.Hour)
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-ahead", ahead, shortLease); err != nil {
		t.Fatalf("the holder with the wrong clock was refused the lease: %v", err)
	}

	time.Sleep(afterShortLease)

	lock, err := second.TryAcquireJanitorLock(ctx, "replica-b", time.Now().UTC(), shortLease)
	if err != nil {
		t.Fatalf("the lease taken by a replica three days ahead is still live: %v", err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Errorf("release: %v", err)
	}

	// The other direction. A replica whose clock is behind must not be told its
	// own lease has already expired either, which is the same comparison read
	// the other way round.
	behind := time.Now().UTC().Add(-72 * time.Hour)
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-behind", behind, leaseLease); err != nil {
		t.Fatalf("the holder with the slow clock was refused the lease: %v", err)
	}
	if _, err := second.TryAcquireJanitorLock(ctx, "replica-b", time.Now().UTC(), leaseLease); !errors.Is(err,
		store.ErrLockHeld) {
		t.Errorf("a lease written by a replica three days behind read as expired: %v", err)
	}
}

// TestJanitorLeaseIsCappedAtTheCeiling covers the other half of the same
// failure: a lease nobody can wait out.
//
// A caller asking for a week gets maxJanitorLease, so the worst a mistake here
// can cost is that ceiling rather than the life of the deployment.
func TestJanitorLeaseIsCappedAtTheCeiling(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.TryAcquireJanitorLock(ctx, "replica-a", leaseNow, 7*24*time.Hour); err != nil {
		t.Fatalf("take the lease: %v", err)
	}

	var acquired, expires string
	err := s.read.QueryRowContext(ctx,
		`SELECT acquired_at, expires_at FROM janitor_leases WHERE name = ?`,
		janitorLeaseName).Scan(&acquired, &expires)
	if err != nil {
		t.Fatalf("read the lease row: %v", err)
	}

	from, err := parseTime(acquired)
	if err != nil {
		t.Fatalf("parse acquired_at: %v", err)
	}
	until, err := parseTime(expires)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	if got := until.Sub(from); got > maxJanitorLease {
		t.Errorf("the lease runs for %s, longer than the ceiling of %s: nothing sweeps until it ends",
			got, maxJanitorLease)
	}
}

func TestJanitorLeaseReleaseIsConditionalOnTheOwner(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	// The first holder's sweep outlives its lease, the second takes over, and
	// the first then finishes and releases. It must not strip the lease the
	// second is relying on. The first lease is short so that it runs out under
	// the sweep, as it would on a replica whose pass took longer than it was
	// given.
	stale, err := first.TryAcquireJanitorLock(ctx, "replica-a", leaseNow, shortLease)
	if err != nil {
		t.Fatalf("the first holder was refused the lease: %v", err)
	}

	time.Sleep(afterShortLease)

	if _, err := second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow, leaseLease); err != nil {
		t.Fatalf("the second holder was refused an expired lease: %v", err)
	}

	if err := stale.Release(ctx); err == nil {
		t.Error("the late release reported success although the lease had been taken over")
	}

	// The takeover is still in force, so a third attempt inside it is refused.
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-a", leaseNow, leaseLease); !errors.Is(err,
		store.ErrLockHeld) {
		t.Errorf("a later attempt got %v, want store.ErrLockHeld: the late release deleted the "+
			"lease of the replica that was sweeping", err)
	}
}

func TestJanitorLeaseRefusesIncompleteArguments(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	tests := []struct {
		name  string
		owner string
		lease time.Duration
	}{
		{"no owner", "", leaseLease},
		{"no lease", "replica-a", 0},
		{"a lease in the past", "replica-a", -time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A lease with no owner could not be released by its holder, and one
			// with no duration would be expired the moment it was written, so
			// both are refused rather than written and wondered about later.
			lock, err := s.TryAcquireJanitorLock(ctx, tc.owner, leaseNow, tc.lease)
			if err == nil {
				_ = lock.Release(ctx)
				t.Fatal("the lease was taken")
			}
			if errors.Is(err, store.ErrLockHeld) {
				t.Errorf("err = %v, want a refusal: a rejected argument must not read as a lost race", err)
			}
		})
	}
}
