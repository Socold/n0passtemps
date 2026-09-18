package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// leaseNow is the instant the lease tests start from. The acquiring clock is a
// parameter, so a lease can be expired by moving it rather than by waiting.
var leaseNow = time.Date(2026, 6, 15, 4, 0, 0, 0, time.UTC)

// leaseLease is how long the janitor takes a lease for, which is its own sweep
// timeout. The tests use the same value so that what they assert about a dead
// holder is what a deployment would see.
const leaseLease = 2 * time.Minute

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

func TestJanitorLeaseOutlivesADeadHolder(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	// The holder is killed mid-sweep: it never releases, and nothing will ever
	// release on its behalf. Only the expiry can free the lease.
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-killed", leaseNow, leaseLease); err != nil {
		t.Fatalf("the first holder was refused the lease: %v", err)
	}

	tests := []struct {
		name string
		at   time.Time
		want error
	}{
		{"one nanosecond before the lease ends", leaseNow.Add(leaseLease - time.Nanosecond), store.ErrLockHeld},
		{"the instant the lease ends", leaseNow.Add(leaseLease), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lock, err := second.TryAcquireJanitorLock(ctx, "replica-b", tc.at, leaseLease)
			if !errors.Is(err, tc.want) {
				t.Fatalf("the survivor got %v, want %v: a lease that never expires wedges the sweep for the life of the deployment", err, tc.want)
			}
			if tc.want == nil {
				if err := lock.Release(ctx); err != nil {
					t.Errorf("release after a takeover: %v", err)
				}
			}
		})
	}
}

func TestJanitorLeaseReleaseIsConditionalOnTheOwner(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	second := secondProcess(t, first.path)

	// The first holder's sweep outlives its lease, the second takes over, and
	// the first then finishes and releases. It must not strip the lease the
	// second is relying on.
	stale, err := first.TryAcquireJanitorLock(ctx, "replica-a", leaseNow, leaseLease)
	if err != nil {
		t.Fatalf("the first holder was refused the lease: %v", err)
	}
	if _, err := second.TryAcquireJanitorLock(ctx, "replica-b", leaseNow.Add(leaseLease), leaseLease); err != nil {
		t.Fatalf("the second holder was refused an expired lease: %v", err)
	}

	if err := stale.Release(ctx); err == nil {
		t.Error("the late release reported success although the lease had been taken over")
	}

	// The takeover is still in force, so a third attempt inside it is refused.
	if _, err := first.TryAcquireJanitorLock(ctx, "replica-a", leaseNow.Add(leaseLease+time.Second), leaseLease); !errors.Is(err, store.ErrLockHeld) {
		t.Errorf("a later attempt got %v, want store.ErrLockHeld: the late release deleted the lease of the replica that was sweeping", err)
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
