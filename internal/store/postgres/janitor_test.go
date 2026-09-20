//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// janitorNow and janitorLease are what the janitor would pass. The PostgreSQL
// implementation ignores both, because the lock lives on the connection, and
// these tests are where that claim is checked: nothing here advances the clock
// and nothing waits for a lease.
var janitorNow = time.Date(2026, 6, 15, 4, 0, 0, 0, time.UTC)

const janitorLease = 2 * time.Minute

// replica opens a store of its own, standing in for another replica.
//
// It needs no schema, unlike newTestStore, because the janitor lock is an
// advisory lock and touches no relation. That is also the reason two replicas
// sharing one database contend for it whatever schema each one is pointed at.
func replica(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{DSN: requireDSN(t)})
	if err != nil {
		t.Fatalf("open a store for another replica: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestJanitorLockUnderContention(t *testing.T) {
	ctx := context.Background()
	first, second := replica(t), replica(t)

	held, err := first.TryAcquireJanitorLock(ctx, "replica-a", janitorNow, janitorLease)
	if err != nil {
		t.Fatalf("the first replica was refused the lock: %v", err)
	}

	// A second replica, and a second attempt from the first one on another
	// connection of its own pool. Neither may be granted the lock, and neither
	// may wait for it.
	for _, tc := range []struct {
		name  string
		store *Store
		owner string
	}{
		{"another replica", second, "replica-b"},
		{"another connection of the holder's pool", first, "replica-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				_, err := tc.store.TryAcquireJanitorLock(ctx, tc.owner, janitorNow, janitorLease)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, store.ErrLockHeld) {
					t.Fatalf("err = %v, want store.ErrLockHeld", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the attempt is still waiting for the holder: a losing replica must skip its pass, not block on somebody else's sweep")
			}
		})
	}

	if err := held.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}

	// A released lock is free at once, and to whichever replica asks first.
	next, err := second.TryAcquireJanitorLock(ctx, "replica-b", janitorNow, janitorLease)
	if err != nil {
		t.Fatalf("the second replica was refused a released lock: %v", err)
	}
	if err := next.Release(ctx); err != nil {
		t.Fatalf("release the second lock: %v", err)
	}
}

func TestJanitorLockDiesWithTheConnection(t *testing.T) {
	ctx := context.Background()
	survivor := replica(t)

	// The holder is killed mid-sweep. It releases nothing, and the socket
	// underneath its session is closed by something other than itself and
	// without the terminate message a graceful close would send, which is what
	// the kernel does to the sockets of a process taken down with SIGKILL.
	//
	// The connection is reached through the concrete type on purpose. Closing
	// the pool instead would not model a kill at all: pgxpool.Close waits for
	// every checked-out connection to come back, so it would block on the lock
	// this test is deliberately not releasing.
	killed := replica(t)
	held, err := killed.TryAcquireJanitorLock(ctx, "replica-killed", janitorNow, janitorLease)
	if err != nil {
		t.Fatalf("the replica to kill was refused the lock: %v", err)
	}
	lock, ok := held.(*janitorLock)
	if !ok {
		t.Fatalf("the lock is a %T, so this test cannot reach the session it lives on", held)
	}
	if err := lock.conn.Hijack().PgConn().Conn().Close(); err != nil {
		t.Fatalf("close the killed replica's socket: %v", err)
	}

	// The server drops a session-level lock when it notices the session has
	// gone, which is prompt but not synchronous with the client closing its
	// socket, so this polls rather than asserting once. What it must never do
	// is wait out a lease: there is none to wait for.
	deadline := time.Now().Add(15 * time.Second)
	for {
		lock, err := survivor.TryAcquireJanitorLock(ctx, "replica-b", janitorNow, janitorLease)
		if err == nil {
			if err := lock.Release(ctx); err != nil {
				t.Errorf("release after the takeover: %v", err)
			}
			return
		}
		if !errors.Is(err, store.ErrLockHeld) {
			t.Fatalf("err = %v, want either the lock or store.ErrLockHeld", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the lock of a replica whose connection is gone is still held: a killed replica has wedged the sweep for the deployment")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestJanitorLockRefusesAnEmptyOwner(t *testing.T) {
	// The owner names the replica in the log an operator reads. A pass that
	// cannot say who is sweeping is a misuse of the interface, not a lost race,
	// and both engines refuse it the same way.
	lock, err := replica(t).TryAcquireJanitorLock(context.Background(), "", janitorNow, janitorLease)
	if err == nil {
		_ = lock.Release(context.Background())
		t.Fatal("the lock was taken with no owner")
	}
	if errors.Is(err, store.ErrLockHeld) {
		t.Errorf("err = %v, want a refusal: a rejected argument must not read as a lost race", err)
	}
}
