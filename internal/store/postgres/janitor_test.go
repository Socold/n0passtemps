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

// TestJanitorLockChecksThatTheSessionIsPinned covers the deployment this lock
// cannot work in, and the deployment it can.
//
// A session-level advisory lock assumes that a connection checked out of the
// pool is one server session until it is handed back. A connection pooler in
// transaction mode breaks that by design, and the unlock then reaches a
// different backend from the one that locked: the lock stays held until the
// pooler recycles the connection, and every replica skips every pass in the
// meantime, erasure purges included.
//
// The check runs before the lock is taken, so a deployment it fires on never
// leaves a lock behind that nobody can reach. Against the cluster this suite
// points at, which is a direct connection, it must never fire: a false positive
// would turn the coordination off on a deployment that has it.
func TestJanitorLockChecksThatTheSessionIsPinned(t *testing.T) {
	ctx := context.Background()
	s := replica(t)

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("take a connection: %v", err)
	}
	defer conn.Release()

	pinned, err := sessionIsPinned(ctx, conn)
	if err != nil {
		t.Fatalf("check the connection: %v", err)
	}
	if !pinned {
		t.Error("a direct connection to the cluster reported two different backends: the janitor " +
			"lock would be turned off on a deployment that can hold it")
	}
}

// TestJanitorLockFallsBackWhenTheSessionIsNotPinned states what happens on the
// deployment where the check does fire.
//
// The pass goes on without the lock rather than not going on. The janitor
// package states the property that allows it: every sweep is an idempotent
// conditional delete, so two replicas sweeping one interval leave the same
// database behind, and the lock removes waste rather than taking on a
// correctness duty. Refusing to sweep would turn a connection topology into a
// compliance failure, which is the one outcome that is not allowed.
func TestJanitorLockFallsBackWhenTheSessionIsNotPinned(t *testing.T) {
	ctx := context.Background()
	s := replica(t)
	s.sessionsPooled.Store(true)

	first, err := s.TryAcquireJanitorLock(ctx, "replica-a", janitorNow, janitorLease)
	if err != nil {
		t.Fatalf("the pass was refused: %v", err)
	}

	// And a second pass at the same moment is granted too, which is the cost
	// being accepted: duplicated work, and nothing else.
	second, err := s.TryAcquireJanitorLock(ctx, "replica-b", janitorNow, janitorLease)
	if err != nil {
		t.Fatalf("the second pass was refused: %v", err)
	}

	for _, lock := range []store.JanitorLock{first, second} {
		if _, ok := lock.(unpinnedSession); !ok {
			t.Fatalf("the lock is a %T, want the stand-in that holds nothing", lock)
		}
		if err := lock.Release(ctx); err != nil {
			t.Errorf("release: %v", err)
		}
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
