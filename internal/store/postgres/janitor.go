package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Socold/n0passtemps/internal/store"
)

// janitorSweepLockKey is the advisory lock one janitor pass takes.
//
// It is the FNV-1a 64-bit hash of "n0passtemps/janitor_sweep", written out as a
// literal for the same reason auditAppendLockKey is: the value must not drift if
// the derivation is ever reworded, and deriving it from a name of this project's
// own keeps it from colliding with an advisory lock some other part of a
// deployment takes.
//
// Advisory keys are scoped to the database, so two deployments in two databases
// of one cluster do not share this lock. Two sharing one database would, which
// is the property the audit append lock already has and a configuration neither
// supports.
const janitorSweepLockKey int64 = 7731116966443686148

// TryAcquireJanitorLock implements store.JanitorLockStore.
//
// A session-level advisory lock, held on one connection taken out of the pool
// for the length of the sweep. Three decisions are worth arguing.
//
// # Session level, and why that answers the dead holder
//
// The server drops the lock when the connection ends, and nothing in this
// process has to be alive for that to happen. A replica killed with SIGKILL
// mid-sweep never releases anything, but the kernel closes its sockets, the
// backend reads EOF and exits, and every lock that session held goes with it. So
// the next pass anywhere in the deployment finds the lock free, and no lease has
// to expire first. That is precisely what a row with an expiry cannot offer, and
// it is why the two engines do not share an implementation here. The one case
// that is slower is a replica whose host vanishes without closing anything: the
// backend then survives until the server's TCP keepalives give up on it, so the
// lock outlives the replica by whatever tcp_keepalives_idle and
// tcp_user_timeout allow, and until then the other replicas skip their passes.
// They skip them safely, which is the property that matters.
//
// # pg_try_advisory_lock rather than pg_advisory_lock
//
// Waiting is the one thing a losing replica must not do. It would reach the
// sweep just as the holder finished the same one and do all of it again, which
// is the duplicated work being removed, and a wait bounded only by somebody
// else's sweep would hold this pass open past its own timeout.
//
// # Session level rather than the transaction lock the audit append uses
//
// prepareAppend in audit.go takes pg_advisory_xact_lock, because it guards one
// insert and wants the lock released at commit whatever happens. A sweep is not
// one statement: it is six independent deletes that must be able to fail one at
// a time, and a transaction around all of them would both undo the five that
// worked when the sixth failed and hold a snapshot open for minutes on the
// tables the sweep is there to keep small.
//
// now and lease are ignored, which store.JanitorLockStore allows and this
// comment is the required notice: the lock lives on the connection rather than
// on a clock, so there is no expiry to compute and no clock skew between
// replicas to get wrong.
func (s *Store) TryAcquireJanitorLock(ctx context.Context, owner string, _ time.Time, _ time.Duration) (store.JanitorLock, error) {
	if owner == "" {
		return nil, errors.New("postgres: janitor lock requires an owner")
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgres: take a connection for the janitor lock: %w", err)
	}

	var taken bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, janitorSweepLockKey).Scan(&taken); err != nil {
		conn.Release()
		return nil, fmt.Errorf("postgres: take janitor lock: %w", mapError(err))
	}
	if !taken {
		// Another replica is sweeping. The connection goes back to the pool
		// unlocked, because nothing was taken on it.
		conn.Release()
		return nil, fmt.Errorf("%w: another session holds the janitor lock", store.ErrLockHeld)
	}
	return &janitorLock{conn: conn}, nil
}

// janitorLock is a held advisory lock and the connection its session belongs to.
// The two cannot be separated: returning the connection without unlocking would
// leave the lock on it.
//
// The connection is checked out of the pool while the lock is held, and
// pgxpool.Close waits for every checked-out connection to come back, so
// Store.Close blocks until the pass ends. That is why the server stops the
// janitor before it closes the store rather than the other way round.
type janitorLock struct {
	conn *pgxpool.Conn
}

// Release implements store.JanitorLock.
//
// The unlock and the return of the connection belong together. A session-level
// lock lives on the session, so a connection handed back to the pool still
// holding one carries it into whatever query borrows that connection next, and
// the deployment would never sweep again until the connection was recycled. When
// the unlock cannot be confirmed the connection is therefore removed from the
// pool and closed, which ends the session and with it every lock it held: a
// failed unlock then costs one connection rather than every future sweep.
func (l *janitorLock) Release(ctx context.Context) error {
	var released bool
	if err := l.conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, janitorSweepLockKey).Scan(&released); err != nil {
		l.discard(ctx)
		return fmt.Errorf("postgres: release janitor lock: %w", mapError(err))
	}
	if !released {
		// pg_advisory_unlock reports false when the session did not hold the
		// lock, which this code believes it did. The connection is discarded
		// rather than trusted, since the lock accounting on it is not what it
		// is thought to be.
		l.discard(ctx)
		return errors.New("postgres: the janitor lock was not held by this session")
	}
	l.conn.Release()
	return nil
}

// discard takes the connection out of the pool and closes it.
//
// The context may already be cancelled, by the shutdown that is the likeliest
// reason an unlock failed. Closing the socket ends the session either way; a
// live context only buys the graceful terminate message.
func (l *janitorLock) discard(ctx context.Context) {
	conn := l.conn.Hijack()
	if conn == nil {
		return
	}
	_ = conn.Close(ctx)
}
