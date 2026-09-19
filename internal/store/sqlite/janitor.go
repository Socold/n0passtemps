package sqlite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// janitorLeaseName names the one lease row. The table is keyed by name rather
// than holding a single anonymous row so that a second periodic task, should
// one ever need the same coordination, does not need a table of its own.
const janitorLeaseName = "janitor_sweep"

// maxJanitorLease is the longest a lease may run for, whatever the caller asks.
//
// The janitor asks for its own sweep timeout, two minutes. The ceiling is well
// above that, so it never applies to a healthy deployment, and it is what keeps
// an unhealthy one from stopping altogether: an expiry is an absolute instant,
// so a caller that asks for an absurd duration, or a clock that is hours ahead
// at the moment the lease is written, would otherwise leave behind a row that
// says the lease runs until tomorrow. Nothing sweeps until then, the erasures
// due in between are not carried out, and the only sign of it is one log line
// saying a pass was skipped.
const maxJanitorLease = 15 * time.Minute

// The lease instants come from the engine rather than from the caller.
//
// A lease is a comparison between a stored expiry and the present, so the two
// have to come from one source or the comparison means nothing. The caller's
// instant is the wrong source: the janitor captures it once at the start of a
// pass and it is already minutes old by the time a long sweep releases, a
// caller under test supplies whatever it likes, and a caller that computes it
// wrongly writes an expiry nothing can wait out. Letting the engine evaluate
// both takes all of that away, and the ceiling above covers what it cannot: on
// this engine the clock is the host's either way, so a host whose clock is
// hours ahead still writes an expiry hours ahead, and what stops that from
// wedging the deployment is the bound on how far ahead it can be.
//
// The format string is the fixed-width layout of the package comment, written
// out here because strftime's %f gives three fractional digits and the stored
// values carry nine. Padding it to nine keeps string order and time order the
// same, which is what the comparison below relies on.
const (
	leaseNowExpr     = `strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')`
	leaseExpiryExpr  = `strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now', ?)`
	takeJanitorLease = `
		INSERT INTO janitor_leases (name, owner, acquired_at, expires_at)
		VALUES (?, ?, ` + leaseNowExpr + `, ` + leaseExpiryExpr + `)
		ON CONFLICT (name) DO UPDATE SET
			owner = excluded.owner,
			acquired_at = excluded.acquired_at,
			expires_at = excluded.expires_at
		WHERE janitor_leases.expires_at <= ` + leaseNowExpr
)

// TryAcquireJanitorLock implements store.JanitorLockStore.
//
// # What the lock means on this engine
//
// It is a real lease, not a no-op, although SQLite admits one writer at a time.
// The engine's write lock serialises the statement below and nothing more: both
// processes take their turn at it, and whichever one wins has let the write lock
// go long before the sweep it guards has finished. Nothing in SQLite coordinates
// over the interval that actually matters, so the coordination is this row.
//
// The arrangement it is worth having for is the unsupported one. A SQLite
// deployment is one process and one file, which docs/DEPLOYMENT.md states and
// the Kubernetes manifests hold to with replicas: 1, and there the lease is
// uncontended: one row written and deleted per interval, no contention ever
// observed. But nothing prevents two processes from opening the same file, over
// a network mount or through two containers sharing a volume, and in that
// configuration this row is the only thing between them and two concurrent
// sweeps. Being unsupported is not the same as being impossible, so the lease
// degrades that case to merely wasteful rather than leaving it uncoordinated.
//
// # Why a row with an expiry rather than a held transaction
//
// A write transaction held open for the length of a sweep would block every
// other writer in the process, and on this engine that means every write in the
// service. Skipping a sweep is the point of the lock; stalling authentication in
// order to serialise housekeeping is not.
//
// The expiry is what makes a holder killed mid-sweep recover without help. A
// process that dies never deletes its row, so the row has to stop meaning
// anything on its own. The janitor asks for exactly as long as one sweep may
// run, so the lease is dead before the next interval at any sane interval, and
// the first pass after it takes over. Nothing has to notice the death, and no
// operator has to clear the row.
//
// The caller's instant is ignored, which store.JanitorLockStore allows and this
// comment is the required notice: both the expiry and the comparison against it
// are computed by the engine, for the reason given above the statement
// constants. What the caller does decide is how long the lease should run, and
// that is bounded by maxJanitorLease.
func (s *Store) TryAcquireJanitorLock(ctx context.Context, owner string, _ time.Time,
	lease time.Duration) (store.JanitorLock, error) {
	if owner == "" {
		return nil, errors.New("sqlite: janitor lock requires an owner")
	}
	if lease <= 0 {
		return nil, errors.New("sqlite: janitor lock requires a positive lease")
	}
	if lease > maxJanitorLease {
		s.log.WarnContext(ctx, "janitor lease shortened to the ceiling",
			slog.String("owner", owner),
			slog.Duration("asked", lease),
			slog.Duration("granted", maxJanitorLease))
		lease = maxJanitorLease
	}

	// One statement, so that the read of the stored expiry and the write that
	// replaces it cannot be separated: in two statements, two processes would
	// both read an expired lease and both take it.
	//
	// The DO UPDATE carries a WHERE, so it applies only to a lease that has run
	// out. A live one is left exactly as its holder wrote it and the statement
	// reports no rows changed, which is how losing is told from winning.
	// Comparing the stored text against the engine's present is exact because
	// both are the same fixed-width layout, so string order is time order.
	//
	// The modifier is a seconds count rather than an instant, so what travels
	// to the engine is the duration asked for and nothing else.
	res, err := s.write.ExecContext(ctx, takeJanitorLease,
		janitorLeaseName, owner, leaseModifier(lease))
	if err != nil {
		return nil, fmt.Errorf("sqlite: take janitor lease: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("sqlite: count janitor lease: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: the janitor lease is live", store.ErrLockHeld)
	}
	return &janitorLease{store: s, owner: owner}, nil
}

// leaseModifier renders a duration as the SQLite date modifier that moves the
// engine's present forward by it.
//
// Milliseconds, because that is the resolution strftime works at and a lease
// expressed more finely would be rounded anyway. The sign is explicit: a
// modifier without one is not a modifier the engine accepts.
func leaseModifier(lease time.Duration) string {
	return "+" + strconv.FormatFloat(lease.Seconds(), 'f', 3, 64) + " seconds"
}

// janitorLease is a held lease.
//
// It carries the owner so that Release deletes only the row this process wrote.
// A lease that ran out under a sweep still running may already have been taken
// over, and an unconditional delete would then strip a lock somebody else is
// relying on.
type janitorLease struct {
	store *Store
	owner string
}

// Release implements store.JanitorLock.
//
// The row is deleted rather than left to expire, so a clean shutdown hands the
// next interval straight to another replica instead of making it sit out a lease
// nobody holds any more.
func (l *janitorLease) Release(ctx context.Context) error {
	res, err := l.store.write.ExecContext(ctx,
		`DELETE FROM janitor_leases WHERE name = ? AND owner = ?`,
		janitorLeaseName, l.owner)
	if err != nil {
		return fmt.Errorf("sqlite: release janitor lease: %w", mapError(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: count released janitor lease: %w", err)
	}
	if n == 0 {
		// The lease ran out while the sweep was still running and another
		// replica has taken it. Worth reporting, because it means a sweep
		// outlived the lease it was given, but there is nothing to undo: two
		// replicas sweeping one interval leave the same database behind.
		return fmt.Errorf("sqlite: the janitor lease of %q had already been taken over", l.owner)
	}
	return nil
}
