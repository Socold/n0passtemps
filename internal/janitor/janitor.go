// Package janitor runs the periodic maintenance the service needs in order not
// to accumulate state it can never clear.
//
// Six things expire on their own and nothing on the request path removes them:
// WebAuthn challenges whose ceremony was abandoned, enrolment tickets nobody
// redeemed, throttle buckets whose window has long passed, approval requests
// nobody decided, erasure requests whose retention window has closed, and audit
// entries past the configured retention.
//
// Each sweep is independent and a failure in one must not stop the others. A
// janitor that stops after its first error is a janitor that silently stops
// working, which is worse than one that reports a problem every interval.
//
// # Why this is not a cron job
//
// The service ships as one binary, and an operator who has to install a
// separate scheduler to keep it healthy will eventually not. Running the sweeps
// in-process means a correctly deployed service is a maintained service. The
// cost is that a deployment running several replicas would perform each sweep
// once per replica, which the lock below removes.
//
// # The sweep lock
//
// One pass per interval across the deployment, rather than one per replica. The
// lock is taken before the pass and given back after it, and a replica that
// cannot take it skips its pass.
//
// Skipping is not a failure and nothing below treats it as one. Every sweep is
// an idempotent conditional delete, so two replicas sweeping the same interval
// leave exactly the same database behind; the lock removes wasted work and
// takes on no correctness duty in exchange. A deployment whose lock never
// worked at all would be as correct as this one and merely busier, which is the
// property to keep whenever this code is changed.
//
// What the lock is made of differs by engine, because the engines offer
// different primitives: a session-level advisory lock on PostgreSQL, released
// by the server the instant a holder's connection dies, and a lease row with an
// expiry on SQLite. Both are argued at their implementation, in
// internal/store/{postgres,sqlite}/janitor.go.
package janitor

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// Janitor performs the periodic sweeps.
type Janitor struct {
	store    store.Store
	recorder *audit.Recorder
	alerts   *alerts.Engine
	cfg      *config.Config
	log      *slog.Logger
	now      func() time.Time

	// kekProbe reports the state of the keyring, when one is wired in.
	kekProbe func() (version uint32, age time.Duration, overdue bool)

	// sweepTimeout bounds one pass. A sweep that hangs on a slow database must
	// not hold the interval open indefinitely, or the next pass never starts.
	sweepTimeout time.Duration

	// owner names this replica in the sweep lock, so that an operator reading
	// the lock or a log line can tell which process is doing the sweeping.
	owner string

	// skipping records whether the previous pass lost the lock, so a replica
	// that is not the one sweeping says so once instead of every interval. It
	// is read and written only by a pass, and a Janitor runs one pass at a
	// time.
	skipping bool
}

// New builds a Janitor.
func New(cfg *config.Config, st store.Store, rec *audit.Recorder, al *alerts.Engine, log *slog.Logger, clock func() time.Time) *Janitor {
	if clock == nil {
		clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Janitor{
		store:        st,
		recorder:     rec,
		alerts:       al,
		cfg:          cfg,
		log:          log,
		now:          clock,
		sweepTimeout: 2 * time.Minute,
		owner:        replicaOwner(),
	}
}

// releaseTimeout bounds giving the lock back.
//
// It is short and it is separate from the sweep timeout, because the release
// runs after the pass and often during a shutdown. A release that waited as long
// as a sweep may would delay the exit; one that fails costs the next interval at
// worst, since the lock is dropped when this process's connection ends or when
// its lease runs out.
const releaseTimeout = 5 * time.Second

// replicaOwner names this process in the sweep lock.
//
// The host and the process identifier together, because neither is enough
// alone: two replicas of one deployment share neither, while two processes on
// one host share the host and two pods restarted in turn can be given the same
// name. A hostname that cannot be read is not worth refusing to sweep over, so
// it degrades to the identifier; the owner is a label for an operator and the
// condition on a release, never a credential.
func replicaOwner() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return host + "/" + strconv.Itoa(os.Getpid())
}

// SetKEKProbe wires in the keyring status, so an overdue rotation raises an
// alert. It is a setter rather than a constructor argument because the janitor
// works without it, and a deployment with the reminder turned off never calls
// it.
func (j *Janitor) SetKEKProbe(fn func() (version uint32, age time.Duration, overdue bool)) {
	j.kekProbe = fn
}

// Run sweeps until the context is cancelled.
//
// The first pass happens immediately rather than after one interval, so a
// restart clears whatever accumulated while the process was down.
func (j *Janitor) Run(ctx context.Context) {
	interval := j.cfg.Features.JanitorInterval.Duration
	if interval <= 0 {
		j.log.WarnContext(ctx, "janitor disabled: interval is not positive")
		return
	}

	j.log.InfoContext(ctx, "janitor started", slog.Duration("interval", interval))

	j.Sweep(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.log.InfoContext(ctx, "janitor stopped")
			return
		case <-ticker.C:
			j.Sweep(ctx)
		}
	}
}

// Result counts what one pass removed.
type Result struct {
	Challenges  int64
	Tickets     int64
	Throttles   int64
	Approvals   int64
	Erasures    int64
	AuditPruned int64

	// Skipped is true when the pass did not run because another replica held
	// the sweep lock. It is the normal outcome on every replica but one, so a
	// skipped pass reports no counts and, by itself, no error.
	Skipped bool

	// Errors holds whatever failed, so a caller sees every problem from one
	// pass rather than only the first.
	Errors []error
}

// Sweep performs one pass.
//
// Every sweep runs regardless of whether an earlier one failed, and the errors
// are collected rather than returned at the first sign of trouble. A database
// that is briefly unavailable should produce one noisy interval, not a janitor
// that has quietly given up on five of its six duties.
//
// The pass begins by taking the deployment's sweep lock and ends by giving it
// back. Losing it means another replica is doing this interval, and the pass
// returns having done nothing; see the package comment on why that is not a
// failure.
func (j *Janitor) Sweep(ctx context.Context) Result {
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, j.sweepTimeout)
	defer cancel()

	now := j.now().UTC()

	// The lease asked for is the sweep timeout exactly. It has to be at least
	// that long, or a lease could run out under a sweep that is still running
	// and let a second replica start another one; and no longer than that,
	// because on an engine that expires leases rather than noticing a dead
	// connection this is also how long a replica killed mid-sweep keeps the
	// lock. The sweep timeout is the only duration that is both.
	lock, err := j.store.TryAcquireJanitorLock(ctx, j.owner, now, j.sweepTimeout)
	switch {
	case errors.Is(err, store.ErrLockHeld):
		j.reportSkipped(ctx)
		return Result{Skipped: true}
	case err != nil:
		// Not a busy sibling but a database that will not answer, so it is
		// reported as the fault it is. The pass is still skipped rather than
		// attempted: a sweep whose database is unreachable has nothing it can
		// do, and the error is already on the record.
		j.log.ErrorContext(ctx, "janitor pass skipped: the sweep lock could not be taken",
			slog.String("owner", j.owner), slog.Any("error", err))
		return Result{Skipped: true, Errors: []error{err}}
	}
	defer j.releaseLock(parent, lock)

	if j.skipping {
		j.skipping = false
		j.log.InfoContext(ctx, "janitor sweep lock taken after a skipped pass",
			slog.String("owner", j.owner))
	}

	var res Result

	if n, err := j.store.DeleteExpiredChallenges(ctx, now); err != nil {
		res.Errors = append(res.Errors, err)
	} else {
		res.Challenges = n
	}

	// Enrolment tickets are removed at their expiry, consumed and revoked ones
	// included. A redemption arriving inside the original window has to be
	// refused by the ticket's own state rather than by a missing row, so that a
	// spent ticket and one that never existed are indistinguishable; past the
	// expiry there is nothing left to be indistinguishable about, and the
	// durable record of what happened is the audit log.
	if n, err := j.store.DeleteExpiredEnrolmentTickets(ctx, now); err != nil {
		res.Errors = append(res.Errors, err)
	} else {
		res.Tickets = n
	}

	// Throttle buckets are kept for a few windows past their expiry, so a
	// lockout that has just ended is still visible to an operator asking why a
	// user was refused. Deleting them the instant they expire would remove the
	// evidence at exactly the moment somebody asks about it.
	throttleCutoff := now.Add(-4 * j.cfg.Throttle.Window.Duration)
	if n, err := j.store.DeleteStaleThrottles(ctx, throttleCutoff); err != nil {
		res.Errors = append(res.Errors, err)
	} else {
		res.Throttles = n
	}

	if j.cfg.Features.DualApproval {
		if n, err := j.store.ExpireApprovals(ctx, now); err != nil {
			res.Errors = append(res.Errors, err)
		} else {
			res.Approvals = n
		}
	}

	// The count is kept even when an error comes back with it. One failing
	// erasure does not undo the ones that completed in the same pass, and the
	// pass with a failure in it is exactly the one an operator will read.
	n, err := j.purgeDueErasures(ctx, now)
	res.Erasures = n
	if err != nil {
		res.Errors = append(res.Errors, err)
	}

	if n, err := j.pruneAudit(ctx, now); err != nil {
		res.Errors = append(res.Errors, err)
	} else {
		res.AuditPruned = n
	}

	j.checkKEK(ctx)

	j.report(ctx, res)
	return res
}

// purgeDueErasures completes the erasure requests whose retention window has
// closed.
//
// The order inside one subject matters. The audit entries are cleared of their
// personal fields first, then the subject row and everything cascading from it
// is removed. Doing it the other way round would delete the subject while its
// audit entries still named it, and there would then be no way to find them.
func (j *Janitor) purgeDueErasures(ctx context.Context, now time.Time) (int64, error) {
	due, err := j.store.ListDueErasures(ctx, now, 100)
	if err != nil {
		return 0, err
	}

	var purged int64
	var errs []error

	for _, er := range due {
		// A failure on one subject must not abandon the rest. An erasure that
		// silently never completes is a compliance failure, so each is
		// attempted and each failure recorded.
		erased, err := j.store.EraseSubjectAuditEntries(ctx, er.TenantID, er.SubjectID,
			"system:janitor", now)
		if err != nil {
			errs = append(errs, err)
			j.log.ErrorContext(ctx, "audit entries not erased for due erasure",
				slog.String("erasure_id", er.ID), slog.Any("error", err))
			continue
		}

		if err := j.store.PurgeSubject(ctx, er.TenantID, er.SubjectID); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			j.log.ErrorContext(ctx, "subject not purged for due erasure",
				slog.String("erasure_id", er.ID), slog.Any("error", err))
			continue
		}

		if err := j.store.MarkErasurePurged(ctx, er.TenantID, er.ID, now); err != nil {
			errs = append(errs, err)
			continue
		}

		if err := j.recorder.Success(ctx, audit.Event{
			TenantID:     er.TenantID,
			EventType:    audit.EventErasurePurged,
			ActorType:    store.ActorSystem,
			ResourceType: "erasure_request",
			ResourceID:   er.ID,
			Detail: map[string]any{
				"requested_by":   er.RequestedBy,
				"requested_at":   er.RequestedAt,
				"erased_entries": erased,
			},
		}); err != nil {
			errs = append(errs, err)
		}

		purged++
		j.log.InfoContext(ctx, "erasure completed",
			slog.String("erasure_id", er.ID),
			slog.Int64("erased_audit_entries", erased))
	}

	return purged, errors.Join(errs...)
}

// pruneAudit trims the audit log to the configured retention.
//
// Retention defaults to keeping everything. Discarding audit history is a
// decision an operator has to take deliberately, so this does nothing unless
// they set a value.
//
// The trim records a checkpoint first, which is what keeps the remaining chain
// verifiable: the checkpoint commits to the hash of the last entry removed, and
// verification resumes from there rather than from the genesis value.
func (j *Janitor) pruneAudit(ctx context.Context, now time.Time) (int64, error) {
	days := j.cfg.Audit.RetentionDays
	if days <= 0 {
		return 0, nil
	}

	cutoff := now.AddDate(0, 0, -days)
	n, err := j.store.PruneAuditLog(ctx, j.cfg.TenantID(), cutoff, now)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		j.log.InfoContext(ctx, "audit log trimmed to retention",
			slog.Int64("removed", n), slog.Int("retention_days", days))
	}
	return n, nil
}

// checkKEK raises the rotation alert. The alert store collapses repeats on a
// fingerprint, so raising it on every pass produces one open alert with a
// rising count rather than one alert per interval.
func (j *Janitor) checkKEK(ctx context.Context) {
	if j.kekProbe == nil || j.alerts == nil || !j.cfg.Features.KEKRotationReminder {
		return
	}
	version, age, overdue := j.kekProbe()
	if !overdue {
		return
	}
	if _, err := j.alerts.KEKRotationOverdue(ctx, j.cfg.TenantID(),
		strconv.FormatUint(uint64(version), 10), age, j.cfg.KEK.RotationInterval.Duration); err != nil {
		j.log.WarnContext(ctx, "keyring rotation alert not raised", slog.Any("error", err))
	}
}

// report logs the pass.
func (j *Janitor) report(ctx context.Context, res Result) {
	attrs := []any{
		slog.Int64("challenges", res.Challenges),
		slog.Int64("tickets", res.Tickets),
		slog.Int64("throttles", res.Throttles),
		slog.Int64("approvals", res.Approvals),
		slog.Int64("erasures", res.Erasures),
		slog.Int64("audit_pruned", res.AuditPruned),
	}

	if len(res.Errors) > 0 {
		attrs = append(attrs, slog.Any("error", errors.Join(res.Errors...)))
		j.log.ErrorContext(ctx, "janitor pass completed with errors", attrs...)
		return
	}

	// A pass that removed nothing is the normal case and should not produce a
	// log line at info level every interval.
	total := res.Challenges + res.Tickets + res.Throttles + res.Approvals + res.Erasures + res.AuditPruned
	if total == 0 {
		j.log.DebugContext(ctx, "janitor pass completed", attrs...)
		return
	}
	j.log.InfoContext(ctx, "janitor pass completed", attrs...)
}

// reportSkipped logs a pass another replica is doing.
//
// The first pass to lose the lock says so at info, because a replica that
// appears to be doing nothing is otherwise indistinguishable from a broken one,
// and the operator asking why needs the answer in the log rather than in this
// comment. Every pass after it says so at debug: the state has not changed, and
// one line per interval per idle replica for the life of the deployment is
// noise. Taking the lock again is logged where it happens, so the pair of
// transitions is what an operator reads.
//
// It stays out of the alert engine on purpose. A skipped pass is the correct
// steady state of every replica but one, so an alert type for it would fire on
// every healthy multi-replica deployment; the condition actually worth alerting
// on is no successful pass anywhere, which the counts on "janitor pass
// completed" and the error level on a failed one already carry.
func (j *Janitor) reportSkipped(ctx context.Context) {
	const msg = "janitor pass skipped: another replica holds the sweep lock"
	if j.skipping {
		j.log.DebugContext(ctx, msg, slog.String("owner", j.owner))
		return
	}
	j.skipping = true
	j.log.InfoContext(ctx, msg, slog.String("owner", j.owner))
}

// releaseLock gives the sweep lock back.
//
// The context is derived from the caller's without its cancellation, because a
// pass often ends for the very reason that the service is shutting down, and a
// release inheriting that cancelled context would not run at all. The cost of
// not releasing is bounded but real: the next pass then waits for the lease to
// expire, or for this process's connection to be noticed, which is exactly the
// wait the release exists to avoid.
func (j *Janitor) releaseLock(parent context.Context, lock store.JanitorLock) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), releaseTimeout)
	defer cancel()

	if err := lock.Release(ctx); err != nil {
		// Worth a warning and not an error: the lock is released by its own
		// expiry or by the connection ending, so the deployment recovers on its
		// own and loses at most one interval.
		j.log.WarnContext(ctx, "janitor sweep lock not released",
			slog.String("owner", j.owner), slog.Any("error", err))
	}
}

// Once runs a single pass and returns its result. It exists for the
// administrative command line and for tests, which should not have to wait for
// an interval.
//
// It takes the sweep lock like any other pass, so a one-off run against a
// deployment that is already sweeping comes back with Skipped set rather than
// running a second pass beside the first. The caller reads that field: an empty
// result and a skipped one are not the same answer.
func (j *Janitor) Once(ctx context.Context) Result { return j.Sweep(ctx) }

// Starter runs a Janitor in a goroutine and waits for it on shutdown.
//
// It exists so main does not have to manage the goroutine and the WaitGroup
// itself, and so the service does not exit while a sweep is mid-transaction.
type Starter struct {
	j    *Janitor
	wg   sync.WaitGroup
	stop context.CancelFunc
}

// Start launches the janitor.
func Start(ctx context.Context, j *Janitor) *Starter {
	ctx, cancel := context.WithCancel(ctx)
	s := &Starter{j: j, stop: cancel}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		j.Run(ctx)
	}()
	return s
}

// Stop cancels the janitor and waits for the current pass to finish.
func (s *Starter) Stop() {
	s.stop()
	s.wg.Wait()
}
