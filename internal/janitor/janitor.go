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
// cost is that a deployment running several replicas performs each sweep once
// per replica. Every sweep is idempotent and expressed as a conditional
// delete, so the duplication is wasteful rather than harmful; a coordinating
// lock belongs with the multi-replica work in a later phase.
package janitor

import (
	"context"
	"errors"
	"log/slog"
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
	}
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
func (j *Janitor) Sweep(ctx context.Context) Result {
	ctx, cancel := context.WithTimeout(ctx, j.sweepTimeout)
	defer cancel()

	now := j.now().UTC()
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

// Once runs a single pass and returns its result. It exists for the
// administrative command line and for tests, which should not have to wait for
// an interval.
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
