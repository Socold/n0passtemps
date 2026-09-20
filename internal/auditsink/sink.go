// Package auditsink delivers a copy of the audit chain to a destination outside
// this deployment.
//
// The hash chain in internal/audit makes tampering detectable. It does not make
// it impossible, and against one attacker it does not even make it detectable:
// the operator owns the database file, so they can edit a row and recompute
// every hash from the edit onwards, and the result is indistinguishable from an
// untouched log. Attacker 9 in docs/THREAT-MODEL.md says so in those words. The
// only thing that closes it is a copy held where that operator cannot reach it,
// because a rewritten chain will not reproduce the hashes a witness already
// holds.
//
// So this package ships each entry to an HTTP endpoint with a bearer
// credential, and nothing more elaborate. Every deployment can stand one up, it
// adds no dependency, and the receiver can be a service run by somebody else,
// which is the property that matters. A file on the same host would be simpler
// still and would be worthless: it falls to exactly the attacker the chain
// already fails to stop, as does a bucket under the same cloud credentials or a
// log collector the same root account administers. The configuration makes the
// operator declare that the receiver is outside their control, because this
// code cannot check it and the feature means nothing when it is false.
//
// # Nothing here is allowed to gate an authentication
//
// The recorder runs on the request path. Offer is a non-blocking hand-off and
// returns no error: it puts the entry on a bounded queue and, if the queue is
// full, drops it and says so loudly. Delivery happens on one background
// goroutine that nothing waits for.
//
// # The audit log is the buffer
//
// Dropping an offer loses a delivery, never a record, because the entry is
// already committed to the audit log and the log is ordered by a sequence
// number. Whenever the queue overflows, an offer arrives out of order, a POST
// fails or the process restarts, the shipper stops trusting the queue and reads
// from the audit log instead, starting one past the last sequence number the
// receiver acknowledged. That is why the queue can be small and why a full one
// costs latency and a database read rather than a gap in the witness.
//
// # At least once, and gaps are the receiver's to notice
//
// The watermark is written only after the receiver has acknowledged a batch. A
// process that dies between the acknowledgement and that write comes back and
// sends the batch again, so a receiver must expect duplicates and de-duplicate
// on the sequence number. The opposite order would give at most once: the
// watermark would move, the entries would never arrive, and nothing anywhere
// would know. Duplicates are a receiver's inconvenience; a silent hole in the
// witness defeats the purpose of having one.
//
// A receiver detects a gap from the sequence numbers and from the chain itself,
// and CheckSequence is that check, written once here so it can be quoted rather
// than described. Given 41, 42 and 44 it reports 44, both because the numbering
// skips and because 44 does not chain onto 42.
//
// # What is delivered
//
// Exactly the fields the chain hash commits to, which is what a receiver needs
// in order to verify and nothing else. The personal fields of an entry are not
// among them: the chain commits to a salted digest of them, and it is that
// digest which travels. See Record.
package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/version"
)

// Errors this package reports.
var (
	// ErrNotConfigured is returned by New when no endpoint is set. It is not a
	// fault: it is how "offline by default" is expressed, and the caller starts
	// no shipper.
	ErrNotConfigured = errors.New("auditsink: no endpoint is configured")

	// ErrNoCredential is returned by New when the variable named by
	// audit.sink.token_env holds nothing.
	//
	// It refuses at startup rather than at the first delivery, because a
	// deployment that believes it has a witness and does not is worse off than
	// one that never started: the operator would find out from an alert nobody
	// had wired up yet.
	ErrNoCredential = errors.New("auditsink: the bearer credential is not set")

	// ErrDelivery is returned when the receiver could not be reached or did not
	// accept the batch.
	ErrDelivery = errors.New("auditsink: the receiver did not accept the batch")

	// ErrBacklog is returned when the audit log could not be read to catch up.
	ErrBacklog = errors.New("auditsink: the audit log could not be read")

	// ErrWatermark is returned when how far delivery has got could not be
	// recorded. The batch was accepted, so the only safe consequence is to send
	// it again.
	ErrWatermark = errors.New("auditsink: the delivery watermark could not be written")

	// ErrMalformedBatch is what Batch.Verify reports. It is here for a receiver
	// written in Go, which can then use the same check the sender does.
	ErrMalformedBatch = errors.New("auditsink: malformed batch")
)

const (
	// maxResponseBytes bounds what is read back from the receiver. The body is
	// not used for anything: it is drained so the connection can be reused. A
	// receiver that answered with gigabytes would otherwise be able to exhaust
	// the sender's memory, which is a strange thing for a witness to do and
	// exactly why it is bounded.
	maxResponseBytes = 4 << 10

	// alertInterval is the shortest gap between two alerts about the same
	// failing sink. The alert store already collapses repeats onto one row by
	// fingerprint, so this is about not writing a row per retry rather than
	// about what an operator sees.
	alertInterval = time.Minute

	// maxReasonLen bounds the failure text carried into the alert and the
	// health report. Both are read by people.
	maxReasonLen = 200
)

// Backlog is the part of the audit store the shipper reads to catch up.
//
// It is an interface, and a narrow one, so that the shipper can be tested
// against a log built in memory and so that this package depends on the one
// store method it actually needs.
type Backlog interface {
	ReadAuditRange(ctx context.Context, fromSeq int64, limit int) ([]*store.AuditEntry, error)
}

// Raiser is the part of the alert engine the shipper needs.
type Raiser interface {
	AuditSinkFailing(ctx context.Context, tenantID, endpoint string, pending int64, reason string) (*store.Alert, error)
}

// Options are the shipper's dependencies.
type Options struct {
	Config   config.AuditSink
	TenantID string

	// WatermarkPath is where delivery progress is recorded. The caller resolves
	// it, because the default sits in the data directory and this package does
	// not read the database section.
	WatermarkPath string

	Backlog Backlog
	Alerts  Raiser
	Logger  *slog.Logger
	Clock   func() time.Time

	// HTTPClient replaces the default client. Only the tests set it.
	HTTPClient *http.Client
}

// Shipper delivers audit entries to the configured endpoint.
type Shipper struct {
	cfg      config.AuditSink
	tenantID string
	endpoint string
	token    string

	client  *http.Client
	backlog Backlog
	alerts  Raiser
	log     *slog.Logger
	now     func() time.Time

	mark *watermark

	// queue is the hand-off from the recorder. It carries entries the store has
	// already committed, so a dropped one is a lost delivery and not a lost
	// record.
	queue chan *store.AuditEntry

	// resync says the queue can no longer be trusted to be the next thing the
	// receiver needs, so the next flush reads from the audit log instead. It is
	// set by a dropped offer, by an out-of-order offer, by a failed delivery
	// and by the first flush after a restart.
	resync atomic.Bool

	// dropped counts offers the queue could not take, for the health report.
	// dropping is the same condition as a state, so that a full queue produces
	// one log line per episode rather than one per entry.
	dropped  atomic.Int64
	dropping atomic.Bool

	// highest is the largest sequence number ever offered, which is how far
	// behind the receiver is measured against.
	highest atomic.Int64

	// The fields below belong to the worker goroutine, except lastErr, which
	// the health probe reads.
	backoff     time.Duration
	nextAttempt time.Time
	lastAlert   time.Time

	errMu   sync.RWMutex
	lastErr string
}

// New builds a Shipper.
//
// It returns ErrNotConfigured when no endpoint is set, which is the normal case
// and which the caller treats as "run without a witness" rather than as a
// failure. Every other error is a misconfiguration and the service refuses to
// start on it: a deployment that thinks it is being witnessed and is not should
// find out from a startup message and not from silence.
func New(opts Options) (*Shipper, error) {
	cfg := opts.Config
	if !cfg.Enabled() {
		return nil, ErrNotConfigured
	}
	if opts.Backlog == nil {
		return nil, errors.New("auditsink: a backlog reader is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	token, err := readCredential(cfg.TokenEnv)
	if err != nil {
		return nil, err
	}

	mark, err := loadWatermark(opts.WatermarkPath, logger)
	if err != nil {
		return nil, err
	}

	client := opts.HTTPClient
	if client == nil {
		// The timeout covers the whole exchange, connection included. The
		// transport is the standard library's, because a hand-written one here
		// would be a second place to keep up with the defaults.
		client = &http.Client{Timeout: cfg.Timeout.Duration}
	}

	s := &Shipper{
		cfg:      cfg,
		tenantID: opts.TenantID,
		endpoint: strings.TrimSpace(cfg.Endpoint),
		token:    token,
		client:   client,
		backlog:  opts.Backlog,
		alerts:   opts.Alerts,
		log:      logger,
		now:      clock,
		mark:     mark,
		queue:    make(chan *store.AuditEntry, cfg.BufferSize),
		backoff:  cfg.RetryBackoff.Duration,
	}

	// The first flush reads from the audit log rather than from the queue.
	// Whatever was buffered when the process last stopped is gone, and the
	// receiver is owed everything past the watermark.
	s.resync.Store(true)
	s.highest.Store(mark.get())

	return s, nil
}

// readCredential takes the bearer token out of the environment.
//
// The variable is unset once read, as the env keyring provider does, so it does
// not remain visible to a child process or through /proc/self/environ. That
// shortens the window rather than closing it: the Go runtime has already copied
// the value into an immutable string, and whatever injected the variable still
// holds it.
func readCredential(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: audit.sink.token_env names no variable", ErrNoCredential)
	}
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "", fmt.Errorf("%w: %s is empty or unset", ErrNoCredential, name)
	}
	if err := os.Unsetenv(name); err != nil {
		return "", fmt.Errorf("%w: %s could not be unset: %v", ErrNoCredential, name, err)
	}
	return v, nil
}

// Offer implements audit.Sink.
//
// It never blocks, never fails and never returns anything. An entry the queue
// cannot take is dropped, counted and logged; the audit log still holds it and
// the next flush reads it from there, so the receiver ends up with it either
// way. Blocking here would put a slow or unreachable third party on the
// authentication path, which is the one thing this must not do.
func (s *Shipper) Offer(entry *store.AuditEntry) {
	if entry == nil {
		return
	}
	s.noteHighest(entry.Seq)

	select {
	case s.queue <- entry:
	default:
		s.dropped.Add(1)
		s.resync.Store(true)
		if s.dropping.CompareAndSwap(false, true) {
			s.log.Error("audit sink buffer is full, delivery falls back to reading the audit log",
				slog.Int("buffer_size", s.cfg.BufferSize),
				slog.Int64("delivered_through_seq", s.mark.get()),
				slog.Int64("seq", entry.Seq))
		}
	}
}

// noteHighest records the largest sequence number offered so far.
//
// The loop is how a maximum is written atomically: a plain load, compare and
// store would let a concurrent offer with a lower number win.
func (s *Shipper) noteHighest(seq int64) {
	for {
		cur := s.highest.Load()
		if seq <= cur || s.highest.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// Run delivers until ctx is cancelled.
//
// Two things trigger a flush: a batch filling up, which is what keeps a busy
// deployment's witness close behind, and the interval, which is what stops a
// quiet one from sitting on two entries indefinitely.
func (s *Shipper) Run(ctx context.Context) {
	s.log.InfoContext(ctx, "audit sink started",
		slog.String("endpoint", s.endpoint),
		slog.Int64("delivered_through_seq", s.mark.get()),
		slog.Int("batch_size", s.cfg.BatchSize))

	ticker := time.NewTicker(s.cfg.FlushInterval.Duration)
	defer ticker.Stop()

	pending := make([]*store.AuditEntry, 0, s.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			s.finalFlush(pending)
			s.log.Info("audit sink stopped",
				slog.Int64("delivered_through_seq", s.mark.get()),
				slog.Int64("dropped_offers", s.dropped.Load()))
			return

		case entry := <-s.queue:
			pending = append(pending, entry)
			if len(pending) >= s.cfg.BatchSize {
				pending = s.flush(ctx, pending)
			}

		case <-ticker.C:
			pending = s.flush(ctx, pending)
		}
	}
}

// finalFlush makes one last attempt as the process shuts down.
//
// The context is detached from the cancelled one, as the HTTP server's shutdown
// is in main: reusing it would abort the attempt immediately, which is the
// opposite of what a drain is for. The backoff is cleared for the same reason,
// so a sink that failed a moment ago is still tried once. Whatever does not get
// through stays in the audit log and is delivered after the next start.
func (s *Shipper) finalFlush(pending []*store.AuditEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout.Duration)
	defer cancel()

	s.nextAttempt = time.Time{}
	s.flush(ctx, pending)
}

// flush delivers what it can and returns the queue's new pending slice, which
// is always empty: anything not sent is recovered from the audit log rather
// than accumulated in memory, so the shipper's footprint does not grow with the
// length of an outage.
func (s *Shipper) flush(ctx context.Context, pending []*store.AuditEntry) []*store.AuditEntry {
	// Drain whatever else is waiting, up to a batch, so that a tick after a
	// burst sends one POST rather than one per interval.
drain:
	for len(pending) < s.cfg.BatchSize {
		select {
		case entry := <-s.queue:
			pending = append(pending, entry)
		default:
			break drain
		}
	}

	if !s.nextAttempt.IsZero() && s.now().Before(s.nextAttempt) {
		// Inside the backoff. The queued entries are discarded rather than
		// held, because the log holds them and the catch-up read is what will
		// pick them up.
		if len(pending) > 0 {
			s.resync.Store(true)
		}
		return pending[:0]
	}

	batch, ok := usableBatch(pending, s.mark.get())
	pending = pending[:0]

	switch {
	case s.resync.Load() || !ok:
		s.catchUp(ctx)
	case len(batch) == 0:
		// Everything offered had already been delivered, which is the normal
		// state of the queue just after a catch-up.
	default:
		if err := s.deliver(ctx, batch); err != nil {
			s.fail(ctx, err)
			break
		}
		s.succeed()
	}
	return pending
}

// usableBatch turns the queued entries into a batch that continues the
// receiver's history exactly, or reports that it cannot.
//
// Entries at or below the watermark are duplicates of what has already been
// acknowledged and are skipped. What remains has to start one past the
// watermark and be consecutive; anything else means an offer was dropped or two
// concurrent appends reached the queue out of order, and the audit log is then
// the only thing that can say what belongs in between.
func usableBatch(pending []*store.AuditEntry, delivered int64) (batch []Record, ok bool) {
	expect := delivered + 1
	for _, e := range pending {
		if e == nil || e.Seq <= delivered {
			continue
		}
		if e.Seq != expect {
			return nil, false
		}
		batch = append(batch, Project(e))
		expect++
	}
	return batch, true
}

// catchUp reads from the audit log and delivers until the receiver is level
// with it.
//
// This is the path that survives a restart, a full buffer, an out-of-order
// offer and a failed POST, and it is the reason none of those four can leave a
// hole in the witness.
func (s *Shipper) catchUp(ctx context.Context) {
	for {
		if err := ctx.Err(); err != nil {
			return
		}

		from := s.mark.get() + 1
		entries, err := s.backlog.ReadAuditRange(ctx, from, s.cfg.BatchSize)
		if err != nil {
			s.fail(ctx, fmt.Errorf("%w: %v", ErrBacklog, err))
			return
		}
		if len(entries) == 0 {
			// Level with the log. Anything queued while this ran is either
			// below the watermark, and so skipped next time, or the start of the
			// next contiguous run.
			s.resync.Store(false)
			s.succeed()
			return
		}

		if entries[0].Seq != from {
			// The log no longer holds what the receiver is owed. Retention
			// trimming is the usual cause, and it is worth a line at error
			// level, because the receiver will see the same gap and cannot tell
			// it from tampering. Delivery continues: an incomplete witness is
			// still better than one that stopped.
			s.log.ErrorContext(ctx, "audit entries are missing from the local log and cannot be delivered",
				slog.Int64("expected_seq", from),
				slog.Int64("first_available_seq", entries[0].Seq))
		}

		batch := make([]Record, 0, len(entries))
		for _, e := range entries {
			batch = append(batch, Project(e))
		}

		if err := s.deliver(ctx, batch); err != nil {
			s.fail(ctx, err)
			return
		}
		s.succeed()

		if len(entries) < s.cfg.BatchSize {
			s.resync.Store(false)
			return
		}
	}
}

// deliver POSTs one batch and, only once the receiver has acknowledged it,
// records how far delivery has got.
//
// The order is the whole of the at-least-once guarantee. Writing the watermark
// first would mean a process that died in between had moved the marker past
// entries the receiver never saw, and nothing would ever go looking for them.
// This way the same crash costs a duplicate, which the receiver drops on the
// sequence number.
func (s *Shipper) deliver(ctx context.Context, batch []Record) error {
	if len(batch) == 0 {
		return nil
	}

	payload := Batch{
		Format:  Format,
		Source:  s.tenantID,
		SentAt:  s.now().UTC(),
		FromSeq: batch[0].Seq,
		ToSeq:   batch[len(batch)-1].Seq,
		Count:   len(batch),
		Entries: batch,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// Nothing in a Record is unmarshalable, so this cannot happen without
		// the type having changed. It is reported rather than ignored so that
		// the change is noticed here and not by a receiver.
		return fmt.Errorf("%w: the batch could not be encoded: %v", ErrDelivery, err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout.Duration)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDelivery, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("User-Agent", "n0passtemps/"+version.Current().Version)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDelivery, err)
	}
	defer func() {
		// The body is drained before closing so the connection can be reused,
		// and bounded so that a receiver answering with an endless stream
		// cannot exhaust this process.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// A 4xx is treated the same as a 5xx, which means it is retried. A
		// rejected credential will not fix itself, but it is fixed by an
		// operator rotating what the receiver expects, and the retry is what
		// picks that up without a restart. The backoff reaches its ceiling
		// either way, so a permanently refused sink costs one request every
		// max_retry_backoff.
		return fmt.Errorf("%w: the receiver answered %s", ErrDelivery, resp.Status)
	}

	if err := s.mark.set(s.now().UTC(), payload.ToSeq); err != nil {
		return err
	}

	s.log.Debug("audit batch delivered",
		slog.Int64("from_seq", payload.FromSeq),
		slog.Int64("to_seq", payload.ToSeq),
		slog.Int("count", payload.Count))
	return nil
}

// succeed clears the failure state after a delivery got through.
func (s *Shipper) succeed() {
	s.backoff = s.cfg.RetryBackoff.Duration
	s.nextAttempt = time.Time{}
	s.dropping.Store(false)
	s.setLastError("")
}

// fail records a failed attempt, schedules the next one and raises the alert.
//
// The backoff doubles to its configured ceiling and delivery is never
// abandoned, because the entries stay in the audit log: a witness that is
// behind catches up, and one the sender gave up on never does.
func (s *Shipper) fail(ctx context.Context, err error) {
	reason := truncate(err.Error(), maxReasonLen)
	s.setLastError(reason)
	s.resync.Store(true)

	if s.backoff <= 0 {
		s.backoff = s.cfg.RetryBackoff.Duration
	}
	s.nextAttempt = s.now().Add(s.backoff)
	if next := s.backoff * 2; next <= s.cfg.MaxRetryBackoff.Duration {
		s.backoff = next
	} else {
		s.backoff = s.cfg.MaxRetryBackoff.Duration
	}

	pending := s.pending()
	s.log.ErrorContext(ctx, "audit entries are not reaching the external sink",
		slog.String("endpoint", s.endpoint),
		slog.Int64("pending", pending),
		slog.Int64("delivered_through_seq", s.mark.get()),
		slog.Duration("retry_in", s.backoff),
		slog.Any("error", err))

	s.raise(ctx, pending, reason)
}

// raise files the alert, at most once per alertInterval.
//
// The engine collapses repeats onto one row by fingerprint, so the limit is
// about not writing a row per retry rather than about what an operator reads.
// The context is deliberately the worker's: an alert that cannot be written
// during shutdown is logged above and nothing waits on it.
func (s *Shipper) raise(ctx context.Context, pending int64, reason string) {
	if s.alerts == nil {
		return
	}
	now := s.now()
	if !s.lastAlert.IsZero() && now.Sub(s.lastAlert) < alertInterval {
		return
	}
	s.lastAlert = now

	if _, err := s.alerts.AuditSinkFailing(ctx, s.tenantID, s.endpoint, pending, reason); err != nil {
		s.log.WarnContext(ctx, "audit sink alert not raised", slog.Any("error", err))
	}
}

// pending estimates how many entries the receiver is behind by.
//
// It is the difference between the highest sequence number offered and the
// highest acknowledged, which is exact while the process has been running and
// an undercount for entries written before it started, since those were never
// offered. It is a number for a human to read, not a control.
func (s *Shipper) pending() int64 {
	if n := s.highest.Load() - s.mark.get(); n > 0 {
		return n
	}
	return 0
}

// Probe reports delivery state for the detailed health report.
//
// It is the shipper's whole surface towards internal/health, which is why it
// returns values rather than a struct: the report's shape belongs to that
// package, and this one should not have to change when a field is added to it.
func (s *Shipper) Probe() (deliveredThroughSeq, droppedOffers int64, lastError string) {
	s.errMu.RLock()
	last := s.lastErr
	s.errMu.RUnlock()
	return s.mark.get(), s.dropped.Load(), last
}

// Endpoint is where entries are being sent, for the startup log and the health
// report. The bearer credential is never exposed anywhere.
func (s *Shipper) Endpoint() string { return s.endpoint }

func (s *Shipper) setLastError(reason string) {
	s.errMu.Lock()
	s.lastErr = reason
	s.errMu.Unlock()
}

// truncate bounds text that ends up in an alert row or a health response, both
// of which are read by people.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// Runner runs a Shipper in a goroutine and waits for it on shutdown.
//
// It exists for the same reason janitor.Starter does: so main does not manage
// the goroutine, and so the process does not exit while a batch is in flight.
type Runner struct {
	wg   sync.WaitGroup
	stop context.CancelFunc
}

// Start launches the shipper.
func Start(ctx context.Context, s *Shipper) *Runner {
	ctx, cancel := context.WithCancel(ctx)
	r := &Runner{stop: cancel}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		s.Run(ctx)
	}()
	return r
}

// Stop cancels the shipper and waits for its last attempt to finish.
func (r *Runner) Stop() {
	r.stop()
	r.wg.Wait()
}
