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
// # At least once, and a break in the chain is the receiver's to notice
//
// The watermark is written only after the receiver has acknowledged a batch. A
// process that dies between the acknowledgement and that write comes back and
// sends the batch again, so a receiver must expect duplicates and de-duplicate
// on the sequence number. The opposite order would give at most once: the
// watermark would move, the entries would never arrive, and nothing anywhere
// would know. Duplicates are a receiver's inconvenience; a silent hole in the
// witness defeats the purpose of having one.
//
// A receiver detects a missing entry from the chain, and CheckSequence is that
// check, written once here so it can be quoted rather than described. It is the
// chain and not the numbering: on PostgreSQL seq comes from a sequence, which
// spends a value even when the transaction that drew it rolls back, so an
// ordinary log has gaps that no entry ever filled. Given 41, 42 and 44 the
// question is whether 44 chains onto 42. If it does, 43 was never written. If
// it does not, something between them has gone, which is what a witness is for.
//
// # Silence has to mean something
//
// Delivering only when there is something to deliver leaves a receiver unable
// to tell a quiet weekend from an outbound path somebody cut, and those are the
// two ends of one attack: stop the deliveries, act, remove the tail of the
// local log, let them resume. So the shipper also says the head of the chain
// out loud every heartbeatInterval when nothing else has reached the receiver,
// and the receiver is told to expect it. A heartbeat is marked as one, carries
// no entry and never moves the watermark. See Heartbeat and docs/SIEM.md.
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

	// ErrWatermarkAhead is returned when the watermark names a sequence number
	// the audit log has not reached.
	//
	// Delivery only ever moves the watermark up to an entry it has just read, so
	// this is never the shipper's own doing: either the file was edited, or the
	// database was restored from a backup older than the watermark. It is not
	// repaired here. Rewriting the file to match the log would erase the one
	// trace of the first cause, and after the second the receiver holds entries
	// this log no longer has, which is for an operator to reconcile.
	ErrWatermarkAhead = errors.New("auditsink: the delivery watermark is ahead of the audit log")

	// ErrMalformedBatch is what Batch.Verify and Heartbeat.Verify report. It is
	// here for a receiver written in Go, which can then use the same checks the
	// sender does.
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

	// heartbeatInterval is how long the receiver may hear nothing before the
	// shipper says the head of the chain out loud.
	//
	// It is a constant and not a setting. The section already has a flush
	// interval, a timeout and two backoffs, and none of them is the right
	// cadence for this: the flush interval is seconds, because it bounds how
	// far behind the witness runs, and a POST every few seconds from a
	// deployment where nothing is happening is noise the receiver has to store.
	// Five minutes is short enough that an outbound path cut during an intrusion
	// shows up while the intrusion is still going on, and long enough that a
	// quiet deployment costs the receiver twelve requests an hour. A setting
	// would be one more thing to get wrong for a value nobody has a reason to
	// choose differently, and adding one is a change to internal/config.
	heartbeatInterval = 5 * time.Minute
)

// Backlog is the part of the audit store the shipper reads to catch up.
//
// It is an interface, and a narrow one, so that the shipper can be tested
// against a log built in memory and so that this package depends on the two
// store methods it actually needs.
type Backlog interface {
	ReadAuditRange(ctx context.Context, fromSeq int64, limit int) ([]*store.AuditEntry, error)

	// ChainHead is what the watermark is checked against. Reading past the
	// watermark cannot do that: a watermark beyond the end of the log and a
	// receiver that is level with it both come back as an empty range.
	ChainHead(ctx context.Context) (seq int64, hash []byte, err error)
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

	// heartbeatEvery is heartbeatInterval. It is a field only so that the tests
	// do not have to wait five minutes for one.
	heartbeatEvery time.Duration

	// The fields below belong to the worker goroutine, except lastErr, which
	// the health probe reads.
	backoff     time.Duration
	nextAttempt time.Time
	lastAlert   time.Time

	// lastContact is when the receiver last answered, and is what the heartbeat
	// measures its silence against. A deployment busy enough to be delivering
	// says the same thing more often and does not need one.
	lastContact time.Time

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
	client = withoutRedirects(client)

	s := &Shipper{
		cfg:            cfg,
		tenantID:       opts.TenantID,
		endpoint:       strings.TrimSpace(cfg.Endpoint),
		token:          token,
		client:         client,
		backlog:        opts.Backlog,
		alerts:         opts.Alerts,
		log:            logger,
		now:            clock,
		mark:           mark,
		queue:          make(chan *store.AuditEntry, cfg.BufferSize),
		backoff:        cfg.RetryBackoff.Duration,
		heartbeatEvery: heartbeatInterval,
	}

	// The first flush reads from the audit log rather than from the queue.
	// Whatever was buffered when the process last stopped is gone, and the
	// receiver is owed everything past the watermark.
	s.resync.Store(true)
	s.highest.Store(mark.get())

	return s, nil
}

// withoutRedirects returns a copy of client that hands a redirect back as the
// response instead of following it.
//
// The receiver is a third party, and following its redirects would let it, or
// anything able to answer in its place, decide where the batch goes. A 307 or
// 308 repeats the POST against the new address, bearer credential included,
// and nothing stops that address being plain http. A 301 or 302 is worse in a
// quieter way: the request is repeated as a GET with no body, and a 2xx from
// wherever it lands would be read as an acknowledgement, moving the watermark
// past entries nobody received. An endpoint that has moved is fixed in the
// configuration, where the operator can see the new address.
//
// It is a copy so that a client supplied by the caller is not altered.
func withoutRedirects(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

// readCredential takes the bearer token out of the environment.
//
// The variable is unset once read, as the env keyring provider does, so a child
// process started later does not inherit it. That narrows the exposure rather
// than closing it: the Go runtime has already copied the value into an
// immutable string, whatever injected the variable still holds it, and the
// environment block the kernel recorded at startup stays readable through
// /proc/<pid>/environ, by the same uid and by root, because os.Unsetenv edits
// only the runtime's copy.
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

	// A watermark the log has not reached is reported now rather than at the
	// first flush, so that it sits next to the start in the log.
	if err := s.checkWatermark(ctx); err != nil {
		s.fail(ctx, err)
	}

	ticker := time.NewTicker(s.cfg.FlushInterval.Duration)
	defer ticker.Stop()

	// The second ticker is what a receiver hears from a deployment where
	// nothing is happening. See heartbeat.
	beat := time.NewTicker(s.heartbeatEvery)
	defer beat.Stop()

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

		case <-beat.C:
			s.heartbeat(ctx)
		}
	}
}

// heartbeat tells the receiver where the chain has got to, when nothing has
// been delivered for a while.
//
// The attack it exists for is the one the external witness is there to catch,
// carried out patiently: cut the outbound path, do whatever was worth doing,
// remove the tail of the local log, let the path recover. A receiver that only
// ever hears about entries cannot tell that from a weekend, so the sender says
// something on its own account and the receiver is told to expect it. What it
// says is the head of the chain, because a liveness ping proves the process is
// running and proves nothing about the log it is running on.
//
// It is skipped while a delivery has got through recently, so a busy deployment
// does not send both, and it is skipped inside the retry backoff, because a
// receiver that has just refused a batch does not need a second request now. A
// heartbeat that fails is reported like any other failed attempt: not reaching
// the witness is the condition being reported, whichever body was being sent.
//
// The watermark is not touched. A heartbeat acknowledges nothing.
func (s *Shipper) heartbeat(ctx context.Context) {
	now := s.now()
	if !s.nextAttempt.IsZero() && now.Before(s.nextAttempt) {
		return
	}
	if !s.lastContact.IsZero() && now.Sub(s.lastContact) < s.heartbeatEvery {
		return
	}

	headSeq, headHash, err := s.backlog.ChainHead(ctx)
	if err != nil {
		s.fail(ctx, fmt.Errorf("%w: %v", ErrBacklog, err))
		return
	}

	delivered := s.mark.get()
	body, err := json.Marshal(Heartbeat{
		Format:              Format,
		Kind:                KindHeartbeat,
		Source:              s.tenantID,
		SentAt:              now.UTC(),
		HeadSeq:             headSeq,
		HeadHash:            headHash,
		DeliveredThroughSeq: delivered,
	})
	if err != nil {
		// Nothing in a Heartbeat is unmarshalable, so this cannot happen
		// without the type having changed.
		s.fail(ctx, fmt.Errorf("%w: the heartbeat could not be encoded: %v", ErrDelivery, err))
		return
	}

	if err := s.post(ctx, body); err != nil {
		s.fail(ctx, err)
		return
	}
	s.log.Debug("audit sink heartbeat sent",
		slog.Int64("head_seq", headSeq),
		slog.Int64("delivered_through_seq", delivered))
	s.succeed()
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

	delivered, deliveredHash := s.mark.head()
	batch, ok := usableBatch(pending, delivered, deliveredHash)
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
// acknowledged and are skipped. What remains has to chain onto the last
// delivered entry and onto each other; anything else means an offer was dropped
// or two concurrent appends reached the queue out of order, and the audit log
// is then the only thing that can say what belongs in between.
//
// The join is checked by hash rather than by the sequence number being one
// higher. On PostgreSQL the numbers are not consecutive: seq is drawn from a
// sequence, which spends a value even when the transaction that drew it is
// rolled back, so an entry legitimately follows one three numbers below it. A
// shipper counting numbers treated every such gap as a dropped offer and fell
// back to reading the audit log for ever after. The hash says exactly what the
// counting was trying to approximate, and says it identically on both engines.
//
// prevHash is nil when the watermark was written before it recorded one. There
// is then nothing to check the join against, so the queue is refused and the
// catch-up read settles it; the first delivery after that records the hash.
func usableBatch(pending []*store.AuditEntry, delivered int64, prevHash []byte) (batch []Record, ok bool) {
	expect := prevHash
	for _, e := range pending {
		if e == nil || e.Seq <= delivered {
			continue
		}
		if len(expect) == 0 || !bytes.Equal(e.PrevHash, expect) {
			return nil, false
		}
		batch = append(batch, Project(e))
		expect = e.EntryHash
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
	// Checked before anything is read, because the read cannot tell: past a
	// watermark that is ahead of the log there is nothing, which is also what
	// being level looks like.
	if err := s.checkWatermark(ctx); err != nil {
		s.fail(ctx, err)
		return
	}

	for {
		if err := ctx.Err(); err != nil {
			return
		}

		delivered, prevHash := s.mark.head()
		entries, err := s.backlog.ReadAuditRange(ctx, delivered+1, s.cfg.BatchSize)
		if err != nil {
			s.fail(ctx, fmt.Errorf("%w: %v", ErrBacklog, err))
			return
		}
		if len(entries) == 0 {
			// Level with the log. Anything queued while this ran is either
			// below the watermark, and so skipped next time, or the start of the
			// next run.
			s.resync.Store(false)
			s.succeed()
			return
		}

		if len(prevHash) != 0 && !bytes.Equal(entries[0].PrevHash, prevHash) {
			// The log no longer holds what the receiver is owed. Retention
			// trimming is the usual cause, and it is worth a line at error
			// level, because the receiver will see the same break and cannot
			// tell it from tampering. Delivery continues: an incomplete witness
			// is still better than one that stopped.
			//
			// The test is on the chain and not on the numbering, because a
			// number the log skipped is not an entry the log lost: PostgreSQL
			// spends a sequence value on an append that rolls back. What says
			// something is really gone is the first entry available failing to
			// chain onto the last one delivered.
			s.log.ErrorContext(ctx, "audit entries are missing from the local log and cannot be delivered",
				slog.Int64("expected_seq", delivered+1),
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

// checkWatermark compares the watermark with the head of the audit log.
//
// Without it a watermark beyond the head stops delivery for good and in
// silence: the catch-up reads an empty range and reports success, and every
// entry offered afterwards is at or below the watermark and so is skipped as
// already delivered, until the log happens to grow past it.
//
// The failure is reported like any other, so it reaches the log, the alert and
// the health report, and it is retried, so it clears by itself once an operator
// has dealt with the cause. The watermark is left as it was found.
func (s *Shipper) checkWatermark(ctx context.Context) error {
	head, _, err := s.backlog.ChainHead(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBacklog, err)
	}
	delivered := s.mark.get()
	if delivered <= head {
		return nil
	}

	s.log.ErrorContext(ctx, "the audit sink watermark is ahead of the audit log and nothing can be delivered: "+
		"either the watermark file was edited, or the database was restored from a backup older than it",
		slog.Int64("delivered_through_seq", delivered),
		slog.Int64("head_seq", head),
		slog.String("path", s.mark.path))
	return fmt.Errorf("%w: it says %d was delivered and the log ends at %d, "+
		"so the file was edited or the database was restored from an older backup",
		ErrWatermarkAhead, delivered, head)
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
		Kind:    KindBatch,
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

	if err := s.post(ctx, body); err != nil {
		return err
	}

	// The hash travels with the sequence number, because it is what the next
	// batch has to chain onto and the numbering cannot say that on its own.
	if err := s.mark.set(s.now().UTC(), payload.ToSeq, batch[len(batch)-1].EntryHash); err != nil {
		return err
	}

	s.log.Debug("audit batch delivered",
		slog.Int64("from_seq", payload.FromSeq),
		slog.Int64("to_seq", payload.ToSeq),
		slog.Int("count", payload.Count))
	return nil
}

// post sends one body to the receiver and reports whether it was accepted.
//
// It is shared by the batch and the heartbeat so that the credential, the
// timeout, the bounded drain and the reading of the status code are written
// once. What is deliberately not here is the watermark: only a delivery moves
// it, and only after this has returned.
func (s *Shipper) post(ctx context.Context, body []byte) error {
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
		// A 3xx ends up here as well: redirects are not followed, see
		// withoutRedirects, and a receiver that answers with one has not taken
		// the body.
		//
		// A 4xx is treated the same as a 5xx, which means it is retried. A
		// rejected credential will not fix itself, but it is fixed by an
		// operator rotating what the receiver expects, and the retry is what
		// picks that up without a restart. The backoff reaches its ceiling
		// either way, so a permanently refused sink costs one request every
		// max_retry_backoff.
		return fmt.Errorf("%w: the receiver answered %s", ErrDelivery, resp.Status)
	}

	// The receiver answered, which is what the heartbeat measures its silence
	// against. It is recorded here rather than in succeed, because a catch-up
	// that finds nothing to send also succeeds and speaks to nobody.
	s.lastContact = s.now()
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
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
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
