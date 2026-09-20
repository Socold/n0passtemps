package auditsink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

const testTenant = "tenant-a"

// fakeLog is an audit log in memory, chained exactly as a store chains one.
//
// The entries have to be genuinely chained rather than stubbed, because every
// property under test here is a property of the chain: a receiver verifying a
// batch, a gap surfacing at the entry after it, a resend being byte identical.
type fakeLog struct {
	mu      sync.Mutex
	entries []*store.AuditEntry
	err     error
}

// append writes one entry and returns it, as a store would.
func (l *fakeLog) append(t *testing.T, eventType string) *store.AuditEntry {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()

	prev := audit.Genesis()
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].EntryHash
	}
	e := &store.AuditEntry{
		TenantID:   testTenant,
		OccurredAt: time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC),
		EventType:  eventType,
		ActorType:  store.ActorSubject,
		ActorID:    "actor-1",
		Outcome:    store.OutcomeSuccess,
		RequestID:  "req-1",
		SubjectID:  "subject-1",
		SourceIP:   "192.0.2.10",
		Detail:     json.RawMessage(`{"reason":"lost device"}`),
	}
	if err := audit.Prepare(e, int64(len(l.entries)+1), prev); err != nil {
		t.Fatalf("prepare entry: %v", err)
	}
	l.entries = append(l.entries, e)
	return e
}

// appendMany writes n entries and returns them.
func (l *fakeLog) appendMany(t *testing.T, n int) []*store.AuditEntry {
	t.Helper()
	out := make([]*store.AuditEntry, 0, n)
	for range n {
		out = append(out, l.append(t, audit.EventAssertionCompleted))
	}
	return out
}

// trimPrefix removes the first n entries, as retention trimming does.
func (l *fakeLog) trimPrefix(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[n:]
}

func (l *fakeLog) ReadAuditRange(_ context.Context, fromSeq int64, limit int) ([]*store.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.err != nil {
		return nil, l.err
	}
	var out []*store.AuditEntry
	for _, e := range l.entries {
		if e.Seq < fromSeq {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, e)
	}
	return out, nil
}

// receiver is a witness. It records what it is given and can be told to refuse
// or to hang, which are the two ways a real one fails.
type receiver struct {
	srv *httptest.Server

	mu       sync.Mutex
	batches  []Batch
	requests int
	refuse   int
	status   int
	hold     chan struct{}
	tokens   []string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{status: http.StatusServiceUnavailable}
	r.srv = httptest.NewServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) handle(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.requests++
	hold := r.hold
	refuse := r.refuse
	status := r.status
	if refuse > 0 {
		r.refuse--
	}
	r.tokens = append(r.tokens, req.Header.Get("Authorization"))
	r.mu.Unlock()

	if hold != nil {
		<-hold
	}
	if refuse > 0 {
		w.WriteHeader(status)
		return
	}

	var batch Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// A receiver that stored a body without this check would file a truncated
	// batch as though it were complete, and then report the gap as the sender's
	// fault.
	if err := batch.Verify(); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	r.mu.Lock()
	r.batches = append(r.batches, batch)
	r.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

// refuseNext makes the next n requests fail with status.
func (r *receiver) refuseNext(n, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refuse = n
	r.status = status
}

// block makes every request wait until the returned function is called.
func (r *receiver) block() (release func()) {
	hold := make(chan struct{})
	r.mu.Lock()
	r.hold = hold
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.hold = nil
			r.mu.Unlock()
			close(hold)
		})
	}
}

// records returns every record the receiver accepted, in arrival order and
// with duplicates left in, because a receiver really does see duplicates.
func (r *receiver) records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Record
	for _, b := range r.batches {
		out = append(out, b.Entries...)
	}
	return out
}

// deduped returns the accepted records once each, in sequence order, which is
// what a receiver stores after de-duplicating on the sequence number.
func (r *receiver) deduped() []Record {
	seen := map[int64]Record{}
	var order []int64
	for _, rec := range r.records() {
		if _, ok := seen[rec.Seq]; !ok {
			order = append(order, rec.Seq)
		}
		seen[rec.Seq] = rec
	}
	out := make([]Record, 0, len(order))
	for _, seq := range order {
		out = append(out, seen[seq])
	}
	return out
}

func (r *receiver) seqs() []int64 {
	var out []int64
	for _, rec := range r.deduped() {
		out = append(out, rec.Seq)
	}
	return out
}

func (r *receiver) requestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

func (r *receiver) presentedTokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

// fakeAlerts records the alerts a failing sink raises.
type fakeAlerts struct {
	mu     sync.Mutex
	raised []string
}

func (a *fakeAlerts) AuditSinkFailing(_ context.Context, _, endpoint string, pending int64, reason string) (*store.Alert, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.raised = append(a.raised, endpoint+" "+reason)
	_ = pending
	return &store.Alert{}, nil
}

func (a *fakeAlerts) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.raised)
}

// logBuffer collects log output so a test can assert that a condition was
// reported rather than swallowed.
type logBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// testSink builds a shipper against the receiver, with intervals short enough
// that a test does not have to wait for a wall-clock second.
type testSink struct {
	shipper *Shipper
	log     *fakeLog
	alerts  *fakeAlerts
	logs    *logBuffer
	path    string
}

type sinkOption func(*config.AuditSink)

func withBuffer(size, batch int) sinkOption {
	return func(c *config.AuditSink) {
		c.BufferSize = size
		c.BatchSize = batch
	}
}

func newTestSink(t *testing.T, rec *receiver, lg *fakeLog, watermarkPath string, opts ...sinkOption) *testSink {
	t.Helper()

	t.Setenv(config.EnvPrefix+"AUDIT_SINK_TOKEN", "witness-credential")

	cfg := config.Default().Audit.Sink
	cfg.Endpoint = rec.srv.URL + "/audit"
	cfg.ReceiverOutsideOperatorControl = true
	cfg.BufferSize = 64
	cfg.BatchSize = 8
	cfg.FlushInterval = config.Duration{Duration: 2 * time.Millisecond}
	cfg.Timeout = config.Duration{Duration: 2 * time.Second}
	cfg.RetryBackoff = config.Duration{Duration: time.Millisecond}
	cfg.MaxRetryBackoff = config.Duration{Duration: 5 * time.Millisecond}
	for _, opt := range opts {
		opt(&cfg)
	}

	al := &fakeAlerts{}
	logs := &logBuffer{}

	s, err := New(Options{
		Config:        cfg,
		TenantID:      testTenant,
		WatermarkPath: watermarkPath,
		Backlog:       lg,
		Alerts:        al,
		Logger:        slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Clock:         time.Now,
		HTTPClient:    rec.srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &testSink{shipper: s, log: lg, alerts: al, logs: logs, path: watermarkPath}
}

// run starts the shipper and stops it when the test ends.
func (ts *testSink) run(t *testing.T) *Runner {
	t.Helper()
	r := Start(context.Background(), ts.shipper)
	t.Cleanup(r.Stop)
	return r
}

func watermarkPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit-sink.watermark")
}

// waitFor polls until cond holds, which is how a test waits on a background
// goroutine without sleeping for a fixed guess.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func seqsEqual(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func rangeSeqs(from, to int64) []int64 {
	var out []int64
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}
