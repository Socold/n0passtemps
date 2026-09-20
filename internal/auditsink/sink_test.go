package auditsink

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
)

func TestNewIsOffWithNoEndpoint(t *testing.T) {
	// Offline by default is the product's whole argument, so an unconfigured
	// sink must not merely fail to connect: no shipper exists at all.
	_, err := New(Options{Config: config.Default().Audit.Sink, Backlog: &fakeLog{}})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("New with no endpoint = %v, want ErrNotConfigured", err)
	}
}

func TestNewRefusesAMissingCredential(t *testing.T) {
	cfg := config.Default().Audit.Sink
	cfg.Endpoint = "https://witness.example.org/audit"
	cfg.ReceiverOutsideOperatorControl = true
	cfg.TokenEnv = config.EnvPrefix + "AUDIT_SINK_TOKEN"
	t.Setenv(cfg.TokenEnv, "")

	// Refused at startup rather than at the first delivery: a deployment that
	// believes it is being witnessed and is not should find out from a startup
	// message, not from an alert nobody had reason to expect.
	_, err := New(Options{
		Config:        cfg,
		Backlog:       &fakeLog{},
		WatermarkPath: watermarkPath(t),
	})
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("New with no credential = %v, want ErrNoCredential", err)
	}
}

func TestNewRefusesAnUnwritableWatermark(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}

	t.Setenv(config.EnvPrefix+"AUDIT_SINK_TOKEN", "witness-credential")
	cfg := config.Default().Audit.Sink
	cfg.Endpoint = rec.srv.URL + "/audit"
	cfg.ReceiverOutsideOperatorControl = true

	// A watermark that can never be written would mean every batch was
	// delivered and then delivered again after the next restart, for ever. That
	// is a misconfiguration to refuse at startup, not to discover from traffic.
	_, err := New(Options{
		Config:        cfg,
		Backlog:       lg,
		WatermarkPath: "/nonexistent-directory-for-a-test/audit-sink.watermark",
		HTTPClient:    rec.srv.Client(),
	})
	if !errors.Is(err, ErrWatermark) {
		t.Fatalf("New with an unwritable watermark = %v, want ErrWatermark", err)
	}
}

func TestDeliversOfferedEntriesInOrder(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	for _, e := range lg.appendMany(t, 3) {
		ts.shipper.Offer(e)
	}

	waitFor(t, "three entries to reach the receiver", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2, 3})
	})

	// The receiver must be able to verify the chain from what it was given and
	// nothing else. That is the property the whole projection exists for.
	if broken := CheckSequence(rec.deduped(), audit.Genesis()); broken != 0 {
		t.Errorf("the delivered run does not verify, broken at %d", broken)
	}

	for _, tok := range rec.presentedTokens() {
		if tok != "Bearer witness-credential" {
			t.Errorf("receiver was presented %q, want the configured bearer credential", tok)
		}
	}

	waitFor(t, "the watermark to reach 3", func() bool {
		delivered, _, _ := ts.shipper.Probe()
		return delivered == 3
	})
}

func TestTheCredentialIsRemovedFromTheEnvironment(t *testing.T) {
	rec := newReceiver(t)
	newTestSink(t, rec, &fakeLog{}, watermarkPath(t))

	// The same treatment the env keyring provider gives its variable: once
	// read, it is not left visible to a child process or to anything reading
	// /proc/self/environ.
	if v, ok := os.LookupEnv(config.EnvPrefix + "AUDIT_SINK_TOKEN"); ok {
		t.Errorf("the credential variable is still set to %q after New", v)
	}
}

func TestASinkThatIsDownIsRetriedAndLosesNothing(t *testing.T) {
	rec := newReceiver(t)
	rec.refuseNext(4, http.StatusServiceUnavailable)

	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	for _, e := range lg.appendMany(t, 5) {
		ts.shipper.Offer(e)
	}

	waitFor(t, "delivery to recover", func() bool {
		return seqsEqual(rec.seqs(), rangeSeqs(1, 5))
	})
	if broken := CheckSequence(rec.deduped(), audit.Genesis()); broken != 0 {
		t.Errorf("the delivered run does not verify, broken at %d", broken)
	}

	// An operator has to find out, and the alert is how: the log line alone
	// assumes somebody is reading the log at the moment it happens.
	if ts.alerts.count() == 0 {
		t.Error("no alert was raised while the sink was refusing batches")
	}
	if !strings.Contains(ts.logs.String(), "not reaching the external sink") {
		t.Error("the failure was not logged")
	}

	// And the failure state clears once delivery works again, so a blip does
	// not leave the health report degraded for ever.
	waitFor(t, "the last error to clear", func() bool {
		_, _, lastErr := ts.shipper.Probe()
		return lastErr == ""
	})
}

func TestARefusedCredentialKeepsBeingRetried(t *testing.T) {
	rec := newReceiver(t)
	rec.refuseNext(3, http.StatusUnauthorized)

	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)
	ts.shipper.Offer(lg.append(t, audit.EventAssertionCompleted))

	// A 401 will not fix itself, but it is fixed by an operator rotating what
	// the receiver expects, and only a retry picks that up without a restart.
	waitFor(t, "delivery to resume after the credential is accepted", func() bool {
		return seqsEqual(rec.seqs(), []int64{1})
	})
}

func TestASlowSinkDoesNotBlockAnOffer(t *testing.T) {
	rec := newReceiver(t)
	release := rec.block()
	t.Cleanup(release)

	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t), withBuffer(8, 4))
	ts.run(t)

	entries := lg.appendMany(t, 200)

	// The recorder is on the request path. Offering 200 entries to a sink that
	// has stopped answering has to cost about nothing, whatever the state of
	// the buffer.
	start := time.Now()
	for _, e := range entries {
		ts.shipper.Offer(e)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("offering 200 entries to a hanging sink took %s, which means an authentication would have waited", elapsed)
	}

	// The buffer holds eight, so most of those offers were dropped.
	waitFor(t, "the buffer to report drops", func() bool {
		_, dropped, _ := ts.shipper.Probe()
		return dropped > 0
	})
	if !strings.Contains(ts.logs.String(), "buffer is full") {
		t.Error("a full buffer was not logged")
	}

	// And a dropped offer is a lost delivery, never a lost entry: once the
	// receiver answers again, everything arrives from the audit log.
	release()
	waitFor(t, "the whole log to reach the receiver", func() bool {
		return seqsEqual(rec.seqs(), rangeSeqs(1, 200))
	})
	if broken := CheckSequence(rec.deduped(), audit.Genesis()); broken != 0 {
		t.Errorf("the delivered run does not verify, broken at %d", broken)
	}
}

func TestAnOutOfOrderOfferFallsBackToTheLog(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	entries := lg.appendMany(t, 3)

	// Two concurrent appends can reach the queue in either order. Delivering
	// what arrived would hand the receiver a hole, so the shipper reads the log
	// instead and the receiver still sees a contiguous run.
	ts.shipper.Offer(entries[2])
	ts.shipper.Offer(entries[0])
	ts.shipper.Offer(entries[1])

	waitFor(t, "the run to arrive in order", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2, 3})
	})
	if broken := CheckSequence(rec.deduped(), audit.Genesis()); broken != 0 {
		t.Errorf("the delivered run does not verify, broken at %d", broken)
	}
}

func TestARestartResumesFromTheWatermark(t *testing.T) {
	path := watermarkPath(t)
	lg := &fakeLog{}

	first := newReceiver(t)
	before := newTestSink(t, first, lg, path)
	runner := before.run(t)

	for _, e := range lg.appendMany(t, 3) {
		before.shipper.Offer(e)
	}
	waitFor(t, "the first three entries to be delivered", func() bool {
		return seqsEqual(first.seqs(), []int64{1, 2, 3})
	})
	runner.Stop()

	// Two more entries are written while nothing is shipping them, which is the
	// process being down.
	lg.appendMany(t, 2)

	second := newReceiver(t)
	after := newTestSink(t, second, lg, path)
	after.run(t)

	// The restart owes the receiver exactly what it has not acknowledged. It
	// must not resend the first three, and it must not skip the last two
	// merely because nothing offered them.
	waitFor(t, "the backlog to be delivered after the restart", func() bool {
		return seqsEqual(second.seqs(), []int64{4, 5})
	})
	if got := second.seqs(); len(got) != 2 {
		t.Errorf("the restart delivered %v, want only the two undelivered entries", got)
	}
}

func TestDeathBeforeTheWatermarkWriteResendsTheBatch(t *testing.T) {
	path := watermarkPath(t)
	lg := &fakeLog{}
	entries := lg.appendMany(t, 3)

	first := newReceiver(t)
	before := newTestSink(t, first, lg, path)
	runner := before.run(t)
	for _, e := range entries {
		before.shipper.Offer(e)
	}
	waitFor(t, "the first delivery", func() bool {
		return seqsEqual(first.seqs(), []int64{1, 2, 3})
	})
	runner.Stop()

	// The receiver acknowledged 1 to 3 and the process died before the
	// watermark reached disk, which is simulated by putting the file back to 1.
	// The order is deliberate: writing the watermark first would have moved the
	// marker past entries the receiver never saw, and nothing anywhere would
	// have gone looking for them.
	rewindWatermark(t, path, 1)

	second := newReceiver(t)
	after := newTestSink(t, second, lg, path)
	after.run(t)

	waitFor(t, "the acknowledged entries to be sent again", func() bool {
		return seqsEqual(second.seqs(), []int64{2, 3})
	})

	// A duplicate has to be identical to the first copy, or a receiver
	// de-duplicating on the sequence number would be hiding a difference.
	firstCopies := indexBySeq(first.deduped())
	for _, again := range second.deduped() {
		original, ok := firstCopies[again.Seq]
		if !ok {
			t.Fatalf("seq %d was resent although it was never delivered", again.Seq)
		}
		if !recordsEqual(original, again) {
			t.Errorf("the resent copy of seq %d differs from the first", again.Seq)
		}
	}
}

func TestACorruptWatermarkStartsFromTheBeginning(t *testing.T) {
	path := watermarkPath(t)
	if err := os.WriteFile(path, []byte("this is not json"), 0o600); err != nil {
		t.Fatalf("write a corrupt watermark: %v", err)
	}

	rec := newReceiver(t)
	lg := &fakeLog{}
	lg.appendMany(t, 3)
	ts := newTestSink(t, rec, lg, path)
	ts.run(t)

	// Resending is the safe direction: the receiver de-duplicates, whereas
	// guessing a higher watermark would skip entries silently.
	waitFor(t, "the whole log to be resent", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2, 3})
	})
	if !strings.Contains(ts.logs.String(), "not readable as JSON") {
		t.Error("a corrupt watermark was not reported")
	}
}

func TestATrimmedPrefixIsReportedRatherThanHidden(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	lg.appendMany(t, 4)
	lg.trimPrefix(2)

	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	// Retention trimming can remove entries the receiver never saw. The
	// receiver will see the same gap and cannot tell it from tampering, so the
	// sender says so at error level rather than delivering in silence.
	waitFor(t, "what is left of the log to be delivered", func() bool {
		return seqsEqual(rec.seqs(), []int64{3, 4})
	})
	if !strings.Contains(ts.logs.String(), "missing from the local log") {
		t.Error("a trimmed prefix was not reported")
	}
}

func TestAnUnreadableLogIsRetried(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{err: errors.New("database is unreachable")}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	waitFor(t, "the read failure to be reported", func() bool {
		_, _, lastErr := ts.shipper.Probe()
		return strings.Contains(lastErr, "audit log could not be read")
	})

	lg.mu.Lock()
	lg.err = nil
	lg.mu.Unlock()
	lg.appendMany(t, 2)

	waitFor(t, "delivery to resume", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2})
	})
}

func TestStopMakesOneLastAttempt(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	// A long interval, so nothing can be delivered by a tick: what reaches the
	// receiver got there because the shutdown drained the queue.
	ts := newTestSink(t, rec, lg, watermarkPath(t), func(c *config.AuditSink) {
		c.FlushInterval = config.Duration{Duration: time.Hour}
	})
	runner := Start(t.Context(), ts.shipper)

	for _, e := range lg.appendMany(t, 2) {
		ts.shipper.Offer(e)
	}
	runner.Stop()

	if got := rec.seqs(); !seqsEqual(got, []int64{1, 2}) {
		t.Errorf("shutdown delivered %v, want the queued entries 1 and 2", got)
	}
}

func TestBatchesCarryOnePostPerBatchSize(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t), withBuffer(64, 4))
	ts.run(t)

	for _, e := range lg.appendMany(t, 12) {
		ts.shipper.Offer(e)
	}

	waitFor(t, "twelve entries to be delivered", func() bool {
		return seqsEqual(rec.seqs(), rangeSeqs(1, 12))
	})

	// Batching is what keeps a busy deployment from making one request per
	// authentication. Three full batches is the floor; a few more requests are
	// possible because a tick can land mid-burst.
	if n := rec.requestCount(); n > 8 {
		t.Errorf("twelve entries took %d requests with a batch size of 4, which is not batching", n)
	}
}

// rewindWatermark puts the watermark file back to seq, standing in for a
// process that died between the receiver's acknowledgement and the write.
func rewindWatermark(t *testing.T, path string, seq int64) {
	t.Helper()
	body, err := json.Marshal(watermarkFile{DeliveredThroughSeq: seq, UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("encode watermark: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("rewind watermark: %v", err)
	}
}

func indexBySeq(records []Record) map[int64]Record {
	out := make(map[int64]Record, len(records))
	for _, r := range records {
		out[r.Seq] = r
	}
	return out
}
