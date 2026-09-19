package auditsink

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
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

func TestAGapInTheNumberingIsDeliveredWithoutComplaint(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	lg.appendMany(t, 2)
	lg.skipSeq()
	lg.appendMany(t, 2)

	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)

	// Seq 3 was spent by an append that rolled back, which is ordinary on
	// PostgreSQL. The shipper used to read that as a dropped offer, resynchronise
	// on every flush and log entries as missing for ever after.
	waitFor(t, "the log to be delivered across the skipped number", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2, 4, 5})
	})
	if broken := CheckSequence(rec.deduped(), audit.Genesis()); broken != 0 {
		t.Errorf("the delivered run does not verify, broken at %d", broken)
	}
	if strings.Contains(ts.logs.String(), "missing from the local log") {
		t.Error("a number the engine never gave to an entry was reported as entries missing from the log")
	}
}

func TestUsableBatchJoinsOnTheChainRatherThanTheNumbering(t *testing.T) {
	lg := &fakeLog{}
	entries := lg.appendMany(t, 2)
	lg.skipSeq()
	entries = append(entries, lg.appendMany(t, 2)...)

	batch, ok := usableBatch(entries, 0, audit.Genesis())
	if !ok || len(batch) != 4 {
		t.Fatalf("a queue whose numbering skips gave (%d records, ok=%v), want all four", len(batch), ok)
	}

	t.Run("an entry that does not continue the chain is refused", func(t *testing.T) {
		// Two concurrent appends reaching the queue out of order, or an offer
		// the buffer dropped. Either way the audit log is the only thing that
		// can say what belongs in between.
		withHole := []*store.AuditEntry{entries[0], entries[1], entries[3]}
		if _, ok := usableBatch(withHole, 0, audit.Genesis()); ok {
			t.Error("a queue missing an entry was accepted as a batch")
		}
	})

	t.Run("a watermark with no hash is refused", func(t *testing.T) {
		// Written by a version that recorded only the sequence number. There is
		// nothing to check the join against, so the catch-up read settles it.
		if _, ok := usableBatch(entries[2:], entries[1].Seq, nil); ok {
			t.Error("a queue was accepted although nothing said what it had to chain onto")
		}
	})
}

func TestAHeartbeatGoesOutWhenThereIsNothingToDeliver(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	// The interval is a constant in the package, and a field only so that a
	// test does not have to wait five minutes for the tick.
	ts.shipper.heartbeatEvery = 5 * time.Millisecond
	ts.run(t)

	// Nothing has ever been written, so nothing will ever be delivered, and a
	// receiver hearing nothing cannot tell this deployment from one whose
	// outbound path was cut before the interesting part.
	waitFor(t, "a heartbeat from a deployment with an empty log", func() bool {
		return len(rec.beats()) > 0
	})

	beat := rec.beats()[0]
	if beat.Kind != KindHeartbeat {
		t.Errorf("the heartbeat is marked %q, want %q: a receiver must not file it as a delivery",
			beat.Kind, KindHeartbeat)
	}
	if beat.HeadSeq != 0 || !bytes.Equal(beat.HeadHash, audit.Genesis()) {
		t.Errorf("the heartbeat carries head (%d, %x), want the genesis value at seq 0",
			beat.HeadSeq, beat.HeadHash)
	}
	if got := rec.seqs(); len(got) != 0 {
		t.Errorf("the receiver stored %v as entries, want a heartbeat to carry none", got)
	}
}

func TestAHeartbeatCarriesTheHeadAndLeavesTheWatermark(t *testing.T) {
	rec := newReceiver(t)
	lg := &fakeLog{}
	entries := lg.appendMany(t, 2)

	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.shipper.heartbeatEvery = 5 * time.Millisecond
	ts.run(t)

	waitFor(t, "the log to be delivered", func() bool {
		return seqsEqual(rec.seqs(), []int64{1, 2})
	})
	waitFor(t, "a heartbeat once delivery has gone quiet", func() bool {
		return len(rec.beats()) > 0
	})

	head := entries[len(entries)-1]
	beat := rec.beats()[0]
	if beat.HeadSeq != head.Seq || !bytes.Equal(beat.HeadHash, head.EntryHash) {
		t.Errorf("the heartbeat carries head (%d, %x), want (%d, %x)",
			beat.HeadSeq, beat.HeadHash, head.Seq, head.EntryHash)
	}
	if beat.DeliveredThroughSeq != head.Seq {
		t.Errorf("the heartbeat says %d was delivered, want %d",
			beat.DeliveredThroughSeq, head.Seq)
	}

	// A heartbeat acknowledges nothing, so it must not move delivery on. A
	// watermark that advanced on one would skip every entry written in between.
	if delivered, _, _ := ts.shipper.Probe(); delivered != head.Seq {
		t.Errorf("the watermark is at %d after a heartbeat, want it left at %d", delivered, head.Seq)
	}
	if got := rec.seqs(); !seqsEqual(got, []int64{1, 2}) {
		t.Errorf("the receiver holds %v, want the two delivered entries and nothing from the heartbeat", got)
	}
}

func TestARedirectIsNotFollowedAndIsNotAnAcknowledgement(t *testing.T) {
	// Where a redirect would send the batch. It answers 2xx to anything, which
	// is what would turn a followed redirect into a false acknowledgement.
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)

	var asked atomic.Int64
	rec := &receiver{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		asked.Add(1)
		http.Redirect(w, req, other.URL+"/audit", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(rec.srv.Close)

	lg := &fakeLog{}
	ts := newTestSink(t, rec, lg, watermarkPath(t))
	ts.run(t)
	ts.shipper.Offer(lg.append(t, audit.EventAssertionCompleted))

	// The receiver is a third party. A 307 it answers with would otherwise
	// carry the batch and the bearer credential to an address of its choosing.
	waitFor(t, "the redirect to be reported as a failed delivery", func() bool {
		_, _, lastErr := ts.shipper.Probe()
		return strings.Contains(lastErr, "307")
	})
	waitFor(t, "the delivery to be retried", func() bool { return asked.Load() >= 2 })

	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect target received %d requests, want none: the batch and the credential left for it", n)
	}
	if delivered, _, _ := ts.shipper.Probe(); delivered != 0 {
		t.Errorf("the watermark moved to %d although no receiver took the batch", delivered)
	}
}

func TestAWatermarkAheadOfTheLogIsAFailureAndIsNotRepaired(t *testing.T) {
	path := watermarkPath(t)
	rewindWatermark(t, path, 9)

	rec := newReceiver(t)
	lg := &fakeLog{}
	lg.appendMany(t, 3)
	ts := newTestSink(t, rec, lg, path)
	ts.run(t)

	// The log ends at 3 and the watermark says 9 was delivered: the file was
	// edited, or the database was restored from an older backup. Reading past 9
	// finds nothing, and that must not be mistaken for being level.
	waitFor(t, "the watermark to be reported", func() bool {
		_, _, lastErr := ts.shipper.Probe()
		return strings.Contains(lastErr, "ahead of the audit log")
	})
	_, _, lastErr := ts.shipper.Probe()
	if !strings.Contains(lastErr, "9") || !strings.Contains(lastErr, "3") {
		t.Errorf("the health report says %q, want both the watermark 9 and the head 3", lastErr)
	}

	logged := ts.logs.String()
	if !strings.Contains(logged, "level=ERROR") || !strings.Contains(logged, "watermark is ahead of the audit log") {
		t.Error("a watermark ahead of the log was not logged at error level")
	}
	if !strings.Contains(logged, "delivered_through_seq=9") || !strings.Contains(logged, "head_seq=3") {
		t.Error("the log line does not carry both sequence numbers")
	}

	// An entry written afterwards is below the watermark. It used to be dropped
	// as a duplicate with the sink reporting itself healthy.
	ts.shipper.Offer(lg.append(t, audit.EventAssertionCompleted))
	waitFor(t, "an alert to be raised", func() bool { return ts.alerts.count() > 0 })
	if _, _, lastErr = ts.shipper.Probe(); lastErr == "" {
		t.Error("the failure cleared although the watermark is still ahead of the log")
	}
	if n := rec.requestCount(); n != 0 {
		t.Errorf("the receiver was sent %d requests from a watermark that cannot be trusted", n)
	}

	// Rewriting the file to match the log would hide that it had been changed.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the watermark back: %v", err)
	}
	var f watermarkFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode the watermark: %v", err)
	}
	if f.DeliveredThroughSeq != 9 {
		t.Errorf("the watermark file now says %d, want it left at 9", f.DeliveredThroughSeq)
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
