package auditsink

import (
	"bytes"
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
)

// Format names the payload version, and travels in every batch.
//
// A receiver that stores what it is given needs to know when the shape changes,
// and a version in the document is the only place it can find out without being
// told out of band. It is a string rather than a number so that a fork can pick
// its own without colliding.
const Format = "n0passtemps.audit.v1"

// The two bodies a receiver is sent, named in the kind field.
//
// A batch carries entries. A heartbeat carries the head of the chain and no
// entries, and is what says the path to the receiver is still open while there
// is nothing to deliver. A receiver has to be able to tell them apart without
// inspecting the payload, because storing a heartbeat as though it were a batch
// would file an empty delivery, and reading a batch as a heartbeat would drop
// entries.
const (
	KindBatch     = "batch"
	KindHeartbeat = "heartbeat"
)

// Record is the part of an audit entry that is delivered to the sink.
//
// It is exactly the set of fields the chain hash commits to, and therefore
// exactly what a receiver needs in order to recompute the hashes and verify
// the chain for itself. That is not a coincidence and it is the whole design:
// the projection cannot be narrowed without making the copy unverifiable, and
// it does not need to be widened, because nothing else takes part in the proof.
//
// # What is deliberately not here
//
// The three personal fields of an entry, SubjectID, SourceIP and Detail, are
// absent. The chain does not commit to them directly either: it commits to
// PIIDigest, a salted digest of all three, which is what lets an entry be
// erased without breaking verification. So the receiver gets the commitment and
// never the data, and the external copy cannot widen what a deployment exposes.
// See internal/audit/chain.go and docs/GDPR.md.
//
// Detail is the field that would otherwise be the leak. It is written by every
// handler and carries counts, reasons, identifiers, revocation reasons and risk
// signals; its shape is not modelled anywhere and nothing bounds what a future
// caller might put in it. Shipping it would mean the sink's exposure grew every
// time somebody added a key to a detail map, which is not a property anyone can
// review. It is bounded here by being excluded, not by being filtered.
//
// PIISalt is absent for a sharper reason. The digest is irreversible only while
// the salt is secret: a source address carries about thirty-two bits of
// entropy, so a receiver holding both the salt and the digest could recover the
// address by exhaustive search in seconds. The salt never leaves the database.
//
// # The hashes
//
// PrevHash and EntryHash are base64 encoded in JSON, because that is how the
// same two fields are rendered by GET /admin/v1/audit. An operator comparing
// what the witness holds against what the database says is then comparing two
// strings rather than converting between encodings.
type Record struct {
	Seq          int64     `json:"seq"`
	TenantID     string    `json:"tenant_id"`
	OccurredAt   time.Time `json:"occurred_at"`
	EventType    string    `json:"event_type"`
	ActorType    string    `json:"actor_type"`
	ActorID      string    `json:"actor_id,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Outcome      string    `json:"outcome"`
	RequestID    string    `json:"request_id,omitempty"`

	// PIIDigest is the salted commitment to the personal fields. It takes part
	// in the chain hash, so a receiver cannot verify without it, and it reveals
	// nothing without the salt, which is never sent.
	PIIDigest []byte `json:"pii_digest"`

	PrevHash  []byte `json:"prev_hash"`
	EntryHash []byte `json:"entry_hash"`
}

// Batch is one POST body.
//
// FromSeq and ToSeq are the range the batch claims to cover. They are stated
// rather than left to be derived, so that a receiver can reject a truncated
// body instead of storing it as though it were complete.
type Batch struct {
	Format string `json:"format"`

	// Kind is KindBatch, and says this body carries entries. See the constant.
	Kind string `json:"kind"`

	// Source labels the deployment, so a receiver collecting from several can
	// keep them apart in storage. It is not evidence of anything: the bearer
	// credential the receiver issued is what identifies the sender, and this
	// field is whatever the sender's configured tenant identifier says.
	Source string `json:"source"`

	SentAt  time.Time `json:"sent_at"`
	FromSeq int64     `json:"from_seq"`
	ToSeq   int64     `json:"to_seq"`
	Count   int       `json:"count"`
	Entries []Record  `json:"entries"`
}

// Heartbeat is the body sent when there is nothing to deliver.
//
// Without it, a receiver cannot tell a deployment where nothing happened from
// one whose outbound path has been cut, and those are the two ends of the same
// attack: stop the deliveries, act, remove the tail of the local log, let the
// deliveries resume. Silence is the only thing the receiver sees in both cases,
// so silence has to mean something. A receiver that is told to expect a body at
// least every few minutes can raise the absence itself.
//
// It carries the head of the chain rather than a bare liveness ping, because
// the head is what makes the absence actionable afterwards: a receiver holding
// (seq, entry_hash) pairs over time can say that the log it is now offered does
// not continue the one it was told about, which is the rewrite the external
// witness exists to catch. DeliveredThroughSeq comes along so the receiver can
// see how far behind delivery is by the sender's own reckoning, and compare it
// with what it holds.
//
// A heartbeat never moves the delivery watermark. It acknowledges nothing and
// carries no entry, so treating it as progress would skip the entries between.
type Heartbeat struct {
	Format string `json:"format"`

	// Kind is KindHeartbeat. See the constant.
	Kind string `json:"kind"`

	Source string    `json:"source"`
	SentAt time.Time `json:"sent_at"`

	// HeadSeq and HeadHash are the newest entry of the local chain at the
	// moment the heartbeat was built, or the genesis value when the log is
	// empty.
	HeadSeq  int64  `json:"head_seq"`
	HeadHash []byte `json:"head_hash"`

	// DeliveredThroughSeq is the last sequence number this sender believes the
	// receiver acknowledged.
	DeliveredThroughSeq int64 `json:"delivered_through_seq"`
}

// Project reduces an entry to what is delivered.
//
// It reads the entry and copies; it never writes to it, because the caller is
// the recorder and the entry it holds has just been handed back by the store.
func Project(e *store.AuditEntry) Record {
	return Record{
		Seq:          e.Seq,
		TenantID:     e.TenantID,
		OccurredAt:   e.OccurredAt.UTC(),
		EventType:    e.EventType,
		ActorType:    string(e.ActorType),
		ActorID:      e.ActorID,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Outcome:      string(e.Outcome),
		RequestID:    e.RequestID,
		// The hashes are copied rather than aliased. The recorder hands the
		// shipper the pointer the store returned and the shipper hands it to a
		// goroutine, so sharing the backing arrays would make a later change to
		// the entry visible inside a batch that is already queued.
		PIIDigest: bytes.Clone(e.PIIDigest),
		PrevHash:  bytes.Clone(e.PrevHash),
		EntryHash: bytes.Clone(e.EntryHash),
	}
}

// entry rebuilds the hash input from a record.
//
// The personal fields are left empty because they are not hash inputs: the
// chain covers PIIDigest instead, which the record carries. This is what makes
// a record verifiable on its own.
func (r Record) entry() *store.AuditEntry {
	return &store.AuditEntry{
		Seq:          r.Seq,
		TenantID:     r.TenantID,
		OccurredAt:   r.OccurredAt,
		EventType:    r.EventType,
		ActorType:    store.ActorType(r.ActorType),
		ActorID:      r.ActorID,
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		Outcome:      store.Outcome(r.Outcome),
		RequestID:    r.RequestID,
		PIIDigest:    r.PIIDigest,
		PrevHash:     r.PrevHash,
		EntryHash:    r.EntryHash,
	}
}

// CheckSequence verifies a run of delivered records and reports the first place
// the run is not what it claims to be.
//
// It is the receiver's side of the contract, kept here so that it is written
// once, tested, and can be quoted in the documentation rather than described.
// A receiver in another language implements the same three checks.
//
// prevHash is the hash the run is expected to chain onto: audit.Genesis() at
// the start of a deployment's history, or the EntryHash of the record
// immediately before records[0].
//
// What makes a run whole is the chaining, not the numbering. Each record's
// PrevHash must equal the EntryHash of the record before it, which is what
// catches an entry removed from the middle, a substitution that kept the
// numbering intact, and a run that does not continue the history the receiver
// already holds. Each EntryHash must in turn be the hash of the record's own
// fields, which catches an edited record whose links were left alone.
//
// The sequence numbers are only required to increase. They are not required to
// be consecutive, and a receiver that requires it will report tampering on an
// ordinary PostgreSQL deployment: seq is drawn from a sequence, which hands out
// a value outside the transaction, so an append whose transaction is rolled
// back, by a cancelled request or a failed insert, spends a number that no
// entry will ever carry. The gap is the engine's, the entries on either side of
// it chain onto each other, and nothing has been lost. On SQLite the numbers do
// come out consecutive, and checking for that here would have made the two
// engines disagree about what a valid log looks like.
//
// So 41, 42 and 44 is no longer reported by itself. If 43 existed and was
// removed, 44 does not chain onto 42 and the break is reported at 44 as before;
// if 43 was never written, 44 chains onto 42 and there is nothing to report. A
// number that repeats or goes backwards is neither of those and is reported,
// because the local chain never produces one.
//
// Delivery is at least once, so a receiver may legitimately be offered a
// sequence number it already holds. That is a duplicate, not a gap, and is
// filtered before this is called. A second copy of a sequence number that does
// not match the first is neither: it is evidence that one of them was written
// by something other than the deployment's chain.
func CheckSequence(records []Record, prevHash []byte) (brokenAt int64) {
	cur := prevHash
	last := int64(0)

	for i, r := range records {
		if i > 0 && r.Seq <= last {
			return r.Seq
		}
		if !audit.VerifyEntry(r.entry(), cur) {
			return r.Seq
		}
		cur = r.EntryHash
		last = r.Seq
	}
	return 0
}

// Verify reports whether a batch is internally consistent before its records
// are checked against what a receiver already holds.
//
// It exists because the declared range is the only way to notice a body that
// arrived incomplete, and a receiver that skips this check would store a short
// batch and then report the gap as tampering by the sender.
func (b Batch) Verify() error {
	if b.Format != Format {
		return fmt.Errorf("%w: format %q is not %q", ErrMalformedBatch, b.Format, Format)
	}
	// An empty kind is accepted because a body carrying entries was a batch
	// before the field existed. Any other value is refused rather than
	// interpreted: a heartbeat read as a batch would be stored as a delivery
	// that acknowledged nothing.
	if b.Kind != "" && b.Kind != KindBatch {
		return fmt.Errorf("%w: kind %q is not %q", ErrMalformedBatch, b.Kind, KindBatch)
	}
	if b.Count != len(b.Entries) {
		return fmt.Errorf("%w: count says %d and the body carries %d entries",
			ErrMalformedBatch, b.Count, len(b.Entries))
	}
	if len(b.Entries) == 0 {
		return fmt.Errorf("%w: no entries", ErrMalformedBatch)
	}
	if b.Entries[0].Seq != b.FromSeq || b.Entries[len(b.Entries)-1].Seq != b.ToSeq {
		return fmt.Errorf("%w: declared range %d..%d does not match the entries %d..%d",
			ErrMalformedBatch, b.FromSeq, b.ToSeq,
			b.Entries[0].Seq, b.Entries[len(b.Entries)-1].Seq)
	}
	return nil
}

// Verify reports whether a heartbeat is the body it claims to be.
//
// The head hash is the one field worth checking here: a heartbeat with nothing
// in it says the sender is alive and says nothing about which chain it is
// alive on, and the head is the whole content of the message.
func (h Heartbeat) Verify() error {
	if h.Format != Format {
		return fmt.Errorf("%w: format %q is not %q", ErrMalformedBatch, h.Format, Format)
	}
	if h.Kind != KindHeartbeat {
		return fmt.Errorf("%w: kind %q is not %q", ErrMalformedBatch, h.Kind, KindHeartbeat)
	}
	if len(h.HeadHash) != audit.HashSize {
		return fmt.Errorf("%w: the head hash is %d bytes and not %d",
			ErrMalformedBatch, len(h.HeadHash), audit.HashSize)
	}
	return nil
}
