package auditsink

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Socold/n0passtemps/internal/audit"
)

func TestTheProjectionCarriesNoPersonalField(t *testing.T) {
	lg := &fakeLog{}
	entry := lg.append(t, audit.EventRecoveryConsumed)

	body, err := json.Marshal(Project(entry))
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	// The sink must not widen what a deployment exposes. The three personal
	// fields of an entry are committed to the chain through a salted digest, so
	// the digest is what travels and the fields themselves never leave.
	for _, key := range []string{"subject_id", "source_ip", "detail", "pii_salt"} {
		if bytes.Contains(body, []byte(`"`+key+`"`)) {
			t.Errorf("the delivered record carries a %q field", key)
		}
	}
	for _, value := range []string{entry.SubjectID, entry.SourceIP, "lost device"} {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Errorf("the delivered record carries the value %q", value)
		}
	}

	// And the salt is the sharper case: a source address has about thirty-two
	// bits of entropy, so a receiver holding both the salt and the digest could
	// recover the address by exhaustive search.
	if bytes.Contains(body, []byte(base64Of(entry.PIISalt))) {
		t.Error("the delivered record carries the per-entry salt")
	}
	if !bytes.Contains(body, []byte(base64Of(entry.PIIDigest))) {
		t.Error("the delivered record does not carry the digest, so it cannot be verified")
	}
}

func TestADeliveredRecordVerifiesOnItsOwn(t *testing.T) {
	lg := &fakeLog{}
	entries := lg.appendMany(t, 4)

	// A round trip through JSON, because that is what a receiver actually
	// holds: anything that did not survive the encoding is not available to it.
	var records []Record
	for _, e := range entries {
		records = append(records, roundTrip(t, Project(e)))
	}

	if broken := CheckSequence(records, audit.Genesis()); broken != 0 {
		t.Fatalf("an untouched run reports a break at %d", broken)
	}
}

func TestCheckSequenceDetectsAGap(t *testing.T) {
	lg := &fakeLog{}
	entries := lg.appendMany(t, 4)

	var records []Record
	for _, e := range entries {
		records = append(records, roundTrip(t, Project(e)))
	}

	t.Run("a missing entry surfaces at the entry after it", func(t *testing.T) {
		// The case from the specification: a receiver holding 1, 2 and 4 must
		// be able to tell. It surfaces twice over, in the numbering and in the
		// chain link, which is why no receiver has to be clever.
		withGap := []Record{records[0], records[1], records[3]}
		if got := CheckSequence(withGap, audit.Genesis()); got != records[3].Seq {
			t.Errorf("a gap before seq %d was reported at %d", records[3].Seq, got)
		}
	})

	t.Run("a substitution that keeps the numbering surfaces too", func(t *testing.T) {
		tampered := append([]Record(nil), records...)
		tampered[2].EventType = audit.EventAssertionRejected
		if got := CheckSequence(tampered, audit.Genesis()); got != tampered[2].Seq {
			t.Errorf("an edited record at seq %d was reported at %d", tampered[2].Seq, got)
		}
	})

	t.Run("an edited hash surfaces at the same entry", func(t *testing.T) {
		tampered := append([]Record(nil), records...)
		hash := bytes.Clone(tampered[1].EntryHash)
		hash[0] ^= 0xff
		tampered[1].EntryHash = hash
		if got := CheckSequence(tampered, audit.Genesis()); got != tampered[1].Seq {
			t.Errorf("an edited hash at seq %d was reported at %d", tampered[1].Seq, got)
		}
	})

	t.Run("a run that does not chain onto the expected head is refused", func(t *testing.T) {
		// This is what a witness does with a rewritten chain: the operator can
		// recompute every hash consistently, but not so that it reproduces the
		// head the witness already holds.
		wrong := bytes.Clone(audit.Genesis())
		wrong[0] ^= 0xff
		if got := CheckSequence(records, wrong); got != records[0].Seq {
			t.Errorf("a run chaining onto the wrong head was reported at %d, want %d", got, records[0].Seq)
		}
	})
}

// TestASkippedSequenceNumberIsNotAGap is the difference between the two
// engines, seen from the receiver.
//
// On PostgreSQL seq comes from a sequence, which hands a number out before the
// transaction commits and does not take it back when the transaction rolls
// back. An append cut short by a cancelled request therefore spends a number no
// entry will ever carry. A receiver requiring consecutive numbers reported that
// as tampering on every deployment that had ever had a failed insert, which is
// all of them.
func TestASkippedSequenceNumberIsNotAGap(t *testing.T) {
	lg := &fakeLog{}
	entries := lg.appendMany(t, 2)
	lg.skipSeq()
	entries = append(entries, lg.appendMany(t, 2)...)

	var records []Record
	for _, e := range entries {
		records = append(records, roundTrip(t, Project(e)))
	}
	if records[2].Seq != 4 {
		t.Fatalf("the entry after the skip has seq %d, want 4: the fixture must leave a hole in the numbering",
			records[2].Seq)
	}

	// The entries on either side of the skipped number chain onto each other,
	// so nothing is missing and there is nothing to report.
	if broken := CheckSequence(records, audit.Genesis()); broken != 0 {
		t.Errorf("a number the engine spent on a rolled back append was reported as a break at %d", broken)
	}

	t.Run("an entry removed from the middle is still reported", func(t *testing.T) {
		// The case the numbering could never tell from the one above, and the
		// reason the check is on the chain: seq 5 says which hash it follows,
		// and it is not the one seq 2 carries.
		withHole := []Record{records[0], records[1], records[3]}
		if got := CheckSequence(withHole, audit.Genesis()); got != records[3].Seq {
			t.Errorf("an entry taken out before seq %d was reported at %d", records[3].Seq, got)
		}
	})

	t.Run("a sequence number that goes backwards is reported", func(t *testing.T) {
		// Nothing the local chain produces repeats a number or lowers one, so a
		// run that does was assembled by something else.
		backwards := []Record{records[0], records[1], records[1]}
		if got := CheckSequence(backwards, audit.Genesis()); got != records[1].Seq {
			t.Errorf("a repeated sequence number was reported at %d, want %d", got, records[1].Seq)
		}
	})
}

func TestBatchVerify(t *testing.T) {
	lg := &fakeLog{}
	entries := lg.appendMany(t, 3)

	var records []Record
	for _, e := range entries {
		records = append(records, Project(e))
	}
	full := Batch{
		Format:  Format,
		Source:  testTenant,
		FromSeq: records[0].Seq,
		ToSeq:   records[len(records)-1].Seq,
		Count:   len(records),
		Entries: records,
	}

	if err := full.Verify(); err != nil {
		t.Fatalf("a complete batch was refused: %v", err)
	}

	t.Run("a truncated body is refused", func(t *testing.T) {
		// The declared range is the only way a receiver can notice a body that
		// arrived incomplete. Without the check it would store the short batch
		// and then report the gap as the sender's fault.
		short := full
		short.Entries = records[:2]
		if err := short.Verify(); !errors.Is(err, ErrMalformedBatch) {
			t.Errorf("a truncated batch gave %v, want ErrMalformedBatch", err)
		}
	})

	t.Run("an unknown format is refused", func(t *testing.T) {
		other := full
		other.Format = "something.else.v9"
		if err := other.Verify(); !errors.Is(err, ErrMalformedBatch) {
			t.Errorf("an unknown format gave %v, want ErrMalformedBatch", err)
		}
	})

	t.Run("an empty batch is refused", func(t *testing.T) {
		empty := Batch{Format: Format, Count: 0}
		if err := empty.Verify(); !errors.Is(err, ErrMalformedBatch) {
			t.Errorf("an empty batch gave %v, want ErrMalformedBatch", err)
		}
	})
}

func TestProjectDoesNotAliasTheEntry(t *testing.T) {
	lg := &fakeLog{}
	entry := lg.append(t, audit.EventAssertionCompleted)
	record := Project(entry)

	// The recorder hands the shipper the pointer the store returned, and the
	// shipper hands it to a goroutine. A record sharing the backing arrays
	// would change under the goroutine's feet.
	entry.EntryHash[0] ^= 0xff
	if record.EntryHash[0] == entry.EntryHash[0] {
		t.Error("the record aliases the entry's hash")
	}
}

func roundTrip(t *testing.T, r Record) Record {
	t.Helper()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	var out Record
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	return out
}

func recordsEqual(a, b Record) bool {
	return a.Seq == b.Seq &&
		a.TenantID == b.TenantID &&
		a.OccurredAt.Equal(b.OccurredAt) &&
		a.EventType == b.EventType &&
		a.ActorType == b.ActorType &&
		a.ActorID == b.ActorID &&
		a.ResourceType == b.ResourceType &&
		a.ResourceID == b.ResourceID &&
		a.Outcome == b.Outcome &&
		a.RequestID == b.RequestID &&
		bytes.Equal(a.PIIDigest, b.PIIDigest) &&
		bytes.Equal(a.PrevHash, b.PrevHash) &&
		bytes.Equal(a.EntryHash, b.EntryHash)
}

// base64Of renders bytes the way encoding/json does, so a test can look for a
// value in a marshalled record.
func base64Of(b []byte) string {
	out, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	return string(bytes.Trim(out, `"`))
}
