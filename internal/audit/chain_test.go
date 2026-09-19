package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// fixedTime carries nanoseconds on purpose, so the truncation in Prepare has
// something to remove.
var fixedTime = time.Date(2026, 3, 14, 9, 26, 53, 123456789, time.UTC)

func sampleEntry() *store.AuditEntry {
	return &store.AuditEntry{
		TenantID:     "tenant-a",
		OccurredAt:   fixedTime,
		EventType:    EventCredentialRevoked,
		ActorType:    store.ActorAdmin,
		ActorID:      "admin-1",
		SubjectID:    "subject-1",
		ResourceType: "credential",
		ResourceID:   "cred-1",
		Outcome:      store.OutcomeSuccess,
		SourceIP:     "192.0.2.10",
		RequestID:    "req-1",
		Detail:       json.RawMessage(`{"reason":"lost device"}`),
	}
}

func clone(e *store.AuditEntry) *store.AuditEntry {
	c := *e
	c.Detail = bytes.Clone(e.Detail)
	c.PIISalt = bytes.Clone(e.PIISalt)
	c.PIIDigest = bytes.Clone(e.PIIDigest)
	c.PrevHash = bytes.Clone(e.PrevHash)
	c.EntryHash = bytes.Clone(e.EntryHash)
	return &c
}

func mustPrepare(t *testing.T, e *store.AuditEntry, seq int64, prev []byte) *store.AuditEntry {
	t.Helper()
	if err := Prepare(e, seq, prev); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return e
}

func buildChain(t *testing.T, n int) []*store.AuditEntry {
	t.Helper()
	out := make([]*store.AuditEntry, 0, n)
	prev := Genesis()
	for i := 1; i <= n; i++ {
		e := sampleEntry()
		e.OccurredAt = fixedTime.Add(time.Duration(i) * time.Second)
		mustPrepare(t, e, int64(i), prev)
		out = append(out, e)
		prev = e.EntryHash
	}
	return out
}

func TestGenesis(t *testing.T) {
	g := Genesis()

	if len(g) != HashSize {
		t.Fatalf("genesis is %d bytes, want %d: a first entry could never satisfy the length check in VerifyEntry", len(g), HashSize)
	}
	if !bytes.Equal(g, Genesis()) {
		t.Error("genesis differs between calls: an intact log would fail verification from its first entry")
	}
	if bytes.Equal(g, make([]byte, HashSize)) {
		t.Error("genesis is all zeroes: a log truncated to nothing would present as a valid empty chain")
	}

	// The returned slice is handed to callers who store it on entries. If it
	// aliased shared state, one caller could corrupt the anchor for the rest.
	g[0] ^= 0xff
	if bytes.Equal(g, Genesis()) {
		t.Error("mutating a returned genesis value changed later ones: the chain anchor must not be shared mutable state")
	}
}

func TestPrepare(t *testing.T) {
	t.Run("fills chain fields", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 7, Genesis())

		if e.Seq != 7 {
			t.Errorf("seq = %d, want 7", e.Seq)
		}
		if len(e.PIISalt) != SaltSize {
			t.Errorf("salt is %d bytes, want %d: without a full salt a source address is recoverable from its digest by exhaustive search", len(e.PIISalt), SaltSize)
		}
		if bytes.Equal(e.PIISalt, make([]byte, SaltSize)) {
			t.Error("salt is all zeroes: the digest of the personal fields would be unsalted in effect")
		}
		if !bytes.Equal(e.PrevHash, Genesis()) {
			t.Error("prev hash was not recorded: the entry does not commit to its predecessor")
		}
		if !bytes.Equal(e.PIIDigest, PIIDigest(e)) {
			t.Error("stored digest does not match the personal fields: alteration of the subject reference would go unnoticed")
		}
		if !bytes.Equal(e.EntryHash, ComputeHash(e, Genesis())) {
			t.Error("stored entry hash does not match the recomputed one")
		}
	})

	t.Run("truncates the timestamp to microseconds", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())

		want := fixedTime.Truncate(time.Microsecond)
		if !e.OccurredAt.Equal(want) {
			t.Errorf("occurred_at = %v, want %v", e.OccurredAt, want)
		}
		if e.OccurredAt.Nanosecond()%1000 != 0 {
			t.Error("sub-microsecond precision survived: PostgreSQL cannot store it, so the entry would fail verification once read back")
		}

		// What a TIMESTAMPTZ column returns is the microsecond value. The hash
		// must be reproducible from that alone.
		stored := clone(e)
		stored.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)
		if !VerifyEntry(stored, Genesis()) {
			t.Error("an entry re-read at microsecond precision no longer verifies")
		}
	})

	t.Run("normalises the zone before hashing", func(t *testing.T) {
		paris := time.FixedZone("CET", 3600)
		a := sampleEntry()
		b := sampleEntry()
		b.OccurredAt = fixedTime.In(paris)
		salt := bytes.Repeat([]byte{0x5a}, SaltSize)
		a.PIISalt, b.PIISalt = salt, bytes.Clone(salt)

		mustPrepare(t, a, 1, Genesis())
		mustPrepare(t, b, 1, Genesis())
		if !bytes.Equal(a.EntryHash, b.EntryHash) {
			t.Error("the same instant hashed differently in two zones: verification would depend on the server's TZ setting")
		}
	})

	t.Run("keeps a salt supplied by the caller", func(t *testing.T) {
		salt := bytes.Repeat([]byte{0x11}, SaltSize)
		e := sampleEntry()
		e.PIISalt = bytes.Clone(salt)
		mustPrepare(t, e, 1, Genesis())
		if !bytes.Equal(e.PIISalt, salt) {
			t.Error("a caller-supplied salt was replaced")
		}
	})

	t.Run("draws a distinct salt per entry", func(t *testing.T) {
		a := mustPrepare(t, sampleEntry(), 1, Genesis())
		b := mustPrepare(t, sampleEntry(), 1, Genesis())
		if bytes.Equal(a.PIISalt, b.PIISalt) {
			t.Error("two entries share a salt: identical personal fields would produce identical digests and become linkable after erasure")
		}
		if bytes.Equal(a.PIIDigest, b.PIIDigest) {
			t.Error("identical personal fields produced identical digests across entries")
		}
	})
}

func TestComputeHashCoversEveryField(t *testing.T) {
	base := mustPrepare(t, sampleEntry(), 3, Genesis())
	baseHash := ComputeHash(base, base.PrevHash)

	otherPrev := bytes.Repeat([]byte{0xab}, HashSize)

	tests := []struct {
		name   string
		mutate func(e *store.AuditEntry)
		prev   []byte
	}{
		{"seq", func(e *store.AuditEntry) { e.Seq++ }, nil},
		{"tenant", func(e *store.AuditEntry) { e.TenantID = "tenant-b" }, nil},
		// One microsecond is the smallest step the column can represent.
		{"time", func(e *store.AuditEntry) { e.OccurredAt = e.OccurredAt.Add(time.Microsecond) }, nil},
		{"event type", func(e *store.AuditEntry) { e.EventType = EventCredentialLabelled }, nil},
		{"actor type", func(e *store.AuditEntry) { e.ActorType = store.ActorSystem }, nil},
		{"actor id", func(e *store.AuditEntry) { e.ActorID = "admin-2" }, nil},
		{"resource type", func(e *store.AuditEntry) { e.ResourceType = "totp_secret" }, nil},
		{"resource id", func(e *store.AuditEntry) { e.ResourceID = "cred-2" }, nil},
		// Rewriting a denial as a success is the alteration an intruder most
		// wants to make.
		{"outcome", func(e *store.AuditEntry) { e.Outcome = store.OutcomeDenied }, nil},
		{"request id", func(e *store.AuditEntry) { e.RequestID = "req-2" }, nil},
		{"pii digest", func(e *store.AuditEntry) { e.PIIDigest[0] ^= 0x01 }, nil},
		{"prev hash", func(*store.AuditEntry) {}, otherPrev},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := clone(base)
			tc.mutate(e)
			prev := base.PrevHash
			if tc.prev != nil {
				prev = tc.prev
			}
			if bytes.Equal(ComputeHash(e, prev), baseHash) {
				t.Errorf("changing %s left the chain hash unchanged: that field could be altered without detection", tc.name)
			}
		})
	}

	t.Run("unchanged entry is stable", func(t *testing.T) {
		if !bytes.Equal(ComputeHash(clone(base), base.PrevHash), baseHash) {
			t.Error("the same entry hashed differently twice: an intact log would report as broken")
		}
	})
}

func TestComputeHashFieldBoundaries(t *testing.T) {
	// Each pair concatenates to the same bytes across two adjacent fields. If
	// the fields were not length-prefixed the pair would collide, and an
	// attacker could substitute one entry for the other.
	tests := []struct {
		name string
		a, b func(e *store.AuditEntry)
	}{
		{
			"event type and actor type",
			func(e *store.AuditEntry) { e.EventType, e.ActorType = "a.b", "" },
			func(e *store.AuditEntry) { e.EventType, e.ActorType = "a", ".b" },
		},
		{
			"event type and actor id with an empty actor type",
			func(e *store.AuditEntry) { e.EventType, e.ActorType, e.ActorID = "a.b", "", "" },
			func(e *store.AuditEntry) { e.EventType, e.ActorType, e.ActorID = "a", "", ".b" },
		},
		{
			"actor type and actor id",
			func(e *store.AuditEntry) { e.ActorType, e.ActorID = "admin", "1" },
			func(e *store.AuditEntry) { e.ActorType, e.ActorID = "admin1", "" },
		},
		{
			"resource type and resource id",
			func(e *store.AuditEntry) { e.ResourceType, e.ResourceID = "credential", "x" },
			func(e *store.AuditEntry) { e.ResourceType, e.ResourceID = "credentia", "lx" },
		},
		{
			"outcome and request id",
			func(e *store.AuditEntry) { e.Outcome, e.RequestID = "denied", "r" },
			func(e *store.AuditEntry) { e.Outcome, e.RequestID = "denie", "dr" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := mustPrepare(t, sampleEntry(), 1, Genesis())
			a, b := clone(base), clone(base)
			tc.a(a)
			tc.b(b)
			if bytes.Equal(ComputeHash(a, Genesis()), ComputeHash(b, Genesis())) {
				t.Error("two different entries share a chain hash: field boundaries are ambiguous, so one entry can be substituted for another")
			}
		})
	}
}

func TestPIIDigest(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, SaltSize)
	base := sampleEntry()
	base.PIISalt = salt
	baseDigest := PIIDigest(base)

	if len(baseDigest) != HashSize {
		t.Fatalf("digest is %d bytes, want %d", len(baseDigest), HashSize)
	}

	tests := []struct {
		name   string
		mutate func(e *store.AuditEntry)
	}{
		{"subject", func(e *store.AuditEntry) { e.SubjectID = "subject-2" }},
		{"source ip", func(e *store.AuditEntry) { e.SourceIP = "192.0.2.11" }},
		{"detail", func(e *store.AuditEntry) { e.Detail = json.RawMessage(`{"reason":"other"}`) }},
		{"salt", func(e *store.AuditEntry) { e.PIISalt = bytes.Repeat([]byte{0x43}, SaltSize) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := clone(base)
			tc.mutate(e)
			if bytes.Equal(PIIDigest(e), baseDigest) {
				t.Errorf("changing %s left the digest unchanged: the chain would not notice that personal field being rewritten", tc.name)
			}
		})
	}

	t.Run("fields outside the digest do not affect it", func(t *testing.T) {
		// These are covered by ComputeHash directly. If they leaked into the
		// digest too, nothing would break, but the split would no longer be
		// what the package comment says it is.
		e := clone(base)
		e.EventType = "other"
		e.ActorID = "other"
		if !bytes.Equal(PIIDigest(e), baseDigest) {
			t.Error("a non-personal field changed the personal-field digest")
		}
	})

	t.Run("subject and source ip boundary", func(t *testing.T) {
		a, b := clone(base), clone(base)
		a.SubjectID, a.SourceIP = "ab", "c"
		b.SubjectID, b.SourceIP = "a", "bc"
		if bytes.Equal(PIIDigest(a), PIIDigest(b)) {
			t.Error("personal fields are not length-prefixed: two different subjects share a digest")
		}
	})

	t.Run("differs from the chain hash domain", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		if bytes.Equal(e.PIIDigest, e.EntryHash) {
			t.Error("digest and chain hash coincide: the domain separators are not doing their job")
		}
	})
}

func TestVerifyEntry(t *testing.T) {
	t.Run("accepts a prepared entry", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		if !VerifyEntry(e, Genesis()) {
			t.Error("a freshly prepared entry does not verify")
		}
	})

	tampering := []struct {
		name   string
		mutate func(e *store.AuditEntry)
	}{
		{"outcome rewritten", func(e *store.AuditEntry) { e.Outcome = store.OutcomeFailure }},
		{"actor rewritten", func(e *store.AuditEntry) { e.ActorID = "someone-else" }},
		{"subject rewritten", func(e *store.AuditEntry) { e.SubjectID = "subject-2" }},
		{"source ip rewritten", func(e *store.AuditEntry) { e.SourceIP = "198.51.100.1" }},
		{"detail rewritten", func(e *store.AuditEntry) { e.Detail = json.RawMessage(`{}`) }},
		{"salt rewritten", func(e *store.AuditEntry) { e.PIISalt[0] ^= 0x01 }},
		{"digest rewritten", func(e *store.AuditEntry) { e.PIIDigest[0] ^= 0x01 }},
		{"entry hash rewritten", func(e *store.AuditEntry) { e.EntryHash[0] ^= 0x01 }},
		{"entry hash truncated", func(e *store.AuditEntry) { e.EntryHash = e.EntryHash[:HashSize-1] }},
		{"entry hash missing", func(e *store.AuditEntry) { e.EntryHash = nil }},
		{"prev hash missing", func(e *store.AuditEntry) { e.PrevHash = nil }},
		{"digest missing", func(e *store.AuditEntry) { e.PIIDigest = nil }},
		{"seq renumbered", func(e *store.AuditEntry) { e.Seq++ }},
	}
	for _, tc := range tampering {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			e := mustPrepare(t, sampleEntry(), 1, Genesis())
			tc.mutate(e)
			if VerifyEntry(e, Genesis()) {
				t.Errorf("an entry with its %s still verifies: tampering would go undetected", tc.name)
			}
		})
	}

	t.Run("refuses a wrong prev hash", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		wrong := bytes.Repeat([]byte{0x01}, HashSize)
		if VerifyEntry(e, wrong) {
			t.Error("an entry verified against a predecessor it does not chain onto: a removed entry would go unnoticed")
		}
	})

	t.Run("refuses a consistently rewritten prev hash", func(t *testing.T) {
		// The attacker recomputes the stored hashes against a predecessor of
		// their choosing. The entry is internally consistent, and must still
		// be refused because the verifier knows the real predecessor.
		wrong := bytes.Repeat([]byte{0x01}, HashSize)
		e := mustPrepare(t, sampleEntry(), 1, wrong)
		if VerifyEntry(e, Genesis()) {
			t.Error("an entry chained onto a forged predecessor verified against the real one")
		}
	})
}

func TestErasure(t *testing.T) {
	t.Run("an erased entry still verifies", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		if Erased(e) {
			t.Fatal("a fresh entry reports as erased")
		}

		Erase(e)

		if e.SubjectID != "" || e.SourceIP != "" || e.Detail != nil {
			t.Error("personal fields survived erasure: the Article 17 request has not been honoured")
		}
		if e.PIISalt != nil {
			t.Error("the salt survived erasure: a low-entropy field such as the source address stays recoverable from the digest")
		}
		if !Erased(e) {
			t.Error("Erased is false after Erase")
		}
		if !VerifyEntry(e, Genesis()) {
			t.Error("erasing an entry broke the chain: erasure and tamper evidence cannot coexist")
		}
	})

	t.Run("the digest of an erased entry is still covered", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		Erase(e)
		e.PIIDigest[0] ^= 0x01
		if VerifyEntry(e, Genesis()) {
			t.Error("the stored digest of an erased entry was altered and the entry still verifies")
		}
	})

	t.Run("the non-personal fields of an erased entry are still covered", func(t *testing.T) {
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		Erase(e)
		e.Outcome = store.OutcomeFailure
		if VerifyEntry(e, Genesis()) {
			t.Error("erasure removed tamper evidence from fields it was never meant to touch")
		}
	})

	t.Run("an erased entry read back with the empty document still verifies", func(t *testing.T) {
		// Both stores write "{}" into the detail column of an erased row, since
		// the column does not take NULL.
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		Erase(e)
		e.Detail = json.RawMessage(`{}`)
		if !VerifyEntry(e, Genesis()) {
			t.Error("the form erasure leaves in the database does not verify")
		}
	})

	refilled := []struct {
		name   string
		mutate func(e *store.AuditEntry)
	}{
		{"subject", func(e *store.AuditEntry) { e.SubjectID = "subject-2" }},
		{"source ip", func(e *store.AuditEntry) { e.SourceIP = "198.51.100.1" }},
		{"detail", func(e *store.AuditEntry) { e.Detail = json.RawMessage(`{"reason":"planted"}`) }},
		{"null detail", func(e *store.AuditEntry) { e.Detail = json.RawMessage(`null`) }},
	}
	for _, tc := range refilled {
		t.Run("refuses an entry with no salt and a "+tc.name, func(t *testing.T) {
			// Nothing covers the personal fields once the salt is gone, so the
			// only safe reading of a missing salt is that they are gone too.
			// Otherwise nulling the salt would be a way to pin an entry on
			// somebody else without breaking the chain.
			e := mustPrepare(t, sampleEntry(), 1, Genesis())
			Erase(e)
			tc.mutate(e)
			if VerifyEntry(e, Genesis()) {
				t.Errorf("an entry with no salt and a %s still verifies: the field is covered by nothing", tc.name)
			}
		})
	}

	t.Run("refuses a salt of the wrong length", func(t *testing.T) {
		// A salt is sixteen bytes or absent. Five bytes would skip the digest
		// check without the entry counting as erased.
		e := mustPrepare(t, sampleEntry(), 1, Genesis())
		e.PIISalt = e.PIISalt[:5]
		if VerifyEntry(e, Genesis()) {
			t.Error("an entry with a five byte salt still verifies: its personal fields were checked against nothing")
		}
	})

	t.Run("erasure in the middle of a chain keeps the whole chain valid", func(t *testing.T) {
		chain := buildChain(t, 5)
		Erase(chain[2])
		if got := VerifySequence(chain, Genesis()); got != 0 {
			t.Errorf("chain reports broken at seq %d after a lawful erasure", got)
		}
	})
}

func TestVerifySequence(t *testing.T) {
	t.Run("intact chain", func(t *testing.T) {
		if got := VerifySequence(buildChain(t, 5), Genesis()); got != 0 {
			t.Errorf("intact chain reports broken at seq %d", got)
		}
	})

	t.Run("empty run", func(t *testing.T) {
		if got := VerifySequence(nil, Genesis()); got != 0 {
			t.Errorf("empty run reports broken at seq %d", got)
		}
	})

	t.Run("resumes from a stored hash", func(t *testing.T) {
		// This is how verification continues after a prune checkpoint.
		chain := buildChain(t, 5)
		if got := VerifySequence(chain[2:], chain[1].EntryHash); got != 0 {
			t.Errorf("a suffix verified against its true predecessor reports broken at seq %d", got)
		}
		if got := VerifySequence(chain[2:], Genesis()); got != 3 {
			t.Errorf("a suffix verified against the wrong anchor reports %d, want 3", got)
		}
	})

	for pos := 0; pos < 5; pos++ {
		seq := int64(pos + 1)

		t.Run(fmt.Sprintf("content tamper at seq %d", seq), func(t *testing.T) {
			chain := buildChain(t, 5)
			chain[pos].Outcome = store.OutcomeDenied
			if got := VerifySequence(chain, Genesis()); got != seq {
				t.Errorf("tamper at seq %d reported at %d: an investigator would be pointed at the wrong entry", seq, got)
			}
		})

		t.Run(fmt.Sprintf("consistent rewrite of seq %d", seq), func(t *testing.T) {
			// The attacker fixes up the tampered entry's own hash. The break
			// then moves to the successor, whose PrevHash no longer matches.
			// For the last entry there is no successor, which is the known
			// limit of a chain without an external witness.
			chain := buildChain(t, 5)
			chain[pos].Outcome = store.OutcomeDenied
			chain[pos].EntryHash = ComputeHash(chain[pos], chain[pos].PrevHash)

			want := seq + 1
			if pos == 4 {
				want = 0
			}
			if got := VerifySequence(chain, Genesis()); got != want {
				t.Errorf("rewrite of seq %d reported at %d, want %d", seq, got, want)
			}
		})

		t.Run(fmt.Sprintf("removal of seq %d", seq), func(t *testing.T) {
			chain := buildChain(t, 5)
			removed := append(append([]*store.AuditEntry{}, chain[:pos]...), chain[pos+1:]...)

			// Removing the tail leaves a valid shorter chain; detecting that
			// needs the head recorded elsewhere.
			var want int64
			if pos < 4 {
				want = chain[pos+1].Seq
			}
			if got := VerifySequence(removed, Genesis()); got != want {
				t.Errorf("removal of seq %d reported at %d, want %d: selective deletion must surface at the entry after the gap", seq, got, want)
			}
		})
	}

	t.Run("reordering", func(t *testing.T) {
		chain := buildChain(t, 5)
		chain[1], chain[2] = chain[2], chain[1]
		if got := VerifySequence(chain, Genesis()); got != 3 {
			t.Errorf("swapped entries reported at %d, want 3 (the first entry out of place)", got)
		}
	})
}

// fakeAuditStore embeds the interface so only Append needs a body. Any other
// method would panic on the nil embedded value, which is the desired outcome
// if Record ever starts calling something unexpected.
type fakeAuditStore struct {
	store.AuditStore
	appended []*store.AuditEntry
	err      error
}

func (f *fakeAuditStore) Append(_ context.Context, e *store.AuditEntry) (*store.AuditEntry, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.appended = append(f.appended, e)
	return e, nil
}

func newTestRecorder(s store.AuditStore, logs io.Writer) *Recorder {
	r := NewRecorder(s, slog.New(slog.NewJSONHandler(logs, nil)))
	r.now = func() time.Time { return fixedTime }
	return r
}

func TestRecorderRecord(t *testing.T) {
	t.Run("fills the entry and passes it on", func(t *testing.T) {
		fs := &fakeAuditStore{}
		r := newTestRecorder(fs, io.Discard)

		err := r.Record(context.Background(), Event{
			TenantID:     "tenant-a",
			EventType:    EventAssertionRejected,
			ActorType:    store.ActorSubject,
			ActorID:      "actor-1",
			SubjectID:    "subject-1",
			ResourceType: "credential",
			ResourceID:   "cred-1",
			Outcome:      store.OutcomeFailure,
			SourceIP:     "192.0.2.10",
			RequestID:    "req-1",
			Detail:       map[string]any{"reason": "bad signature"},
		})
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if len(fs.appended) != 1 {
			t.Fatalf("store received %d entries, want 1", len(fs.appended))
		}

		got := fs.appended[0]
		want := store.AuditEntry{
			TenantID:     "tenant-a",
			OccurredAt:   fixedTime,
			EventType:    EventAssertionRejected,
			ActorType:    store.ActorSubject,
			ActorID:      "actor-1",
			SubjectID:    "subject-1",
			ResourceType: "credential",
			ResourceID:   "cred-1",
			Outcome:      store.OutcomeFailure,
			SourceIP:     "192.0.2.10",
			RequestID:    "req-1",
		}
		gotDetail := got.Detail
		cmp := *got
		cmp.Detail = nil
		if !entriesEqual(&cmp, &want) {
			t.Errorf("entry handed to the store = %+v, want %+v: a field dropped here never reaches the audit log", cmp, want)
		}
		if string(gotDetail) != `{"reason":"bad signature"}` {
			t.Errorf("detail = %s", gotDetail)
		}

		// The chain fields belong to the store, which computes them inside
		// the transaction that reads the head.
		if got.Seq != 0 || got.PrevHash != nil || got.EntryHash != nil || got.PIISalt != nil {
			t.Error("the recorder filled chain fields itself: two concurrent appends could chain onto the same predecessor")
		}
	})

	t.Run("empty detail stays absent", func(t *testing.T) {
		fs := &fakeAuditStore{}
		r := newTestRecorder(fs, io.Discard)
		if err := r.Record(context.Background(), Event{EventType: EventSubjectCreated}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if fs.appended[0].Detail != nil {
			t.Errorf("detail = %q, want none", fs.appended[0].Detail)
		}
	})

	t.Run("unserialisable detail still records the event", func(t *testing.T) {
		fs := &fakeAuditStore{}
		var logs bytes.Buffer
		r := newTestRecorder(fs, &logs)

		err := r.Record(context.Background(), Event{
			EventType: EventCredentialRevoked,
			Outcome:   store.OutcomeSuccess,
			Detail:    map[string]any{"ch": make(chan int)},
		})
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if len(fs.appended) != 1 {
			t.Fatal("the event was dropped because its detail could not be serialised: losing context is acceptable, losing the event is not")
		}
		got := fs.appended[0]
		if string(got.Detail) != `{"detail_error":"not serialisable"}` {
			t.Errorf("detail = %s, want the placeholder", got.Detail)
		}
		if !json.Valid(got.Detail) {
			t.Error("the placeholder is not valid JSON and would be refused by a JSONB column")
		}
		if got.EventType != EventCredentialRevoked || got.Outcome != store.OutcomeSuccess {
			t.Error("the rest of the entry was disturbed by the detail failure")
		}
		if !bytes.Contains(logs.Bytes(), []byte("audit detail could not be serialised")) {
			t.Error("the serialisation failure was not logged, so nobody would learn the detail was lost")
		}
	})

	t.Run("store error is returned wrapped and logged", func(t *testing.T) {
		sentinel := errors.New("disk full")
		fs := &fakeAuditStore{err: sentinel}
		var logs bytes.Buffer
		r := newTestRecorder(fs, &logs)

		err := r.Record(context.Background(), Event{EventType: EventCredentialRevoked})
		if err == nil {
			t.Fatal("a failed append returned nil: the caller would commit a change that has no audit entry")
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("error %q does not wrap the store error", err)
		}
		if !bytes.Contains([]byte(err.Error()), []byte(EventCredentialRevoked)) {
			t.Errorf("error %q does not name the event type", err)
		}
		if !bytes.Contains(logs.Bytes(), []byte("audit append failed")) {
			t.Error("a failed append was not logged: an audit log silently dropping entries is itself an incident")
		}
	})
}

func TestRecorderOutcomeHelpers(t *testing.T) {
	tests := []struct {
		name string
		call func(*Recorder, context.Context, Event) error
		want store.Outcome
	}{
		{"Success", (*Recorder).Success, store.OutcomeSuccess},
		{"Failure", (*Recorder).Failure, store.OutcomeFailure},
		{"Denied", (*Recorder).Denied, store.OutcomeDenied},
		{"Errored", (*Recorder).Errored, store.OutcomeError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeAuditStore{}
			r := newTestRecorder(fs, io.Discard)
			// A caller-supplied outcome must not survive: Denied recording a
			// success would invert the meaning of the entry.
			if err := tc.call(r, context.Background(), Event{EventType: "x", Outcome: "bogus"}); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got := fs.appended[0].Outcome; got != tc.want {
				t.Errorf("%s recorded outcome %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func entriesEqual(a, b *store.AuditEntry) bool {
	return a.Seq == b.Seq &&
		a.TenantID == b.TenantID &&
		a.OccurredAt.Equal(b.OccurredAt) &&
		a.EventType == b.EventType &&
		a.ActorType == b.ActorType &&
		a.ActorID == b.ActorID &&
		a.SubjectID == b.SubjectID &&
		a.ResourceType == b.ResourceType &&
		a.ResourceID == b.ResourceID &&
		a.Outcome == b.Outcome &&
		a.SourceIP == b.SourceIP &&
		a.RequestID == b.RequestID &&
		bytes.Equal(a.Detail, b.Detail)
}
