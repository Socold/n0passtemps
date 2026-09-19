package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// fakeKEK is a KEKProvider backed by a map of versions. It hands out copies,
// as the interface requires: Seal and Unseal zeroize the slice they receive,
// so a provider that returned its own storage would be wiped by the first
// call and every later test would run against an all-zero key.
type fakeKEK struct {
	keys    map[uint32][]byte
	current uint32
}

func (f *fakeKEK) Current() (version uint32, key []byte, err error) {
	k, ok := f.keys[f.current]
	if !ok {
		return 0, nil, fmt.Errorf("fake kek: current version %d absent", f.current)
	}
	return f.current, append([]byte(nil), k...), nil
}

func (f *fakeKEK) ByVersion(v uint32) ([]byte, error) {
	k, ok := f.keys[v]
	if !ok {
		return nil, fmt.Errorf("fake kek: version %d absent", v)
	}
	return append([]byte(nil), k...), nil
}

// sameKeyEveryVersion answers any version with one key. It removes the key
// lookup as a line of defence, so that a test altering the version field can
// only be stopped by the authenticated header. That is the worst case in
// production too: an operator who re-imports the same key under a new version
// number.
type sameKeyEveryVersion struct {
	key []byte
}

func (s sameKeyEveryVersion) Current() (version uint32, key []byte, err error) {
	return 1, append([]byte(nil), s.key...), nil
}

func (s sameKeyEveryVersion) ByVersion(uint32) ([]byte, error) {
	return append([]byte(nil), s.key...), nil
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return k
}

// rowA and rowB name two places a record could be stored: two rows of one
// column, in one tenant. They are the simplest form of the substitution a
// binding context exists to defeat, so they are shared by the tests below.
var (
	rowA = SubjectRef("tenant-1", "subject-1")
	rowB = SubjectRef("tenant-1", "subject-2")
)

// mustSeal seals for rowA, which is the row used by every test that is about
// something other than the binding. The tests that are about the binding name
// their row at the call.
func mustSeal(t *testing.T, s *Sealer, plaintext []byte) []byte {
	t.Helper()
	sealed, err := s.Seal(plaintext, rowA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestSealUnsealRoundTrip(t *testing.T) {
	large := make([]byte, 1<<20)
	if _, err := rand.Read(large); err != nil {
		t.Fatalf("generate payload: %v", err)
	}

	cases := []struct {
		name      string
		plaintext []byte
	}{
		// An empty secret still has to produce an authenticated record, or an
		// attacker could substitute "nothing" for a stored value unnoticed.
		{"empty payload", []byte{}},
		{"small payload", []byte("totp-seed-0123456789")},
		{"1 MiB payload", large},
	}

	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealed := mustSeal(t, s, tc.plaintext)
			if want := minSize + len(tc.plaintext); len(sealed) != want {
				t.Fatalf("sealed record is %d bytes, want %d: the wire format has drifted", len(sealed), want)
			}
			if len(tc.plaintext) > 0 && bytes.Contains(sealed, tc.plaintext) {
				t.Fatal("sealed record contains the plaintext in clear")
			}
			got, err := s.Unseal(sealed, rowA)
			if err != nil {
				t.Fatalf("a record sealed by this Sealer must unseal, got %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Fatal("unsealed plaintext differs from what was sealed")
			}
		})
	}
}

// Reusing a DEK or a GCM nonce across records would let an attacker who holds
// two ciphertexts recover the XOR of the plaintexts and forge tags. Each part
// that must be fresh is compared separately so a failure names the culprit.
func TestSealIsFreshForIdenticalPlaintext(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	plaintext := bytes.Repeat([]byte{0x42}, 32)
	a := mustSeal(t, s, plaintext)
	b := mustSeal(t, s, plaintext)

	parts := []struct {
		name     string
		from, to int
	}{
		{"DEK-wrapping nonce", 5, 5 + nonceSize},
		{"wrapped DEK", 5 + nonceSize, headerSize},
		{"payload nonce", headerSize, headerSize + nonceSize},
		{"payload ciphertext", headerSize + nonceSize, len(a)},
	}
	for _, p := range parts {
		t.Run(p.name, func(t *testing.T) {
			if bytes.Equal(a[p.from:p.to], b[p.from:p.to]) {
				t.Fatalf("%s is identical across two seals of the same plaintext: it must be fresh per record", p.name)
			}
		})
	}
}

func TestUnsealRejectsEverySingleBitFlip(t *testing.T) {
	// The provider answers every version with the same key, so a flip inside
	// the KEK version field is not caught by a failed key lookup. It has to be
	// caught by the header being authenticated.
	s := NewSealer(sameKeyEveryVersion{key: newKey(t)})
	sealed := mustSeal(t, s, []byte("short secret"))

	for i := range sealed {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), sealed...)
			mutated[i] ^= 1 << bit

			got, err := s.Unseal(mutated, rowA)
			if err == nil {
				t.Fatalf("byte %d bit %d: a tampered record unsealed; every byte of the record must be authenticated", i, bit)
			}
			if !errors.Is(err, ErrUnsealFailed) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("byte %d bit %d: got %v, want ErrUnsealFailed or ErrMalformed; any finer error is an oracle", i, bit, err)
			}
			if got != nil {
				t.Fatalf("byte %d bit %d: plaintext returned alongside an error", i, bit)
			}
		}
	}
}

func TestUnsealRejectsTruncationAndExtension(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	sealed := mustSeal(t, s, []byte("short secret"))

	// Every shorter length is tried, not a sample: the lengths around the
	// header and nonce boundaries are where a slicing mistake would panic or
	// accept a record whose tag has been cut off.
	for n := 0; n < len(sealed); n++ {
		got, err := s.Unseal(sealed[:n:n], rowA)
		if err == nil {
			t.Fatalf("record truncated to %d of %d bytes unsealed", n, len(sealed))
		}
		if !errors.Is(err, ErrUnsealFailed) && !errors.Is(err, ErrMalformed) {
			t.Fatalf("truncated to %d bytes: got %v, want ErrUnsealFailed or ErrMalformed", n, err)
		}
		if got != nil {
			t.Fatalf("truncated to %d bytes: plaintext returned alongside an error", n)
		}
	}

	extended := append(append([]byte(nil), sealed...), 0x00)
	if _, err := s.Unseal(extended, rowA); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("record with one appended byte: got %v, want ErrUnsealFailed", err)
	}
}

func TestUnsealRejectsUnknownFormatVersion(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	sealed := mustSeal(t, s, []byte("secret"))

	// A future layout must never be parsed with today's offsets. 0x01 and 0x02
	// are the two layouts this package knows and are covered below instead.
	for _, v := range []byte{0x00, 0x03, 0xff} {
		mutated := append([]byte(nil), sealed...)
		mutated[0] = v
		if _, err := s.Unseal(mutated, rowA); !errors.Is(err, ErrMalformed) {
			t.Errorf("format byte %#x: Unseal got %v, want ErrMalformed", v, err)
		}
		if _, err := s.Rewrap(mutated, rowA); !errors.Is(err, ErrMalformed) {
			t.Errorf("format byte %#x: Rewrap got %v, want ErrMalformed", v, err)
		}
		if _, err := KEKVersion(mutated); !errors.Is(err, ErrMalformed) {
			t.Errorf("format byte %#x: KEKVersion got %v, want ErrMalformed", v, err)
		}
	}

	// Relabelling a version 2 record as version 1 is the downgrade that would
	// strip the binding from a record that has one, so it has to fail. It does
	// because the format byte is the first byte of the authenticated header.
	downgraded := append([]byte(nil), sealed...)
	downgraded[0] = FormatLegacy
	if _, err := s.Unseal(downgraded, rowA); !errors.Is(err, ErrUnsealFailed) {
		t.Errorf("a version 2 record relabelled as version 1: got %v, want ErrUnsealFailed", err)
	}
}

func TestUnsealFailsUnderADifferentKEK(t *testing.T) {
	sealed := mustSeal(t, NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}), []byte("secret"))

	other := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	got, err := other.Unseal(sealed, rowA)
	if !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("record unsealed under a different key with the same version: got %v, want ErrUnsealFailed", err)
	}
	if got != nil {
		t.Fatal("plaintext returned alongside an error")
	}
}

// An attacker with write access to the database may try to rebuild a record
// from pieces of two others, for instance to make a record sealed under a
// retired (possibly leaked) KEK look current, or to attach a DEK they know to
// a payload they do not. Both providers are exercised: with distinct keys, and
// with the same key under both versions, where only the authenticated header
// stands in the way.
func TestHeaderCannotBeSplicedBetweenRecords(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	providers := []struct {
		name string
		keys map[uint32][]byte
	}{
		{"distinct keys per version", map[uint32][]byte{1: k1, 2: k2}},
		{"same key under both versions", map[uint32][]byte{1: k1, 2: k1}},
	}

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			kek := &fakeKEK{keys: p.keys, current: 1}
			s := NewSealer(kek)
			a := mustSeal(t, s, []byte("record A, sealed under version 1"))
			kek.current = 2
			b := mustSeal(t, s, []byte("record B, sealed under version 2"))

			for _, rec := range [][]byte{a, b} {
				if _, err := s.Unseal(rec, rowA); err != nil {
					t.Fatalf("baseline record does not unseal, the splices below would prove nothing: %v", err)
				}
			}

			splice := func(head, body []byte, n int) []byte {
				return append(append([]byte(nil), head[:n]...), body[n:]...)
			}
			cases := []struct {
				name   string
				record []byte
			}{
				{"version field of A on the rest of B", splice(a, b, 5)},
				{"version field of B on the rest of A", splice(b, a, 5)},
				{"full header of A on the payload of B", splice(a, b, headerSize)},
				{"full header of B on the payload of A", splice(b, a, headerSize)},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got, err := s.Unseal(tc.record, rowA)
					if !errors.Is(err, ErrUnsealFailed) {
						t.Fatalf("spliced record: got %v, want ErrUnsealFailed; the header must be bound to the wrapped DEK and to the payload", err)
					}
					if got != nil {
						t.Fatal("plaintext returned alongside an error")
					}
					// Rewrap authenticates before it decides anything, so a
					// spliced record is refused outright. The outcome is
					// checked as well as the error, because the property that
					// matters is that rotation never turns a forged record
					// into one that unseals.
					out, err := s.Rewrap(tc.record, rowA)
					if err != nil {
						if !errors.Is(err, ErrUnsealFailed) {
							t.Fatalf("Rewrap of a spliced record: got %v, want ErrUnsealFailed", err)
						}
						return
					}
					if _, err := s.Unseal(out, rowA); !errors.Is(err, ErrUnsealFailed) {
						t.Fatalf("Rewrap laundered a spliced record into one that unseals (Unseal error: %v)", err)
					}
				})
			}
		})
	}
}

func TestUnknownKEKVersionIsReportedAsUnavailable(t *testing.T) {
	kek := &fakeKEK{keys: map[uint32][]byte{7: newKey(t)}, current: 7}
	s := NewSealer(kek)
	sealed := mustSeal(t, s, []byte("secret"))

	// The operator has dropped version 7 from the keyring. This must surface
	// as a distinct, actionable error: it is a configuration fault, and
	// reporting it as a failed unseal would send the operator looking for
	// corruption that is not there.
	kek.keys = map[uint32][]byte{8: newKey(t)}
	kek.current = 8

	if got, err := s.Unseal(sealed, rowA); !errors.Is(err, ErrKEKUnavailable) || got != nil {
		t.Fatalf("Unseal with the KEK version absent: got (%v, %v), want (nil, ErrKEKUnavailable)", got, err)
	}
	if got, err := s.Rewrap(sealed, rowA); !errors.Is(err, ErrKEKUnavailable) || got != nil {
		t.Fatalf("Rewrap with the KEK version absent: got (%v, %v), want (nil, ErrKEKUnavailable)", got, err)
	}
}

func TestKEKVersionReadsHeaderWithoutTheKey(t *testing.T) {
	cases := []uint32{0, 1, 2, 0x01020304, 0xffffffff}
	for _, v := range cases {
		t.Run(fmt.Sprintf("version %d", v), func(t *testing.T) {
			sealed := mustSeal(t, NewSealer(&fakeKEK{keys: map[uint32][]byte{v: newKey(t)}, current: v}), []byte("secret"))
			// No provider is involved from here on: a rotation job has to be
			// able to list stale records even when the old key is offline.
			got, err := KEKVersion(sealed)
			if err != nil {
				t.Fatalf("KEKVersion: %v", err)
			}
			if got != v {
				t.Fatalf("KEKVersion = %d, want %d: a byte-order mistake would send rotation after the wrong records", got, v)
			}
			if raw := binary.BigEndian.Uint32(sealed[1:5]); raw != v {
				t.Fatalf("version field on the wire = %d, want %d", raw, v)
			}
		})
	}

	t.Run("short input is malformed, not a panic", func(t *testing.T) {
		sealed := mustSeal(t, NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}), nil)
		for n := 0; n < headerSize; n++ {
			if _, err := KEKVersion(sealed[:n]); !errors.Is(err, ErrMalformed) {
				t.Fatalf("KEKVersion on %d bytes: got %v, want ErrMalformed", n, err)
			}
		}
	})
}

func TestRewrapMovesRecordToCurrentKEK(t *testing.T) {
	kek := &fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}
	s := NewSealer(kek)
	plaintext := []byte("secret that outlives a key rotation")
	original := mustSeal(t, s, plaintext)
	originalCopy := append([]byte(nil), original...)

	kek.keys[2] = newKey(t)
	kek.current = 2

	rewrapped, err := s.Rewrap(original, rowA)
	if err != nil {
		t.Fatalf("Rewrap from version 1 to version 2: %v", err)
	}
	if !bytes.Equal(original, originalCopy) {
		t.Fatal("Rewrap modified its input; a failed database write would then leave no intact record")
	}
	v, err := KEKVersion(rewrapped)
	if err != nil || v != 2 {
		t.Fatalf("rewrapped record reports KEK version (%d, %v), want (2, nil)", v, err)
	}
	if len(rewrapped) != len(original) {
		t.Fatalf("rewrapped record is %d bytes, original is %d", len(rewrapped), len(original))
	}
	// The payload is re-sealed under the same DEK, so a repeated nonce here
	// would be a nonce reuse under one key with GCM.
	if bytes.Equal(rewrapped[headerSize:headerSize+nonceSize], original[headerSize:headerSize+nonceSize]) {
		t.Fatal("rewrapped record reuses the payload nonce under the same DEK")
	}

	got, err := s.Unseal(rewrapped, rowA)
	if err != nil {
		t.Fatalf("rewrapped record does not unseal: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("rewrapped record unseals to a different plaintext")
	}

	// The point of rotation is to be able to retire the old key. If the
	// rewrapped record still depended on version 1 in any way, removing it
	// would lose data.
	delete(kek.keys, 1)
	got, err = s.Unseal(rewrapped, rowA)
	if err != nil {
		t.Fatalf("rewrapped record no longer unseals once the old KEK is removed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("rewrapped record unseals to a different plaintext once the old KEK is removed")
	}
	if _, err := s.Unseal(original, rowA); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("the version 1 record after version 1 was removed: got %v, want ErrKEKUnavailable", err)
	}
}

func TestRewrapOfCurrentRecordReturnsIndependentCopy(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	plaintext := []byte("secret")
	sealed := mustSeal(t, s, plaintext)
	pristine := append([]byte(nil), sealed...)

	out, err := s.Rewrap(sealed, rowA)
	if err != nil {
		t.Fatalf("Rewrap of an already-current record: %v", err)
	}
	if !bytes.Equal(out, sealed) {
		t.Fatal("Rewrap changed a record that was already under the current KEK")
	}

	// A caller may zeroize or reuse either buffer. Aliasing would let that
	// corrupt the other one silently.
	for i := range out {
		out[i] = 0
	}
	if !bytes.Equal(sealed, pristine) {
		t.Fatal("overwriting the Rewrap result altered the input: the result aliases it")
	}
	out2, err := s.Rewrap(sealed, rowA)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	for i := range sealed {
		sealed[i] = 0
	}
	if !bytes.Equal(out2, pristine) {
		t.Fatal("overwriting the input altered the Rewrap result: the result aliases it")
	}
	got, err := s.Unseal(out2, rowA)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("copy returned by Rewrap does not unseal to the original plaintext: %v", err)
	}
}

func TestWrongSizeKeyIsRefused(t *testing.T) {
	// 16 and 24 bytes are the dangerous entries: they are valid AES key
	// sizes, so without an explicit check the cipher would accept them and the
	// deployment would run on AES-128 or AES-192 without anyone noticing.
	sizes := []int{0, 1, 16, 24, 31, 33, 64}

	good := newKey(t)
	sealed := mustSeal(t, NewSealer(&fakeKEK{keys: map[uint32][]byte{1: good}, current: 1}), []byte("secret"))

	for _, n := range sizes {
		t.Run(fmt.Sprintf("%d byte key", n), func(t *testing.T) {
			bad := make([]byte, n)
			if _, err := rand.Read(bad); err != nil {
				t.Fatalf("generate key: %v", err)
			}
			s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: bad}, current: 1})

			if out, err := s.Seal([]byte("secret"), rowA); err == nil || out != nil {
				t.Errorf("Seal accepted a %d byte KEK (err=%v, %d bytes out); only 32 byte keys may be used", n, err, len(out))
			}
			if out, err := s.Unseal(sealed, rowA); err == nil || out != nil {
				t.Errorf("Unseal accepted a %d byte KEK (err=%v)", n, err)
			}

			// Old key valid, new current key of the wrong size: rotation
			// must stop rather than move records under a weaker key.
			rot := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: good, 2: bad}, current: 2})
			if out, err := rot.Rewrap(sealed, rowA); err == nil || out != nil {
				t.Errorf("Rewrap moved a record under a %d byte KEK (err=%v)", n, err)
			}
		})
	}
}
