package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// sealLegacy writes a record in the format this package produced before
// binding contexts existed: version 1 in the first byte, and nothing but the
// record header as additional authenticated data.
//
// It is the fixture for the reading path that carries an upgraded deployment
// until its first rewrap pass. Reproducing the old writer here is the only way
// to have a version 1 record to read, and it fails the day the shared layout
// constants move, which is the right moment to find out.
func sealLegacy(t *testing.T, kek KEKProvider, plaintext []byte) []byte {
	t.Helper()

	version, key, err := kek.Current()
	if err != nil {
		t.Fatalf("current kek: %v", err)
	}
	kekGCM, err := newGCM(key)
	if err != nil {
		t.Fatalf("kek gcm: %v", err)
	}

	dek := make([]byte, keySize)
	if _, err = rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		t.Fatalf("dek gcm: %v", err)
	}

	out := make([]byte, headerSize, minSize+len(plaintext))
	out[0] = FormatLegacy
	binary.BigEndian.PutUint32(out[1:5], version)
	wrapNonce := out[5 : 5+nonceSize]
	if _, err = rand.Read(wrapNonce); err != nil {
		t.Fatalf("generate wrap nonce: %v", err)
	}
	kekGCM.Seal(out[5+nonceSize:5+nonceSize], wrapNonce, dek, out[:5])

	payloadNonce := make([]byte, nonceSize)
	if _, err = rand.Read(payloadNonce); err != nil {
		t.Fatalf("generate payload nonce: %v", err)
	}
	out = append(out, payloadNonce...)
	return dekGCM.Seal(out, payloadNonce, plaintext, out[:headerSize])
}

// TestARecordDoesNotOpenAnywhereButTheRowItWasSealedFor is the defect this
// binding exists to close. An attacker who can write to the database without
// holding the key encryption key, through an injection, a restored backup or
// an administrator of the database itself, used to be able to move any valid
// ciphertext into any row of the matching column.
func TestARecordDoesNotOpenAnywhereButTheRowItWasSealedFor(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})

	sealedFor := TOTPSecret("tenant-1", "subject-1", "secret-1")
	cases := []struct {
		name string
		open Context
	}{
		{"another row of the same column", TOTPSecret("tenant-1", "subject-1", "secret-2")},
		{"another subject in the same tenant", TOTPSecret("tenant-1", "subject-2", "secret-1")},
		{"the same row identifiers in another tenant", TOTPSecret("tenant-2", "subject-1", "secret-1")},
		{"another column", SubjectRef("tenant-1", "secret-1")},
	}

	sealed, err := s.Seal([]byte("totp-seed"), sealedFor)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err = s.Unseal(sealed, sealedFor); err != nil {
		t.Fatalf("the record does not open where it belongs, so the refusals below would prove nothing: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Unseal(sealed, tc.open)
			if !errors.Is(err, ErrUnsealFailed) {
				t.Fatalf("got %v, want ErrUnsealFailed", err)
			}
			if got != nil {
				t.Fatal("plaintext returned alongside an error")
			}
		})
	}
}

// TestASecretCopiedIntoAnotherSubjectsRowIsRefused plays out the attack in full
// rather than only the property behind it: the attacker enrols, keeps the seed
// they were shown, and writes their own sealed secret over the victim's row so
// that codes they can generate authenticate as the victim.
func TestASecretCopiedIntoAnotherSubjectsRowIsRefused(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})

	attackerSeed := []byte("seed the attacker generated codes from")
	attackerRow := TOTPSecret("tenant-1", "attacker", "secret-attacker")
	mine, err := s.Seal(attackerSeed, attackerRow)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The bytes are now in the victim's row. The service reads them with the
	// victim's identifiers, because that is the row it read them from.
	victimRow := TOTPSecret("tenant-1", "victim", "secret-victim")
	got, err := s.Unseal(mine, victimRow)
	if !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("the attacker's own secret opened in the victim's row: got %v, want ErrUnsealFailed", err)
	}
	if got != nil {
		t.Fatal("plaintext returned alongside an error")
	}
}

// TestARewrapKeepsTheRecordBoundToItsRow checks the property a rotation must
// not lose. A pass that dropped the binding, or renegotiated it, would hand
// back the substitution the binding was added to prevent.
func TestARewrapKeepsTheRecordBoundToItsRow(t *testing.T) {
	kek := &fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}
	s := NewSealer(kek)
	plaintext := []byte("secret that outlives a key rotation")

	row := TOTPSecret("tenant-1", "subject-1", "secret-1")
	sealed, err := s.Seal(plaintext, row)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	kek.keys[2] = newKey(t)
	kek.current = 2
	rewrapped, err := s.Rewrap(sealed, row)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	got, err := s.Unseal(rewrapped, row)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the rewrapped record does not open in its own row: %v", err)
	}
	other := TOTPSecret("tenant-1", "subject-2", "secret-2")
	if _, err = s.Unseal(rewrapped, other); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("the rewrapped record opened in another row: got %v, want ErrUnsealFailed", err)
	}

	// Rewrapping under a context the record was not sealed with must fail
	// rather than produce a record bound to somewhere else.
	if _, err = s.Rewrap(sealed, other); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("Rewrap under another row: got %v, want ErrUnsealFailed", err)
	}
}

// TestARewrapOpensARecordThatIsAlreadyCurrent states the property a rotation
// pass reads as its integrity report. A record on the current key in the
// current format is still opened, so a corrupted payload is a failure and not a
// row reported as sound by the only pass that ever looks at it.
func TestARewrapOpensARecordThatIsAlreadyCurrent(t *testing.T) {
	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	sealed := mustSeal(t, s, []byte("secret"))

	corrupted := append([]byte(nil), sealed...)
	corrupted[len(corrupted)-1] ^= 0x01

	got, err := s.Rewrap(corrupted, rowA)
	if !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("a corrupted record already on the current key: got %v, want ErrUnsealFailed", err)
	}
	if got != nil {
		t.Fatal("a record returned alongside an error")
	}

	// The same record in the row it does not belong to: current key, current
	// format, intact bytes, wrong place.
	if _, err = s.Rewrap(sealed, rowB); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("an intact record rewrapped in another row: got %v, want ErrUnsealFailed", err)
	}
}

// TestAVersion1RecordIsStillReadableAndIsUpgradedByARewrap covers the
// transition. A deployment upgraded to this version holds records written
// before the binding existed, and they have to keep opening until a rewrap pass
// has rewritten them.
func TestAVersion1RecordIsStillReadableAndIsUpgradedByARewrap(t *testing.T) {
	kek := &fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}
	s := NewSealer(kek)
	plaintext := []byte("sealed before binding contexts existed")
	row := TOTPSecret("tenant-1", "subject-1", "secret-1")

	legacy := sealLegacy(t, kek, plaintext)
	if legacy[0] != FormatLegacy {
		t.Fatalf("the fixture is not a version 1 record: format byte %#x", legacy[0])
	}

	got, err := s.Unseal(legacy, row)
	if err != nil {
		t.Fatalf("a version 1 record must still open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("a version 1 record opened to a different plaintext")
	}

	// This is the weakness the transition carries, and it is asserted rather
	// than left implicit: a version 1 record is not bound to anything, so it
	// opens in any row until it has been rewritten.
	if _, err = s.Unseal(legacy, rowA); err != nil {
		t.Fatalf("a version 1 record is unbound by construction and should open anywhere, got %v", err)
	}

	// The upgrade happens on the next pass, with the key version unchanged.
	upgraded, err := s.Rewrap(legacy, row)
	if err != nil {
		t.Fatalf("Rewrap of a version 1 record: %v", err)
	}
	if upgraded[0] != FormatVersion {
		t.Fatalf("a rewrapped record carries format byte %#x, want %#x", upgraded[0], FormatVersion)
	}
	if bytes.Equal(upgraded, legacy) {
		t.Fatal("Rewrap left a version 1 record alone, so nothing would ever be upgraded")
	}
	version, err := KEKVersion(upgraded)
	if err != nil || version != 1 {
		t.Fatalf("upgraded record reports key version (%d, %v), want (1, nil)", version, err)
	}

	got, err = s.Unseal(upgraded, row)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the upgraded record does not open in its own row: %v", err)
	}
	if _, err = s.Unseal(upgraded, rowA); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("the upgraded record still opens in another row: got %v, want ErrUnsealFailed", err)
	}
}

// TestAnIncompleteContextIsRefusedByEveryOperation checks that a context that
// binds nothing cannot be used at all. Accepting one would reintroduce the
// defect quietly, in whichever call site forgot a field.
func TestAnIncompleteContextIsRefusedByEveryOperation(t *testing.T) {
	cases := []struct {
		name string
		bind Context
	}{
		{"nothing at all", Context{}},
		{"no kind", Context{TenantID: "tenant-1", RowID: "row-1"}},
		{"an unknown kind", Context{Kind: "invented", TenantID: "tenant-1", RowID: "row-1"}},
		{"no tenant", Context{Kind: KindSubjectRef, RowID: "row-1"}},
		{"no row", Context{Kind: KindSubjectRef, TenantID: "tenant-1"}},
		{"a totp secret naming no subject", Context{Kind: KindTOTPSecret, TenantID: "tenant-1", RowID: "row-1"}},
		{"a subject reference naming a second subject", Context{
			Kind: KindSubjectRef, TenantID: "tenant-1", RowID: "row-1", SubjectID: "subject-2",
		}},
		{"a field longer than the limit", Context{
			Kind: KindSubjectRef, TenantID: strings.Repeat("t", maxBindingField+1), RowID: "row-1",
		}},
	}

	s := NewSealer(&fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1})
	sealed := mustSeal(t, s, []byte("secret"))
	legacy := sealLegacy(t, &fakeKEK{keys: map[uint32][]byte{1: newKey(t)}, current: 1}, []byte("secret"))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.bind.Validate(); !errors.Is(err, ErrContextInvalid) {
				t.Errorf("Validate: got %v, want ErrContextInvalid", err)
			}
			if _, err := s.Seal([]byte("secret"), tc.bind); !errors.Is(err, ErrContextInvalid) {
				t.Errorf("Seal: got %v, want ErrContextInvalid", err)
			}
			if _, err := s.Unseal(sealed, tc.bind); !errors.Is(err, ErrContextInvalid) {
				t.Errorf("Unseal: got %v, want ErrContextInvalid", err)
			}
			if _, err := s.Rewrap(sealed, tc.bind); !errors.Is(err, ErrContextInvalid) {
				t.Errorf("Rewrap: got %v, want ErrContextInvalid", err)
			}
			// A version 1 record does not use the context, and still refuses
			// an incomplete one. Otherwise a caller with nothing to bind would
			// find that it works, on exactly the records that are least
			// protected.
			if _, err := s.Unseal(legacy, tc.bind); !errors.Is(err, ErrContextInvalid) {
				t.Errorf("Unseal of a version 1 record: got %v, want ErrContextInvalid", err)
			}
		})
	}
}

// TestNoTwoContextsSerialiseToTheSameBytes is the property that makes the
// encoding a binding rather than a suggestion. The pairs below are the ones a
// separator-joined encoding would collapse: the same characters, split
// differently between two fields.
func TestNoTwoContextsSerialiseToTheSameBytes(t *testing.T) {
	contexts := []Context{
		SubjectRef("tenant-1", "subject-1"),
		SubjectRef("tenant", "1subject-1"),
		SubjectRef("tenant-1subject", "-1"),
		SubjectRef("tenant-1", "subject-2"),
		SubjectRef("tenant-2", "subject-1"),
		TOTPSecret("tenant-1", "subject-1", "secret-1"),
		TOTPSecret("tenant-1", "subject-1secret", "-1"),
		TOTPSecret("tenant-1", "secret-1", "subject-1"),
	}

	seen := map[string]Context{}
	for _, c := range contexts {
		encoded, err := c.bytes()
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if previous, clash := seen[string(encoded)]; clash {
			t.Errorf("%+v and %+v serialise to the same bytes, so one opens the other's records", c, previous)
		}
		seen[string(encoded)] = c
		if !bytes.HasPrefix(encoded, []byte(bindingDomain)) {
			t.Errorf("%+v: the serialised context does not start with the domain separator", c)
		}
	}
}
