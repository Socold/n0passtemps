// Package envelope implements authenticated envelope encryption for secrets at
// rest.
//
// Each secret is sealed under a freshly generated data encryption key (DEK).
// The DEK is itself sealed under the key encryption key (KEK) supplied by the
// configured provider. Only the KEK-wrapped DEK and the ciphertext are
// persisted, so rotating the KEK re-wraps a small fixed-size blob per row
// instead of re-encrypting every secret.
//
// Wire format, version 2:
//
//	byte  0      format version (0x02)
//	bytes 1..4   KEK version, big endian uint32
//	bytes 5..16  DEK-wrapping nonce (12 bytes)
//	bytes 17..48 wrapped DEK (32-byte key + 16-byte GCM tag)
//	bytes 49..60 payload nonce (12 bytes)
//	bytes 61..    payload ciphertext with appended GCM tag
//
// Both Seal calls take the record header followed by the serialised binding
// context as additional authenticated data. The header stops the KEK version
// and the wrapped DEK from being swapped between records; the context ties the
// record to the row it belongs to, so a ciphertext copied into another row,
// another column or another tenant no longer opens. See Context and ADR 0021.
//
// Version 1 is the same layout with 0x01 in the first byte and nothing but the
// header as authenticated data. It is read and never written, until a rewrap
// pass has moved every stored record to version 2.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

const (
	// FormatVersion is the current envelope layout identifier. A record
	// carrying it is bound to the row it was sealed for.
	FormatVersion = 0x02

	// FormatLegacy is the layout written before binding contexts existed. The
	// bytes on the wire have the same shape; what differs is that its
	// authenticated data stops at the record header, so nothing ties it to a
	// row. It is accepted on read so that an upgraded deployment keeps working
	// before its first rewrap pass, and it is never written.
	FormatLegacy = 0x01

	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
	tagSize   = 16 // GCM tag
	wrapSize  = keySize + tagSize

	headerSize = 1 + 4 + nonceSize + wrapSize
	minSize    = headerSize + nonceSize + tagSize
)

// Errors returned by this package. They are deliberately coarse: a caller must
// not be able to distinguish a corrupted tag from a wrong key, because that
// distinction is an oracle.
//
// ErrContextInvalid is the exception, and is deliberately loud: it reports a
// caller that did not say where the record lives, which is a fault in this
// service rather than anything an attacker supplied.
var (
	ErrMalformed      = errors.New("envelope: malformed ciphertext")
	ErrUnsealFailed   = errors.New("envelope: unseal failed")
	ErrKEKUnavailable = errors.New("envelope: kek version unavailable")
	ErrContextInvalid = errors.New("envelope: binding context is incomplete")
)

// KEKProvider supplies key encryption keys by version.
//
// Current returns the version that new secrets must be sealed under. ByVersion
// returns any version still retained, which lets old records be read during a
// gradual rotation. Implementations must treat the returned slice as owned by
// the caller and safe to zeroize.
type KEKProvider interface {
	Current() (version uint32, key []byte, err error)
	ByVersion(version uint32) (key []byte, err error)
}

// Sealer seals and unseals secrets under the KEKs of a provider.
type Sealer struct {
	kek KEKProvider
}

// NewSealer returns a Sealer backed by kek.
func NewSealer(kek KEKProvider) *Sealer {
	return &Sealer{kek: kek}
}

// Seal encrypts plaintext under a new DEK wrapped by the current KEK, bound to
// the row named by bind.
//
// The same context has to be supplied to open the record again, so it must be
// derived from values that are stable for the life of the row. An incomplete
// context is refused rather than sealed under a weaker binding.
//
// The caller retains ownership of plaintext and is responsible for zeroizing
// it. Seal does not retain a reference to it.
func (s *Sealer) Seal(plaintext []byte, bind Context) ([]byte, error) {
	bound, err := bind.bytes()
	if err != nil {
		return nil, err
	}

	kekVersion, kekKey, err := s.kek.Current()
	if err != nil {
		return nil, fmt.Errorf("envelope: current kek: %w", err)
	}
	defer zeroize.Bytes(kekKey)

	dek := make([]byte, keySize)
	if _, err = rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: generate dek: %w", err)
	}
	defer zeroize.Bytes(dek)

	out := make([]byte, headerSize, minSize+len(plaintext))
	out[0] = FormatVersion
	binary.BigEndian.PutUint32(out[1:5], kekVersion)

	wrapNonce := out[5 : 5+nonceSize]
	if _, err = rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}

	kekGCM, err := newGCM(kekKey)
	if err != nil {
		return nil, err
	}
	// Bind the wrapped DEK to the version field that precedes it, and to the
	// row, so a wrapped DEK cannot be lifted out of another record either.
	kekGCM.Seal(out[5+nonceSize:5+nonceSize], wrapNonce, dek, aad(out[:5], bound))

	payloadNonce := make([]byte, nonceSize)
	if _, err = rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}
	out = append(out, payloadNonce...)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	// Bind the payload to the whole header, so a record cannot be rebuilt
	// from parts of two different records, and to the row it belongs to.
	out = dekGCM.Seal(out, payloadNonce, plaintext, aad(out[:headerSize], bound))
	return out, nil
}

// Unseal decrypts a sealed record that was sealed for the row named by bind.
// The returned plaintext is owned by the caller, which must zeroize it when
// done.
//
// A record sealed for another row, another column or another tenant fails with
// ErrUnsealFailed, exactly as a corrupted one does: from here the two are the
// same event, a record that does not authenticate.
func (s *Sealer) Unseal(sealed []byte, bind Context) ([]byte, error) {
	bound, err := openingAAD(sealed, bind)
	if err != nil {
		return nil, err
	}

	kekVersion := binary.BigEndian.Uint32(sealed[1:5])
	kekKey, err := s.kek.ByVersion(kekVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: version %d", ErrKEKUnavailable, kekVersion)
	}
	defer zeroize.Bytes(kekKey)

	kekGCM, err := newGCM(kekKey)
	if err != nil {
		return nil, err
	}

	wrapNonce := sealed[5 : 5+nonceSize]
	wrapped := sealed[5+nonceSize : headerSize]
	dek, err := kekGCM.Open(nil, wrapNonce, wrapped, aad(sealed[:5], bound))
	if err != nil {
		return nil, ErrUnsealFailed
	}
	defer zeroize.Bytes(dek)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	payloadNonce := sealed[headerSize : headerSize+nonceSize]
	payload := sealed[headerSize+nonceSize:]
	plaintext, err := dekGCM.Open(nil, payloadNonce, payload, aad(sealed[:headerSize], bound))
	if err != nil {
		return nil, ErrUnsealFailed
	}
	return plaintext, nil
}

// aad joins the part of the record header that authenticates a GCM call with
// the serialised binding context.
//
// GCM takes one slice, so the two halves are concatenated in a fixed order. No
// separator is needed between them: the header half has a fixed length for a
// given format version, and the format version is its first byte.
func aad(header, bound []byte) []byte {
	out := make([]byte, 0, len(header)+len(bound))
	out = append(out, header...)
	return append(out, bound...)
}

// openingAAD validates bind, checks the shape of an existing record and returns
// the binding half of the authenticated data needed to open it.
//
// A version 1 record is opened with no binding half, which reproduces the
// authenticated data it was written with. That branch is transitional: it is
// what lets a deployment upgraded to this version keep reading the records it
// already holds, and it carries the weakness this binding exists to remove, so
// a version 1 record can still be moved between rows until a rewrap pass has
// rewritten it. ADR 0021 says what that costs and for how long.
//
// The context is validated whichever version the record turns out to be. A
// caller holding an incomplete context must not find that it works against the
// rows that happen to be old.
func openingAAD(sealed []byte, bind Context) ([]byte, error) {
	bound, err := bind.bytes()
	if err != nil {
		return nil, err
	}
	if len(sealed) < minSize {
		return nil, ErrMalformed
	}
	switch sealed[0] {
	case FormatVersion:
		return bound, nil
	case FormatLegacy:
		return nil, nil
	default:
		return nil, ErrMalformed
	}
}

// KEKVersion reports which KEK a sealed record was wrapped under, without
// needing that KEK to be available. Rotation jobs use this to find the records
// that still have to be re-wrapped.
func KEKVersion(sealed []byte) (uint32, error) {
	if len(sealed) < headerSize {
		return 0, ErrMalformed
	}
	switch sealed[0] {
	case FormatVersion, FormatLegacy:
		// The version field sits at the same offset in both layouts, which is
		// why a pass can report on records it has not yet rewritten.
		return binary.BigEndian.Uint32(sealed[1:5]), nil
	default:
		return 0, ErrMalformed
	}
}

// CurrentVersion reports the KEK version new records are sealed under, which is
// the version a rewrap pass moves records onto.
//
// The provider hands out the key together with the version. The key is not
// needed here, so it is zeroized before returning rather than left in memory
// until the garbage collector reclaims it.
func (s *Sealer) CurrentVersion() (uint32, error) {
	version, key, err := s.kek.Current()
	if err != nil {
		return 0, fmt.Errorf("envelope: current kek: %w", err)
	}
	zeroize.Bytes(key)
	return version, nil
}

// Rewrap moves an existing record onto the current KEK and onto the current
// format version, keeping the binding named by bind.
//
// The binding is not renegotiated here: bind is the context the record was
// sealed with and the context it is sealed with again. A rotation that could
// rebind a record to a different row would hand an attacker with database write
// access the very substitution the binding exists to prevent, performed by the
// service itself with the key it holds.
//
// The payload is always opened, even when the record is already current. Two
// reasons. The header is authenticated data of the payload and the header is
// about to change, so the payload has to be re-sealed in any case. And a
// rotation job reads the error from this function as its integrity report: if
// the already-current path returned early without authenticating, a corrupted
// row would be reported as successfully rotated and the corruption would
// surface months later as a user who cannot sign in.
//
// A version 1 record is rewritten as version 2 whatever its KEK version, which
// is how the binding reaches records sealed before it existed.
func (s *Sealer) Rewrap(sealed []byte, bind Context) ([]byte, error) {
	bound, err := openingAAD(sealed, bind)
	if err != nil {
		return nil, err
	}
	legacy := bound == nil

	oldVersion := binary.BigEndian.Uint32(sealed[1:5])
	oldKey, err := s.kek.ByVersion(oldVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: version %d", ErrKEKUnavailable, oldVersion)
	}
	defer zeroize.Bytes(oldKey)

	oldGCM, err := newGCM(oldKey)
	if err != nil {
		return nil, err
	}
	dek, err := oldGCM.Open(nil, sealed[5:5+nonceSize], sealed[5+nonceSize:headerSize], aad(sealed[:5], bound))
	if err != nil {
		return nil, ErrUnsealFailed
	}
	defer zeroize.Bytes(dek)

	// Authenticate the payload before anything else is decided. See the
	// function comment for why this is not skipped for a current record.
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, sealed[headerSize:headerSize+nonceSize], sealed[headerSize+nonceSize:],
		aad(sealed[:headerSize], bound))
	if err != nil {
		return nil, ErrUnsealFailed
	}
	defer zeroize.Bytes(plaintext)

	newVersion, newKey, err := s.kek.Current()
	if err != nil {
		return nil, fmt.Errorf("envelope: current kek: %w", err)
	}
	defer zeroize.Bytes(newKey)

	if newVersion == oldVersion && !legacy {
		// Already current in both the key version and the format, and now
		// known to be intact. Return a copy so callers may treat the result as
		// independent of the input.
		return append([]byte(nil), sealed...), nil
	}

	// A version 1 record was opened with no binding half, because that is the
	// authenticated data it was written with. It is written back as version 2,
	// so the context has to be rendered before it is sealed again.
	if legacy {
		if bound, err = bind.bytes(); err != nil {
			return nil, err
		}
	}

	out := make([]byte, headerSize, len(sealed))
	out[0] = FormatVersion
	binary.BigEndian.PutUint32(out[1:5], newVersion)

	wrapNonce := out[5 : 5+nonceSize]
	if _, err = rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}
	newGCM, err := newGCM(newKey)
	if err != nil {
		return nil, err
	}
	newGCM.Seal(out[5+nonceSize:5+nonceSize], wrapNonce, dek, aad(out[:5], bound))

	payloadNonce := make([]byte, nonceSize)
	if _, err := rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}
	out = append(out, payloadNonce...)
	out = dekGCM.Seal(out, payloadNonce, plaintext, aad(out[:headerSize], bound))
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("envelope: key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: new gcm: %w", err)
	}
	return gcm, nil
}
