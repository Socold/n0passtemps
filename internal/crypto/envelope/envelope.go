// Package envelope implements authenticated envelope encryption for secrets at
// rest.
//
// Each secret is sealed under a freshly generated data encryption key (DEK).
// The DEK is itself sealed under the key encryption key (KEK) supplied by the
// configured provider. Only the KEK-wrapped DEK and the ciphertext are
// persisted, so rotating the KEK re-wraps a small fixed-size blob per row
// instead of re-encrypting every secret.
//
// Wire format, version 1:
//
//	byte  0      format version (0x01)
//	bytes 1..4   KEK version, big endian uint32
//	bytes 5..16  DEK-wrapping nonce (12 bytes)
//	bytes 17..48 wrapped DEK (32-byte key + 16-byte GCM tag)
//	bytes 49..60 payload nonce (12 bytes)
//	bytes 61..    payload ciphertext with appended GCM tag
//
// The header is passed to both Seal calls as additional authenticated data, so
// the KEK version and the wrapped DEK cannot be swapped between records.
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
	// FormatVersion is the current envelope layout identifier.
	FormatVersion = 0x01

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
var (
	ErrMalformed      = errors.New("envelope: malformed ciphertext")
	ErrUnsealFailed   = errors.New("envelope: unseal failed")
	ErrKEKUnavailable = errors.New("envelope: kek version unavailable")
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

// Seal encrypts plaintext under a new DEK wrapped by the current KEK.
//
// The caller retains ownership of plaintext and is responsible for zeroizing
// it. Seal does not retain a reference to it.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	kekVersion, kekKey, err := s.kek.Current()
	if err != nil {
		return nil, fmt.Errorf("envelope: current kek: %w", err)
	}
	defer zeroize.Bytes(kekKey)

	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: generate dek: %w", err)
	}
	defer zeroize.Bytes(dek)

	out := make([]byte, headerSize, minSize+len(plaintext))
	out[0] = FormatVersion
	binary.BigEndian.PutUint32(out[1:5], kekVersion)

	wrapNonce := out[5 : 5+nonceSize]
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}

	kekGCM, err := newGCM(kekKey)
	if err != nil {
		return nil, err
	}
	// Bind the wrapped DEK to the version field that precedes it.
	kekGCM.Seal(out[5+nonceSize:5+nonceSize], wrapNonce, dek, out[:5])

	payloadNonce := make([]byte, nonceSize)
	if _, err := rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}
	out = append(out, payloadNonce...)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	// Bind the payload to the whole header, so a record cannot be rebuilt
	// from parts of two different records.
	out = dekGCM.Seal(out, payloadNonce, plaintext, out[:headerSize])
	return out, nil
}

// Unseal decrypts a sealed record. The returned plaintext is owned by the
// caller, which must zeroize it when done.
func (s *Sealer) Unseal(sealed []byte) ([]byte, error) {
	if len(sealed) < minSize || sealed[0] != FormatVersion {
		return nil, ErrMalformed
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
	dek, err := kekGCM.Open(nil, wrapNonce, wrapped, sealed[:5])
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
	plaintext, err := dekGCM.Open(nil, payloadNonce, payload, sealed[:headerSize])
	if err != nil {
		return nil, ErrUnsealFailed
	}
	return plaintext, nil
}

// KEKVersion reports which KEK a sealed record was wrapped under, without
// needing that KEK to be available. Rotation jobs use this to find the records
// that still have to be re-wrapped.
func KEKVersion(sealed []byte) (uint32, error) {
	if len(sealed) < headerSize || sealed[0] != FormatVersion {
		return 0, ErrMalformed
	}
	return binary.BigEndian.Uint32(sealed[1:5]), nil
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

// Rewrap moves an existing record onto the current KEK.
//
// The payload is always opened, even when the record is already current. Two
// reasons. The header is authenticated data of the payload and the header is
// about to change, so the payload has to be re-sealed in any case. And a
// rotation job reads the error from this function as its integrity report: if
// the already-current path returned early without authenticating, a corrupted
// row would be reported as successfully rotated and the corruption would
// surface months later as a user who cannot sign in.
func (s *Sealer) Rewrap(sealed []byte) ([]byte, error) {
	if len(sealed) < minSize || sealed[0] != FormatVersion {
		return nil, ErrMalformed
	}

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
	dek, err := oldGCM.Open(nil, sealed[5:5+nonceSize], sealed[5+nonceSize:headerSize], sealed[:5])
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
		sealed[:headerSize])
	if err != nil {
		return nil, ErrUnsealFailed
	}
	defer zeroize.Bytes(plaintext)

	newVersion, newKey, err := s.kek.Current()
	if err != nil {
		return nil, fmt.Errorf("envelope: current kek: %w", err)
	}
	defer zeroize.Bytes(newKey)

	if newVersion == oldVersion {
		// Already current, and now known to be intact. Return a copy so
		// callers may treat the result as independent of the input.
		return append([]byte(nil), sealed...), nil
	}

	out := make([]byte, headerSize, len(sealed))
	out[0] = FormatVersion
	binary.BigEndian.PutUint32(out[1:5], newVersion)

	wrapNonce := out[5 : 5+nonceSize]
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}
	newGCM, err := newGCM(newKey)
	if err != nil {
		return nil, err
	}
	newGCM.Seal(out[5+nonceSize:5+nonceSize], wrapNonce, dek, out[:5])

	payloadNonce := make([]byte, nonceSize)
	if _, err := rand.Read(payloadNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}
	out = append(out, payloadNonce...)
	out = dekGCM.Seal(out, payloadNonce, plaintext, out[:headerSize])
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
