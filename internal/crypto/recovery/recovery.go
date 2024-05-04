// Package recovery generates and verifies single-use account recovery codes.
//
// Recovery codes are hashed, not encrypted. The server never needs to read a
// code back: it only needs to decide whether a code presented by a user matches
// one it issued. Hashing rather than sealing under the KEK has two consequences
// that matter operationally. Losing the KEK does not invalidate recovery codes,
// so a KEK loss stays recoverable through re-enrolment. And a stolen database
// yields no usable codes even if the attacker also holds the KEK.
//
// Each code is split into a selector and a verifier:
//
//	MC4TK-B9YQZ-3HDWR-7FGNP
//	^^^^^^ selector           stored in clear, indexed, used to find the row
//	       ^^^^^^^^^^^^^^^^^^ verifier, stored only as an Argon2id hash
//
// The selector makes verification a single indexed lookup followed by one
// Argon2id evaluation. Hashing every stored code on each attempt would cost one
// evaluation per issued code, which is both slow and a denial-of-service
// vector.
package recovery

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// Code layout. The alphabet is Crockford base32 without I, L, O and U, which
// removes the character pairs users most often transcribe wrongly.
const (
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	selectorLen = 6  // 30 bits, enough to keep collisions negligible
	verifierLen = 14 // 70 bits, far beyond any offline search
	groupLen    = 5

	// CodeLen is the number of significant characters in a code, excluding
	// the group separators.
	CodeLen = selectorLen + verifierLen
)

// Argon2id parameters. These follow the OWASP Password Storage Cheat Sheet
// baseline of m=19456 KiB, t=2, p=1. A recovery code already carries 70 bits of
// entropy, so the hash is defence in depth rather than the primary barrier;
// the baseline is kept so the cost is well understood rather than invented.
const (
	argonTime    = 2
	argonMemory  = 19456 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

var (
	ErrMalformedCode = errors.New("recovery: malformed code")
	ErrBadHash       = errors.New("recovery: malformed stored hash")
)

// Code is a freshly generated recovery code, ready to be shown to the user
// exactly once.
type Code struct {
	// Display is the grouped human-readable form, for example
	// "MC4TK-B9YQZ-3HDWR-7FGNP".
	Display string
	// Selector is the clear-text lookup key to persist and index.
	Selector string
	// Hash is the Argon2id encoding of the verifier, to persist.
	Hash string
}

// Generate returns n independent recovery codes.
//
// The caller must present Display to the user and persist only Selector and
// Hash. Display is not recoverable afterwards, by design.
func Generate(n int) ([]Code, error) {
	if n <= 0 {
		return nil, fmt.Errorf("recovery: code count must be positive, got %d", n)
	}
	out := make([]Code, 0, n)
	seen := make(map[string]struct{}, n)

	for len(out) < n {
		raw, err := randomChars(CodeLen)
		if err != nil {
			return nil, err
		}
		selector := string(raw[:selectorLen])
		if _, dup := seen[selector]; dup {
			// A 30-bit collision inside one batch is vanishingly unlikely,
			// but a duplicate selector would make one code unreachable, so
			// draw again rather than rely on the odds.
			zeroize.Bytes(raw)
			continue
		}
		seen[selector] = struct{}{}

		verifier := raw[selectorLen:]

		hash, err := hashVerifier(verifier)
		zeroize.Bytes(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, Code{
			Display:  format(selector + strings.ToUpper(string(verifier))),
			Selector: selector,
			Hash:     hash,
		})
	}
	return out, nil
}

// Split normalises a user-supplied code and separates its selector from its
// verifier. Lowercase input, whitespace and separators are accepted, and the
// Crockford homoglyphs I, L and O are folded onto 1, 1 and 0.
func Split(input string) (selector string, verifier []byte, err error) {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range strings.ToUpper(input) {
		switch r {
		case '-', ' ', '\t', '_':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		case 'U':
			// Not in the alphabet and not a safe fold; reject below.
		}
		if !strings.ContainsRune(alphabet, r) {
			return "", nil, fmt.Errorf("%w: unexpected character %q", ErrMalformedCode, r)
		}
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) != CodeLen {
		return "", nil, fmt.Errorf("%w: expected %d characters, got %d", ErrMalformedCode, CodeLen, len(s))
	}
	return s[:selectorLen], []byte(s[selectorLen:]), nil
}

// Verify reports whether verifier matches storedHash.
//
// The comparison is constant time. A malformed stored hash returns an error
// rather than false, so a corrupted row is not silently read as a failed
// attempt.
func Verify(verifier []byte, storedHash string) (bool, error) {
	salt, want, err := decodeHash(storedHash)
	if err != nil {
		return false, err
	}
	defer zeroize.Bytes(salt)
	defer zeroize.Bytes(want)

	got := argon2.IDKey(verifier, salt, argonTime, argonMemory, argonThreads, uint32(len(want)))
	defer zeroize.Bytes(got)

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func hashVerifier(verifier []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("recovery: generate salt: %w", err)
	}
	defer zeroize.Bytes(salt)

	sum := argon2.IDKey(verifier, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer zeroize.Bytes(sum)

	// PHC string format, so the parameters travel with the hash and can be
	// raised later without invalidating existing rows.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

func decodeHash(s string) (salt, sum []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("%w: not an argon2id PHC string", ErrBadHash)
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, fmt.Errorf("%w: version: %v", ErrBadHash, err)
	}
	if version != argon2.Version {
		return nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrBadHash, version)
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, fmt.Errorf("%w: parameters: %v", ErrBadHash, err)
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, nil, fmt.Errorf("%w: salt: %v", ErrBadHash, err)
	}
	if sum, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		zeroize.Bytes(salt)
		return nil, nil, fmt.Errorf("%w: hash: %v", ErrBadHash, err)
	}
	if len(sum) == 0 {
		zeroize.Bytes(salt)
		return nil, nil, fmt.Errorf("%w: empty hash", ErrBadHash)
	}
	return salt, sum, nil
}

// randomChars draws n characters uniformly from the alphabet.
//
// len(alphabet) is 32, a divisor of 256, so masking the low 5 bits of a random
// byte is already uniform and no rejection sampling is needed.
func randomChars(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("recovery: read random: %w", err)
	}
	for i := range buf {
		buf[i] = alphabet[buf[i]&0x1f]
	}
	return buf, nil
}

func format(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%groupLen == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
