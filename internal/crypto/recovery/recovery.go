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
//
// # Why the selector stays at thirty bits
//
// The selector is unique per tenant, enforced by an index, so issuing a batch
// into a tenant that already holds n codes has roughly n/2^30 chance per code
// of colliding and being refused. That is negligible for as long as n stays
// bounded, and it did not: consumed codes used to be kept for the life of the
// account, so n only ever grew and a tenant with a long history would start
// seeing refusals on ordinary reissues.
//
// The answer is to bound n, which the janitor now does by removing codes spent
// longer ago than its retention window. Widening the selector was the obvious
// alternative and is the wrong one. The width is in the code the user holds:
// every printed sheet in circulation carries twenty significant characters,
// Split would refuse them the moment the constant moved, and an upgrade would
// invalidate exactly the codes people keep for the day they cannot sign in.
// Any change here has to accept both lengths for as long as the old sheets
// exist, which is a real design and not a constant.
//
// Enrolment tickets share the format and the same index, and are already
// bounded: the janitor deletes them at their expiry, consumed and revoked ones
// included, so nothing accumulates there to collide with.
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

	// 30 bits. Collisions stay negligible as long as the number of stored
	// codes per tenant stays bounded, which is the janitor's job; see the
	// package comment on why this is not simply made wider.
	selectorLen = 6
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

	// maxStoredHashLen bounds the digest a stored PHC string may carry. Verify
	// recomputes at the stored length, so that length is the one value from
	// the row that reaches argon2 as an output size. 64 bytes covers every
	// digest width this package has written or would write, and refusing more
	// keeps a damaged or crafted row from asking argon2 for a huge output.
	maxStoredHashLen = 64

	// Bounds on the cost parameters a stored PHC string may carry. Verify
	// recomputes with the parameters of the row, not with the constants above,
	// so without a ceiling a forged or damaged row could ask for gigabytes of
	// memory or minutes of work on an unauthenticated request. The ceilings sit
	// far above the baseline, which leaves room to raise it, and far below
	// anything that would hurt the host. The salt floor is the RFC 9106
	// minimum; this package has only ever written saltLen.
	maxStoredMemory  = 256 * 1024 // KiB, that is 256 MiB
	maxStoredTime    = 16
	maxStoredThreads = 16
	minStoredSaltLen = 8
)

// argonParams are the cost parameters read back from a stored PHC string.
type argonParams struct {
	memory  uint32 // KiB
	time    uint32
	threads uint8
}

// The errors this package reports. Both are deliberately coarse at the API
// boundary: which half of a code was wrong is exactly what an attacker is
// asking, and the caller answers a single generic refusal either way.
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

		// The displayed form is built before raw is zeroized. verifier is a
		// slice of raw, so zeroizing first would leave Display holding null
		// bytes and every issued code would be unusable.
		display := format(selector + string(verifier))

		hash, err := hashVerifier(verifier)
		zeroize.Bytes(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, Code{
			Display:  display,
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
	params, salt, want, err := decodeHash(storedHash)
	if err != nil {
		return false, err
	}
	defer zeroize.Bytes(salt)
	defer zeroize.Bytes(want)

	// The recomputation uses the cost parameters and the digest length of the
	// row, not the constants of this package, so a row written before the
	// constants were raised still verifies. decodeHash has bounded all of them
	// by this point: that is what keeps the conversion in range and stops a
	// crafted row from asking argon2 for an absurd amount of work or output.
	// #nosec G115 -- decodeHash rejects a stored hash longer than maxStoredHashLen (64 bytes)
	got := argon2.IDKey(verifier, salt, params.time, params.memory, params.threads, uint32(len(want)))
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

	// PHC string format, so the parameters travel with the hash. Verify reads
	// them back and recomputes with them, which is what allows the constants to
	// be raised later without invalidating existing rows. Such rows keep the
	// cost they were written under: nothing here rehashes them.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// decodeHash parses a stored PHC string and bounds everything in it that
// reaches argon2: the cost parameters, the salt and the digest length. Verify
// relies on that, and does no hashing work until this has returned.
func decodeHash(s string) (params argonParams, salt, sum []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, fmt.Errorf("%w: not an argon2id PHC string", ErrBadHash)
	}

	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: version: %v", ErrBadHash, err)
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrBadHash, version)
	}

	if params, err = decodeParams(parts[3]); err != nil {
		return argonParams{}, nil, nil, err
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("%w: salt: %v", ErrBadHash, err)
	}
	if len(salt) < minStoredSaltLen {
		zeroize.Bytes(salt)
		return argonParams{}, nil, nil,
			fmt.Errorf("%w: salt of %d bytes is shorter than %d", ErrBadHash, len(salt), minStoredSaltLen)
	}
	if sum, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		zeroize.Bytes(salt)
		return argonParams{}, nil, nil, fmt.Errorf("%w: hash: %v", ErrBadHash, err)
	}
	if len(sum) == 0 {
		zeroize.Bytes(salt)
		return argonParams{}, nil, nil, fmt.Errorf("%w: empty hash", ErrBadHash)
	}
	if len(sum) > maxStoredHashLen {
		zeroize.Bytes(salt)
		zeroize.Bytes(sum)
		return argonParams{}, nil, nil,
			fmt.Errorf("%w: hash of %d bytes exceeds %d", ErrBadHash, len(sum), maxStoredHashLen)
	}
	return params, salt, sum, nil
}

// decodeParams reads the m, t and p of a PHC string and refuses values no
// version of this package would have written.
//
// Zero is refused as well as the excess. argon2 panics on a time or a
// parallelism of zero, so a damaged row would otherwise take the request down
// with it instead of being reported.
func decodeParams(s string) (argonParams, error) {
	var p argonParams
	if _, err := fmt.Sscanf(s, "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, fmt.Errorf("%w: parameters: %v", ErrBadHash, err)
	}
	if p.memory == 0 || p.memory > maxStoredMemory {
		return argonParams{},
			fmt.Errorf("%w: memory of %d KiB is outside 1..%d", ErrBadHash, p.memory, maxStoredMemory)
	}
	if p.time == 0 || p.time > maxStoredTime {
		return argonParams{},
			fmt.Errorf("%w: time of %d is outside 1..%d", ErrBadHash, p.time, maxStoredTime)
	}
	if p.threads == 0 || p.threads > maxStoredThreads {
		return argonParams{},
			fmt.Errorf("%w: parallelism of %d is outside 1..%d", ErrBadHash, p.threads, maxStoredThreads)
	}
	return p, nil
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
