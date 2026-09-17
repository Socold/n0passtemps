// Package totp implements time-based one-time passwords, RFC 6238, over the
// HMAC counter construction of RFC 4226.
//
// The default hash is SHA1, which RFC 6238 requires for interoperability with
// the authenticator applications people already have: HMAC does not inherit
// the collision weakness of the bare hash. See the Algorithm type.
//
// Counter-based HOTP is not offered as a factor. A counter factor needs its own
// look-ahead window and resynchronisation policy, which is a second anti-replay
// surface to get right for no benefit to a passwordless deployment. Only the
// dynamic truncation of RFC 4226 section 5.3 is shared, and it stays
// unexported.
//
// The package keeps no state. Anti-replay is the caller's responsibility: it
// persists the highest timestep already spent for a secret and hands it to
// Verify, which refuses to match at or below that mark. See the LastTimestep
// field of store.TOTPSecret.
package totp

import (
	"crypto/hmac"
	"crypto/rand"

	// #nosec G505 -- RFC 6238 interoperability requires HMAC-SHA1; see the Algorithm doc comment
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// MinSecretBytes is the shortest shared secret this package will generate.
//
// RFC 4226 section 4 requirement R6 obliges an implementation to use a shared
// secret of at least 128 bits and recommends 160. Authenticator applications
// all handle 160, so there is no compatibility reason to go below it.
const MinSecretBytes = 20

// Errors a caller may need to distinguish. A failed verification is not among
// them: Verify reports only whether the code matched, so that no caller can
// turn it into an oracle.
var (
	ErrInvalidAlgorithm = errors.New("totp: unsupported algorithm")
	ErrInvalidParams    = errors.New("totp: invalid parameters")
	ErrShortSecret      = errors.New("totp: shared secret too short")
	ErrInvalidLabel     = errors.New("totp: invalid provisioning label")
	ErrTimeBeforeEpoch  = errors.New("totp: instant precedes the Unix epoch")
)

// Algorithm names the HMAC hash function of RFC 6238 section 1.2.
//
// SHA1 stays the default despite its collision weakness. HMAC does not inherit
// that weakness, and it is the only algorithm every authenticator application
// implements: an unreadable QR code is a worse outcome than a theoretical one.
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// Valid reports whether a is one of the three algorithms RFC 6238 defines.
func (a Algorithm) Valid() bool {
	switch a {
	case SHA1, SHA256, SHA512:
		return true
	default:
		return false
	}
}

// hash returns the constructor for a. The caller must have checked Valid
// first; an unknown algorithm yields nil rather than a silent fallback to
// SHA1, because a silent downgrade is exactly what an attacker would want.
func (a Algorithm) hash() func() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return nil
	}
}

// Params are the per-secret generation parameters. They are persisted
// alongside the secret, because changing them invalidates every enrolled
// authenticator.
type Params struct {
	Algorithm Algorithm
	Digits    int
	Period    time.Duration

	// Skew is the number of timesteps either side of the current one that
	// Verify will accept, to absorb clock drift between the client and the
	// server. Each extra step widens the window an attacker may guess in, so
	// it is kept small; the configuration layer narrows it further.
	Skew int
}

// MaxDigits is the longest code the RFC 4226 truncation can produce without
// the leading digit being heavily biased. Dynamic truncation yields a 31-bit
// value, so ten digits would only ever start with 0, 1 or 2.
const MaxDigits = 8

// Validate reports whether p can be used to generate or verify codes.
//
// The bounds here are those the algorithm imposes. Deployment policy is
// narrower and lives in the configuration layer.
func (p Params) Validate() error {
	if !p.Algorithm.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidAlgorithm, p.Algorithm)
	}
	// RFC 4226 section 5.3 requires at least six digits.
	if p.Digits < 6 || p.Digits > MaxDigits {
		return fmt.Errorf("%w: digits must be between 6 and %d, got %d", ErrInvalidParams, MaxDigits, p.Digits)
	}
	if p.Period <= 0 {
		return fmt.Errorf("%w: period must be positive, got %s", ErrInvalidParams, p.Period)
	}
	// RFC 6238 section 4.1 defines the time step X in seconds. A sub-second
	// remainder would make the step boundaries disagree with every client.
	if p.Period%time.Second != 0 {
		return fmt.Errorf("%w: period must be a whole number of seconds, got %s", ErrInvalidParams, p.Period)
	}
	if p.Skew < 0 {
		return fmt.Errorf("%w: skew must not be negative, got %d", ErrInvalidParams, p.Skew)
	}
	return nil
}

// GenerateSecret returns n cryptographically random bytes for use as a shared
// secret.
//
// The caller owns the result and must zeroize it once it has been sealed.
func GenerateSecret(n int) ([]byte, error) {
	if n < MinSecretBytes {
		return nil, fmt.Errorf("%w: RFC 4226 section 4 requires at least 128 bits and recommends 160, got %d bytes",
			ErrShortSecret, n)
	}
	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("totp: read random: %w", err)
	}
	return secret, nil
}

// Timestep returns the RFC 6238 section 4.2 counter value T for the instant t.
//
// It returns 0 when p.Period is not positive, so a caller that skipped
// Validate gets a useless answer rather than a panic.
func Timestep(p Params, t time.Time) int64 {
	step := int64(p.Period / time.Second)
	if step <= 0 {
		return 0
	}
	secs := t.Unix()
	// Go truncates integer division towards zero, which would place instants
	// before the Unix epoch in the wrong step. Floor the quotient instead.
	if secs < 0 {
		return -((-secs + step - 1) / step)
	}
	return secs / step
}

// counterFor maps a timestep onto the RFC 4226 section 5.1 counter.
//
// The counter is an unsigned 64-bit quantity, so a negative timestep has no
// counter: ok is false. Converting it would wrap to a counter near 2^64 and
// change the HMAC input to one no authenticator would ever compute, which is
// a wrong answer dressed up as a right one.
func counterFor(step int64) (counter uint64, ok bool) {
	if step < 0 {
		return 0, false
	}
	return uint64(step), true
}

// Code returns the code for the timestep containing t, zero-padded to
// p.Digits.
//
// It reports ErrTimeBeforeEpoch for an instant before 1970-01-01T00:00:00Z,
// whose timestep is negative and therefore not a valid counter.
func Code(secret []byte, p Params, t time.Time) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("%w: secret is empty", ErrShortSecret)
	}
	counter, ok := counterFor(Timestep(p, t))
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrTimeBeforeEpoch, t.UTC().Format(time.RFC3339))
	}
	return codeForStep(secret, p, counter), nil
}

// Verify reports whether presented is the code for a timestep inside the
// tolerance window around t, and returns the timestep that matched.
//
// lastStep is the highest timestep already spent for this secret. Any
// candidate at or below it is refused, which makes a code single-use even
// while it is still inside its own validity period. The caller must persist
// the returned step before acting on a successful verification, or the replay
// barrier does not exist.
//
// On failure the returned step is 0 and ok is false, with no indication of
// whether the code was wrong, malformed or already spent. Those three
// outcomes must stay indistinguishable: telling an attacker that a code was
// correct but spent confirms the code, and telling them a code was rejected
// early confirms that somebody else has just authenticated.
func Verify(secret []byte, p Params, presented string, t time.Time, lastStep int64) (step int64, ok bool) {
	if err := p.Validate(); err != nil || len(secret) == 0 {
		return 0, false
	}

	// Normalise and length-check before touching the secret. A string that
	// cannot possibly be a code is not worth 2*Skew+1 HMAC evaluations, and
	// its shape is not a secret: the attacker chose it.
	candidate, valid := normalise(presented, p.Digits)
	if !valid {
		return 0, false
	}

	now := Timestep(p, t)
	// An instant before the Unix epoch has no counter, so no code can be
	// verified against it. It is refused like any other failure, without
	// saying why.
	if now < 0 {
		return 0, false
	}
	var matched int
	var matchedStep int64

	// Every step in the window is evaluated, including those already spent.
	// Skipping the spent ones would make a replay measurably faster to reject
	// than a wrong code, which leaks the state of the replay counter. The
	// window is at most a handful of steps, so the fixed cost is negligible.
	for s := now - int64(p.Skew); s <= now+int64(p.Skew); s++ {
		// Within Skew steps of the epoch the low end of the window is
		// negative and has no counter. Such a step is still evaluated, on
		// counter 0, and its comparison forced to a miss, so the loop costs
		// the same number of HMAC evaluations at every instant.
		counter, inRange := counterFor(s)
		code := codeForStep(secret, p, counter)
		// Constant-time comparison: a byte-wise early exit would reveal how
		// many leading digits of a guess were right, which turns a 10^6 search
		// into 6 searches of 10.
		eq := subtle.ConstantTimeCompare([]byte(code), []byte(candidate))
		fresh := ctGreater(s, lastStep)
		hit := eq & fresh & boolToInt(inRange)

		matched |= hit
		// Branch-free select, so the loop takes the same path whether or not
		// this step is the one that matched.
		mask := -int64(hit)
		matchedStep ^= mask & (s ^ matchedStep)
	}

	if matched != 1 {
		return 0, false
	}
	return matchedStep, true
}

// ProvisioningURI returns the otpauth URI to encode in an enrolment QR code,
// following the Key Uri Format that authenticator applications implement.
//
// The returned string carries the shared secret in clear. It is as sensitive
// as the secret itself, it cannot be zeroized because Go strings are
// immutable, and it must never be logged.
func ProvisioningURI(issuer, accountName string, secret []byte, p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("%w: secret is empty", ErrShortSecret)
	}
	if issuer == "" || accountName == "" {
		return "", fmt.Errorf("%w: issuer and account name are required", ErrInvalidLabel)
	}
	// The colon is the label delimiter, so neither half may contain one: a
	// crafted account name would otherwise re-brand the entry under a
	// different issuer in the user's authenticator.
	if strings.ContainsRune(issuer, ':') || strings.ContainsRune(accountName, ':') {
		return "", fmt.Errorf("%w: issuer and account name must not contain a colon", ErrInvalidLabel)
	}

	// Base32 without padding. The trailing "=" of padded base32 is legal but
	// several widely deployed authenticator applications reject or mangle it,
	// so the unpadded form is the only interoperable one.
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	buf := make([]byte, enc.EncodedLen(len(secret)))
	enc.Encode(buf, secret)
	b32 := string(buf)
	// The string copy above cannot be reclaimed, but the buffer can.
	zeroize.Bytes(buf)

	q := url.Values{}
	q.Set("secret", b32)
	q.Set("issuer", issuer)
	q.Set("algorithm", string(p.Algorithm))
	q.Set("digits", strconv.Itoa(p.Digits))
	q.Set("period", strconv.FormatInt(int64(p.Period/time.Second), 10))

	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		// The label repeats the issuer as a prefix. Applications that predate
		// the issuer parameter read the prefix instead, and those that read
		// both expect the two to agree.
		Path:     "/" + issuer + ":" + accountName,
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}

// boolToInt maps a boolean onto the 0 or 1 that the helpers of crypto/subtle
// work with.
//
// The branch is safe here: its condition is derived from the clock, never
// from secret material or from the code presented.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// codeForStep computes the code for one counter value. Params must already be
// valid.
func codeForStep(secret []byte, p Params, counterValue uint64) string {
	var counter [8]byte
	// RFC 4226 section 5.1: the counter is an 8-byte big-endian value.
	binary.BigEndian.PutUint64(counter[:], counterValue)

	mac := hmac.New(p.Algorithm.hash(), secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	// The MAC is a deterministic function of the secret, so it is treated as
	// key material. The copy hmac holds internally is beyond reach.
	defer zeroize.Bytes(sum)

	return fmt.Sprintf("%0*d", p.Digits, truncate(sum, p.Digits))
}

// truncate is the dynamic truncation of RFC 4226 section 5.3, shared with
// nothing else: HOTP is not exposed, see the package comment.
func truncate(sum []byte, digits int) uint32 {
	offset := sum[len(sum)-1] & 0x0f
	// The high bit is masked off so the result is a positive 31-bit integer on
	// every platform, signed or not.
	binCode := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return binCode % pow10[digits]
}

var pow10 = [MaxDigits + 1]uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

// normalise strips the grouping a user or an authenticator may have added and
// requires exactly digits ASCII digits.
//
// Only ASCII digits count. A code typed with Arabic-Indic or fullwidth digits
// is refused rather than folded: accepting several spellings of one code would
// mean the replay counter and the comparison disagree about what was
// presented.
func normalise(presented string, digits int) (string, bool) {
	var b strings.Builder
	b.Grow(len(presented))
	for i := 0; i < len(presented); i++ {
		switch c := presented[i]; {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == ' ' || c == '\t' || c == '-' || c == '_':
			// Grouping separators carry no information.
		default:
			return "", false
		}
	}
	s := b.String()
	if len(s) != digits {
		return "", false
	}
	return s, true
}

// ctGreater returns 1 when a > b and 0 otherwise, without a data-dependent
// branch.
func ctGreater(a, b int64) int {
	// Biasing by 2^63 maps the signed order onto the unsigned one, so the
	// borrow is correct for negative timesteps too. bits.Sub64 exposes the
	// borrow directly, which a shift of the wrapped difference would not do
	// correctly for large operands.
	const bias = uint64(1) << 63
	// The uint64 conversions reinterpret the bit pattern on purpose: the bias
	// trick needs the two's-complement encoding, not the numeric value, and
	// xor with 2^63 restores the signed ordering.
	// #nosec G115 -- two's-complement reinterpretation of a signed timestep, the wrap is what the bias relies on
	_, borrow := bits.Sub64(uint64(b)^bias, uint64(a)^bias, 0)
	// #nosec G115 -- bits.Sub64 defines borrow as 0 or 1, which every int holds
	return int(borrow)
}
