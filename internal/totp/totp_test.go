package totp

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rfcSeed reproduces the shared secrets of RFC 6238 Appendix B.
//
// The appendix prints one ASCII seed, "12345678901234567890", but its test
// data uses a seed as long as the HMAC block requires: 20 bytes for SHA1, 32
// for SHA256 and 64 for SHA512, obtained by repeating "1234567890" and
// truncating. Reading the table as though all three used the 20-byte seed
// produces wrong expectations for SHA256 and SHA512.
func rfcSeed(n int) []byte {
	const unit = "1234567890"
	return []byte(strings.Repeat(unit, n/len(unit)+1)[:n])
}

func TestRFC6238AppendixB(t *testing.T) {
	seeds := map[Algorithm][]byte{
		SHA1:   rfcSeed(20),
		SHA256: rfcSeed(32),
		SHA512: rfcSeed(64),
	}

	cases := []struct {
		unix   int64
		step   int64
		sha1   string
		sha256 string
		sha512 string
	}{
		{59, 0x0000000000000001, "94287082", "46119246", "90693936"},
		{1111111109, 0x00000000023523EC, "07081804", "68084774", "25091201"},
		{1111111111, 0x00000000023523ED, "14050471", "67062674", "99943326"},
		{1234567890, 0x000000000273EF07, "89005924", "91819424", "93441116"},
		{2000000000, 0x0000000003F940AA, "69279037", "90698825", "38618901"},
		{20000000000, 0x0000000027BC86AA, "65353130", "77737706", "47863826"},
	}

	for _, c := range cases {
		for _, alg := range []Algorithm{SHA1, SHA256, SHA512} {
			want := map[Algorithm]string{SHA1: c.sha1, SHA256: c.sha256, SHA512: c.sha512}[alg]
			name := strconv.FormatInt(c.unix, 10) + "/" + string(alg)
			t.Run(name, func(t *testing.T) {
				p := Params{Algorithm: alg, Digits: 8, Period: 30 * time.Second}
				at := time.Unix(c.unix, 0).UTC()

				if got := Timestep(p, at); got != c.step {
					t.Fatalf("Timestep = %#x, want %#x", got, c.step)
				}
				got, err := Code(seeds[alg], p, at)
				if err != nil {
					t.Fatalf("Code: %v", err)
				}
				if got != want {
					t.Fatalf("Code = %s, want %s", got, want)
				}
				// The same vector must verify through the public entry point.
				step, ok := Verify(seeds[alg], p, want, at, 0)
				if !ok || step != c.step {
					t.Fatalf("Verify = (%d, %v), want (%d, true)", step, ok, c.step)
				}
			})
		}
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	at := time.Unix(1234567890, 0).UTC()
	step := Timestep(p, at)

	code, err := Code(secret, p, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	if got, ok := Verify(secret, p, code, at, step-1); !ok || got != step {
		t.Fatalf("fresh code: Verify = (%d, %v), want (%d, true)", got, ok, step)
	}
	if got, ok := Verify(secret, p, code, at, step); ok {
		t.Fatalf("lastStep == step: Verify = (%d, %v), want (0, false)", got, ok)
	}
	if got, ok := Verify(secret, p, code, at, step+1); ok {
		t.Fatalf("lastStep > step: Verify = (%d, %v), want (0, false)", got, ok)
	}
}

// TestVerifyReplayWithinSkewWindow covers the case the replay barrier exists
// for: the code is still inside the tolerance window, so a second presentation
// would otherwise succeed.
func TestVerifyReplayWithinSkewWindow(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second, Skew: 1}
	at := time.Unix(1234567890, 0).UTC()
	step := Timestep(p, at)

	code, err := Code(secret, p, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	// One period later the code is still accepted by the skew window.
	later := at.Add(30 * time.Second)
	if got, ok := Verify(secret, p, code, later, 0); !ok || got != step {
		t.Fatalf("still in window: Verify = (%d, %v), want (%d, true)", got, ok, step)
	}
	// Once spent, it is refused even though the window still covers it.
	if got, ok := Verify(secret, p, code, later, step); ok {
		t.Fatalf("spent code accepted: Verify = (%d, %v)", got, ok)
	}
}

func TestVerifySkewWindow(t *testing.T) {
	secret := rfcSeed(20)
	at := time.Unix(1234567890, 0).UTC()
	base := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	now := Timestep(base, at)

	// Codes for the five steps centred on now.
	codes := map[int64]string{}
	for _, offset := range []int64{-2, -1, 0, 1, 2} {
		codes[offset] = codeForStep(secret, base, uint64(now+offset))
	}

	cases := []struct {
		skew   int
		accept []int64
	}{
		{0, []int64{0}},
		{1, []int64{-1, 0, 1}},
		{2, []int64{-2, -1, 0, 1, 2}},
	}

	for _, c := range cases {
		t.Run("skew"+strconv.Itoa(c.skew), func(t *testing.T) {
			p := base
			p.Skew = c.skew
			accepted := map[int64]bool{}
			for _, offset := range c.accept {
				accepted[offset] = true
			}

			for _, offset := range []int64{-2, -1, 0, 1, 2} {
				step, ok := Verify(secret, p, codes[offset], at, 0)
				if accepted[offset] {
					if !ok || step != now+offset {
						t.Errorf("offset %+d: Verify = (%d, %v), want (%d, true)", offset, step, ok, now+offset)
					}
					continue
				}
				if ok {
					t.Errorf("offset %+d: Verify = (%d, true), want rejection", offset, step)
				}
			}
		})
	}
}

func TestVerifyMalformedInput(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	at := time.Unix(1234567890, 0).UTC()

	valid, err := Code(secret, p, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	// The grouped spellings a user may type must reduce to the same code.
	grouped := []string{
		valid[:3] + " " + valid[3:],
		valid[:2] + " " + valid[2:4] + " " + valid[4:],
		" " + valid + " ",
		valid[:3] + "-" + valid[3:],
		valid[:3] + "\t" + valid[3:],
	}
	for _, in := range grouped {
		t.Run("grouped/"+in, func(t *testing.T) {
			if _, ok := Verify(secret, p, in, at, 0); !ok {
				t.Fatalf("Verify(%q) = false, want true after normalisation", in)
			}
		})
	}

	// Digits that are not ASCII digits are refused rather than folded.
	unicodeDigits := "١٢٣٤٥٦" // Arabic-Indic 123456
	fullwidth := "１２３４５６"     // fullwidth 123456

	rejected := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too_short", valid[:5]},
		{"too_long", valid + "0"},
		{"letters", "abcdef"},
		{"digits_and_letter", valid[:5] + "a"},
		{"separator_only", "------"},
		{"arabic_indic_digits", unicodeDigits},
		{"fullwidth_digits", fullwidth},
		{"newline", valid[:3] + "\n" + valid[3:]},
		{"plus_sign", "+" + valid[1:]},
	}
	for _, c := range rejected {
		t.Run("rejected/"+c.name, func(t *testing.T) {
			if step, ok := Verify(secret, p, c.in, at, 0); ok {
				t.Fatalf("Verify(%q) = (%d, true), want rejection", c.in, step)
			}
		})
	}
}

func TestProvisioningURIRoundTrip(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA256, Digits: 8, Period: 45 * time.Second}

	const issuer = "n0 passtemps"
	const account = "alice+test@example.com"

	raw, err := ProvisioningURI(issuer, account, secret, p)
	if err != nil {
		t.Fatalf("ProvisioningURI: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	if u.Scheme != "otpauth" {
		t.Errorf("scheme = %q, want otpauth", u.Scheme)
	}
	if u.Host != "totp" {
		t.Errorf("host = %q, want totp", u.Host)
	}
	if want := "/" + issuer + ":" + account; u.Path != want {
		t.Errorf("path = %q, want %q", u.Path, want)
	}
	// The label has to travel percent-encoded, or a space or a plus sign in it
	// would be re-read as a separator.
	if strings.Contains(u.EscapedPath(), " ") {
		t.Errorf("escaped path %q contains a raw space", u.EscapedPath())
	}

	q := u.Query()
	if got := q.Get("issuer"); got != issuer {
		t.Errorf("issuer = %q, want %q", got, issuer)
	}
	if got := q.Get("algorithm"); got != "SHA256" {
		t.Errorf("algorithm = %q, want SHA256", got)
	}
	if got := q.Get("digits"); got != "8" {
		t.Errorf("digits = %q, want 8", got)
	}
	if got := q.Get("period"); got != "45" {
		t.Errorf("period = %q, want 45", got)
	}

	b32 := q.Get("secret")
	if strings.Contains(b32, "=") {
		t.Errorf("secret %q carries base32 padding", b32)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if !bytes.Equal(decoded, secret) {
		t.Errorf("decoded secret = %q, want %q", decoded, secret)
	}
}

func TestProvisioningURIRejectsAmbiguousLabel(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}

	cases := []struct {
		name    string
		issuer  string
		account string
	}{
		{"empty_issuer", "", "alice"},
		{"empty_account", "acme", ""},
		{"colon_in_issuer", "ac:me", "alice"},
		{"colon_in_account", "acme", "ali:ce"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ProvisioningURI(c.issuer, c.account, secret, p); err == nil {
				t.Fatalf("ProvisioningURI(%q, %q) = nil error, want rejection", c.issuer, c.account)
			}
		})
	}
}

func TestGenerateSecret(t *testing.T) {
	if _, err := GenerateSecret(MinSecretBytes - 1); err == nil {
		t.Fatalf("GenerateSecret(%d) = nil error, want ErrShortSecret", MinSecretBytes-1)
	}

	a, err := GenerateSecret(32)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("len = %d, want 32", len(a))
	}
	b, err := GenerateSecret(32)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated secrets are identical")
	}
}

func TestParamsValidate(t *testing.T) {
	ok := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	cases := []struct {
		name string
		p    Params
	}{
		{"unknown_algorithm", Params{Algorithm: "MD5", Digits: 6, Period: 30 * time.Second}},
		{"empty_algorithm", Params{Digits: 6, Period: 30 * time.Second}},
		{"too_few_digits", Params{Algorithm: SHA1, Digits: 5, Period: 30 * time.Second}},
		{"too_many_digits", Params{Algorithm: SHA1, Digits: 9, Period: 30 * time.Second}},
		{"zero_period", Params{Algorithm: SHA1, Digits: 6}},
		{"negative_period", Params{Algorithm: SHA1, Digits: 6, Period: -30 * time.Second}},
		{"fractional_period", Params{Algorithm: SHA1, Digits: 6, Period: 1500 * time.Millisecond}},
		{"negative_skew", Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second, Skew: -1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.p.Validate(); err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			// Invalid parameters must not verify anything either.
			if _, accepted := Verify(rfcSeed(20), c.p, "000000", time.Unix(0, 0), 0); accepted {
				t.Fatal("Verify accepted a code under invalid parameters")
			}
		})
	}
}

func TestAlgorithmHashUnknownIsNil(t *testing.T) {
	// An unknown algorithm must not silently fall back to SHA1.
	if Algorithm("MD5").hash() != nil {
		t.Fatal("hash() for an unknown algorithm is not nil")
	}
}

func TestTimestepBeforeEpoch(t *testing.T) {
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}
	cases := []struct {
		unix int64
		want int64
	}{
		{0, 0},
		{29, 0},
		{30, 1},
		{-1, -1},
		{-30, -1},
		{-31, -2},
	}
	for _, c := range cases {
		if got := Timestep(p, time.Unix(c.unix, 0)); got != c.want {
			t.Errorf("Timestep(%d) = %d, want %d", c.unix, got, c.want)
		}
	}
	// A caller that skipped Validate gets 0 rather than a division by zero.
	if got := Timestep(Params{}, time.Unix(1234567890, 0)); got != 0 {
		t.Errorf("Timestep with zero period = %d, want 0", got)
	}
}

// A negative timestep is not a valid RFC 4226 counter. Code must report it,
// and Verify must refuse, rather than wrapping the step into a counter near
// 2^64 and computing an HMAC no authenticator would ever produce.
func TestCodeBeforeEpoch(t *testing.T) {
	secret := rfcSeed(20)
	p := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second}

	for _, unix := range []int64{-1, -30, -1234567890} {
		at := time.Unix(unix, 0).UTC()
		if _, err := Code(secret, p, at); !errors.Is(err, ErrTimeBeforeEpoch) {
			t.Errorf("Code at unix %d: err = %v, want ErrTimeBeforeEpoch", unix, err)
		}
		// The wrapped counter for this instant, had the conversion been left
		// to wrap, would have produced this code. No instant may accept it.
		wrapped := codeForStep(secret, p, uint64(Timestep(p, at)))
		if _, ok := Verify(secret, p, wrapped, at, 0); ok {
			t.Errorf("Verify accepted the wrapped-counter code at unix %d", unix)
		}
	}

	// The first valid instant is unaffected, and so is a step inside Skew of
	// the epoch, where the low end of the window is negative.
	if _, err := Code(secret, p, time.Unix(0, 0).UTC()); err != nil {
		t.Errorf("Code at the epoch: %v", err)
	}
	skewed := Params{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second, Skew: 1}
	at := time.Unix(0, 0).UTC()
	code, err := Code(secret, skewed, at)
	if err != nil {
		t.Fatalf("Code at the epoch with skew: %v", err)
	}
	// lastStep is -1 so that step 0 counts as fresh.
	if step, ok := Verify(secret, skewed, code, at, -1); !ok || step != 0 {
		t.Errorf("Verify at the epoch = (%d, %v), want (0, true)", step, ok)
	}
}

func TestCtGreater(t *testing.T) {
	cases := []struct {
		a, b int64
		want int
	}{
		{1, 0, 1},
		{0, 0, 0},
		{0, 1, 0},
		{-1, -2, 1},
		{-2, -1, 0},
		{1 << 62, -(1 << 62), 1},
		{-(1 << 62), 1 << 62, 0},
	}
	for _, c := range cases {
		if got := ctGreater(c.a, c.b); got != c.want {
			t.Errorf("ctGreater(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
