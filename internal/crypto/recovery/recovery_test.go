package recovery

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestGeneratedCodeVerifies is the property the whole feature rests on: a code
// as it is shown to the user must verify against the hash that was stored
// alongside it.
//
// It is written as an explicit round trip because the two halves are produced a
// few lines apart in Generate, and an earlier revision zeroized the random
// buffer before building the displayed form. Since the verifier is a slice of
// that buffer, every issued code came out as null bytes and none of them could
// ever be redeemed. Nothing in the unit surface caught it; only redeeming a
// code does.
func TestGeneratedCodeVerifies(t *testing.T) {
	codes, err := Generate(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 16 {
		t.Fatalf("generated %d codes, want 16", len(codes))
	}

	for i, c := range codes {
		selector, verifier, err := Split(c.Display)
		if err != nil {
			t.Fatalf("code %d (%q) does not parse: %v", i, c.Display, err)
		}
		if selector != c.Selector {
			t.Errorf("code %d: parsed selector %q, stored %q", i, selector, c.Selector)
		}

		ok, err := Verify(verifier, c.Hash)
		if err != nil {
			t.Fatalf("code %d: verify returned an error: %v", i, err)
		}
		if !ok {
			t.Errorf("code %d (%q) does not verify against its own stored hash", i, c.Display)
		}
	}
}

// TestDisplayedCodeIsPrintable guards the same failure from the other side.
func TestDisplayedCodeIsPrintable(t *testing.T) {
	codes, err := Generate(4)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		for _, r := range c.Display {
			if r == '-' {
				continue
			}
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("%q contains %q, which is outside the alphabet", c.Display, r)
			}
		}
		// Four groups of five, separated by hyphens.
		if got := len(c.Display); got != CodeLen+3 {
			t.Errorf("%q is %d characters, want %d", c.Display, got, CodeLen+3)
		}
	}
}

// TestSelectorsAreUniqueWithinABatch checks that no issued code is unreachable.
//
// Two codes sharing a selector would mean one of them could never be looked up,
// so the user would hold a code that silently does not work.
func TestSelectorsAreUniqueWithinABatch(t *testing.T) {
	codes, err := Generate(64)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int, len(codes))
	for i, c := range codes {
		if prev, dup := seen[c.Selector]; dup {
			t.Fatalf("codes %d and %d share the selector %q", prev, i, c.Selector)
		}
		seen[c.Selector] = i
	}
}

// TestWrongVerifierIsRefused checks the obvious negative.
func TestWrongVerifierIsRefused(t *testing.T) {
	codes, err := Generate(2)
	if err != nil {
		t.Fatal(err)
	}

	_, verifier, err := Split(codes[0].Display)
	if err != nil {
		t.Fatal(err)
	}

	// The second code's hash must not accept the first code's verifier.
	ok, err := Verify(verifier, codes[1].Hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("one code's verifier matched another code's hash")
	}
}

// TestSplitNormalisation covers the transcription forgiveness the format is
// designed around.
func TestSplitNormalisation(t *testing.T) {
	codes, err := Generate(1)
	if err != nil {
		t.Fatal(err)
	}
	canonical := codes[0].Display

	for name, variant := range map[string]string{
		"as issued":         canonical,
		"lowercase":         strings.ToLower(canonical),
		"no separators":     strings.ReplaceAll(canonical, "-", ""),
		"spaces instead":    strings.ReplaceAll(canonical, "-", " "),
		"underscores":       strings.ReplaceAll(canonical, "-", "_"),
		"surrounding space": "  " + canonical + "  ",
		"tab separated":     strings.ReplaceAll(canonical, "-", "\t"),
	} {
		t.Run(name, func(t *testing.T) {
			selector, verifier, err := Split(variant)
			if err != nil {
				t.Fatalf("%q was refused: %v", variant, err)
			}
			if selector != codes[0].Selector {
				t.Errorf("selector = %q, want %q", selector, codes[0].Selector)
			}
			ok, err := Verify(verifier, codes[0].Hash)
			if err != nil || !ok {
				t.Errorf("verify = %v, %v; want true, nil", ok, err)
			}
		})
	}
}

// TestSplitRefusesMalformed checks that rubbish is rejected before any hashing
// work is done.
func TestSplitRefusesMalformed(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"too short":       "ABCDE",
		"too long":        "ABCDE-FGHJK-MNPQR-STVWX-YZ012",
		"non alphabet":    "ABCDE-FGHJK-MNPQR-STVW!",
		"letter u":        "UBCDE-FGHJK-MNPQR-STVWX",
		"only separators": "--------------------",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Split(input); err == nil {
				t.Errorf("%q was accepted", input)
			}
		})
	}
}

// TestHomoglyphFolding checks the Crockford substitutions.
//
// The alphabet omits I, L, O and U so that a user reading a code off paper
// cannot produce an ambiguous character. The three that have an unambiguous
// numeric counterpart are folded onto it rather than refused, because a user
// who typed a letter O meant a zero.
func TestHomoglyphFolding(t *testing.T) {
	for _, tc := range []struct{ typed, folds string }{
		{"I", "1"}, {"i", "1"}, {"L", "1"}, {"l", "1"}, {"O", "0"}, {"o", "0"},
	} {
		// Build a code shaped correctly but containing the homoglyph, and
		// check it parses to the folded character.
		input := tc.typed + "2345-67890-12345-67890"
		selector, _, err := Split(input)
		if err != nil {
			t.Fatalf("%q was refused: %v", input, err)
		}
		if got := selector[:1]; got != tc.folds {
			t.Errorf("%q folded to %q, want %q", tc.typed, got, tc.folds)
		}
	}

	// U has no unambiguous counterpart, so it is refused rather than guessed.
	if _, _, err := Split("U2345-67890-12345-67890"); err == nil {
		t.Error("the letter U was accepted; it is not in the alphabet and has no safe fold")
	}
}

// TestVerifyRejectsMalformedStoredHash checks that a corrupted row is reported
// rather than silently read as a failed attempt.
func TestVerifyRejectsMalformedStoredHash(t *testing.T) {
	for name, hash := range map[string]string{
		"empty":           "",
		"not phc":         "deadbeef",
		"wrong algorithm": "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"truncated":       "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA",
		"bad salt":        "$argon2id$v=19$m=19456,t=2,p=1$!!!!$aGFzaA",
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := Verify([]byte("whatever"), hash)
			if err == nil {
				t.Error("a malformed stored hash returned no error, so a corrupted row " +
					"would look like an ordinary failed attempt")
			}
			if ok {
				t.Error("a malformed stored hash verified")
			}
		})
	}
}

// phc builds a stored hash by hand, under parameters of the test's choosing.
func phc(verifier, salt []byte, m, t uint32, p uint8) string {
	sum := argon2.IDKey(verifier, salt, t, m, p, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, t, p,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
}

// TestAHashWrittenUnderOtherParametersStillVerifies is the promise the PHC
// format makes and that Verify once broke: it parsed m, t and p, discarded
// them, and recomputed with the constants of the package. Every test passed,
// because every hash in them had been written under those same constants. The
// day the constants were raised, every recovery code and enrolment ticket
// already issued would have stopped verifying, with no error to say why.
//
// The parameters below differ from the constants in all three positions, and
// are small so the test stays quick.
func TestAHashWrittenUnderOtherParametersStillVerifies(t *testing.T) {
	const (
		memory  = 64
		time    = 1
		threads = 2
	)
	if memory == argonMemory || time == argonTime || threads == argonThreads {
		t.Fatal("the parameters of this test match the constants, so it proves nothing")
	}

	verifier := []byte("3HDWR7FGNPB9YQ")
	stored := phc(verifier, []byte("0123456789abcdef"), memory, time, threads)

	ok, err := Verify(verifier, stored)
	if err != nil {
		t.Fatalf("verify returned an error: %v", err)
	}
	if !ok {
		t.Error("a hash written under other parameters does not verify, so raising the " +
			"constants would invalidate every row already stored")
	}

	// The stored parameters are used, not merely tolerated.
	ok, err = Verify([]byte("3HDWR7FGNPB9YR"), stored)
	if err != nil {
		t.Fatalf("verify returned an error: %v", err)
	}
	if ok {
		t.Error("a wrong verifier matched a hash written under other parameters")
	}
}

// TestVerifyRefusesParametersNoRowShouldCarry checks the other side of reading
// the parameters from the row: a row is input, and a forged one must not be
// able to ask for gigabytes of memory, or reach the panics argon2 keeps for a
// time or a parallelism of zero.
//
// Every case is a well-formed PHC string, so the refusal can only come from the
// bounds. None of them may reach argon2, which the largest would show by taking
// the test machine's memory with it.
func TestVerifyRefusesParametersNoRowShouldCarry(t *testing.T) {
	const tail = "$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

	for name, hash := range map[string]string{
		"memory above the ceiling":      "$argon2id$v=19$m=262145,t=2,p=1" + tail,
		"memory at the uint32 limit":    "$argon2id$v=19$m=4294967295,t=2,p=1" + tail,
		"memory of zero":                "$argon2id$v=19$m=0,t=2,p=1" + tail,
		"time above the ceiling":        "$argon2id$v=19$m=19456,t=17,p=1" + tail,
		"time of zero":                  "$argon2id$v=19$m=19456,t=0,p=1" + tail,
		"parallelism above the ceiling": "$argon2id$v=19$m=19456,t=2,p=17" + tail,
		"parallelism of zero":           "$argon2id$v=19$m=19456,t=2,p=0" + tail,
		"parallelism beyond a byte":     "$argon2id$v=19$m=19456,t=2,p=256" + tail,
		"negative memory":               "$argon2id$v=19$m=-1,t=2,p=1" + tail,
		"salt of seven bytes": "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Ng" +
			"$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := Verify([]byte("whatever"), hash)
			if !errors.Is(err, ErrBadHash) {
				t.Errorf("err = %v, want ErrBadHash", err)
			}
			if ok {
				t.Error("a stored hash with refused parameters verified")
			}
		})
	}
}

// TestVerifyAcceptsParametersAtTheirBounds keeps the ceilings honest from the
// inside: the largest time and parallelism a row may carry, and the shortest
// salt, are accepted. Memory is left small, since 256 MiB under the race
// detector is a slow way to learn that a comparison is not off by one.
func TestVerifyAcceptsParametersAtTheirBounds(t *testing.T) {
	verifier := []byte("3HDWR7FGNPB9YQ")
	stored := phc(verifier, []byte("01234567"), 8*maxStoredThreads, maxStoredTime, maxStoredThreads)

	ok, err := Verify(verifier, stored)
	if err != nil {
		t.Fatalf("parameters at their bounds were refused: %v", err)
	}
	if !ok {
		t.Error("a hash with parameters at their bounds does not verify")
	}
}

// TestGenerateRefusesNonPositiveCount covers the argument guard.
func TestGenerateRefusesNonPositiveCount(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := Generate(n); err == nil {
			t.Errorf("Generate(%d) returned no error", n)
		}
	}
}
