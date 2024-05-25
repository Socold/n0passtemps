package recovery

import (
	"strings"
	"testing"
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

// TestGenerateRefusesNonPositiveCount covers the argument guard.
func TestGenerateRefusesNonPositiveCount(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := Generate(n); err == nil {
			t.Errorf("Generate(%d) returned no error", n)
		}
	}
}
