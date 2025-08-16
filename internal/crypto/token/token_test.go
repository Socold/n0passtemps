package token

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// Fixed, well-formed parts used to build malformed variants. Each refusal case
// changes one thing relative to this baseline, so a refusal can only be due to
// that change.
const fixtureSelector = "3f9a2c1d8b7e6f5a"

func fixtureVerifier() string {
	raw := make([]byte, verifierBytes)
	for i := range raw {
		raw[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

var kinds = []struct {
	name string
	kind Kind
}{
	{"API key", KindAPIKey},
	{"admin token", KindAdmin},
}

func TestGenerateParseVerifyRoundTrip(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			tok, err := Generate(k.kind)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			p, err := Parse(tok.Display)
			if err != nil {
				t.Fatalf("the token shown to the operator does not parse: %v", err)
			}
			if p.Kind != k.kind {
				t.Errorf("parsed kind = %q, want %q", p.Kind, k.kind)
			}
			if p.Selector != tok.Selector {
				t.Errorf("parsed selector %q differs from the persisted selector %q: the lookup would miss", p.Selector, tok.Selector)
			}
			ok, err := p.Verify(tok.Hash)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("a freshly issued token does not verify against its own stored hash")
			}

			// The stored hash must not give the token away.
			if strings.Contains(tok.Hash, p.verifier) || strings.Contains(tok.Selector, p.verifier) {
				t.Fatal("a persisted field contains the verifier in clear")
			}

			other, err := Generate(k.kind)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			ok, err = p.Verify(other.Hash)
			if err != nil {
				t.Fatalf("Verify against another token's hash: %v", err)
			}
			if ok {
				t.Fatal("a token verified against the stored hash of a different token")
			}
		})
	}
}

func TestGenerateRefusesUnknownKind(t *testing.T) {
	for _, k := range []Kind{"", "npx", "NPT", "npt_"} {
		tok, err := Generate(k)
		if !errors.Is(err, ErrBadKind) || tok != nil {
			t.Errorf("Generate(%q) = (%v, %v), want (nil, ErrBadKind)", k, tok, err)
		}
	}
}

// Secret scanners and log redaction rules match on this shape. A drift in the
// format would leave leaked tokens undetected.
func TestDisplayFormat(t *testing.T) {
	format := regexp.MustCompile(`^(npt|npa)_[0-9a-f]{16}\.[A-Za-z0-9_-]{27}$`)
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				tok, err := Generate(k.kind)
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				if !format.MatchString(tok.Display) {
					t.Fatalf("token does not match the documented format %s", format)
				}
				if !strings.HasPrefix(tok.Display, string(k.kind)+"_") {
					t.Fatalf("token of kind %q carries the wrong prefix", k.kind)
				}
				if len(tok.Selector) != SelectorLen {
					t.Fatalf("selector is %d characters, the schema expects %d", len(tok.Selector), SelectorLen)
				}
			}
		})
	}
}

// A repeated selector would make two rows answer one lookup; a repeated
// verifier would mean the random source is not being used as intended. With 64
// and 160 random bits a collision in 1000 draws is not a plausible accident.
func TestGeneratedTokensAreUnique(t *testing.T) {
	const n = 1000
	selectors := make(map[string]struct{}, n)
	verifiers := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		tok, err := Generate(KindAPIKey)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		p, err := Parse(tok.Display)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, dup := selectors[p.Selector]; dup {
			t.Fatalf("selector repeated after %d tokens", i)
		}
		if _, dup := verifiers[p.verifier]; dup {
			t.Fatalf("verifier repeated after %d tokens", i)
		}
		selectors[p.Selector] = struct{}{}
		verifiers[p.verifier] = struct{}{}
	}
}

func TestHashIsBoundToKindAndSelector(t *testing.T) {
	ver := fixtureVerifier()
	const otherSelector = "0123456789abcdef"

	cases := []struct {
		name       string
		presented  string
		storedHash string
		failure    string
	}{
		{
			// An attacker who can write to the database copies the hash of an
			// API key they own into the admin token table, keeping selector
			// and verifier. The kind in the digest must defeat that.
			name:       "API key against a hash computed for the admin kind",
			presented:  "npt_" + fixtureSelector + "." + ver,
			storedHash: Hash(KindAdmin, fixtureSelector, ver),
			failure:    "an API key verified against an admin hash: a leaked API key could be promoted to the administrative surface",
		},
		{
			name:       "admin token against a hash computed for the API key kind",
			presented:  "npa_" + fixtureSelector + "." + ver,
			storedHash: Hash(KindAPIKey, fixtureSelector, ver),
			failure:    "an admin token verified against an API key hash",
		},
		{
			// Same idea within one table: the hash of a known token is moved
			// onto the row of a victim's selector.
			name:       "hash moved to a different selector",
			presented:  "npt_" + otherSelector + "." + ver,
			storedHash: Hash(KindAPIKey, fixtureSelector, ver),
			failure:    "a hash moved to another row still verified: the digest is not bound to its selector",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.presented)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ok, err := p.Verify(tc.storedHash)
			if err != nil {
				t.Fatalf("a well-formed hash that does not match is a plain refusal, not an error: %v", err)
			}
			if ok {
				t.Fatal(tc.failure)
			}
		})
	}

	// The end-to-end form of the kind attack: a real API key presented with
	// its prefix rewritten, against its own stored hash.
	t.Run("generated API key presented under the admin prefix", func(t *testing.T) {
		tok, err := Generate(KindAPIKey)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		p, err := Parse("npa_" + strings.TrimPrefix(tok.Display, "npt_"))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		ok, err := p.Verify(tok.Hash)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if ok {
			t.Fatal("an API key verified as an admin token after its prefix was rewritten")
		}
	})
}

func TestParseRefusesMalformedTokens(t *testing.T) {
	ver := fixtureVerifier()
	valid := "npt_" + fixtureSelector + "." + ver
	if _, err := Parse(valid); err != nil {
		t.Fatalf("the baseline token must parse, otherwise the refusals below prove nothing: %v", err)
	}
	if len(ver) != 27 {
		t.Fatalf("baseline verifier is %d characters, expected 27", len(ver))
	}

	replaceAt := func(s string, i int, c byte) string {
		b := []byte(s)
		b[i] = c
		return string(b)
	}

	cases := []struct {
		name      string
		presented string
	}{
		{"empty", ""},
		{"whitespace only", "  \t "},
		{"no prefix", fixtureSelector + "." + ver},
		{"prefix without underscore", "npt" + fixtureSelector + "." + ver},
		{"underscore without prefix", "_" + fixtureSelector + "." + ver},
		{"unknown prefix", "npx_" + fixtureSelector + "." + ver},
		// Kinds are matched exactly. Folding case here would create a second
		// spelling of every token that secret scanners do not know about.
		{"uppercase prefix", "NPT_" + fixtureSelector + "." + ver},
		// The selector is compared as text in the database, so a second
		// spelling of the same selector must not reach the query.
		{"uppercase hex selector", "npt_" + strings.ToUpper(fixtureSelector) + "." + ver},
		{"non-hex selector", "npt_" + replaceAt(fixtureSelector, 3, 'g') + "." + ver},
		{"short selector", "npt_" + fixtureSelector[:SelectorLen-1] + "." + ver},
		{"long selector", "npt_" + fixtureSelector + "0." + ver},
		{"empty selector", "npt_." + ver},
		{"missing dot", "npt_" + fixtureSelector + ver},
		{"empty verifier", "npt_" + fixtureSelector + "."},
		// Two shapes of padding: one that keeps the expected length and one
		// that is the padded encoding a careless client might send.
		{"verifier ending in padding, length preserved", "npt_" + fixtureSelector + "." + ver[:26] + "="},
		{"verifier with padding appended", "npt_" + fixtureSelector + "." + ver + "="},
		{"verifier one character short", "npt_" + fixtureSelector + "." + ver[:26]},
		{"verifier one character long", "npt_" + fixtureSelector + "." + ver + "A"},
		// The standard base64 alphabet. Accepting it would give some tokens
		// two valid spellings.
		{"verifier with '+'", "npt_" + fixtureSelector + "." + replaceAt(ver, 5, '+')},
		{"verifier with '/'", "npt_" + fixtureSelector + "." + replaceAt(ver, 5, '/')},
		{"verifier with a space inside", "npt_" + fixtureSelector + "." + replaceAt(ver, 5, ' ')},
		// 'B' leaves non-zero bits after the 160th: same decoded bytes, other
		// spelling. Strict decoding must refuse it.
		{"verifier with non-canonical trailing bits", "npt_" + fixtureSelector + "." + replaceAt(ver, 26, 'B')},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.presented)
			if err == nil {
				t.Fatal("a malformed token was accepted; it must be refused before any database lookup")
			}
			// One error for every defect: a finer error would tell a caller
			// which part of a guess was well formed.
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if p != nil {
				t.Fatal("a parsed value was returned alongside an error")
			}
		})
	}
}

// A corrupted row is an integrity problem for the operator, not a failed login.
// Reporting it as false would hide it among ordinary refusals.
func TestVerifyReportsMalformedStoredHashAsError(t *testing.T) {
	ver := fixtureVerifier()
	p, err := Parse("npt_" + fixtureSelector + "." + ver)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	good := Hash(KindAPIKey, fixtureSelector, ver)
	if ok, err := p.Verify(good); err != nil || !ok {
		t.Fatalf("baseline hash must verify, got (%v, %v)", ok, err)
	}
	digest := strings.TrimPrefix(good, "sha256:")

	cases := []struct {
		name   string
		stored string
	}{
		{"empty", ""},
		{"digest without the sha256: prefix", digest},
		{"prefix in the wrong case", "SHA256:" + digest},
		{"another algorithm label", "sha512:" + digest},
		{"prefix only", "sha256:"},
		{"non-hex digest", "sha256:" + strings.Repeat("zz", 32)},
		{"digest one byte short", "sha256:" + digest[:62]},
		{"digest one byte long", "sha256:" + digest + "00"},
		{"digest with an odd number of hex digits", "sha256:" + digest[:63]},
		// A truncated digest that still matched its prefix would cut the
		// work needed to forge a match.
		{"digest truncated to 16 bytes", "sha256:" + digest[:32]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := p.Verify(tc.stored)
			if ok {
				t.Fatal("a token verified against a malformed stored hash")
			}
			if !errors.Is(err, ErrBadHash) {
				t.Fatalf("got error %v, want ErrBadHash: a corrupted row must not read as a failed authentication", err)
			}
		})
	}
}

func TestFromAuthorizationHeader(t *testing.T) {
	accepted := []struct {
		name   string
		header string
	}{
		{"canonical scheme", "Bearer x"},
		// RFC 7235 makes the scheme case-insensitive and clients differ.
		{"lowercase scheme", "bearer x"},
		{"uppercase scheme", "BEARER x"},
		{"tab separator", "Bearer\tx"},
		{"surrounding spaces", "  Bearer x  "},
		{"several spaces before the value", "Bearer    x"},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			got, err := FromAuthorizationHeader(tc.header)
			if err != nil {
				t.Fatalf("a valid bearer header was refused: %v", err)
			}
			if got != "x" {
				t.Fatalf("extracted %q, want %q with no surrounding whitespace", got, "x")
			}
		})
	}

	refused := []struct {
		name   string
		header string
	}{
		{"empty header", ""},
		{"scheme alone", "Bearer"},
		{"scheme and a space, no value", "Bearer "},
		{"scheme and a tab, no value", "Bearer\t"},
		// Another scheme's credentials must never be read as a bearer token.
		{"Basic scheme", "Basic x"},
		// Without a separator check, any header starting with these six
		// letters would have its tail taken as a token.
		{"no separator after the scheme", "Bearerx"},
		{"value alone", "x"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			got, err := FromAuthorizationHeader(tc.header)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got error %v, want ErrInvalid", err)
			}
			if got != "" {
				t.Fatalf("returned %q alongside an error", got)
			}
		})
	}
}
