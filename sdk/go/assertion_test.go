package n0passtemps

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer   = "n0passtemps"
	testAudience = "3e1f0a52-7c1d-4b8e-9a60-5d2c4f6b8a90"
)

// testNow is the verifier's clock in every test below.
var testNow = time.Unix(1_789_000_000, 0)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// validClaims mirrors what the server signs: nbf a little before iat, exp
// sixty seconds after.
func validClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"sub": "5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c",
		"aud": testAudience,
		"iat": testNow.Unix(),
		"nbf": testNow.Unix() - 5,
		"exp": testNow.Unix() + 60,
		"jti": "Zm9vYmFyYmF6cXV4MTIzNA",
		"amr": []string{"webauthn", "webauthn-uv"},
		"cid": "AQIDBA",
	}
}

// sign assembles a compact JWS from a literal header, so that a test controls
// every byte of it.
func sign(t testing.TB, priv ed25519.PrivateKey, header string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64([]byte(header)) + "." + b64(payload)
	return input + "." + b64(ed25519.Sign(priv, []byte(input)))
}

func header(kid string) string {
	return `{"alg":"EdDSA","kid":"` + kid + `","typ":"JWT"}`
}

type fixture struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	kid      string
	verifier *Verifier
}

func newFixture(t testing.TB, opts ...VerifierOption) *fixture {
	t.Helper()
	pub, priv := newKey(t)
	keys, err := NewStaticKeys(pub)
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]VerifierOption{WithClock(func() time.Time { return testNow })}, opts...)
	v, err := NewVerifier(testIssuer, testAudience, keys, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{pub: pub, priv: priv, kid: Thumbprint(pub), verifier: v}
}

func (f *fixture) token(t testing.TB, mutate func(map[string]any)) string {
	t.Helper()
	claims := validClaims()
	if mutate != nil {
		mutate(claims)
	}
	return sign(t, f.priv, header(f.kid), claims)
}

// mustRefuse asserts the single coarse error, and that it is the bare
// sentinel: a wrapped error would carry a reason with it.
func mustRefuse(t *testing.T, v *Verifier, token string) {
	t.Helper()
	claims, err := v.Verify(context.Background(), token)
	if err != ErrInvalidAssertion {
		t.Errorf("err = %v, want exactly ErrInvalidAssertion", err)
	}
	if claims != nil {
		t.Errorf("claims were returned beside an error: %+v", claims)
	}
}

func TestThumbprintKnownVector(t *testing.T) {
	// RFC 8037 appendix A.3.
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	if got := Thumbprint(ed25519.PublicKey(x)); got != want {
		t.Errorf("Thumbprint = %s, want %s", got, want)
	}
}

func TestVerifyValidToken(t *testing.T) {
	f := newFixture(t)
	claims, err := f.verifier.Verify(context.Background(), f.token(t, nil))
	if err != nil {
		t.Fatalf("a valid token was refused: %v", err)
	}
	if claims.Issuer != testIssuer || claims.Audience != testAudience ||
		claims.Subject != "5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c" ||
		claims.ID != "Zm9vYmFyYmF6cXV4MTIzNA" || claims.CredentialID != "AQIDBA" ||
		claims.ExpiresAt != testNow.Unix()+60 || claims.IssuedAt != testNow.Unix() || claims.NotBefore != testNow.Unix()-5 {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.HasFactor(FactorWebAuthn) || !claims.HasFactor(FactorWebAuthnUV) {
		t.Errorf("amr = %v", claims.AMR)
	}
	if claims.HasFactor(FactorTOTP) || claims.HasFactor(FactorRecoveryCode) {
		t.Errorf("HasFactor reports a factor that is not in %v", claims.AMR)
	}
}

func TestVerifyAcceptsHeaderWithoutTyp(t *testing.T) {
	f := newFixture(t)
	token := sign(t, f.priv, `{"alg":"EdDSA","kid":"`+f.kid+`"}`, validClaims())
	if _, err := f.verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestHasFactorOnNilClaims(t *testing.T) {
	var c *Claims
	if c.HasFactor(FactorWebAuthn) {
		t.Error("nil claims report a factor")
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	f := newFixture(t)
	parts := strings.Split(f.token(t, nil), ".")

	claims := validClaims()
	claims["sub"] = "00000000-0000-4000-8000-00000000dead"
	forged, _ := json.Marshal(claims)

	mustRefuse(t, f.verifier, parts[0]+"."+b64(forged)+"."+parts[2])
}

func TestVerifyTamperedHeader(t *testing.T) {
	f := newFixture(t)
	parts := strings.Split(f.token(t, nil), ".")
	// Same members, different byte sequence: still not what was signed.
	reordered := `{"kid":"` + f.kid + `","alg":"EdDSA","typ":"JWT"}`
	mustRefuse(t, f.verifier, b64([]byte(reordered))+"."+parts[1]+"."+parts[2])
}

func TestVerifyTamperedSignature(t *testing.T) {
	f := newFixture(t)
	parts := strings.Split(f.token(t, nil), ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])

	for _, i := range []int{0, 31, 32, 63} {
		flipped := append([]byte(nil), sig...)
		flipped[i] ^= 0x01
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+b64(flipped))
	}

	t.Run("truncated", func(t *testing.T) {
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+b64(sig[:63]))
	})
	t.Run("extended", func(t *testing.T) {
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+b64(append(append([]byte(nil), sig...), 0)))
	})
	t.Run("signed by another key", func(t *testing.T) {
		_, other := newKey(t)
		mustRefuse(t, f.verifier, sign(t, other, header(f.kid), validClaims()))
	})
}

func TestVerifyAlgNone(t *testing.T) {
	f := newFixture(t)
	payload, _ := json.Marshal(validClaims())

	for _, alg := range []string{"none", "None", "NONE", ""} {
		hdr := b64([]byte(`{"alg":"` + alg + `","kid":"` + f.kid + `","typ":"JWT"}`))
		// The classic form, with an empty signature.
		mustRefuse(t, f.verifier, hdr+"."+b64(payload)+".")
		// And with a signature of the right length, in case the emptiness was
		// what got it refused.
		mustRefuse(t, f.verifier, hdr+"."+b64(payload)+"."+b64(make([]byte, ed25519.SignatureSize)))
	}

	t.Run("a genuine signature under a header that says none", func(t *testing.T) {
		mustRefuse(t, f.verifier, sign(t, f.priv, `{"alg":"none","kid":"`+f.kid+`","typ":"JWT"}`, validClaims()))
	})
	t.Run("no alg member at all", func(t *testing.T) {
		mustRefuse(t, f.verifier, sign(t, f.priv, `{"kid":"`+f.kid+`","typ":"JWT"}`, validClaims()))
	})
}

func TestVerifyHS256WithPublicKeyAsSecret(t *testing.T) {
	f := newFixture(t)
	payload, _ := json.Marshal(validClaims())

	// The attack: the public key is public, so anyone can compute an HMAC
	// under it. A verifier that lets the header pick the routine, and feeds
	// "the key" to it, accepts the result.
	secrets := map[string][]byte{
		"raw key bytes":     f.pub,
		"base64url of them": []byte(b64(f.pub)),
	}
	for name, secret := range secrets {
		for alg, newHash := range map[string]func() hash.Hash{"HS256": sha256.New, "HS384": sha512.New384, "HS512": sha512.New} {
			input := b64([]byte(`{"alg":"`+alg+`","kid":"`+f.kid+`","typ":"JWT"}`)) + "." + b64(payload)
			mac := hmac.New(newHash, secret)
			mac.Write([]byte(input))
			t.Run(alg+" with "+name, func(t *testing.T) {
				mustRefuse(t, f.verifier, input+"."+b64(mac.Sum(nil)))
			})
		}
	}

	for _, alg := range []string{"ES256", "RS256", "PS256", "Ed25519", "eddsa", "EdDSA "} {
		t.Run("alg "+alg, func(t *testing.T) {
			mustRefuse(t, f.verifier, sign(t, f.priv, `{"alg":"`+alg+`","kid":"`+f.kid+`","typ":"JWT"}`, validClaims()))
		})
	}
}

func TestVerifyCrit(t *testing.T) {
	f := newFixture(t)
	for _, crit := range []string{`["exp"]`, `["b64"]`, `["urn:example:unknown"]`, `[]`, `"exp"`, `{}`} {
		hdr := `{"alg":"EdDSA","kid":"` + f.kid + `","typ":"JWT","crit":` + crit + `}`
		t.Run(crit, func(t *testing.T) {
			// Correctly signed: the header alone must be what refuses it.
			mustRefuse(t, f.verifier, sign(t, f.priv, hdr, validClaims()))
		})
	}
}

func TestVerifyWrongTyp(t *testing.T) {
	f := newFixture(t)
	hdr := `{"alg":"EdDSA","kid":"` + f.kid + `","typ":"at+jwt"}`
	mustRefuse(t, f.verifier, sign(t, f.priv, hdr, validClaims()))
}

func TestVerifyUnknownKid(t *testing.T) {
	f := newFixture(t)

	t.Run("a kid that is not in the set", func(t *testing.T) {
		// Signed by the trusted key, so only the key selection can refuse it.
		// A verifier that tried every key it knows would accept this.
		mustRefuse(t, f.verifier, sign(t, f.priv, header("bm90LWEtcmVhbC1raWQ"), validClaims()))
	})
	t.Run("an empty kid", func(t *testing.T) {
		mustRefuse(t, f.verifier, sign(t, f.priv, header(""), validClaims()))
	})
	t.Run("no kid member", func(t *testing.T) {
		mustRefuse(t, f.verifier, sign(t, f.priv, `{"alg":"EdDSA","typ":"JWT"}`, validClaims()))
	})
	t.Run("a second key signs under the first key's kid", func(t *testing.T) {
		otherPub, otherPriv := newKey(t)
		keys, _ := NewStaticKeys(f.pub, otherPub)
		v, err := NewVerifier(testIssuer, testAudience, keys, WithClock(func() time.Time { return testNow }))
		if err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, v, sign(t, otherPriv, header(f.kid), validClaims()))
		if _, err := v.Verify(context.Background(), sign(t, otherPriv, header(Thumbprint(otherPub)), validClaims())); err != nil {
			t.Errorf("the second key under its own kid was refused: %v", err)
		}
	})
}

func TestVerifyTimeClaims(t *testing.T) {
	now := testNow.Unix()
	skew := int64(DefaultClockSkew / time.Second)

	cases := []struct {
		name   string
		mutate func(map[string]any)
		ok     bool
	}{
		{"expired long ago", func(c map[string]any) { c["exp"] = now - 3600 }, false},
		{"expired one second past the skew", func(c map[string]any) { c["exp"] = now - skew - 1 }, false},
		{"expired exactly at the skew boundary", func(c map[string]any) { c["exp"] = now - skew }, true},
		{"expired within the skew", func(c map[string]any) { c["exp"] = now - skew + 1 }, true},
		{"expires this second", func(c map[string]any) { c["exp"] = now }, true},

		{"not yet valid by an hour", func(c map[string]any) { c["nbf"] = now + 3600 }, false},
		{"not yet valid by one second past the skew", func(c map[string]any) { c["nbf"] = now + skew + 1 }, false},
		{"not yet valid exactly at the skew boundary", func(c map[string]any) { c["nbf"] = now + skew }, true},
		{"not yet valid within the skew", func(c map[string]any) { c["nbf"] = now + skew - 1 }, true},
		{"no nbf", func(c map[string]any) { delete(c, "nbf") }, true},

		{"missing exp", func(c map[string]any) { delete(c, "exp") }, false},
		{"exp of zero", func(c map[string]any) { c["exp"] = 0 }, false},
		{"negative exp", func(c map[string]any) { c["exp"] = -1 }, false},
		{"exp as a string", func(c map[string]any) { c["exp"] = "never" }, false},
		{"exp as null", func(c map[string]any) { c["exp"] = nil }, false},
		{"fractional exp", func(c map[string]any) { c["exp"] = float64(now) + 60.5 }, false},
	}

	f := newFixture(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := f.token(t, tc.mutate)
			if !tc.ok {
				mustRefuse(t, f.verifier, token)
				return
			}
			if _, err := f.verifier.Verify(context.Background(), token); err != nil {
				t.Errorf("err = %v, want success", err)
			}
		})
	}
}

func TestVerifyMissingExpWithClockAtEpoch(t *testing.T) {
	// With a clock at the epoch a missing "exp", read as zero, is not in the
	// past. Only the explicit requirement refuses it.
	f := newFixture(t, WithClock(func() time.Time { return time.Unix(0, 0) }))
	mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) {
		delete(c, "exp")
		delete(c, "nbf")
	}))
}

func TestVerifyOversizedToken(t *testing.T) {
	// Correctly signed, so that the size is the only fault.
	f := newFixture(t)
	mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) {
		c["cid"] = strings.Repeat("A", maxAssertionBytes)
	}))
}

func TestVerifyConfigurableSkew(t *testing.T) {
	now := testNow.Unix()

	t.Run("zero skew", func(t *testing.T) {
		f := newFixture(t, WithClockSkew(0))
		if _, err := f.verifier.Verify(context.Background(), f.token(t, func(c map[string]any) { c["exp"] = now })); err != nil {
			t.Errorf("exp == now was refused: %v", err)
		}
		mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) { c["exp"] = now - 1 }))
		mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) { c["nbf"] = now + 1 }))
	})

	t.Run("two minutes", func(t *testing.T) {
		f := newFixture(t, WithClockSkew(2*time.Minute))
		if _, err := f.verifier.Verify(context.Background(), f.token(t, func(c map[string]any) { c["exp"] = now - 120 })); err != nil {
			t.Errorf("exp at the boundary was refused: %v", err)
		}
		mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) { c["exp"] = now - 121 }))
	})

	t.Run("the clock is injectable", func(t *testing.T) {
		clock := testNow
		f := newFixture(t, WithClock(func() time.Time { return clock }))
		token := f.token(t, nil)
		if _, err := f.verifier.Verify(context.Background(), token); err != nil {
			t.Fatalf("err = %v", err)
		}
		clock = testNow.Add(91 * time.Second) // exp is +60s, the skew 30s
		mustRefuse(t, f.verifier, token)
	})
}

func TestVerifyIssuerAndAudience(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(map[string]any){
		"wrong issuer":               func(c map[string]any) { c["iss"] = "someone-else" },
		"issuer differing by case":   func(c map[string]any) { c["iss"] = "N0passtemps" },
		"missing issuer":             func(c map[string]any) { delete(c, "iss") },
		"wrong audience":             func(c map[string]any) { c["aud"] = "00000000-0000-4000-8000-000000000000" },
		"missing audience":           func(c map[string]any) { delete(c, "aud") },
		"audience as an array":       func(c map[string]any) { c["aud"] = []string{testAudience} },
		"audience with a suffix":     func(c map[string]any) { c["aud"] = testAudience + "x" },
		"missing subject":            func(c map[string]any) { delete(c, "sub") },
		"empty amr":                  func(c map[string]any) { c["amr"] = []string{} },
		"missing amr":                func(c map[string]any) { delete(c, "amr") },
		"payload that is not object": nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if mutate == nil {
				input := b64([]byte(header(f.kid))) + "." + b64([]byte(`"a string"`))
				mustRefuse(t, f.verifier, input+"."+b64(ed25519.Sign(f.priv, []byte(input))))
				return
			}
			mustRefuse(t, f.verifier, f.token(t, mutate))
		})
	}
}

func TestVerifySegmentCount(t *testing.T) {
	f := newFixture(t)
	token := f.token(t, nil)
	parts := strings.Split(token, ".")

	cases := map[string]string{
		"empty":             "",
		"one segment":       parts[0],
		"two segments":      parts[0] + "." + parts[1],
		"four segments":     token + "." + parts[2],
		"trailing dot":      token + ".",
		"leading dot":       "." + token,
		"five segments JWE": token + ".." + parts[2],
		"empty header":      "." + parts[1] + "." + parts[2],
		"empty payload":     parts[0] + ".." + parts[2],
		"oversized":         token + strings.Repeat("A", maxAssertionBytes),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			mustRefuse(t, f.verifier, candidate)
		})
	}
}

func TestVerifyStrictBase64(t *testing.T) {
	f := newFixture(t)

	// A header whose encoding leaves a partial final quantum, so that padding
	// is meaningful for it.
	var hdr string
	for _, candidate := range []string{header(f.kid), `{"alg":"EdDSA", "kid":"` + f.kid + `","typ":"JWT"}`, `{"alg":"EdDSA",  "kid":"` + f.kid + `","typ":"JWT"}`} {
		if len(candidate)%3 != 0 {
			hdr = candidate
			break
		}
	}
	token := sign(t, f.priv, hdr, validClaims())
	if _, err := f.verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("the unmodified token was refused: %v", err)
	}
	parts := strings.Split(token, ".")

	t.Run("padded header", func(t *testing.T) {
		padded := base64.URLEncoding.EncodeToString([]byte(hdr))
		if !strings.HasSuffix(padded, "=") {
			t.Fatal("the test header needs no padding")
		}
		// Signed over the padded form, so that the padding is the only fault.
		input := padded + "." + parts[1]
		mustRefuse(t, f.verifier, input+"."+b64(ed25519.Sign(f.priv, []byte(input))))
	})

	t.Run("padded signature", func(t *testing.T) {
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+base64.URLEncoding.EncodeToString(sig))
	})

	t.Run("standard alphabet", func(t *testing.T) {
		// Signatures are random, so mint tokens until one has a character
		// that the two alphabets spell differently.
		var candidate []string
		for i := 0; i < 1000 && candidate == nil; i++ {
			p := strings.Split(f.token(t, func(c map[string]any) { c["jti"] = itoa(i) }), ".")
			if strings.ContainsAny(p[2], "-_") {
				candidate = p
			}
		}
		if candidate == nil {
			t.Fatal("no signature with a distinguishing character in 1000 attempts")
		}
		sig, _ := base64.RawURLEncoding.DecodeString(candidate[2])
		mustRefuse(t, f.verifier, candidate[0]+"."+candidate[1]+"."+base64.RawStdEncoding.EncodeToString(sig))
	})

	t.Run("non-zero trailing bits in the signature", func(t *testing.T) {
		// 64 bytes encode to 86 characters, the last of which carries four
		// unused bits. Setting one yields a second spelling of the same bytes.
		last := parts[2][len(parts[2])-1]
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		idx := strings.IndexByte(alphabet, last)
		respelled := parts[2][:len(parts[2])-1] + string(alphabet[idx|1])
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+respelled)
	})

	t.Run("line break inside the signature", func(t *testing.T) {
		// encoding/base64 skips these even in strict mode.
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+parts[2][:40]+"\n"+parts[2][40:])
		mustRefuse(t, f.verifier, parts[0]+"."+parts[1]+"."+parts[2]+"\r\n")
	})

	t.Run("surrounding white space", func(t *testing.T) {
		mustRefuse(t, f.verifier, " "+token)
		mustRefuse(t, f.verifier, token+" ")
	})
}

func TestVerifyMalformedHeader(t *testing.T) {
	f := newFixture(t)
	payload := b64([]byte(`{}`))
	sig := b64(make([]byte, ed25519.SignatureSize))
	for _, hdr := range []string{`not json`, `[]`, `"EdDSA"`, `{"alg":"EdDSA","kid":7}`, `{"alg":"EdDSA","kid":"x"} trailing`} {
		mustRefuse(t, f.verifier, b64([]byte(hdr))+"."+payload+"."+sig)
	}
}

// failingKeys is a KeySource that cannot reach its keys.
type failingKeys struct{ err error }

func (f failingKeys) Key(context.Context, string) (ed25519.PublicKey, error) { return nil, f.err }

// shortKeys is a KeySource that returns a key of the wrong size.
type shortKeys struct{}

func (shortKeys) Key(context.Context, string) (ed25519.PublicKey, error) {
	return make(ed25519.PublicKey, 16), nil
}

func TestVerifyKeySourceFailure(t *testing.T) {
	_, priv := newKey(t)
	token := sign(t, priv, header("some-kid"), validClaims())
	cause := errors.New("connection refused")

	v, err := NewVerifier(testIssuer, testAudience, failingKeys{cause})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), token)
	if !errors.Is(err, ErrInvalidAssertion) {
		t.Errorf("an outage does not fail closed: %v", err)
	}
	if !errors.Is(err, ErrKeysUnavailable) || !errors.Is(err, cause) {
		t.Errorf("the outage cannot be told from a bad token: %v", err)
	}

	t.Run("a key of the wrong size does not panic", func(t *testing.T) {
		v, err := NewVerifier(testIssuer, testAudience, shortKeys{})
		if err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, v, token)
	})
}

func TestNewVerifierRefusesOpenConfiguration(t *testing.T) {
	keys := StaticKeys{}
	if _, err := NewVerifier("", testAudience, keys); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := NewVerifier(testIssuer, "", keys); err == nil {
		t.Error("an empty audience was accepted")
	}
	if _, err := NewVerifier(testIssuer, testAudience, nil); err == nil {
		t.Error("a nil key source was accepted")
	}
	if _, err := NewVerifier(testIssuer, testAudience, keys, WithClockSkew(-time.Second)); err == nil {
		t.Error("a negative skew was accepted")
	}
	if _, err := NewVerifier(testIssuer, testAudience, keys, WithClock(nil)); err == nil {
		t.Error("a nil clock was accepted")
	}
}

func TestVerifyConcurrently(t *testing.T) {
	f := newFixture(t)
	token := f.token(t, nil)
	done := make(chan error, 16)
	for i := 0; i < cap(done); i++ {
		go func() {
			_, err := f.verifier.Verify(context.Background(), token)
			done <- err
		}()
	}
	for i := 0; i < cap(done); i++ {
		if err := <-done; err != nil {
			t.Errorf("err = %v", err)
		}
	}
}

func FuzzVerify(f *testing.F) {
	fx := newFixture(f)
	valid := fx.token(f, nil)
	f.Add(valid)
	f.Add("")
	f.Add("a.b.c")
	f.Add(valid + ".")

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := fx.verifier.Verify(context.Background(), token)
		if err == nil && token != valid {
			t.Fatalf("a token other than the signed one verified: %q", token)
		}
		if err != nil && (err != ErrInvalidAssertion || claims != nil) {
			t.Fatalf("err = %v, claims = %v", err, claims)
		}
	})
}

// TestVerifyReadsTheRiskClaim covers the claim an application branches on when
// it decides whether to ask for more than the ceremony proved.
func TestVerifyReadsTheRiskClaim(t *testing.T) {
	f := newFixture(t)

	token := f.token(t, func(c map[string]any) {
		c["risk"] = map[string]any{
			"level":   "elevated",
			"reasons": []any{"user_verification_absent", "credential_dormant"},
			"score":   30,
		}
	})

	claims, err := f.verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("a token carrying a risk claim was refused: %v", err)
	}
	if claims.Risk == nil {
		t.Fatal("the risk claim was dropped")
	}
	if claims.Risk.Level != RiskElevated || claims.Risk.Score != 30 {
		t.Errorf("risk = %+v", claims.Risk)
	}
	if !claims.HasRiskReason("credential_dormant") {
		t.Errorf("reasons = %v", claims.Risk.Reasons)
	}
	if claims.HasRiskReason("signature_counter_stalled") {
		t.Error("HasRiskReason reports a signal that did not fire")
	}
}

// TestVerifyWithoutARiskClaim pins the distinction the doc comment insists on:
// no claim is not a low assessment.
func TestVerifyWithoutARiskClaim(t *testing.T) {
	f := newFixture(t)

	claims, err := f.verifier.Verify(context.Background(), f.token(t, nil))
	if err != nil {
		t.Fatalf("a valid token was refused: %v", err)
	}
	if claims.Risk != nil {
		t.Errorf("risk = %+v, want nil when the deployment does not report it", claims.Risk)
	}
	if claims.HasRiskReason("recovery_code_used") {
		t.Error("HasRiskReason must not report a signal when no risk was reported")
	}
}

// TestVerifyRefusesMalformedRisk checks the claim fails closed. Accepting the
// token and dropping the claim would tell an application that risk was not
// reported when it was, which is fail-open on the one signal it asked for.
func TestVerifyRefusesMalformedRisk(t *testing.T) {
	f := newFixture(t)

	for name, value := range map[string]any{
		"not an object":       "elevated",
		"level not a string":  map[string]any{"level": 2},
		"reasons not strings": map[string]any{"level": "high", "reasons": []any{1, 2}},
		"score not a number":  map[string]any{"level": "high", "score": "lots"},
	} {
		t.Run(name, func(t *testing.T) {
			mustRefuse(t, f.verifier, f.token(t, func(c map[string]any) {
				c["risk"] = value
			}))
		})
	}
}
