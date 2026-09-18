package assertion

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/risk"
)

const (
	testIssuer   = "n0passtemps-test"
	testAudience = "key_01HXYZ"
	testSubject  = "sub_7f3a"
	testTTL      = 60 * time.Second
	testSkew     = 30 * time.Second
)

// fixedNow is the instant every test issues at, so expiry arithmetic is exact.
var fixedNow = time.Unix(1758000000, 0).UTC()

func newTestIssuer(t *testing.T) (*Issuer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	iss, err := NewIssuer(priv, testIssuer, testTTL, testSkew)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	iss.now = func() time.Time { return fixedNow }
	return iss, pub
}

func newTestVerifier(iss *Issuer, at time.Time) *Verifier {
	v := NewVerifier(map[string]ed25519.PublicKey{iss.KeyID(): iss.PublicKey()}, testIssuer, testSkew)
	v.now = func() time.Time { return at }
	return v
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	iss, pub := newTestIssuer(t)
	credID := []byte{0x01, 0x02, 0x03, 0xff}

	token, issued, err := iss.Issue(testSubject, "tenant_a", testAudience,
		[]Factor{FactorWebAuthn, FactorWebAuthnUV}, credID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if n := len(strings.Split(token, ".")); n != 3 {
		t.Fatalf("token has %d segments, want 3", n)
	}

	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	got, err := v.Verify(token, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if got.Issuer != testIssuer {
		t.Errorf("iss = %q, want %q", got.Issuer, testIssuer)
	}
	if got.Subject != testSubject {
		t.Errorf("sub = %q, want %q", got.Subject, testSubject)
	}
	if got.Audience != testAudience {
		t.Errorf("aud = %q, want %q", got.Audience, testAudience)
	}
	if got.TenantID != "tenant_a" {
		t.Errorf("tid = %q, want tenant_a", got.TenantID)
	}
	if got.IssuedAt != fixedNow.Unix() {
		t.Errorf("iat = %d, want %d", got.IssuedAt, fixedNow.Unix())
	}
	if want := fixedNow.Add(-testSkew).Unix(); got.NotBefore != want {
		t.Errorf("nbf = %d, want %d", got.NotBefore, want)
	}
	if want := fixedNow.Add(testTTL).Unix(); got.ExpiresAt != want {
		t.Errorf("exp = %d, want %d", got.ExpiresAt, want)
	}
	if got.ID == "" {
		t.Error("jti is empty")
	}
	if len(got.AMR) != 2 || got.AMR[0] != FactorWebAuthn || got.AMR[1] != FactorWebAuthnUV {
		t.Errorf("amr = %v, want [webauthn webauthn-uv]", got.AMR)
	}
	if want := base64.RawURLEncoding.EncodeToString(credID); got.CredentialID != want {
		t.Errorf("cid = %q, want %q", got.CredentialID, want)
	}

	// The claims returned by Issue must be what a verifier reads back.
	if issued.ID != got.ID || issued.ExpiresAt != got.ExpiresAt {
		t.Errorf("Issue claims disagree with verified claims: %+v vs %+v", issued, got)
	}

	// Two issuances must not share a token identifier.
	_, second, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if second.ID == issued.ID {
		t.Error("two assertions share a jti")
	}

	// KeyID must be the thumbprint of the public half.
	if iss.KeyID() != Thumbprint(pub) {
		t.Errorf("KeyID = %q, want %q", iss.KeyID(), Thumbprint(pub))
	}
}

func TestIssueRejectsIncompleteCeremony(t *testing.T) {
	iss, _ := newTestIssuer(t)

	cases := []struct {
		name    string
		subject string
		aud     string
		factors []Factor
	}{
		{"empty_subject", "", testAudience, []Factor{FactorTOTP}},
		{"empty_audience", testSubject, "", []Factor{FactorTOTP}},
		{"no_factor", testSubject, testAudience, nil},
		{"empty_factor_slice", testSubject, testAudience, []Factor{}},
		{"unknown_factor", testSubject, testAudience, []Factor{"password"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := iss.Issue(c.subject, "", c.aud, c.factors, nil)
			if !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
}

// craft builds a compact serialisation from an arbitrary header and payload,
// signed by sign. It is how the attack cases below are constructed.
func craft(header string, payload []byte, sign func(signingInput string) []byte) string {
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sign(signingInput))
}

func testPayload(t *testing.T) []byte {
	t.Helper()
	c := Claims{
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audience:  testAudience,
		IssuedAt:  fixedNow.Unix(),
		NotBefore: fixedNow.Unix(),
		ExpiresAt: fixedNow.Add(testTTL).Unix(),
		ID:        "Zm9yZ2Vk",
		AMR:       []Factor{FactorWebAuthn},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return raw
}

// mutate replaces the character at index i with a different base64url
// character, so the segment stays decodable and only its content changes.
func mutate(s string, i int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	repl := alphabet[0]
	if s[i] == repl {
		repl = alphabet[1]
	}
	return s[:i] + string(repl) + s[i+1:]
}

func TestVerifyRejectsForgeries(t *testing.T) {
	iss, pub := newTestIssuer(t)

	// Issue until the signature contains a character that differs between the
	// URL-safe and the standard base64 alphabets. Roughly one signature in ten
	// contains neither '-' nor '_', and for those the "standard alphabet"
	// forgery below is byte-identical to the valid token, which the verifier
	// is right to accept. Each token has a fresh identifier, so the signature
	// changes on every attempt.
	var valid string
	for range 200 {
		tok, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthn}, nil)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if sig := tok[strings.LastIndexByte(tok, '.')+1:]; strings.ContainsAny(sig, "-_") {
			valid = tok
			break
		}
	}
	if valid == "" {
		t.Fatal("no signature containing a URL-safe-only character in 200 attempts")
	}
	parts := strings.Split(valid, ".")
	payload := testPayload(t)
	kid := iss.KeyID()

	// A signature the attacker cannot produce, used where the case is about
	// something other than the signature itself.
	unsigned := func(string) []byte { return nil }

	cases := []struct {
		name  string
		token string
	}{
		{
			// The classic unsecured JWS: drop the signature and declare that
			// none was needed.
			name:  "alg_none",
			token: craft(`{"alg":"none","kid":"`+kid+`","typ":"JWT"}`, payload, unsigned),
		},
		{
			name:  "alg_none_uppercase",
			token: craft(`{"alg":"None","kid":"`+kid+`","typ":"JWT"}`, payload, unsigned),
		},
		{
			// Algorithm confusion: the attacker knows the public key because
			// it is published, and asks for it to be treated as a symmetric
			// HMAC secret.
			name: "alg_hs256_with_public_key_as_hmac_secret",
			token: craft(`{"alg":"HS256","kid":"`+kid+`","typ":"JWT"}`, payload, func(si string) []byte {
				mac := hmac.New(sha256.New, pub)
				mac.Write([]byte(si))
				return mac.Sum(nil)
			}),
		},
		{
			name: "alg_hs512_with_public_key_as_hmac_secret",
			token: craft(`{"alg":"HS512","kid":"`+kid+`","typ":"JWT"}`, payload, func(si string) []byte {
				mac := hmac.New(sha256.New, pub)
				mac.Write([]byte(si))
				return mac.Sum(nil)
			}),
		},
		{
			name:  "alg_missing",
			token: craft(`{"kid":"`+kid+`","typ":"JWT"}`, payload, unsigned),
		},
		{
			name:  "crit_header_not_understood",
			token: craft(`{"alg":"EdDSA","kid":"`+kid+`","typ":"JWT","crit":["exp"]}`, payload, unsigned),
		},
		{
			name:  "kid_missing",
			token: craft(`{"alg":"EdDSA","typ":"JWT"}`, payload, unsigned),
		},
		{
			name:  "kid_unknown",
			token: craft(`{"alg":"EdDSA","kid":"not-a-published-key","typ":"JWT"}`, payload, unsigned),
		},
		{
			name:  "typ_not_jwt",
			token: craft(`{"alg":"EdDSA","kid":"`+kid+`","typ":"at+jwt"}`, payload, unsigned),
		},
		{
			name:  "header_not_json",
			token: craft(`not json at all`, payload, unsigned),
		},
		{"tampered_payload", parts[0] + "." + mutate(parts[1], 4) + "." + parts[2]},
		{"tampered_signature", parts[0] + "." + parts[1] + "." + mutate(parts[2], 0)},
		{"tampered_header", mutate(parts[0], 6) + "." + parts[1] + "." + parts[2]},
		{"two_segments", parts[0] + "." + parts[1]},
		{"four_segments", valid + "." + parts[2]},
		{"trailing_dot", valid + "."},
		{"one_segment", parts[0]},
		{"empty_token", ""},
		{"empty_signature", parts[0] + "." + parts[1] + "."},
		{"signature_truncated", parts[0] + "." + parts[1] + "." + parts[2][:40]},
		{
			// Padded base64: a 64-byte Ed25519 signature encodes to 86
			// characters plus two "=" under the padded alphabet.
			name: "padded_signature",
			token: func() string {
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatalf("decode signature: %v", err)
				}
				return parts[0] + "." + parts[1] + "." + base64.URLEncoding.EncodeToString(sig)
			}(),
		},
		{
			// Non-canonical base64: the last character of an 86-character
			// segment has four unused bits, which must be zero.
			name:  "non_canonical_signature",
			token: parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "B",
		},
		{
			name: "standard_base64_alphabet_in_signature",
			token: parts[0] + "." + parts[1] + "." + strings.Map(func(r rune) rune {
				switch r {
				case '-':
					return '+'
				case '_':
					return '/'
				}
				return r
			}, parts[2]),
		},
	}

	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := v.Verify(c.token, testAudience)
			if err == nil {
				t.Fatalf("Verify accepted %s: %+v", c.name, got)
			}
			// The failure must be indistinguishable from any other.
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
			if got != nil {
				t.Fatalf("claims returned alongside an error: %+v", got)
			}
		})
	}
}

// TestVerifyNonCanonicalSignatureIsReallyNonCanonical guards the test above:
// if the replacement character happened to be canonical the case would pass
// for the wrong reason.
func TestVerifyNonCanonicalSignatureIsReallyNonCanonical(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	enc := base64.RawURLEncoding.EncodeToString(sig)
	if len(enc) != 86 {
		t.Fatalf("encoded signature length = %d, want 86", len(enc))
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(enc[:85] + "B"); err == nil {
		t.Fatal("strict decoding accepted a non-zero trailing quantum")
	}
}

func TestVerifyRejectsWrongAudienceAndIssuer(t *testing.T) {
	iss, _ := newTestIssuer(t)
	token, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	at := fixedNow.Add(time.Second)

	t.Run("wrong_audience", func(t *testing.T) {
		v := newTestVerifier(iss, at)
		if _, err := v.Verify(token, "key_someone_else"); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("empty_expected_audience", func(t *testing.T) {
		v := newTestVerifier(iss, at)
		if _, err := v.Verify(token, ""); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("wrong_issuer", func(t *testing.T) {
		v := NewVerifier(map[string]ed25519.PublicKey{iss.KeyID(): iss.PublicKey()}, "some-other-deployment", testSkew)
		v.now = func() time.Time { return at }
		if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("empty_expected_issuer", func(t *testing.T) {
		v := NewVerifier(map[string]ed25519.PublicKey{iss.KeyID(): iss.PublicKey()}, "", testSkew)
		v.now = func() time.Time { return at }
		if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("key_from_another_issuer", func(t *testing.T) {
		other, _ := newTestIssuer(t)
		// Same kid the token carries, but the wrong key material behind it.
		v := NewVerifier(map[string]ed25519.PublicKey{iss.KeyID(): other.PublicKey()}, testIssuer, testSkew)
		v.now = func() time.Time { return at }
		if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})
}

func TestVerifyClockBoundaries(t *testing.T) {
	iss, _ := newTestIssuer(t)
	token, claims, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthn}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	exp := time.Unix(claims.ExpiresAt, 0)
	nbf := time.Unix(claims.NotBefore, 0)

	cases := []struct {
		name   string
		at     time.Time
		accept bool
	}{
		{"at_issuance", fixedNow, true},
		{"before_nbf_within_skew", nbf.Add(-testSkew), true},
		{"before_nbf_beyond_skew", nbf.Add(-testSkew - time.Second), false},
		{"just_before_exp", exp.Add(-time.Second), true},
		{"at_exp", exp, true},
		{"after_exp_within_skew", exp.Add(testSkew), true},
		{"after_exp_beyond_skew", exp.Add(testSkew + time.Second), false},
		{"long_expired", exp.Add(time.Hour), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newTestVerifier(iss, c.at)
			_, err := v.Verify(token, testAudience)
			if c.accept && err != nil {
				t.Fatalf("Verify at %s: %v, want acceptance", c.at.UTC(), err)
			}
			if !c.accept && !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify at %s: err = %v, want ErrInvalidToken", c.at.UTC(), err)
			}
		})
	}

	// A zero-skew verifier must not tolerate anything past expiry.
	t.Run("zero_skew_at_exp_plus_one", func(t *testing.T) {
		v := NewVerifier(map[string]ed25519.PublicKey{iss.KeyID(): iss.PublicKey()}, testIssuer, 0)
		v.now = func() time.Time { return exp.Add(time.Second) }
		if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})
}

// TestVerifyRequiresExp covers the case a missing "exp" would create: a
// captured assertion that never stops being accepted.
func TestVerifyRequiresExp(t *testing.T) {
	iss, _ := newTestIssuer(t)

	c := Claims{
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audience:  testAudience,
		IssuedAt:  fixedNow.Unix(),
		NotBefore: fixedNow.Unix(),
		ID:        "no-exp",
		AMR:       []Factor{FactorWebAuthn},
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Signed with the real key, so only the missing claim can reject it.
	token := craft(`{"alg":"EdDSA","kid":"`+iss.KeyID()+`","typ":"JWT"}`, payload, func(si string) []byte {
		return ed25519.Sign(iss.priv, []byte(si))
	})

	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// TestVerifyRequiresFactors covers a correctly signed token that asserts no
// authentication took place.
func TestVerifyRequiresFactors(t *testing.T) {
	iss, _ := newTestIssuer(t)

	c := Claims{
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audience:  testAudience,
		IssuedAt:  fixedNow.Unix(),
		NotBefore: fixedNow.Unix(),
		ExpiresAt: fixedNow.Add(testTTL).Unix(),
		ID:        "no-amr",
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	token := craft(`{"alg":"EdDSA","kid":"`+iss.KeyID()+`","typ":"JWT"}`, payload, func(si string) []byte {
		return ed25519.Sign(iss.priv, []byte(si))
	})

	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	if _, err := v.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// TestVerifyAcceptsTokenWithoutTyp keeps the typ check from becoming a
// compatibility break: RFC 7519 section 5.1 makes "typ" optional.
func TestVerifyAcceptsTokenWithoutTyp(t *testing.T) {
	iss, _ := newTestIssuer(t)
	payload := testPayload(t)
	token := craft(`{"alg":"EdDSA","kid":"`+iss.KeyID()+`"}`, payload, func(si string) []byte {
		return ed25519.Sign(iss.priv, []byte(si))
	})

	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	if _, err := v.Verify(token, testAudience); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifierSelectsByKidAcrossRotation checks that two keys can be published
// at once and that each token is checked against its own.
func TestVerifierSelectsByKidAcrossRotation(t *testing.T) {
	outgoing, _ := newTestIssuer(t)
	incoming, _ := newTestIssuer(t)
	if outgoing.KeyID() == incoming.KeyID() {
		t.Fatal("two independent keys share a thumbprint")
	}

	keys := map[string]ed25519.PublicKey{
		outgoing.KeyID(): outgoing.PublicKey(),
		incoming.KeyID(): incoming.PublicKey(),
	}
	v := NewVerifier(keys, testIssuer, testSkew)
	v.now = func() time.Time { return fixedNow.Add(time.Second) }

	for _, iss := range []*Issuer{outgoing, incoming} {
		token, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, err := v.Verify(token, testAudience); err != nil {
			t.Fatalf("Verify under kid %s: %v", iss.KeyID(), err)
		}
	}

	// Removing a key must make its tokens fail, which is what a revocation
	// during rotation relies on.
	token, _, err := outgoing.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	narrow := NewVerifier(map[string]ed25519.PublicKey{incoming.KeyID(): incoming.PublicKey()}, testIssuer, testSkew)
	narrow.now = func() time.Time { return fixedNow.Add(time.Second) }
	if _, err := narrow.Verify(token, testAudience); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// TestNewVerifierCopiesKeys guards against a caller mutating the map after
// construction and silently changing which keys are trusted.
func TestNewVerifierCopiesKeys(t *testing.T) {
	iss, _ := newTestIssuer(t)
	keys := map[string]ed25519.PublicKey{iss.KeyID(): iss.PublicKey()}
	v := NewVerifier(keys, testIssuer, testSkew)
	v.now = func() time.Time { return fixedNow.Add(time.Second) }

	delete(keys, iss.KeyID())

	token, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Verify(token, testAudience); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestThumbprintRFC8037 pins the thumbprint construction to the worked example
// of RFC 8037 Appendix A.3.
func TestThumbprintRFC8037(t *testing.T) {
	const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("key has %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	if got := Thumbprint(ed25519.PublicKey(raw)); got != want {
		t.Fatalf("Thumbprint = %q, want %q", got, want)
	}
}

func TestJWKS(t *testing.T) {
	iss, pub := newTestIssuer(t)

	raw, err := iss.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(set.Keys))
	}
	k := set.Keys[0]

	for field, want := range map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"use": "sig",
		"alg": "EdDSA",
		"kid": iss.KeyID(),
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	} {
		got, ok := k[field].(string)
		if !ok {
			t.Errorf("jwk field %q is missing or not a string: %v", field, k[field])
			continue
		}
		if got != want {
			t.Errorf("jwk %q = %q, want %q", field, got, want)
		}
	}

	// The published document must not leak the private half.
	if strings.Contains(string(raw), `"d"`) {
		t.Errorf("jwks contains a private key parameter: %s", raw)
	}

	// A verifier built from the published document must accept a fresh token.
	x, err := base64.RawURLEncoding.DecodeString(jwkString(t, k, "x"))
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	v := NewVerifier(map[string]ed25519.PublicKey{jwkString(t, k, "kid"): ed25519.PublicKey(x)}, testIssuer, testSkew)
	v.now = func() time.Time { return fixedNow.Add(time.Second) }

	token, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorRecoveryCode}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Verify(token, testAudience); err != nil {
		t.Fatalf("Verify with key from jwks: %v", err)
	}
}

func TestNewIssuerRejectsBadArguments(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := []struct {
		name   string
		priv   ed25519.PrivateKey
		issuer string
		ttl    time.Duration
		skew   time.Duration
	}{
		{"short_key", priv[:16], testIssuer, testTTL, testSkew},
		{"nil_key", nil, testIssuer, testTTL, testSkew},
		{"empty_issuer", priv, "", testTTL, testSkew},
		{"zero_ttl", priv, testIssuer, 0, testSkew},
		{"negative_ttl", priv, testIssuer, -time.Second, testSkew},
		{"negative_skew", priv, testIssuer, testTTL, -time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewIssuer(c.priv, c.issuer, c.ttl, c.skew); err == nil {
				t.Fatal("NewIssuer accepted invalid arguments")
			}
		})
	}
}

func TestGenerateAndLoadKeyPEM(t *testing.T) {
	privPEM, pubPEM, err := GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "assertion-key.pem")
	if err := os.WriteFile(path, privPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// os.WriteFile is subject to the process umask, so the mode is pinned.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	priv, err := LoadPrivateKeyPEM(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}

	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public PEM block = %v", block)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public PEM holds a %T, want ed25519.PublicKey", parsed)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("the generated PEM files do not form a key pair")
	}

	// The loaded key must actually sign verifiable assertions.
	iss, err := NewIssuer(priv, testIssuer, testTTL, testSkew)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	iss.now = func() time.Time { return fixedNow }
	token, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthnUV}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := newTestVerifier(iss, fixedNow.Add(time.Second))
	if _, err := v.Verify(token, testAudience); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestLoadPrivateKeyPEMRejectsPermissiveMode(t *testing.T) {
	privPEM, _, err := GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "assertion-key.pem")
			if err := os.WriteFile(path, privPEM, mode); err != nil {
				t.Fatalf("write key: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			_, err := LoadPrivateKeyPEM(path)
			if !errors.Is(err, ErrInsecureKeyMode) {
				t.Fatalf("err = %v, want ErrInsecureKeyMode", err)
			}
		})
	}
}

func TestLoadPrivateKeyPEMRejectsNonEd25519(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "ec-key.pem")
	if err := os.WriteFile(path, ecPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = LoadPrivateKeyPEM(path)
	if !errors.Is(err, ErrNotEd25519) {
		t.Fatalf("err = %v, want ErrNotEd25519", err)
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("error message does not name the expected key type: %v", err)
	}
}

func TestLoadPrivateKeyPEMRejectsMalformedFiles(t *testing.T) {
	privPEM, _, err := GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{"not_pem", []byte("this is not a pem file\n")},
		{"empty", nil},
		{"wrong_block_type", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"trailing_key", append(append([]byte(nil), privPEM...), privPEM...)},
		{"body_not_pkcs8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, c.content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			if _, err := LoadPrivateKeyPEM(path); !errors.Is(err, ErrBadPEM) {
				t.Fatalf("err = %v, want ErrBadPEM", err)
			}
		})
	}

	t.Run("missing_file", func(t *testing.T) {
		if _, err := LoadPrivateKeyPEM(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
			t.Fatal("LoadPrivateKeyPEM accepted a missing file")
		}
	})
}

func TestFactorValid(t *testing.T) {
	for _, f := range []Factor{FactorWebAuthn, FactorWebAuthnUV, FactorTOTP, FactorRecoveryCode} {
		if !f.Valid() {
			t.Errorf("Factor(%q).Valid() = false", f)
		}
	}
	for _, f := range []Factor{"", "password", "WEBAUTHN", "otp"} {
		if f.Valid() {
			t.Errorf("Factor(%q).Valid() = true", f)
		}
	}
}

// TestClaimsJSONTags pins the wire names, which are the contract with every
// integrating application and cannot change without breaking them.
func TestClaimsJSONTags(t *testing.T) {
	raw, err := json.Marshal(Claims{
		Issuer:       "i",
		Subject:      "s",
		Audience:     "a",
		IssuedAt:     1,
		NotBefore:    2,
		ExpiresAt:    3,
		ID:           "j",
		AMR:          []Factor{FactorTOTP},
		CredentialID: "c",
		TenantID:     "t",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"iss":"i","sub":"s","aud":"a","iat":1,"nbf":2,"exp":3,"jti":"j","amr":["totp"],"cid":"c","tid":"t"}`
	if string(raw) != want {
		t.Fatalf("marshalled claims =\n%s\nwant\n%s", raw, want)
	}

	// The optional claims disappear when unset rather than serialising as
	// empty strings.
	raw, err = json.Marshal(Claims{Issuer: "i", Subject: "s", Audience: "a", AMR: []Factor{FactorTOTP}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"cid"`) || strings.Contains(string(raw), `"tid"`) {
		t.Fatalf("optional claims present when unset: %s", raw)
	}
}

// TestVerifyRefusesWhitespaceInsideASegment is the regression test for a
// verifier that accepted several spellings of one valid token.
//
// encoding/base64 discards carriage returns and newlines even through Strict(),
// so a break inserted into any segment used to decode to the same bytes and
// verify. One captured assertion therefore yielded an unbounded number of
// distinct token strings that were all valid, which defeats a replay cache
// keyed on the token text. RFC 7515 section 3.1 permits no whitespace in the
// compact serialisation.
func TestVerifyRefusesWhitespaceInsideASegment(t *testing.T) {
	iss, _ := newTestIssuer(t)
	valid, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newTestVerifier(iss, fixedNow)

	// The control: the token as issued must verify, so a failure below is
	// about the injected character and nothing else.
	if _, err := verifier.Verify(valid, testAudience); err != nil {
		t.Fatalf("the token as issued does not verify: %v", err)
	}

	parts := strings.Split(valid, ".")
	for segment, name := range map[int]string{0: "header", 1: "payload", 2: "signature"} {
		for _, ws := range []string{"\n", "\r", "\r\n", "\t", " "} {
			mangled := append([]string(nil), parts...)
			half := len(mangled[segment]) / 2
			mangled[segment] = mangled[segment][:half] + ws + mangled[segment][half:]

			got, err := verifier.Verify(strings.Join(mangled, "."), testAudience)
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("%s segment with %q accepted (err=%v, claims=%v); one assertion "+
					"must have exactly one valid encoding", name, ws, err, got)
			}
		}
	}
}

// TestRiskClaimSurvivesARoundTrip checks the optional claim end to end.
//
// It has to come back exactly as it went in, because an application's step-up
// decision is taken on it and an audit entry is expected to match it.
func TestRiskClaimSurvivesARoundTrip(t *testing.T) {
	iss, _ := newTestIssuer(t)
	assessed := risk.Assessment{
		Level: risk.LevelElevated,
		Reasons: []risk.Reason{
			risk.ReasonRecoveryCodeUsed,
			risk.ReasonRecentFailuresSubject,
		},
		Score: 35,
	}

	token, issued, err := iss.Issue(testSubject, "", testAudience,
		[]Factor{FactorRecoveryCode}, nil, WithRisk(assessed))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Risk == nil {
		t.Fatal("Issue returned claims with no risk")
	}

	got, err := newTestVerifier(iss, fixedNow.Add(time.Second)).Verify(token, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Risk == nil {
		t.Fatal("the verified claims carry no risk")
	}
	if got.Risk.Level != assessed.Level || got.Risk.Score != assessed.Score {
		t.Errorf("risk = %+v, want level %s and score %d", *got.Risk, assessed.Level, assessed.Score)
	}
	if len(got.Risk.Reasons) != len(assessed.Reasons) {
		t.Fatalf("risk reasons = %v, want %v", got.Risk.Reasons, assessed.Reasons)
	}
	for i, reason := range assessed.Reasons {
		if got.Risk.Reasons[i] != reason {
			t.Errorf("risk reason %d = %q, want %q", i, got.Risk.Reasons[i], reason)
		}
	}

	// The claim is a copy, so mutating the caller's slice afterwards cannot
	// make the token disagree with what the caller believes it signed.
	assessed.Reasons[0] = risk.ReasonTOTPOnly
	if issued.Risk.Reasons[0] != risk.ReasonRecoveryCodeUsed {
		t.Error("the signed claim shares its backing array with the caller's assessment")
	}

	// And the member is actually named "risk" on the wire, since a verifier in
	// another language reads it by name.
	var raw map[string]any
	payload, err := decodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	claim, ok := raw["risk"].(map[string]any)
	if !ok {
		t.Fatalf("the payload has no risk object: %s", payload)
	}
	for _, member := range []string{"level", "reasons", "score"} {
		if _, ok := claim[member]; !ok {
			t.Errorf("the risk claim has no %q member: %s", member, payload)
		}
	}
}

// TestTokenWithNoRiskClaimStillVerifies is the compatibility guarantee.
//
// A deployment with risk reporting off must produce a token that is exactly
// what it produced before the feature existed: no risk member at all, not an
// empty one, and a verifier must not require it.
func TestTokenWithNoRiskClaimStillVerifies(t *testing.T) {
	iss, _ := newTestIssuer(t)

	token, issued, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Risk != nil {
		t.Errorf("Issue attached a risk claim nobody asked for: %+v", *issued.Risk)
	}

	got, err := newTestVerifier(iss, fixedNow.Add(time.Second)).Verify(token, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Risk != nil {
		t.Errorf("the verified claims invented a risk claim: %+v", *got.Risk)
	}

	// Omitted entirely, so a strict verifier that rejects unknown members and
	// one that ignores them both see the payload they saw before.
	payload, err := decodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(string(payload), "risk") {
		t.Errorf("the payload mentions risk although none was attached: %s", payload)
	}

	// A nil option is tolerated, so a caller may build the slice
	// unconditionally.
	if _, _, err := iss.Issue(testSubject, "", testAudience, []Factor{FactorTOTP}, nil, nil); err != nil {
		t.Errorf("Issue with a nil option: %v", err)
	}
}

// jwkString reads one member of a published JWK as a string.
//
// The members are read back out of a JSON document, so their types are not
// guaranteed by the compiler. Asserting inline would fail a malformed document
// with a panic naming an interface conversion, which says nothing about which
// member was wrong.
func jwkString(t *testing.T, jwk map[string]any, member string) string {
	t.Helper()
	v, ok := jwk[member].(string)
	if !ok {
		t.Fatalf("JWK member %q is %T, want a string", member, jwk[member])
	}
	return v
}

// TestJWKSPublishesRetiredKeys is the test the whole feature exists for: a
// token minted under the outgoing key still verifies against the document the
// service publishes after the signing key has been replaced.
func TestJWKSPublishesRetiredKeys(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The issuer as it was before the rotation, used only to mint a token that
	// is still inside its lifetime when the rotation happens.
	before, err := NewIssuer(oldPriv, testIssuer, testTTL, testSkew)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	before.now = func() time.Time { return fixedNow }
	inFlight, _, err := before.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthn}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	after, err := NewIssuer(newPriv, testIssuer, testTTL, testSkew, WithRetiredKeys(oldPub))
	if err != nil {
		t.Fatalf("NewIssuer with retired key: %v", err)
	}
	after.now = func() time.Time { return fixedNow }

	raw, err := after.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	keys := jwksKeys(t, raw)
	if len(keys) != 2 {
		t.Fatalf("jwks has %d keys, want 2", len(keys))
	}
	// The signing key leads, so a reader can tell which one is live.
	if got := jwkString(t, keys[0], "kid"); got != after.KeyID() {
		t.Errorf("first jwk kid = %q, want the signing key %q", got, after.KeyID())
	}
	if got := jwkString(t, keys[1], "kid"); got != Thumbprint(oldPub) {
		t.Errorf("second jwk kid = %q, want the retired key %q", got, Thumbprint(oldPub))
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Errorf("jwks contains a private key parameter: %s", raw)
	}

	// Both the in-flight token and a fresh one verify against the published set.
	v := NewVerifier(verifierFromJWKS(t, raw), testIssuer, testSkew)
	v.now = func() time.Time { return fixedNow.Add(time.Second) }

	if _, err := v.Verify(inFlight, testAudience); err != nil {
		t.Fatalf("a token minted under the retired key was refused after rotation: %v", err)
	}
	fresh, _, err := after.Issue(testSubject, "", testAudience, []Factor{FactorWebAuthn}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Verify(fresh, testAudience); err != nil {
		t.Fatalf("a token minted under the new key was refused: %v", err)
	}

	// Dropping the retired entry is what ends the window, and it has to end:
	// after it, the outgoing key verifies nothing.
	closed, err := NewIssuer(newPriv, testIssuer, testTTL, testSkew)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	closedRaw, err := closed.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	vClosed := NewVerifier(verifierFromJWKS(t, closedRaw), testIssuer, testSkew)
	vClosed.now = func() time.Time { return fixedNow.Add(time.Second) }
	if _, err := vClosed.Verify(inFlight, testAudience); err == nil {
		t.Fatal("a token minted under the retired key still verified once the key was withdrawn")
	}
}

func TestJWKSRetiredKeyOrderIsStable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var retired []ed25519.PublicKey
	for range 4 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		retired = append(retired, pub)
	}

	// The same keys in a different order must produce the same document, so a
	// cached copy and a freshly fetched one compare equal.
	first, err := NewIssuer(priv, testIssuer, testTTL, testSkew, WithRetiredKeys(retired...))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	reversed := make([]ed25519.PublicKey, len(retired))
	for n, k := range retired {
		reversed[len(retired)-1-n] = k
	}
	second, err := NewIssuer(priv, testIssuer, testTTL, testSkew, WithRetiredKeys(reversed...))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	a, err := first.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	b, err := second.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("jwks depends on the order the retired keys were listed:\n%s\n%s", a, b)
	}

	kids := first.RetiredKeyIDs()
	if len(kids) != len(retired) {
		t.Fatalf("RetiredKeyIDs returned %d, want %d", len(kids), len(retired))
	}
	for n := 1; n < len(kids); n++ {
		if kids[n-1] >= kids[n] {
			t.Errorf("RetiredKeyIDs is not sorted: %q then %q", kids[n-1], kids[n])
		}
	}
}

func TestWithRetiredKeysRejectsBadArguments(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := []struct {
		name    string
		retired []ed25519.PublicKey
		want    string
	}{
		{"the signing key itself", []ed25519.PublicKey{pub}, "is the signing key"},
		{"the same key twice", []ed25519.PublicKey{other, other}, "listed twice"},
		{"a key of the wrong length", []ed25519.PublicKey{other[:16]}, "want 32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewIssuer(priv, testIssuer, testTTL, testSkew, WithRetiredKeys(tc.retired...))
			if err == nil {
				t.Fatal("NewIssuer accepted it")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error is %v, want ErrInvalidKey", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadPublicKeyPEM(t *testing.T) {
	dir := t.TempDir()

	privPEM, pubPEM, err := GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}
	pubPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	pub, err := LoadPublicKeyPEM(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	priv, err := parseTestPrivate(t, privPEM)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	if !pub.Equal(priv.Public()) {
		t.Error("the loaded public key does not match the private key it was written with")
	}

	// A world-readable public key is fine: it is served to every caller.
	if err := os.Chmod(pubPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadPublicKeyPEM(pubPath); err != nil {
		t.Errorf("a mode 0644 public key was refused: %v", err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal ec public: %v", err)
	}

	bad := []struct {
		name    string
		content []byte
		want    string
	}{
		{"a private key", privPEM, "holds a private key"},
		{"no pem block", []byte("not a key"), "contains no PEM block"},
		{"trailing data", append(append([]byte(nil), pubPEM...), []byte("second block\n")...), "trailing data"},
		{"an unexpected label", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), `expected "PUBLIC KEY"`},
		{"a p-256 key", pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: ecDER}), "only Ed25519"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(p, tc.content, 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadPublicKeyPEM(p)
			if err == nil {
				t.Fatal("LoadPublicKeyPEM accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	if _, err := LoadPublicKeyPEM(filepath.Join(dir, "absent.pem")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// jwksKeys decodes a published JWK Set into its members, in document order.
func jwksKeys(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	return set.Keys
}

// verifierFromJWKS builds the key map a Verifier takes from a published
// document, the way an integrating application would.
func verifierFromJWKS(t *testing.T, raw []byte) map[string]ed25519.PublicKey {
	t.Helper()
	out := make(map[string]ed25519.PublicKey)
	for _, k := range jwksKeys(t, raw) {
		x, err := base64.RawURLEncoding.DecodeString(jwkString(t, k, "x"))
		if err != nil {
			t.Fatalf("decode x: %v", err)
		}
		out[jwkString(t, k, "kid")] = ed25519.PublicKey(x)
	}
	return out
}

func parseTestPrivate(t *testing.T, privPEM []byte) (ed25519.PrivateKey, error) {
	t.Helper()
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("no pem block in the generated private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("generated key is a %T", parsed)
	}
	return priv, nil
}
