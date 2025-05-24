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
	x, err := base64.RawURLEncoding.DecodeString(k["x"].(string))
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	v := NewVerifier(map[string]ed25519.PublicKey{k["kid"].(string): ed25519.PublicKey(x)}, testIssuer, testSkew)
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
