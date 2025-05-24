// Package assertion issues and verifies the short-lived signed proof that an
// authentication ceremony has just completed.
//
// The proof is a compact JWS (RFC 7515) signed with Ed25519 under the "EdDSA"
// algorithm of RFC 8037 section 3.1, carrying JWT claims (RFC 7519). The
// integrating application verifies it offline against the public key published
// as a JWK Set (RFC 7517), so it does not have to trust the network path
// between itself and this service.
//
// The JWS is assembled and parsed here rather than through a JWT library. The
// format is a few dozen lines, and the recurring vulnerabilities of those
// libraries have all been in the parsing side: honouring the "none" algorithm,
// letting the token choose which verification routine runs, or accepting a
// public key as an HMAC secret. Verify refuses all three by construction, see
// the comments on each check.
//
// Ed25519 is the only algorithm this package will ever accept. There is no
// negotiation, because an algorithm field that the token controls is the root
// of the confusion attacks above.
package assertion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// algEdDSA is the only value of the "alg" header this package produces or
// accepts, per RFC 8037 section 3.1.
const algEdDSA = "EdDSA"

// typJWT marks the payload as a JWT claims set, per RFC 7519 section 5.1. It
// is checked on the way in so a JWS minted for some other purpose under the
// same key cannot be presented as an assertion.
const typJWT = "JWT"

// pemTypePrivate and pemTypePublic are the PEM labels of RFC 7468 sections 10
// and 13.
const (
	pemTypePrivate = "PRIVATE KEY"
	pemTypePublic  = "PUBLIC KEY"
)

// jtiBytes is the size of the random token identifier. 128 bits is enough for
// a relying party to use "jti" as the key of a replay cache without worrying
// about collisions between concurrent issuers.
const jtiBytes = 16

// Errors a caller may need to distinguish.
//
// ErrInvalidToken is deliberately the only verification outcome. Reporting
// which check failed would tell an attacker whether a forged token had the
// right audience, whether a "kid" exists, or whether a captured token is
// merely expired rather than wrongly signed. The distinction is kept inside
// Verify and never surfaces.
var (
	ErrInvalidToken    = errors.New("assertion: token is not valid")
	ErrNotEd25519      = errors.New("assertion: key is not an Ed25519 key")
	ErrInsecureKeyMode = errors.New("assertion: signing key has permissive file mode")
	ErrBadPEM          = errors.New("assertion: malformed PKCS#8 PEM file")
	ErrInvalidKey      = errors.New("assertion: invalid Ed25519 key")
	ErrInvalidClaims   = errors.New("assertion: incomplete ceremony result")
)

// Factor names one authentication factor that contributed to a ceremony.
//
// These populate the "amr" claim of RFC 8176. That registry has no value for a
// WebAuthn assertion specifically, so the deployment-specific names below are
// used; an application that wants registry values can map them.
type Factor string

const (
	// FactorWebAuthn is a WebAuthn assertion where the authenticator proved
	// possession only.
	FactorWebAuthn Factor = "webauthn"

	// FactorWebAuthnUV is a WebAuthn assertion where the authenticator also
	// reported user verification, a PIN or a biometric. It is a separate
	// factor because an application may require it for sensitive operations,
	// and it must not be inferred from FactorWebAuthn.
	FactorWebAuthnUV Factor = "webauthn-uv"

	// FactorTOTP is a time-based one-time password.
	FactorTOTP Factor = "totp"

	// FactorRecoveryCode is a single-use recovery code. Applications
	// commonly treat a recovery-code login as lower assurance and force a
	// re-enrolment, which is why it is distinguishable in the token.
	FactorRecoveryCode Factor = "recovery-code"
)

// Valid reports whether f is a factor this service can record.
func (f Factor) Valid() bool {
	switch f {
	case FactorWebAuthn, FactorWebAuthnUV, FactorTOTP, FactorRecoveryCode:
		return true
	default:
		return false
	}
}

// Claims is the JWT claims set of an assertion.
//
// The date claims are seconds since the Unix epoch, as RFC 7519 section 2
// defines NumericDate. They are plain integers rather than time.Time so the
// wire form is exactly what was signed, with no timezone or precision
// ambiguity between the issuer and the verifier.
type Claims struct {
	// Issuer identifies the deployment that ran the ceremony.
	Issuer string `json:"iss"`

	// Subject is the internal subject identifier, not the caller's own user
	// reference: the reference is sealed at rest and is not the service's to
	// re-publish.
	Subject string `json:"sub"`

	// Audience is the identifier of the API key the ceremony was performed
	// for. A verifier must pin it, so a token minted for one tenant's key
	// cannot be presented to another.
	Audience string `json:"aud"`

	IssuedAt  int64 `json:"iat"`
	NotBefore int64 `json:"nbf"`
	ExpiresAt int64 `json:"exp"`

	// ID is a unique token identifier, suitable as a replay-cache key.
	ID string `json:"jti"`

	// AMR lists the factors that completed the ceremony, per RFC 8176.
	AMR []Factor `json:"amr"`

	// CredentialID is the base64url WebAuthn credential identifier, present
	// when a WebAuthn factor was used. It lets an application pin a session
	// to one authenticator.
	CredentialID string `json:"cid,omitempty"`

	// TenantID is present on multi-tenant deployments.
	TenantID string `json:"tid,omitempty"`
}

// joseHeader is the JWS protected header, restricted to the members this
// package inspects.
type joseHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// Issuer signs assertions with one Ed25519 key.
type Issuer struct {
	priv   ed25519.PrivateKey
	issuer string
	ttl    time.Duration
	skew   time.Duration
	kid    string

	// header is the encoded protected header, identical for every token this
	// Issuer produces, so it is built once.
	header string

	// now is overridden in tests.
	now func() time.Time
}

// NewIssuer returns an Issuer signing with priv.
//
// ttl is how long an assertion stays valid. skew is subtracted from "nbf" so
// that a verifier whose clock lags slightly accepts a token immediately; it
// does not extend "exp", because moving expiry later is the direction that
// costs security.
func NewIssuer(priv ed25519.PrivateKey, issuer string, ttl, skew time.Duration) (*Issuer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key has %d bytes, want %d", ErrInvalidKey, len(priv), ed25519.PrivateKeySize)
	}
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer must not be empty", ErrInvalidKey)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: ttl must be positive, got %s", ErrInvalidKey, ttl)
	}
	if skew < 0 {
		return nil, fmt.Errorf("%w: skew must not be negative, got %s", ErrInvalidKey, skew)
	}

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrNotEd25519
	}
	kid := Thumbprint(pub)

	// Built by hand rather than marshalled from a map: the byte sequence that
	// gets signed must be fixed, and map iteration order is not.
	header := encodeSegment([]byte(`{"alg":"` + algEdDSA + `","kid":"` + kid + `","typ":"` + typJWT + `"}`))

	return &Issuer{
		priv:   priv,
		issuer: issuer,
		ttl:    ttl,
		skew:   skew,
		kid:    kid,
		header: header,
		now:    time.Now,
	}, nil
}

// KeyID returns the JWK thumbprint of the signing key, per RFC 7638. It is the
// "kid" header of every token this Issuer produces, so a verifier can pick the
// right key while two keys are published side by side during a rotation.
func (i *Issuer) KeyID() string { return i.kid }

// PublicKey returns the verification key matching the signing key.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.priv.Public().(ed25519.PublicKey)
}

// Issue signs an assertion for a completed ceremony.
//
// factors must be non-empty: a token with no "amr" entry asserts that the
// subject authenticated by no means at all, which no application should be
// asked to interpret. credentialID may be nil when no WebAuthn factor was
// used.
func (i *Issuer) Issue(subjectID, tenantID, audience string, factors []Factor, credentialID []byte) (token string, claims *Claims, err error) {
	if subjectID == "" {
		return "", nil, fmt.Errorf("%w: subject id is empty", ErrInvalidClaims)
	}
	if audience == "" {
		return "", nil, fmt.Errorf("%w: audience is empty", ErrInvalidClaims)
	}
	if len(factors) == 0 {
		return "", nil, fmt.Errorf("%w: no factor recorded", ErrInvalidClaims)
	}
	for _, f := range factors {
		if !f.Valid() {
			return "", nil, fmt.Errorf("%w: unknown factor %q", ErrInvalidClaims, f)
		}
	}

	jti := make([]byte, jtiBytes)
	if _, err := rand.Read(jti); err != nil {
		return "", nil, fmt.Errorf("assertion: read random: %w", err)
	}

	now := i.now()
	c := &Claims{
		Issuer:    i.issuer,
		Subject:   subjectID,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-i.skew).Unix(),
		ExpiresAt: now.Add(i.ttl).Unix(),
		ID:        encodeSegment(jti),
		// Copied, so a later mutation by the caller cannot disagree with what
		// was signed.
		AMR:      append([]Factor(nil), factors...),
		TenantID: tenantID,
	}
	if len(credentialID) > 0 {
		c.CredentialID = encodeSegment(credentialID)
	}

	payload, err := json.Marshal(c)
	if err != nil {
		return "", nil, fmt.Errorf("assertion: marshal claims: %w", err)
	}

	signingInput := i.header + "." + encodeSegment(payload)
	sig := ed25519.Sign(i.priv, []byte(signingInput))
	return signingInput + "." + encodeSegment(sig), c, nil
}

// jwk is one JSON Web Key, restricted to the OKP members of RFC 8037
// section 2.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// JWKS returns the JWK Set document to publish, per RFC 7517 section 5.
//
// It contains the public key only. During a rotation an operator serves the
// union of the sets of the outgoing and incoming issuers, and the "kid" of
// each token selects between them.
func (i *Issuer) JWKS() ([]byte, error) {
	pub := i.PublicKey()
	set := jwkSet{Keys: []jwk{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   encodeSegment(pub),
		Use: "sig",
		Alg: algEdDSA,
		Kid: i.kid,
	}}}
	out, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("assertion: marshal jwks: %w", err)
	}
	return out, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint of an Ed25519 public key.
//
// RFC 7638 section 3 fixes the hash input as the JSON object of the required
// members only, with no whitespace and the member names in lexicographic
// order. RFC 8037 section 2 names those members for an OKP key: crv, kty and
// x. The construction has to be exact, because two implementations that
// disagree about it produce different key identifiers for the same key.
func Thumbprint(pub ed25519.PublicKey) string {
	input := `{"crv":"Ed25519","kty":"OKP","x":"` + encodeSegment(pub) + `"}`
	sum := sha256.Sum256([]byte(input))
	return encodeSegment(sum[:])
}

// Verifier checks assertions against a set of published public keys.
//
// It ships with the service so the service can test its own output, and it is
// mirrored by the shipped Go example, which implements the same checks
// directly against crypto/ed25519.
//
// The example cannot import this package: Go confines an internal package to
// importers inside the module, and the example exists to be copied into another
// project. The two are therefore deliberate duplicates, so a change to the
// checks below needs the same change in examples/go/client.go.
type Verifier struct {
	keys           map[string]ed25519.PublicKey
	expectedIssuer string
	skew           time.Duration

	// now is overridden in tests.
	now func() time.Time
}

// NewVerifier returns a Verifier over keys, indexed by JWK thumbprint.
//
// skew is the tolerance applied to "exp" and "nbf". It absorbs clock drift
// between the issuing service and the verifier, and nothing more: it is added
// to the lifetime of every token, so it is kept well below the TTL.
func NewVerifier(keys map[string]ed25519.PublicKey, expectedIssuer string, skew time.Duration) *Verifier {
	own := make(map[string]ed25519.PublicKey, len(keys))
	for kid, pub := range keys {
		own[kid] = pub
	}
	if skew < 0 {
		skew = 0
	}
	return &Verifier{
		keys:           own,
		expectedIssuer: expectedIssuer,
		skew:           skew,
		now:            time.Now,
	}
}

// Verify checks token and returns its claims.
//
// Every failure returns ErrInvalidToken with no further detail, see the
// comment on that variable. The order of the checks is deliberate: nothing in
// the payload is parsed, let alone trusted, until the signature has been
// verified.
func (v *Verifier) Verify(token string, expectedAudience string) (*Claims, error) {
	// Fail closed. An empty expected audience would otherwise accept a token
	// minted for any other API key, which is the whole point of pinning it.
	if expectedAudience == "" || v.expectedIssuer == "" {
		return nil, ErrInvalidToken
	}

	// RFC 7515 section 7.1: the compact serialisation is exactly three
	// segments. Splitting on every dot and requiring three rejects a fourth
	// segment, which a lenient parser would ignore while a second recipient
	// might read it, and rejects a two-segment unsecured JWS outright.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var hdr joseHeader
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return nil, ErrInvalidToken
	}

	// The algorithm is fixed by this package, never read from the token to
	// decide what to do. This is the single check that stops the whole family
	// of algorithm-confusion attacks: "alg":"none" with an empty signature,
	// and "alg":"HS256" with the published Ed25519 public key used as the
	// HMAC secret. Both land here and are refused before any key is loaded.
	if hdr.Alg != algEdDSA {
		return nil, ErrInvalidToken
	}

	// RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a
	// "crit" header extension it does not understand. This package
	// understands none, so any "crit" at all is fatal. Ignoring it would let
	// an attacker attach a header that a future, stricter verifier would act
	// on while this one does not.
	if len(hdr.Crit) != 0 {
		return nil, ErrInvalidToken
	}

	// A JWS signed by the same key for another purpose must not pass as an
	// assertion.
	if hdr.Typ != "" && hdr.Typ != typJWT {
		return nil, ErrInvalidToken
	}

	// The key is selected by "kid", and one candidate only. Trying every
	// known key in turn would mean a token signed under a revoked or
	// deliberately weak key still verifies as long as that key is in the set,
	// and it would make the cost of a failure depend on the size of the set.
	if hdr.Kid == "" {
		return nil, ErrInvalidToken
	}
	pub, ok := v.keys[hdr.Kid]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidToken
	}

	sig, err := decodeSegment(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}

	// The signature covers the header and the payload exactly as they were
	// received, which is why the encoded form is signed rather than any
	// re-serialisation of the parsed structures.
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, ErrInvalidToken
	}

	// Only now is the payload worth parsing.
	rawPayload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return nil, ErrInvalidToken
	}

	if c.Issuer != v.expectedIssuer {
		return nil, ErrInvalidToken
	}
	if c.Audience != expectedAudience {
		return nil, ErrInvalidToken
	}
	if c.Subject == "" || len(c.AMR) == 0 {
		return nil, ErrInvalidToken
	}

	// "exp" is required. A JWT library that treats a missing "exp" as "no
	// expiry" turns a captured assertion into a permanent credential.
	if c.ExpiresAt == 0 {
		return nil, ErrInvalidToken
	}
	now := v.now()
	if now.After(time.Unix(c.ExpiresAt, 0).Add(v.skew)) {
		return nil, ErrInvalidToken
	}
	if c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-v.skew)) {
		return nil, ErrInvalidToken
	}

	return &c, nil
}

// LoadPrivateKeyPEM reads an Ed25519 private key from a PKCS#8 PEM file.
//
// The file mode is checked before the contents are read, in the same spirit as
// internal/crypto/kek: a signing key readable by any local account is a
// forgery waiting to happen, and refusing to start is the only way an operator
// finds out.
func LoadPrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("assertion: resolve %q: %w", path, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("assertion: stat %q: %w", abs, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: %q is mode %#o, must not be readable by group or other (chmod 600)", ErrInsecureKeyMode, abs, mode)
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("assertion: read %q: %w", abs, err)
	}
	defer zeroize.Bytes(raw)

	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %q contains no PEM block", ErrBadPEM, abs)
	}
	if block.Type != pemTypePrivate {
		return nil, fmt.Errorf("%w: %q holds a %q block, expected %q (convert with: openssl pkcs8 -topk8 -nocrypt)",
			ErrBadPEM, abs, block.Type, pemTypePrivate)
	}
	// Trailing content is refused so a second key cannot sit unnoticed behind
	// the first, where an operator rotating the file would not see it.
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: %q has trailing data after the PEM block", ErrBadPEM, abs)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrBadPEM, abs, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %q holds a %T, and this package signs only with Ed25519", ErrNotEd25519, abs, parsed)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: %q holds %d bytes", ErrInvalidKey, abs, len(priv))
	}
	return priv, nil
}

// GenerateKeyPEM returns a fresh Ed25519 signing key as PKCS#8 PEM and its
// public key as SubjectPublicKeyInfo PEM, for the setup wizard.
//
// The private PEM must be written with mode 0600, or LoadPrivateKeyPEM will
// refuse it.
func GenerateKeyPEM() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("assertion: generate key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("assertion: marshal private key: %w", err)
	}
	defer zeroize.Bytes(privDER)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("assertion: marshal public key: %w", err)
	}

	privPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypePrivate, Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: pubDER})
	if privPEM == nil || pubPEM == nil {
		return nil, nil, fmt.Errorf("assertion: encode pem: unexpected failure")
	}
	return privPEM, pubPEM, nil
}

// encodeSegment encodes one compact serialisation segment. RFC 7515 section 2
// defines every segment as base64url with the padding removed.
func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSegment decodes one compact serialisation segment.
//
// RawURLEncoding has no "=" in its alphabet, so a padded segment is rejected,
// and Strict additionally rejects a final quantum whose unused bits are not
// zero. Together they leave each segment exactly one valid encoding: a lenient
// decoder would let an attacker re-encode a captured header or payload into a
// different string that still carries the same bytes past the signature check
// of a second, laxer implementation.
func decodeSegment(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidToken
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return b, nil
}
