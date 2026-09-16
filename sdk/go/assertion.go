package n0passtemps

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// algEdDSA is the only value of the "alg" header this package accepts, per
// RFC 8037 section 3.1.
const algEdDSA = "EdDSA"

// typJWT marks the payload as a JWT claims set, per RFC 7519 section 5.1.
const typJWT = "JWT"

// maxAssertionBytes bounds the work an unauthenticated string can cause. A
// real assertion is around five hundred bytes.
const maxAssertionBytes = 8 << 10

// DefaultClockSkew is the tolerance applied to "exp" and "nbf" unless
// WithClockSkew says otherwise.
const DefaultClockSkew = 30 * time.Second

// ErrInvalidAssertion is the only outcome of a failed verification.
//
// Which check failed is deliberately not reported. The distinction would tell
// whoever submitted the token whether a forgery had the right audience,
// whether a "kid" exists, or whether a captured token is expired and not
// wrongly signed, and error strings have a way of reaching the person on the
// other end.
var ErrInvalidAssertion = errors.New("n0passtemps: the assertion is not valid")

// Factor names one authentication factor that contributed to a ceremony. The
// values populate the "amr" claim.
type Factor string

// The factors the server records.
const (
	// FactorWebAuthn is a WebAuthn assertion that proved possession of the
	// authenticator.
	FactorWebAuthn Factor = "webauthn"

	// FactorWebAuthnUV is present beside FactorWebAuthn when the authenticator
	// also verified the user, with a PIN or a biometric, during this very
	// ceremony. It is never inferred from how the credential was registered.
	FactorWebAuthnUV Factor = "webauthn-uv"

	// FactorTOTP is a time-based one-time password.
	FactorTOTP Factor = "totp"

	// FactorRecoveryCode is a single-use recovery code.
	FactorRecoveryCode Factor = "recovery-code"
)

// Claims is the verified content of an assertion.
//
// Verify establishes that the server issued the token for this application a
// moment ago. Two decisions remain with the caller, because only the caller
// can make them:
//
// Enforce single use of ID. An assertion stays valid until it expires, sixty
// seconds by default, and within that window a copy verifies as well as the
// original. Record each "jti" until its ExpiresAt in a store shared by every
// instance of the application, and refuse one seen before.
//
// Check AMR against the policy of the operation at hand, with HasFactor. The
// factors are not equivalent: a recovery code is a bearer secret that may have
// sat in a drawer for a year, which is not the assurance of a WebAuthn
// ceremony with user verification. A sign-in may accept any factor where a
// payment requires FactorWebAuthnUV, and a recovery-code sign-in is commonly
// confined to re-enrolling an authenticator.
//
// The date claims are seconds since the Unix epoch, kept as the integers that
// were signed.
type Claims struct {
	// Issuer identifies the deployment that ran the ceremony.
	Issuer string `json:"iss"`

	// Subject is the server's subject identifier, Subject.SubjectID, and not
	// the reference the application supplied.
	Subject string `json:"sub"`

	// Audience is the identifier of the API key the ceremony was performed
	// for.
	Audience string `json:"aud"`

	IssuedAt  int64 `json:"iat"`
	NotBefore int64 `json:"nbf"`
	ExpiresAt int64 `json:"exp"`

	// ID is the unique token identifier, the key of the caller's replay cache.
	ID string `json:"jti"`

	// AMR lists the factors that completed the ceremony.
	AMR []Factor `json:"amr"`

	// CredentialID is the base64url WebAuthn credential identifier, present
	// when a WebAuthn factor was used.
	CredentialID string `json:"cid,omitempty"`

	// TenantID is present on multi-tenant deployments.
	TenantID string `json:"tid,omitempty"`
}

// HasFactor reports whether f is among the factors that completed the
// ceremony.
func (c *Claims) HasFactor(f Factor) bool {
	if c == nil {
		return false
	}
	for _, got := range c.AMR {
		if got == f {
			return true
		}
	}
	return false
}

// Verifier checks assertions for one issuer and one audience.
//
// A Verifier is safe for concurrent use.
type Verifier struct {
	issuer   string
	audience string
	keys     KeySource
	skew     time.Duration
	now      func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithClockSkew sets the tolerance applied to "exp" and "nbf". The default is
// DefaultClockSkew.
//
// It absorbs clock drift between the server and this process and nothing more.
// It is added to the lifetime of every assertion, so it belongs well below the
// sixty seconds an assertion lives.
func WithClockSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.skew = d }
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) { v.now = now }
}

// NewVerifier returns a Verifier that accepts only assertions issued by issuer
// for audience, and signed by a key of keys.
//
// issuer is the server's configured issuer name, "n0passtemps" unless the
// operator changed it. audience is the identifier of the application's API
// key, as reported when the key was minted: it is what stops an assertion
// obtained through another tenant's key from being presented here. Both are
// required, because an empty expectation would match a token that omits the
// claim.
func NewVerifier(issuer, audience string, keys KeySource, opts ...VerifierOption) (*Verifier, error) {
	if issuer == "" {
		return nil, errors.New("n0passtemps: new verifier: the expected issuer is empty")
	}
	if audience == "" {
		return nil, errors.New("n0passtemps: new verifier: the expected audience is empty")
	}
	if keys == nil {
		return nil, errors.New("n0passtemps: new verifier: the key source is nil")
	}

	v := &Verifier{issuer: issuer, audience: audience, keys: keys, skew: DefaultClockSkew, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(v)
		}
	}
	if v.skew < 0 {
		return nil, fmt.Errorf("n0passtemps: new verifier: clock skew %s is negative", v.skew)
	}
	if v.now == nil {
		return nil, errors.New("n0passtemps: new verifier: the clock is nil")
	}
	return v, nil
}

// joseHeader is the JWS protected header, restricted to the members inspected
// here. Crit is raw so that its mere presence can be detected.
type joseHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
}

// Verify checks token and returns its claims.
//
// Every failure is ErrInvalidAssertion and nothing more specific; see that
// variable. The one distinction kept is operational: when the KeySource itself
// fails, the error also matches ErrKeysUnavailable, so that an outage of the
// JWKS endpoint can be told from a stream of bad tokens.
//
// The order of the checks is deliberate. Nothing in the payload is parsed, let
// alone trusted, until the signature has been verified.
//
// A nil error means the token is authentic, current and meant for this
// application. It does not mean the token is new or sufficient: see Claims for
// the "jti" and "amr" checks that remain the caller's.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if len(token) > maxAssertionBytes {
		return nil, ErrInvalidAssertion
	}

	// RFC 7515 section 7.1: the compact serialisation is exactly three
	// segments. Splitting on every dot and requiring three refuses a fourth
	// segment, which a lenient parser would ignore while a second recipient
	// might read it, and refuses a two-segment unsecured JWS outright.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidAssertion
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrInvalidAssertion
	}
	var hdr joseHeader
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return nil, ErrInvalidAssertion
	}

	// The algorithm is fixed by this package and never read from the token to
	// decide what to do. This one comparison stops the whole family of
	// algorithm confusion attacks: "none" with an empty signature, and "HS256"
	// with the published Ed25519 public key used as the HMAC secret. Both end
	// here, before any key is looked up.
	if hdr.Alg != algEdDSA {
		return nil, ErrInvalidAssertion
	}

	// RFC 7515 section 4.1.11: a recipient must refuse a JWS whose "crit"
	// names an extension it does not understand. This verifier understands
	// none, so the member is refused whatever it holds. Ignoring it would let
	// a header through that a stricter verifier elsewhere would act on.
	if len(hdr.Crit) != 0 {
		return nil, ErrInvalidAssertion
	}

	// A JWS signed by the same key for another purpose must not pass as an
	// assertion.
	if hdr.Typ != "" && hdr.Typ != typJWT {
		return nil, ErrInvalidAssertion
	}

	// The key is selected by "kid", and one candidate only. Trying every known
	// key in turn would let a token signed under a key that should no longer
	// be in use verify for as long as that key lingers in the set, and would
	// make the cost of a failure grow with the size of the set.
	if hdr.Kid == "" {
		return nil, ErrInvalidAssertion
	}

	// The signature is decoded before the key is looked up, so that a token
	// which could never verify does not reach a KeySource that may go to the
	// network for it.
	sig, err := decodeSegment(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidAssertion
	}

	pub, err := v.keys.Key(ctx, hdr.Kid)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, ErrInvalidAssertion
		}
		return nil, fmt.Errorf("%w: %w: %w", ErrInvalidAssertion, ErrKeysUnavailable, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidAssertion
	}

	// The signature covers the header and the payload exactly as they were
	// received, which is why the encoded form is checked and not a
	// re-serialisation of the parsed structures.
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrInvalidAssertion
	}

	// Only now is the payload worth parsing.
	rawPayload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, ErrInvalidAssertion
	}
	var c Claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return nil, ErrInvalidAssertion
	}

	if c.Issuer != v.issuer || c.Audience != v.audience {
		return nil, ErrInvalidAssertion
	}
	if c.Subject == "" || len(c.AMR) == 0 {
		return nil, ErrInvalidAssertion
	}

	// "exp" is required. Reading a missing "exp" as "no expiry" would turn a
	// captured assertion into a permanent credential.
	if c.ExpiresAt <= 0 {
		return nil, ErrInvalidAssertion
	}
	now := v.now()
	if now.After(time.Unix(c.ExpiresAt, 0).Add(v.skew)) {
		return nil, ErrInvalidAssertion
	}
	if c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-v.skew)) {
		return nil, ErrInvalidAssertion
	}

	return &c, nil
}

// decodeSegment decodes one compact serialisation segment.
//
// RawURLEncoding has no "=" in its alphabet, so a padded segment is refused,
// and Strict also refuses a final quantum whose unused bits are not zero.
// Together they leave each segment exactly one valid encoding. A lenient
// decoder would let someone re-encode a captured header or payload into a
// different string that carries the same bytes, which is enough to slip the
// same token twice past a replay cache keyed on the token text.
//
// The decoder of encoding/base64 skips carriage returns and line feeds even in
// strict mode, so they are refused here first. In the signature segment they
// would otherwise yield a second spelling of a token that still verifies.
func decodeSegment(s string) ([]byte, error) {
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return nil, ErrInvalidAssertion
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrInvalidAssertion
	}
	return b, nil
}
