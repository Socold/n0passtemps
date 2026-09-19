// Package token issues and verifies the bearer credentials that authenticate
// callers of the service: the API keys used on the public surface and the
// tokens used on the administrative one.
//
// # Why these are hashed with SHA-256 and not with Argon2id
//
// Recovery codes in this project are hashed with Argon2id. These are not, and
// the difference is deliberate rather than an inconsistency.
//
// Password stretching exists to make each guess expensive, which is worth
// paying for when the secret has little entropy. These tokens are generated
// here, never chosen by a person, and carry 160 bits of entropy in the
// verifier. An attacker guessing one is not helped by a fast hash: 2^160 is out
// of reach whether each attempt costs a nanosecond or a second.
//
// Meanwhile the cost would be paid on every single request. Argon2id at the
// OWASP baseline allocates 19 MiB and takes tens of milliseconds, so putting it
// on the authentication path of an API key would add that to every call and hand
// an unauthenticated caller a way to exhaust memory by presenting invalid keys.
// That is a denial-of-service vector introduced in the name of hardening.
//
// So the construction here is a single SHA-256 over a domain separator and the
// verifier, compared in constant time. What makes it safe is the entropy of the
// verifier, which this package generates and therefore guarantees.
//
// # Format
//
// A token is presented as:
//
//	npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY
//	^^^^ prefix         ^^^^^^^^^^^^^^^^^^^^^^ verifier, 160 bits
//	     ^^^^^^^^^^^^^^^ selector, stored in clear and indexed
//
// Every example in this repository uses that shape: a selector beginning
// EXAMPLEONLY and a verifier that is plain text. A real verifier is 27
// base64url characters, so nothing written down in the documentation can be
// mistaken for a credential, by a reader or by a secret scanner.
//
// The selector makes authentication one indexed lookup followed by one hash,
// instead of a scan that hashes every stored key. Without it, verifying a
// token would cost one hash per key in the database, which both scales badly
// and leaks the number of keys through timing.
//
// The prefix is included so that a leaked token is recognisable. Secret
// scanners key on exactly this kind of marker, which is what lets a token
// pushed to a public repository be caught before it is used.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// Kind distinguishes the two credential families, so a token minted for one
// surface cannot be presented on the other even if it leaks.
type Kind string

const (
	// KindAPIKey authenticates an integrating application on /v1.
	KindAPIKey Kind = "npt"
	// KindAdmin authenticates an operator on /admin/v1.
	KindAdmin Kind = "npa"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindAPIKey || k == KindAdmin }

const (
	selectorBytes = 8  // 64 bits, ample to keep the lookup key unique
	verifierBytes = 20 // 160 bits, beyond any search

	// SelectorLen is the length of the encoded selector, for the schema.
	SelectorLen = selectorBytes * 2
)

// Errors reported by this package.
//
// ErrInvalid is deliberately the single failure returned for anything wrong
// with a presented token. Distinguishing a malformed token from an unknown
// selector from a wrong verifier would tell an attacker which half of a guess
// was right.
var (
	ErrInvalid = errors.New("token: invalid credential")
	ErrBadKind = errors.New("token: unknown credential kind")
	ErrBadHash = errors.New("token: malformed stored hash")
)

// Token is a freshly minted credential.
type Token struct {
	// Display is the full token, shown to the operator exactly once.
	Display string
	// Selector is the clear lookup key to persist and index.
	Selector string
	// Hash is the encoded digest of the verifier, to persist.
	Hash string
}

// Generate mints a credential of the given kind.
//
// Display is not recoverable afterwards. Only Selector and Hash are persisted,
// so a stolen database yields no usable token.
func Generate(kind Kind) (*Token, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrBadKind, kind)
	}

	selRaw := make([]byte, selectorBytes)
	if _, err := rand.Read(selRaw); err != nil {
		return nil, fmt.Errorf("token: generate selector: %w", err)
	}
	selector := hex.EncodeToString(selRaw)

	verRaw := make([]byte, verifierBytes)
	if _, err := rand.Read(verRaw); err != nil {
		return nil, fmt.Errorf("token: generate verifier: %w", err)
	}
	defer zeroize.Bytes(verRaw)

	verifier := base64.RawURLEncoding.EncodeToString(verRaw)

	return &Token{
		Display:  string(kind) + "_" + selector + "." + verifier,
		Selector: selector,
		Hash:     Hash(kind, selector, verifier),
	}, nil
}

// Hash computes the stored digest for a verifier.
//
// The kind and the selector are mixed in alongside the verifier. Binding the
// digest to them means a stored hash cannot be moved to a different row, or
// from the API key table to the admin token table, and still verify.
func Hash(kind Kind, selector, verifier string) string {
	h := sha256.New()
	h.Write([]byte("n0passtemps/bearer-token/v1"))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(selector))
	h.Write([]byte{0})
	h.Write([]byte(verifier))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Parsed is a presented token split into its parts.
type Parsed struct {
	Kind     Kind
	Selector string
	verifier string
}

// Parse splits a presented token without touching the database.
//
// It performs only structural checks, so a malformed token is rejected before
// any query runs. That keeps an unauthenticated caller from generating database
// load with rubbish input.
func Parse(presented string) (*Parsed, error) {
	s := strings.TrimSpace(presented)

	underscore := strings.IndexByte(s, '_')
	if underscore <= 0 {
		return nil, ErrInvalid
	}
	kind := Kind(s[:underscore])
	if !kind.Valid() {
		return nil, ErrInvalid
	}

	rest := s[underscore+1:]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return nil, ErrInvalid
	}

	selector, verifier := rest[:dot], rest[dot+1:]
	if len(selector) != SelectorLen || !isHex(selector) {
		return nil, ErrInvalid
	}
	// The verifier is checked for length and alphabet, not decoded: a decode
	// failure and a wrong value must be indistinguishable to the caller.
	if len(verifier) != base64.RawURLEncoding.EncodedLen(verifierBytes) {
		return nil, ErrInvalid
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(verifier); err != nil {
		return nil, ErrInvalid
	}

	return &Parsed{Kind: kind, Selector: selector, verifier: verifier}, nil
}

// Verify reports whether the parsed token matches a stored hash.
//
// The comparison is constant time. A malformed stored hash returns an error
// rather than false, so a corrupted row is not silently read as a failed
// authentication attempt and left to look like an attack.
func (p *Parsed) Verify(storedHash string) (bool, error) {
	if !strings.HasPrefix(storedHash, "sha256:") {
		return false, fmt.Errorf("%w: expected a sha256 prefix", ErrBadHash)
	}
	want, err := hex.DecodeString(strings.TrimPrefix(storedHash, "sha256:"))
	if err != nil || len(want) != sha256.Size {
		return false, fmt.Errorf("%w: digest is not %d hex bytes", ErrBadHash, sha256.Size)
	}

	computed := Hash(p.Kind, p.Selector, p.verifier)
	got, err := hex.DecodeString(strings.TrimPrefix(computed, "sha256:"))
	if err != nil {
		return false, fmt.Errorf("token: encode digest: %w", err)
	}

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// FromAuthorizationHeader extracts a bearer token from an Authorization header.
//
// The scheme comparison is case-insensitive because RFC 7235 section 2.1 makes
// it so, and clients disagree on the casing in practice.
func FromAuthorizationHeader(header string) (string, error) {
	const scheme = "bearer"
	h := strings.TrimSpace(header)
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", ErrInvalid
	}
	if h[len(scheme)] != ' ' && h[len(scheme)] != '\t' {
		return "", ErrInvalid
	}
	value := strings.TrimSpace(h[len(scheme)+1:])
	if value == "" {
		return "", ErrInvalid
	}
	return value, nil
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return len(s) > 0
}
