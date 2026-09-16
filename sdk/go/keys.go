package n0passtemps

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultJWKSCacheTTL is how long a fetched key set is trusted. It matches the
// max-age the server puts on the document.
const DefaultJWKSCacheTTL = 5 * time.Minute

// DefaultJWKSRefetchInterval is the shortest time between two fetches that a
// token can provoke.
const DefaultJWKSRefetchInterval = 10 * time.Second

// ErrKeyNotFound is what a KeySource returns when it holds no key for a "kid".
// Any other error from a KeySource means the keys could not be obtained.
var ErrKeyNotFound = errors.New("n0passtemps: no verification key has that identifier")

// ErrKeysUnavailable reports that verification could not run because the key
// source failed, as opposed to the assertion being wrong. An error carrying it
// also matches ErrInvalidAssertion, so that a caller who checks only that one
// still fails closed.
var ErrKeysUnavailable = errors.New("n0passtemps: the verification keys are unavailable")

// KeySource supplies the Ed25519 public key that has a given "kid".
//
// Key returns ErrKeyNotFound when no key has that identifier. It must never
// fall back on another key: the Verifier tries one candidate only, so that a
// token cannot shop around the published set.
type KeySource interface {
	Key(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// StaticKeys is a fixed set of verification keys indexed by "kid". It suits a
// deployment that pins the server's public key in its own configuration and
// wants verification to make no network call at all.
type StaticKeys map[string]ed25519.PublicKey

// NewStaticKeys indexes keys by their RFC 7638 thumbprint, which is the "kid"
// the server puts in every assertion.
func NewStaticKeys(keys ...ed25519.PublicKey) (StaticKeys, error) {
	set := make(StaticKeys, len(keys))
	for _, pub := range keys {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("n0passtemps: static keys: a key has %d bytes, want %d", len(pub), ed25519.PublicKeySize)
		}
		set[Thumbprint(pub)] = pub
	}
	return set, nil
}

// Key implements KeySource.
func (s StaticKeys) Key(_ context.Context, kid string) (ed25519.PublicKey, error) {
	pub, ok := s[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return pub, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint of an Ed25519 public key,
// base64url without padding.
//
// RFC 7638 section 3 fixes the hash input as the JSON object of the required
// members only, with no whitespace and the member names in lexicographic
// order. RFC 8037 section 2 names those members for an OKP key: crv, kty and
// x. The string is built by hand because the construction has to be exact: two
// implementations that disagree about it derive different identifiers for the
// same key.
func Thumbprint(pub ed25519.PublicKey) string {
	input := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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

// ParseJWKS reads a JWK Set document, as served at /v1/.well-known/jwks.json,
// into a StaticKeys.
//
// An entry that is not an Ed25519 signing key is skipped and not refused, so a
// deployment publishing an unrelated key alongside does not break
// verification. An entry whose "kid" is not the thumbprint of its own key is
// skipped as well: the server derives one from the other, so a mismatch means
// the document did not come from where the caller believes. A document with no
// usable key at all is an error.
func ParseJWKS(document []byte) (StaticKeys, error) {
	var set jwkSet
	if err := json.Unmarshal(document, &set); err != nil {
		return nil, fmt.Errorf("n0passtemps: parse JWKS: %w", err)
	}

	keys := make(StaticKeys, len(set.Keys))
	for _, entry := range set.Keys {
		if entry.Kty != "OKP" || entry.Crv != "Ed25519" {
			continue
		}
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}
		if entry.Alg != "" && entry.Alg != algEdDSA {
			continue
		}
		raw, err := decodeSegment(entry.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		if entry.Kid == "" || entry.Kid != Thumbprint(raw) {
			continue
		}
		keys[entry.Kid] = ed25519.PublicKey(raw)
	}

	if len(keys) == 0 {
		return nil, errors.New("n0passtemps: parse JWKS: the document holds no usable Ed25519 key")
	}
	return keys, nil
}

// RemoteKeySet is a KeySource backed by the server's JWKS endpoint. Build it
// with RemoteJWKS. It is safe for concurrent use.
type RemoteKeySet struct {
	url    string
	client *http.Client
	ttl    time.Duration
	minGap time.Duration
	now    func() time.Time

	// mu guards the cache. fetchMu serialises fetches and is always taken
	// first, so that a lookup served from the cache never waits on the
	// network.
	mu        sync.RWMutex
	keys      StaticKeys
	fetchedAt time.Time

	fetchMu sync.Mutex

	// notBefore is the earliest time another fetch may start. It is guarded by
	// fetchMu.
	notBefore time.Time
}

// JWKSOption configures a RemoteKeySet.
type JWKSOption func(*jwksOptions)

type jwksOptions struct {
	ttl      time.Duration
	minGap   time.Duration
	now      func() time.Time
	insecure bool
}

// WithJWKSCacheTTL sets how long a fetched key set is served before it is
// fetched again. The default is DefaultJWKSCacheTTL.
//
// The lifetime is also how long a key withdrawn from the server keeps
// verifying here, so it should stay short.
func WithJWKSCacheTTL(d time.Duration) JWKSOption {
	return func(o *jwksOptions) { o.ttl = d }
}

// WithJWKSRefetchInterval sets the minimum time between two fetches that a
// token can provoke. The default is DefaultJWKSRefetchInterval.
func WithJWKSRefetchInterval(d time.Duration) JWKSOption {
	return func(o *jwksOptions) { o.minGap = d }
}

// WithJWKSClock replaces time.Now, for tests.
func WithJWKSClock(now func() time.Time) JWKSOption {
	return func(o *jwksOptions) { o.now = now }
}

// WithInsecureJWKS permits a plain http JWKS URL on a host that is not
// loopback. See RemoteJWKS for why that is refused by default.
func WithInsecureJWKS() JWKSOption {
	return func(o *jwksOptions) { o.insecure = true }
}

// RemoteJWKS returns a KeySource that fetches the JWK Set at jwksURL, normally
// "<base URL>/v1/.well-known/jwks.json", through client. A nil client selects
// one with a ten second timeout that follows no redirect.
//
// The set is cached. A "kid" missing from a fresh cache triggers one refetch,
// which is how a key rotation is picked up without waiting for the cache to
// lapse, and such refetches are spaced by a minimum interval. The "kid" of a
// token is attacker controlled and is read before any signature can be
// checked, so without that spacing anyone able to submit tokens could make
// this process send one request to the server per forged token.
//
// When the keys cannot be fetched and the cache has lapsed, lookups fail. A
// stale key is not served: a key withdrawn after a compromise must stop
// verifying once the cache lifetime has passed, even if the endpoint is
// unreachable at that moment.
//
// The URL must use https unless the host is loopback or WithInsecureJWKS is
// passed. Whoever can alter this document in transit chooses the keys that
// assertions are verified against, and can then forge a login for any subject.
func RemoteJWKS(jwksURL string, client *http.Client, opts ...JWKSOption) (*RemoteKeySet, error) {
	o := jwksOptions{ttl: DefaultJWKSCacheTTL, minGap: DefaultJWKSRefetchInterval, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.ttl <= 0 {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: cache lifetime %s is not positive", o.ttl)
	}
	if o.minGap <= 0 {
		// Zero would switch the protection off, which no caller should do by
		// leaving a field unset.
		return nil, fmt.Errorf("n0passtemps: remote JWKS: refetch interval %s is not positive", o.minGap)
	}
	if o.now == nil {
		return nil, errors.New("n0passtemps: remote JWKS: the clock is nil")
	}

	u, err := checkEndpoint(jwksURL, o.insecure)
	if err != nil {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: %w", err)
	}

	if client == nil {
		client = newHTTPClient()
		client.Timeout = DefaultTimeout
	}

	return &RemoteKeySet{
		url:    u.String(),
		client: client,
		ttl:    o.ttl,
		minGap: o.minGap,
		now:    o.now,
	}, nil
}

// Key implements KeySource.
func (r *RemoteKeySet) Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	if pub, fresh := r.cached(kid); fresh && pub != nil {
		return pub, nil
	}

	r.fetchMu.Lock()
	defer r.fetchMu.Unlock()

	// Another goroutine may have refreshed the cache while this one waited for
	// the lock, in which case there is nothing left to do.
	pub, fresh := r.cached(kid)
	if fresh && pub != nil {
		return pub, nil
	}

	now := r.now()
	if now.Before(r.notBefore) {
		if fresh {
			return nil, ErrKeyNotFound
		}
		return nil, errors.New("n0passtemps: remote JWKS: the last fetch failed and the next one is not due yet")
	}

	keys, err := r.fetch(ctx)
	if err != nil {
		// A caller whose own context ended has not shown the endpoint to be
		// at fault, so it does not delay everyone else.
		if ctx.Err() == nil {
			r.notBefore = now.Add(r.minGap)
		}
		return nil, err
	}

	// A successful fetch that replaced a lapsed cache happens once per
	// lifetime at most and needs no spacing. One provoked by an unknown "kid"
	// does, whatever its outcome.
	if fresh {
		r.notBefore = now.Add(r.minGap)
	}

	r.mu.Lock()
	r.keys = keys
	r.fetchedAt = now
	r.mu.Unlock()

	if pub, ok := keys[kid]; ok {
		return pub, nil
	}
	return nil, ErrKeyNotFound
}

// cached looks kid up in the cache and reports whether the cache is fresh.
func (r *RemoteKeySet) cached(kid string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.keys == nil || r.now().Sub(r.fetchedAt) >= r.ttl {
		return nil, false
	}
	return r.keys[kid], true
}

// fetch downloads and parses the key set.
func (r *RemoteKeySet) fetch(ctx context.Context) (StaticKeys, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: build request: %w", stripURL(err))
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: %w", stripURL(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: unexpected status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: read response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("n0passtemps: remote JWKS: %w", ErrResponseTooLarge)
	}
	return ParseJWKS(raw)
}
