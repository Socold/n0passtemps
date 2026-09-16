package n0passtemps

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer serves a JWK Set that a test can swap, and counts the fetches.
type jwksServer struct {
	mu     sync.Mutex
	doc    string
	status int
	hits   atomic.Int32
}

func (s *jwksServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	s.mu.Lock()
	doc, status := s.doc, s.status
	s.mu.Unlock()
	if r.URL.Path != "/v1/.well-known/jwks.json" {
		http.NotFound(w, r)
		return
	}
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(doc))
}

func (s *jwksServer) set(doc string, status int) {
	s.mu.Lock()
	s.doc, s.status = doc, status
	s.mu.Unlock()
}

func jwkJSON(pub ed25519.PublicKey) string {
	return `{"kty":"OKP","crv":"Ed25519","x":"` + b64(pub) + `","use":"sig","alg":"EdDSA","kid":"` + Thumbprint(pub) + `"}`
}

func jwksJSON(keys ...ed25519.PublicKey) string {
	entries := make([]string, len(keys))
	for i, k := range keys {
		entries[i] = jwkJSON(k)
	}
	return `{"keys":[` + strings.Join(entries, ",") + `]}`
}

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newRemote(t *testing.T, s *jwksServer, opts ...JWKSOption) (*RemoteKeySet, *fakeClock) {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	clock := &fakeClock{now: testNow}
	opts = append([]JWKSOption{WithJWKSClock(clock.Now)}, opts...)
	r, err := RemoteJWKS(srv.URL+"/v1/.well-known/jwks.json", srv.Client(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return r, clock
}

func TestRemoteJWKSCacheHit(t *testing.T) {
	pub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, clock := newRemote(t, s)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		got, err := r.Key(ctx, Thumbprint(pub))
		if err != nil || !got.Equal(pub) {
			t.Fatalf("lookup %d: key = %x, err = %v", i, got, err)
		}
		clock.Advance(time.Minute - time.Second)
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches for five lookups inside the cache lifetime, want 1", n)
	}
}

func TestRemoteJWKSRefreshAfterTTL(t *testing.T) {
	pub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, clock := newRemote(t, s, WithJWKSCacheTTL(time.Minute))
	ctx := context.Background()

	if _, err := r.Key(ctx, Thumbprint(pub)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(59 * time.Second)
	if _, err := r.Key(ctx, Thumbprint(pub)); err != nil || s.hits.Load() != 1 {
		t.Fatalf("err = %v after %d fetches", err, s.hits.Load())
	}
	clock.Advance(time.Second)
	if _, err := r.Key(ctx, Thumbprint(pub)); err != nil || s.hits.Load() != 2 {
		t.Fatalf("err = %v after %d fetches, want a second fetch at the lifetime", err, s.hits.Load())
	}
}

func TestRemoteJWKSRefetchOnUnknownKid(t *testing.T) {
	oldPub, _ := newKey(t)
	newPub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(oldPub)}
	r, _ := newRemote(t, s)
	ctx := context.Background()

	if _, err := r.Key(ctx, Thumbprint(oldPub)); err != nil {
		t.Fatal(err)
	}

	// The operator rotates: both keys are now published side by side.
	s.set(jwksJSON(oldPub, newPub), 0)

	got, err := r.Key(ctx, Thumbprint(newPub))
	if err != nil || !got.Equal(newPub) {
		t.Fatalf("the rotated key was not picked up: %v", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches, want 2", n)
	}

	// The refetch replaced the cache, so both keys are now served from it.
	if _, err := r.Key(ctx, Thumbprint(oldPub)); err != nil {
		t.Errorf("the old key was lost: %v", err)
	}
	if _, err := r.Key(ctx, Thumbprint(newPub)); err != nil {
		t.Errorf("the new key was not cached: %v", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches, want 2", n)
	}
}

func TestRemoteJWKSRefetchRateLimit(t *testing.T) {
	pub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, clock := newRemote(t, s, WithJWKSRefetchInterval(10*time.Second))
	ctx := context.Background()

	if _, err := r.Key(ctx, Thumbprint(pub)); err != nil {
		t.Fatal(err)
	}

	// An attacker submits tokens with random key identifiers.
	for i := 0; i < 100; i++ {
		_, err := r.Key(ctx, "random-kid-"+itoa(i))
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("lookup %d: err = %v, want ErrKeyNotFound", i, err)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Fatalf("%d fetches for 100 unknown identifiers, want 2: the first load and one refetch", n)
	}

	// The known key keeps verifying throughout.
	if _, err := r.Key(ctx, Thumbprint(pub)); err != nil {
		t.Errorf("the cached key stopped resolving: %v", err)
	}

	clock.Advance(9 * time.Second)
	_, _ = r.Key(ctx, "still-too-early")
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches before the interval elapsed, want 2", n)
	}

	clock.Advance(time.Second)
	_, _ = r.Key(ctx, "now-allowed")
	_, _ = r.Key(ctx, "but-only-once")
	if n := s.hits.Load(); n != 3 {
		t.Errorf("%d fetches once the interval elapsed, want 3", n)
	}
}

func TestRemoteJWKSThroughVerifier(t *testing.T) {
	pub, priv := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, _ := newRemote(t, s)
	v, err := NewVerifier(testIssuer, testAudience, r, WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := v.Verify(ctx, sign(t, priv, header(Thumbprint(pub)), validClaims())); err != nil {
		t.Fatalf("err = %v", err)
	}

	// Tokens that fail before the key lookup must not reach the network.
	before := s.hits.Load()
	_, _ = v.Verify(ctx, sign(t, priv, `{"alg":"HS256","kid":"unknown-1","typ":"JWT"}`, validClaims()))
	_, _ = v.Verify(ctx, b64([]byte(header("unknown-2")))+".e30.c2hvcnQ")
	if n := s.hits.Load(); n != before {
		t.Errorf("a token refused on its header or signature length caused %d fetches", n-before)
	}

	_, other := newKey(t)
	for i := 0; i < 20; i++ {
		mustRefuse(t, v, sign(t, other, header("forged-"+itoa(i)), validClaims()))
	}
	if n := s.hits.Load() - before; n != 1 {
		t.Errorf("20 forged key identifiers caused %d fetches, want 1", n)
	}
}

func TestRemoteJWKSFailure(t *testing.T) {
	pub, priv := newKey(t)
	s := &jwksServer{status: http.StatusServiceUnavailable}
	r, clock := newRemote(t, s, WithJWKSRefetchInterval(10*time.Second), WithJWKSCacheTTL(time.Minute))
	ctx := context.Background()
	kid := Thumbprint(pub)

	if _, err := r.Key(ctx, kid); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want a fetch failure", err)
	}
	// A failing endpoint is not hammered either.
	if _, err := r.Key(ctx, kid); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want a failure", err)
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches against a failing endpoint inside the interval, want 1", n)
	}

	v, err := NewVerifier(testIssuer, testAudience, r, WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx, sign(t, priv, header(kid), validClaims()))
	if !errors.Is(err, ErrInvalidAssertion) || !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("err = %v, want both ErrInvalidAssertion and ErrKeysUnavailable", err)
	}

	// The endpoint recovers.
	s.set(jwksJSON(pub), 0)
	clock.Advance(10 * time.Second)
	if _, err := r.Key(ctx, kid); err != nil {
		t.Fatalf("no recovery: %v", err)
	}

	// It fails again, and the cache lapses: a stale key is not served.
	s.set("", http.StatusInternalServerError)
	clock.Advance(time.Minute)
	if _, err := r.Key(ctx, kid); err == nil {
		t.Error("a lapsed key was served while the endpoint was down")
	}
}

func TestRemoteJWKSCancelledCallerDoesNotDelayOthers(t *testing.T) {
	pub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, _ := newRemote(t, s)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Key(cancelled, Thumbprint(pub)); err == nil {
		t.Fatal("a cancelled context fetched keys")
	}
	if _, err := r.Key(context.Background(), Thumbprint(pub)); err != nil {
		t.Errorf("the next caller was held back: %v", err)
	}
}

func TestRemoteJWKSConcurrentLookupsShareOneFetch(t *testing.T) {
	pub, _ := newKey(t)
	s := &jwksServer{doc: jwksJSON(pub)}
	r, _ := newRemote(t, s)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Key(context.Background(), Thumbprint(pub)); err != nil {
				t.Errorf("err = %v", err)
			}
		}()
	}
	wg.Wait()
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches for 32 concurrent lookups, want 1", n)
	}
}

func TestRemoteJWKSBodyLimit(t *testing.T) {
	pub, _ := newKey(t)
	doc := `{"keys":[` + jwkJSON(pub) + `],"padding":"` + strings.Repeat("a", maxResponseBytes) + `"}`
	r, _ := newRemote(t, &jwksServer{doc: doc})
	if _, err := r.Key(context.Background(), Thumbprint(pub)); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestRemoteJWKSTransportRule(t *testing.T) {
	if _, err := RemoteJWKS("http://auth.example.org/v1/.well-known/jwks.json", nil); err == nil {
		t.Error("a plain http JWKS URL was accepted")
	}
	if _, err := RemoteJWKS("http://auth.internal/v1/.well-known/jwks.json", nil, WithInsecureJWKS()); err != nil {
		t.Errorf("the explicit option was not honoured: %v", err)
	}
	if _, err := RemoteJWKS("https://auth.example.org/v1/.well-known/jwks.json", nil); err != nil {
		t.Errorf("an https URL was refused: %v", err)
	}
	if _, err := RemoteJWKS("http://127.0.0.1:8080/v1/.well-known/jwks.json", nil); err != nil {
		t.Errorf("a loopback URL was refused: %v", err)
	}
	const good = "https://auth.example.org/v1/.well-known/jwks.json"
	if _, err := RemoteJWKS(good, nil, WithJWKSRefetchInterval(0)); err == nil {
		t.Error("a zero refetch interval, which disables the protection, was accepted")
	}
	if _, err := RemoteJWKS(good, nil, WithJWKSCacheTTL(0)); err == nil {
		t.Error("a zero cache lifetime was accepted")
	}
	if _, err := RemoteJWKS(good, nil, WithJWKSClock(nil)); err == nil {
		t.Error("a nil clock was accepted")
	}
}

func TestParseJWKS(t *testing.T) {
	pub, _ := newKey(t)
	other, _ := newKey(t)
	good := jwkJSON(pub)

	t.Run("unusable entries are skipped", func(t *testing.T) {
		doc := `{"keys":[` + strings.Join([]string{
			`{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"rsa-1"}`,
			`{"kty":"OKP","crv":"X25519","x":"` + b64(other) + `","kid":"x25519"}`,
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64(other) + `","use":"enc","kid":"` + Thumbprint(other) + `"}`,
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64(other) + `","alg":"HS256","kid":"` + Thumbprint(other) + `"}`,
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64(other[:16]) + `","kid":"short"}`,
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64(other) + `","kid":"not-the-thumbprint"}`,
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64(other) + `"}`,
			good,
		}, ",") + `]}`
		keys, err := ParseJWKS([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 1 || !keys[Thumbprint(pub)].Equal(pub) {
			t.Errorf("keys = %v", keys)
		}
	})

	t.Run("a kid cannot be claimed by another key", func(t *testing.T) {
		doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64(other) + `","kid":"` + Thumbprint(pub) + `"}]}`
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Error("a key published under the thumbprint of another was accepted")
		}
	})

	for name, doc := range map[string]string{
		"not JSON":      `<html>`,
		"no keys":       `{"keys":[]}`,
		"no member":     `{}`,
		"only unusable": `{"keys":[{"kty":"RSA"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWKS([]byte(doc)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestStaticKeys(t *testing.T) {
	pub, _ := newKey(t)
	keys, err := NewStaticKeys(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keys.Key(context.Background(), Thumbprint(pub))
	if err != nil || !got.Equal(pub) {
		t.Errorf("key = %x, err = %v", got, err)
	}
	if _, err := keys.Key(context.Background(), "other"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("err = %v, want ErrKeyNotFound", err)
	}
	if _, err := NewStaticKeys(pub[:8]); err == nil {
		t.Error("a short key was accepted")
	}
	var empty StaticKeys
	if _, err := empty.Key(context.Background(), "x"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("nil set: err = %v", err)
	}
}
