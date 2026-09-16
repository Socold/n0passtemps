package n0passtemps_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	n0passtemps "github.com/Socold/n0passtemps/sdk/go"
)

// The examples run against a stand-in for the server, so that they execute
// under "go test" with no deployment at hand. Everything below this comment
// and above the first Example function is scaffolding; an application has a
// real base URL instead.

const (
	exampleIssuer   = "n0passtemps"
	exampleAudience = "3e1f0a52-7c1d-4b8e-9a60-5d2c4f6b8a90" // the API key identifier
	exampleSubject  = "5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c"
)

// exampleTime is the moment the examples take place, so their output is fixed.
var exampleTime = time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)

func exampleClock() time.Time { return exampleTime }

// exampleKey is a fixed signing key, so that the examples print the same thing
// on every run. A deployment's key comes from its own configuration.
var exampleKey = ed25519.NewKeyFromSeed([]byte("an example seed of 32 bytes here"))

func examplePublicKey() ed25519.PublicKey { return exampleKey.Public().(ed25519.PublicKey) }

// issue signs an assertion the way the server does.
func issue(jti string, factors ...n0passtemps.Factor) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := `{"alg":"EdDSA","kid":"` + n0passtemps.Thumbprint(examplePublicKey()) + `","typ":"JWT"}`
	payload, _ := json.Marshal(n0passtemps.Claims{
		Issuer: exampleIssuer, Subject: exampleSubject, Audience: exampleAudience,
		IssuedAt: exampleTime.Unix(), NotBefore: exampleTime.Unix() - 5, ExpiresAt: exampleTime.Unix() + 60,
		ID: jti, AMR: factors,
	})
	input := enc([]byte(header)) + "." + enc(payload)
	return input + "." + enc(ed25519.Sign(exampleKey, []byte(input)))
}

// newExampleServer stands in for a deployment.
func newExampleServer() *httptest.Server {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	assertion := func(jti string, factors ...n0passtemps.Factor) string {
		names, _ := json.Marshal(factors)
		return `{"subject_id":"` + exampleSubject + `","assertion":"` + issue(jti, factors...) +
			`","expires_at":"2026-09-16T10:01:00Z","factors":` + string(names)
	}

	mux.HandleFunc("GET /v1/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := examplePublicKey()
		w.Header().Set("Content-Type", "application/jwk-set+json")
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"use":"sig","alg":"EdDSA","kid":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub), n0passtemps.Thumbprint(pub))
	})
	mux.HandleFunc("POST /v1/subjects", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, `{"subject_id":"`+exampleSubject+`","status":"active","created_at":"2026-09-01T08:00:00Z",`+
			`"credential_count":1,"totp_enrolled":true,"recovery_codes_remaining":8}`)
	})
	mux.HandleFunc("POST /v1/webauthn/{ref}/assert", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, `{"challenge_id":"0f1d2b3c-4e5f-6a7b-8c9d-0e1f2a3b4c5d",`+
			`"options":{"publicKey":{"challenge":"c29tZS1jaGFsbGVuZ2U","rpId":"example.org"}},"expires_at":"2026-09-16T10:05:00Z"}`)
	})
	mux.HandleFunc("POST /v1/webauthn/{ref}/assert/complete", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, assertion("d2ViYXV0aG4tanRpLTAwMQ", n0passtemps.FactorWebAuthn, n0passtemps.FactorWebAuthnUV)+`}`)
	})
	mux.HandleFunc("POST /v1/totp/{ref}/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body.Code {
		case "492817":
			reply(w, 200, assertion("dG90cC1qdGktMDAwMDAwMQ", n0passtemps.FactorTOTP)+`}`)
		case "throttle":
			w.Header().Set("Retry-After", "30")
			w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"type":"urn:n0passtemps:error:throttled","title":"too many attempts","status":429,` +
				`"request_id":"9f2a1c7b5d3e4f60a1b2c3d4","retry_after_seconds":30}`))
		default:
			w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"type":"urn:n0passtemps:error:ceremony-failed","title":"authentication did not succeed",` +
				`"status":401,"request_id":"5d3e4f60a1b2c3d49f2a1c7b"}`))
		}
	})
	mux.HandleFunc("POST /v1/recovery/{ref}/consume", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, assertion("cmVjb3ZlcnktanRpLTAwMQ", n0passtemps.FactorRecoveryCode)+`,"recovery_codes_remaining":7}`)
	})
	return httptest.NewServer(mux)
}

// Example is the whole of a TOTP sign-in: call the server, verify what it
// returns, refuse a replay, and apply a policy to the factors.
func Example() {
	srv := newExampleServer()
	defer srv.Close()
	ctx := context.Background()

	client, err := n0passtemps.New(srv.URL, "npt_example_key")
	if err != nil {
		log.Fatal(err)
	}
	keys, err := n0passtemps.RemoteJWKS(srv.URL+"/v1/.well-known/jwks.json", nil)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := n0passtemps.NewVerifier(exampleIssuer, exampleAudience, keys,
		n0passtemps.WithClock(exampleClock)) // an application leaves the clock alone
	if err != nil {
		log.Fatal(err)
	}

	if _, err := client.ResolveSubject(ctx, "user-7f3a", ""); err != nil {
		log.Fatal(err)
	}
	result, err := client.VerifyTOTP(ctx, "user-7f3a", "492817")
	if err != nil {
		log.Fatal(err)
	}

	claims, err := verifier.Verify(ctx, result.Assertion)
	if err != nil {
		log.Fatal(err)
	}

	// Single use is the application's to enforce. A map stands in for a store
	// shared by every instance, with entries kept until claims.ExpiresAt.
	seen := map[string]bool{}
	if seen[claims.ID] {
		log.Fatal("assertion replayed")
	}
	seen[claims.ID] = true

	fmt.Println("subject:", claims.Subject)
	fmt.Println("factors:", claims.AMR)
	fmt.Println("good for a payment:", claims.HasFactor(n0passtemps.FactorWebAuthnUV))
	// Output:
	// subject: 5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c
	// factors: [totp]
	// good for a payment: false
}

// Plain http is accepted for a loopback host and refused for any other, unless
// WithInsecureTransport is passed.
func ExampleNew() {
	client, err := n0passtemps.New("http://127.0.0.1:8080", "npt_example_key",
		n0passtemps.WithTimeout(5*time.Second),
		n0passtemps.WithUserAgent("acme-portal/2.1"),
	)
	fmt.Println(client != nil, err)

	_, err = n0passtemps.New("http://auth.example.org", "npt_example_key")
	fmt.Println(err)
	// Output:
	// true <nil>
	// n0passtemps: new client: plain http to "auth.example.org" is refused: use https, or opt in to clear-text transport explicitly
}

// The two round trips of a WebAuthn sign-in. The options go to the browser and
// the credential comes back from it, both untouched.
func ExampleClient_CompleteAssertion() {
	srv := newExampleServer()
	defer srv.Close()
	ctx := context.Background()
	client, _ := n0passtemps.New(srv.URL, "npt_example_key")

	ceremony, err := client.BeginAssertion(ctx, "user-7f3a")
	if err != nil {
		log.Fatal(err)
	}
	// Send ceremony.Options to the page as it is. The page decodes the
	// base64url members and calls navigator.credentials.get() with it. Keep
	// ceremony.ChallengeID in the user's session meanwhile.
	fmt.Println("to the browser:", string(ceremony.Options))

	// What the page posts back, forwarded without decoding it.
	fromBrowser := json.RawMessage(`{"id":"AQIDBA","rawId":"AQIDBA","type":"public-key","response":{"clientDataJSON":"e30"}}`)

	result, err := client.CompleteAssertion(ctx, "user-7f3a", ceremony.ChallengeID, fromBrowser)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("factors reported:", result.Factors)
	fmt.Println("assertion segments:", strings.Count(result.Assertion, ".")+1)
	// Output:
	// to the browser: {"publicKey":{"challenge":"c29tZS1jaGFsbGVuZ2U","rpId":"example.org"}}
	// factors reported: [webauthn webauthn-uv]
	// assertion segments: 3
}

// Branching on a refusal. A failed ceremony and a throttle are answers to show
// the user, not faults to retry.
func ExampleError() {
	srv := newExampleServer()
	defer srv.Close()
	ctx := context.Background()
	client, _ := n0passtemps.New(srv.URL, "npt_example_key")

	for _, code := range []string{"000000", "throttle"} {
		_, err := client.VerifyTOTP(ctx, "user-7f3a", code)

		var apiErr *n0passtemps.Error
		switch {
		case errors.Is(err, n0passtemps.ErrAuthenticationFailed):
			fmt.Println("wrong code; ask again")
		case errors.Is(err, n0passtemps.ErrThrottled) && errors.As(err, &apiErr):
			fmt.Printf("locked out for %s; quote request %s to support\n", apiErr.RetryAfter, apiErr.RequestID)
		case err != nil:
			log.Fatal(err)
		}
	}
	// Output:
	// wrong code; ask again
	// locked out for 30s; quote request 9f2a1c7b5d3e4f60a1b2c3d4 to support
}

// Verification with a pinned key and no network call, and a policy that tells
// a recovery code from a WebAuthn ceremony.
func ExampleVerifier_Verify() {
	keys, err := n0passtemps.NewStaticKeys(examplePublicKey())
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := n0passtemps.NewVerifier(exampleIssuer, exampleAudience, keys,
		n0passtemps.WithClockSkew(10*time.Second),
		n0passtemps.WithClock(exampleClock))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	claims, err := verifier.Verify(ctx, issue("cmVjb3ZlcnktanRpLTAwMg", n0passtemps.FactorRecoveryCode))
	if err != nil {
		log.Fatal(err)
	}
	if claims.HasFactor(n0passtemps.FactorRecoveryCode) {
		fmt.Println("recovery sign-in: allow re-enrolment only")
	}

	// A token for another application fails like any other bad token.
	other, _ := n0passtemps.NewVerifier(exampleIssuer, "another-api-key-id", keys, n0passtemps.WithClock(exampleClock))
	_, err = other.Verify(ctx, issue("cmVjb3ZlcnktanRpLTAwMw", n0passtemps.FactorTOTP))
	fmt.Println(err)
	fmt.Println(errors.Is(err, n0passtemps.ErrInvalidAssertion))
	// Output:
	// recovery sign-in: allow re-enrolment only
	// n0passtemps: the assertion is not valid
	// true
}

// The "kid" of a published key is its RFC 7638 thumbprint. This is the key of
// RFC 8037 appendix A.
func ExampleThumbprint() {
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	fmt.Println(n0passtemps.Thumbprint(ed25519.PublicKey(x)))
	// Output:
	// kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
}
