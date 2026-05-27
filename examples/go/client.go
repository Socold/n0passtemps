//go:build ignore

// Command client is a n0passtemps client for the parts of the flow a
// server-side integration performs: resolving a subject, the two server-side
// halves of a WebAuthn assertion, TOTP verification, and verifying the signed
// assertion a successful ceremony returns.
//
// It is built with the standard library alone and carries the ignore build
// constraint, so it is excluded from "go build ./..." at the repository root
// and is run on its own:
//
//	go run client.go subject [subject-reference]
//	go run client.go assert-begin [subject-reference]
//	go run client.go assert-complete -credential response.json [subject-reference]
//	go run client.go totp -code 000000 [subject-reference]
//	go run client.go verify -audience <api key id> <assertion>
//
// Environment:
//
//	N0PASSTEMPS_URL      the base URL, for example http://127.0.0.1:8080
//	N0PASSTEMPS_API_KEY  an npt_ token minted by POST /admin/v1/api-keys
//	N0PASSTEMPS_ISSUER   pins the "iss" claim, defaulting to n0passtemps
//
// # Why the verification is written out here
//
// This repository ships a verifier in internal/assertion, and the checks below
// mirror it deliberately rather than inventing their own reading of the
// specification. They are not a call into it.
//
// Go's internal-package rule confines that package to importers inside this
// module. A reader who copies this file into their own project, which is the
// only reason an example exists, would find the import refused at compile
// time. An example that only works while it sits in the repository it
// documents is not an example, so the checks are implemented against
// crypto/ed25519 here, in the shape an integrating application has to write
// them anyway.
//
// Where the two disagree, internal/assertion is authoritative.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultSubjectRef = "example-user-0001"
	defaultIssuer     = "n0passtemps"

	// algEdDSA is the only "alg" this verifier accepts, per RFC 8037
	// section 3.1.
	algEdDSA = "EdDSA"

	// typJWT marks the payload as a JWT claims set, per RFC 7519 section 5.1.
	typJWT = "JWT"

	// verifySkew absorbs clock drift between the issuing service and this
	// process, and nothing more. It is added to the lifetime of every token,
	// so it is kept well below the assertion TTL.
	verifySkew = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "subject":
		err = runSubject(args)
	case "assert-begin":
		err = runAssertBegin(args)
	case "assert-complete":
		err = runAssertComplete(args)
	case "totp":
		err = runTOTP(args)
	case "verify":
		err = runVerify(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", command)
		usage()
		os.Exit(2)
	}

	if err == nil {
		return
	}

	// Every exit path reports a sentence rather than a panic, because an
	// example that fails with a stack trace teaches nothing about the failure.
	var problem *problemError
	switch {
	case errors.As(err, &problem):
		fmt.Fprintf(os.Stderr, "the service refused the request: %v\n", problem)
		if problem.Status == http.StatusUnauthorized {
			fmt.Fprintln(os.Stderr,
				"a 401 covers a refused API key and a failed ceremony alike; the type\n"+
					"member says which: unauthorized is the key, ceremony-failed is the ceremony")
		}
		if problem.RetryAfterSeconds > 0 {
			fmt.Fprintf(os.Stderr, "rate limited, retry in %d seconds\n", problem.RetryAfterSeconds)
		}
		os.Exit(1)
	case errors.Is(err, errConfiguration):
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	case errors.Is(err, errUsage):
		fmt.Fprintf(os.Stderr, "%v\n\n", err)
		usage()
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "failed: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: go run client.go <command> [flags] [subject-reference]

commands:
  subject           resolve a subject reference and report its enrolled factors
  assert-begin      start an assertion ceremony and print the browser's options
  assert-complete   finish one with the credential the browser returned
  totp              authenticate with a TOTP code
  verify            verify an assertion against the JWKS endpoint

environment:
  N0PASSTEMPS_URL      base URL, for example http://127.0.0.1:8080
  N0PASSTEMPS_API_KEY  an npt_ token from POST /admin/v1/api-keys
  N0PASSTEMPS_ISSUER   pins the "iss" claim, default n0passtemps

flags:
  -code string        the TOTP code, for the totp command
  -challenge string   the challenge identifier, for assert-complete
  -credential string  a file holding the browser's credential, for assert-complete
  -audience string    the API key id to pin as "aud", for verify
`)
}

var (
	errConfiguration = errors.New("configuration is incomplete")
	errUsage         = errors.New("usage")
)

// problemError is an RFC 9457 problem document returned by the service.
//
// Title and Type describe a class of failure and never the specific reason one
// request was refused, so RequestID is the field that matters: it locates the
// log and audit entries where the real reason was written down.
type problemError struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Status            int    `json:"status"`
	Detail            string `json:"detail,omitempty"`
	RequestID         string `json:"request_id,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

func (p *problemError) Error() string {
	parts := []string{fmt.Sprintf("%d", p.Status), p.Type, p.Title}
	if p.Detail != "" {
		parts = append(parts, p.Detail)
	}
	if p.RequestID != "" {
		parts = append(parts, "request_id="+p.RequestID)
	}
	return strings.Join(parts, ": ")
}

// client is a thin wrapper over the /v1 surface.
type client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// newClient reads the shared environment variables.
//
// needKey is false for the JWKS endpoint, which carries no credential because
// its contents are public keys and an integrating application has to be able
// to fetch them in order to verify an assertion offline.
func newClient(needKey bool) (*client, error) {
	baseURL := strings.TrimSpace(os.Getenv("N0PASSTEMPS_URL"))
	if baseURL == "" {
		return nil, fmt.Errorf("%w: N0PASSTEMPS_URL is unset (for example http://127.0.0.1:8080)", errConfiguration)
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("%w: N0PASSTEMPS_URL is not a URL: %v", errConfiguration, err)
	}

	apiKey := strings.TrimSpace(os.Getenv("N0PASSTEMPS_API_KEY"))
	if needKey && apiKey == "" {
		return nil, fmt.Errorf("%w: N0PASSTEMPS_API_KEY is unset (an npt_ token from POST /admin/v1/api-keys)", errConfiguration)
	}

	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// do performs one request and decodes the response into out.
//
// body may be nil for a GET. A POST always sends a JSON body, even an empty
// one, because every write route requires the JSON content type: a request
// without it is refused with 415, which is what stops a form-encoded request
// being read as an object with no fields.
func (c *client) do(method, path string, body, out any) error {
	var payload io.Reader
	if method == http.MethodPost {
		encoded, err := json.Marshal(orEmptyObject(body))
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, c.baseURL+path, payload)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("could not reach the service: %w", err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		problem := &problemError{Status: response.StatusCode}
		if err := json.Unmarshal(raw, problem); err != nil || problem.Title == "" {
			problem.Title = strings.TrimSpace(string(raw))
		}
		if problem.Status == 0 {
			problem.Status = response.StatusCode
		}
		return problem
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func orEmptyObject(body any) any {
	if body == nil {
		return struct{}{}
	}
	return body
}

// refPath percent-encodes a subject reference for use in a path segment.
func refPath(subjectRef string) string {
	return url.PathEscape(subjectRef)
}

// --- response shapes ------------------------------------------------------

type subjectSummary struct {
	SubjectID       string    `json:"subject_id"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	CredentialCount int       `json:"credential_count"`
	TOTPEnrolled    bool      `json:"totp_enrolled"`
	RecoveryCodes   int       `json:"recovery_codes_remaining"`
}

type beginAssertionResult struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

type assertionResult struct {
	SubjectID string         `json:"subject_id"`
	Assertion string         `json:"assertion"`
	ExpiresAt time.Time      `json:"expires_at"`
	Factors   []string       `json:"factors"`
	Signals   map[string]any `json:"signals,omitempty"`
}

// completeRequest is the body of both completion routes.
//
// Credential is raw JSON so the browser's response passes through untouched.
// Decoding it into a struct here would drop any member this file does not know
// about, and the service needs all of them in order to verify.
type completeRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// --- commands -------------------------------------------------------------

func runSubject(args []string) error {
	flags := flag.NewFlagSet("subject", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	subjectRef := positional(flags, defaultSubjectRef)

	c, err := newClient(true)
	if err != nil {
		return err
	}

	// Resolution is idempotent, so an application may call it on every login
	// rather than tracking whether this service has seen the user before.
	var summary subjectSummary
	err = c.do(http.MethodPost, "/v1/subjects", map[string]string{
		"subject_ref":  subjectRef,
		"display_name": "Example User",
	}, &summary)
	if err != nil {
		return err
	}

	fmt.Printf("subject_id:               %s\n", summary.SubjectID)
	fmt.Printf("status:                   %s\n", summary.Status)
	fmt.Printf("created_at:               %s\n", summary.CreatedAt.Format(time.RFC3339))
	fmt.Printf("credential_count:         %d\n", summary.CredentialCount)
	fmt.Printf("totp_enrolled:            %t\n", summary.TOTPEnrolled)
	fmt.Printf("recovery_codes_remaining: %d\n", summary.RecoveryCodes)
	fmt.Println()
	fmt.Println("The response never echoes subject_ref. You already hold it, and")
	fmt.Println("echoing it would put it in a body an intermediary may cache or log.")
	return nil
}

func runAssertBegin(args []string) error {
	flags := flag.NewFlagSet("assert-begin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	subjectRef := positional(flags, defaultSubjectRef)

	c, err := newClient(true)
	if err != nil {
		return err
	}

	var begin beginAssertionResult
	if err := c.do(http.MethodPost, "/v1/webauthn/"+refPath(subjectRef)+"/assert", nil, &begin); err != nil {
		return err
	}

	pretty, err := json.MarshalIndent(json.RawMessage(begin.Options), "", "  ")
	if err != nil {
		return fmt.Errorf("format options: %w", err)
	}

	fmt.Printf("challenge_id: %s\n", begin.ChallengeID)
	fmt.Printf("expires_at:   %s\n", begin.ExpiresAt.Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Hand these options to the browser unchanged:")
	fmt.Println()
	fmt.Printf("%s\n", pretty)
	fmt.Println()
	fmt.Println("The browser decodes publicKey.challenge and every")
	fmt.Println("publicKey.allowCredentials[].id from base64url into ArrayBuffers,")
	fmt.Println("calls navigator.credentials.get, and encodes the members of the")
	fmt.Println("result back to base64url. ../node/register.html shows both")
	fmt.Println("conversions in full.")
	fmt.Println()
	fmt.Println("Save what the browser returns to a file and finish the ceremony:")
	fmt.Println()
	fmt.Printf("  go run client.go assert-complete -challenge %s \\\n", begin.ChallengeID)
	fmt.Printf("      -credential credential.json %s\n", subjectRef)
	fmt.Println()
	fmt.Println("The state that binds the two halves lives in the service's")
	fmt.Println("database under that challenge identifier, so nothing here can")
	fmt.Println("alter the expected challenge, the expected user handle or the")
	fmt.Println("user-verification requirement in between. The challenge is single")
	fmt.Println("use and expires.")
	return nil
}

func runAssertComplete(args []string) error {
	flags := flag.NewFlagSet("assert-complete", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	challengeID := flags.String("challenge", "", "the challenge identifier from assert-begin")
	credentialFile := flags.String("credential", "", "a file holding the browser's credential as JSON")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	subjectRef := positional(flags, defaultSubjectRef)

	if *credentialFile == "" {
		return fmt.Errorf("%w: -credential is required", errUsage)
	}

	raw, err := os.ReadFile(*credentialFile)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", *credentialFile, err)
	}
	if !json.Valid(raw) {
		return fmt.Errorf("%s does not contain valid JSON", *credentialFile)
	}

	// The file may hold either the bare credential or the whole completion
	// body, because both shapes turn up in practice when a developer saves
	// what a browser printed.
	body := completeRequest{ChallengeID: *challengeID, Credential: json.RawMessage(raw)}
	var wrapped completeRequest
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Credential) > 0 {
		body.Credential = wrapped.Credential
		if body.ChallengeID == "" {
			body.ChallengeID = wrapped.ChallengeID
		}
	}
	if body.ChallengeID == "" {
		return fmt.Errorf("%w: pass -challenge, or include challenge_id in the file", errUsage)
	}

	c, err := newClient(true)
	if err != nil {
		return err
	}

	var result assertionResult
	err = c.do(http.MethodPost,
		"/v1/webauthn/"+refPath(subjectRef)+"/assert/complete", body, &result)
	if err != nil {
		return err
	}

	printAssertion(&result)
	return nil
}

func runTOTP(args []string) error {
	flags := flag.NewFlagSet("totp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	code := flags.String("code", "", "the code from the user's authenticator application")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	subjectRef := positional(flags, defaultSubjectRef)

	if strings.TrimSpace(*code) == "" {
		return fmt.Errorf("%w: -code is required", errUsage)
	}

	c, err := newClient(true)
	if err != nil {
		return err
	}

	var result assertionResult
	err = c.do(http.MethodPost, "/v1/totp/"+refPath(subjectRef)+"/verify",
		map[string]string{"code": strings.TrimSpace(*code)}, &result)
	if err != nil {
		return err
	}

	printAssertion(&result)
	fmt.Println()
	fmt.Println("A code is single use. The accepted timestep is consumed by a")
	fmt.Println("compare-and-swap, so two requests presenting the same code inside")
	fmt.Println("one period cannot both succeed.")
	return nil
}

func printAssertion(result *assertionResult) {
	fmt.Printf("subject_id: %s\n", result.SubjectID)
	fmt.Printf("factors:    %s\n", strings.Join(result.Factors, ", "))
	fmt.Printf("expires_at: %s\n", result.ExpiresAt.Format(time.RFC3339))
	if len(result.Signals) > 0 {
		encoded, _ := json.Marshal(result.Signals)
		fmt.Printf("signals:    %s\n", encoded)
		fmt.Println()
		fmt.Println("A signal did not refuse the authentication. sign_count_regression")
		fmt.Println("is the documented indication of two copies of a credential private")
		fmt.Println("key in use, but many authenticators report a constant zero and a")
		fmt.Println("synchronised platform authenticator does the same, so it is")
		fmt.Println("reported for you to act on rather than enforced.")
	}
	fmt.Println()
	fmt.Printf("assertion:  %s\n", result.Assertion)
	fmt.Println()
	fmt.Println("Verify it before granting anything. The 200 above only says the")
	fmt.Println("request reached the service; the detached signature is what removes")
	fmt.Println("the need to trust the network path in between.")
	fmt.Println()
	fmt.Printf("  go run client.go verify -audience <api key id> '%s'\n", result.Assertion)
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	audience := flags.String("audience", "", "the id of the API key the ceremony was performed for")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}

	token := strings.TrimSpace(positional(flags, ""))
	if token == "" {
		return fmt.Errorf("%w: pass the assertion as the final argument", errUsage)
	}
	if strings.TrimSpace(*audience) == "" {
		// Fail closed. An empty expected audience would accept a token minted
		// for any other API key, which is the whole point of pinning it. The
		// value is the "id" of the key in GET /admin/v1/api-keys.
		return fmt.Errorf("%w: -audience is required (the API key id from GET /admin/v1/api-keys)", errUsage)
	}

	issuer := strings.TrimSpace(os.Getenv("N0PASSTEMPS_ISSUER"))
	if issuer == "" {
		issuer = defaultIssuer
	}

	c, err := newClient(false)
	if err != nil {
		return err
	}

	var document jwkSet
	fmt.Printf("Fetching %s/v1/.well-known/jwks.json\n", c.baseURL)
	if err := c.do(http.MethodGet, "/v1/.well-known/jwks.json", nil, &document); err != nil {
		return err
	}

	keys := loadKeys(document)
	if len(keys) == 0 {
		return errors.New("the JWK Set contains no usable Ed25519 signing key")
	}
	published := make([]string, 0, len(keys))
	for kid := range keys {
		published = append(published, kid)
	}
	fmt.Printf("  keys published: %s\n\n", strings.Join(published, ", "))
	fmt.Printf("Pinning iss=%s aud=%s\n", issuer, *audience)

	claims, err := verifyAssertion(token, keys, issuer, strings.TrimSpace(*audience))
	if err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "The assertion is not valid.")
		fmt.Fprintln(os.Stderr,
			"No further detail is available by design. Reporting which check failed\n"+
				"would tell an attacker whether a forged token had the right audience,\n"+
				"whether a key identifier exists, or whether a captured token is merely\n"+
				"expired rather than wrongly signed.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("The assertion is valid.")
	fmt.Printf("  iss: %s\n", claims.Issuer)
	fmt.Printf("  sub: %s\n", claims.Subject)
	fmt.Printf("  aud: %s\n", claims.Audience)
	fmt.Printf("  iat: %d\n", claims.IssuedAt)
	fmt.Printf("  nbf: %d\n", claims.NotBefore)
	fmt.Printf("  exp: %d\n", claims.ExpiresAt)
	fmt.Printf("  jti: %s\n", claims.ID)
	fmt.Printf("  amr: %s\n", strings.Join(claims.AMR, ", "))
	if claims.CredentialID != "" {
		fmt.Printf("  cid: %s\n", claims.CredentialID)
	}
	if claims.TenantID != "" {
		fmt.Printf("  tid: %s\n", claims.TenantID)
	}

	fmt.Println()
	fmt.Println("Two things remain for a real integration.")
	fmt.Println()
	fmt.Println("Record jti in a replay cache until exp passes. A valid signature does")
	fmt.Println("not make a token single use, and an assertion captured in transit")
	fmt.Println("stays replayable for the rest of its lifetime otherwise.")
	fmt.Println()
	fmt.Println("Apply your own policy to amr. A WebAuthn assertion with user")
	fmt.Println("verification is a different assurance from a recovery code, which is")
	fmt.Println("why the factors are listed separately rather than collapsed into a")
	fmt.Println("single boolean.")
	return nil
}

// positional returns the first non-flag argument, or fallback.
func positional(flags *flag.FlagSet, fallback string) string {
	if flags.NArg() > 0 {
		return flags.Arg(0)
	}
	return fallback
}

// --- assertion verification ----------------------------------------------

// jwkSet mirrors the document served at /v1/.well-known/jwks.json, restricted
// to the OKP members of RFC 8037 section 2.
type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	} `json:"keys"`
}

// claims is the JWT claims set of an assertion.
//
// The date claims are seconds since the Unix epoch, as RFC 7519 section 2
// defines NumericDate. They are plain integers rather than time.Time so that
// the wire form is exactly what was signed, with no timezone or precision
// ambiguity between the issuer and this verifier.
type claims struct {
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub"`
	Audience     string   `json:"aud"`
	IssuedAt     int64    `json:"iat"`
	NotBefore    int64    `json:"nbf"`
	ExpiresAt    int64    `json:"exp"`
	ID           string   `json:"jti"`
	AMR          []string `json:"amr"`
	CredentialID string   `json:"cid,omitempty"`
	TenantID     string   `json:"tid,omitempty"`
}

// joseHeader is the JWS protected header, restricted to the members inspected
// below.
type joseHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// errInvalidToken is the only verification outcome.
//
// Reporting which check failed would tell an attacker whether a forged token
// had the right audience, whether a "kid" exists, or whether a captured token
// is merely expired rather than wrongly signed.
var errInvalidToken = errors.New("assertion is not valid")

// loadKeys indexes the Ed25519 signing keys of a JWK Set by key identifier.
//
// Anything that is not one is skipped rather than rejected, so a deployment
// publishing an unrelated key alongside does not break verification. A key
// whose "kid" disagrees with its own thumbprint is skipped too: the service
// derives "kid" from the key, so a mismatch means the document was not
// produced the way this verifier expects.
func loadKeys(document jwkSet) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))

	for _, entry := range document.Keys {
		if entry.Kty != "OKP" || entry.Crv != "Ed25519" {
			continue
		}
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}
		if entry.Alg != "" && entry.Alg != algEdDSA {
			continue
		}
		if entry.Kid == "" {
			continue
		}

		raw, err := decodeSegment(entry.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		if thumbprint(raw) != entry.Kid {
			continue
		}

		keys[entry.Kid] = ed25519.PublicKey(raw)
	}

	return keys
}

// thumbprint returns the RFC 7638 JWK thumbprint of an Ed25519 public key.
//
// RFC 7638 section 3 fixes the hash input as the JSON object of the required
// members only, with no whitespace and the member names in lexicographic
// order. RFC 8037 section 2 names those members for an OKP key: crv, kty and
// x. The construction has to be exact, because two implementations that
// disagree about it derive different identifiers for the same key.
func thumbprint(publicKey []byte) string {
	input := `{"crv":"Ed25519","kty":"OKP","x":"` + encodeSegment(publicKey) + `"}`
	sum := sha256.Sum256([]byte(input))
	return encodeSegment(sum[:])
}

// verifyAssertion checks token and returns its claims.
//
// The order of the checks is deliberate: nothing in the payload is parsed, let
// alone trusted, until the signature has been verified.
func verifyAssertion(token string, keys map[string]ed25519.PublicKey, expectedIssuer, expectedAudience string) (*claims, error) {
	if expectedIssuer == "" || expectedAudience == "" {
		return nil, errInvalidToken
	}

	// RFC 7515 section 7.1: the compact serialisation is exactly three
	// segments. Splitting on every dot and requiring three rejects a fourth
	// segment, which a lenient parser would ignore while a second recipient
	// might read it, and rejects a two-segment unsecured JWS outright.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, errInvalidToken
	}
	var header joseHeader
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, errInvalidToken
	}

	// The algorithm is fixed here, never read from the token to decide what to
	// do. This single check stops the whole family of algorithm-confusion
	// attacks: "alg":"none" with an empty signature, and "alg":"HS256" with
	// the published Ed25519 public key used as the HMAC secret. Both land here
	// and are refused before any key is loaded.
	if header.Alg != algEdDSA {
		return nil, errInvalidToken
	}

	// RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a "crit"
	// header extension it does not understand. This verifier understands none,
	// so any "crit" at all is fatal. Ignoring it would let an attacker attach
	// a header that a future, stricter verifier would act on while this one
	// does not.
	if len(header.Crit) != 0 {
		return nil, errInvalidToken
	}

	// A JWS signed by the same key for another purpose must not pass as an
	// assertion.
	if header.Typ != "" && header.Typ != typJWT {
		return nil, errInvalidToken
	}

	// The key is selected by "kid", and one candidate only. Trying every known
	// key in turn would mean a token signed under a revoked or deliberately
	// weak key still verifies as long as that key is in the set, and it would
	// make the cost of a failure depend on the size of the set.
	if header.Kid == "" {
		return nil, errInvalidToken
	}
	publicKey, ok := keys[header.Kid]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errInvalidToken
	}

	signature, err := decodeSegment(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errInvalidToken
	}

	// The signature covers the header and the payload exactly as they were
	// received, which is why the encoded form is verified rather than any
	// re-serialisation of the parsed structures.
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(publicKey, []byte(signingInput), signature) {
		return nil, errInvalidToken
	}

	// Only now is the payload worth parsing.
	rawPayload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, errInvalidToken
	}
	var c claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return nil, errInvalidToken
	}

	if c.Issuer != expectedIssuer {
		return nil, errInvalidToken
	}
	if c.Audience != expectedAudience {
		return nil, errInvalidToken
	}
	if c.Subject == "" || len(c.AMR) == 0 {
		return nil, errInvalidToken
	}

	// "exp" is required. Treating a missing "exp" as no expiry turns a
	// captured assertion into a permanent credential.
	if c.ExpiresAt == 0 {
		return nil, errInvalidToken
	}
	now := time.Now()
	if now.After(time.Unix(c.ExpiresAt, 0).Add(verifySkew)) {
		return nil, errInvalidToken
	}
	if c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-verifySkew)) {
		return nil, errInvalidToken
	}

	return &c, nil
}

// encodeSegment encodes one compact serialisation segment. RFC 7515 section 2
// defines every segment as base64url with the padding removed.
func encodeSegment(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSegment decodes one compact serialisation segment.
//
// RawURLEncoding has no "=" in its alphabet, so a padded segment is rejected,
// and Strict additionally rejects a final quantum whose unused bits are not
// zero. Together they leave each segment exactly one valid encoding: a lenient
// decoder would let an attacker re-encode a captured header or payload into a
// different string that still carries the same bytes past the signature check
// of a second, laxer implementation.
func decodeSegment(segment string) ([]byte, error) {
	if segment == "" {
		return nil, errInvalidToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, errInvalidToken
	}
	return raw, nil
}
