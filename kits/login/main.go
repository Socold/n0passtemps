// Command login is a reference sign-in and enrolment front end.
//
// # What it is
//
// The smallest complete integration: a page that runs both WebAuthn
// ceremonies, falls back to TOTP and to a recovery code, and a backend that
// holds the API key and turns a verified assertion into its own session. It is
// meant to be read, then adapted, then thrown away. Nothing here is imported by
// the server, and deleting this directory changes nothing about the service.
//
// # What it is not
//
// Not a user portal and not an account management surface. It signs a person in
// and enrols their factors, and stops. The moment it grew a profile page or a
// list of devices it would be taking over the part of the application that
// belongs to the application, which is the line docs/EXTENSIONS.md draws.
//
// # The one thing to copy
//
// The API key never reaches the browser. examples/node/register.html puts it
// there on purpose, to demonstrate a ceremony in a page with no backend, and
// says in capitals not to copy the pattern. This is the pattern to copy: the
// browser talks to routes under /api, this process talks to n0passtemps, and
// the key lives in one environment variable on one side of that boundary.
//
// A key that reached the browser would be a key every visitor holds, and it
// carries whatever scopes it was minted with: enrol an authenticator for any
// subject, issue recovery codes for any subject, read whether a given person
// has an account.
//
// # Running it
//
//	export N0PASSTEMPS_URL=https://auth.example.com
//	export N0PASSTEMPS_API_KEY=npa_...
//	go run ./kits/login -addr 127.0.0.1:5173
//
// The deployment's webauthn.rp_id must match the host the page is served from
// and webauthn.origins must list its origin, because the authenticator signs
// over both and the server checks them against what it was configured with
// rather than against anything in the request. http://localhost counts as a
// secure context, so a certificate is not needed to try it.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	n0 "github.com/Socold/n0passtemps/sdk/go"
)

//go:embed public
var assets embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:5173", "address to listen on")
	flag.Parse()

	base := os.Getenv("N0PASSTEMPS_URL")
	key := os.Getenv("N0PASSTEMPS_API_KEY")
	if base == "" || key == "" {
		log.Fatal("set N0PASSTEMPS_URL and N0PASSTEMPS_API_KEY")
	}

	client, err := n0.New(base, key)
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	pub, err := fs.Sub(assets, "public")
	if err != nil {
		log.Fatalf("assets: %v", err)
	}

	app := &app{client: client, sessions: map[string]session{}}

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(pub))
	mux.HandleFunc("POST /api/register/begin", app.json(app.registerBegin))
	mux.HandleFunc("POST /api/register/complete", app.json(app.registerComplete))
	mux.HandleFunc("POST /api/login/begin", app.json(app.loginBegin))
	mux.HandleFunc("POST /api/login/complete", app.json(app.loginComplete))
	mux.HandleFunc("POST /api/totp/enrol", app.json(app.totpEnrol))
	mux.HandleFunc("POST /api/totp/confirm", app.json(app.totpConfirm))
	mux.HandleFunc("POST /api/totp/verify", app.json(app.totpVerify))
	mux.HandleFunc("POST /api/recovery/issue", app.json(app.recoveryIssue))
	mux.HandleFunc("POST /api/recovery/consume", app.json(app.recoveryConsume))
	mux.HandleFunc("GET /api/session", app.json(app.whoami))
	mux.HandleFunc("POST /api/logout", app.json(app.logout))

	log.Printf("listening on http://%s, talking to %s", *addr, base)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// app holds the one credential and the sessions this front end issues.
type app struct {
	client *n0.Client

	mu       sync.Mutex
	sessions map[string]session
}

// session is what the application knows about a signed-in person.
//
// In memory and lost on restart, because this is a reference and a session
// store is the application's own decision. What matters is where it is created:
// only in loginComplete, totpVerify and recoveryConsume, each of which has a
// verified assertion in hand first.
type session struct {
	SubjectRef string    `json:"subject_ref"`
	SubjectID  string    `json:"subject_id"`
	Factors    []string  `json:"factors"`
	At         time.Time `json:"at"`
}

// request is every field the browser may send. One struct rather than nine
// keeps the surface visible: this is the whole of what the page can ask for.
type request struct {
	SubjectRef  string          `json:"subject_ref"`
	Label       string          `json:"label"`
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
	Code        string          `json:"code"`
}

func (a *app) registerBegin(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	// ResolveSubject creates the subject or returns the existing one, so a page
	// does not have to know which it is dealing with.
	if _, err := a.client.ResolveSubject(r.Context(), req.SubjectRef, ""); err != nil {
		return nil, err
	}
	return a.client.BeginRegistration(r.Context(), req.SubjectRef, req.Label)
}

func (a *app) registerComplete(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	cred, err := a.client.CompleteRegistration(r.Context(), req.SubjectRef, req.ChallengeID, req.Credential)
	if err != nil {
		return nil, err
	}
	// Registering is not signing in. The person proved they hold an
	// authenticator; they have not yet used it to authenticate, and conflating
	// the two is how an enrolment flow becomes a way in.
	return map[string]any{"credential": cred, "signed_in": false}, nil
}

func (a *app) loginBegin(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	if req.SubjectRef == "" {
		// No subject named: the authenticator offers whichever passkey it holds
		// for this relying party, and the server reports who it turned out to
		// be. This is what people now expect from a passkey.
		return a.client.BeginDiscoverableAssertion(r.Context())
	}
	return a.client.BeginAssertion(r.Context(), req.SubjectRef)
}

func (a *app) loginComplete(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	var (
		result *n0.AssertionResult
		ref    = req.SubjectRef
		err    error
	)
	if ref == "" {
		// The response says which subject the credential turned out to belong
		// to. It is the internal identifier rather than the application's own
		// reference, which the service does not re-publish: the sealed copy is
		// not its to hand back, and a page that needed the reference would be
		// asking the authentication service to disclose who has an account.
		result, err = a.client.CompleteDiscoverableAssertion(r.Context(), req.ChallengeID, req.Credential)
	} else {
		result, err = a.client.CompleteAssertion(r.Context(), ref, req.ChallengeID, req.Credential)
	}
	if err != nil {
		return nil, err
	}
	return a.signIn(w, ref, result), nil
}

func (a *app) totpEnrol(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	if _, err := a.client.ResolveSubject(r.Context(), req.SubjectRef, ""); err != nil {
		return nil, err
	}
	return a.client.EnrolTOTP(r.Context(), req.SubjectRef)
}

func (a *app) totpConfirm(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	return a.client.ConfirmTOTP(r.Context(), req.SubjectRef, req.Code)
}

func (a *app) totpVerify(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	result, err := a.client.VerifyTOTP(r.Context(), req.SubjectRef, req.Code)
	if err != nil {
		return nil, err
	}
	return a.signIn(w, req.SubjectRef, result), nil
}

func (a *app) recoveryIssue(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	return a.client.IssueRecoveryCodes(r.Context(), req.SubjectRef)
}

func (a *app) recoveryConsume(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	consumed, err := a.client.ConsumeRecoveryCode(r.Context(), req.SubjectRef, req.Code)
	if err != nil {
		return nil, err
	}
	result := &consumed.AssertionResult
	// A recovery code is the way back in, not a factor to keep. An application
	// that stopped here would leave the person with one fewer code and no
	// authenticator; the page says to enrol one now, and means it.
	out := a.signIn(w, req.SubjectRef, result)
	out["enrol_now"] = true
	out["recovery_codes_remaining"] = consumed.RecoveryCodesRemaining
	return out, nil
}

// signIn is where this front end decides somebody is authenticated.
//
// It runs only with an AssertionResult in hand, which is the service's signed
// statement that a ceremony just completed. A real application verifies that
// assertion offline against the published JWK Set before trusting it, which the
// Go SDK does in one call and examples/go/client.go shows; this one trusts its
// own TLS connection to the service, which is a defensible shortcut only
// because the two are the same deployment and is called out rather than hidden.
func (a *app) signIn(w http.ResponseWriter, ref string, result *n0.AssertionResult) map[string]any {
	id := newID()
	factors := make([]string, 0, len(result.Factors))
	for _, f := range result.Factors {
		factors = append(factors, string(f))
	}

	a.mu.Lock()
	a.sessions[id] = session{SubjectRef: ref, SubjectID: result.SubjectID, Factors: factors, At: time.Now()}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "kit_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure is set from the scheme so that the kit works on
		// http://localhost, which is a secure context for WebAuthn and not for
		// cookies. An application sets it unconditionally.
		Secure: strings.HasPrefix(strings.ToLower(os.Getenv("N0PASSTEMPS_KIT_PUBLIC_URL")), "https://"),
		MaxAge: int((12 * time.Hour).Seconds()),
	})

	return map[string]any{
		"signed_in":   true,
		"subject_ref": ref,
		"subject_id":  result.SubjectID,
		"factors":     factors,
		"signals":     result.Signals,
		"expires_at":  result.ExpiresAt,
	}
}

func (a *app) whoami(w http.ResponseWriter, r *http.Request, _ request) (any, error) {
	c, err := r.Cookie("kit_session")
	if err != nil {
		return map[string]any{"signed_in": false}, nil
	}
	a.mu.Lock()
	s, ok := a.sessions[c.Value]
	a.mu.Unlock()
	if !ok {
		return map[string]any{"signed_in": false}, nil
	}
	return map[string]any{
		"signed_in": true, "subject_ref": s.SubjectRef,
		"subject_id": s.SubjectID, "factors": s.Factors,
	}, nil
}

func (a *app) logout(w http.ResponseWriter, r *http.Request, _ request) (any, error) {
	if c, err := r.Cookie("kit_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "kit_session", Path: "/", MaxAge: -1})
	return map[string]any{"signed_in": false}, nil
}

// json adapts a handler, decodes the body and renders the result.
//
// A failure from the service is passed through as its status and its problem
// document, so the page shows what the service said rather than a generic
// message. The service is careful about what it discloses on a failed ceremony,
// and an integration that invented its own wording would be undoing that.
func (a *app) json(h func(http.ResponseWriter, *http.Request, request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the request body is not JSON"})
				return
			}
		}

		out, err := h(w, r, req)
		if err != nil {
			status, body := translate(err)
			writeJSON(w, status, body)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// translate turns an SDK error into something the page can render.
func translate(err error) (int, map[string]any) {
	var apiErr *n0.Error
	if errors.As(err, &apiErr) {
		return apiErr.Status, map[string]any{
			"error":  apiErr.Title,
			"detail": apiErr.Detail,
			"type":   apiErr.Type,
		}
	}
	return http.StatusBadGateway, map[string]any{"error": "the authentication service is unreachable"}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response not written: %v", err)
	}
}

// newID is a session identifier: 128 bits from the cryptographic source.
//
// A session identifier that is guessable is a way in, so a failure to read
// randomness stops the process rather than producing a weaker one.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("kit: no randomness available: %v", err))
	}
	return hex.EncodeToString(b[:])
}
