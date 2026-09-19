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
// # The other thing to copy
//
// A route that adds or replaces a factor takes its subject from the session,
// never from the request. Keeping the key on this side is not enough by itself:
// a backend that relays whatever subject_ref the page sends has handed every
// visitor what the key allows, one request at a time. Issue recovery codes for
// somebody else, consume one, and the session that comes back is theirs. So
// the five routes that enrol or issue answer 401 without a session, and refuse
// a subject_ref that is not the session's own. The four that sign a person in
// stay open, because they are where a session comes from, and each of them
// proves something before it creates one.
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
//
// Somebody with no factor yet cannot have a session, so the first enrolment has
// to be let in some other way. A deployment does it with an enrolment ticket
// delivered out of band, or from its own sign-up flow, where it already knows
// who it is talking to. This kit has neither, and says so with a flag:
//
//	go run ./kits/login -open-enrolment
//
// which lets a visitor with no session enrol a first factor for a subject that
// has none. It is off by default and is for trying the kit on one machine.
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
	openEnrolment := flag.Bool("open-enrolment", false,
		"let a visitor with no session enrol a first factor for a subject that has none (local demonstration only)")
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

	app := &app{
		client:        client,
		openEnrolment: *openEnrolment,
		secureCookies: strings.HasPrefix(strings.ToLower(os.Getenv("N0PASSTEMPS_KIT_PUBLIC_URL")), "https://"),
		sessions:      map[string]session{},
	}
	if app.openEnrolment {
		log.Print("WARNING: -open-enrolment is set. Anybody who can reach this page can enrol the first " +
			"factor of any subject that has none, and so become that subject. This is for a " +
			"demonstration on one machine and nothing else.")
	}

	log.Printf("listening on http://%s, talking to %s", *addr, base)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           app.routes(pub),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// routes is the whole surface: the page, and eleven routes under /api.
func (a *app) routes(pub fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(pub))
	mux.HandleFunc("POST /api/register/begin", a.json(a.registerBegin))
	mux.HandleFunc("POST /api/register/complete", a.json(a.registerComplete))
	mux.HandleFunc("POST /api/login/begin", a.json(a.loginBegin))
	mux.HandleFunc("POST /api/login/complete", a.json(a.loginComplete))
	mux.HandleFunc("POST /api/totp/enrol", a.json(a.totpEnrol))
	mux.HandleFunc("POST /api/totp/confirm", a.json(a.totpConfirm))
	mux.HandleFunc("POST /api/totp/verify", a.json(a.totpVerify))
	mux.HandleFunc("POST /api/recovery/issue", a.json(a.recoveryIssue))
	mux.HandleFunc("POST /api/recovery/consume", a.json(a.recoveryConsume))
	mux.HandleFunc("GET /api/session", a.json(a.whoami))
	mux.HandleFunc("POST /api/logout", a.json(a.logout))
	return mux
}

// app holds the one credential and the sessions this front end issues.
type app struct {
	client *n0.Client

	// openEnrolment is the -open-enrolment flag. See enrolmentSubject for the
	// one thing it relaxes.
	openEnrolment bool

	// secureCookies is whether N0PASSTEMPS_KIT_PUBLIC_URL says the page is
	// served over https, which this process cannot see for itself when the TLS
	// is terminated by a proxy in front of it.
	secureCookies bool

	mu       sync.Mutex
	sessions map[string]session
}

// sessionTTL is how long a session lives, and it is also the cookie's MaxAge.
//
// Both ends have to agree. The cookie alone would leave the server honouring an
// identifier a browser had already thrown away, and whoever had copied that
// identifier would still be signed in.
const sessionTTL = 12 * time.Hour

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

// refusal is a request this front end turns down by itself, before the service
// is asked anything. It is an error so that a handler can return it like any
// other, and json renders it with its own status rather than as a 502.
type refusal struct {
	status int
	reason string
}

func (e *refusal) Error() string { return e.reason }

// sessionOf returns the session the request's cookie names, if it names one
// and it has not expired.
//
// An expired session is dropped here rather than left for a sweep, so that a
// copied cookie stops working at the moment it should and not at the next
// sweep. The rest of the map is swept at the same time, which costs one pass
// over a map that holds one entry per signed-in person and keeps a process that
// runs for months from accumulating every session it ever issued.
func (a *app) sessionOf(r *http.Request) (session, bool) {
	c, err := r.Cookie("kit_session")
	if err != nil {
		return session{}, false
	}
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()
	for id, sess := range a.sessions {
		if now.Sub(sess.At) >= sessionTTL {
			delete(a.sessions, id)
		}
	}
	s, ok := a.sessions[c.Value]
	return s, ok
}

// enrolmentSubject decides whose factors a request may add to or replace.
//
// The answer is the session's subject. The subject_ref in the body is not an
// input to that decision: it is checked against the session only so that a page
// asking for somebody else is told no, rather than quietly given its own
// subject and left to believe otherwise.
//
// Every route that enrols an authenticator, enrols a TOTP secret or issues
// recovery codes goes through here. Without it they are the sign-in routes with
// the proof removed: whoever can name a subject can give that subject a factor
// they hold, and then sign in with it.
func (a *app) enrolmentSubject(r *http.Request, req request) (string, error) {
	s, ok := a.sessionOf(r)
	if !ok {
		if a.openEnrolment {
			return a.firstEnrolmentSubject(r, req)
		}
		return "", &refusal{http.StatusUnauthorized, "sign in before adding or replacing a factor"}
	}
	if req.SubjectRef != "" && req.SubjectRef != s.SubjectRef {
		return "", &refusal{http.StatusForbidden, "the subject named is not the one signed in"}
	}
	if s.SubjectRef == "" {
		// A passkey offered by the authenticator signs in with no reference
		// named, and the service reports its own identifier and not the
		// application's. An application maps one to the other in its user table.
		// This kit has no user table, and taking the reference from the body to
		// fill the gap would be the very thing this function exists to prevent.
		return "", &refusal{http.StatusForbidden, "this session does not name its subject; sign in by address to add a factor"}
	}
	return s.SubjectRef, nil
}

// firstEnrolmentSubject is what -open-enrolment allows: no session, and the
// subject taken from the body, for a subject that has nothing to sign in with.
//
// The check is against the service and not against anything this process
// remembers. A subject with an authenticator, a confirmed TOTP secret or an
// unused recovery code can prove who they are, and is told to. That is the line
// which holds even with the flag set: nobody who already has a factor is given
// another one on the strength of a name.
//
// What the flag does give away is every subject that has none. The first
// visitor to name one owns it, which is why it is for a demonstration on one
// machine. It also answers differently for a subject with factors and one
// without, which the service itself is careful never to do.
func (a *app) firstEnrolmentSubject(r *http.Request, req request) (string, error) {
	if req.SubjectRef == "" {
		return "", &refusal{http.StatusBadRequest, "subject_ref is required"}
	}
	sub, err := a.client.GetSubject(r.Context(), req.SubjectRef)
	if errors.Is(err, n0.ErrNotFound) {
		return req.SubjectRef, nil
	}
	if err != nil {
		return "", err
	}
	if sub.CredentialCount > 0 || sub.TOTPEnrolled || sub.RecoveryCodesRemaining > 0 {
		return "", &refusal{http.StatusUnauthorized, "sign in before adding or replacing a factor"}
	}
	return req.SubjectRef, nil
}

func (a *app) registerBegin(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	ref, err := a.enrolmentSubject(r, req)
	if err != nil {
		return nil, err
	}
	// ResolveSubject creates the subject or returns the existing one. It comes
	// after the check above, so that naming a subject is not enough to have one
	// created: with a session it already exists, and only -open-enrolment lets
	// this line create anything.
	if _, err := a.client.ResolveSubject(r.Context(), ref, ""); err != nil {
		return nil, err
	}
	return a.client.BeginRegistration(r.Context(), ref, req.Label)
}

func (a *app) registerComplete(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	// Checked again, and not remembered from registerBegin: the challenge is
	// the service's, and what ties this half to a person is the session.
	ref, err := a.enrolmentSubject(r, req)
	if err != nil {
		return nil, err
	}
	cred, err := a.client.CompleteRegistration(r.Context(), ref, req.ChallengeID, req.Credential)
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
	return a.signIn(w, r, ref, result), nil
}

func (a *app) totpEnrol(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	ref, err := a.enrolmentSubject(r, req)
	if err != nil {
		return nil, err
	}
	if _, err := a.client.ResolveSubject(r.Context(), ref, ""); err != nil {
		return nil, err
	}
	return a.client.EnrolTOTP(r.Context(), ref)
}

func (a *app) totpConfirm(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	ref, err := a.enrolmentSubject(r, req)
	if err != nil {
		return nil, err
	}
	return a.client.ConfirmTOTP(r.Context(), ref, req.Code)
}

func (a *app) totpVerify(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	result, err := a.client.VerifyTOTP(r.Context(), req.SubjectRef, req.Code)
	if err != nil {
		return nil, err
	}
	return a.signIn(w, r, req.SubjectRef, result), nil
}

// recoveryIssue is the one enrolment route -open-enrolment does not open.
//
// Issuing retires the previous batch and returns the new one in clear, so an
// open version would both lock a person out of their codes and hand the caller
// a way in. A first factor is an authenticator or a TOTP secret, and the codes
// come after it, from the session it produced.
func (a *app) recoveryIssue(w http.ResponseWriter, r *http.Request, req request) (any, error) {
	if _, ok := a.sessionOf(r); !ok {
		return nil, &refusal{http.StatusUnauthorized, "sign in before adding or replacing a factor"}
	}
	ref, err := a.enrolmentSubject(r, req)
	if err != nil {
		return nil, err
	}
	return a.client.IssueRecoveryCodes(r.Context(), ref)
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
	out := a.signIn(w, r, req.SubjectRef, result)
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
func (a *app) signIn(w http.ResponseWriter, r *http.Request, ref string, result *n0.AssertionResult) map[string]any {
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
		// cookies. The scheme is this connection's when the TLS ends here, and
		// N0PASSTEMPS_KIT_PUBLIC_URL's when a proxy ends it first; a forwarded
		// header is not consulted, because whoever sends the request writes it.
		// An application sets it unconditionally.
		Secure: r.TLS != nil || a.secureCookies,
		MaxAge: int(sessionTTL.Seconds()),
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
	s, ok := a.sessionOf(r)
	if !ok {
		// The page asks before it draws, so that it does not offer a first
		// passkey that this process would refuse.
		return map[string]any{"signed_in": false, "open_enrolment": a.openEnrolment}, nil
	}
	return map[string]any{
		"signed_in": true, "subject_ref": s.SubjectRef,
		"subject_id": s.SubjectID, "factors": s.Factors,
		"open_enrolment": a.openEnrolment,
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
	var refused *refusal
	if errors.As(err, &refused) {
		return refused.status, map[string]any{"error": refused.reason}
	}
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
