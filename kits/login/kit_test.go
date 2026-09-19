package main

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	n0 "github.com/Socold/n0passtemps/sdk/go"
)

// TestTheBrowserHelpersAreTheSDKCopy keeps a deliberate duplicate from drifting.
//
// public/webauthn.js is sdk/node/src/browser.js, byte for byte. It is copied
// rather than imported because this kit embeds its assets and go:embed cannot
// reach outside the package directory, and because the file's own comment says
// it has no imports so that it can go into a page as it is.
//
// The copy is the part every WebAuthn integration gets wrong: the conversion
// between the base64url of WebAuthn's JSON form and the ArrayBuffers
// navigator.credentials wants. Two versions of that would be one version that
// is wrong.
func TestTheBrowserHelpersAreTheSDKCopy(t *testing.T) {
	const rel = "../../sdk/node/src/browser.js"

	source, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read the SDK helpers: %v", err)
	}
	copied, err := os.ReadFile("public/webauthn.js")
	if err != nil {
		t.Fatalf("read the copy: %v", err)
	}
	if !bytes.Equal(source, copied) {
		t.Fatalf("public/webauthn.js differs from %s.\n"+
			"They are one file in two places on purpose. Copy it again:\n"+
			"  cp sdk/node/src/browser.js kits/login/public/webauthn.js", rel)
	}
}

// TestTheAssetsAreEmbedded catches the build that ships a page with no page in
// it, which is the failure mode of go:embed and is silent until somebody opens
// the site.
func TestTheAssetsAreEmbedded(t *testing.T) {
	for _, name := range []string{"public/index.html", "public/app.js", "public/style.css", "public/webauthn.js"} {
		b, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Errorf("%s is not embedded: %v", name, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("%s is embedded and empty", name)
		}
	}
}

// TestTheApiKeyNeverReachesTheBrowser is the property this kit exists to
// demonstrate, so it is asserted rather than described.
//
// A key in a served asset is a key every visitor holds, carrying whatever
// scopes it was minted with: enrol an authenticator for any subject, issue
// recovery codes for any subject, learn whether a given person has an account.
func TestTheApiKeyNeverReachesTheBrowser(t *testing.T) {
	err := fs.WalkDir(assets, "public", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, readErr := fs.ReadFile(assets, path)
		if readErr != nil {
			return readErr
		}
		body := string(b)
		for _, forbidden := range []string{"N0PASSTEMPS_API_KEY", "Authorization", "npa_"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s mentions %q; the browser half must never carry a credential", path, forbidden)
			}
		}
		// Every call the page makes is to this origin. An absolute URL to the
		// service would mean the browser talking to it directly, which it
		// cannot do without a key.
		if strings.Contains(body, "fetch(\"http") || strings.Contains(body, "fetch(`http") {
			t.Errorf("%s fetches an absolute URL; the page talks to /api on its own origin", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// service stands in for n0passtemps and remembers what it was asked.
//
// What reaches it is the thing under test. A refusal that arrives after the
// call went out is no refusal: the recovery codes have been reissued by then,
// and the subject has been created.
type service struct {
	*httptest.Server

	mu    sync.Mutex
	calls []string
}

// newService answers the two questions these tests put to the service: a TOTP
// verification, which always succeeds and is how a test gets a session the way
// a person does, and a subject lookup, which describes whichever subject the
// test says exists.
func newService(t *testing.T, subjects map[string]string) *service {
	t.Helper()
	svc := &service{}
	svc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.mu.Lock()
		svc.calls = append(svc.calls, r.Method+" "+r.URL.Path)
		svc.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		ref, isLookup := strings.CutPrefix(r.URL.Path, "/v1/subjects/")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/totp/") && strings.HasSuffix(r.URL.Path, "/verify"):
			_, _ = w.Write([]byte(`{"subject_id":"sub_1","assertion":"a.b.c","factors":["totp"]}`))
		case r.Method == http.MethodGet && isLookup && subjects[ref] != "":
			_, _ = w.Write([]byte(subjects[ref]))
		case r.Method == http.MethodGet && isLookup:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"type":"urn:n0passtemps:error:not-found","title":"Not found","status":404}`))
		default:
			// Everything else is an enrolment call that got through. The body
			// does not matter to these tests; that it was asked for does.
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(svc.Close)
	return svc
}

// asked reports the calls received since the last time it was read.
func (s *service) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	calls := s.calls
	s.calls = nil
	return calls
}

// newKit serves the real routes in front of svc.
func newKit(t *testing.T, svc *service, openEnrolment bool) *httptest.Server {
	t.Helper()
	kit, _ := newKitApp(t, svc, openEnrolment)
	return kit
}

// newKitApp is newKit for a test that has to look at the state the process
// keeps, rather than only at what it answers.
func newKitApp(t *testing.T, svc *service, openEnrolment bool) (*httptest.Server, *app) {
	t.Helper()
	client, err := n0.New(svc.URL, "npa_test")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	pub, err := fs.Sub(assets, "public")
	if err != nil {
		t.Fatalf("assets: %v", err)
	}
	a := &app{client: client, openEnrolment: openEnrolment, sessions: map[string]session{}}
	kit := httptest.NewServer(a.routes(pub))
	t.Cleanup(kit.Close)
	return kit, a
}

// post sends body to the kit, with the session cookie when there is one.
func post(t *testing.T, kit *httptest.Server, path, body string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, kit.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := kit.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// signInAs gets a session the way a person does, through a route that creates
// one, so that these tests cannot pass by writing to the session map.
func signInAs(t *testing.T, kit *httptest.Server, svc *service, ref string) *http.Cookie {
	t.Helper()
	resp := post(t, kit, "/api/totp/verify", `{"subject_ref":"`+ref+`","code":"123456"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign in as %s: status %d", ref, resp.StatusCode)
	}
	svc.asked()
	for _, c := range resp.Cookies() {
		if c.Name == "kit_session" {
			return c
		}
	}
	t.Fatalf("sign in as %s: no session cookie", ref)
	return nil
}

// enrolmentRoutes are the routes that add or replace a factor.
var enrolmentRoutes = []string{
	"/api/register/begin",
	"/api/register/complete",
	"/api/totp/enrol",
	"/api/totp/confirm",
	"/api/recovery/issue",
}

// TestAddingAFactorNeedsASession is the second property this kit exists to
// demonstrate.
//
// The key stays on the server, and that is worth nothing if the server does
// whatever the page asks for whichever subject the page names. Without this, a
// visitor with no session issues recovery codes for somebody else, consumes
// one, and is handed that person's session.
func TestAddingAFactorNeedsASession(t *testing.T) {
	svc := newService(t, nil)
	kit := newKit(t, svc, false)

	for _, route := range enrolmentRoutes {
		resp := post(t, kit, route, `{"subject_ref":"victim@example.com","code":"123456"}`, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with no session: status %d, want 401", route, resp.StatusCode)
		}
		if calls := svc.asked(); len(calls) != 0 {
			t.Errorf("%s with no session still reached the service: %v", route, calls)
		}
	}

	// A cookie is not a session. Only a value this process issued is.
	forged := &http.Cookie{Name: "kit_session", Value: strings.Repeat("0", 32)}
	for _, route := range enrolmentRoutes {
		resp := post(t, kit, route, `{"subject_ref":"victim@example.com"}`, forged)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with a cookie nobody issued: status %d, want 401", route, resp.StatusCode)
		}
	}
	if calls := svc.asked(); len(calls) != 0 {
		t.Errorf("a cookie nobody issued reached the service: %v", calls)
	}
}

// TestTheSubjectComesFromTheSession covers the person who is signed in and asks
// on behalf of somebody else. They are refused, not quietly served as
// themselves, and nothing is asked of the service either way.
func TestTheSubjectComesFromTheSession(t *testing.T) {
	svc := newService(t, nil)
	kit := newKit(t, svc, false)
	cookie := signInAs(t, kit, svc, "mallory@example.com")

	for _, route := range enrolmentRoutes {
		resp := post(t, kit, route, `{"subject_ref":"victim@example.com","code":"123456"}`, cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s for somebody else: status %d, want 403", route, resp.StatusCode)
		}
		if calls := svc.asked(); len(calls) != 0 {
			t.Errorf("%s for somebody else still reached the service: %v", route, calls)
		}
	}

	// With no subject named, and with their own, the call goes out for the
	// session's subject and for nobody else.
	for _, body := range []string{`{}`, `{"subject_ref":"mallory@example.com"}`} {
		resp := post(t, kit, "/api/recovery/issue", body, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("recovery/issue with %s: status %d, want 200", body, resp.StatusCode)
		}
		calls := svc.asked()
		if len(calls) != 1 || calls[0] != "POST /v1/recovery/mallory@example.com/issue" {
			t.Errorf("recovery/issue with %s asked the service for %v", body, calls)
		}
	}
}

// TestOpenEnrolmentStopsAtTheFirstFactor pins what the flag does not relax. It
// exists for the person who has nothing to sign in with, and a subject who has
// anything at all is not that person.
func TestOpenEnrolmentStopsAtTheFirstFactor(t *testing.T) {
	svc := newService(t, map[string]string{
		"passkey@example.com":  `{"subject_id":"sub_2","status":"active","credential_count":1}`,
		"totp@example.com":     `{"subject_id":"sub_3","status":"active","totp_enrolled":true}`,
		"recovery@example.com": `{"subject_id":"sub_4","status":"active","recovery_codes_remaining":3}`,
		"empty@example.com":    `{"subject_id":"sub_5","status":"active"}`,
	})
	kit := newKit(t, svc, true)

	for _, ref := range []string{"passkey@example.com", "totp@example.com", "recovery@example.com"} {
		for _, route := range enrolmentRoutes {
			resp := post(t, kit, route, `{"subject_ref":"`+ref+`","code":"123456"}`, nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s for %s, who has a factor: status %d, want 401", route, ref, resp.StatusCode)
			}
			for _, call := range svc.asked() {
				if !strings.HasPrefix(call, "GET ") {
					t.Errorf("%s for %s, who has a factor, reached the service: %s", route, ref, call)
				}
			}
		}
	}

	// Recovery codes are never a first factor, flag or no flag.
	for _, ref := range []string{"empty@example.com", "nobody@example.com"} {
		resp := post(t, kit, "/api/recovery/issue", `{"subject_ref":"`+ref+`"}`, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("recovery/issue for %s with no session: status %d, want 401", ref, resp.StatusCode)
		}
		if calls := svc.asked(); len(calls) != 0 {
			t.Errorf("recovery/issue for %s with no session reached the service: %v", ref, calls)
		}
	}

	// And what it is for: a subject with nothing, or one that does not exist.
	for _, ref := range []string{"empty@example.com", "nobody@example.com"} {
		resp := post(t, kit, "/api/totp/enrol", `{"subject_ref":"`+ref+`"}`, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("totp/enrol for %s, who has no factor: status %d, want 200", ref, resp.StatusCode)
		}
		svc.asked()
	}
}

// TestTheSessionCookieIsSecureOverTLS keeps the cookie off clear text wherever
// the page is not: when the connection that carried the sign-in was TLS, and
// when a proxy ended the TLS and the public URL says so.
func TestTheSessionCookieIsSecureOverTLS(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tls           bool
		secureCookies bool
		want          bool
	}{
		{"clear text on localhost", false, false, false},
		{"TLS ends here", true, false, true},
		{"TLS ends at a proxy", false, true, true},
	} {
		svc := newService(t, nil)
		client, err := n0.New(svc.URL, "npa_test")
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		a := &app{client: client, secureCookies: tc.secureCookies, sessions: map[string]session{}}
		kit := httptest.NewUnstartedServer(a.routes(assets))
		if tc.tls {
			kit.StartTLS()
		} else {
			kit.Start()
		}
		t.Cleanup(kit.Close)

		cookie := signInAs(t, kit, svc, "alice@example.com")
		if cookie.Secure != tc.want {
			t.Errorf("%s: Secure is %v, want %v", tc.name, cookie.Secure, tc.want)
		}
	}
}

// TestASessionDoesNotOutliveItsCookie holds the server side to the lifetime the
// browser was given.
//
// The map was never swept and the time a session was created was never read, so
// an identifier copied from a cookie stayed valid until the process restarted,
// months later, and the map kept every session the process had ever issued.
func TestASessionDoesNotOutliveItsCookie(t *testing.T) {
	svc := newService(t, map[string]string{"alice@example.com": "sub-alice"})
	kit, a := newKitApp(t, svc, false)
	cookie := signInAs(t, kit, svc, "alice@example.com")

	// Signed in, the session answers for its own subject.
	if resp := post(t, kit, "/api/totp/enrol", `{}`, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("enrol with a fresh session = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	svc.asked()

	// Age it past the lifetime the cookie carries.
	a.mu.Lock()
	sess := a.sessions[cookie.Value]
	sess.At = time.Now().Add(-sessionTTL - time.Minute)
	a.sessions[cookie.Value] = sess
	a.mu.Unlock()

	if resp := post(t, kit, "/api/totp/enrol", `{}`, cookie); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("enrol with an expired session = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if calls := svc.asked(); len(calls) != 0 {
		t.Errorf("an expired session still reached the service: %v", calls)
	}

	a.mu.Lock()
	held := len(a.sessions)
	a.mu.Unlock()
	if held != 0 {
		t.Errorf("%d expired sessions are still held, want 0", held)
	}
}
