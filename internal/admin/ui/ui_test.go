package ui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// testKEK is a single-version key provider.
//
// The real providers read a keyring from disk or from the environment, neither of
// which a test should need. Only the envelope sealer consumes this, and only so
// that a subject reference can be sealed and read back.
type testKEK struct{}

func (testKEK) Current() (version uint32, key []byte, err error) {
	key = make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return 1, key, nil
}

func (testKEK) ByVersion(_ uint32) ([]byte, error) {
	_, key, err := testKEK{}.Current()
	return key, err
}

// clock is a settable time source, so a test can move a session past its
// deadline without sleeping.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock {
	return &clock{at: time.Date(2024, 6, 5, 9, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// harness is one interface handler over a fresh database.
type harness struct {
	t       *testing.T
	handler *Handler
	store   *sqlite.Store
	clock   *clock
	cfg     *config.Config
}

const testTenantID = "default"

// newHarness builds a handler over a migrated database with one tenant.
//
// tune adjusts the configuration before anything is built, so a test that needs
// a setting the default does not carry says so in one line rather than
// assembling its own handler and drifting from this one.
func newHarness(t *testing.T, tune ...func(*config.Config)) *harness {
	t.Helper()

	t.Setenv("N0PASSTEMPS_TEST_PEPPER", strings.Repeat("ab", 32))

	st, err := sqlite.Open(sqlite.Options{DSN: filepath.Join(t.TempDir(), "admin.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err = st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Date(2024, 6, 5, 9, 0, 0, 0, time.UTC)
	if err = st.CreateTenant(context.Background(), &store.Tenant{
		ID: testTenantID, Name: "Test deployment", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	cfg := config.Default()
	cfg.Tenant.ID = testTenantID
	cfg.Tenant.Name = "Test deployment"
	cfg.Subject.PepperEnv = "N0PASSTEMPS_TEST_PEPPER"
	cfg.Admin.SessionCookieSecure = true
	cfg.Admin.SessionTTL = config.Duration{Duration: 30 * time.Minute}
	// Throttling is left off so that a test which makes several failed sign-in
	// attempts is not locked out by an earlier one.
	cfg.Throttle.Enabled = false
	// The relying party the console's own passkeys are enrolled against. It is
	// the same one the public surface uses, because the identifier and the
	// origins are one deployment-wide fact; what keeps the credentials apart is
	// the table each lives in.
	cfg.WebAuthn.RPID = "console.example.test"
	cfg.WebAuthn.Origins = []string{"https://console.example.test"}

	for _, fn := range tune {
		fn(&cfg)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clk := newClock()

	subjects, err := subject.New(cfg.Subject, st, envelope.NewSealer(testKEK{}), clk.now)
	if err != nil {
		t.Fatalf("subject service: %v", err)
	}
	t.Cleanup(subjects.Close)

	rp, err := webauthn.New(cfg.WebAuthn, st, clk.now)
	if err != nil {
		t.Fatalf("relying party: %v", err)
	}

	h, err := New(Deps{
		Store:    st,
		Recorder: audit.NewRecorder(st, log),
		Alerts:   alerts.New(st, log, clk.now),
		Config:   &cfg,
		Logger:   log,
		Clock:    clk.now,
		Limiter:  throttle.New(st, cfg.Throttle, clk.now),
		Subjects: subjects,
		WebAuthn: rp,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	return &harness{t: t, handler: h, store: st, clock: clk, cfg: &cfg}
}

// mintToken creates an administrative token in the store and returns the value
// an operator would paste in.
func (h *harness) mintToken(role store.Role) (rec *store.AdminToken, display string) {
	h.t.Helper()

	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		h.t.Fatalf("generate token: %v", err)
	}
	rec = &store.AdminToken{
		ID: uuid.NewString(), TenantID: testTenantID,
		Name:     "Token for " + string(role),
		Selector: tok.Selector, VerifierHash: tok.Hash, Role: role,
		CreatedAt: h.clock.now(),
	}
	if err := h.store.CreateAdminToken(context.Background(), rec); err != nil {
		h.t.Fatalf("create admin token: %v", err)
	}
	return rec, tok.Display
}

// seedSubject creates one person to act on.
func (h *harness) seedSubject() *store.Subject {
	h.t.Helper()

	sub, err := h.handler.deps.Subjects.Resolve(context.Background(), testTenantID,
		"person@example.test", "A Person")
	if err != nil {
		h.t.Fatalf("resolve subject: %v", err)
	}
	return sub
}

// get issues a GET with the supplied cookies.
func (h *harness) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()

	r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	r.RemoteAddr = "192.0.2.10:54321"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

// post issues a form submission with the supplied cookies.
func (h *harness) post(path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()

	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.10:54321"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

// signIn pastes a token and returns the session cookie it was given.
func (h *harness) signIn(display string) *http.Cookie {
	h.t.Helper()

	w := h.post("/admin/sign-in", url.Values{"token": {display}})
	if w.Code != http.StatusSeeOther {
		h.t.Fatalf("sign in: status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	c := sessionCookieFrom(w.Result().Cookies())
	if c == nil {
		h.t.Fatal("sign in: no session cookie was set")
	}
	return c
}

func sessionCookieFrom(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// csrfFor reads the request token out of a rendered page, which is the only
// place it appears.
func (h *harness) csrfFor(path string, cookie *http.Cookie) string {
	h.t.Helper()

	w := h.get(path, cookie)
	if w.Code != http.StatusOK {
		h.t.Fatalf("load %s: status = %d, want %d", path, w.Code, http.StatusOK)
	}
	m := csrfPattern.FindStringSubmatch(w.Body.String())
	if m == nil {
		h.t.Fatalf("load %s: no request token in the page", path)
	}
	return m[1]
}

// auditEntries reads the recorded history.
func (h *harness) auditEntries(tenantID, eventType string) []*store.AuditEntry {
	h.t.Helper()

	entries, err := h.store.QueryAudit(context.Background(), tenantID, store.AuditFilter{
		EventType: eventType,
		Limit:     100,
	})
	if err != nil {
		h.t.Fatalf("query audit: %v", err)
	}
	return entries
}

// TestTemplatesParse asserts that every embedded template and asset is usable.
//
// Parsing at initialisation would fail on the first request an operator made,
// which is exactly when nobody wants to discover it. Asserting it here means a
// template that no longer parses breaks the build instead.
func TestTemplatesParse(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	for _, want := range []string{
		"signin", "dashboard", "subjects", "subject", "audit", "alerts", "approvals", "message",
	} {
		page, ok := pages[want]
		if !ok {
			t.Fatalf("template %q is not in the set", want)
		}
		if page.Lookup("layout") == nil {
			t.Errorf("template %q does not carry the layout", want)
		}
		if page.Lookup("content") == nil {
			t.Errorf("template %q defines no content block", want)
		}
		if page.Lookup("title") == nil {
			t.Errorf("template %q defines no title block", want)
		}
	}

	if _, _, err := loadAssets(); err != nil {
		t.Fatalf("load assets: %v", err)
	}
}

// TestEveryScreenRendersForAnAdministrator exercises each screen end to end, so
// a template that parses but fails on the data it is given is caught here.
func TestEveryScreenRendersForAnAdministrator(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	for _, path := range []string{
		"/admin/",
		"/admin/subjects",
		"/admin/subjects/" + sub.ID,
		"/admin/audit",
		"/admin/alerts",
		"/admin/approvals",
	} {
		w := h.get(path, cookie)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want %d", path, w.Code, http.StatusOK)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: content type = %q, want HTML", path, ct)
		}
	}
}

// TestUnauthenticatedRequestRedirectsToSignIn covers every screen, because a
// single screen that forgot the check is a fully open administrative surface.
func TestUnauthenticatedRequestRedirectsToSignIn(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/admin/",
		"/admin/subjects",
		"/admin/subjects/" + uuid.NewString(),
		"/admin/audit",
		"/admin/alerts",
		"/admin/approvals",
	} {
		w := h.get(path)
		if w.Code != http.StatusSeeOther {
			t.Errorf("GET %s: status = %d, want %d", path, w.Code, http.StatusSeeOther)
			continue
		}
		if got := w.Header().Get("Location"); got != "/admin/sign-in" {
			t.Errorf("GET %s: redirected to %q, want %q", path, got, "/admin/sign-in")
		}
	}
}

// TestBadTokenIsRefusedAndAudited checks both halves: no session, and a record
// of the attempt.
func TestBadTokenIsRefusedAndAudited(t *testing.T) {
	h := newHarness(t)

	w := h.post("/admin/sign-in", url.Values{"token": {"npa_00112233445566778899aabbccddeeff.AAAAAAAAAAAAAAAAAAAAAAAAAAA"}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if c := sessionCookieFrom(w.Result().Cookies()); c != nil {
		t.Fatal("a session cookie was set for a refused token")
	}
	if body := w.Body.String(); strings.Contains(body, "not recognised") {
		t.Error("the page told the caller why the token failed")
	}

	entries := h.auditEntries(store.SystemTenantID, audit.EventAdminAuthFailed)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Outcome != store.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", entries[0].Outcome, store.OutcomeDenied)
	}
	if h.handler.sessions.count() != 0 {
		t.Errorf("live sessions = %d, want 0", h.handler.sessions.count())
	}
}

// TestGoodTokenMintsSessionAndSetsCookie asserts the attributes one by one,
// because each of them stops something specific and a regression on any single
// one is silent.
func TestGoodTokenMintsSessionAndSetsCookie(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)

	w := h.post("/admin/sign-in", url.Values{"token": {display}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if got := w.Header().Get("Location"); got != "/admin/" {
		t.Errorf("redirected to %q, want %q", got, "/admin/")
	}

	c := sessionCookieFrom(w.Result().Cookies())
	if c == nil {
		t.Fatal("no session cookie was set")
	}
	if !c.HttpOnly {
		t.Error("the cookie is readable by script")
	}
	if !c.Secure {
		t.Error("the cookie may be sent over plain HTTP")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("same site = %v, want %v", c.SameSite, http.SameSiteStrictMode)
	}
	if c.Path != "/admin" {
		t.Errorf("path = %q, want %q", c.Path, "/admin")
	}
	if want := int((30 * time.Minute).Seconds()); c.MaxAge != want {
		t.Errorf("max age = %d, want %d", c.MaxAge, want)
	}
	if c.Value == "" {
		t.Error("the cookie carries no value")
	}

	if h.handler.sessions.count() != 1 {
		t.Errorf("live sessions = %d, want 1", h.handler.sessions.count())
	}

	entries := h.auditEntries(testTenantID, audit.EventAdminAuthorised)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].ActorID != tok.ID {
		t.Errorf("actor = %q, want %q", entries[0].ActorID, tok.ID)
	}
}

// TestPostWithoutRequestTokenIsRefused covers the case a forged cross-site form
// produces: a valid cookie the browser attached, and no token the attacker could
// have read.
func TestPostWithoutRequestTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	w := h.post("/admin/subjects/"+sub.ID+"/lock", url.Values{"reason": {"testing"}}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	after, err := h.store.GetSubject(context.Background(), testTenantID, sub.ID)
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	if after.Status != store.SubjectActive {
		t.Errorf("status = %q, want %q; the action was carried out anyway",
			after.Status, store.SubjectActive)
	}
}

// TestPostWithAnotherSessionsRequestTokenIsRefused checks that the token is
// bound to one session rather than being a value any session accepts.
func TestPostWithAnotherSessionsRequestTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	_, displayOne := h.mintToken(store.RoleFull)
	_, displayTwo := h.mintToken(store.RoleFull)

	cookieOne := h.signIn(displayOne)
	cookieTwo := h.signIn(displayTwo)
	sub := h.seedSubject()

	csrfTwo := h.csrfFor("/admin/subjects/"+sub.ID, cookieTwo)

	w := h.post("/admin/subjects/"+sub.ID+"/lock",
		url.Values{csrfFieldName: {csrfTwo}, "reason": {"testing"}}, cookieOne)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	after, err := h.store.GetSubject(context.Background(), testTenantID, sub.ID)
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	if after.Status != store.SubjectActive {
		t.Errorf("status = %q, want %q; another session's token was accepted",
			after.Status, store.SubjectActive)
	}
}

// TestValidRequestTokenIsAccepted is the companion to the two refusals above.
// Without it, a handler that refused every POST would pass them both.
func TestValidRequestTokenIsAccepted(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)
	w := h.post("/admin/subjects/"+sub.ID+"/lock",
		url.Values{csrfFieldName: {csrf}, "reason": {"the person asked us to"}}, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}

	after, err := h.store.GetSubject(context.Background(), testTenantID, sub.ID)
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	if after.Status != store.SubjectLocked {
		t.Errorf("status = %q, want %q", after.Status, store.SubjectLocked)
	}

	entries := h.auditEntries(testTenantID, audit.EventSubjectLocked)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].ActorID != tok.ID {
		t.Errorf("actor = %q, want %q", entries[0].ActorID, tok.ID)
	}
	if entries[0].SubjectID != sub.ID {
		t.Errorf("subject = %q, want %q", entries[0].SubjectID, sub.ID)
	}
}

// TestExpiredSessionIsRefused covers both deadlines. The idle bound is exercised
// by waiting without making a request; the absolute bound by staying active and
// then passing the session length.
func TestExpiredSessionIsRefused(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		h := newHarness(t)
		_, display := h.mintToken(store.RoleFull)
		cookie := h.signIn(display)

		if w := h.get("/admin/", cookie); w.Code != http.StatusOK {
			t.Fatalf("before expiry: status = %d, want %d", w.Code, http.StatusOK)
		}

		h.clock.advance(h.handler.idleTTL + time.Second)

		w := h.get("/admin/", cookie)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("after idle timeout: status = %d, want %d", w.Code, http.StatusSeeOther)
		}
		if got := w.Header().Get("Location"); got != "/admin/sign-in" {
			t.Errorf("redirected to %q, want %q", got, "/admin/sign-in")
		}
		if h.handler.sessions.count() != 0 {
			t.Errorf("live sessions = %d, want 0; the expired session was kept",
				h.handler.sessions.count())
		}
	})

	t.Run("absolute", func(t *testing.T) {
		h := newHarness(t)
		_, display := h.mintToken(store.RoleFull)
		cookie := h.signIn(display)

		// Stay active, so the idle bound is renewed on every step and only the
		// absolute deadline can end the session. The steps stop short of that
		// deadline; the advance that follows crosses it.
		steps := int(h.handler.absoluteTTL / h.handler.idleTTL)
		for i := 0; i < steps; i++ {
			h.clock.advance(h.handler.idleTTL / 2)
			if w := h.get("/admin/", cookie); w.Code != http.StatusOK {
				t.Fatalf("step %d: status = %d, want %d", i, w.Code, http.StatusOK)
			}
		}

		h.clock.advance(h.handler.absoluteTTL)

		w := h.get("/admin/", cookie)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("after the absolute deadline: status = %d, want %d",
				w.Code, http.StatusSeeOther)
		}
	})
}

// TestSweepDiscardsExpiredSessions asserts the map does not grow without bound.
func TestSweepDiscardsExpiredSessions(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	h.signIn(display)

	if h.handler.sessions.count() != 1 {
		t.Fatalf("live sessions = %d, want 1", h.handler.sessions.count())
	}

	h.clock.advance(h.handler.absoluteTTL + time.Second)
	h.handler.sessions.sweep(h.clock.now(), h.handler.idleTTL, h.handler.absoluteTTL)

	if h.handler.sessions.count() != 0 {
		t.Errorf("live sessions = %d, want 0", h.handler.sessions.count())
	}
}

// TestSignOutInvalidatesTheSessionServerSide replays the cookie afterwards,
// which is what an attacker who captured it would do. Clearing the cookie alone
// would leave this test passing on the browser side and failing here.
func TestSignOutInvalidatesTheSessionServerSide(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)

	csrf := h.csrfFor("/admin/", cookie)
	w := h.post("/admin/sign-out", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("sign out: status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if h.handler.sessions.count() != 0 {
		t.Errorf("live sessions = %d, want 0", h.handler.sessions.count())
	}

	replay := h.get("/admin/", cookie)
	if replay.Code != http.StatusSeeOther {
		t.Fatalf("replayed cookie: status = %d, want %d", replay.Code, http.StatusSeeOther)
	}
	if got := replay.Header().Get("Location"); got != "/admin/sign-in" {
		t.Errorf("replayed cookie redirected to %q, want %q", got, "/admin/sign-in")
	}
}

// TestAuditorIsRefusedAWriteActionServerSide submits the form directly, without
// going through a page that would have hidden the control.
//
// This is the check that matters. Hiding a control is a courtesy to the
// operator; the server refusing the action is the boundary.
func TestAuditorIsRefusedAWriteActionServerSide(t *testing.T) {
	h := newHarness(t)
	tok, display := h.mintToken(store.RoleAuditor)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	detail := h.get("/admin/subjects/"+sub.ID, cookie)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail page: status = %d, want %d", detail.Code, http.StatusOK)
	}
	if strings.Contains(detail.Body.String(), "/lock") {
		t.Error("the detail page offered a control the auditor cannot use")
	}
	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)

	for _, action := range []string{
		"/admin/subjects/" + sub.ID + "/lock",
		"/admin/subjects/" + sub.ID + "/unlock",
		"/admin/subjects/" + sub.ID + "/clear-limit",
		"/admin/subjects/" + sub.ID + "/recovery-codes",
	} {
		w := h.post(action, url.Values{csrfFieldName: {csrf}, "reason": {"testing"}}, cookie)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s: status = %d, want %d", action, w.Code, http.StatusForbidden)
		}
	}

	after, err := h.store.GetSubject(context.Background(), testTenantID, sub.ID)
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	if after.Status != store.SubjectActive {
		t.Errorf("status = %q, want %q; an auditor changed a record",
			after.Status, store.SubjectActive)
	}

	denials := h.auditEntries(testTenantID, audit.EventAdminDenied)
	if len(denials) != 4 {
		t.Fatalf("recorded denials = %d, want 4", len(denials))
	}
	for _, d := range denials {
		if d.ActorID != tok.ID {
			t.Errorf("denial actor = %q, want %q", d.ActorID, tok.ID)
		}
	}
}

// TestAuditorMayReadEveryScreen is the other side of the role: reading is never
// bundled with writing, so the read screens must stay available.
func TestAuditorMayReadEveryScreen(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleAuditor)
	cookie := h.signIn(display)

	for _, path := range []string{"/admin/", "/admin/subjects", "/admin/audit",
		"/admin/alerts", "/admin/approvals"} {
		if w := h.get(path, cookie); w.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want %d", path, w.Code, http.StatusOK)
		}
	}
}

// TestExactReferenceLookup asserts the one search the interface offers, and that
// a reference nobody uses reports nothing rather than everything.
func TestExactReferenceLookup(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	found := h.get("/admin/subjects?reference=person%40example.test", cookie)
	if found.Code != http.StatusOK {
		t.Fatalf("lookup: status = %d, want %d", found.Code, http.StatusOK)
	}
	if !strings.Contains(found.Body.String(), sub.ID) {
		t.Error("the exact reference did not find the person")
	}

	missing := h.get("/admin/subjects?reference=nobody%40example.test", cookie)
	if missing.Code != http.StatusOK {
		t.Fatalf("empty lookup: status = %d, want %d", missing.Code, http.StatusOK)
	}
	if strings.Contains(missing.Body.String(), sub.ID) {
		t.Error("a reference nobody uses returned a person")
	}
}

// TestRevealingAReferenceIsAudited covers the one operation that turns a row
// back into something identifying a person.
func TestRevealingAReferenceIsAudited(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)
	sub := h.seedSubject()

	csrf := h.csrfFor("/admin/subjects/"+sub.ID, cookie)
	w := h.post("/admin/subjects/"+sub.ID+"/reference", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "person@example.test") {
		t.Error("the reference was not shown")
	}

	entries := h.auditEntries(testTenantID, "admin.subject_ref_revealed")
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
}

// TestHistoryCheckReportsAnIntactChain exercises the button and the plain
// language it produces.
func TestHistoryCheckReportsAnIntactChain(t *testing.T) {
	h := newHarness(t)
	_, display := h.mintToken(store.RoleFull)
	cookie := h.signIn(display)

	csrf := h.csrfFor("/admin/audit", cookie)
	w := h.post("/admin/audit/check", url.Values{csrfFieldName: {csrf}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "has not been altered") {
		t.Error("the result was not reported in plain language")
	}

	if entries := h.auditEntries(testTenantID, audit.EventChainVerified); len(entries) == 0 {
		t.Error("the check itself was not recorded")
	}
}

// TestAssetsAreCachedOnTheirDigest asserts the one place the interface departs
// from the no-store policy, and that it departs safely.
func TestAssetsAreCachedOnTheirDigest(t *testing.T) {
	h := newHarness(t)

	w := h.get(h.handler.assetRefs.CSS)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("content type = %q, want %q", ct, "text/css; charset=utf-8")
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("cache control = %q, want an immutable lifetime", cc)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no entity tag was set")
	}

	r := httptest.NewRequest(http.MethodGet, h.handler.assetRefs.CSS, http.NoBody)
	r.Header.Set("If-None-Match", etag)
	again := httptest.NewRecorder()
	h.handler.ServeHTTP(again, r)
	if again.Code != http.StatusNotModified {
		t.Errorf("revalidation: status = %d, want %d", again.Code, http.StatusNotModified)
	}

	if missing := h.get("/admin/static/nothing.css"); missing.Code != http.StatusNotFound {
		t.Errorf("unknown asset: status = %d, want %d", missing.Code, http.StatusNotFound)
	}
}

// TestNewRefusesIncompleteDependencies keeps the constructor honest, so a wiring
// mistake in main fails at startup rather than on the first request.
func TestNewRefusesIncompleteDependencies(t *testing.T) {
	cfg := config.Default()

	if _, err := New(Deps{Recorder: &audit.Recorder{}, Config: &cfg}); err == nil {
		t.Error("a handler was built without a store")
	}
	if _, err := New(Deps{Store: &sqlite.Store{}, Config: &cfg}); err == nil {
		t.Error("a handler was built without an audit recorder")
	}
	if _, err := New(Deps{Store: &sqlite.Store{}, Recorder: &audit.Recorder{}}); err == nil {
		t.Error("a handler was built without a configuration")
	}
}
