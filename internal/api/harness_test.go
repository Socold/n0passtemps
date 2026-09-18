package api

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/health"
	"github.com/Socold/n0passtemps/internal/metrics"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// harness is a fully wired service over a temporary SQLite database.
//
// It builds the real components rather than mocks: the real store, the real
// envelope sealer over a real keyring, the real rate limiter, the real audit
// recorder. A test that substitutes those proves the handler calls a mock, not
// that the service behaves correctly, and the properties worth testing here
// (replay refusal, lockout, tenant isolation, audit completeness) all live in
// the interaction between them.
type harness struct {
	t     *testing.T
	srv   *httptest.Server
	store store.Store
	cfg   *config.Config
	clock *testClock

	// sealer is exposed so a test can insert an envelope-encrypted record the
	// way the service would, rather than reimplementing the sealing.
	sealer *envelope.Sealer

	// metrics is the registry the server writes into, so a test can assert on
	// the exposition without scraping it over HTTP.
	metrics *metrics.Registry

	apiKey string
	admin  map[store.Role]string
}

// testClock is advanced by hand so that expiry and rate-limit windows can be
// crossed without sleeping.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time      { return c.t }
func (c *testClock) add(d time.Duration) { c.t = c.t.Add(d) }
func (c *testClock) set(t time.Time)     { c.t = t }

const testTenant = "default"

// base32Encoding matches what the enrolment route emits.
var base32Encoding = base32.StdEncoding

func newHarness(t *testing.T, tune ...func(*config.Config)) *harness {
	t.Helper()

	dir := t.TempDir()
	clock := &testClock{t: time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)}

	// The keyring lives outside the data directory, which the provider
	// enforces. Putting it inside would be refused, which is the point.
	keyDir := filepath.Join(dir, "secrets")
	dataDir := filepath.Join(dir, "data")
	for _, d := range []string{keyDir, dataDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	keyPath := filepath.Join(keyDir, "kek.json")
	writeKeyring(t, keyPath)

	cfg := config.Default()
	cfg.Tenant.ID = testTenant
	cfg.Server.Addr = "127.0.0.1:0"
	cfg.Database.Driver = "sqlite"
	cfg.Database.DSN = filepath.Join(dataDir, "test.db")
	cfg.Database.DataDir = dataDir
	cfg.KEK.Path = keyPath
	cfg.WebAuthn.RPID = "localhost"
	cfg.WebAuthn.Origins = []string{"http://localhost:8080"}
	cfg.Assertion.SigningKeyPath = filepath.Join(keyDir, "assert.pem")
	cfg.Admin.UIEnabled = false
	cfg.Logging.Level = "error"
	for _, fn := range tune {
		fn(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("harness config does not validate: %v", err)
	}

	st, err := sqlite.Open(sqlite.Options{DSN: cfg.Database.DSN, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err = st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	keyring, err := kek.LoadFileProvider(keyPath, cfg.DataDirs()...)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	sealer := envelope.NewSealer(keyring)

	t.Setenv(config.EnvPrefix+"SUBJECT_PEPPER",
		base64.StdEncoding.EncodeToString([]byte("a-test-pepper-of-thirty-two-byte")))
	subjects, err := subject.New(cfg.Subject, st, sealer, clock.now)
	if err != nil {
		t.Fatalf("subject service: %v", err)
	}
	t.Cleanup(subjects.Close)

	priv, _, err := assertion.GenerateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Assertion.SigningKeyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	signingKey, err := assertion.LoadPrivateKeyPEM(cfg.Assertion.SigningKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := assertion.NewIssuer(signingKey, cfg.Assertion.Issuer,
		cfg.Assertion.TTL.Duration, cfg.Assertion.AllowedClockSkew.Duration)
	if err != nil {
		t.Fatal(err)
	}

	log := discardLogger()
	recorder := audit.NewRecorder(st, log)
	engine := alerts.New(st, log, clock.now)
	limiter := throttle.New(st, cfg.Throttle, clock.now)

	rp, err := webauthn.New(cfg.WebAuthn, st, clock.now)
	if err != nil {
		t.Fatal(err)
	}

	seedTenant(t, st, cfg.TenantID(), clock.now())
	checker := health.New(&cfg, st, keyring, clock.now(), clock.now)

	reg := metrics.New()
	server := NewServer(Deps{
		Config: &cfg, Store: st, Subjects: subjects, WebAuthn: rp,
		Sealer: sealer, Assertion: issuer, Recorder: recorder,
		Alerts: engine, Limiter: limiter, Health: checker,
		Logger: log, Metrics: reg, Clock: clock.now,
	})

	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	h := &harness{
		t: t, srv: ts, store: st, cfg: &cfg, clock: clock, sealer: sealer,
		metrics: reg, admin: map[store.Role]string{},
	}
	h.apiKey = h.mintAPIKey("integration")
	for _, role := range []store.Role{store.RoleFull, store.RoleOperator, store.RoleAuditor} {
		h.admin[role] = h.mintAdminToken(string(role), role)
	}
	return h
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeKeyring(t *testing.T, path string) {
	t.Helper()
	key := make([]byte, kek.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	doc := map[string]any{
		"current": 1,
		"keys":    map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedTenant(t *testing.T, st store.Store, id string, now time.Time) {
	t.Helper()
	err := st.CreateTenant(context.Background(), &store.Tenant{
		ID: id, Name: "test", Status: "active", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// mintAPIKey creates a credential directly in the store, because the route that
// mints one needs an administrative token that does not exist yet.
func (h *harness) mintAPIKey(name string) string {
	h.t.Helper()
	tok, err := token.Generate(token.KindAPIKey)
	if err != nil {
		h.t.Fatal(err)
	}
	err = h.store.CreateAPIKey(context.Background(), &store.APIKey{
		ID: uuid.NewString(), TenantID: h.cfg.TenantID(), Name: name,
		Selector: tok.Selector, VerifierHash: tok.Hash, CreatedAt: h.clock.now(),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.Display
}

func (h *harness) mintAdminToken(name string, role store.Role) string {
	h.t.Helper()
	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		h.t.Fatal(err)
	}
	err = h.store.CreateAdminToken(context.Background(), &store.AdminToken{
		ID: uuid.NewString(), TenantID: h.cfg.TenantID(), Name: name,
		Selector: tok.Selector, VerifierHash: tok.Hash, Role: role,
		CreatedAt: h.clock.now(),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.Display
}

// response is a decoded HTTP reply.
type response struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    string
}

// do performs a request. An empty bearer means no Authorization header, which
// is how the unauthenticated cases are exercised.
func (h *harness) do(method, path, bearer string, body any) response {
	h.t.Helper()
	return h.doWith(method, path, bearer, body, nil)
}

// doWith is do with extra request headers, for the routes that read one.
func (h *harness) doWith(method, path, bearer string, body any, headers map[string]string) response {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	}

	req, err := http.NewRequest(method, h.srv.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}

	out := response{Status: res.StatusCode, Header: res.Header, Raw: string(raw)}
	if len(raw) > 0 {
		// A non-JSON body is not an error here: the JWKS route returns a
		// document this decoder handles, and a problem response is JSON too.
		_ = json.Unmarshal(raw, &out.Body)
	}
	return out
}

// auditEntries reads the log, for the tests that assert an action was recorded.
func (h *harness) auditEntries(eventType string) []*store.AuditEntry {
	h.t.Helper()
	entries, err := h.store.QueryAudit(context.Background(), h.cfg.TenantID(),
		store.AuditFilter{EventType: eventType, Limit: 500})
	if err != nil {
		h.t.Fatal(err)
	}
	return entries
}

// str pulls a string out of a decoded body, failing the test when absent.
// The bodies these accessors read are decoded JSON, so their shapes are not
// guaranteed by the compiler. Asserting inline fails a changed shape with a
// panic naming an interface conversion, which says nothing about which field
// moved; these say which, and print the body.

// obj reads a JSON object field.
func (r response) obj(t *testing.T, key string) map[string]any {
	t.Helper()
	v, ok := r.Body[key]
	if !ok {
		t.Fatalf("response has no %q field: %s", key, r.Raw)
	}
	return asObject(t, v, key, r.Raw)
}

// list reads a JSON array field.
func (r response) list(t *testing.T, key string) []any {
	t.Helper()
	v, ok := r.Body[key]
	if !ok {
		t.Fatalf("response has no %q field: %s", key, r.Raw)
	}
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("field %q is %T, not an array: %s", key, v, r.Raw)
	}
	return l
}

// num reads a JSON number field, which decodes as a float64.
func (r response) num(t *testing.T, key string) float64 {
	t.Helper()
	v, ok := r.Body[key]
	if !ok {
		t.Fatalf("response has no %q field: %s", key, r.Raw)
	}
	n, ok := v.(float64)
	if !ok {
		t.Fatalf("field %q is %T, not a number: %s", key, v, r.Raw)
	}
	return n
}

// asObject narrows one decoded value, for elements read out of an array.
func asObject(t *testing.T, v any, what, raw string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, not an object: %s", what, v, raw)
	}
	return m
}

// asNumber narrows one decoded value. JSON numbers decode as float64.
func asNumber(t *testing.T, v any, what string) float64 {
	t.Helper()
	n, ok := v.(float64)
	if !ok {
		t.Fatalf("%s is %T, not a number", what, v)
	}
	return n
}

// asString narrows one decoded value, for members read out of an element.
func asString(t *testing.T, v any, what string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s is %T, not a string", what, v)
	}
	return s
}

func (r response) str(t *testing.T, key string) string {
	t.Helper()
	v, ok := r.Body[key]
	if !ok {
		t.Fatalf("response has no %q field: %s", key, r.Raw)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("field %q is %T, not a string: %s", key, v, r.Raw)
	}
	return s
}

// newReader wraps a string as a body, so the media-type test can send a
// non-JSON payload without going through the JSON encoder in do.
func newReader(s string) io.Reader { return strings.NewReader(s) }

// decodeBase32 reads the unpadded base32 seed the enrolment route returns.
//
// The padding is stripped on the way out because several widely used
// authenticator applications refuse a padded secret, so it has to be restored
// before decoding.
func decodeBase32(t *testing.T, s string) []byte {
	t.Helper()
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	out, err := base32Encoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	return out
}
