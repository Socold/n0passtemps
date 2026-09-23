// Package ui renders the administration interface.
//
// The interface is server-rendered with html/template and embedded in the
// binary, for the reasons recorded in docs/adr/0012. Six screens do not justify
// a Node.js toolchain and its transitive build-time dependency surface inside an
// authentication product, so the only dependency here is the Go standard
// library.
//
// # How it is mounted
//
// New returns a *Handler, which is an http.Handler. The main package builds it
// and passes it to the API server as Deps.AdminUI, where it is mounted at the
// /admin/ prefix behind the administrative network allow list and outside the
// bearer-token middleware. This package deliberately does not import
// internal/api: that package holds this one as a dependency, so the import would
// be a cycle.
//
// Every route this package serves is registered with its full path, starting
// with /admin, because the prefix mount hands the request on unchanged.
//
// # Content Security Policy
//
// The policy set by the API middleware is "default-src 'none'; script-src
// 'self'; style-src 'self'" with no 'unsafe-inline'. Nothing here emits an
// inline style, an inline script or an inline event handler; the stylesheet and
// the script are served as files from the embedded filesystem. A template that
// grew an inline handler would not be a cosmetic problem, it would stop working.
//
// # Escaping
//
// html/template escapes contextually by default and nothing in this package
// marks a value as trusted HTML. Values read from the database reach the page as
// ordinary interpolations, so a subject reference containing markup is rendered
// as text rather than parsed.
package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/rbac"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/app.css static/app.js
var staticFS embed.FS

// Deps are the collaborators the interface needs.
//
// They are passed in rather than constructed here so that the main package owns
// the lifecycle of everything that has to be closed, and so a test can
// substitute any one of them. The set is deliberately smaller than the API
// server's: the interface reads through the same store methods the API uses and
// holds nothing of its own beyond the session map.
type Deps struct {
	// Store is the persistence contract. Every action goes through the same
	// methods the API calls, so the two surfaces cannot drift apart on what an
	// operation actually does.
	Store store.Store

	// Recorder appends to the hash-chained audit log. Every sign-in attempt and
	// every action writes an entry through it.
	Recorder *audit.Recorder

	// Config supplies the tenant, the session settings and the feature gates.
	Config *config.Config

	// Logger receives operational failures. A nil logger falls back to the
	// default.
	Logger *slog.Logger

	// Clock is injected so tests are deterministic. Nothing in this package
	// reads the wall clock directly. A nil clock falls back to time.Now.
	Clock func() time.Time

	// Limiter rate-limits sign-in attempts per source address and bounds how
	// many authenticators one operator may withdraw inside the window. It is
	// also what clears a person's sign-in limit. A nil limiter leaves those
	// controls off, which is only appropriate when throttling is disabled
	// deployment-wide.
	Limiter *throttle.Limiter

	// Subjects resolves an exact application reference to a record, and
	// decrypts a stored reference when an operator asks to see it. A nil
	// service disables the lookup and the reveal; the rest of the interface
	// works without it.
	Subjects *subject.Service

	// WebAuthn drives the console's own passkey ceremonies. It is the same
	// relying party the public surface uses, because the relying party
	// identifier and the acceptable origins are one deployment-wide fact and
	// two services would be two chances to disagree about them. What is not
	// shared is the credentials: the console's live in their own table and
	// neither surface can reach the other's. See internal/webauthn/admin.go.
	//
	// A nil service leaves the console on pasted tokens alone, and the passkey
	// controls are not rendered. That is the correct behaviour rather than a
	// degraded one: a deployment may reasonably not want a second way in.
	WebAuthn *webauthn.Service
}

// Handler serves the administration interface.
//
// It is safe for concurrent use. The template set and the asset map are built
// once in New and never written to afterwards; the session map has its own
// mutex.
type Handler struct {
	deps Deps
	now  func() time.Time

	// pages maps a screen name to the template set for that screen. Each set is
	// the layout plus one page file, because a single set can hold only one
	// definition of "content".
	pages map[string]*template.Template

	sessions *sessionStore

	assets    map[string]*asset
	assetRefs assetRefs

	// absoluteTTL bounds a session from the moment it is minted, and idleTTL
	// bounds it from the last request. See newSessionStore for why both exist.
	absoluteTTL time.Duration
	idleTTL     time.Duration

	mux *http.ServeMux
}

// defaultSessionTTL is used when the configuration carries no usable value.
//
// Validate refuses a non-positive admin.session_ttl when the interface is
// enabled, so this is reached only by a caller that built a Config by hand, such
// as a test. Falling back to a bounded session is safer than falling back to an
// unbounded one.
const defaultSessionTTL = 30 * time.Minute

// minIdleTimeout is the floor on the inactivity bound.
//
// Deriving the idle timeout from the session length alone would make a short
// configured session expire mid-form for an operator who is reading the page.
const minIdleTimeout = 5 * time.Minute

// New builds the interface handler.
//
// The signature takes one struct so that the main package can construct it
// beside the API server's own Deps and pass the result straight into
// api.Deps.AdminUI:
//
//	adminUI, err := ui.New(ui.Deps{
//		Store:    st,
//		Recorder: recorder,
//		Config:   cfg,
//		Logger:   log,
//		Clock:    clock,
//		Limiter:  limiter,
//		Subjects: subjects,
//	})
//	if err != nil {
//		return err
//	}
//	srv := api.NewServer(api.Deps{ /* ... */ AdminUI: adminUI})
//
// It returns an error rather than panicking on a broken template, so a build
// that ships an unparsable page fails at startup with a message naming the file
// instead of on the first request an operator makes.
func New(deps Deps) (*Handler, error) {
	if deps.Store == nil {
		return nil, fmt.Errorf("adminui: build handler: %w", errMissingStore)
	}
	if deps.Recorder == nil {
		return nil, fmt.Errorf("adminui: build handler: %w", errMissingRecorder)
	}
	if deps.Config == nil {
		return nil, fmt.Errorf("adminui: build handler: %w", errMissingConfig)
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}

	absolute := deps.Config.Admin.SessionTTL.Duration
	if absolute <= 0 {
		absolute = defaultSessionTTL
	}
	idle := absolute / 2
	if idle < minIdleTimeout {
		idle = minIdleTimeout
	}
	if idle > absolute {
		idle = absolute
	}

	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	assets, refs, err := loadAssets()
	if err != nil {
		return nil, err
	}

	h := &Handler{
		deps:        deps,
		now:         deps.Clock,
		pages:       pages,
		sessions:    newSessionStore(),
		assets:      assets,
		assetRefs:   refs,
		absoluteTTL: absolute,
		idleTTL:     idle,
	}
	h.routes()
	return h, nil
}

// Errors reported by New.
var (
	errMissingStore    = constError("a store is required")
	errMissingRecorder = constError("an audit recorder is required")
	errMissingConfig   = constError("a configuration is required")
)

// constError is an error value that can be declared as a constant, so these
// sentinels cannot be reassigned by another package.
type constError string

func (e constError) Error() string { return string(e) }

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// routes registers every path the interface answers.
//
// The patterns carry the /admin prefix because the API mounts this handler at
// that prefix and passes the path through unchanged. The dashboard is registered
// with {$} so it matches /admin/ exactly rather than acting as a catch-all
// prefix that would swallow every other screen.
//
// The method is part of each pattern. A screen registered without one would
// answer a POST by rendering the read-only page, which hides a failed action
// behind a page that looks like it worked.
func (h *Handler) routes() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/{$}", h.handleDashboard)

	mux.HandleFunc("GET /admin/sign-in", h.handleSignInForm)
	mux.HandleFunc("POST /admin/sign-in", h.handleSignInSubmit)
	mux.HandleFunc("POST /admin/sign-out", h.handleSignOut)

	// The console's own passkeys. They add no screen: signing in with one is
	// the sign-in screen, and managing them is a section of the dashboard,
	// which is where an operator already looks to see what their sign-in is.
	// ADR 0012 counted six screens as the reason a build toolchain was not
	// worth it, and a seventh would erode the count and the three-click rule
	// together.
	mux.HandleFunc("POST /admin/sign-in/passkey/begin", h.handlePasskeySignInBegin)
	mux.HandleFunc("POST /admin/sign-in/passkey/complete", h.handlePasskeySignInComplete)
	mux.HandleFunc("POST /admin/passkeys/begin", h.handlePasskeyEnrolBegin)
	mux.HandleFunc("POST /admin/passkeys/complete", h.handlePasskeyEnrolComplete)
	mux.HandleFunc("POST /admin/passkeys/{credential_id}/withdraw", h.handlePasskeyWithdraw)

	mux.HandleFunc("GET /admin/subjects", h.handleSubjectList)
	mux.HandleFunc("GET /admin/subjects/{subject_id}", h.handleSubjectDetail)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/lock", h.handleSubjectLock)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/unlock", h.handleSubjectUnlock)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/clear-limit", h.handleSubjectClearLimit)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/recovery-codes", h.handleSubjectRecoveryCodes)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/reference", h.handleSubjectReference)
	mux.HandleFunc("POST /admin/subjects/{subject_id}/authenticators/{credential_id}/withdraw",
		h.handleCredentialWithdraw)

	mux.HandleFunc("GET /admin/audit", h.handleAuditList)
	mux.HandleFunc("POST /admin/audit/check", h.handleAuditCheck)

	mux.HandleFunc("GET /admin/alerts", h.handleAlertList)
	mux.HandleFunc("POST /admin/alerts/{alert_id}/acknowledge", h.handleAlertAcknowledge)

	mux.HandleFunc("GET /admin/approvals", h.handleApprovalList)
	mux.HandleFunc("POST /admin/approvals/{approval_id}/approve", h.handleApprovalApprove)
	mux.HandleFunc("POST /admin/approvals/{approval_id}/reject", h.handleApprovalReject)

	mux.HandleFunc("GET /admin/static/{file}", h.handleAsset)

	// Anything else under the prefix. A bare 404 here rather than a redirect,
	// because a redirect from an unknown path is how an open redirect starts.
	mux.HandleFunc("/admin/", h.handleNotFound)

	h.mux = mux
}

// asset is one embedded static file, with the digest that keys its cache entry.
type asset struct {
	body        []byte
	contentType string
	etag        string
	digest      string
}

// assetRefs are the URLs the layout references.
//
// The digest travels as a query parameter rather than in the filename, so the
// embedded path and the served path stay identical and there is no rewriting
// step between the two.
type assetRefs struct {
	CSS string
	JS  string
}

// loadAssets reads the embedded static files and derives a cache key from the
// content of each.
//
// Keying on a digest is what makes a one-year cache lifetime safe: a changed
// stylesheet gets a different URL, so a browser holding the old one fetches the
// new one instead of serving a stale page for a year. Changing a stylesheet
// requires recompiling the binary, which is the consequence recorded in ADR
// 0012, and the digest is computed from the compiled-in bytes so the two cannot
// disagree.
func loadAssets() (map[string]*asset, assetRefs, error) {
	types := map[string]string{
		".css": "text/css; charset=utf-8",
		".js":  "text/javascript; charset=utf-8",
	}

	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		return nil, assetRefs{}, fmt.Errorf("adminui: read embedded assets: %w", err)
	}

	out := make(map[string]*asset, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := staticFS.ReadFile(path.Join("static", e.Name()))
		if err != nil {
			return nil, assetRefs{}, fmt.Errorf("adminui: read embedded asset %s: %w", e.Name(), err)
		}
		ct, ok := types[strings.ToLower(path.Ext(e.Name()))]
		if !ok {
			return nil, assetRefs{}, fmt.Errorf("adminui: embedded asset %s: %w", e.Name(), errUnknownAssetType)
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])[:16]
		out[e.Name()] = &asset{
			body:        body,
			contentType: ct,
			etag:        `"` + digest + `"`,
			digest:      digest,
		}
	}

	css, okCSS := out["app.css"]
	js, okJS := out["app.js"]
	if !okCSS || !okJS {
		return nil, assetRefs{}, fmt.Errorf("adminui: embedded assets: %w", errMissingAsset)
	}

	return out, assetRefs{
		CSS: "/admin/static/app.css?v=" + css.digest,
		JS:  "/admin/static/app.js?v=" + js.digest,
	}, nil
}

var (
	errUnknownAssetType = constError("no content type is declared for this extension")
	errMissingAsset     = constError("app.css and app.js must both be present")
)

// handleAsset serves a stylesheet or a script from the embedded filesystem.
//
// The response overrides the no-store header the surrounding middleware sets.
// That header is right for every page, because pages carry authentication state,
// and wrong for these two files, which carry none and are addressed by a digest
// of their own content.
func (h *Handler) handleAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := h.assets[r.PathValue("file")]
	if !ok {
		h.handleNotFound(w, r)
		return
	}

	head := w.Header()
	head.Set("Content-Type", a.contentType)
	head.Set("ETag", a.etag)
	head.Set("Cache-Control", "public, max-age=31536000, immutable")
	head.Del("Pragma")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, a.digest) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	head.Set("Content-Length", fmt.Sprint(len(a.body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a.body)
}

// parsePages builds one template set per screen.
//
// Each set is the shared layout plus a single page file. Parsing every page into
// one set is not possible, because each page defines "content" and the last
// definition parsed would win silently.
func parsePages() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("adminui: list templates: %w", err)
	}

	layout, err := templateFS.ReadFile("templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("adminui: read layout template: %w", err)
	}

	out := make(map[string]*template.Template, len(names))
	for _, name := range names {
		base := strings.TrimSuffix(path.Base(name), ".html")
		if base == "layout" {
			continue
		}
		body, err := templateFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("adminui: read template %s: %w", base, err)
		}

		t := template.New(base).Funcs(templateFuncs())
		if _, err := t.Parse(string(layout)); err != nil {
			return nil, fmt.Errorf("adminui: parse layout for %s: %w", base, err)
		}
		if _, err := t.Parse(string(body)); err != nil {
			return nil, fmt.Errorf("adminui: parse template %s: %w", base, err)
		}
		if t.Lookup("content") == nil {
			return nil, fmt.Errorf("adminui: template %s: %w", base, errNoContentBlock)
		}
		if t.Lookup("title") == nil {
			return nil, fmt.Errorf("adminui: template %s: %w", base, errNoTitleBlock)
		}
		out[base] = t
	}

	for _, required := range []string{
		"signin", "dashboard", "subjects", "subject", "audit", "alerts", "approvals", "message",
	} {
		if _, ok := out[required]; !ok {
			return nil, fmt.Errorf("adminui: template %s: %w", required, errTemplateMissing)
		}
	}
	return out, nil
}

var (
	errNoContentBlock  = constError(`no "content" block is defined`)
	errNoTitleBlock    = constError(`no "title" block is defined`)
	errTemplateMissing = constError("the template is not embedded")
)

// templateFuncs are the helpers the pages use.
//
// The set is small on purpose. Anything that needs a decision belongs in Go,
// where it can be tested; a template function that formats a value is the only
// kind that earns its place here.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"datetime":  formatTime,
		"yesno":     yesNo,
		"eventName": eventName,
		"severity":  severityWord,
		"outcome":   outcomeWord,
		"operation": operationWord,
		"fields":    payloadFields,
	}
}

// formatTime renders an instant in a form an operator can read.
//
// A zero time and a nil pointer both render as an em-free dash-free placeholder,
// because a blank cell is indistinguishable from a rendering fault.
func formatTime(v any) string {
	var t time.Time
	switch tv := v.(type) {
	case time.Time:
		t = tv
	case *time.Time:
		if tv == nil {
			return "not recorded"
		}
		t = *tv
	default:
		return "not recorded"
	}
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2 January 2006, 15:04") + " UTC"
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// eventNames translates the audit vocabulary into plain words.
//
// The stored event type is a dotted machine name, and showing it to an operator
// would be exactly the jargon the specification rules out. Anything not listed
// falls back to the dotted name with its separators softened, so a new event
// type reads awkwardly rather than not at all.
var eventNames = map[string]string{
	"subject.created":                 "Person added",
	"subject.status_changed":          "Status changed",
	"subject.locked":                  "Sign-in blocked",
	"subject.unlocked":                "Sign-in allowed again",
	"webauthn.registration.started":   "Started adding a security key or passkey",
	"webauthn.registration.completed": "Added a security key or passkey",
	"webauthn.registration.rejected":  "Adding a security key or passkey was refused",
	"webauthn.assertion.started":      "Started signing in",
	"webauthn.assertion.completed":    "Signed in",
	"webauthn.assertion.rejected":     "Sign-in refused",
	"webauthn.sign_count_regression":  "An authenticator may have been copied",
	"webauthn.binding_changed":        "An authenticator changed",
	"credential.revoked":              "Authenticator withdrawn",
	"credential.labelled":             "Authenticator renamed",
	"credential.bulk_revoked":         "Several authenticators withdrawn at once",
	"totp.enrolled":                   "Started setting up an authenticator app",
	"totp.confirmed":                  "Authenticator app set up",
	"totp.verified":                   "Code from the authenticator app accepted",
	"totp.rejected":                   "Code from the authenticator app refused",
	"totp.replay_detected":            "A code from the authenticator app was reused",
	"totp.revoked":                    "Authenticator app removed",
	"recovery.issued":                 "Recovery codes issued",
	"recovery.consumed":               "A recovery code was used",
	"recovery.rejected":               "A recovery code was refused",
	"recovery.exhausted":              "No recovery codes are left",
	"throttle.tripped":                "Too many attempts, sign-in paused",
	"throttle.reset":                  "Sign-in limit cleared",
	"api_key.created":                 "Application key created",
	"api_key.revoked":                 "Application key withdrawn",
	"api_key.rejected":                "Application key refused",
	"admin_token.created":             "Administrator sign-in created",
	"admin_token.revoked":             "Administrator sign-in withdrawn",
	"admin.auth_failed":               "Administrator sign-in refused",
	"admin.authorised":                "Administrator signed in",
	"admin_credential.enrolled":       "Administrator added a passkey",
	"admin_credential.revoked":        "Administrator passkey withdrawn",
	"admin.denied":                    "Administrator action refused",
	"admin.subjects_listed":           "Looked at the list of people",
	"admin.subject_ref_revealed":      "Looked at a person's reference",
	"approval.requested":              "Second approval requested",
	"approval.granted":                "Request approved",
	"approval.rejected":               "Request rejected",
	"approval.expired":                "Request expired",
	"approval.executed":               "Approved request carried out",
	"erasure.requested":               "Deletion requested",
	"erasure.cancelled":               "Deletion cancelled",
	"erasure.purged":                  "Record deleted",
	"erasure.entries_redacted":        "Personal details removed from the history",
	"kek.loaded":                      "Encryption key loaded",
	"kek.rotated":                     "Encryption key replaced",
	"kek.rewrapped":                   "Records re-encrypted under the new key",
	"service.started":                 "Service started",
	"service.stopping":                "Service stopping",
	"service.migration_applied":       "Database updated",
	"audit.chain_verified":            "History checked",
	"audit.chain_broken":              "History check failed",
	"alert.raised":                    "Alert raised",
	"alert.acknowledged":              "Alert marked as seen",
}

// eventName renders an audit event type in plain words.
func eventName(v string) string {
	if name, ok := eventNames[v]; ok {
		return name
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, ".", " "), "_", " ")
}

// severityWord renders an alert severity as something an operator can act on.
func severityWord(v store.Severity) string {
	switch v {
	case store.SeverityCritical:
		return "Needs attention now"
	case store.SeverityWarning:
		return "Worth a look"
	case store.SeverityInfo:
		return "For information"
	}
	return string(v)
}

// outcomeWord renders an audit outcome in plain words.
func outcomeWord(v store.Outcome) string {
	switch v {
	case store.OutcomeSuccess:
		return "Succeeded"
	case store.OutcomeFailure:
		return "Did not succeed"
	case store.OutcomeDenied:
		return "Refused"
	case store.OutcomeError:
		return "Faulted"
	}
	return string(v)
}

// operationWord renders a queued operation in plain words.
var operationWords = map[string]string{
	"credential.revoke_bulk": "Withdraw several authenticators at once",
	"subject.erase":          "Delete a person's record",
	"admin_token.create":     "Create an administrator sign-in",
	"kek.rotate":             "Replace the encryption key",
}

func operationWord(v string) string {
	if name, ok := operationWords[v]; ok {
		return name
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, ".", " "), "_", " ")
}

// field is one key and value from a stored JSON document.
type field struct {
	Name  string
	Value string
}

// payloadFields flattens a stored JSON document into sorted label and value
// pairs.
//
// The audit detail, the alert detail and the approval payload are all JSON. A
// raw document on the page would be jargon, and marking it as trusted HTML to
// pretty-print it would defeat the escaping this interface depends on, so it is
// decoded here and rendered as ordinary text.
func payloadFields(raw json.RawMessage) []field {
	if len(raw) == 0 {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]field, 0, len(keys))
	for _, k := range keys {
		out = append(out, field{
			Name:  strings.ReplaceAll(k, "_", " "),
			Value: fmt.Sprint(doc[k]),
		})
	}
	return out
}

// allowed reports whether the operator's role may exercise a permission.
//
// It delegates to rbac.Allowed, which is the same mapping the API middleware
// consults, so the two surfaces cannot disagree about what a role may do. With
// role-based access control disabled, any valid role carries full authority,
// because that is what the lite deployment means; see internal/rbac.
//
// The result is used twice for every action: once to decide whether to render
// the control, and once in the handler to decide whether to perform it. Hiding a
// control is a courtesy to the operator, not a security boundary, since a form
// can be submitted directly.
func (h *Handler) allowed(role store.Role, p rbac.Permission) bool {
	if !role.Valid() {
		return false
	}
	if !h.deps.Config.Features.AdminRBAC {
		return true
	}
	return rbac.Allowed(role, p)
}

// tenantID is the tenant every query and every audit entry is written under.
func (h *Handler) tenantID() string { return h.deps.Config.TenantID() }

// renderBuffer is the size hint for a rendered page.
const renderBuffer = 16 << 10

// render writes a screen.
//
// The page is rendered into a buffer first. A template that fails halfway
// through would otherwise have already written a partial document and a 200
// status, leaving the operator with a page that looks truncated rather than an
// error they can report.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, page string, data *pageData) {
	t, ok := h.pages[page]
	if !ok {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: unknown page requested",
			slog.String("page", page))
		http.Error(w, "The page is not available.", http.StatusInternalServerError)
		return
	}

	buf := bytes.NewBuffer(make([]byte, 0, renderBuffer))
	if err := t.ExecuteTemplate(buf, "layout", data); err != nil {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: page not rendered",
			slog.String("page", page), slog.Any("error", err))
		http.Error(w, "The page could not be displayed.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
