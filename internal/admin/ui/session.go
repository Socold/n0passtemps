package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// sessionCookieName is the cookie the browser sends back.
//
// The name is prefixed with the product rather than being a bare "session", so
// that it cannot collide with a cookie set by another application an operator
// happens to have on the same host during development.
const sessionCookieName = "n0passtemps_admin_session"

// csrfFieldName is the hidden form field every state-changing form carries.
const csrfFieldName = "csrf_token"

// session is one signed-in operator.
//
// It holds the identity resolved from the administrative token, never the token
// itself: a long-lived credential in a cookie is a worse exposure than a bounded
// session. It does not outlive the token either. requireSession reads the token
// back by its identifier on every request, which needs nothing the browser
// holds, so a revoked or expired token ends the sessions made with it.
type session struct {
	// TokenID is the administrative token this session was established with. It
	// is the actor identifier on every audit entry the session writes.
	TokenID string

	// TokenName is what the operator named the token, shown so they can tell
	// which credential they are signed in with.
	TokenName string

	TenantID string
	Role     store.Role

	// csrf is bound to this session and to no other. See checkCSRF.
	csrf string

	// establishedAt fixes the absolute deadline, and lastSeenAt the idle one.
	establishedAt time.Time
	lastSeenAt    time.Time
}

// sessionStore holds the live sessions.
//
// # Why the key is a digest
//
// The map is keyed on a SHA-256 of the cookie value rather than on the value
// itself. The cookie value is a live credential: anyone holding it is signed in.
// Keyed by the value, the credential would sit in process memory, in a heap dump
// and in any diagnostic that walked the map, and a timing difference in a map
// probe would leak a prefix of it. Keyed by a digest, a reader of the map learns
// nothing they can present back to the service, because the digest cannot be
// reversed and is not what the cookie check compares.
//
// # Why sessions are lost on restart
//
// They are held in memory and nowhere else. This is a single-binary service with
// no session store, and adding one would mean either a table in the database,
// which puts a live credential surrogate next to the data it protects, or an
// external cache, which is a new dependency and a new failure mode for a set of
// six screens. Losing them on restart means every operator signs in again after
// an upgrade, which is the correct behaviour for an administrative surface and
// is also what an operator would expect a restart to do.
type sessionStore struct {
	mu   sync.Mutex
	live map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{live: make(map[string]*session)}
}

// sessionKey derives the map key from a cookie value.
func sessionKey(cookieValue string) string {
	sum := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(sum[:])
}

// randomToken returns n bytes from the operating system, base64url encoded.
//
// A failure to read the random source is returned rather than worked around. A
// session identifier derived from anything predictable is not a session
// identifier, so refusing to sign the operator in is the only safe answer.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("adminui: read random source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sessionBytes is the entropy of a session identifier.
//
// 32 bytes is 256 bits, which puts guessing beyond reach and leaves no reason to
// think about the birthday bound on the map key.
const sessionBytes = 32

// mint creates a session and returns the cookie value that addresses it.
//
// The cookie value is returned to the caller and never retained: only its digest
// is stored, so this function is the last place in the process that holds the
// live credential.
func (s *sessionStore) mint(now time.Time, tok *store.AdminToken, idle, absolute time.Duration) (string, *session,
	error) {
	value, err := randomToken(sessionBytes)
	if err != nil {
		return "", nil, err
	}
	csrf, err := randomToken(sessionBytes)
	if err != nil {
		return "", nil, err
	}

	sess := &session{
		TokenID:       tok.ID,
		TokenName:     tok.Name,
		TenantID:      tok.TenantID,
		Role:          tok.Role,
		csrf:          csrf,
		establishedAt: now,
		lastSeenAt:    now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now, idle, absolute)
	s.live[sessionKey(value)] = sess
	return value, sess, nil
}

// get returns the session a cookie value addresses, and renews its idle
// deadline.
//
// An expired session is removed here rather than left for the sweep, so that a
// replayed cookie cannot be used even in the window before the next sweep runs.
func (s *sessionStore) get(now time.Time, cookieValue string, idle, absolute time.Duration) (*session, bool) {
	if cookieValue == "" {
		return nil, false
	}
	key := sessionKey(cookieValue)

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.live[key]
	if !ok {
		return nil, false
	}
	if expired(sess, now, idle, absolute) {
		delete(s.live, key)
		return nil, false
	}
	sess.lastSeenAt = now
	return sess, true
}

// destroy removes a session server-side.
//
// Clearing the cookie alone would leave the session usable by anyone who had
// already captured the value, which is precisely the case signing out exists to
// close.
func (s *sessionStore) destroy(cookieValue string) {
	if cookieValue == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, sessionKey(cookieValue))
}

// sweep discards expired sessions.
//
// Without it the map would keep every session an operator ever established until
// the process restarted, which is a slow leak on a long-running service and a
// growing set of entries a memory disclosure could read.
func (s *sessionStore) sweep(now time.Time, idle, absolute time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now, idle, absolute)
}

func (s *sessionStore) sweepLocked(now time.Time, idle, absolute time.Duration) {
	for key, sess := range s.live {
		if expired(sess, now, idle, absolute) {
			delete(s.live, key)
		}
	}
}

// count reports how many sessions are live, for the dashboard and for tests.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// expired applies both deadlines.
//
// Two bounds are needed and neither substitutes for the other. The idle timeout
// closes a session left open on an unattended screen, which is the common case
// on a shared support desk. The absolute deadline bounds a session that is kept
// alive by activity, so a stolen cookie cannot be refreshed indefinitely by the
// thief making one request every few minutes.
func expired(s *session, now time.Time, idle, absolute time.Duration) bool {
	if !now.Before(s.establishedAt.Add(absolute)) {
		return true
	}
	return !now.Before(s.lastSeenAt.Add(idle))
}

// setSessionCookie writes the cookie that addresses a session.
//
// Each attribute stops something specific:
//
//	HttpOnly          keeps the value out of document.cookie, so a script
//	                  injected through any future template mistake cannot read
//	                  the session and post it elsewhere
//	SameSite=Strict   stops the browser sending the cookie on a request another
//	                  site initiated, which is what a cross-site request forgery
//	                  depends on
//	Secure            stops the cookie being sent over plain HTTP, where a
//	                  network observer would read it; it is forced on by the
//	                  configuration validator whenever TLS is terminated here or
//	                  a trusted proxy is declared
//	Path=/admin       keeps the cookie off every other path on the host, so the
//	                  public /v1 routes and anything else sharing the origin
//	                  never receive it
//	MaxAge            makes the browser discard the cookie when the session
//	                  would have expired anyway, rather than keeping a value the
//	                  server will refuse
func (h *Handler) setSessionCookie(w http.ResponseWriter, value string) {
	// #nosec G124 -- HttpOnly and SameSite=Strict are unconditional; Secure comes from configuration only so a
	// developer can sign in over http://localhost, and config.Validate forces it on whenever TLS is terminated here
	// or a proxy is trusted
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   h.deps.Config.Admin.SessionCookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.absoluteTTL.Seconds()),
	})
}

// clearSessionCookie tells the browser to discard the cookie.
//
// It is only half of signing out. The other half, and the half that matters, is
// removing the session from the store.
func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	// #nosec G124 -- the discard cookie carries the same attributes as the one it replaces, so a browser matches and
	// drops it; see setSessionCookie for why Secure is configurable
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   h.deps.Config.Admin.SessionCookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// cookieValue reads the session cookie from a request.
func cookieValue(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// requireSession resolves the signed-in operator, or redirects to the sign-in
// screen.
//
// It returns nil when it has already answered the request, so a handler reads:
//
//	sess := h.requireSession(w, r)
//	if sess == nil {
//		return
//	}
//
// A redirect rather than a 401, because the caller is a browser and the operator
// needs somewhere to type their token. The target is a fixed path, never
// anything taken from the request, so this cannot be turned into an open
// redirect.
func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) *session {
	sess, ok := h.sessions.get(h.now().UTC(), cookieValue(r), h.idleTTL, h.absoluteTTL)
	if !ok {
		h.clearSessionCookie(w)
		http.Redirect(w, r, "/admin/sign-in", http.StatusSeeOther)
		return nil
	}

	// A session established under a different tenant is refused for the same
	// reason the API refuses a credential naming one: a database carried over
	// from another deployment, or a tenant identifier changed under a running
	// service, must fail loudly rather than operate on rows it does not own.
	if sess.TenantID != h.tenantID() {
		h.sessions.destroy(cookieValue(r))
		h.clearSessionCookie(w)
		http.Redirect(w, r, "/admin/sign-in", http.StatusSeeOther)
		return nil
	}

	// The session is only as good as the token it was made with. Revoking a
	// token is what an operator does about a colleague who has left or a
	// credential that leaked, and a session that carried on for the rest of its
	// twelve hours could still lock subjects, reissue recovery codes and decide
	// approval requests under a role its holder no longer had.
	tok, err := h.deps.Store.GetAdminTokenByID(r.Context(), sess.TenantID, sess.TokenID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.serverFault(w, r, nil, "read the session's administrative token", err)
		return nil
	}
	// A role that no longer matches ends the session as well. Nothing changes a
	// token's role today, and signing in again is the cheap answer if something
	// ever does: the session is shared between requests, so correcting its copy
	// in place would need a lock on every read of it.
	if err != nil || !tok.Usable(h.now().UTC()) || tok.Role != sess.Role {
		h.sessions.destroy(cookieValue(r))
		h.clearSessionCookie(w)
		http.Redirect(w, r, "/admin/sign-in", http.StatusSeeOther)
		return nil
	}
	return sess
}

// checkCSRF refuses a state-changing request that does not carry the token bound
// to its own session.
//
// # Why SameSite=Strict is not enough on its own
//
// SameSite is a browser behaviour, not a server check. It does nothing for a
// browser that does not implement it, it does nothing when a request does not
// come from a browser at all, and it does nothing against an attacker who has
// any foothold on the same site: a page served from another path on this origin,
// or from a subdomain the cookie is scoped to, is same-site by definition and its
// requests carry the cookie. The token closes that, because the attacker would
// have to read a value that only the session's own rendered pages contain.
//
// The comparison is constant time. A byte-by-byte comparison that returned early
// would let an attacker recover the token one character at a time by measuring
// how long the refusal took.
func (h *Handler) checkCSRF(w http.ResponseWriter, r *http.Request, sess *session) bool {
	if err := r.ParseForm(); err != nil {
		h.renderMessage(w, r, sess, http.StatusBadRequest, "The form could not be read",
			"Go back, reload the page and try again.")
		return false
	}

	presented := r.PostFormValue(csrfFieldName)
	if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(sess.csrf)) != 1 {
		h.deps.Logger.WarnContext(r.Context(), "adminui: form submitted without a valid request token",
			slog.String("path", r.URL.Path),
			slog.String("actor_id", sess.TokenID))
		h.auditDenied(w, r, sess, "csrf", r.URL.Path, "the form did not carry a valid request token")
		h.renderMessage(w, r, sess, http.StatusForbidden, "This form has expired",
			"Reload the page and try the action again. Nothing has been changed.")
		return false
	}
	return true
}

// handleSignInForm renders the sign-in screen.
//
// An operator who already holds a session is sent to the dashboard rather than
// shown the form again, so signing in twice cannot mint a second session for the
// same browser.
func (h *Handler) handleSignInForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessions.get(h.now().UTC(), cookieValue(r), h.idleTTL, h.absoluteTTL); ok {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	pd := h.newPage(r, nil, "Sign in")
	pd.Data = signInData{PasskeyOffered: h.passkeysOffered()}
	h.render(w, r, http.StatusOK, "signin", pd)
}

// handleSignInSubmit verifies a pasted administrative token and mints a session.
//
// The order of operations matches internal/api/auth.go, and for the same
// reasons. The rate limit is consulted first, so a caller that is already locked
// out gets no verification work out of the service. The token is then parsed,
// which rejects malformed input without a query. The selector drives a single
// indexed lookup, the verifier is compared in constant time, and usability is
// checked last. Every failure produces the same message, because distinguishing
// an unknown selector from a wrong verifier would confirm to an attacker that
// half of their guess was right.
func (h *Handler) handleSignInSubmit(w http.ResponseWriter, r *http.Request) {
	now := h.now().UTC()
	ip := h.sourceIP(r)

	if err := r.ParseForm(); err != nil {
		h.renderSignInRefusal(w, r, "The form could not be read. Try again.")
		return
	}

	// The sign-in form is the one unauthenticated state-changing route, so it
	// cannot carry a session-bound token. It is rate limited per source address
	// instead, which is the control that makes repeated guessing expensive.
	dims := h.signInDims(ip)
	if blocked, retryAfter := h.signInBlocked(r, dims); blocked {
		h.auditSignInFailure(w, r, ip, "the source address has made too many attempts")
		h.renderSignInRefusal(w, r, fmt.Sprintf(
			"Too many attempts from this network. Wait %d minutes and try again.",
			minutesAtLeastOne(retryAfter)))
		return
	}

	presented := strings.TrimSpace(r.PostFormValue("token"))
	if presented == "" {
		h.recordSignInAttempt(r, dims, true)
		h.auditSignInFailure(w, r, ip, "no token was supplied")
		h.renderSignInRefusal(w, r, "Paste your administrator sign-in token to continue.")
		return
	}

	tok, err := h.verifyAdminToken(r, presented, now)
	if err != nil {
		h.recordSignInAttempt(r, dims, true)
		h.auditSignInFailure(w, r, ip, err.Error())
		h.renderSignInRefusal(w, r, "That sign-in token was not accepted.")
		return
	}
	if tok.TenantID != h.tenantID() {
		h.recordSignInAttempt(r, dims, true)
		h.auditSignInFailure(w, r, ip, "the token belongs to another deployment")
		h.renderSignInRefusal(w, r, "That sign-in token was not accepted.")
		return
	}

	// A deployment may require the passkey once this token has one. The refusal
	// is deliberately not the fixed one above: the token verified, so there is
	// nothing left to learn from being told why, and an operator who has just
	// pasted a working token needs to be told to use their key rather than left
	// to conclude the token has been withdrawn. The attempt is still counted
	// and still audited, because a run of them from one address is worth
	// seeing whatever the reason.
	if h.passkeyRequiredFor(r, tok) {
		h.recordSignInAttempt(r, dims, true)
		h.auditSignInFailure(w, r, ip, "this deployment requires the passkey enrolled for this token")
		h.renderSignInRefusal(w, r, "This administrator signs in with a passkey. "+
			"Use the passkey button rather than the token.")
		return
	}

	// A session the browser still holds ends here, before the new one exists.
	// Signing in again is what an operator does when they suspect the session
	// they have, and leaving the old one live in the store would keep whoever
	// captured its cookie signed in for the rest of the idle window. The form
	// redirects a live session to the dashboard, so reaching this line with one
	// means the request was made without loading the page, which is the case
	// worth closing rather than the one to assume away.
	h.sessions.destroy(cookieValue(r))

	value, sess, err := h.sessions.mint(now, tok, h.idleTTL, h.absoluteTTL)
	if err != nil {
		h.deps.Logger.ErrorContext(r.Context(), "adminui: session not created", slog.Any("error", err))
		h.renderSignInRefusal(w, r, "The session could not be started. Try again.")
		return
	}

	// A successful attempt still counts towards the volume the address is
	// allowed, so a compromised token cannot be used to enumerate from one
	// address without limit.
	h.recordSignInAttempt(r, dims, false)

	// Recording last use must not be able to fail the sign-in. A write error
	// here means the database is unhappy, which the health summary reports;
	// refusing a valid sign-in over it would turn a degraded database into an
	// administrative outage.
	if err := h.deps.Store.TouchAdminToken(r.Context(), tok.ID, now); err != nil {
		h.deps.Logger.WarnContext(r.Context(), "adminui: token last-use timestamp not recorded",
			slog.Any("error", err))
	}

	h.audited(w, r, audit.Event{
		TenantID:  sess.TenantID,
		EventType: audit.EventAdminAuthorised,
		ActorType: store.ActorAdmin,
		ActorID:   sess.TokenID,
		Outcome:   store.OutcomeSuccess,
		SourceIP:  ip,
		Detail: map[string]any{
			"role":    string(sess.Role),
			"surface": "administration interface",
			// Which of the two ways in was used. The console mints one kind of
			// session from either, so the entry is the only place the
			// difference survives, and an operator reviewing who signed in
			// with a pasted token after passkeys were rolled out has nowhere
			// else to look.
			"method": "sign-in token",
		},
	})

	h.setSessionCookie(w, value)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// handleSignOut ends a session.
//
// The session is removed from the store before the cookie is cleared, so a
// captured cookie stops working whether or not the browser honours the
// instruction to discard it.
func (h *Handler) handleSignOut(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.checkCSRF(w, r, sess) {
		return
	}

	h.sessions.destroy(cookieValue(r))
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/admin/sign-in?notice=signed-out", http.StatusSeeOther)
}

// verifyAdminToken resolves and checks a pasted administrative token.
//
// The returned error is for the audit entry and the log line. It is never shown
// to the operator, who sees one fixed refusal whatever went wrong.
func (h *Handler) verifyAdminToken(r *http.Request, presented string, now time.Time) (*store.AdminToken, error) {
	parsed, err := token.Parse(presented)
	if err != nil {
		return nil, errors.New("the token is malformed")
	}
	// A token minted for the public surface must not sign an operator in. The
	// kind is bound into the stored digest as well, so this check is belt and
	// braces rather than the only guard.
	if parsed.Kind != token.KindAdmin {
		return nil, errors.New("the token is not an administrator token")
	}

	tok, err := h.deps.Store.GetAdminTokenBySelector(r.Context(), parsed.Selector)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("the token is not recognised")
		}
		return nil, fmt.Errorf("adminui: look up administrator token: %w", err)
	}

	ok, err := parsed.Verify(tok.VerifierHash)
	if err != nil {
		// A malformed stored hash is an operational fault, not an attack, and it
		// must not be mistaken for a failed attempt.
		return nil, fmt.Errorf("adminui: verify administrator token: %w", err)
	}
	if !ok {
		return nil, errors.New("the token is not recognised")
	}
	if !tok.Usable(now) {
		return nil, errors.New("the token is expired, withdrawn or carries an unknown role")
	}
	return tok, nil
}

// signInDims builds the rate-limiting dimensions for a sign-in attempt.
//
// Only the source address is available: the attempt has not established an
// identity yet, which is the point of limiting it.
func (h *Handler) signInDims(ip string) map[throttle.Dimension]string {
	if ip == "" {
		return nil
	}
	return map[throttle.Dimension]string{throttle.DimIP: ip}
}

// signInBlocked reports whether the source address is currently locked out.
func (h *Handler) signInBlocked(r *http.Request, dims map[throttle.Dimension]string) (bool, time.Duration) {
	if h.deps.Limiter == nil || len(dims) == 0 {
		return false, 0
	}
	res, err := h.deps.Limiter.Check(r.Context(), h.tenantID(), dims)
	if err != nil {
		// A limiter that cannot read its own state must not refuse the sign-in:
		// that would turn a database hiccup into an administrative lockout. The
		// failure is logged so it is visible.
		h.deps.Logger.WarnContext(r.Context(), "adminui: sign-in limit state unavailable",
			slog.Any("error", err))
		return false, 0
	}
	if res.Allowed {
		return false, 0
	}
	return true, res.RetryAfter
}

// recordSignInAttempt counts the attempt against the source address.
func (h *Handler) recordSignInAttempt(r *http.Request, dims map[throttle.Dimension]string, failure bool) {
	if h.deps.Limiter == nil || len(dims) == 0 {
		return
	}
	if _, err := h.deps.Limiter.Record(r.Context(), h.tenantID(), dims, failure); err != nil {
		h.deps.Logger.WarnContext(r.Context(), "adminui: sign-in attempt not counted",
			slog.Any("error", err))
	}
}

// auditSignInFailure records a refused sign-in.
//
// Failures on the credential path are audited because a run of them is the
// earliest visible sign of a leaked token being probed, and the audit log is
// where an operator looks for it afterwards. The tenant is unknown at this point
// by definition, since the credential that would have named it is the one that
// did not verify, so the reserved system tenant carries the entry.
func (h *Handler) auditSignInFailure(w http.ResponseWriter, r *http.Request, ip, reason string) {
	h.audited(w, r, audit.Event{
		TenantID:  store.SystemTenantID,
		EventType: audit.EventAdminAuthFailed,
		ActorType: store.ActorSystem,
		Outcome:   store.OutcomeDenied,
		SourceIP:  ip,
		Detail: map[string]any{
			"reason":  reason,
			"surface": "administration interface",
		},
	})
}

// minutesAtLeastOne renders a retry delay as whole minutes, never zero, so the
// advice on the page is actionable.
func minutesAtLeastOne(d time.Duration) int {
	m := int(d.Minutes())
	if m < 1 {
		return 1
	}
	return m
}

// sourceIP resolves the client address.
//
// This duplicates what the API middleware already does, because reading the
// value that middleware stores would mean importing internal/api, and that
// package holds this one as a dependency. The rule it implements is the one that
// matters: a forwarded header is honoured only when the immediate peer is inside
// a declared proxy network. Trusting X-Forwarded-For from any source would let a
// caller choose the address their sign-in attempts are counted against, which
// turns the rate limit off entirely and writes whatever they please into the
// audit trail.
func (h *Handler) sourceIP(r *http.Request) string {
	peer := peerIP(r.RemoteAddr)
	cfg := h.deps.Config.Server

	if !cfg.TrustProxy || peer == nil {
		if peer == nil {
			return ""
		}
		return peer.String()
	}

	trusted := parseCIDRs(cfg.TrustedProxyCIDRs)
	if !ipInAny(peer, trusted) {
		return peer.String()
	}

	// The header is a list appended to by each hop, so the rightmost entries
	// were added by infrastructure the operator controls. Walking from the right
	// and stopping at the first address outside the trusted set yields the
	// closest hop the operator does not control, which is the real client.
	var chain []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				chain = append(chain, p)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.Trim(chain[i], "[]"))
		if ip == nil {
			// A malformed entry means the chain cannot be trusted any further,
			// so fall back to the peer rather than guessing.
			break
		}
		if !ipInAny(ip, trusted) {
			return ip.String()
		}
	}
	return peer.String()
}

func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
