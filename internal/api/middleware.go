package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/logging"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first argument is the outermost wrapper.
//
// Order matters and is not cosmetic. Recovery has to be outside logging so a
// panic is still logged with its request identifier, and the identifier has to
// be assigned outside both so everything that follows can reference it.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestIDHeader is the header read and echoed.
const RequestIDHeader = "X-Request-Id"

// RequestID assigns an identifier to every request.
//
// A client-supplied value is accepted so a trace can span the integrating
// application and this service, but it is bounded and filtered first: the
// identifier reaches log lines and audit entries, where an unfiltered value
// containing a newline could forge an entry and one containing a terminal
// escape could rewrite what an operator reading the log sees.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := sanitiseRequestID(r.Header.Get(RequestIDHeader))
			if id == "" {
				id = newRequestID()
			}

			ctx := withRequestID(r.Context(), id)
			w.Header().Set(RequestIDHeader, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

const maxRequestIDLen = 64

// sanitiseRequestID keeps only characters that are safe in a log field, and
// returns the empty string if nothing usable is left.
func sanitiseRequestID(v string) string {
	if v == "" || len(v) > maxRequestIDLen {
		return ""
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			return ""
		}
	}
	return b.String()
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A request without an identifier is worse than one with a
		// time-derived identifier, so fall back rather than fail the request.
		return "t" + hex.EncodeToString([]byte(time.Now().UTC().Format("150405.000000")))
	}
	return hex.EncodeToString(b[:])
}

// Recover turns a panic into a 500 instead of dropping the connection.
//
// A panic on one request must not take the process down: this is an
// authentication service, and every other user's ability to log in should not
// depend on one malformed input. The stack trace is logged and never sent.
func Recover() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				// A client that disconnects mid-write makes net/http panic
				// with this sentinel. It is not a fault, and there is nobody
				// left to answer.
				if rec == http.ErrAbortHandler {
					panic(rec)
				}

				logging.FromContext(r.Context()).ErrorContext(r.Context(),
					"handler panicked",
					slog.Any("panic", rec),
					slog.String("stack", string(debug.Stack())),
					slog.String(logging.KeyMethod, r.Method),
					slog.String(logging.KeyRoute, r.URL.Path),
				)

				WriteProblem(w, r, Internal(errors.New("handler panicked")))
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder captures the status code and the bytes written, which the
// standard ResponseWriter does not expose.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.written += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer, which is
// what keeps flushing and deadline control working through this wrapper.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// RequestLog logs one line per request and attaches a request-scoped logger.
//
// The route is deliberately not among the attributes set here. This middleware
// wraps the multiplexer from outside, and the multiplexer is what fills in
// Request.Pattern, as it dispatches. At this point there is only the concrete
// path, and the concrete path is what carries a subject reference on the
// ceremony routes. RouteLabel adds the field once routing has happened; the
// summary line below reads the pattern after the handler has returned, by which
// time it is set on the request the multiplexer was given.
func RequestLog(root *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			log := root.With(
				slog.String(logging.KeyRequestID, RequestIDFrom(r.Context())),
				slog.String(logging.KeyMethod, r.Method),
			)
			if ip := SourceIPFrom(r.Context()); ip != "" {
				log = log.With(slog.String(logging.KeySourceIP, ip))
			}

			ctx := logging.WithLogger(r.Context(), log)
			rec := &statusRecorder{ResponseWriter: w}

			routed := r.WithContext(ctx)
			next.ServeHTTP(rec, routed)

			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			log.InfoContext(ctx, "request",
				slog.String(logging.KeyRoute, routePattern(routed)),
				slog.Int(logging.KeyStatus, rec.status),
				slog.Int64(logging.KeyDurationMS, time.Since(start).Milliseconds()),
				slog.Int64("bytes", rec.written),
			)
		})
	}
}

// RequestObserver records one served request. internal/metrics implements it.
//
// It is an interface rather than the concrete registry so that this package
// does not depend on the shape of the exposition format, and so that a
// deployment with no registry passes nil and pays for nothing.
type RequestObserver interface {
	ObserveRequest(route, method string, status int, d time.Duration)
}

// RequestMetrics records every served request.
//
// It sits beside RequestLog rather than inside it. The two want the same three
// values and have different reasons to exist, and a log line that stopped being
// written because a metric changed shape would be the wrong kind of coupling on
// the one path that has to keep working.
//
// The route it reports is the matched pattern, read after the handler has
// returned for the reason RequestLog explains. Reporting the concrete path here
// would be worse than in the log: a Prometheus series lives as long as the
// process, so a label taken from a request is unbounded memory with a caller
// holding the pen, and on the ceremony routes it would be a list of users.
func RequestMetrics(obs RequestObserver) Middleware {
	return func(next http.Handler) http.Handler {
		if obs == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			routed := r.WithContext(r.Context())
			next.ServeHTTP(rec, routed)

			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			obs.ObserveRequest(routePattern(routed), r.Method, rec.status, time.Since(start))
		})
	}
}

// RouteLabel adds the matched route to the request-scoped logger.
//
// It is mounted inside the multiplexer, on every route, because that is the
// first moment the route is known. Putting it in the outer chain is what
// produced the defect it exists to fix: the field held the path a caller asked
// for, which on the ceremony routes is the subject reference, so redaction
// covered subject_ref and an address travelled in the field next to it.
//
// It is a middleware rather than something wrap does, so that the lines written
// by authentication and authorisation carry the route as well. Those are the
// lines an operator reads when a request was refused, and "refused which
// route" is the first question.
func RouteLabel() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := logging.FromContext(r.Context()).With(
				slog.String(logging.KeyRoute, routePattern(r)),
			)
			next.ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), log)))
		})
	}
}

// routePattern returns the matched route rather than the concrete path.
//
// Logging the pattern keeps a subject reference out of the log field, and makes
// the lines aggregatable: a thousand requests to one route produce one label
// instead of a thousand.
func routePattern(r *http.Request) string {
	if p := r.Pattern; p != "" {
		return p
	}
	return r.URL.Path
}

// SecurityHeaders sets the response headers that constrain a browser.
//
// Most of these matter only for the administrative interface, since the /v1
// routes are called server to server. They are applied everywhere because a
// header that is set unconditionally cannot be forgotten on the one route where
// it was needed.
func SecurityHeaders(hstsMaxAgeSeconds int) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// No inline script, no framing, no plugin content. The admin
			// interface is server-rendered with its scripts served from the
			// same origin, so it needs nothing looser.
			h.Set("Content-Security-Policy",
				"default-src 'none'; script-src 'self'; style-src 'self'; "+
					"img-src 'self' data:; connect-src 'self'; form-action 'self'; "+
					"frame-ancestors 'none'; base-uri 'none'")

			// Stops a browser from second-guessing a declared content type,
			// which is how a JSON response gets executed as script.
			h.Set("X-Content-Type-Options", "nosniff")

			// Redundant with frame-ancestors above for current browsers, kept
			// for the ones that only implement this.
			h.Set("X-Frame-Options", "DENY")

			// A referrer would carry the path, which on some routes contains a
			// subject reference.
			h.Set("Referrer-Policy", "no-referrer")

			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")

			// Responses carry authentication state, so no shared cache should
			// keep them.
			h.Set("Cache-Control", "no-store")

			// HSTS is only meaningful, and only safe, over TLS. Sending it on
			// a plain HTTP response is ignored by browsers, and sending it
			// from a development deployment on localhost would pin a
			// developer's browser to HTTPS for that host.
			if hstsMaxAgeSeconds > 0 && isTLS(r) {
				h.Set("Strict-Transport-Security",
					"max-age="+itoa(hstsMaxAgeSeconds)+"; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Set by the reverse proxy. It is only consulted when the request already
	// came from a trusted proxy, which SourceIP establishes before this runs.
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// BodyLimit caps the request body.
//
// http.MaxBytesReader is used rather than a length check, because a client can
// send a body without a Content-Length or lie about it. The reader enforces the
// limit as the body is consumed, so an oversized body is refused without ever
// being buffered.
func BodyLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireJSON refuses a request whose body is not JSON.
//
// A request that arrives as form-encoded would otherwise be parsed as an empty
// JSON object and silently treated as a request with no fields. Refusing it
// also removes the simple-request form that bypasses a CORS preflight, so a
// cross-origin caller cannot reach a state-changing route without the browser
// asking first.
func RequireJSON() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			ct := r.Header.Get("Content-Type")
			if ct == "" {
				WriteProblem(w, r, &APIError{
					Status: http.StatusUnsupportedMediaType, Type: TypeUnsupportedMedia,
					Title:  "a JSON request body is required",
					Detail: "set Content-Type to application/json",
				})
				return
			}
			media := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
			if !strings.EqualFold(media, "application/json") {
				WriteProblem(w, r, &APIError{
					Status: http.StatusUnsupportedMediaType, Type: TypeUnsupportedMedia,
					Title:  "a JSON request body is required",
					Detail: "Content-Type " + media + " is not accepted",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS answers preflight requests against an explicit allow list.
//
// The list is never a wildcard. These endpoints are credentialed, and the fetch
// specification forbids combining a wildcard origin with credentials precisely
// because it would let any site read the response.
func CORS(allowedOrigins []string) Middleware {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.ToLower(strings.TrimRight(o, "/"))] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Not a cross-origin request. Server-to-server callers send no
				// Origin, and they are the expected users of /v1.
				next.ServeHTTP(w, r)
				return
			}

			_, ok := allowed[strings.ToLower(strings.TrimRight(origin, "/"))]
			if !ok {
				// The request is not rejected here. Omitting the headers is
				// what makes the browser refuse to expose the response, and
				// returning an error instead would leak which origins are
				// configured.
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			// The response varies by Origin, so a cache must not serve one
			// origin's response to another.
			h.Add("Vary", "Origin")

			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers",
					"Authorization, Content-Type, "+RequestIDHeader)
				h.Set("Access-Control-Max-Age", "600")
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			h.Set("Access-Control-Expose-Headers", RequestIDHeader+", Retry-After")
			next.ServeHTTP(w, r)
		})
	}
}

// SourceIP resolves the client address once and attaches it.
//
// A forwarded header is honoured only when the immediate peer is inside one of
// the configured proxy networks. Trusting X-Forwarded-For from any source lets
// a caller choose the address that rate limiting and audit entries are keyed
// on, which turns both controls off: an attacker sends a fresh address with
// every attempt and is never throttled, and the audit trail records whatever
// they wrote.
func SourceIP(trustProxy bool, trustedCIDRs []string) Middleware {
	nets := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, c := range trustedCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveSourceIP(r, trustProxy, nets)
			next.ServeHTTP(w, r.WithContext(withSourceIP(r.Context(), ip)))
		})
	}
}

func resolveSourceIP(r *http.Request, trustProxy bool, trusted []*net.IPNet) string {
	peer := peerIP(r.RemoteAddr)
	if !trustProxy || peer == nil || !ipInAny(peer, trusted) {
		if peer == nil {
			return ""
		}
		return peer.String()
	}

	// X-Forwarded-For is a list appended to by each hop, so the rightmost
	// entries are the ones added by infrastructure under the operator's
	// control. Walking from the right and stopping at the first address
	// outside the trusted set yields the closest hop the operator does not
	// control, which is the real client.
	forwarded := r.Header.Values("X-Forwarded-For")
	var chain []string
	for _, v := range forwarded {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				chain = append(chain, p)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.Trim(chain[i], "[]"))
		if ip == nil {
			// A malformed entry means the chain cannot be trusted any
			// further, so fall back to the peer rather than guessing.
			break
		}
		if !ipInAny(ip, trusted) {
			return ip.String()
		}
	}

	if peer == nil {
		return ""
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

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IPAllowList restricts a route group to named networks.
//
// This guards the administrative surface. It is a network control rather than
// an authentication one, so it runs before authentication: a caller outside the
// allow list should not even be able to present a token for verification, which
// keeps the token-guessing surface off the public internet entirely.
func IPAllowList(cidrs []string) Middleware {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}

	return func(next http.Handler) http.Handler {
		if len(nets) == 0 {
			// No list configured means no restriction. The configuration
			// validator is what refuses that combination on a non-loopback
			// listener, so this does not have to second-guess it.
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := net.ParseIP(SourceIPFrom(r.Context()))
			if ip == nil || !ipInAny(ip, nets) {
				// A 404 rather than a 403: a caller outside the allow list
				// should not learn that an administrative surface exists here.
				WriteProblem(w, r, NotFound(errors.New("source address is not in the admin allow list")))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore is applied to the routes that must never be cached even by a
// misconfigured intermediary.
func NoStore() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			next.ServeHTTP(w, r)
		})
	}
}
