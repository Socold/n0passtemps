package n0passtemps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Version is the version of this SDK, reported in the default user agent.
const Version = "1.1.2"

// DefaultTimeout bounds one HTTP attempt when no other timeout is configured.
const DefaultTimeout = 10 * time.Second

// maxResponseBytes caps how much of a response body is read. Every /v1 body is
// a few kilobytes at most, so the cap only matters when something other than
// the server answers, and then it stops a misbehaving peer from exhausting
// memory.
const maxResponseBytes = 1 << 20

// retryBaseDelay is the first backoff delay. It doubles on each attempt.
const retryBaseDelay = 200 * time.Millisecond

// retryMaxDelay caps the backoff delay.
const retryMaxDelay = 5 * time.Second

// ErrResponseTooLarge reports a response body above the 1 MiB limit.
var ErrResponseTooLarge = errors.New("n0passtemps: response body exceeds the size limit")

// Client calls the /v1 routes of one n0passtemps deployment with one API key.
//
// A Client is safe for concurrent use and holds no state beyond its
// configuration.
type Client struct {
	baseURL   string
	apiKey    string
	http      *http.Client
	timeout   time.Duration
	userAgent string
	retries   int

	// retryDelay is overridden in tests so the backoff does not slow them.
	retryDelay time.Duration
}

// Option configures a Client.
type Option func(*options)

type options struct {
	httpClient    *http.Client
	httpClientSet bool
	timeout       time.Duration
	userAgent     string
	insecure      bool
	retries       int
}

// WithHTTPClient makes the Client send its requests through hc.
//
// The default client refuses to follow redirects, because the API never
// redirects and a redirect is a way to walk a bearer credential to another
// origin. A caller who supplies a client takes over that decision.
func WithHTTPClient(hc *http.Client) Option {
	return func(o *options) {
		o.httpClient = hc
		o.httpClientSet = true
	}
}

// WithTimeout bounds each HTTP attempt. The default is DefaultTimeout.
//
// The bound is applied through the request context rather than by altering
// the http.Client, so a client shared with other code is left untouched. Zero
// disables it and leaves the caller's context as the only limit.
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithUserAgent replaces the default User-Agent header.
func WithUserAgent(ua string) Option {
	return func(o *options) { o.userAgent = ua }
}

// WithInsecureTransport permits a plain http base URL on a host that is not
// loopback.
//
// It exists for a deployment where TLS is terminated by a trusted proxy on a
// private network segment. It is a named option, and not a flag read from the
// URL, so that sending the API key in clear text is a decision visible in code
// review.
func WithInsecureTransport() Option {
	return func(o *options) { o.insecure = true }
}

// WithRetries lets the Client retry an idempotent call up to n more times.
//
// Retrying is off by default. When enabled it covers only the calls that the
// contract declares idempotent (GetSubject, ResolveSubject, Health and
// HealthDetail), and only a transport failure or a 502, 503 or 504 answer.
//
// Nothing else is ever retried. A ceremony completion, a TOTP code and a
// recovery code are single use on the server, so a second attempt can only
// fail and would count against the subject's throttle. An authentication
// failure is an answer, not a fault, and a 429 is the server asking for
// patience: both go back to the caller.
func WithRetries(n int) Option {
	return func(o *options) { o.retries = n }
}

// New returns a Client for the deployment at baseURL, authenticating with
// apiKey.
//
// The base URL must use https. The API key is a bearer credential: anyone who
// reads it off the wire can run ceremonies against every subject of the
// tenant, and nothing in the request binds it to the connection it travelled
// on. Plain http is therefore accepted only for a loopback host, where the
// traffic never leaves the machine, or when the caller passes
// WithInsecureTransport.
func New(baseURL, apiKey string, opts ...Option) (*Client, error) {
	o := options{timeout: DefaultTimeout, userAgent: "n0passtemps-go/" + Version}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("n0passtemps: new client: the API key is empty")
	}
	if o.httpClientSet && o.httpClient == nil {
		return nil, errors.New("n0passtemps: new client: the HTTP client is nil")
	}
	if o.timeout < 0 {
		return nil, fmt.Errorf("n0passtemps: new client: timeout %s is negative", o.timeout)
	}
	if o.retries < 0 {
		return nil, fmt.Errorf("n0passtemps: new client: retry count %d is negative", o.retries)
	}

	base, err := checkEndpoint(baseURL, o.insecure)
	if err != nil {
		return nil, fmt.Errorf("n0passtemps: new client: %w", err)
	}

	hc := o.httpClient
	if hc == nil {
		hc = newHTTPClient()
	}

	return &Client{
		baseURL:    strings.TrimRight(base.String(), "/"),
		apiKey:     apiKey,
		http:       hc,
		timeout:    o.timeout,
		userAgent:  o.userAgent,
		retries:    o.retries,
		retryDelay: retryBaseDelay,
	}, nil
}

// newHTTPClient returns the client used when the caller supplies none.
func newHTTPClient() *http.Client {
	return &http.Client{
		// The API does not redirect. Following one would resend the request,
		// and on a same-host downgrade the Authorization header with it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkEndpoint parses raw and applies the transport rule shared by the API
// client and the remote key source.
func checkEndpoint(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// url.Parse echoes its input, which may carry credentials.
		return nil, errors.New("the URL cannot be parsed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("the URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("the URL must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("the URL must not carry a query or a fragment")
	}

	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure && !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("plain http to %q is refused: use https, or opt in to clear-text transport explicitly", u.Hostname())
		}
	default:
		return nil, fmt.Errorf("scheme %q is not supported", u.Scheme)
	}
	return u, nil
}

// isLoopback reports whether host names the local machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// EndUserIPHeader is the header the end user's address is declared in.
const EndUserIPHeader = "X-End-User-IP"

// endUserIPKey is the context key WithEndUserIP stores the address under.
type endUserIPKey struct{}

// WithEndUserIP declares the address of the end user a call is made for.
//
// The server sees every call arrive from the address of the application's
// backend, which says nothing about who is signing in, so its per-address rate
// limit and its network risk signal work from the address declared here. Pass
// the address the application itself observed for the user's browser, on every
// ceremony call. Without it the server applies no per-address limit to the
// call, and the limits per subject and per key still hold.
//
// The address travels in the context because it is a property of the incoming
// request an application is serving, like the deadline, and an application
// typically sets it once in the middleware that knows the client address:
//
//	ctx = n0passtemps.WithEndUserIP(ctx, clientIP)
//	result, err := client.VerifyTOTP(ctx, subjectRef, code)
//
// ip is an IPv4 or IPv6 address. A host:port pair, which is what
// http.Request.RemoteAddr holds, is accepted and the port dropped. An empty
// string declares nothing. Anything else makes the call fail before a request
// is sent, since the server would refuse it with a 400 anyway.
func WithEndUserIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, endUserIPKey{}, ip)
}

// endUserIP returns the declared address in the form the server accepts, or
// the empty string when none was declared.
func endUserIP(ctx context.Context) (string, error) {
	raw, _ := ctx.Value(endUserIPKey{}).(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		var hostPort netip.AddrPort
		if hostPort, err = netip.ParseAddrPort(raw); err == nil {
			addr = hostPort.Addr()
		}
	}
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		// The value is not quoted. It came from the application's own request
		// handling and may be the one thing about the user it does not log.
		return "", errors.New("the end user address given to WithEndUserIP is not an IP address")
	}
	return addr.Unmap().String(), nil
}

// call describes one request.
type call struct {
	method string

	// route is the path pattern, with placeholders. It is what error messages
	// quote, so that a subject reference never reaches the caller's logs
	// through this package.
	route string

	// path is the concrete, already escaped path.
	path string

	// body is marshalled as JSON when not nil.
	body any

	// out receives the decoded 2xx body when not nil.
	out any

	// anonymous leaves the API key out. The liveness probe needs no
	// credential, so it is not sent one.
	anonymous bool

	// idempotent marks a call that WithRetries may repeat.
	idempotent bool
}

// do performs a call, with retries when they are enabled and permitted.
func (c *Client) do(ctx context.Context, cl call) error {
	var payload []byte
	if cl.body != nil {
		var err error
		payload, err = json.Marshal(cl.body)
		if err != nil {
			return fmt.Errorf("n0passtemps: %s %s: encode request: %w", cl.method, cl.route, err)
		}
	}

	attempts := 1
	if cl.idempotent {
		attempts += c.retries
	}

	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if werr := wait(ctx, backoff(c.retryDelay, attempt)); werr != nil {
				return fmt.Errorf("n0passtemps: %s %s: %w", cl.method, cl.route, werr)
			}
		}
		err = c.attempt(ctx, cl, payload)
		if err == nil || !retryable(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

// backoff doubles base for each attempt after the first retry, up to
// retryMaxDelay. The cap also keeps a large retry count from overflowing the
// shift into a negative, and therefore immediate, delay.
func backoff(base time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt && d < retryMaxDelay; i++ {
		d *= 2
	}
	if d > retryMaxDelay {
		d = retryMaxDelay
	}
	return d
}

// retryable reports whether err is a fault worth a second attempt.
func retryable(err error) bool {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	var transport *transportError
	return errors.As(err, &transport)
}

// transportError marks a failure to exchange a request and a response at all.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// wait sleeps for d or until ctx ends.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// attempt performs one HTTP exchange.
func (c *Client) attempt(ctx context.Context, cl call, payload []byte) error {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, c.baseURL+cl.path, body)
	if err != nil {
		return fmt.Errorf("n0passtemps: %s %s: build request: %w", cl.method, cl.route, stripURL(err))
	}

	// The server refuses any write whose media type is not JSON, including a
	// POST that takes no body, so that a form-encoded request is never read as
	// an object with no fields. Setting the header on every request keeps the
	// rule in one place.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, application/problem+json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if !cl.anonymous {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		// Only next to the key. The header means something because an
		// authenticated caller states it, and the anonymous probe has no use
		// for it.
		endUser, addrErr := endUserIP(ctx)
		if addrErr != nil {
			return fmt.Errorf("n0passtemps: %s %s: %w", cl.method, cl.route, addrErr)
		}
		if endUser != "" {
			req.Header.Set(EndUserIPHeader, endUser)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("n0passtemps: %s %s: %w", cl.method, cl.route, &transportError{stripURL(err)})
	}
	defer resp.Body.Close()

	// One byte past the limit is enough to tell a body at the limit from one
	// above it, without reading the remainder.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("n0passtemps: %s %s: read response: %w", cl.method, cl.route, &transportError{err})
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("n0passtemps: %s %s: %w", cl.method, cl.route, ErrResponseTooLarge)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return newError(resp, raw)
	}
	if cl.out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, cl.out); err != nil {
		return fmt.Errorf("n0passtemps: %s %s: decode response: %w", cl.method, cl.route, err)
	}
	return nil
}

// stripURL removes the request URL from an error of net/http.
//
// The URL carries the subject reference in its path. The server goes to some
// length to keep that value out of logs, and an error string is the most
// likely thing an application logs.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// subjectPath builds "/v1/<family>/<escaped reference><suffix>".
func subjectPath(family, subjectRef, suffix string) (string, error) {
	switch subjectRef {
	case "":
		return "", errors.New("n0passtemps: the subject reference is empty")
	case ".", "..":
		// url.PathEscape leaves dots alone, and the server's router resolves
		// dot segments before matching, so these two values would address a
		// different route. No escaping can express them as one path segment.
		return "", errors.New("n0passtemps: the subject reference cannot be a dot segment")
	}
	return "/v1/" + family + "/" + url.PathEscape(subjectRef) + suffix, nil
}
