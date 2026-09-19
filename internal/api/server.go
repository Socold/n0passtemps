package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/health"
	"github.com/Socold/n0passtemps/internal/metrics"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// Deps are the collaborators a Server needs.
//
// They are passed in rather than constructed here so that main owns the
// lifecycle of everything that has to be closed, and so a test can substitute
// any one of them.
type Deps struct {
	Config    *config.Config
	Store     store.Store
	Subjects  *subject.Service
	WebAuthn  *webauthn.Service
	Sealer    *envelope.Sealer
	Assertion *assertion.Issuer
	Recorder  *audit.Recorder
	Alerts    *alerts.Engine
	Limiter   *throttle.Limiter
	Health    *health.Checker
	Logger    *slog.Logger

	// Metrics is the Prometheus registry. A nil registry is the normal case in
	// a test and costs nothing at runtime: the middleware is not mounted and
	// the route answers that metrics are not configured.
	Metrics *metrics.Registry

	// Clock is injected so that tests are deterministic. Nothing in the
	// request path calls time.Now directly.
	Clock func() time.Time

	// AdminUI is mounted at /admin when the interface is enabled. It is an
	// http.Handler rather than a concrete type so that this package does not
	// depend on the template rendering.
	AdminUI http.Handler
}

// Server holds the dependencies and builds the routes.
type Server struct {
	deps Deps
	auth *Authenticator
	now  func() time.Time
}

// NewServer builds a Server.
func NewServer(d Deps) *Server {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &Server{
		deps: d,
		auth: NewAuthenticator(d.Store, d.Recorder, d.Alerts, d.Clock),
		now:  d.Clock,
	}
}

// tenantID returns the tenant every row is written under.
//
// v1 serves one tenant, named in configuration. Reading it from the caller's
// credential instead would be the multi-tenant behaviour, and is what the
// credential's TenantID field is there for; until then the two must agree,
// which callerTenant enforces.
func (s *Server) tenantID() string { return s.deps.Config.TenantID() }

// callerTenant returns the tenant of the authenticated caller, refusing a
// credential issued for a different one.
//
// In a single-tenant deployment the two always agree. The check exists so that
// a database carried over from another deployment, or a credential minted
// before tenant.id was changed, fails loudly instead of operating on rows it
// does not own.
func (s *Server) callerTenant(c *Caller) (string, error) {
	want := s.tenantID()
	if c.TenantID != want {
		return "", Forbidden(&tenantMismatchError{credential: c.TenantID, configured: want})
	}
	return want, nil
}

type tenantMismatchError struct {
	credential string
	configured string
}

func (e *tenantMismatchError) Error() string {
	return "credential belongs to tenant " + e.credential +
		" but this deployment serves " + e.configured
}

// EndUserIPHeader is the request header in which an integrating application
// declares the address of the end user it is calling on behalf of.
//
// /v1 is called from server to server, so the peer address of a request is that
// of the application's backend and says nothing about who is trying to sign in.
// Limiting on it put every user of the application in one bucket, which any
// anonymous visitor of its sign-in page could fill. The application is the only
// party that sees the end user's address, so it is the one that has to say it.
//
// The value is declared by the caller, not observed, and is treated that way:
// it selects a rate-limit bucket and feeds the network risk signal, and it is
// audited next to the observed peer address, never in place of it.
const EndUserIPHeader = "X-End-User-IP"

// auditKeyEndUserIP is the audit detail key the declared address is kept under.
// source_ip stays the peer address: one is an observation, the other a claim by
// an authenticated caller, and a reader of the log has to be able to tell.
const auditKeyEndUserIP = "end_user_ip"

// endUserIP reads the address the caller declared, if it declared one.
//
// A value that is not one IP address is refused rather than ignored. Ignoring
// it would drop the network limit for that request without anybody noticing,
// and an integration that sends "unknown", or a host and port, would run
// without the limit for good.
func endUserIP(r *http.Request) (addr netip.Addr, declared bool, err error) {
	values := r.Header.Values(EndUserIPHeader)
	if len(values) == 0 {
		return netip.Addr{}, false, nil
	}
	if len(values) > 1 {
		return netip.Addr{}, false, BadRequest("the "+EndUserIPHeader+" header must be sent once", nil)
	}
	addr, err = netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return netip.Addr{}, false, BadRequest("the "+EndUserIPHeader+" header must carry one IPv4 or IPv6 "+
			"address, with no port, no zone and no prefix length; omit the header when the address is not known",
			err)
	}
	return addr.Unmap(), true, nil
}

// throttleScope is what one ceremony is limited on: the factor whose
// per-subject budget it draws from, and the dimensions.
type throttleScope struct {
	factor throttle.Factor
	dims   map[throttle.Dimension]string
}

// limiter returns the limiter view for the scope's factor, or nil when there
// is nothing to limit.
func (s *Server) limiter(scope throttleScope) *throttle.Limiter {
	if s.deps.Limiter == nil || len(scope.dims) == 0 {
		return nil
	}
	return s.deps.Limiter.ForFactor(scope.factor)
}

// ceremonyThrottleScope builds the rate-limiting scope for a ceremony route.
//
// The subject and the end user's network are limited together. Limiting on
// either alone is wrong: per subject alone lets an attacker spread one guess
// across many accounts, and per address alone punishes everyone behind one NAT
// gateway. The third dimension, volume per API key, is metered for every
// request by the MeterAPIKey middleware rather than here, so that routes which
// record no authentication outcome are counted too.
//
// The network is the one the caller declared in EndUserIPHeader. When it
// declared none, the dimension is left out rather than filled with the peer
// address, because the peer is the application's backend and its address
// identifies nobody; the per-subject and per-key limits still apply. The
// administration console and the authentication of API keys keep limiting on
// the peer address, which for them is the right one.
//
// The per-subject budget is that of one factor. See throttle.Factor.
func (s *Server) ceremonyThrottleScope(r *http.Request, factor throttle.Factor, subjectID string) (throttleScope,
	error) {
	scope := throttleScope{factor: factor, dims: make(map[throttle.Dimension]string, 2)}
	addr, declared, err := endUserIP(r)
	if err != nil {
		return throttleScope{}, err
	}
	if declared {
		scope.dims[throttle.DimIP] = throttle.NormaliseIP(addr.String())
	}
	if subjectID != "" {
		scope.dims[throttle.DimSubject] = subjectID
	}
	return scope, nil
}

// checkThrottle refuses a request that is currently locked out on dimensions
// that involve no subject, which is what the administrative routes limit on.
func (s *Server) checkThrottle(r *http.Request, tenantID string, dims map[throttle.Dimension]string) error {
	return s.checkCeremonyThrottle(r, tenantID, throttleScope{dims: dims})
}

// checkCeremonyThrottle refuses a request that is currently locked out.
//
// It is consulted before any expensive work, so a locked-out caller does not
// get an Argon2id evaluation or a signature verification out of the service.
//
// It guards the routes where nothing is guessed: starting a ceremony, and
// completing a WebAuthn one, where a challenge is single use and a signature
// cannot be tried twice. A route that compares a secret uses reserveAttempt.
func (s *Server) checkCeremonyThrottle(r *http.Request, tenantID string, scope throttleScope) error {
	limiter := s.limiter(scope)
	if limiter == nil {
		return nil
	}
	res, err := limiter.Check(r.Context(), tenantID, scope.dims)
	if err != nil {
		// A limiter that cannot read its own state must not fail the request:
		// that would turn a database hiccup into an outage. The failure is
		// logged so it is visible.
		s.deps.Logger.WarnContext(r.Context(), "throttle state unavailable",
			slog.Any("error", err))
		return nil
	}
	if !res.Allowed {
		return Throttled(int(res.RetryAfter.Seconds()), &throttledError{dim: string(res.Dimension)})
	}
	return nil
}

type throttledError struct{ dim string }

func (e *throttledError) Error() string { return "rate limit reached on dimension " + e.dim }

// reserveAttempt refuses a request that is locked out or over its budget, and
// otherwise counts the attempt before the secret it carries is compared.
//
// It replaces checkCeremonyThrottle on the routes that compare a guessable secret. With
// the count taken after the comparison, a parallel burst got every one of its
// requests evaluated before the first failure was written; see
// throttle.Limiter.Reserve. The reservation is handed to settleAttempt once the
// outcome is known.
//
// An attempt that ends in neither, because the request failed on a fault of the
// service after this point, stays counted as a failure. The store cannot take
// one failure back, and a user left with nine attempts by a database error is
// the smaller harm next to a budget that does not hold.
//
// A nil reservation with a nil error means the limiter is off or could not be
// reached. settleAttempt then records the outcome the way recordAttempt does.
func (s *Server) reserveAttempt(r *http.Request, tenantID string, scope throttleScope) (*throttle.Reservation,
	error) {
	limiter := s.limiter(scope)
	if limiter == nil {
		return nil, nil
	}
	held, res, err := limiter.Reserve(r.Context(), tenantID, scope.dims)
	if err != nil {
		// Fails open, for the reason checkCeremonyThrottle gives.
		s.deps.Logger.WarnContext(r.Context(), "throttle state unavailable",
			slog.Any("error", err))
		return nil, nil
	}
	if !res.Allowed {
		return nil, Throttled(int(res.RetryAfter.Seconds()), &throttledError{dim: string(res.Dimension)})
	}
	return held, nil
}

// settleAttempt reports the outcome of an attempt reserveAttempt let through.
func (s *Server) settleAttempt(r *http.Request, tenantID, subjectID string, scope throttleScope,
	held *throttle.Reservation, failure bool) throttle.Result {
	if held == nil {
		return s.recordAttempt(r, tenantID, subjectID, scope, failure)
	}
	ctx := r.Context()

	var (
		res throttle.Result
		err error
	)
	if failure {
		res, err = held.Fail(ctx)
	} else {
		res, err = held.Succeed(ctx)
	}
	if err != nil {
		s.deps.Logger.WarnContext(ctx, "attempt not recorded against throttle",
			slog.Any("error", err))
		return throttle.Result{Allowed: true}
	}
	if failure {
		s.reportLockout(r, tenantID, subjectID, scope, res)
	}
	return res
}

// recordAttempt registers the outcome of an authentication attempt and raises
// an alert when a limit trips.
//
// The limiter's result is returned so that risk reporting can read the failure
// counters this call already fetched, rather than querying for them again on
// the authentication path. Callers with no use for it ignore it, which is why
// it is a return value and not an out parameter.
func (s *Server) recordAttempt(r *http.Request, tenantID, subjectID string, scope throttleScope,
	failure bool) throttle.Result {
	limiter := s.limiter(scope)
	if limiter == nil {
		return throttle.Result{Allowed: true}
	}
	ctx := r.Context()

	res, err := limiter.Record(ctx, tenantID, scope.dims, failure)
	if err != nil {
		s.deps.Logger.WarnContext(ctx, "attempt not recorded against throttle",
			slog.Any("error", err))
		return throttle.Result{Allowed: true}
	}
	if failure {
		// Only a failure trips a lockout, so only a failure reports one. A
		// success recorded against a network somebody else got blocked would
		// otherwise be alerted on as though it had caused the block.
		s.reportLockout(r, tenantID, subjectID, scope, res)
	}
	return res
}

// reportLockout alerts on and audits a limit that an attempt has just tripped.
func (s *Server) reportLockout(r *http.Request, tenantID, subjectID string, scope throttleScope,
	res throttle.Result) {
	// An advisory crossing is reported although the attempt was allowed. It is
	// the one case where a budget is used up and nothing is refused, and the
	// operator has more reason to hear about it than about an ordinary
	// lockout, not less: see throttle.Limiter.locksOut.
	if (res.Allowed && !res.Advisory) || s.deps.Alerts == nil {
		return
	}
	ctx := r.Context()

	// A lockout is worth an alert: it is either an attack on one account or a
	// user locked out of their own, and an operator wants to know which.
	var alertErr error
	switch res.Dimension {
	case throttle.DimSubject:
		_, alertErr = s.deps.Alerts.AuthFailureBurst(ctx, tenantID, subjectID, res.Failures)
	case throttle.DimIP:
		_, alertErr = s.deps.Alerts.AuthFailureBurstFromNetwork(ctx, tenantID,
			scope.dims[throttle.DimIP], res.Failures)
	}
	if alertErr != nil {
		s.deps.Logger.WarnContext(ctx, "lockout alert not raised", slog.Any("error", alertErr))
	}

	detail := map[string]any{
		"dimension": string(res.Dimension),
		"failures":  res.Failures,
		// Whether anything was actually refused. An entry that said a limit
		// tripped, on a request that was served, would be read as a lockout by
		// anyone reviewing the log later.
		"enforced": !res.Advisory,
	}
	if scope.factor != "" {
		detail["factor"] = string(scope.factor)
	}
	s.audited(r, audit.Event{
		TenantID:  tenantID,
		EventType: audit.EventThrottleTripped,
		ActorType: store.ActorSystem,
		SubjectID: subjectID,
		Outcome:   store.OutcomeDenied,
		Detail:    detail,
	})
}

// kdfSlots bounds how many Argon2id evaluations run at once on behalf of
// requests.
//
// One evaluation holds 19 MiB for its whole duration and keeps a core busy.
// Issuing a batch of recovery codes performs ten of them, and nothing bounded
// how many requests did so at the same time, so memory use was the number of
// requests in flight multiplied by 19 MiB, chosen by the caller. A slot is held
// around every evaluation a request triggers, whether it hashes a new secret or
// verifies a presented one.
//
// The size follows the core count, since the work is CPU bound and more slots
// than cores buys contention and no throughput. It is kept between 2 and 8: two
// so that one slow request never serialises the service on a single-core host,
// eight so that a large host still caps the memory at about 150 MiB.
var kdfSlots = make(chan struct{}, min(max(runtime.NumCPU(), 2), 8))

// kdfMaxWait is how long a request queues for a slot before it is turned away.
// It is short of any sensible client timeout, so the caller is told to come
// back rather than left to give up on a connection the server is still holding.
const kdfMaxWait = 3 * time.Second

// kdfRetryAfterSeconds is the Retry-After sent with that refusal. One batch of
// recovery codes holds a slot for well under a second on current hardware.
const kdfRetryAfterSeconds = 2

// acquireKDF waits for a slot and returns the function that gives it back.
//
// The wait ends early when the request is cancelled, so an abandoned connection
// does not keep its place in the queue, and ends with a 503 after kdfMaxWait,
// so the queue cannot grow without bound either.
func acquireKDF(ctx context.Context) (release func(), err error) {
	return acquireKDFWithin(ctx, kdfMaxWait)
}

// acquireKDFWithin is acquireKDF with the patience given, so that a test does
// not have to sit through kdfMaxWait to see the refusal.
func acquireKDFWithin(ctx context.Context, patience time.Duration) (release func(), err error) {
	wait := time.NewTimer(patience)
	defer wait.Stop()

	select {
	case kdfSlots <- struct{}{}:
		return func() { <-kdfSlots }, nil
	case <-ctx.Done():
		return nil, Unavailable(ctx.Err())
	case <-wait.C:
		refusal := Unavailable(errors.New("no key derivation slot became free within " + patience.String()))
		refusal.RetryAfterSeconds = kdfRetryAfterSeconds
		return nil, refusal
	}
}

// audited records an event, logging rather than failing when the append does
// not work.
//
// A handler that has already changed state cannot be undone by a failed audit
// append, so the choice is between losing the record and losing the change.
// Where the store allows both in one transaction, that is used instead; this
// helper is for the cases where it cannot.
func (s *Server) audited(r *http.Request, ev audit.Event) {
	ctx := r.Context()
	ev.Detail = withEndUserIP(r, ev.Detail)
	if ev.SourceIP == "" {
		ev.SourceIP = SourceIPFrom(ctx)
	}
	if ev.RequestID == "" {
		ev.RequestID = RequestIDFrom(ctx)
	}
	if err := s.deps.Recorder.Record(ctx, ev); err != nil {
		s.deps.Logger.ErrorContext(ctx, "event not audited",
			slog.String("event_type", ev.EventType), slog.Any("error", err))
	}
}

// withEndUserIP adds the address an integrating application declared to an
// audit detail, under a key of its own.
//
// Only a request authenticated with an API key is read. The header means
// nothing on the administrative surface, and an administrator's entry must not
// carry an address that anybody could have typed into a request. A value that
// does not parse is left out: the routes that act on the header have already
// refused such a request, and the others ignore the header altogether.
func withEndUserIP(r *http.Request, detail map[string]any) map[string]any {
	caller := CallerFrom(r.Context())
	if caller == nil || caller.APIKey == nil {
		return detail
	}
	addr, declared, err := endUserIP(r)
	if err != nil || !declared {
		return detail
	}
	if detail == nil {
		detail = make(map[string]any, 1)
	}
	detail[auditKeyEndUserIP] = addr.String()
	return detail
}
