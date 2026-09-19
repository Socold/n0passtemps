package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/health"
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

// clientThrottleDims builds the rate-limiting dimensions for a request.
//
// The subject and the source address are limited together. Limiting on either
// alone is wrong: per subject alone lets an attacker spread one guess across
// many accounts, and per address alone punishes everyone behind one NAT
// gateway. The third dimension, volume per API key, is metered for every
// request by the MeterAPIKey middleware rather than here, so that routes which
// record no authentication outcome are counted too.
func (s *Server) clientThrottleDims(r *http.Request, caller *Caller, subjectID string) map[throttle.Dimension]string {
	dims := make(map[throttle.Dimension]string, 3)
	if ip := SourceIPFrom(r.Context()); ip != "" {
		dims[throttle.DimIP] = ip
	}
	if subjectID != "" {
		dims[throttle.DimSubject] = subjectID
	}
	return dims
}

// checkThrottle refuses a request that is currently locked out.
//
// It is consulted before any expensive work, so a locked-out caller does not
// get an Argon2id evaluation or a signature verification out of the service.
func (s *Server) checkThrottle(r *http.Request, tenantID string, dims map[throttle.Dimension]string) error {
	if s.deps.Limiter == nil || len(dims) == 0 {
		return nil
	}
	res, err := s.deps.Limiter.Check(r.Context(), tenantID, dims)
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

// recordAttempt registers the outcome of an authentication attempt and raises
// an alert when a limit trips.
//
// The limiter's result is returned so that risk reporting can read the failure
// counters this call already fetched, rather than querying for them again on
// the authentication path. Callers with no use for it ignore it, which is why
// it is a return value and not an out parameter.
func (s *Server) recordAttempt(r *http.Request, tenantID, subjectID string, dims map[throttle.Dimension]string, failure bool) throttle.Result {
	if s.deps.Limiter == nil || len(dims) == 0 {
		return throttle.Result{Allowed: true}
	}
	ctx := r.Context()

	res, err := s.deps.Limiter.Record(ctx, tenantID, dims, failure)
	if err != nil {
		s.deps.Logger.WarnContext(ctx, "attempt not recorded against throttle",
			slog.Any("error", err))
		return throttle.Result{Allowed: true}
	}
	if res.Allowed || s.deps.Alerts == nil {
		return res
	}

	// A lockout is worth an alert: it is either an attack on one account or a
	// user locked out of their own, and an operator wants to know which.
	var alertErr error
	switch res.Dimension {
	case throttle.DimSubject:
		_, alertErr = s.deps.Alerts.AuthFailureBurst(ctx, tenantID, subjectID, res.Failures)
	case throttle.DimIP:
		_, alertErr = s.deps.Alerts.AuthFailureBurstFromNetwork(ctx, tenantID,
			dims[throttle.DimIP], res.Failures)
	}
	if alertErr != nil {
		s.deps.Logger.WarnContext(ctx, "lockout alert not raised", slog.Any("error", alertErr))
	}

	if err := s.deps.Recorder.Record(ctx, audit.Event{
		TenantID:  tenantID,
		EventType: audit.EventThrottleTripped,
		ActorType: store.ActorSystem,
		SubjectID: subjectID,
		Outcome:   store.OutcomeDenied,
		SourceIP:  SourceIPFrom(ctx),
		RequestID: RequestIDFrom(ctx),
		Detail: map[string]any{
			"dimension": string(res.Dimension),
			"failures":  res.Failures,
		},
	}); err != nil {
		s.deps.Logger.ErrorContext(ctx, "lockout not audited", slog.Any("error", err))
	}
	return res
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
