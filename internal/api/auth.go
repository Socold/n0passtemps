package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/logging"
	"github.com/Socold/n0passtemps/internal/rbac"
	"github.com/Socold/n0passtemps/internal/store"
)

// Authenticator verifies bearer credentials.
//
// Both surfaces require one. The public /v1 routes are not anonymous: an
// unauthenticated registration endpoint would let anyone enrol an authenticator
// against any subject, which is a complete authentication bypass rather than a
// missing hardening measure. See docs/adr/0002.
type Authenticator struct {
	store    store.Store
	recorder *audit.Recorder
	alerts   *alerts.Engine
	now      func() time.Time

	// rejections folds the refusals on the credential path, so that being
	// refused costs the service a bounded number of writes however often it
	// happens. See recordRejection.
	rejections rejectionTally
}

// NewAuthenticator builds an Authenticator.
func NewAuthenticator(st store.Store, rec *audit.Recorder, al *alerts.Engine, clock func() time.Time) *Authenticator {
	if clock == nil {
		clock = time.Now
	}
	return &Authenticator{store: st, recorder: rec, alerts: al, now: clock}
}

// RequireAPIKey authenticates a caller on the public surface.
func (a *Authenticator) RequireAPIKey() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, err := a.verifyAPIKey(r)
			if err != nil {
				var unavailable *unavailableError
				if errors.As(err, &unavailable) {
					// Not audited as a rejection: nothing was rejected.
					WriteProblem(w, r, Unavailable(unavailable.cause))
					return
				}
				a.recordRejection(r, audit.EventAPIKeyRejected, err)
				WriteProblem(w, r, Unauthorized(err))
				return
			}

			caller := &Caller{TenantID: key.TenantID, APIKey: key}
			ctx := withCaller(r.Context(), caller)

			log := logging.FromContext(ctx).With(
				slog.String(logging.KeyTenantID, key.TenantID),
				slog.String(logging.KeyActorType, string(store.ActorAPIKey)),
				slog.String(logging.KeyActorID, key.ID),
			)
			ctx = logging.WithLogger(ctx, log)

			// Recording last use must not be able to fail the request. A write
			// error here means the database is unhappy, which the health check
			// will surface; refusing a valid authentication over it would turn
			// a degraded database into an outage.
			if err := a.store.TouchAPIKey(ctx, key.ID, a.now().UTC()); err != nil {
				log.WarnContext(ctx, "api key last-use timestamp not recorded", slog.Any("error", err))
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin authenticates a caller on the administrative surface.
func (a *Authenticator) RequireAdmin() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := a.verifyAdminToken(r)
			if err != nil {
				var unavailable *unavailableError
				if errors.As(err, &unavailable) {
					WriteProblem(w, r, Unavailable(unavailable.cause))
					return
				}
				a.recordRejection(r, audit.EventAdminAuthFailed, err)
				WriteProblem(w, r, Unauthorized(err))
				return
			}

			caller := &Caller{TenantID: tok.TenantID, AdminToken: tok}
			ctx := withCaller(r.Context(), caller)

			log := logging.FromContext(ctx).With(
				slog.String(logging.KeyTenantID, tok.TenantID),
				slog.String(logging.KeyActorType, string(store.ActorAdmin)),
				slog.String(logging.KeyActorID, tok.ID),
				slog.String("role", string(tok.Role)),
			)
			ctx = logging.WithLogger(ctx, log)

			if err := a.store.TouchAdminToken(ctx, tok.ID, a.now().UTC()); err != nil {
				log.WarnContext(ctx, "admin token last-use timestamp not recorded", slog.Any("error", err))
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// errNoCredential marks a request that presented nothing at all.
//
// It is told apart from every other refusal because the two mean different
// things. A malformed, unknown or expired credential was presented by somebody
// who once had one, and a run of them is worth an operator's time. A request
// with no Authorization header at all names nobody: it is a scanner walking the
// address space, and there is nothing in it for an operator to read. See
// recordRejection for what follows from the difference.
var errNoCredential = errors.New("no bearer credential presented")

// unavailableError marks a failure that is the service's fault rather than the
// caller's, so the middleware can answer 503 instead of 401.
type unavailableError struct{ cause error }

func (e *unavailableError) Error() string { return "credential store unavailable: " + e.cause.Error() }
func (e *unavailableError) Unwrap() error { return e.cause }

// verifyAPIKey resolves and checks a presented API key.
//
// The order of operations matters. The token is parsed first, so malformed
// input is refused without a query. The selector then drives a single indexed
// lookup, and the verifier is compared in constant time. Every failure returns
// the same error, because distinguishing an unknown selector from a wrong
// verifier would let a caller confirm which selectors exist.
func (a *Authenticator) verifyAPIKey(r *http.Request) (*store.APIKey, error) {
	presented, err := token.FromAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return nil, errNoCredential
	}

	parsed, err := token.Parse(presented)
	if err != nil {
		return nil, errors.New("credential is malformed")
	}
	// A token minted for the administrative surface must not authenticate here,
	// and the reverse. The kind is bound into the stored digest as well, so
	// this check is belt and braces rather than the only guard.
	if parsed.Kind != token.KindAPIKey {
		return nil, errors.New("credential is not an api key")
	}

	key, err := a.store.GetAPIKeyBySelector(r.Context(), parsed.Selector)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("credential is not recognised")
		}
		// The lookup itself failed, which means the database is in trouble
		// rather than the credential being wrong. Reporting it as a rejected
		// credential would mislead the caller and fill the audit log with
		// authentication failures that never happened.
		return nil, &unavailableError{cause: err}
	}

	ok, err := parsed.Verify(key.VerifierHash)
	if err != nil {
		// A malformed stored hash is an operational fault, not an attack, and
		// it must not be mistaken for a failed attempt.
		return nil, err
	}
	if !ok {
		return nil, errors.New("credential is not recognised")
	}

	if !key.Usable(a.now().UTC()) {
		return nil, errors.New("credential is expired or revoked")
	}
	return key, nil
}

// verifyAdminToken resolves and checks a presented administrative token.
func (a *Authenticator) verifyAdminToken(r *http.Request) (*store.AdminToken, error) {
	presented, err := token.FromAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return nil, errNoCredential
	}

	parsed, err := token.Parse(presented)
	if err != nil {
		return nil, errors.New("credential is malformed")
	}
	if parsed.Kind != token.KindAdmin {
		return nil, errors.New("credential is not an admin token")
	}

	tok, err := a.store.GetAdminTokenBySelector(r.Context(), parsed.Selector)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("credential is not recognised")
		}
		// See verifyAPIKey: a failed lookup is a database problem, not a
		// rejected credential.
		return nil, &unavailableError{cause: err}
	}

	ok, err := parsed.Verify(tok.VerifierHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("credential is not recognised")
	}

	if !tok.Usable(a.now().UTC()) {
		return nil, errors.New("credential is expired, revoked or holds an unknown role")
	}
	return tok, nil
}

// How a refused authentication is recorded.
//
// Every refusal used to write one audit entry and upsert one alert. Both are
// writes, the audit chain has a single writer by construction, and neither
// needed a credential to happen: anyone at all could take that writer away from
// the ceremonies that need it, and fill a table an operator cannot prune
// freely with entries that carry no subject and are therefore outside the reach
// of an erasure request. What follows folds the refusals from one source
// address into one entry and one alert per window, each carrying how many
// refusals it covers, so a run of them is still visible, with its volume, in
// both places an operator looks.

const (
	// rejectionWindow is how long refusals from one source address are folded
	// together. It is short enough that a run shows up in the history while it
	// is still going on, and long enough that a caller cannot make the service
	// write once per request.
	rejectionWindow = time.Minute

	// maxTrackedSources bounds what the fold may hold at once, so that a
	// caller rotating through addresses cannot turn the saving in database
	// writes into unbounded memory.
	maxTrackedSources = 4096
)

// rejectionRun is what one source address has accumulated since its last
// report.
type rejectionRun struct {
	openedAt time.Time

	// refusals counts every refusal, and credentials only those that presented
	// something. A run with no credentials in it is audited as nothing; see
	// recordRejection.
	refusals    int
	credentials int
}

// rejectionTally folds refusals per source address.
//
// The zero value is ready to use, so an Authenticator assembled as a struct
// literal behaves like one built by NewAuthenticator rather than panicking on
// the first refusal.
type rejectionTally struct {
	mu   sync.Mutex
	runs map[string]*rejectionRun
}

// rejectionFold is what one report covers: the refusals since the last report
// for that address, the one being reported included.
type rejectionFold struct {
	Refusals    int
	Credentials int
}

// observe records one refusal and reports whether it is to be written now.
//
// The first refusal from an address is reported at once, so that a single
// failure is still on the record and a burst is visible from its first attempt
// rather than a window later. Every further refusal inside the window is
// counted and writes nothing, and the next refusal after the window has elapsed
// reports the whole run. A run that is never followed by another refusal keeps
// its tail unreported, which is the deliberate trade: the report that opened it
// already said this address was being refused, and the tail is a refinement of
// a number, not the only sign of the thing.
func (t *rejectionTally) observe(now time.Time, key string, presented bool) (rejectionFold, bool) {
	credential := 0
	if presented {
		credential = 1
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.runs == nil {
		t.runs = make(map[string]*rejectionRun)
	}

	run, ok := t.runs[key]
	switch {
	case ok && now.Sub(run.openedAt) < rejectionWindow:
		run.refusals++
		run.credentials += credential
		return rejectionFold{}, false
	case ok:
		// The window has elapsed. This refusal closes the run, reports it, and
		// opens the next one empty, because everything the next one would have
		// counted is in the report being returned.
		reported := rejectionFold{
			Refusals:    run.refusals + 1,
			Credentials: run.credentials + credential,
		}
		*run = rejectionRun{openedAt: now}
		return reported, true
	default:
		t.evictLocked(now)
		t.runs[key] = &rejectionRun{openedAt: now}
		return rejectionFold{Refusals: 1, Credentials: credential}, true
	}
}

// evictLocked keeps the map bounded.
//
// Runs whose window has elapsed go first, because what they hold is the
// refinement described in observe rather than a report nobody has written. If
// the map is still full the oldest open run goes, which costs the same
// refinement: a run is reported when it is opened, never when it is dropped, so
// no address can be made invisible by crowding the map from another one.
func (t *rejectionTally) evictLocked(now time.Time) {
	if len(t.runs) < maxTrackedSources {
		return
	}

	oldest, oldestAt := "", time.Time{}
	for key, run := range t.runs {
		if now.Sub(run.openedAt) >= rejectionWindow {
			delete(t.runs, key)
			continue
		}
		if oldestAt.IsZero() || run.openedAt.Before(oldestAt) {
			oldest, oldestAt = key, run.openedAt
		}
	}
	if len(t.runs) >= maxTrackedSources && oldest != "" {
		delete(t.runs, oldest)
	}
}

// recordRejection records a refused authentication, folded by source address.
//
// Refusals on the credential path are worth recording because a run of them is
// the earliest visible sign of a leaked credential being probed, and the audit
// log is where an operator looks for it afterwards. What is not worth recording
// is one entry per request, for the reasons given above the fold.
//
// A fold in which nothing was ever presented is not audited at all. A request
// with no Authorization header teaches an operator nothing they can act on, and
// the alert still counts it, so a scan is visible as a number rather than as a
// thousand entries nobody can delete.
//
// The two credential families are folded apart, so that a refused
// administrative token is never counted into an entry about an API key.
func (a *Authenticator) recordRejection(r *http.Request, eventType string, cause error) {
	ctx := r.Context()
	source := SourceIPFrom(ctx)
	presented := !errors.Is(cause, errNoCredential)

	fold, report := a.rejections.observe(a.now().UTC(), eventType+"\x00"+source, presented)
	if !report {
		return
	}

	if fold.Credentials > 0 {
		ev := audit.Event{
			// The tenant is unknown at this point, by definition: the
			// credential that would have named it did not verify. A fixed
			// placeholder keeps the entry insertable without inventing a
			// tenant.
			TenantID:  store.SystemTenantID,
			EventType: eventType,
			ActorType: store.ActorSystem,
			Outcome:   store.OutcomeDenied,
			SourceIP:  source,
			RequestID: RequestIDFrom(ctx),
			Detail: map[string]any{
				// The reason and the route are those of the refusal that
				// produced this entry; the counts cover everything folded into
				// it since the last one for this address.
				"reason":    cause.Error(),
				"route":     routePattern(r),
				"refusals":  fold.Refusals,
				"presented": fold.Credentials,
				"window":    rejectionWindow.String(),
			},
		}
		if err := a.recorder.Record(ctx, ev); err != nil {
			logging.FromContext(ctx).ErrorContext(ctx,
				"authentication failure not audited", slog.Any("error", err))
		}
	}

	if a.alerts != nil {
		if _, err := a.alerts.APIKeyRejected(ctx, store.SystemTenantID, source, fold.Refusals); err != nil {
			logging.FromContext(ctx).WarnContext(ctx,
				"alert not raised for rejected credential", slog.Any("error", err))
		}
	}
}

// RequirePermission enforces the administrative role model on a route.
//
// It runs after RequireAdmin, so a missing caller here means the route was
// mounted without authentication. That is a programming error, and it is
// treated as a refusal rather than a panic so a misrouted request cannot take
// the process down.
func (a *Authenticator) RequirePermission(p rbac.Permission, rbacEnabled bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			caller := CallerFrom(ctx)
			if caller == nil || !caller.IsAdmin() {
				WriteProblem(w, r, Forbidden(errors.New("route requires an authenticated administrator")))
				return
			}

			decision := rbac.Authorise(caller.Role(), p, rbacEnabled)
			if !decision.Allowed {
				// The reason is logged and audited, never returned. It names
				// the permission and the role, which tells a caller probing
				// the surface exactly what to look for next.
				ev := audit.Event{
					TenantID:     caller.TenantID,
					EventType:    audit.EventAdminDenied,
					ActorType:    store.ActorAdmin,
					ActorID:      caller.ActorID(),
					ResourceType: "permission",
					ResourceID:   p.String(),
					Outcome:      store.OutcomeDenied,
					SourceIP:     SourceIPFrom(ctx),
					RequestID:    RequestIDFrom(ctx),
					Detail: map[string]any{
						"role":   string(caller.Role()),
						"reason": decision.Reason,
						"route":  routePattern(r),
					},
				}
				if err := a.recorder.Record(ctx, ev); err != nil {
					logging.FromContext(ctx).ErrorContext(ctx,
						"authorisation denial not audited", slog.Any("error", err))
				}
				if a.alerts != nil {
					if _, err := a.alerts.AdminDenied(ctx, caller.TenantID,
						caller.ActorID(), p.String()); err != nil {
						logging.FromContext(ctx).WarnContext(ctx,
							"alert not raised for authorisation denial", slog.Any("error", err))
					}
				}

				WriteProblem(w, r, Forbidden(errors.New(decision.Reason)))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireCaller is the helper handlers use to fetch the identity they were
// mounted behind.
func requireCaller(ctx context.Context) (*Caller, error) {
	c := CallerFrom(ctx)
	if c == nil {
		return nil, Internal(errors.New("route is mounted without authentication middleware"))
	}
	return c, nil
}
