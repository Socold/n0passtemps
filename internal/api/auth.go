package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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
		return nil, errors.New("no bearer credential presented")
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
		return nil, errors.New("no bearer credential presented")
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

// recordRejection audits a refused authentication and raises an alert.
//
// Failures on the credential path are audited because a run of them is the
// earliest visible sign of a leaked key being probed, and the audit log is
// where an operator looks for it afterwards.
func (a *Authenticator) recordRejection(r *http.Request, eventType string, cause error) {
	ctx := r.Context()

	ev := audit.Event{
		// The tenant is unknown at this point, by definition: the credential
		// that would have named it did not verify. A fixed placeholder keeps
		// the entry insertable without inventing a tenant.
		TenantID:  store.SystemTenantID,
		EventType: eventType,
		ActorType: store.ActorSystem,
		Outcome:   store.OutcomeDenied,
		SourceIP:  SourceIPFrom(ctx),
		RequestID: RequestIDFrom(ctx),
		Detail:    map[string]any{"reason": cause.Error(), "route": routePattern(r)},
	}
	if err := a.recorder.Record(ctx, ev); err != nil {
		logging.FromContext(ctx).ErrorContext(ctx,
			"authentication failure not audited", slog.Any("error", err))
	}

	if a.alerts != nil {
		if _, err := a.alerts.APIKeyRejected(ctx, store.SystemTenantID, SourceIPFrom(ctx), 1); err != nil {
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
