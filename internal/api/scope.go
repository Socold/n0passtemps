package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// Scope names one family of public routes an API key may call.
//
// Scopes exist so that a key can be issued for the one thing an integration
// does. A service that only checks TOTP codes has no business issuing recovery
// codes, and a key that cannot do so is a key whose leak costs less.
type Scope string

// The scopes follow the route families, so the mapping from a route to the
// scope it needs is visible in the router rather than hidden in a table.
const (
	ScopeSubjects Scope = "subjects"
	ScopeWebAuthn Scope = "webauthn"
	ScopeTOTP     Scope = "totp"
	ScopeRecovery Scope = "recovery"
	ScopeHealth   Scope = "health"
)

var allScopes = []Scope{ScopeSubjects, ScopeWebAuthn, ScopeTOTP, ScopeRecovery, ScopeHealth}

// ValidateScopes checks a requested scope list and returns it normalised:
// lowercased, deduplicated and sorted.
//
// An unknown scope is refused rather than stored. A key minted with a
// misspelled scope would otherwise hold a permission that matches nothing, and
// the operator would discover it as an unexplained 403 in production.
func ValidateScopes(in []string) ([]string, error) {
	known := make(map[string]struct{}, len(allScopes))
	for _, s := range allScopes {
		known[string(s)] = struct{}{}
	}

	seen := map[string]struct{}{}
	for _, raw := range in {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := known[v]; !ok {
			names := make([]string, 0, len(allScopes))
			for _, s := range allScopes {
				names = append(names, string(s))
			}
			return nil, errors.New("unknown scope " + raw + "; the scopes are " + strings.Join(names, ", "))
		}
		seen[v] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// keyHasScope reports whether a key may call routes in the given scope.
//
// A key with no scopes at all is unrestricted. That is the conventional meaning
// and the only one compatible with keys minted before scopes were enforced; the
// response to minting such a key says so, so that an unrestricted key is a
// visible choice rather than a silent default.
func keyHasScope(key *store.APIKey, want Scope) bool {
	if len(key.Scopes) == 0 {
		return true
	}
	for _, s := range key.Scopes {
		if strings.EqualFold(s, string(want)) {
			return true
		}
	}
	return false
}

// RequireScope refuses an API key that was not issued for this route family.
//
// It runs after RequireAPIKey. The refusal is a 403 rather than a 401, because
// the credential is valid and re-authenticating would not help, and it is
// audited, because a key reaching outside its scope is either a
// misconfiguration worth fixing or a stolen key being explored.
func (s *Server) RequireScope(want Scope) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := CallerFrom(r.Context())
			if caller == nil || caller.APIKey == nil {
				WriteProblem(w, r, Forbidden(errors.New("route requires an api key")))
				return
			}
			if !keyHasScope(caller.APIKey, want) {
				s.audited(r, audit.Event{
					TenantID:     caller.TenantID,
					EventType:    audit.EventAPIKeyRejected,
					ActorType:    store.ActorAPIKey,
					ActorID:      caller.ActorID(),
					ResourceType: "scope",
					ResourceID:   string(want),
					Outcome:      store.OutcomeDenied,
					Detail:       map[string]any{"route": routePattern(r), "held": caller.APIKey.Scopes},
				})
				WriteProblem(w, r, Forbidden(errors.New("api key lacks scope "+string(want))))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MeterAPIKey counts every authenticated request against the key's volume
// limit, and refuses once the limit is reached.
//
// The count is taken here, in one place, for every public route. Counting it
// inside the handlers that record an authentication outcome would leave the
// other routes unmetered: a leaked key could then start ceremonies and resolve
// subjects without bound, which is precisely the abuse the per-key ceiling
// exists to cap.
func (s *Server) MeterAPIKey() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := CallerFrom(r.Context())
			if s.deps.Limiter == nil || caller == nil || caller.APIKey == nil {
				next.ServeHTTP(w, r)
				return
			}

			dims := map[throttle.Dimension]string{throttle.DimAPIKey: caller.APIKey.ID}
			res, err := s.deps.Limiter.Record(r.Context(), caller.TenantID, dims, false)
			if err != nil {
				// A limiter that cannot reach its state must not take the
				// service down with it. The health report surfaces the
				// underlying database problem.
				s.deps.Logger.WarnContext(r.Context(), "api key volume not recorded")
				next.ServeHTTP(w, r)
				return
			}
			if !res.Allowed {
				WriteProblem(w, r, Throttled(int(res.RetryAfter.Seconds()),
					&throttledError{dim: string(throttle.DimAPIKey)}))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
