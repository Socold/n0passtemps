package api

import (
	"net/http"

	"github.com/Socold/n0passtemps/internal/metrics"
	"github.com/Socold/n0passtemps/internal/rbac"
)

// Routes builds the complete HTTP handler.
//
// # Middleware order
//
// The order below is load bearing, not cosmetic. Reading outwards in:
//
//	RequestID        assigns the identifier everything else references
//	Recover          so a panic is still logged with that identifier
//	SourceIP         resolves the client address once, before anything keys on it
//	RequestLog       attaches the request-scoped logger
//	RequestMetrics   counts the response, inside Recover so a panic counts as 500
//	SecurityHeaders  applied to every response, including error responses
//	BodyLimit        caps the body before any handler reads it
//
// Recovery sits inside RequestID so the panic log carries the identifier, and
// outside everything else so a panic anywhere below is caught. SourceIP runs
// before the rate limiter and before the administrative allow list, because
// both key on the address it resolves.
//
// # Two authenticated surfaces
//
// Neither surface is anonymous. The public routes carry an API key and the
// administrative routes an administrative token, and the two credential kinds
// cannot be substituted for each other. The only unauthenticated routes are the
// liveness probe and the JWKS document, and both are listed explicitly below so
// that adding a third is a visible decision rather than an oversight.
func (s *Server) Routes() http.Handler {
	cfg := s.deps.Config

	mux := http.NewServeMux()

	s.mountUnauthenticated(mux)
	s.mountPublic(mux)
	s.mountAdmin(mux)

	if cfg.Admin.UIEnabled && s.deps.AdminUI != nil {
		// The interface authenticates through its own session cookie rather
		// than a bearer token, so it is mounted with the network allow list
		// but outside the token middleware.
		mux.Handle("/admin/", Chain(s.deps.AdminUI,
			RouteLabel(),
			IPAllowList(cfg.Admin.IPAllowList),
			NoStore(),
		))
	}

	// A request that matches no route still passes through the outer chain, so
	// it gets a request identifier, a log line and the security headers.
	mux.Handle("/", Chain(wrap(func(w http.ResponseWriter, r *http.Request) error {
		return NotFound(nil)
	}), RouteLabel()))

	hsts := 0
	if cfg.Server.TLSCertFile != "" || cfg.Server.TrustProxy {
		// One year, which is the minimum a browser preload list accepts. It is
		// only emitted over TLS; see SecurityHeaders.
		hsts = 31536000
	}

	return Chain(mux,
		RequestID(),
		Recover(),
		SourceIP(cfg.Server.TrustProxy, cfg.Server.TrustedProxyCIDRs),
		RequestLog(s.deps.Logger),
		// Inside Recover, so a panic is counted as the 500 it becomes rather
		// than not counted at all.
		RequestMetrics(observerOrNil(s.deps.Metrics)),
		SecurityHeaders(hsts),
		BodyLimit(cfg.Server.MaxBodyBytes),
	)
}

// mountUnauthenticated registers the two routes that carry no credential.
//
// Both are deliberate and both disclose only public information. The liveness
// probe answers whether the process can serve traffic, which a load balancer
// has to be able to ask without holding a key. The JWKS document contains
// public keys, and an integrating application has to fetch it in order to
// verify an assertion offline.
func (s *Server) mountUnauthenticated(mux *http.ServeMux) {
	mux.Handle("GET /v1/health", Chain(wrap(s.handleLiveness), RouteLabel()))
	mux.Handle("GET /v1/.well-known/jwks.json", Chain(wrap(s.handleJWKS), RouteLabel()))

	// Served at both paths because the well-known prefix is what the JWKS
	// convention specifies, while integrations frequently look for the shorter
	// form. Two routes are cheaper than a support question nobody can ask.
	mux.Handle("GET /v1/jwks.json", Chain(wrap(s.handleJWKS), RouteLabel()))
}

// mountPublic registers the routes an integrating application calls.
//
// Every one of them requires an API key. An unauthenticated registration route
// would let anyone enrol an authenticator against any subject, which is a
// complete authentication bypass rather than a missing hardening measure. See
// docs/adr/0002.
func (s *Server) mountPublic(mux *http.ServeMux) {
	// Every route names the scope it belongs to at the point it is created, for
	// the same reason administrative routes name their permission there: a
	// route that forgot would not compile into anything callable.
	authed := func(scope Scope, h handler) http.Handler {
		return Chain(wrap(h),
			RouteLabel(),
			CORS(s.deps.Config.Server.CORSAllowedOrigins),
			s.auth.RequireAPIKey(),
			s.RequireScope(scope),
			s.MeterAPIKey(),
			RequireJSON(),
			NoStore(),
		)
	}

	mux.Handle("GET /v1/health/detail", authed(ScopeHealth, s.handleHealthDetail))
	mux.Handle("GET /v1/metrics", authed(ScopeMetrics, s.handleMetrics))

	mux.Handle("POST /v1/subjects", authed(ScopeSubjects, s.handleCreateSubject))
	mux.Handle("GET /v1/subjects/{subject_ref}", authed(ScopeSubjects, s.handleGetSubject))

	mux.Handle("POST /v1/webauthn/{subject_ref}/register", authed(ScopeWebAuthn, s.handleRegisterBegin))
	mux.Handle("POST /v1/webauthn/{subject_ref}/register/complete", authed(ScopeWebAuthn, s.handleRegisterComplete))
	mux.Handle("POST /v1/webauthn/{subject_ref}/assert", authed(ScopeWebAuthn, s.handleAssertBegin))
	mux.Handle("POST /v1/webauthn/{subject_ref}/assert/complete", authed(ScopeWebAuthn, s.handleAssertComplete))

	// Named "assert/discoverable" rather than "discoverable/assert" so the
	// pattern cannot collide with {subject_ref}: a subject whose reference was
	// literally "discoverable" would otherwise make two patterns match one
	// path.
	mux.Handle("POST /v1/webauthn/assert/discoverable", authed(ScopeWebAuthn, s.handleDiscoverableAssertBegin))
	mux.Handle("POST /v1/webauthn/assert/discoverable/complete",
		authed(ScopeWebAuthn, s.handleDiscoverableAssertComplete))

	mux.Handle("POST /v1/totp/{subject_ref}/enrol", authed(ScopeTOTP, s.handleTOTPEnrol))
	mux.Handle("POST /v1/totp/{subject_ref}/enrol/confirm", authed(ScopeTOTP, s.handleTOTPConfirm))
	mux.Handle("POST /v1/totp/{subject_ref}/verify", authed(ScopeTOTP, s.handleTOTPVerify))

	// The specification spelled this "enroll". Both spellings are served so a
	// published integration does not break over an orthography choice.
	mux.Handle("POST /v1/totp/{subject_ref}/enroll", authed(ScopeTOTP, s.handleTOTPEnrol))
	mux.Handle("POST /v1/totp/{subject_ref}/enroll/confirm", authed(ScopeTOTP, s.handleTOTPConfirm))

	mux.Handle("POST /v1/recovery/{subject_ref}/issue", authed(ScopeRecovery, s.handleRecoveryIssue))
	mux.Handle("POST /v1/recovery/{subject_ref}/consume", authed(ScopeRecovery, s.handleRecoveryConsume))

	// Enrolment tickets. Issuing names the subject, because the caller chooses
	// who gets one; redeeming does not, because the ticket already says whose
	// it is and a second, caller-supplied answer would only be a way to probe
	// which references exist.
	//
	// The ticket itself travels in the request body on both redemption routes,
	// never in the path, which is why neither path carries it and why the routes
	// are named for what they do. See internal/api/tickets.go for the reasoning:
	// a path reaches proxy access logs, a body does not.
	mux.Handle("POST /v1/subjects/{subject_ref}/enrolment-ticket",
		authed(ScopeTickets, s.handleIssueEnrolmentTicket))
	mux.Handle("POST /v1/enrolment/register", authed(ScopeTickets, s.handleTicketRegisterBegin))
	mux.Handle("POST /v1/enrolment/register/complete",
		authed(ScopeTickets, s.handleTicketRegisterComplete))

	// A preflight request carries no credential, by definition, so it cannot
	// pass through the authentication middleware. It is answered by the CORS
	// middleware alone.
	preflight := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), CORS(s.deps.Config.Server.CORSAllowedOrigins))
	mux.Handle("OPTIONS /v1/", preflight)
}

// mountAdmin registers the administrative routes.
//
// Each carries three layers: the network allow list, the administrative token,
// and the permission the route requires. The allow list runs first on purpose,
// so a caller outside it cannot even present a token for verification and the
// token-guessing surface stays off the public internet.
//
// The permission is attached per route rather than checked inside the handler.
// A handler that forgot the check would be an open route; a route mounted
// without a permission does not compile into anything callable, because this is
// the only place a route is created.
func (s *Server) mountAdmin(mux *http.ServeMux) {
	cfg := s.deps.Config

	guarded := func(p rbac.Permission, h handler) http.Handler {
		return Chain(wrap(h),
			RouteLabel(),
			IPAllowList(cfg.Admin.IPAllowList),
			s.auth.RequireAdmin(),
			s.auth.RequirePermission(p, cfg.Features.AdminRBAC),
			RequireJSON(),
			NoStore(),
		)
	}

	// Subjects.
	mux.Handle("GET /admin/v1/subjects", guarded(rbac.PermSubjectList, s.handleAdminListSubjects))
	mux.Handle("GET /admin/v1/subjects/{subject_id}", guarded(rbac.PermSubjectRead, s.handleAdminGetSubject))
	mux.Handle("POST /admin/v1/subjects/{subject_id}/lock", guarded(rbac.PermSubjectLock, s.handleAdminLockSubject))
	mux.Handle("POST /admin/v1/subjects/{subject_id}/unlock",
		guarded(rbac.PermSubjectUnlock, s.handleAdminUnlockSubject))

	// Credentials.
	mux.Handle("GET /admin/v1/subjects/{subject_id}/credentials",
		guarded(rbac.PermCredentialList, s.handleAdminListCredentials))
	mux.Handle("POST /admin/v1/subjects/{subject_id}/credentials/{credential_id}/revoke",
		guarded(rbac.PermCredentialRevoke, s.handleAdminRevokeCredential))
	mux.Handle("POST /admin/v1/subjects/{subject_id}/credentials/revoke-all",
		guarded(rbac.PermCredentialRevokeBulk, s.handleAdminRevokeAllCredentials))

	// Recovery codes and throttling, the two operations behind a user who
	// cannot log in.
	mux.Handle("POST /admin/v1/subjects/{subject_id}/recovery/reissue",
		guarded(rbac.PermRecoveryReissue, s.handleAdminReissueRecovery))
	mux.Handle("POST /admin/v1/subjects/{subject_id}/throttle/reset",
		guarded(rbac.PermThrottleReset, s.handleAdminResetThrottle))

	// Enrolment tickets, the third thing behind a user who cannot log in, and
	// the only one that works when they hold no factor at all. Withdrawing one
	// shares the issuing permission; see handleAdminRevokeEnrolmentTicket.
	mux.Handle("POST /admin/v1/subjects/{subject_id}/enrolment-ticket",
		guarded(rbac.PermEnrolmentTicketIssue, s.handleAdminIssueEnrolmentTicket))
	mux.Handle("POST /admin/v1/enrolment-tickets/{ticket_id}/revoke",
		guarded(rbac.PermEnrolmentTicketIssue, s.handleAdminRevokeEnrolmentTicket))

	// Erasure.
	mux.Handle("POST /admin/v1/subjects/{subject_id}/erasure",
		guarded(rbac.PermErasureRequest, s.handleAdminRequestErasure))
	mux.Handle("DELETE /admin/v1/subjects/{subject_id}/erasure",
		guarded(rbac.PermErasureCancel, s.handleAdminCancelErasure))

	// Audit.
	mux.Handle("GET /admin/v1/audit", guarded(rbac.PermAuditRead, s.handleAdminQueryAudit))
	mux.Handle("GET /admin/v1/audit/verify", guarded(rbac.PermAuditVerify, s.handleAdminVerifyAudit))

	// Alerts.
	mux.Handle("GET /admin/v1/alerts", guarded(rbac.PermAlertRead, s.handleAdminListAlerts))
	mux.Handle("POST /admin/v1/alerts/{alert_id}/acknowledge",
		guarded(rbac.PermAlertAcknowledge, s.handleAdminAcknowledgeAlert))

	// Dual approval.
	mux.Handle("GET /admin/v1/approvals", guarded(rbac.PermApprovalRead, s.handleAdminListApprovals))
	mux.Handle("POST /admin/v1/approvals/{approval_id}/approve",
		guarded(rbac.PermApprovalDecide, s.handleAdminApprove))
	mux.Handle("POST /admin/v1/approvals/{approval_id}/reject",
		guarded(rbac.PermApprovalDecide, s.handleAdminReject))

	// Caller credentials.
	mux.Handle("GET /admin/v1/api-keys", guarded(rbac.PermAPIKeyList, s.handleAdminListAPIKeys))
	mux.Handle("POST /admin/v1/api-keys", guarded(rbac.PermAPIKeyCreate, s.handleAdminCreateAPIKey))
	mux.Handle("POST /admin/v1/api-keys/{key_id}/revoke",
		guarded(rbac.PermAPIKeyRevoke, s.handleAdminRevokeAPIKey))
	mux.Handle("POST /admin/v1/api-keys/{key_id}/rotate",
		guarded(rbac.PermAPIKeyRotate, s.handleAdminRotateAPIKey))

	mux.Handle("GET /admin/v1/admin-tokens", guarded(rbac.PermAdminTokenList, s.handleAdminListAdminTokens))
	mux.Handle("POST /admin/v1/admin-tokens", guarded(rbac.PermAdminTokenCreate, s.handleAdminCreateAdminToken))
	mux.Handle("POST /admin/v1/admin-tokens/{token_id}/revoke",
		guarded(rbac.PermAdminTokenRevoke, s.handleAdminRevokeAdminToken))

	// A token rotates itself and only itself, so the path names no token. A
	// {token_id} segment here would be a route for obtaining another
	// administrator's successor credential; see handleAdminRotateOwnToken.
	mux.Handle("POST /admin/v1/admin-tokens/self/rotate",
		guarded(rbac.PermAdminTokenRotateSelf, s.handleAdminRotateOwnToken))

	// Key management. Adding a key version is a command-line operation on the
	// keyring file; moving the stored records onto it is this route.
	mux.Handle("POST /admin/v1/kek/rewrap", guarded(rbac.PermKEKRotate, s.handleAdminRewrapKEK))

	// Health.
	mux.Handle("GET /admin/v1/health", guarded(rbac.PermHealthReadFull, s.handleHealthDetail))
}

// observerOrNil keeps a nil *metrics.Registry from becoming a non-nil
// RequestObserver holding a nil pointer, which is the interface trap the admin
// interface is converted around a few lines above and the same one.
func observerOrNil(r *metrics.Registry) RequestObserver {
	if r == nil {
		return nil
	}
	return r
}
