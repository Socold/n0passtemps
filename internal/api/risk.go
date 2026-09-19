package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/risk"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
	wa "github.com/Socold/n0passtemps/internal/webauthn"
)

// Risk reporting lives in this file so that the three handlers which complete
// an authentication gain a line each rather than a paragraph each. Nothing
// here decides anything: internal/risk does the deciding, purely, and this
// file only gathers what it needs and puts the answer where it belongs, which
// is the signed assertion, the audit entry and, unsigned, the response body.

// assessWebAuthn assesses a completed WebAuthn assertion.
//
// It performs no query. Everything the assessment needs is already in hand:
// the ceremony signals come from the outcome, the credential's registration
// and last use come from the stored record the ceremony loaded, and the
// failure counters come from the throttle result the attempt was recorded
// against. The totp_only reason cannot apply, because a WebAuthn credential
// demonstrably exists.
//
// A nil return means the deployment does not report risk, which is how the
// claim comes to be omitted from the assertion entirely.
func (s *Server) assessWebAuthn(outcome *wa.AssertionOutcome, th throttle.Result) *risk.Assessment {
	cfg := s.deps.Config.Risk
	if !cfg.Enabled {
		return nil
	}

	in := risk.Input{
		Ceremony:       risk.CeremonyWebAuthn,
		UserVerified:   outcome.UserVerified,
		CloneWarning:   outcome.CloneWarning,
		BindingChanged: outcome.BindingChanged,

		// One, and it is the one that just authenticated. Asking whether the
		// subject holds others would be a query for an answer that changes
		// nothing: totp_only is about a subject with no unphishable factor,
		// and this subject has just used one.
		WebAuthnCredentials: 1,
	}
	if cred := outcome.Credential; cred != nil {
		// The record as it was loaded for the ceremony, so LastUsedAt is the
		// previous use rather than this one. Reading it after the update would
		// make every credential look as though it had just been used, which
		// is exactly the question credential_dormant asks.
		in.CredentialCreatedAt = cred.CreatedAt
		in.CredentialLastUsedAt = cred.LastUsedAt
	}
	applyFailureCounters(&in, th)

	out := risk.Assess(in, cfg, s.now().UTC())
	return &out
}

// assessCodeCeremony assesses a completed TOTP verification or recovery-code
// redemption.
//
// This is the path that needs a query, and it is one: the subject's WebAuthn
// credentials. It answers both questions that cannot be answered from what is
// already in hand. Whether the subject holds any at all decides totp_only, and
// the freshest of them gives the registration and last-use instants that
// decide credential_dormant and credential_new. Doing it as two lookups, one
// for the count and one for the timestamps, would be two round trips for one
// row set, so the listing is read once and both are taken from it.
//
// A query that fails is logged and the assessment proceeds without it, rather
// than failing an authentication that has already succeeded over a signal.
func (s *Server) assessCodeCeremony(r *http.Request, tenantID, subjectID string, ceremony risk.Ceremony, th throttle.Result) *risk.Assessment {
	cfg := s.deps.Config.Risk
	if !cfg.Enabled {
		return nil
	}

	in := risk.Input{Ceremony: ceremony}
	applyFailureCounters(&in, th)

	creds, err := s.deps.Store.ListCredentials(r.Context(), tenantID, subjectID, false)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// Logged and carried on. The subject is already authenticated, and
		// losing a signal must not turn a database hiccup into a refusal.
		s.deps.Logger.WarnContext(r.Context(),
			"risk assessment could not read the subject's credentials")
	} else {
		// ErrNotFound and an empty list are the same thing here: the subject
		// holds no WebAuthn credential, which is what totp_only reports.
		in.WebAuthnCredentials = len(creds)
		if freshest := freshestCredential(creds); freshest != nil {
			in.CredentialCreatedAt = freshest.CreatedAt
			in.CredentialLastUsedAt = freshest.LastUsedAt
		}
	}

	out := risk.Assess(in, cfg, s.now().UTC())
	return &out
}

// freshestCredential returns the credential whose last use, or registration
// when it has never been used, is the most recent.
//
// The freshest is the right one to judge dormancy by. A subject with one key
// they use daily and one they enrolled and forgot is not dormant, and picking
// the forgotten one would report every such subject as dormant for ever.
func freshestCredential(creds []*store.Credential) *store.Credential {
	var best *store.Credential
	for _, c := range creds {
		if best == nil || credentialActivity(c).After(credentialActivity(best)) {
			best = c
		}
	}
	return best
}

// credentialActivity is the instant a credential was last known to be in use,
// falling back to its registration when it has never been used.
func credentialActivity(c *store.Credential) time.Time {
	if c.LastUsedAt != nil {
		return *c.LastUsedAt
	}
	return c.CreatedAt
}

// applyFailureCounters copies the throttle counters the attempt was recorded
// against onto the risk input.
//
// They come from the limiter's own result, which already read every bucket it
// was given, so this costs nothing. A deployment with throttling off has no
// counters and reports no failure reasons, which is correct: it counted no
// failures.
func applyFailureCounters(in *risk.Input, th throttle.Result) {
	in.RecentFailuresSubject = th.Counters[throttle.DimSubject].Failures
	in.RecentFailuresNetwork = th.Counters[throttle.DimIP].Failures
}

// issueOptions turns an assessment into the options Issue takes. A nil
// assessment yields none, so the claim is absent rather than empty.
func issueOptions(a *risk.Assessment) []assertion.IssueOption {
	if a == nil {
		return nil
	}
	return []assertion.IssueOption{assertion.WithRisk(*a)}
}

// riskDetail adds the assessment to an audit entry detail and returns it.
//
// The audit entry carries the same level, reasons and score as the claim, from
// the same value, so an operator reading the entry sees exactly what the
// application was told. It is written as a nested object rather than as three
// flat keys so that its shape matches the claim's.
func riskDetail(detail map[string]any, a *risk.Assessment) map[string]any {
	if a == nil {
		return detail
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["risk"] = map[string]any{
		"level":   string(a.Level),
		"reasons": a.Reasons,
		"score":   a.Score,
	}
	return detail
}

// withRisk returns resp with the unsigned risk fields set from a.
//
// They repeat the risk claim for a caller that wants to look without verifying
// first. Nothing may be decided on them: they are ordinary JSON in a response
// body, so anything on the network path can rewrite them, and a caller that
// reads its step-up policy out of the body has thrown away the reason the
// assertion is signed at all. See the field comments on assertionResponse.
func (resp assertionResponse) withRisk(a *risk.Assessment) assertionResponse {
	if a == nil {
		return resp
	}
	resp.RiskLevel = a.Level
	resp.RiskReasons = a.Reasons
	return resp
}

// reportHighRisk raises an alert when an authentication was assessed high.
//
// Only high. Elevated is common enough that alerting on it would bury the rest
// of the stream, and it is already in the audit log and in the claim the
// application acted on.
//
// The authentication has already succeeded when this runs, and a failure to
// record the alert must not change that: it is logged and the request carries
// on, as everywhere else in this service.
func (s *Server) reportHighRisk(r *http.Request, tenantID, subjectID string, a *risk.Assessment) {
	if a == nil || a.Level != risk.LevelHigh || s.deps.Alerts == nil {
		return
	}
	reasons := make([]string, 0, len(a.Reasons))
	for _, reason := range a.Reasons {
		reasons = append(reasons, string(reason))
	}
	if _, err := s.deps.Alerts.RiskHigh(r.Context(), tenantID, subjectID, a.Score, reasons); err != nil {
		s.deps.Logger.WarnContext(r.Context(), "high risk alert not raised")
	}
}
