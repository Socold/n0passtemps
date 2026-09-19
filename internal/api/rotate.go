package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
)

// rotateRequest is the body of both rotation routes. The body is optional, and
// an absent one means the configured grace and no expiry of the caller's
// choosing.
type rotateRequest struct {
	// Grace is how long the predecessor keeps working beside its successor,
	// as a Go duration such as "24h". Empty means features.rotation_grace.
	// "0s" stops the predecessor at once, which is the right answer when the
	// reason for rotating is that the credential leaked.
	Grace string `json:"grace,omitempty"`

	// ExpiresInDays bounds the successor's life, as it does when minting.
	// Zero means no expiry of the caller's choosing.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
}

// decodeRotateRequest reads the optional body.
//
// The test is for a length other than zero rather than above it. A chunked
// request reports a length of minus one, and skipping its body would discard a
// grace of "0s": the caller would believe a leaked credential was dead while
// it went on working for the configured default.
func decodeRotateRequest(r *http.Request) (rotateRequest, error) {
	var req rotateRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			return req, err
		}
	}
	return req, nil
}

// rotationGrace resolves the overlap for one rotation.
//
// The maximum is enforced per request as well as in configuration validation.
// The configured value is only a default, so checking it alone would leave the
// bound to whoever writes the request body.
func (s *Server) rotationGrace(raw string) (time.Duration, error) {
	if raw == "" {
		return s.deps.Config.Features.RotationGrace.Duration, nil
	}
	grace, err := time.ParseDuration(raw)
	if err != nil {
		return 0, BadRequest(`grace must be a duration such as "24h", or "0s" to stop the `+
			"predecessor at once", err)
	}
	if grace < 0 {
		return 0, BadRequest("grace must not be negative", nil)
	}
	if grace > config.MaxRotationGrace {
		return 0, BadRequest(fmt.Sprintf("grace is above the maximum of %s; an overlap that long "+
			"is two live credentials, not a rotation", config.MaxRotationGrace), nil)
	}
	return grace, nil
}

// predecessorCutoff returns the instant handed to the store and the instant the
// predecessor will in fact stop, which differ when the predecessor already
// expires sooner. The store applies the same rule; computing it here as well is
// what lets the response and the audit entry report the real instant rather
// than the requested one.
func predecessorCutoff(now time.Time, grace time.Duration, current *time.Time) (cutoff, effective time.Time) {
	cutoff = now.Add(grace)
	effective = cutoff
	if current != nil && current.Before(cutoff) {
		effective = *current
	}
	return cutoff, effective
}

// handleAdminRotateAPIKey replaces an application credential without downtime.
//
// Replacing a key used to mean minting a new one and revoking the old one, and
// the order forced a choice between two bad outcomes. Revoking first is an
// outage until the integration is redeployed. Minting first leaves two live
// keys and a revocation somebody has to remember, and the overlap that nobody
// remembers to close is how a key that was meant to be retired is still valid
// when it turns up in a leak a year later.
//
// Rotation makes the overlap explicit and self-closing. The successor carries
// the same name, scopes and tenant, and the predecessor is given an expiry of
// now plus the grace in the same store transaction, so there is no state in
// which the old key is unbounded and the new one exists.
//
// Three rules keep rotation from becoming a way round other controls:
//
//   - A predecessor that already expires sooner keeps its earlier expiry.
//     Rotating a credential never extends its life.
//   - The successor does not inherit the predecessor's expiry. It is a new
//     credential minted by an administrator who could mint one anyway, so it
//     takes expires_in_days from the body or has none, and the response says
//     which, as minting does.
//   - A revoked or expired key is refused. Rotating it would bring back, under
//     a fresh token, an integration somebody deliberately switched off.
func (s *Server) handleAdminRotateAPIKey(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "key_id")
	if err != nil {
		return err
	}
	req, err := decodeRotateRequest(r)
	if err != nil {
		return err
	}
	grace, err := s.rotationGrace(req.Grace)
	if err != nil {
		return err
	}

	keys, err := s.deps.Store.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		return Internal(err)
	}
	var predecessor *store.APIKey
	for _, k := range keys {
		if k.ID == id {
			predecessor = k
			break
		}
	}
	if predecessor == nil {
		return NotFound(errors.New("api key does not exist"))
	}

	now := s.now().UTC()
	if predecessor.RevokedAt != nil {
		return Conflict("the key is revoked and cannot be rotated; mint a new one instead", nil)
	}
	if !predecessor.Usable(now) {
		return Conflict("the key has already expired and cannot be rotated; mint a new one instead", nil)
	}

	tok, err := token.Generate(token.KindAPIKey)
	if err != nil {
		return Internal(err)
	}

	successor := &store.APIKey{
		ID: uuid.NewString(), TenantID: tenantID, Name: predecessor.Name,
		Selector: tok.Selector, VerifierHash: tok.Hash,
		// Copied, so the successor does not alias a slice owned by the row
		// that was read.
		Scopes:    append([]string(nil), predecessor.Scopes...),
		CreatedAt: now, CreatedBy: caller.ActorID(),
	}
	// Bounded exactly as minting is. A rotation is where a lifetime is most
	// often typed again, and a successor is a new credential whatever it
	// replaces.
	expiry, err := expiryFromDays(now, req.ExpiresInDays)
	if err != nil {
		return err
	}
	if expiry != nil {
		successor.ExpiresAt = expiry
	}

	cutoff, effective := predecessorCutoff(now, grace, predecessor.ExpiresAt)
	if err := s.deps.Store.RotateAPIKey(r.Context(), tenantID, predecessor.ID, successor, cutoff); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The key was live when it was read a moment ago, so the only way
			// to arrive here is a revocation that landed in between. The
			// store inserted nothing.
			return Conflict("the key was revoked while it was being rotated", err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAPIKeyRotated,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "api_key", ResourceID: predecessor.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"name":                   predecessor.Name,
			"predecessor_id":         predecessor.ID,
			"successor_id":           successor.ID,
			"grace":                  grace.String(),
			"predecessor_expires_at": effective,
			"successor_expires_at":   successor.ExpiresAt,
		},
	})

	// The token is returned once, exactly as when minting. If this response is
	// lost the successor cannot be recovered; the remedy is to rotate again,
	// which the grace window leaves time for.
	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"api_key":                successor,
		"token":                  tok.Display,
		"warning":                "this token is shown once and cannot be retrieved again",
		"no_expiry":              successor.ExpiresAt == nil,
		"unrestricted":           len(successor.Scopes) == 0,
		"predecessor_id":         predecessor.ID,
		"predecessor_expires_at": effective,
	})
	return nil
}

// handleAdminRotateOwnToken replaces the administrative token that made the
// request, and only that one.
//
// There is deliberately no route that rotates another administrator's token.
// The response to a rotation carries the successor credential, so rotating
// someone else's token would hand the caller that person's next credential,
// under that person's name and role. That is impersonation, and it would be
// available to anyone holding the permission. Replacing another
// administrator's token is a revocation followed by a mint, and the mint is
// approval-gated.
//
// Rotating one's own token changes no authority: the successor carries the same
// name and the same role, and the caller already held everything it grants. It
// is therefore not held for a second administrator, since there is nothing for
// the second administrator to weigh, and it is open to every role including
// admin_auditor. It is the one write an auditor may perform, because it touches
// nothing but the caller's own credential. Withholding it would mean an auditor
// whose token may have leaked has to wait on somebody else to replace it.
//
// For the same reason the successor may not outlive the token it replaces. An
// administrator who issued a token for thirty days decided how long its holder
// is trusted for, and a self-service route that answered with a token valid for
// ever would let the holder overrule that. The successor inherits the
// predecessor's original expiry, and expires_in_days may shorten it but not
// extend it. This differs from API key rotation on purpose: there the caller is
// a full administrator who could mint an unbounded key anyway.
//
// The last-administrator guard needs no special case. The successor is inserted
// in the same transaction that bounds the predecessor, so a rotation cannot
// leave a role with no usable token.
//
// A token that holds a console passkey is refused, because the passkey cannot
// be carried across; see the check in the body for what that would otherwise
// cost.
func (s *Server) handleAdminRotateOwnToken(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	req, err := decodeRotateRequest(r)
	if err != nil {
		return err
	}
	grace, err := s.rotationGrace(req.Grace)
	if err != nil {
		return err
	}

	// The predecessor is the token the middleware verified for this request.
	// No identifier is read from the path or the body, which is what makes
	// "only your own" a property of the route rather than a check that could
	// be got wrong.
	predecessor := caller.AdminToken
	now := s.now().UTC()

	// A console passkey enrolled for this token cannot follow it.
	//
	// The credential row names the token it signs in as, an authenticator may
	// be enrolled once per relying party, and there is no operation that moves
	// the row onto the successor. Rotating anyway would do two things, both
	// without saying so. The passkeys would go on working until the
	// predecessor's grace ran out and then stop, with nothing said at the
	// moment the decision was taken. And admin.passkey_required, which applies
	// to a token that holds a passkey, would stop applying: the successor holds
	// none, so whoever held the rotated token could paste it into the console
	// form and be let in without the key the deployment asked for. Refusing is
	// what keeps the requirement and the credentials together until the
	// rotation can carry them.
	passkeys, err := s.deps.Store.CountActiveAdminCredentials(r.Context(), tenantID, predecessor.ID)
	if err != nil {
		return Internal(err)
	}
	if passkeys > 0 {
		return Conflict(fmt.Sprintf("this token has %d console passkeys enrolled, and a passkey cannot "+
			"follow a token to its successor; withdraw them in the administration interface first, or ask "+
			"a full administrator to mint a replacement token and revoke this one", passkeys), nil)
	}

	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		return Internal(err)
	}

	successor := &store.AdminToken{
		ID: uuid.NewString(), TenantID: tenantID, Name: predecessor.Name,
		Selector: tok.Selector, VerifierHash: tok.Hash, Role: predecessor.Role,
		CreatedAt: now, CreatedBy: caller.ActorID(),
	}
	if predecessor.ExpiresAt != nil {
		inherited := *predecessor.ExpiresAt
		successor.ExpiresAt = &inherited
	}
	expiry, err := expiryFromDays(now, req.ExpiresInDays)
	if err != nil {
		return err
	}
	if expiry != nil {
		exp := *expiry
		if predecessor.ExpiresAt != nil && exp.After(*predecessor.ExpiresAt) {
			return BadRequest("expires_in_days would outlive the token being rotated, which expires at "+
				predecessor.ExpiresAt.UTC().Format(time.RFC3339)+
				"; a token cannot extend its own life", nil)
		}
		successor.ExpiresAt = &exp
	}

	cutoff, effective := predecessorCutoff(now, grace, predecessor.ExpiresAt)
	if err := s.deps.Store.RotateAdminToken(r.Context(), tenantID, predecessor.ID, successor, cutoff); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The token authenticated this very request, so it was revoked
			// while the request was in flight. The store inserted nothing.
			return Conflict("the token was revoked while it was being rotated", err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAdminTokenRotated,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "admin_token", ResourceID: predecessor.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"name":                   predecessor.Name,
			"role":                   string(predecessor.Role),
			"predecessor_id":         predecessor.ID,
			"successor_id":           successor.ID,
			"grace":                  grace.String(),
			"predecessor_expires_at": effective,
			"successor_expires_at":   successor.ExpiresAt,
		},
	})

	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"admin_token":            successor,
		"token":                  tok.Display,
		"warning":                "this token is shown once and cannot be retrieved again",
		"no_expiry":              successor.ExpiresAt == nil,
		"predecessor_id":         predecessor.ID,
		"predecessor_expires_at": effective,
	})
	return nil
}
