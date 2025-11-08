package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// adminContext is the common preamble of every administrative handler.
//
// It establishes the caller and the tenant together, because an administrative
// operation that resolved one without the other would be able to act on rows it
// does not own.
func (s *Server) adminContext(r *http.Request) (*Caller, string, error) {
	caller, err := requireCaller(r.Context())
	if err != nil {
		return nil, "", err
	}
	if !caller.IsAdmin() {
		return nil, "", Forbidden(errors.New("route requires an administrative token"))
	}
	tenantID, err := s.callerTenant(caller)
	if err != nil {
		return nil, "", err
	}
	return caller, tenantID, nil
}

// pathID reads and validates an identifier from the path.
//
// Validating the shape here means a malformed identifier is refused before it
// reaches a query, so an unauthenticated shape of rubbish cannot generate
// database load.
func pathID(r *http.Request, name string) (string, error) {
	v := r.PathValue(name)
	if v == "" {
		return "", BadRequest("the "+name+" path segment is missing", nil)
	}
	if _, err := uuid.Parse(v); err != nil {
		return "", BadRequest("the "+name+" path segment is not a valid identifier", err)
	}
	return v, nil
}

// queryLimit reads a page size, applying the configured cap.
func (s *Server) queryLimit(r *http.Request, def int) int {
	max := s.deps.Config.Audit.MaxQueryLimit
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// adminSubjectView is what the administrative surface discloses about a
// subject.
//
// The reference the integrating application supplied is included only when the
// caller asks for it and holds the permission, and reading it is audited. It is
// the one operation that turns a row back into something identifying a person,
// so it is not part of a routine listing.
type adminSubjectView struct {
	SubjectID     string                `json:"subject_id"`
	Status        store.SubjectStatus   `json:"status"`
	DisplayName   string                `json:"display_name,omitempty"`
	SubjectRef    string                `json:"subject_ref,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	DeletedAt     *time.Time            `json:"deleted_at,omitempty"`
	Credentials   []*store.Credential   `json:"credentials,omitempty"`
	TOTPEnrolled  bool                  `json:"totp_enrolled"`
	RecoveryCodes int                   `json:"recovery_codes_remaining"`
	Erasure       *store.ErasureRequest `json:"erasure,omitempty"`
}

// handleAdminListSubjects pages through subjects.
//
// There is no substring search on the application's reference. The reference is
// encrypted at rest precisely so that it cannot be scanned, and offering a
// search that decrypted every row to match a pattern would undo that. A caller
// looking for one person supplies the exact reference instead.
func (s *Server) handleAdminListSubjects(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	f := store.SubjectFilter{
		AfterID: r.URL.Query().Get("after"),
		Limit:   s.queryLimit(r, 50),
	}
	if st := r.URL.Query().Get("status"); st != "" {
		f.Status = store.SubjectStatus(st)
	}
	if ref := r.URL.Query().Get("subject_ref"); ref != "" {
		if err := s.deps.Subjects.ValidateRef(ref); err != nil {
			return BadRequest("subject_ref is not acceptable: "+err.Error(), err)
		}
		f.RefHMAC = s.deps.Subjects.RefHMAC(ref)
	}

	subjects, err := s.deps.Store.ListSubjects(r.Context(), tenantID, f)
	if err != nil {
		return Internal(err)
	}

	views := make([]adminSubjectView, 0, len(subjects))
	for _, sub := range subjects {
		views = append(views, adminSubjectView{
			SubjectID:   sub.ID,
			Status:      sub.Status,
			DisplayName: sub.DisplayName,
			CreatedAt:   sub.CreatedAt,
			UpdatedAt:   sub.UpdatedAt,
			DeletedAt:   sub.DeletedAt,
		})
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: "admin.subjects_listed",
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"returned": len(views)},
	})

	next := ""
	if len(views) == f.Limit && len(views) > 0 {
		next = views[len(views)-1].SubjectID
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{
		"subjects": views,
		"next":     next,
	})
	return nil
}

// handleAdminGetSubject returns one subject with its enrolled factors.
func (s *Server) handleAdminGetSubject(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	sub, err := s.deps.Store.GetSubject(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	creds, err := s.deps.Store.ListCredentials(r.Context(), tenantID, sub.ID, true)
	if err != nil {
		return Internal(err)
	}
	codes, err := s.deps.Store.CountUnusedRecoveryCodes(r.Context(), tenantID, sub.ID)
	if err != nil {
		return Internal(err)
	}

	view := adminSubjectView{
		SubjectID:     sub.ID,
		Status:        sub.Status,
		DisplayName:   sub.DisplayName,
		CreatedAt:     sub.CreatedAt,
		UpdatedAt:     sub.UpdatedAt,
		DeletedAt:     sub.DeletedAt,
		Credentials:   creds,
		RecoveryCodes: codes,
	}

	if _, err := s.deps.Store.GetActiveTOTPSecret(r.Context(), tenantID, sub.ID); err == nil {
		view.TOTPEnrolled = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return Internal(err)
	}

	if er, err := s.deps.Store.GetErasureBySubject(r.Context(), tenantID, sub.ID); err == nil {
		view.Erasure = er
	} else if !errors.Is(err, store.ErrNotFound) {
		return Internal(err)
	}

	// Revealing the application's reference is a separate, audited act rather
	// than part of reading the record.
	if r.URL.Query().Get("reveal_ref") == "true" {
		// No second permission check here. The route is already guarded by
		// subject.read, and a duplicate check would have to decide for itself
		// whether the role model is enabled, which is exactly the kind of
		// second code path that drifts from the first.
		ref, err := s.deps.Subjects.RevealRef(sub)
		if err != nil {
			// A subject created while seal_reference was off has nothing to
			// reveal. That is a configuration consequence, not a fault.
			s.deps.Logger.WarnContext(r.Context(), "subject reference could not be revealed")
		} else {
			view.SubjectRef = ref
			s.audited(r, audit.Event{
				TenantID: tenantID, EventType: "admin.subject_ref_revealed",
				ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
				SubjectID: sub.ID, ResourceType: "subject", ResourceID: sub.ID,
				Outcome: store.OutcomeSuccess,
			})
		}
	}

	WriteJSON(w, r, http.StatusOK, view)
	return nil
}

// statusChangeRequest is the body of the lock and unlock routes.
type statusChangeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleAdminLockSubject stops a subject authenticating.
func (s *Server) handleAdminLockSubject(w http.ResponseWriter, r *http.Request) error {
	return s.changeSubjectStatus(w, r, store.SubjectLocked, audit.EventSubjectLocked)
}

// handleAdminUnlockSubject lets a locked subject authenticate again.
//
// Unlocking is distinct from resetting a throttle. A lock is an operator
// decision and persists; a throttle lockout is automatic and expires. An
// operator helping a user who cannot log in usually wants the throttle reset,
// which is why both exist.
func (s *Server) handleAdminUnlockSubject(w http.ResponseWriter, r *http.Request) error {
	return s.changeSubjectStatus(w, r, store.SubjectActive, audit.EventSubjectUnlocked)
}

func (s *Server) changeSubjectStatus(w http.ResponseWriter, r *http.Request, status store.SubjectStatus, eventType string) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	var req statusChangeRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
	}

	if err := s.deps.Store.SetSubjectStatus(r.Context(), tenantID, id, status); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: eventType,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: id, ResourceType: "subject", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"status": string(status), "reason": req.Reason},
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"subject_id": id,
		"status":     status,
	})
	return nil
}

// handleAdminListCredentials lists a subject's authenticators, revoked ones
// included.
func (s *Server) handleAdminListCredentials(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	creds, err := s.deps.Store.ListCredentials(r.Context(), tenantID, id, true)
	if err != nil {
		return Internal(err)
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"credentials": creds})
	return nil
}

// revokeRequest is the body of the credential revoke route.
type revokeRequest struct {
	Reason string `json:"reason"`

	// AllowLast permits revoking a subject's only remaining credential, which
	// is refused by default because it locks the user out with no way back
	// except a recovery code.
	AllowLast bool `json:"allow_last,omitempty"`
}

// handleAdminRevokeCredential revokes one authenticator.
//
// Revocation is final. There is deliberately no un-revoke: a credential is
// revoked because it is believed compromised, and a window in which that can be
// reversed is a window in which the compromised credential can be restored.
// Protection against a mistaken bulk revocation comes from the rate limit
// applied to this route and the alert above the threshold, not from
// reversibility. See docs/adr/0010.
func (s *Server) handleAdminRevokeCredential(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}
	credentialID, err := pathID(r, "credential_id")
	if err != nil {
		return err
	}

	var req revokeRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
	}
	if strings.TrimSpace(req.Reason) == "" {
		// A revocation with no stated reason is an audit entry nobody can act
		// on later, so the reason is required rather than optional.
		return BadRequest("reason is required", nil)
	}

	// The revoke route is rate limited per administrator. This is the control
	// that replaces the reversible revocation the specification asked for: a
	// rogue or mistaken script is stopped after the burst rather than allowed
	// to empty the table and be undone afterwards.
	dims := map[throttle.Dimension]string{throttle.DimAdminRevoke: caller.ActorID()}
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	cred, err := s.deps.Store.GetCredential(r.Context(), tenantID, credentialID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}
	if cred.SubjectID != subjectID {
		// The credential exists but under a different subject. Reported as
		// absent, so the route cannot be used to discover which subject owns a
		// given credential.
		return NotFound(errors.New("credential belongs to a different subject"))
	}
	if cred.Revoked() {
		return Conflict("the credential is already revoked", nil)
	}

	active, err := s.deps.Store.CountActiveCredentials(r.Context(), tenantID, subjectID)
	if err != nil {
		return Internal(err)
	}
	if active <= 1 && !req.AllowLast {
		return Conflict("this is the subject's only remaining authenticator; "+
			"set allow_last to revoke it anyway, and make sure the user holds "+
			"recovery codes first", nil)
	}

	if err := s.deps.Store.RevokeCredential(r.Context(), tenantID, credentialID,
		req.Reason, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	// The limiter is guarded because a Server can legitimately be built
	// without one, which every other call site already accounts for. An
	// unguarded call here would panic on a credential revocation in exactly
	// that configuration.
	if s.deps.Limiter != nil {
		res, limitErr := s.deps.Limiter.Record(r.Context(), tenantID, dims, false)
		if limitErr != nil {
			s.deps.Logger.WarnContext(r.Context(), "revocation not recorded against throttle",
				slog.Any("error", limitErr))
		} else if !res.Allowed && s.deps.Alerts != nil {
			if _, err := s.deps.Alerts.BulkRevocation(r.Context(), tenantID, caller.ActorID(),
				res.Attempts, s.deps.Config.Throttle.AdminRevokeBurst); err != nil {
				s.deps.Logger.WarnContext(r.Context(), "bulk revocation alert not raised",
					slog.Any("error", err))
			}
		}
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventCredentialRevoked,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: subjectID, ResourceType: "credential", ResourceID: credentialID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"reason":              req.Reason,
			"remaining_active":    active - 1,
			"was_last_credential": active <= 1,
		},
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"credential_id":    credentialID,
		"revoked":          true,
		"remaining_active": active - 1,
	})
	return nil
}

// handleAdminReissueRecovery issues a fresh batch of recovery codes.
//
// The codes are returned here and nowhere else. An operator running this on
// behalf of a user has to transmit them out of band, which is why the response
// says so rather than leaving it implied.
func (s *Server) handleAdminReissueRecovery(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	sub, err := s.deps.Store.GetSubject(r.Context(), tenantID, subjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	codes, err := recovery.Generate(s.deps.Config.Recovery.CodeCount)
	if err != nil {
		return Internal(err)
	}

	batchID := uuid.NewString()
	now := s.now().UTC()
	records := make([]*store.RecoveryCode, 0, len(codes))
	display := make([]string, 0, len(codes))
	for _, c := range codes {
		records = append(records, &store.RecoveryCode{
			ID: uuid.NewString(), TenantID: tenantID, SubjectID: sub.ID,
			BatchID: batchID, Selector: c.Selector, VerifierHash: c.Hash,
			CreatedAt: now,
		})
		display = append(display, c.Display)
	}

	if err := s.deps.Store.ReplaceRecoveryCodes(r.Context(), tenantID, sub.ID, batchID, records); err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventRecoveryIssued,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "recovery_batch", ResourceID: batchID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"count": len(display), "reissued_by_operator": true},
	})

	WriteJSON(w, r, http.StatusCreated, recoveryIssueResponse{
		BatchID: batchID, Codes: display, Count: len(display),
		Warning: "these codes are shown once and cannot be retrieved again; " +
			"transmit them to the user over a channel you trust, and any unused " +
			"codes from a previous batch have been retired",
	})
	return nil
}

// handleAdminResetThrottle clears a subject's rate-limit state.
//
// This is the operation behind a user reporting that they are locked out. It is
// separate from unlocking a subject: a throttle lockout is automatic and
// temporary, a lock is a deliberate operator decision.
func (s *Server) handleAdminResetThrottle(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	if s.deps.Limiter != nil {
		if err := s.deps.Limiter.ResetSubject(r.Context(), tenantID, subjectID); err != nil {
			return Internal(err)
		}
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventThrottleReset,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: subjectID, ResourceType: "subject", ResourceID: subjectID,
		Outcome: store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"subject_id": subjectID,
		"reset":      true,
	})
	return nil
}

// erasureRequestBody is the body of the erasure route.
type erasureRequestBody struct {
	Reason string `json:"reason"`
}

// handleAdminRequestErasure starts a GDPR Article 17 erasure.
//
// Erasure is two-phase when deferred_erasure is on. The subject is blocked from
// authenticating at once and the record is purged after the retention window.
// An immediate hard delete would destroy the evidence that the erasure was
// legitimate, and would hand anyone who obtained one administrative token a way
// to wipe accounts irreversibly.
func (s *Server) handleAdminRequestErasure(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	var req erasureRequestBody
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
	}

	sub, err := s.deps.Store.GetSubject(r.Context(), tenantID, subjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	// Erasure is one of the operations that can be held for a second
	// administrator, because it destroys data and cannot be undone once the
	// window closes.
	if held, err := s.approvalGate(r, caller, tenantID, "subject.erase",
		map[string]any{"subject_id": sub.ID, "reason": req.Reason}, req.Reason); held {
		return err
	}

	now := s.now().UTC()
	retention := s.deps.Config.Features.ErasureRetention.Duration
	if !s.deps.Config.Features.DeferredErasure {
		retention = 0
	}

	er := &store.ErasureRequest{
		ID: uuid.NewString(), TenantID: tenantID, SubjectID: sub.ID,
		Status: store.ErasurePending, Reason: req.Reason,
		RequestedBy: caller.ActorID(), RequestedAt: now,
		PurgeAfter: now.Add(retention),
	}
	if err := s.deps.Store.CreateErasure(r.Context(), er); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Conflict("an erasure request is already pending for this subject", err)
		}
		return Internal(err)
	}

	// The subject stops authenticating immediately, which is the part of
	// Article 17 that cannot wait for the retention window.
	if err := s.deps.Store.SoftDeleteSubject(r.Context(), tenantID, sub.ID, now); err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventErasureRequested,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "erasure_request", ResourceID: er.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"reason":      req.Reason,
			"purge_after": er.PurgeAfter,
			"deferred":    s.deps.Config.Features.DeferredErasure,
		},
	})

	WriteJSON(w, r, http.StatusAccepted, er)
	return nil
}

// handleAdminCancelErasure withdraws a pending erasure.
//
// It works only inside the retention window, which is the window's purpose: a
// request made in error, or withdrawn by the person who made it, can be undone
// before anything is destroyed. Once purged there is nothing to restore.
func (s *Server) handleAdminCancelErasure(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	er, err := s.deps.Store.GetErasureBySubject(r.Context(), tenantID, subjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}
	if er.Status != store.ErasurePending {
		return Conflict("the erasure request is "+string(er.Status)+" and cannot be cancelled", nil)
	}

	now := s.now().UTC()
	if err := s.deps.Store.CancelErasure(r.Context(), tenantID, er.ID, caller.ActorID(), now); err != nil {
		if errors.Is(err, store.ErrStaleWrite) {
			return Conflict("the erasure request is no longer pending", err)
		}
		return Internal(err)
	}
	// Restoring is the other half of cancelling. Without it the request would
	// be withdrawn while the subject stayed blocked, which is the worst of both
	// outcomes: nothing is erased and the user still cannot sign in.
	if err := s.deps.Store.RestoreSubject(r.Context(), tenantID, subjectID, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Conflict("the erasure was cancelled but the subject is no longer "+
				"pending deletion, so there was nothing to restore", err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventErasureCancelled,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: subjectID, ResourceType: "erasure_request", ResourceID: er.ID,
		Outcome: store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"erasure_id": er.ID,
		"cancelled":  true,
	})
	return nil
}

// handleAdminQueryAudit reads the append-only log.
func (s *Server) handleAdminQueryAudit(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	q := r.URL.Query()
	f := store.AuditFilter{
		EventType: q.Get("event_type"),
		SubjectID: q.Get("subject_id"),
		ActorID:   q.Get("actor_id"),
		Outcome:   store.Outcome(q.Get("outcome")),
		Limit:     s.queryLimit(r, 100),
	}
	if v := q.Get("after_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return BadRequest("after_seq must be an integer", err)
		}
		f.AfterSeq = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return BadRequest("since must be an RFC 3339 timestamp", err)
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return BadRequest("until must be an RFC 3339 timestamp", err)
		}
		f.Until = t
	}

	entries, err := s.deps.Store.QueryAudit(r.Context(), tenantID, f)
	if err != nil {
		return Internal(err)
	}

	next := int64(0)
	if len(entries) == f.Limit && len(entries) > 0 {
		next = entries[len(entries)-1].Seq
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{
		"entries":  entries,
		"next_seq": next,
		"limit":    f.Limit,
	})
	return nil
}

// handleAdminVerifyAudit recomputes the hash chain.
//
// This is the operation that makes the chain worth having. It reports whether
// the log has been altered since it was written, and the result is itself
// recorded, so a verification run cannot be performed quietly.
func (s *Server) handleAdminVerifyAudit(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	from := int64(1)
	if v := r.URL.Query().Get("from_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return BadRequest("from_seq must be a positive integer", err)
		}
		from = n
	}

	checked, brokenAt, err := s.deps.Recorder.Verify(r.Context(), tenantID, from)
	if err != nil {
		return Internal(err)
	}

	if brokenAt != 0 && s.deps.Alerts != nil {
		if _, err := s.deps.Alerts.AuditChainBroken(r.Context(), tenantID, brokenAt); err != nil {
			s.deps.Logger.ErrorContext(r.Context(), "audit chain alert not raised")
		}
	}

	status := http.StatusOK
	if brokenAt != 0 {
		// A broken chain is not a client error, but returning 200 would let a
		// monitoring check that only looks at the status code miss it.
		status = http.StatusConflict
	}
	WriteJSON(w, r, status, map[string]any{
		"from_seq":  from,
		"checked":   checked,
		"intact":    brokenAt == 0,
		"broken_at": brokenAt,
	})
	return nil
}

// handleAdminListAlerts reads open alerts.
func (s *Server) handleAdminListAlerts(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	q := r.URL.Query()
	f := store.AlertFilter{
		Severity:     store.Severity(q.Get("severity")),
		AlertType:    q.Get("alert_type"),
		SubjectID:    q.Get("subject_id"),
		IncludeAcked: q.Get("include_acknowledged") == "true",
		AfterID:      q.Get("after"),
		Limit:        s.queryLimit(r, 50),
	}

	list, err := s.deps.Store.ListAlerts(r.Context(), tenantID, f)
	if err != nil {
		return Internal(err)
	}
	counts, err := s.deps.Store.CountOpenAlerts(r.Context(), tenantID)
	if err != nil {
		return Internal(err)
	}

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"alerts": list,
		"open":   counts,
	})
	return nil
}

// handleAdminAcknowledgeAlert closes an alert.
func (s *Server) handleAdminAcknowledgeAlert(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "alert_id")
	if err != nil {
		return err
	}

	if err := s.deps.Store.AcknowledgeAlert(r.Context(), tenantID, id,
		caller.ActorID(), s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAlertAcknowledged,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "alert", ResourceID: id,
		Outcome: store.OutcomeSuccess,
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{"alert_id": id, "acknowledged": true})
	return nil
}

// handleAdminListApprovals reads the dual-approval queue.
func (s *Server) handleAdminListApprovals(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	status := store.ApprovalStatus(r.URL.Query().Get("status"))
	if status == "" {
		status = store.ApprovalPending
	}

	list, err := s.deps.Store.ListApprovals(r.Context(), tenantID, status, s.queryLimit(r, 50))
	if err != nil {
		return Internal(err)
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"approvals": list})
	return nil
}

// approvalDecisionRequest is the body of the approve and reject routes.
type approvalDecisionRequest struct {
	Note string `json:"note,omitempty"`
}

// handleAdminApprove grants a queued operation.
func (s *Server) handleAdminApprove(w http.ResponseWriter, r *http.Request) error {
	return s.decideApproval(w, r, true)
}

// handleAdminReject refuses a queued operation.
func (s *Server) handleAdminReject(w http.ResponseWriter, r *http.Request) error {
	return s.decideApproval(w, r, false)
}

// decideApproval records a decision on a queued operation.
//
// The store refuses a decision by the administrator who raised the request. A
// two-administrator rule that one administrator can satisfy alone is not a
// control, so that check belongs in the same transaction as the state change
// rather than here where it could be bypassed by a second code path.
func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "approval_id")
	if err != nil {
		return err
	}

	var req approvalDecisionRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			return err
		}
	}

	decided, err := s.deps.Store.DecideApproval(r.Context(), tenantID, id,
		caller.ActorID(), approve, req.Note, s.now().UTC())
	switch {
	case errors.Is(err, store.ErrSelfApproval):
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventApprovalRejected,
			ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
			ResourceType: "approval_request", ResourceID: id,
			Outcome: store.OutcomeDenied,
			Detail:  map[string]any{"reason": "self approval"},
		})
		return Forbidden(err)
	case errors.Is(err, store.ErrStaleWrite):
		return Conflict("the request is no longer pending", err)
	case errors.Is(err, store.ErrNotFound):
		return NotFound(err)
	case err != nil:
		return Internal(err)
	}

	eventType := audit.EventApprovalGranted
	if !approve {
		eventType = audit.EventApprovalRejected
	}
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: eventType,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "approval_request", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"operation":    decided.Operation,
			"requested_by": decided.RequestedBy,
			"note":         req.Note,
		},
	})

	WriteJSON(w, r, http.StatusOK, decided)
	return nil
}

// ApprovalHeader carries the identifier of an approved request being redeemed.
//
// It is a header rather than a body field because the routes it applies to have
// different bodies, and because the body is part of what the approval is bound
// to: putting the identifier inside it would make the bound content depend on
// the thing that references it.
const ApprovalHeader = "X-Approval-Id"

// approvalGate decides whether a sensitive operation may run now.
//
// Dual approval is modelled as a capability rather than as a deferred job. The
// first request queues the operation and performs nothing. A second, different
// administrator approves it. The original requester then repeats the identical
// request with the approval identifier, and only that redemption executes.
//
// The alternative, executing at the moment of approval, has two problems. The
// result would be delivered to the approver rather than to the person who asked,
// which for a freshly minted token means the secret reaches the wrong
// administrator. And the executor would need a second implementation of every
// operation, reachable from a different code path with different checks, which
// is where an authorisation rule eventually goes missing.
//
// A redemption is accepted only when all of the following hold, and each check
// closes a specific abuse:
//
//   - the approval names the same operation, so an approval for one action
//     cannot be spent on another
//   - the redeemer is the original requester, so an approval cannot be stolen
//   - the payload equals the approved payload, so what runs is what the second
//     administrator actually read
//   - it has not expired, so an old approval cannot be held in reserve
//   - the conditional update from approved to executed succeeds, so it is
//     spent exactly once even under concurrent redemption
//
// The claim happens before the operation runs. If the operation then fails the
// approval is spent anyway and a new request is needed. Failing closed costs an
// administrator a repeated request; failing open would let one approval run an
// operation twice.
//
// held reports that the caller must stop and return err. When held is false the
// operation may proceed.
func (s *Server) approvalGate(r *http.Request, caller *Caller, tenantID, operation string, payload map[string]any, reason string) (held bool, err error) {
	if !s.deps.Config.Features.DualApproval {
		return false, nil
	}
	if !slicesContains(s.deps.Config.Features.DualApprovalOperations, operation) {
		return false, nil
	}

	if id := r.Header.Get(ApprovalHeader); id != "" {
		if err := s.redeemApproval(r, caller, tenantID, id, operation, payload); err != nil {
			return true, err
		}
		return false, nil
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return true, Internal(fmt.Errorf("marshal approval payload: %w", err))
	}

	now := s.now().UTC()
	req := &store.ApprovalRequest{
		ID: uuid.NewString(), TenantID: tenantID, Operation: operation,
		Payload: raw, Reason: reason, Status: store.ApprovalPending,
		RequestedBy: caller.ActorID(), RequestedAt: now,
		ExpiresAt: now.Add(s.deps.Config.Features.ApprovalTTL.Duration),
	}
	if err := s.deps.Store.CreateApproval(r.Context(), req); err != nil {
		return true, Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventApprovalRequested,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "approval_request", ResourceID: req.ID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"operation": operation, "reason": reason},
	})

	return true, ApprovalRequired("queued as approval request " + req.ID +
		"; once a different administrator approves it, repeat this exact request " +
		"with the header " + ApprovalHeader + ": " + req.ID)
}

// redeemApproval spends an approved request. See approvalGate for the rules.
func (s *Server) redeemApproval(r *http.Request, caller *Caller, tenantID, id, operation string, payload map[string]any) error {
	if _, err := uuid.Parse(id); err != nil {
		return BadRequest(ApprovalHeader+" is not a valid identifier", err)
	}

	refuse := func(reason string) error {
		s.audited(r, audit.Event{
			TenantID: tenantID, EventType: audit.EventApprovalRejected,
			ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
			ResourceType: "approval_request", ResourceID: id,
			Outcome: store.OutcomeDenied,
			Detail:  map[string]any{"operation": operation, "reason": reason},
		})
		// One response for every refusal. Telling a caller which check failed
		// would let them probe for another administrator's approvals.
		return Forbidden(errors.New("approval redemption refused: " + reason))
	}

	req, err := s.deps.Store.GetApproval(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refuse("unknown approval")
		}
		return Internal(err)
	}

	switch {
	case req.Operation != operation:
		return refuse("approval is for a different operation")
	case !strings.EqualFold(strings.TrimSpace(req.RequestedBy), strings.TrimSpace(caller.ActorID())):
		return refuse("approval belongs to a different requester")
	case req.Status != store.ApprovalApproved:
		return refuse("approval is " + string(req.Status))
	case !s.now().UTC().Before(req.ExpiresAt):
		return refuse("approval has expired")
	case !samePayload(req.Payload, payload):
		return refuse("request differs from what was approved")
	}

	// The claim. Conditional on the status still being approved, so two
	// concurrent redemptions have exactly one winner.
	if err := s.deps.Store.MarkApprovalExecuted(r.Context(), tenantID, id, nil, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrStaleWrite) || errors.Is(err, store.ErrNotFound) {
			return refuse("approval was already spent")
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventApprovalExecuted,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "approval_request", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"operation":   operation,
			"approved_by": req.DecidedBy,
		},
	})
	return nil
}

// samePayload compares the approved payload with the one being redeemed as
// documents rather than as bytes.
//
// PostgreSQL stores the payload as JSONB and returns it with its own key order
// and spacing, so a byte comparison would refuse every legitimate redemption on
// that engine.
func samePayload(stored json.RawMessage, presented map[string]any) bool {
	var approved map[string]any
	if err := json.Unmarshal(stored, &approved); err != nil {
		return false
	}
	// Round-trip the presented payload through JSON as well, so both sides
	// have been through the same type coercion (every number a float64).
	raw, err := json.Marshal(presented)
	if err != nil {
		return false
	}
	var current map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		return false
	}
	return reflect.DeepEqual(approved, current)
}

// createKeyRequest is the body of both credential-minting routes.
type createKeyRequest struct {
	Name string `json:"name"`

	// Role applies to an administrative token only.
	Role store.Role `json:"role,omitempty"`

	// ExpiresInDays bounds the credential's life. Zero means no expiry, which
	// the response warns about rather than refuses: a long-lived key is
	// sometimes the only practical option for an integration that cannot
	// rotate.
	ExpiresInDays int `json:"expires_in_days,omitempty"`

	// Scopes applies to an API key only and restricts it to the named route
	// families: subjects, webauthn, totp, recovery, health. Empty means all.
	Scopes []string `json:"scopes,omitempty"`
}

// handleAdminCreateAPIKey mints a credential for an integrating application.
func (s *Server) handleAdminCreateAPIKey(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	var req createKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Name) == "" {
		return BadRequest("name is required", nil)
	}

	scopes, err := ValidateScopes(req.Scopes)
	if err != nil {
		return BadRequest(err.Error(), err)
	}
	req.Scopes = scopes

	tok, err := token.Generate(token.KindAPIKey)
	if err != nil {
		return Internal(err)
	}

	now := s.now().UTC()
	key := &store.APIKey{
		ID: uuid.NewString(), TenantID: tenantID, Name: req.Name,
		Selector: tok.Selector, VerifierHash: tok.Hash, Scopes: req.Scopes,
		CreatedAt: now, CreatedBy: caller.ActorID(),
	}
	if req.ExpiresInDays > 0 {
		exp := now.AddDate(0, 0, req.ExpiresInDays)
		key.ExpiresAt = &exp
	}

	if err := s.deps.Store.CreateAPIKey(r.Context(), key); err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAPIKeyCreated,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "api_key", ResourceID: key.ID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"name": req.Name, "expires_at": key.ExpiresAt},
	})

	// The token is returned once. Only its selector and a digest of its
	// verifier are stored, so there is no operation that can show it again.
	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"api_key":   key,
		"token":     tok.Display,
		"warning":   "this token is shown once and cannot be retrieved again",
		"no_expiry": key.ExpiresAt == nil,
		// An empty scope list means every route family. Saying so in the
		// response makes an unrestricted key a visible choice.
		"unrestricted": len(key.Scopes) == 0,
	})
	return nil
}

// handleAdminCreateAdminToken mints an administrative credential.
func (s *Server) handleAdminCreateAdminToken(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	var req createKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Name) == "" {
		return BadRequest("name is required", nil)
	}
	if !req.Role.Valid() {
		return BadRequest("role must be admin_full, admin_operator or admin_auditor", nil)
	}

	// Minting an administrative credential is the operation that grants
	// authority, so it is a candidate for the approval queue.
	if held, err := s.approvalGate(r, caller, tenantID, "admin_token.create",
		map[string]any{"name": req.Name, "role": string(req.Role)}, ""); held {
		return err
	}

	tok, err := token.Generate(token.KindAdmin)
	if err != nil {
		return Internal(err)
	}

	now := s.now().UTC()
	at := &store.AdminToken{
		ID: uuid.NewString(), TenantID: tenantID, Name: req.Name,
		Selector: tok.Selector, VerifierHash: tok.Hash, Role: req.Role,
		CreatedAt: now, CreatedBy: caller.ActorID(),
	}
	if req.ExpiresInDays > 0 {
		exp := now.AddDate(0, 0, req.ExpiresInDays)
		at.ExpiresAt = &exp
	}

	if err := s.deps.Store.CreateAdminToken(r.Context(), at); err != nil {
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAdminTokenCreated,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "admin_token", ResourceID: at.ID,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"name": req.Name, "role": string(req.Role)},
	})

	WriteJSON(w, r, http.StatusCreated, map[string]any{
		"admin_token": at,
		"token":       tok.Display,
		"warning":     "this token is shown once and cannot be retrieved again",
	})
	return nil
}

// handleAdminListAPIKeys lists the credentials of integrating applications.
func (s *Server) handleAdminListAPIKeys(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	keys, err := s.deps.Store.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		return Internal(err)
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"api_keys": keys})
	return nil
}

// handleAdminListAdminTokens lists administrative credentials.
func (s *Server) handleAdminListAdminTokens(w http.ResponseWriter, r *http.Request) error {
	_, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	tokens, err := s.deps.Store.ListAdminTokens(r.Context(), tenantID)
	if err != nil {
		return Internal(err)
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"admin_tokens": tokens})
	return nil
}

// handleAdminRevokeAPIKey revokes an application credential.
func (s *Server) handleAdminRevokeAPIKey(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "key_id")
	if err != nil {
		return err
	}

	if err := s.deps.Store.RevokeAPIKey(r.Context(), tenantID, id, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAPIKeyRevoked,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "api_key", ResourceID: id,
		Outcome: store.OutcomeSuccess,
	})
	WriteJSON(w, r, http.StatusOK, map[string]any{"api_key_id": id, "revoked": true})
	return nil
}

// handleAdminRevokeAdminToken revokes an administrative credential.
//
// The last usable full administrator cannot be revoked. A deployment with no
// administrator left has no way to mint one, so the service would become
// permanently unadministrable, and the recovery would be editing the database
// by hand.
func (s *Server) handleAdminRevokeAdminToken(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	id, err := pathID(r, "token_id")
	if err != nil {
		return err
	}

	tokens, err := s.deps.Store.ListAdminTokens(r.Context(), tenantID)
	if err != nil {
		return Internal(err)
	}
	var target *store.AdminToken
	for _, t := range tokens {
		if t.ID == id {
			target = t
			break
		}
	}
	if target == nil || target.RevokedAt != nil {
		return NotFound(errors.New("admin token does not exist or is already revoked"))
	}

	if target.Role == store.RoleFull {
		count, err := s.deps.Store.CountAdminTokensByRole(r.Context(), tenantID, store.RoleFull)
		if err != nil {
			return Internal(err)
		}
		if count <= 1 {
			return Conflict("this is the last usable full administrator; mint a "+
				"replacement before revoking it, or the deployment becomes "+
				"unadministrable", nil)
		}
	}

	if err := s.deps.Store.RevokeAdminToken(r.Context(), tenantID, id, s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventAdminTokenRevoked,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "admin_token", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"role": string(target.Role)},
	})
	WriteJSON(w, r, http.StatusOK, map[string]any{"admin_token_id": id, "revoked": true})
	return nil
}

// slicesContains avoids taking a dependency for one membership test.
func slicesContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
