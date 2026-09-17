package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// bulkRevokeRequest is the body of the revoke-all route.
type bulkRevokeRequest struct {
	Reason string `json:"reason"`
}

// handleAdminRevokeAllCredentials revokes every authenticator of one subject.
//
// This is the response to a suspected account compromise. Every active WebAuthn
// credential and the TOTP secret are revoked in one store transaction, because
// revoking them one request at a time can stop half way and leave the attacker
// one working factor while the operator believes the account is closed.
//
// Recovery codes are deliberately left alone. They are the user's way back in,
// and revoking them here would turn every incident response into a permanent
// lockout. The response says how many remain, and warns when none do, because
// at that point the user cannot sign in until an operator reissues codes. An
// operator who believes the codes were taken as well reissues them, which
// retires the old batch.
//
// Revocation is final, as it is for a single credential. There is no un-revoke,
// for the reason given on handleAdminRevokeCredential.
func (s *Server) handleAdminRevokeAllCredentials(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}
	subjectID, err := pathID(r, "subject_id")
	if err != nil {
		return err
	}

	var req bulkRevokeRequest
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

	// The same per-administrator limit as the single revoke, on the same
	// bucket. A separate bucket would let a script that had exhausted one
	// route carry on through the other.
	dims := map[throttle.Dimension]string{throttle.DimAdminRevoke: caller.ActorID()}
	if err := s.checkThrottle(r, tenantID, dims); err != nil {
		return err
	}

	sub, err := s.deps.Store.GetSubject(r.Context(), tenantID, subjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return NotFound(err)
		}
		return Internal(err)
	}

	// Counted before anything changes. Revocation does not touch the codes, so
	// the figure is the same either side of it, and a failure to read it here
	// stops the request before an approval has been spent or a factor revoked.
	codes, err := s.deps.Store.CountUnusedRecoveryCodes(r.Context(), tenantID, sub.ID)
	if err != nil {
		return Internal(err)
	}

	// Held for a second administrator because it removes every factor a
	// subject holds in one call and cannot be undone.
	if held, err := s.approvalGate(r, caller, tenantID, "credential.revoke_bulk",
		map[string]any{"subject_id": sub.ID, "reason": req.Reason}, req.Reason); held {
		return err
	}

	credentials, totp, err := s.deps.Store.RevokeAllCredentials(r.Context(), tenantID, sub.ID,
		req.Reason, s.now().UTC())
	if err != nil {
		return Internal(err)
	}

	// One hit per call rather than one per authenticator. The limit bounds how
	// many subjects one administrator can cut off in a window, which is what a
	// single revoke with allow_last already amounts to; counting every
	// authenticator would lock the administrator out after the first subject,
	// in the middle of the incident the route exists for.
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
		TenantID: tenantID, EventType: audit.EventCredentialBulkRevoked,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		SubjectID: sub.ID, ResourceType: "subject", ResourceID: sub.ID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"reason":                   req.Reason,
			"credentials_revoked":      credentials,
			"totp_revoked":             totp,
			"recovery_codes_remaining": codes,
		},
	})

	body := map[string]any{
		"subject_id":               sub.ID,
		"credentials_revoked":      credentials,
		"totp_revoked":             totp,
		"recovery_codes_remaining": codes,
	}
	if codes == 0 {
		body["warning"] = "the subject holds no unused recovery codes and is now locked " +
			"out; they cannot sign in until an operator reissues recovery codes and " +
			"transmits them over a channel you trust"
	}
	WriteJSON(w, r, http.StatusOK, body)
	return nil
}

// rewrapPageSize is how many sealed records one page of a rewrap pass reads.
// It bounds how much sealed material is held in memory at once, and how long
// the pass runs between two looks at the request context.
const rewrapPageSize = 200

// rewrapReport is the outcome of one rewrap pass, and the response body of the
// rewrap route.
type rewrapReport struct {
	CurrentVersion uint32 `json:"current_version"`
	Examined       int    `json:"examined"`
	Rewrapped      int    `json:"rewrapped"`
	AlreadyCurrent int    `json:"already_current"`
	Failed         int    `json:"failed"`

	// VersionsInUse lists the distinct key versions still referenced once the
	// pass has finished, in ascending order.
	VersionsInUse []uint32 `json:"versions_in_use"`
}

// handleAdminRewrapKEK moves every sealed record onto the current key.
//
// It is the second half of a key rotation. `n0passtemps-wizard kek rotate` adds
// a key version to the keyring file, but the records sealed under the previous
// version still name it, so without this pass the old key can never be retired
// and a rotation never finishes.
//
// The service reads the keyring once, at startup. After `wizard kek rotate` it
// has to be restarted before a rewrap can target the new version; until then
// the pass sees the old version as current and reports every record as already
// current, which is true of the running process and not of the file.
//
// versions_in_use is the operational answer. When it holds only
// current_version, and failed is zero, no stored record depends on an older key
// and the operator may delete the older versions from the keyring file. A
// record that could not be read at all has no version to report, which is why
// failed has to be zero as well.
//
// A record that fails to rewrap is counted and logged and the pass carries on.
// The response is 200 with the counts even then: a failure is usually one
// record whose key version has already left the keyring, and the operator
// needs the numbers to decide what to do about it more than they need a status
// code.
//
// The pass covers every tenant, because one keyring serves them all. It
// discloses nothing and leaves every plaintext as it was, so running it on
// behalf of the whole deployment crosses no tenant boundary that matters.
func (s *Server) handleAdminRewrapKEK(w http.ResponseWriter, r *http.Request) error {
	caller, tenantID, err := s.adminContext(r)
	if err != nil {
		return err
	}

	// Held for a second administrator because it rewrites key material for
	// every sealed record in the deployment.
	if held, err := s.approvalGate(r, caller, tenantID, "kek.rotate",
		map[string]any{"action": "rewrap"}, ""); held {
		return err
	}

	report, passErr := s.rewrapAll(r.Context(), s.deps.Sealer)

	detail := map[string]any{
		"current_version": report.CurrentVersion,
		"examined":        report.Examined,
		"rewrapped":       report.Rewrapped,
		"already_current": report.AlreadyCurrent,
		"failed":          report.Failed,
		"versions_in_use": report.VersionsInUse,
	}
	outcome := store.OutcomeSuccess
	if passErr != nil {
		// An interrupted pass has still rewritten the records it reached, so
		// it is recorded with what it did rather than not at all.
		outcome = store.OutcomeError
		detail["interrupted"] = true
	}
	s.audited(r, audit.Event{
		TenantID: tenantID, EventType: audit.EventKEKRewrapped,
		ActorType: store.ActorAdmin, ActorID: caller.ActorID(),
		ResourceType: "keyring",
		Outcome:      outcome,
		Detail:       detail,
	})
	if passErr != nil {
		return Internal(passErr)
	}

	WriteJSON(w, r, http.StatusOK, report)
	return nil
}

// rewrapAll walks every sealed record and moves those sealed under an older key
// version onto the sealer's current one.
//
// The sealer is a parameter rather than read from the dependencies so that the
// walk can be exercised against a keyring with several versions.
//
// An error is returned only when the pass cannot continue: the current version
// is unavailable, a page cannot be read, or the context was cancelled. The
// report returned with it covers the records reached before that point, and is
// not a statement about the rest.
func (s *Server) rewrapAll(ctx context.Context, sealer *envelope.Sealer) (rewrapReport, error) {
	report := rewrapReport{VersionsInUse: []uint32{}}

	current, err := sealer.CurrentVersion()
	if err != nil {
		return report, err
	}
	report.CurrentVersion = current

	inUse := make(map[uint32]struct{})
	finish := func() { report.VersionsInUse = sortedVersions(inUse) }

	for _, kind := range []store.SealedKind{store.SealedTOTP, store.SealedSubjectRef} {
		after := ""
		for {
			// Checked between pages. A caller who has gone away should not
			// keep a walk over the whole database running on their behalf.
			if err := ctx.Err(); err != nil {
				finish()
				return report, err
			}

			page, err := s.deps.Store.ListSealed(ctx, kind, after, rewrapPageSize)
			if err != nil {
				finish()
				return report, err
			}
			for _, rec := range page {
				s.rewrapOne(ctx, sealer, kind, rec, current, &report, inUse)
			}
			if len(page) < rewrapPageSize {
				break
			}
			after = page[len(page)-1].ID
		}
	}

	finish()
	return report, nil
}

// sortedVersions flattens the set of versions seen into ascending order, so the
// response is stable from one pass to the next and can be compared by eye.
func sortedVersions(set map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// rewrapOne handles a single record and accounts for it in the report.
//
// Log lines carry the record's identifier and key version and never its bytes.
// The sealed value is ciphertext, but a log is kept for longer and read by more
// people than the database, and nothing in it helps diagnose a failure.
func (s *Server) rewrapOne(ctx context.Context, sealer *envelope.Sealer, kind store.SealedKind, rec store.SealedRecord,
	current uint32, report *rewrapReport, inUse map[uint32]struct{}) {
	version, err := envelope.KEKVersion(rec.Sealed)
	if err != nil {
		// Not an envelope at all, so there is no version to report. It shows
		// up in failed, which is why an operator checks both figures before
		// retiring a key.
		report.Examined++
		report.Failed++
		s.deps.Logger.WarnContext(ctx, "sealed record is malformed and was not rewrapped",
			slog.String("kind", string(kind)), slog.String("id", rec.ID))
		return
	}

	if version == current {
		report.Examined++
		report.AlreadyCurrent++
		inUse[current] = struct{}{}
		return
	}

	failed := func(msg string, err error) {
		report.Examined++
		report.Failed++
		// The record still names the old version, so that version is still in
		// use and must not be retired.
		inUse[version] = struct{}{}
		s.deps.Logger.WarnContext(ctx, msg,
			slog.String("kind", string(kind)), slog.String("id", rec.ID),
			slog.Uint64("kek_version", uint64(version)), slog.Any("error", err))
	}

	replacement, err := sealer.Rewrap(rec.Sealed)
	if err != nil {
		failed("sealed record could not be rewrapped", err)
		return
	}

	switch err := s.deps.Store.ReplaceSealed(ctx, kind, rec.ID, rec.Sealed, replacement); {
	case err == nil:
		report.Examined++
		report.Rewrapped++
		inUse[current] = struct{}{}
	case errors.Is(err, store.ErrNotFound):
		// Purged while the pass was running. The row no longer references any
		// key, so it belongs in none of the counts.
	case errors.Is(err, store.ErrStaleWrite):
		// Resealed by another request between the read and the write. Its new
		// version is unknown here, so it is reported against the old one; the
		// next pass reads the new value and settles it.
		failed("sealed record changed during the pass and was left alone", err)
	default:
		failed("rewrapped record could not be written back", err)
	}
}
