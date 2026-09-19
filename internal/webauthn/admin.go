package webauthn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	lib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/store"
)

// The console's ceremonies, kept in this file and apart from the subject ones.
//
// # What separates an administrative credential from a subject credential
//
// A passkey enrolled for an administrator must never authenticate a subject
// through /v1/webauthn, and a subject's passkey must never sign anybody into
// the console. The second direction is the dangerous one: it would make every
// enrolled user of the deployment an administrator. Three independent things
// stop both, and each would be enough on its own, which is the point of having
// three:
//
//  1. The rows live in different tables. The subject paths resolve a credential
//     through webauthn_credentials and never read admin_credentials; the console
//     resolves one through admin_credentials and never reads the other. A
//     forgotten predicate cannot reach across, because there is no predicate
//     that would. The same holds for the ceremony state: the console's
//     challenges are in admin_webauthn_challenges, so a challenge issued by one
//     surface cannot be spent on the other, which matters because a console
//     sign-in ceremony and a subject usernameless ceremony are otherwise
//     identical as rows.
//
//  2. The relying-party user handle is derived under a different domain
//     separator. An authenticator keys a discoverable credential on the relying
//     party and the user handle, so enrolling an administrative passkey on a key
//     that already holds a subject's passkey creates a second, distinct
//     credential rather than replacing the first, and the two can never have the
//     same credential identifier. A response is also checked against the handle
//     the service derives for the identity it resolved, so one assembled from
//     the two spaces is refused.
//
//  3. Neither registration will store a credential identifier that already
//     exists in the other table. Given (2) this should be unreachable, and
//     refusing on it is what turns "no credential is both" into a property of
//     what is stored rather than a consequence of how handles are built.
//
// # What a passkey does not carry
//
// Authority. The role comes from the admin_tokens row the credential names, and
// is read at sign-in from that row. A credential proves who is signing in and
// nothing about what they may do, which is why AdminCredential has no role
// field and why a completed ceremony returns the token rather than a role.

// ErrAdminTokenUnusable is returned when the administrative token a ceremony is
// for has been revoked, has expired or carries a role this build does not
// recognise.
//
// It is the counterpart of ErrSubjectInactive, and it exists for the same
// reason: a ceremony for an identity that cannot authenticate must fail before
// any credential is written or any signature is checked.
var ErrAdminTokenUnusable = errors.New("webauthn: administrative token cannot authenticate")

// adminUserHandle converts an administrative token identifier into the opaque
// byte sequence the specification calls for.
//
// The domain separator differs from the one in userHandle, and that difference
// is load-bearing rather than decorative. It guarantees the two handle spaces
// are disjoint: a subject handle is either the sixteen raw bytes of a UUID or a
// digest under "n0passtemps/user-handle/v1", and neither can equal a digest
// under the string below. An authenticator therefore treats an administrative
// enrolment as a different credential from any subject enrolment on the same
// key, and a response carrying a handle from the other space fails the handle
// comparison in CompleteAdminAssertion.
//
// The identifier is not personal data. It names a credential record, not a
// person, which is what makes it safe to publish to an authenticator; see
// subjectUser for why an application-supplied reference would not be.
func adminUserHandle(adminTokenID string) ([]byte, error) {
	if adminTokenID == "" {
		return nil, errors.New("webauthn: administrative token has no identifier")
	}
	sum := sha256.Sum256([]byte("n0passtemps/admin-user-handle/v1" + adminTokenID))
	return sum[:], nil
}

// newAdminUser builds the library user for an administrative token.
//
// The name shown while the operator confirms is the name they gave the token,
// so the browser's passkey list says which administrative sign-in a key belongs
// to. It is a label an operator chose for a credential and identifies no end
// user.
func newAdminUser(tok *store.AdminToken, creds []lib.Credential) (*subjectUser, error) {
	handle, err := adminUserHandle(tok.ID)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(tok.Name)
	if name == "" {
		name = "administrator-" + shortID(tok.ID)
	}
	return &subjectUser{
		id:          handle,
		name:        name,
		displayName: name,
		credentials: creds,
	}, nil
}

// adminCredentialWriter routes the bookkeeping of a completed console assertion
// to the administrative credential table.
//
// It is the reason recordAssertion takes a credentialWriter rather than using
// the store directly: the counter advance, the clone signal and the record of
// use are one implementation serving both credential families.
type adminCredentialWriter struct{ st store.Store }

// TouchCredential records that the administrative credential was used.
func (w adminCredentialWriter) TouchCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error {
	return w.st.TouchAdminCredential(ctx, tenantID, id, usedAt)
}

// MarkCloneWarning records a signature counter that failed to advance, which is
// the documented signal for two copies of one private key in use.
func (w adminCredentialWriter) MarkCloneWarning(ctx context.Context, tenantID, id string) error {
	return w.st.MarkAdminCredentialCloneWarning(ctx, tenantID, id)
}

// AdvanceSignCount moves the counter forward, compare-and-swap against
// expectedPrev so that two concurrent assertions cannot both advance it.
func (w adminCredentialWriter) AdvanceSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32,
	usedAt time.Time) error {
	return w.st.AdvanceAdminCredentialSignCount(ctx, tenantID, id, expectedPrev, next, usedAt)
}

// asCredentialView presents an administrative credential in the shape the
// ceremony helpers work on.
//
// It is a view for BindingHash, toLibCredential and recordAssertion, none of
// which has any business knowing which table a credential came from. SubjectID
// is left empty and is never read on this path: an administrative credential
// belongs to an administrative token and to no subject, which is the whole
// separation.
func asCredentialView(c *store.AdminCredential) *store.Credential {
	return &store.Credential{
		ID:              c.ID,
		TenantID:        c.TenantID,
		CredentialID:    c.CredentialID,
		PublicKey:       c.PublicKey,
		AAGUID:          c.AAGUID,
		AttestationType: c.AttestationType,
		Transports:      c.Transports,
		SignCount:       c.SignCount,
		CloneWarning:    c.CloneWarning,
		BackupEligible:  c.BackupEligible,
		BackupState:     c.BackupState,
		UserVerified:    c.UserVerified,
		BindingHash:     c.BindingHash,
		Label:           c.Label,
		RPID:            c.RPID,
		CreatedAt:       c.CreatedAt,
		LastUsedAt:      c.LastUsedAt,
		RevokedAt:       c.RevokedAt,
		RevokedReason:   c.RevokedReason,
	}
}

// BeginAdminRegistration starts the enrolment of a console passkey for one
// administrative token.
//
// The token is supplied by the caller and is the one that authenticated the
// request. There is deliberately no way to name a different token: the
// ceremony produces a credential that signs in as that token, so enrolling for
// somebody else would be handing yourself their sign-in, which is
// impersonation. That is the same reason internal/rbac offers rotation of the
// caller's own token and of nobody else's.
//
// The passkeys already enrolled for the token are excluded, so a key that is
// already registered cannot be registered twice and the browser can say why.
// It takes no label, unlike the subject registration. The label an operator
// types names the key on the console's own screen and is recorded on
// completion; the name the authenticator shows is the token's, so there is
// nothing for a label to change here.
func (s *Service) BeginAdminRegistration(ctx context.Context, tok *store.AdminToken) (*BeginRegistrationResult, error) {
	if !tok.Usable(s.now().UTC()) {
		return nil, ErrAdminTokenUnusable
	}

	existing, err := s.store.ListAdminCredentials(ctx, tok.TenantID, tok.ID, false)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list administrative credentials: %w", err)
	}
	// The per-identity cap is the one configured for a subject. There is no
	// separate setting because there is no separate question behind it: it
	// bounds how many authenticators one identity may accumulate, and an
	// administrator has no reason to hold more of them than a user does.
	if len(existing) >= s.cfg.MaxCredentialsPerSubject {
		return nil, fmt.Errorf("%w: %d of %d",
			ErrTooManyCredentials, len(existing), s.cfg.MaxCredentialsPerSubject)
	}

	exclude := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    c.CredentialID,
			Transport:       toTransports(c.Transports),
			AttestationType: string(c.AttestationType),
		})
	}

	user, err := newAdminUser(tok, nil)
	if err != nil {
		return nil, err
	}

	// A resident key is required rather than preferred, unlike the subject
	// registration. The console signs in without naming an administrator
	// first, because there is nothing for an operator to type that would name
	// one: the token itself is the thing they are trying not to paste. An
	// authenticator that cannot store a discoverable credential would enrol
	// successfully here and then never appear in a sign-in prompt, so it is
	// refused at enrolment where the operator can still do something about it.
	//
	// User verification is required for the same reason the usernameless
	// subject route requires it, and more so: the credential this ceremony
	// creates is the one that will later sign in with no other factor.
	creation, session, err := s.rp.BeginRegistration(user,
		lib.WithExclusions(exclude),
		lib.WithConveyancePreference(protocol.ConveyancePreference(s.cfg.AttestationPreference)),
		lib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin administrative registration: %w", err)
	}

	challengeID, expiresAt, err := s.persistAdminChallenge(ctx, tok.TenantID, tok.ID,
		store.CeremonyRegistration, session)
	if err != nil {
		return nil, err
	}

	return &BeginRegistrationResult{
		ChallengeID: challengeID,
		Options:     creation,
		ExpiresAt:   expiresAt,
	}, nil
}

// CompleteAdminRegistration finishes an enrolment and stores the credential.
//
// The response has to have been collected at the console's own origin, which is
// the one thing the library cannot check for this surface: it holds the relying
// party's whole origin list, and that list is the integrating application's.
// Enrolling a console passkey from a page served by the application would let
// that page decide which key opens the console.
func (s *Service) CompleteAdminRegistration(ctx context.Context, tok *store.AdminToken, challengeID string,
	credentialJSON []byte, label string) (*store.AdminCredential, error) {
	if !tok.Usable(s.now().UTC()) {
		return nil, ErrAdminTokenUnusable
	}

	challenge, session, err := s.consumeAdminChallenge(ctx, tok.TenantID, challengeID,
		store.CeremonyRegistration)
	if err != nil {
		return nil, err
	}

	// The challenge was issued for one administrative token. A completion
	// presented for another would let an operator graft a passkey of their own
	// onto a colleague's sign-in, which is the impersonation BeginAdminRegistration
	// refuses to offer a route to.
	if challenge.AdminTokenID != tok.ID {
		return nil, ErrCeremonyFailed
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}
	if err = s.checkAdminOrigin(parsed.Response.CollectedClientData.Origin); err != nil {
		return nil, err
	}

	user, err := newAdminUser(tok, nil)
	if err != nil {
		return nil, err
	}

	credential, err := s.rp.CreateCredential(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}

	if err := s.checkAuthenticatorModel(credential); err != nil {
		return nil, err
	}
	if err := s.checkAttestation(credential); err != nil {
		return nil, err
	}

	// The identifier must not already name an administrative credential, for
	// the reason it must not on the subject side, and must not name a subject
	// credential either. See the file comment: the second check is what makes
	// the disjointness of the two spaces a stored fact.
	if _, err := s.store.GetAdminCredentialByID(ctx, tok.TenantID, s.cfg.RPID, credential.ID); err == nil {
		return nil, ErrCredentialExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("webauthn: look up administrative credential: %w", err)
	}
	if _, err := s.store.GetCredentialByID(ctx, tok.TenantID, s.cfg.RPID, credential.ID); err == nil {
		return nil, ErrCredentialExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("webauthn: look up credential: %w", err)
	}

	// The per-identity cap is re-read here for the reason CompleteRegistration
	// re-reads it, and with the same limitation: it is not atomic, and the
	// definitive form of it is a count taken inside the insert, which belongs
	// to whoever owns the store.
	held, listErr := s.store.ListAdminCredentials(ctx, tok.TenantID, tok.ID, false)
	if listErr != nil {
		return nil, fmt.Errorf("webauthn: list administrative credentials: %w", listErr)
	}
	if len(held) >= s.cfg.MaxCredentialsPerSubject {
		return nil, fmt.Errorf("%w: %d of %d",
			ErrTooManyCredentials, len(held), s.cfg.MaxCredentialsPerSubject)
	}

	rec := &store.AdminCredential{
		ID:              uuid.NewString(),
		TenantID:        tok.TenantID,
		AdminTokenID:    tok.ID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AAGUID:          credential.Authenticator.AAGUID,
		AttestationType: normaliseAttestation(credential.AttestationType),
		Transports:      fromTransports(credential.Transport),
		SignCount:       credential.Authenticator.SignCount,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		UserVerified:    credential.Flags.UserVerified,
		Label:           strings.TrimSpace(label),
		RPID:            s.cfg.RPID,
		CreatedAt:       s.now().UTC(),
	}
	rec.BindingHash = BindingHash(asCredentialView(rec))

	if err := s.store.CreateAdminCredential(ctx, rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrCredentialExists
		}
		return nil, fmt.Errorf("webauthn: store administrative credential: %w", err)
	}
	return rec, nil
}

// BeginAdminAssertion starts a console sign-in that does not name the
// administrator in advance.
//
// It has to be discoverable. The alternative would be for the operator to type
// something that names their administrative token, and the only such value is
// the token itself, which is exactly what this feature exists to keep out of a
// form field.
//
// User verification is required, as on the subject usernameless route and for a
// stronger version of the same reason. The ceremony is scoped to nothing: the
// authenticator alone decides which administrative token the response is for,
// and the response is the whole of the sign-in. A possession-only answer would
// mean a found or stolen key opens the console.
func (s *Service) BeginAdminAssertion(ctx context.Context, tenantID string) (*BeginAssertionResult, error) {
	assertion, session, err := s.rp.BeginDiscoverableLogin(
		lib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin administrative login: %w", err)
	}

	// Stored naming no token, because there is none yet. The enrolment
	// completion requires the challenge to name the token it was handed and
	// this one requires it to name nobody, so neither ceremony can be finished
	// through the other's route.
	challengeID, expiresAt, err := s.persistAdminChallenge(ctx, tenantID, "",
		store.CeremonyAssertion, session)
	if err != nil {
		return nil, err
	}

	return &BeginAssertionResult{
		ChallengeID: challengeID,
		Options:     assertion,
		ExpiresAt:   expiresAt,
	}, nil
}

// AdminAssertionResult is a completed console sign-in ceremony.
//
// Token is the administrative token the credential turned out to belong to, and
// is the only thing that decides what the resulting session may do. Credential
// and Outcome are carried so that the caller can audit which key was used and
// what the ceremony observed about it.
type AdminAssertionResult struct {
	Token      *store.AdminToken
	Credential *store.AdminCredential
	Outcome    *AssertionOutcome
}

// CompleteAdminAssertion finishes a console sign-in and reports which
// administrative token the response turned out to be for.
//
// The token is resolved from the credential identifier and never from the user
// handle, for the reason CompleteDiscoverableAssertion resolves a subject that
// way: the identifier selects a stored public key which then has to verify the
// signature, whereas the handle is only a value the client sent. The handle is
// still compared, because a response whose two halves disagree is not one this
// service issued, and that comparison is also what refuses a subject's passkey
// presented here, since a subject handle can never equal an administrative one.
//
// The response has to have been collected at the console's own origin, and not
// merely at one of the relying party's. Both surfaces share a relying party
// identifier, so an authenticator will happily produce an assertion for this
// one on any page the application serves; without this check every origin
// trusted to sign a user in would also be trusted to sign an administrator in,
// and the phishing resistance the passkey was chosen for would be absent from
// the surface that needs it most. The origin is taken from the collected client
// data, which the authenticator signed over.
//
// Every refusal returns ErrCeremonyFailed, so an unknown credential, a
// withdrawn one, a token that has expired and a token that has been revoked are
// one answer from outside. The wrapped text names which of them it was, for the
// audit entry and the log line only; it is never shown to the operator. That is
// the arrangement handleSignInSubmit already uses for a pasted token.
func (s *Service) CompleteAdminAssertion(ctx context.Context, tenantID, challengeID string,
	credentialJSON []byte) (*AdminAssertionResult, error) {
	challenge, session, err := s.consumeAdminChallenge(ctx, tenantID, challengeID,
		store.CeremonyAssertion)
	if err != nil {
		return nil, err
	}
	// The mirror of the token check in CompleteAdminRegistration. A challenge
	// issued for a named token must not be completed here, where there is no
	// allow list and no caller-supplied identity to compare it against.
	if challenge.AdminTokenID != "" {
		return nil, ErrCeremonyFailed
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}
	if err = s.checkAdminOrigin(parsed.Response.CollectedClientData.Origin); err != nil {
		return nil, err
	}

	var (
		rec *store.AdminCredential
		tok *store.AdminToken
		// refused carries why the lookup said no, for the audit entry. The
		// library wraps whatever the lookup returns, so the sentinel does not
		// survive the round trip and the reason has to be captured here.
		refused string
	)

	lookup := func(rawID, handle []byte) (lib.User, error) {
		found, lookupErr := s.store.GetAdminCredentialByID(ctx, tenantID, s.cfg.RPID, rawID)
		if errors.Is(lookupErr, store.ErrNotFound) {
			// This is where a subject's passkey lands, and where a passkey from
			// another deployment lands. The credential is not in this table, so
			// there is nothing to verify against and nothing to resolve.
			refused = "the credential is not enrolled for the administration interface"
			return nil, ErrCeremonyFailed
		}
		if lookupErr != nil {
			return nil, fmt.Errorf("webauthn: administrative credential lookup: %w", lookupErr)
		}
		// GetAdminCredentialByID deliberately does not filter withdrawn rows:
		// the enrolment path uses it to refuse an authenticator that is already
		// known, whether or not it still works. Here a withdrawn credential must
		// authenticate nothing, and refusing at this point rather than relying on
		// the "revoked_at IS NULL" carried by the counter writes makes withdrawal
		// a stated property of this path rather than a side effect of a clause
		// written to serve the replay guard.
		if found.Revoked() {
			refused = "the credential has been withdrawn"
			return nil, ErrCeremonyFailed
		}

		t, lookupErr := s.store.GetAdminTokenByID(ctx, tenantID, found.AdminTokenID)
		if errors.Is(lookupErr, store.ErrNotFound) {
			refused = "the administrative token the credential belongs to no longer exists"
			return nil, ErrCeremonyFailed
		}
		if lookupErr != nil {
			return nil, fmt.Errorf("webauthn: administrative token lookup: %w", lookupErr)
		}
		if !t.Usable(s.now().UTC()) {
			refused = "the administrative token is expired, withdrawn or carries an unknown role"
			return nil, ErrCeremonyFailed
		}

		expected, lookupErr := adminUserHandle(t.ID)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if !hmac.Equal(expected, handle) {
			refused = "the user handle does not match the credential"
			return nil, ErrCeremonyFailed
		}

		rec, tok = found, t

		// Only the credential that was presented goes into the list the library
		// validates against. Handing it the token's other credentials would let
		// a response be accepted against a key the operator did not just use.
		return newAdminUser(t, []lib.Credential{toLibCredential(asCredentialView(found))})
	}

	validated, err := s.rp.ValidateDiscoverableLogin(lookup, *session, parsed)
	if err != nil {
		if refused != "" {
			return nil, fmt.Errorf("%w: %s", ErrCeremonyFailed, refused)
		}
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}
	if rec == nil || tok == nil || !hmac.Equal(rec.CredentialID, validated.ID) {
		// The lookup sets both, and the library validates against what the
		// lookup returned, so this should be unreachable. Refusing rather than
		// trusting it keeps the invariant local.
		return nil, ErrCeremonyFailed
	}

	outcome, err := s.recordAssertion(ctx, adminCredentialWriter{st: s.store},
		asCredentialView(rec), validated, parsed)
	if err != nil {
		return nil, err
	}

	// The record the caller reads back carries what the ceremony observed, so
	// an audit entry does not have to re-derive it from the stale row.
	rec.SignCount = outcome.NewSignCount
	rec.CloneWarning = rec.CloneWarning || outcome.CloneWarning

	return &AdminAssertionResult{Token: tok, Credential: rec, Outcome: outcome}, nil
}

// persistAdminChallenge stores console ceremony state and returns its
// identifier.
//
// It is persistChallenge against the console's own table. The two are separate
// functions rather than one with a flag, because the table a challenge lands in
// is the thing that keeps the two surfaces apart, and a flag is a thing a caller
// can pass wrongly.
func (s *Service) persistAdminChallenge(ctx context.Context, tenantID, adminTokenID string, ceremony store.Ceremony,
	session *lib.SessionData) (string, time.Time, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("webauthn: marshal session: %w", err)
	}

	challengeBytes := decodeChallenge(session.Challenge)

	now := s.now().UTC()
	expires := now.Add(s.cfg.ChallengeTTL.Duration)

	c := &store.AdminChallenge{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		AdminTokenID: adminTokenID,
		Ceremony:     ceremony,
		Challenge:    challengeBytes,
		RPID:         s.cfg.RPID,
		SessionData:  raw,
		CreatedAt:    now,
		ExpiresAt:    expires,
	}
	if err := s.store.CreateAdminChallenge(ctx, c); err != nil {
		return "", time.Time{}, fmt.Errorf("webauthn: store administrative challenge: %w", err)
	}
	return c.ID, expires, nil
}

// consumeAdminChallenge marks a console challenge used and returns its session
// data.
func (s *Service) consumeAdminChallenge(ctx context.Context, tenantID, challengeID string,
	want store.Ceremony) (*store.AdminChallenge, *lib.SessionData, error) {
	c, err := s.store.ConsumeAdminChallenge(ctx, tenantID, challengeID, s.now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: consume administrative challenge: %w", err)
	}

	// An enrolment challenge must not complete a sign-in, or the reverse. The
	// two differ in the checks that follow, so a caller allowed to choose
	// between them would be choosing which checks apply.
	if c.Ceremony != want {
		return nil, nil, ErrChallengeNotFound
	}

	// The relying party identifier recorded when the challenge was issued must
	// still be the one configured. A reconfiguration mid-ceremony would
	// otherwise validate a response against an origin the operator has already
	// stopped trusting.
	if c.RPID != s.cfg.RPID {
		return nil, nil, ErrChallengeNotFound
	}

	var session lib.SessionData
	if err := json.Unmarshal(c.SessionData, &session); err != nil {
		return nil, nil, fmt.Errorf("webauthn: unmarshal session: %w", err)
	}
	return c, &session, nil
}
