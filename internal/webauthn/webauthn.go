// Package webauthn drives the two WebAuthn ceremonies against the store.
//
// # This service is the relying party
//
// The relying party identifier and the list of acceptable origins are server
// configuration. They are never read from a request. WebAuthn's security rests
// on the authenticator signing over an origin and a relying party identifier
// that the server independently expects: a caller allowed to nominate either
// could declare its own origin and the binding would prove nothing. The
// consequence for an integrating application, which is worth stating plainly
// because it constrains deployment, is that its front end has to be served from
// a configured origin, and moving to a new subdomain is a configuration change
// here rather than a client-side one.
//
// # Ceremony state lives in the database
//
// Each ceremony is two round trips, and the challenge issued by the first has
// to be bound to the second. The library's session data is persisted server
// side rather than handed back to the caller, so the caller cannot alter the
// expected challenge, the expected user handle or the user-verification
// requirement between the two halves. Single use is then a property of the
// store's conditional update rather than of a convention.
//
// # What is stored
//
// The credential public key is stored in clear. It is a public key: it needs
// integrity, not confidentiality, and sealing it under the key encryption key
// would make losing that key destroy credentials which were never secret.
package webauthn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	lib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// Errors a caller may need to distinguish.
//
// The ceremony failures are deliberately coarse. A caller learns that the
// ceremony did not complete, not which check refused it: telling an attacker
// whether the challenge was unknown, the origin wrong or the signature invalid
// turns the endpoint into an oracle for probing the configuration.
var (
	ErrCeremonyFailed     = errors.New("webauthn: ceremony failed")
	ErrChallengeNotFound  = errors.New("webauthn: challenge is unknown, expired or already used")
	ErrCredentialExists   = errors.New("webauthn: authenticator is already registered")
	ErrTooManyCredentials = errors.New("webauthn: credential limit reached for this subject")
	ErrAuthenticatorModel = errors.New("webauthn: authenticator model is not permitted")
	ErrNoCredentials      = errors.New("webauthn: subject has no usable credential")
	ErrSubjectInactive    = errors.New("webauthn: subject cannot authenticate")
)

// Service performs registration and assertion.
type Service struct {
	rp    *lib.WebAuthn
	cfg   config.WebAuthn
	store store.Store
	now   func() time.Time

	allowed map[string]struct{}
	blocked map[string]struct{}
}

// New builds a Service from the validated configuration.
//
// The AAGUID policy is compiled into sets here rather than being re-parsed on
// every ceremony. An allow list is the offline-friendly alternative to full
// attestation verification: it restricts registration to named authenticator
// models without needing the FIDO Metadata Service, and therefore without
// needing network egress.
func New(cfg config.WebAuthn, st store.Store, clock func() time.Time) (*Service, error) {
	if clock == nil {
		clock = time.Now
	}

	mds, err := loadMetadata(cfg)
	if err != nil {
		return nil, err
	}

	rp, err := lib.New(&lib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		// Nil when no metadata file is configured, which leaves attestation
		// statements checked for internal consistency only.
		MDS: mds,
		Timeouts: lib.TimeoutsConfig{
			Login: lib.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.CeremonyTimeout.Duration,
			},
			Registration: lib.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.CeremonyTimeout.Duration,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: configure relying party: %w", err)
	}

	s := &Service{
		rp:      rp,
		cfg:     cfg,
		store:   st,
		now:     clock,
		allowed: toAAGUIDSet(cfg.AllowedAAGUIDs),
		blocked: toAAGUIDSet(cfg.BlockedAAGUIDs),
	}
	return s, nil
}

// RPID reports the configured relying party identifier, for the health report
// and the admin interface.
func (s *Service) RPID() string { return s.cfg.RPID }

// subjectUser adapts a store.Subject to the library's user interface.
//
// The user handle is the subject's internal identifier, not the reference the
// integrating application supplied. The handle is stored on the authenticator
// and can be disclosed by a discoverable credential, so putting an application
// identifier in it, which is frequently an email address whatever the
// documentation advises, would publish personal data to every relying party the
// user visits with that key.
type subjectUser struct {
	id          []byte
	name        string
	displayName string
	credentials []lib.Credential
}

func (u *subjectUser) WebAuthnID() []byte                    { return u.id }
func (u *subjectUser) WebAuthnName() string                  { return u.name }
func (u *subjectUser) WebAuthnDisplayName() string           { return u.displayName }
func (u *subjectUser) WebAuthnCredentials() []lib.Credential { return u.credentials }
func (u *subjectUser) WebAuthnIcon() string                  { return "" }

// newUser builds the library user for a subject.
//
// label is used only inside the ceremony, for what the authenticator shows the
// user while they confirm. It is never persisted, so a caller may pass
// something human-readable without that value entering the database.
func newUser(subject *store.Subject, label string, creds []lib.Credential) (*subjectUser, error) {
	handle, err := userHandle(subject.ID)
	if err != nil {
		return nil, err
	}
	name := label
	if name == "" {
		name = subject.DisplayName
	}
	if name == "" {
		// Falling back to a truncated identifier keeps the prompt meaningful
		// without disclosing anything the authenticator did not already hold.
		name = "subject-" + shortID(subject.ID)
	}
	return &subjectUser{
		id:          handle,
		name:        name,
		displayName: name,
		credentials: creds,
	}, nil
}

// userHandle converts the subject identifier into the opaque byte sequence the
// specification calls for, capped at the 64 bytes it permits.
func userHandle(subjectID string) ([]byte, error) {
	if id, err := uuid.Parse(subjectID); err == nil {
		b := id[:]
		return append([]byte(nil), b...), nil
	}
	if subjectID == "" {
		return nil, errors.New("webauthn: subject has no identifier")
	}
	sum := sha256.Sum256([]byte("n0passtemps/user-handle/v1" + subjectID))
	return sum[:], nil
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// BeginRegistrationResult is returned by BeginRegistration.
type BeginRegistrationResult struct {
	// ChallengeID identifies the ceremony and must be presented again on
	// completion.
	ChallengeID string `json:"challenge_id"`

	// Options is the PublicKeyCredentialCreationOptions structure, ready to be
	// handed to navigator.credentials.create in the browser.
	Options *protocol.CredentialCreation `json:"options"`

	// ExpiresAt is when the challenge stops being accepted.
	ExpiresAt time.Time `json:"expires_at"`
}

// BeginRegistration starts a registration ceremony for a subject.
//
// The subject's existing credentials are excluded, so an authenticator already
// enrolled cannot be enrolled twice and the browser can tell the user why.
func (s *Service) BeginRegistration(ctx context.Context, subject *store.Subject, label string) (*BeginRegistrationResult, error) {
	if !subject.Active() {
		return nil, ErrSubjectInactive
	}

	existing, err := s.store.ListCredentials(ctx, subject.TenantID, subject.ID, false)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
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

	user, err := newUser(subject, label, nil)
	if err != nil {
		return nil, err
	}

	creation, session, err := s.rp.BeginRegistration(user,
		lib.WithExclusions(exclude),
		lib.WithConveyancePreference(protocol.ConveyancePreference(s.cfg.AttestationPreference)),
		lib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.UserVerificationRequirement(s.cfg.UserVerification),
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin registration: %w", err)
	}

	challengeID, expiresAt, err := s.persistChallenge(ctx, subject.TenantID, subject.ID,
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

// CompleteRegistration finishes a registration ceremony and stores the
// credential.
//
// credentialJSON is the raw PublicKeyCredential the browser produced, forwarded
// verbatim by the integrating application.
func (s *Service) CompleteRegistration(ctx context.Context, subject *store.Subject, challengeID string, credentialJSON []byte, label string) (*store.Credential, error) {
	if !subject.Active() {
		return nil, ErrSubjectInactive
	}

	challenge, session, err := s.consumeChallenge(ctx, subject.TenantID, challengeID,
		store.CeremonyRegistration)
	if err != nil {
		return nil, err
	}

	// The challenge was issued for a specific subject. A completion presented
	// for a different one would otherwise let a caller holding a valid API key
	// graft an authenticator onto an account it did not start a ceremony for.
	if challenge.SubjectID != subject.ID {
		return nil, ErrCeremonyFailed
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}

	user, err := newUser(subject, label, nil)
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

	// A credential identifier is unique per relying party, so the same
	// authenticator must not appear under two subjects.
	if _, err := s.store.GetCredentialByID(ctx, subject.TenantID, s.cfg.RPID, credential.ID); err == nil {
		return nil, ErrCredentialExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("webauthn: look up credential: %w", err)
	}

	rec := &store.Credential{
		ID:              uuid.NewString(),
		TenantID:        subject.TenantID,
		SubjectID:       subject.ID,
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
	rec.BindingHash = BindingHash(rec)

	if err := s.store.CreateCredential(ctx, rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrCredentialExists
		}
		return nil, fmt.Errorf("webauthn: store credential: %w", err)
	}
	return rec, nil
}

// BeginAssertionResult is returned by BeginAssertion.
type BeginAssertionResult struct {
	ChallengeID string                        `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
	ExpiresAt   time.Time                     `json:"expires_at"`
}

// BeginAssertion starts an authentication ceremony.
func (s *Service) BeginAssertion(ctx context.Context, subject *store.Subject) (*BeginAssertionResult, error) {
	if !subject.Active() {
		return nil, ErrSubjectInactive
	}

	stored, err := s.store.ListCredentials(ctx, subject.TenantID, subject.ID, false)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(stored) == 0 {
		return nil, ErrNoCredentials
	}

	creds := make([]lib.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, toLibCredential(c))
	}

	user, err := newUser(subject, "", creds)
	if err != nil {
		return nil, err
	}

	assertion, session, err := s.rp.BeginLogin(user,
		lib.WithUserVerification(protocol.UserVerificationRequirement(s.cfg.UserVerification)),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin login: %w", err)
	}

	challengeID, expiresAt, err := s.persistChallenge(ctx, subject.TenantID, subject.ID,
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

// AssertionOutcome describes a completed assertion.
//
// The signals are reported rather than acted on, because each of them has a
// legitimate cause as well as a suspicious one and refusing on either would
// lock out users for doing nothing wrong.
type AssertionOutcome struct {
	Credential *store.Credential

	// UserVerified reports whether the authenticator proved user identity and
	// not merely possession. It decides whether the assertion is sufficient on
	// its own or is one factor of two.
	UserVerified bool

	// CloneWarning is set when the signature counter failed to advance. The
	// specification names this as the signal for two copies of a credential
	// private key in use. Many authenticators legitimately report a constant
	// zero, so this raises an alert rather than refusing the assertion.
	CloneWarning bool

	// BindingChanged is set when the authenticator characteristics differ from
	// those recorded at registration. A firmware update or a transport change
	// moves them legitimately, so this is recorded rather than refused.
	BindingChanged bool

	// PreviousSignCount and NewSignCount are carried so the audit entry can
	// record what actually happened to the counter.
	PreviousSignCount uint32
	NewSignCount      uint32
}

// CompleteAssertion finishes an authentication ceremony.
//
// The signature counter is advanced with a compare-and-swap against the value
// read at the start. Two concurrent completions of the same assertion therefore
// have exactly one winner: the loser sees a stale write and is refused, which
// is what stops the same signed assertion being accepted twice.
func (s *Service) CompleteAssertion(ctx context.Context, subject *store.Subject, challengeID string, credentialJSON []byte) (*AssertionOutcome, error) {
	if !subject.Active() {
		return nil, ErrSubjectInactive
	}

	challenge, session, err := s.consumeChallenge(ctx, subject.TenantID, challengeID,
		store.CeremonyAssertion)
	if err != nil {
		return nil, err
	}
	if challenge.SubjectID != subject.ID {
		return nil, ErrCeremonyFailed
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}

	stored, err := s.store.ListCredentials(ctx, subject.TenantID, subject.ID, false)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(stored) == 0 {
		return nil, ErrNoCredentials
	}

	byID := make(map[string]*store.Credential, len(stored))
	creds := make([]lib.Credential, 0, len(stored))
	for _, c := range stored {
		byID[string(c.CredentialID)] = c
		creds = append(creds, toLibCredential(c))
	}

	user, err := newUser(subject, "", creds)
	if err != nil {
		return nil, err
	}

	validated, err := s.rp.ValidateLogin(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}

	rec, ok := byID[string(validated.ID)]
	if !ok {
		// The library validated against the allow list it was given, so this
		// should be unreachable. Refusing rather than trusting it keeps the
		// invariant local.
		return nil, ErrCeremonyFailed
	}

	outcome := &AssertionOutcome{
		Credential: rec,
		// Read from the authenticator data of THIS ceremony, not from the
		// credential the library hands back. The library merges the flags of
		// the assertion into the stored ones with a logical OR, so for any
		// credential registered with user verification its value is true for
		// ever after. Reporting that would sign a possession-only assertion,
		// the kind a stolen key without its PIN produces, as a user-verified
		// one, and the calling application would treat one factor as two.
		UserVerified:      parsed.Response.AuthenticatorData.Flags.HasUserVerified(),
		PreviousSignCount: rec.SignCount,
		NewSignCount:      validated.Authenticator.SignCount,
	}

	// A counter that did not advance is the documented clone signal. Zero on
	// both sides means the authenticator does not implement a counter at all,
	// which is common and is not a signal.
	counterStuck := validated.Authenticator.SignCount <= rec.SignCount
	noCounter := validated.Authenticator.SignCount == 0 && rec.SignCount == 0
	outcome.CloneWarning = validated.Authenticator.CloneWarning || (counterStuck && !noCounter)

	if expected := BindingHash(rec); len(rec.BindingHash) > 0 {
		current := bindingHashFrom(validated, s.cfg.RPID)
		outcome.BindingChanged = !hmac.Equal(rec.BindingHash, current) && !hmac.Equal(expected, current)
	}

	usedAt := s.now().UTC()
	if noCounter {
		// There is no counter to advance, so only the use is recorded. This is
		// the common case: most passkeys report zero for ever.
		if err := s.store.TouchCredential(ctx, rec.TenantID, rec.ID, usedAt); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Revoked between the listing above and now. The assertion
				// must not succeed on a credential that is no longer valid.
				return nil, ErrCeremonyFailed
			}
			return nil, fmt.Errorf("webauthn: record credential use: %w", err)
		}
	} else if counterStuck {
		if err := s.store.MarkCloneWarning(ctx, rec.TenantID, rec.ID); err != nil {
			return nil, fmt.Errorf("webauthn: record clone warning: %w", err)
		}
		if err := s.store.TouchCredential(ctx, rec.TenantID, rec.ID, usedAt); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("webauthn: record credential use: %w", err)
		}
	} else {
		err := s.store.AdvanceSignCount(ctx, rec.TenantID, rec.ID,
			rec.SignCount, validated.Authenticator.SignCount, usedAt)
		if errors.Is(err, store.ErrStaleWrite) {
			// Another completion moved the counter first. This one is either a
			// replay or the loser of a race; either way it must not succeed.
			return nil, ErrCeremonyFailed
		}
		if err != nil {
			return nil, fmt.Errorf("webauthn: advance sign count: %w", err)
		}
	}

	return outcome, nil
}

// persistChallenge stores the ceremony state and returns its identifier.
func (s *Service) persistChallenge(ctx context.Context, tenantID, subjectID string, ceremony store.Ceremony, session *lib.SessionData) (string, time.Time, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("webauthn: marshal session: %w", err)
	}

	// The challenge bytes are indexed unique, so the same challenge cannot be
	// registered twice even if the generator were ever to repeat.
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		// The library emits unpadded base64url; fall back to the string form
		// rather than failing the ceremony over an encoding detail.
		challengeBytes = []byte(session.Challenge)
	}

	now := s.now().UTC()
	expires := now.Add(s.cfg.ChallengeTTL.Duration)

	c := &store.Challenge{
		ID:          uuid.NewString(),
		TenantID:    tenantID,
		SubjectID:   subjectID,
		Ceremony:    ceremony,
		Challenge:   challengeBytes,
		RPID:        s.cfg.RPID,
		SessionData: raw,
		CreatedAt:   now,
		ExpiresAt:   expires,
	}
	if err := s.store.CreateChallenge(ctx, c); err != nil {
		return "", time.Time{}, fmt.Errorf("webauthn: store challenge: %w", err)
	}
	return c.ID, expires, nil
}

// consumeChallenge marks the challenge used and returns its session data.
func (s *Service) consumeChallenge(ctx context.Context, tenantID, challengeID string, want store.Ceremony) (*store.Challenge, *lib.SessionData, error) {
	c, err := s.store.ConsumeChallenge(ctx, tenantID, challengeID, s.now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: consume challenge: %w", err)
	}

	// A registration challenge must not complete an assertion, or the reverse.
	// Without this a caller could present a registration ceremony's challenge
	// to the assertion endpoint, where the user-verification requirement and
	// the allow list differ.
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

// checkAuthenticatorModel applies the AAGUID policy.
func (s *Service) checkAuthenticatorModel(c *lib.Credential) error {
	id := formatAAGUID(c.Authenticator.AAGUID)

	if _, blocked := s.blocked[id]; blocked {
		return fmt.Errorf("%w: %s is blocked", ErrAuthenticatorModel, id)
	}
	if len(s.allowed) == 0 {
		return nil
	}
	if _, ok := s.allowed[id]; !ok {
		return fmt.Errorf("%w: %s is not in the allow list", ErrAuthenticatorModel, id)
	}
	return nil
}

// checkAttestation refuses a credential whose attestation was required but not
// provided.
//
// Verifying an attestation statement against a certificate chain needs either
// the FIDO Metadata Service over the network or a metadata blob on disk. This
// service is meant to run offline, so attestation is off by default and the
// AAGUID allow list is the recommended control. When an operator does turn it
// on, a credential arriving with no attestation has to be refused, otherwise
// the setting would be satisfied by any authenticator that declines to attest.
func (s *Service) checkAttestation(c *lib.Credential) error {
	if !s.cfg.RequireAttestation {
		return nil
	}
	switch normaliseAttestation(c.AttestationType) {
	case store.AttestationNone, store.AttestationSelf:
		return fmt.Errorf("%w: attestation is required but the authenticator provided %q",
			ErrAuthenticatorModel, c.AttestationType)
	}
	if len(c.Authenticator.AAGUID) == 0 || formatAAGUID(c.Authenticator.AAGUID) == zeroAAGUID {
		return fmt.Errorf("%w: attestation is required but the authenticator reported no model",
			ErrAuthenticatorModel)
	}
	return nil
}

const zeroAAGUID = "00000000-0000-0000-0000-000000000000"

// BindingHash commits to the authenticator characteristics observed at
// registration.
//
// It covers the model, the attestation type, the advertised transports and the
// relying party, which are the properties that stay constant for a given
// physical key. It deliberately excludes the signature counter and the backup
// state, both of which change on every use.
//
// A later assertion whose characteristics hash differently is recorded, not
// refused: a firmware update can change the advertised transports, and a
// platform authenticator can gain backup eligibility, neither of which means
// the key was swapped.
func BindingHash(c *store.Credential) []byte {
	h := sha256.New()
	h.Write([]byte("n0passtemps/credential-binding/v1"))
	h.Write([]byte{0})
	h.Write(c.AAGUID)
	h.Write([]byte{0})
	h.Write([]byte(c.AttestationType))
	h.Write([]byte{0})

	transports := slices.Clone(c.Transports)
	slices.Sort(transports)
	h.Write([]byte(strings.Join(transports, ",")))
	h.Write([]byte{0})
	h.Write([]byte(c.RPID))
	return h.Sum(nil)
}

func bindingHashFrom(c *lib.Credential, rpID string) []byte {
	return BindingHash(&store.Credential{
		AAGUID:          c.Authenticator.AAGUID,
		AttestationType: normaliseAttestation(c.AttestationType),
		Transports:      fromTransports(c.Transport),
		RPID:            rpID,
	})
}

// normaliseAttestation maps the library's attestation type vocabulary onto the
// values the schema's CHECK constraint permits.
func normaliseAttestation(s string) store.AttestationType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "basic", "basic_full":
		return store.AttestationBasic
	case "self", "basic_surrogate":
		return store.AttestationSelf
	case "attca":
		return store.AttestationAttCA
	case "anonca":
		return store.AttestationAnonCA
	case "indirect":
		return store.AttestationIndirect
	default:
		return store.AttestationNone
	}
}

// toLibCredential converts a stored credential for the library.
//
// Two stored values are deliberately NOT passed through, because the library
// latches both: it ORs the stored user-verified flag and the stored clone
// warning into what it returns. Passing them would make every later ceremony
// report the history of the credential instead of what just happened. The
// stored values remain on the record for an operator to read; the outcome of a
// ceremony describes that ceremony only.
func toLibCredential(c *store.Credential) lib.Credential {
	return lib.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: string(c.AttestationType),
		Transport:       toTransports(c.Transports),
		Flags: lib.CredentialFlags{
			// Backup eligibility is a fixed property of the credential and
			// the library checks that it never changes, so it is passed.
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: lib.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func toTransports(in []string) []protocol.AuthenticatorTransport {
	out := make([]protocol.AuthenticatorTransport, 0, len(in))
	for _, t := range in {
		out = append(out, protocol.AuthenticatorTransport(t))
	}
	return out
}

func fromTransports(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

// formatAAGUID renders the 16-byte identifier in the canonical 8-4-4-4-12 form
// the configuration uses.
func formatAAGUID(b []byte) string {
	if len(b) != 16 {
		if len(b) == 0 {
			return zeroAAGUID
		}
		return hex.EncodeToString(b)
	}
	var id uuid.UUID
	copy(id[:], b)
	return id.String()
}

func toAAGUIDSet(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}
