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
//
// Two of them are the exception, and the distinction is drawn on purpose so
// that the decision belongs to the caller rather than to this package.
// ErrChallengeNotFound says the challenge is not one this ceremony may spend,
// which is a statement about a value the caller supplied and about nothing the
// subject did; an attempt counter that charges it to the subject is punishing
// them for somebody else's replay. ErrNoCredentials and ErrSubjectInactive say
// the named subject cannot begin a ceremony at all, which is a fact about
// enrolment: a caller that turns them into a different response from a
// successful begin has told whoever asked whether that subject holds a key.
// Which of the two matters more is a deployment's judgement, and both answers
// are defensible; what this package owes the caller is the ability to choose,
// so it reports them apart and decides nothing.
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

	// adminOrigins is the console's own origin list, resolved once. See
	// resolveAdminOrigins for how it is derived and why it is narrower than
	// the relying party's.
	adminOrigins []string

	// metadataNextUpdate is the nextUpdate the loaded BLOB declares, or the
	// zero time when none is configured.
	metadataNextUpdate time.Time
}

// New builds a Service from the validated configuration.
//
// The AAGUID policy is compiled into sets here rather than being re-parsed on
// every ceremony. Note what that policy is and is not: it filters on a value
// the registration response declares, so it keeps a fleet on the models an
// operator chose, and it stops nothing that is willing to declare an AAGUID it
// does not have. The control that requires proof is a metadata BLOB, which is
// why the configuration validator will not accept require_attestation without
// one.
func New(cfg config.WebAuthn, st store.Store, clock func() time.Time) (*Service, error) {
	if clock == nil {
		clock = time.Now
	}

	mds, nextUpdate, err := loadMetadata(cfg)
	if err != nil {
		return nil, err
	}

	rp, err := lib.New(&lib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		// Nil when no metadata file is configured. The library's
		// VerifyAttestation returns as soon as the statement is internally
		// consistent when this is nil, so with no BLOB nothing is checked
		// against a trust anchor at all.
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
		rp:                 rp,
		cfg:                cfg,
		store:              st,
		now:                clock,
		allowed:            toAAGUIDSet(cfg.AllowedAAGUIDs),
		blocked:            toAAGUIDSet(cfg.BlockedAAGUIDs),
		adminOrigins:       resolveAdminOrigins(cfg),
		metadataNextUpdate: nextUpdate,
	}
	return s, nil
}

// RPID reports the configured relying party identifier, for the health report
// and the admin interface.
func (s *Service) RPID() string { return s.cfg.RPID }

// AdminOrigins reports the origins a console ceremony will accept, so that an
// operator can see which of the relying party's origins the administration
// interface is held to without reading the configuration back.
func (s *Service) AdminOrigins() []string { return slices.Clone(s.adminOrigins) }

// MetadataNextUpdate reports the date the loaded metadata BLOB declares as the
// latest it will be superseded, or the zero time when none is configured.
//
// It exists so a health report can say how old the trust anchors are. A BLOB
// far enough past this date is refused at startup, so a service that is running
// has one within the tolerance; what this reports is how much of it is left.
func (s *Service) MetadataNextUpdate() time.Time { return s.metadataNextUpdate }

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

// The five accessors of the library's user interface. See the type's comment
// for why the name and display name carry no personal identifier.

// WebAuthnID returns the opaque user handle the authenticator stores.
func (u *subjectUser) WebAuthnID() []byte { return u.id }

// WebAuthnName returns the account name shown by the authenticator.
func (u *subjectUser) WebAuthnName() string { return u.name }

// WebAuthnDisplayName returns the human-readable name shown beside it.
func (u *subjectUser) WebAuthnDisplayName() string { return u.displayName }

// WebAuthnCredentials returns the credentials already registered to the subject.
func (u *subjectUser) WebAuthnCredentials() []lib.Credential { return u.credentials }

// WebAuthnIcon is empty. The interface predates its removal from the
// specification, and serving a URL here would tell the authenticator's vendor
// which deployment a user belongs to.
func (u *subjectUser) WebAuthnIcon() string { return "" }

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
func (s *Service) BeginRegistration(ctx context.Context, subject *store.Subject,
	label string) (*BeginRegistrationResult, error) {
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
	// CompleteRegistration checks the same thing again before it stores
	// anything, because this count is read at the start of a ceremony the
	// caller may hold open for as long as the challenge lives.

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
func (s *Service) CompleteRegistration(ctx context.Context, subject *store.Subject, challengeID string,
	credentialJSON []byte, label string) (*store.Credential, error) {
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

	// The same identifier must not already name an administrative credential
	// either. Deriving the user handle under a different domain separator
	// already makes an authenticator produce distinct credentials for the two
	// spaces, so this should never fire; refusing on it turns "no credential is
	// both a subject's and an administrator's" from a consequence of how
	// handles are built into a property of what is stored, which is the form a
	// later reader can check.
	if _, err := s.store.GetAdminCredentialByID(ctx, subject.TenantID, s.cfg.RPID, credential.ID); err == nil {
		return nil, ErrCredentialExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("webauthn: look up administrative credential: %w", err)
	}

	// The cap is checked again here, as close to the insertion as this package
	// can get. BeginRegistration checks it too, and on its own that check is
	// only advisory: N ceremonies begun together each see the same count and
	// each are allowed, and the N completions that follow all store a
	// credential. Re-reading now closes the window to the gap between this
	// listing and the insert below rather than to the whole span of a ceremony.
	//
	// It is still not atomic, and cannot be made so from here: the guarantee
	// wanted is a count taken inside the transaction that inserts, which means
	// a conditional insert in the store. That belongs to whoever owns the
	// store, and until it exists a determined caller can still exceed the cap
	// by a small number.
	if err := s.checkCredentialCap(ctx, subject.TenantID, subject.ID); err != nil {
		return nil, err
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
func (s *Service) CompleteAssertion(ctx context.Context, subject *store.Subject, challengeID string,
	credentialJSON []byte) (*AssertionOutcome, error) {
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

	return s.recordAssertion(ctx, s.store, rec, validated, parsed)
}

// credentialWriter is the three writes a completed assertion makes to the
// credential it used.
//
// It exists so that recordAssertion is the only place in the service that
// touches a signature counter, whichever table the credential came from. The
// subject store satisfies it directly; the console's credentials are written
// through the adapter in admin.go. The alternative, a second copy of the
// bookkeeping for the second table, would be a second place for the clone
// signal and the replay guard to drift apart, and that drift is silent: a
// counter check that stopped refusing a replay still looks like a working
// sign-in.
type credentialWriter interface {
	TouchCredential(ctx context.Context, tenantID, id string, usedAt time.Time) error
	MarkCloneWarning(ctx context.Context, tenantID, id string) error
	AdvanceSignCount(ctx context.Context, tenantID, id string, expectedPrev, next uint32, usedAt time.Time) error
}

// recordAssertion turns a validated assertion into an outcome and records what
// the ceremony did to the credential.
//
// The named, the discoverable and the console completion paths share it. The
// counter bookkeeping is the part of an assertion easiest to get subtly wrong,
// so w decides which table the writes land in and nothing else varies.
func (s *Service) recordAssertion(ctx context.Context, w credentialWriter, rec *store.Credential,
	validated *lib.Credential, parsed *protocol.ParsedCredentialAssertionData) (*AssertionOutcome, error) {
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
		if err := w.TouchCredential(ctx, rec.TenantID, rec.ID, usedAt); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Revoked between the listing above and now. The assertion
				// must not succeed on a credential that is no longer valid.
				return nil, ErrCeremonyFailed
			}
			return nil, fmt.Errorf("webauthn: record credential use: %w", err)
		}
	} else if counterStuck {
		if err := w.MarkCloneWarning(ctx, rec.TenantID, rec.ID); err != nil {
			return nil, fmt.Errorf("webauthn: record clone warning: %w", err)
		}
		// A counter strictly below a stored value that is not zero is the one
		// case no correct authenticator produces: a counter advances, or it is
		// absent and stays at zero. An operator who has decided that the
		// likeliest explanation is a copy of the key, rather than a device
		// restored from a backup, may refuse it. The warning is written first,
		// so the refusal leaves the same durable record the permissive
		// behaviour does.
		//
		// The presented value is read from the authenticator data of this
		// ceremony rather than from the credential the library returns, for
		// the reason the user-verified flag is: the library declines to lower
		// the counter it was given, so the record it hands back still holds
		// the stored value and a regression is invisible in it.
		presented := parsed.Response.AuthenticatorData.Counter
		if s.cfg.RefuseSignCountRegression && rec.SignCount != 0 && presented < rec.SignCount {
			return nil, fmt.Errorf("%w: the signature counter went from %d to %d, and "+
				"webauthn.refuse_sign_count_regression is on",
				ErrCeremonyFailed, rec.SignCount, presented)
		}
		if err := w.TouchCredential(ctx, rec.TenantID, rec.ID, usedAt); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Revoked between the listing and now, as in the branch above,
				// and here of all places: a counter that did not advance is
				// what a copy of the key produces, and revoking is what an
				// operator does about one.
				return nil, ErrCeremonyFailed
			}
			return nil, fmt.Errorf("webauthn: record credential use: %w", err)
		}
	} else {
		err := w.AdvanceSignCount(ctx, rec.TenantID, rec.ID,
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

// BeginDiscoverableAssertion starts an authentication ceremony that does not
// name the subject in advance.
//
// This is what a passkey prompt does. The authenticator offers whichever
// credentials it holds for this relying party, the user picks one, and the
// response says which subject it belonged to. The caller therefore does not
// have to know who is signing in before they sign in, which is the point, and
// is also why this route needs its own reasoning about what the ceremony
// proves.
//
// User verification is required here rather than taken from the
// configuration. A named assertion is already scoped to a subject the caller
// chose, so possession of that subject's authenticator is a meaningful answer
// on its own. A discoverable ceremony is scoped to nothing: the authenticator
// alone decides which account the response is for. Accepting a
// possession-only response would mean a found or stolen passkey signs in as
// its owner with nothing further needed, and the caller cannot compensate,
// because it did not choose the subject either. A deployment whose
// authenticators cannot verify a user cannot offer this, which is the correct
// outcome rather than a limitation to work around.
func (s *Service) BeginDiscoverableAssertion(ctx context.Context, tenantID string) (*BeginAssertionResult, error) {
	assertion, session, err := s.rp.BeginDiscoverableLogin(
		lib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin discoverable login: %w", err)
	}

	// Stored with no subject, because there is none yet. That empty value is
	// also what keeps the two assertion flows apart: the named completion
	// requires the challenge to name the subject it was handed, and the
	// discoverable completion requires it to name nobody. Neither ceremony can
	// be finished through the other's route, which matters because they differ
	// in exactly the two checks an attacker would want to choose between, the
	// allow list and the user-verification requirement.
	challengeID, expiresAt, err := s.persistChallenge(ctx, tenantID, "",
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

// CompleteDiscoverableAssertion finishes a ceremony begun without a subject
// and reports which subject the response turned out to belong to.
//
// The subject is resolved from the credential identifier and never from the
// user handle. Both arrive in the same client-controlled response, but they
// are not equally trustworthy: the credential identifier selects a stored
// public key which then has to verify the signature, whereas the handle is
// only a value the client sent. Resolving the subject from the handle would
// let anyone present their own authenticator alongside somebody else's handle
// and be told they are that person. The handle is still checked, because a
// response whose two halves disagree is not one this service issued.
func (s *Service) CompleteDiscoverableAssertion(ctx context.Context, tenantID, challengeID string,
	credentialJSON []byte) (*store.Subject, *AssertionOutcome, error) {
	challenge, session, err := s.consumeChallenge(ctx, tenantID, challengeID,
		store.CeremonyAssertion)
	if err != nil {
		return nil, nil, err
	}
	// The mirror of the subject check in CompleteAssertion. A challenge issued
	// for a named subject must not be completed here, where there is no allow
	// list and no caller-supplied subject to compare it against.
	if challenge.SubjectID != "" {
		return nil, nil, ErrCeremonyFailed
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}

	var (
		rec     *store.Credential
		subject *store.Subject
	)

	// The library calls this to turn the response into the user it should
	// validate against. Everything the service knows about who is signing in
	// is decided here.
	lookup := func(rawID, handle []byte) (lib.User, error) {
		found, lookupErr := s.store.GetCredentialByID(ctx, tenantID, s.cfg.RPID, rawID)
		if errors.Is(lookupErr, store.ErrNotFound) {
			return nil, ErrCeremonyFailed
		}
		if lookupErr != nil {
			return nil, fmt.Errorf("webauthn: credential lookup: %w", lookupErr)
		}
		// GetCredentialByID deliberately does not filter revoked rows: the
		// registration path uses it to refuse an authenticator that is already
		// known, whether or not it still works. Here a revoked credential must
		// authenticate nothing.
		//
		// This is the earlier of two refusals rather than the only one. Both
		// AdvanceSignCount and TouchCredential carry "revoked_at IS NULL", so
		// the ceremony would fail at the end anyway. Relying on that would
		// mean verifying a signature against a revoked key first, resolving
		// the subject it belongs to, and depending on a WHERE clause written
		// to serve the replay guard to also serve revocation. Refusing here
		// makes revocation a stated property of this path.
		if found.Revoked() {
			return nil, ErrCeremonyFailed
		}

		sub, lookupErr := s.store.GetSubject(ctx, tenantID, found.SubjectID)
		if errors.Is(lookupErr, store.ErrNotFound) {
			return nil, ErrCeremonyFailed
		}
		if lookupErr != nil {
			return nil, fmt.Errorf("webauthn: subject lookup: %w", lookupErr)
		}
		if !sub.Active() {
			return nil, ErrCeremonyFailed
		}

		expected, lookupErr := userHandle(sub.ID)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if !hmac.Equal(expected, handle) {
			return nil, ErrCeremonyFailed
		}

		rec, subject = found, sub

		// Only the credential that was presented goes into the list the
		// library validates against. Handing it the subject's other
		// credentials would let a response be accepted against a key the user
		// did not just use.
		return newUser(sub, "", []lib.Credential{toLibCredential(found)})
	}

	validated, err := s.rp.ValidateDiscoverableLogin(lookup, *session, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCeremonyFailed, err)
	}
	if rec == nil || subject == nil || !hmac.Equal(rec.CredentialID, validated.ID) {
		// The lookup sets both, and the library validates against what the
		// lookup returned, so this should be unreachable. Refusing rather than
		// trusting it keeps the invariant local.
		return nil, nil, ErrCeremonyFailed
	}

	outcome, err := s.recordAssertion(ctx, s.store, rec, validated, parsed)
	if err != nil {
		return nil, nil, err
	}
	return subject, outcome, nil
}

// persistChallenge stores the ceremony state and returns its identifier.
func (s *Service) persistChallenge(ctx context.Context, tenantID, subjectID string, ceremony store.Ceremony,
	session *lib.SessionData) (string, time.Time, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("webauthn: marshal session: %w", err)
	}

	challengeBytes := decodeChallenge(session.Challenge)

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

// decodeChallenge turns the library's encoded challenge into the bytes the
// column holds.
//
// The bytes are indexed unique, so the same challenge cannot be registered
// twice even if the generator were ever to repeat. The library emits unpadded
// base64url; a value that does not decode falls back to its string form rather
// than failing the ceremony over an encoding detail, which keeps this shared by
// both surfaces without either having to care.
func decodeChallenge(encoded string) []byte {
	if b, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return b
	}
	return []byte(encoded)
}

// consumeChallenge marks the challenge used and returns its session data.
func (s *Service) consumeChallenge(ctx context.Context, tenantID, challengeID string,
	want store.Ceremony) (*store.Challenge, *lib.SessionData, error) {
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

// checkCredentialCap re-reads how many credentials a subject holds and refuses
// a further one.
//
// See the call site in CompleteRegistration for why the count is taken twice
// and for what this still does not guarantee.
func (s *Service) checkCredentialCap(ctx context.Context, tenantID, subjectID string) error {
	held, err := s.store.ListCredentials(ctx, tenantID, subjectID, false)
	if err != nil {
		return fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(held) >= s.cfg.MaxCredentialsPerSubject {
		return fmt.Errorf("%w: %d of %d",
			ErrTooManyCredentials, len(held), s.cfg.MaxCredentialsPerSubject)
	}
	return nil
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
//
// libAttestation is its inverse and has to stay one. The pair is what lets a
// credential be handed back to the library in the vocabulary the library
// itself uses, which matters on every assertion; see that function.
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

// libAttestation renders a stored attestation type in the vocabulary the
// library uses, and names the statement format where the stored value
// determines it.
//
// This is not cosmetic. With a metadata BLOB loaded, every assertion runs
// protocol.ValidateMetadata, which compares the type it is given against the
// attestationTypes of the model's MDS entry. Those entries say "basic_full"
// and "basic_surrogate"; the column says "basic" and "self", because that is
// what its CHECK constraint permits. Handing the stored spelling straight back
// therefore matches nothing, and a key that registered successfully could never
// sign in again, which is the sort of failure that ends with an operator
// turning metadata verification off.
//
// The inverse is exact for everything the library produces. It only ever emits
// the long forms; the short ones normaliseAttestation also accepts are there to
// absorb a value that has already been through this service once. The storage
// convention is unchanged by any of this, so a row written by an earlier build
// reads back exactly as a row written today, and no migration is needed for
// one.
//
// The format is not stored, and there is no column to put it in. It costs
// nothing for the four attested types, where the library uses it only to
// recognise a fido-u2f credential for the AppID extension. It is worth naming
// for "none": ValidateMetadata returns immediately for that format, which is
// the right answer, because an attestation of none carries no proof and the
// AAGUID beside it is a claim rather than an identification. Without the format
// the same credential is instead looked up in the BLOB, and under
// require_attestation a model with no entry is refused, so credentials enrolled
// before an operator turned attestation on would stop working at sign-in.
func libAttestation(t store.AttestationType) (attestationType, attestationFormat string) {
	switch t {
	case store.AttestationBasic:
		return "basic_full", ""
	case store.AttestationSelf:
		return "basic_surrogate", ""
	case store.AttestationAttCA:
		return "attca", ""
	case store.AttestationAnonCA:
		return "anonca", ""
	case store.AttestationNone:
		return "none", "none"
	}
	// store.AttestationIndirect, and anything a later schema adds. "indirect"
	// is a conveyance preference rather than an attestation type and the
	// library has no such type, so the honest answer is to claim nothing: an
	// empty type skips the comparison instead of failing it.
	return "", ""
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
	attestationType, attestationFormat := libAttestation(c.AttestationType)
	return lib.Credential{
		ID:                c.CredentialID,
		PublicKey:         c.PublicKey,
		AttestationType:   attestationType,
		AttestationFormat: attestationFormat,
		Transport:         toTransports(c.Transports),
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

// resolveAdminOrigins decides which origins the console's own ceremonies
// accept.
//
// The configured list wins when there is one. When there is not, a deployment
// serving a single origin is unambiguous and that origin is used: the console
// is served from it because there is nowhere else it could be served from.
// Anything else resolves to nothing, and nothing means the console refuses
// every ceremony rather than falling back to the relying party's whole list.
// Falling back would be the failure this exists to prevent, quietly; refusing
// is visible on the first sign-in attempt, and the configuration validator has
// already said so at startup.
func resolveAdminOrigins(cfg config.WebAuthn) []string {
	if len(cfg.AdminOrigins) > 0 {
		return normaliseOrigins(cfg.AdminOrigins)
	}
	if len(cfg.Origins) == 1 {
		return normaliseOrigins(cfg.Origins)
	}
	return nil
}

// normaliseOrigins puts configured origins into the form a browser writes them
// in the collected client data: lower case, and with no trailing slash.
//
// The configuration validator has already checked that each is a scheme, a host
// and an optional port, so this is about the two differences a human writing
// TOML introduces rather than about parsing.
func normaliseOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		out = append(out, normaliseOrigin(o))
	}
	return out
}

func normaliseOrigin(o string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/"))
}

// checkAdminOrigin refuses a console ceremony whose response was collected
// somewhere other than the console's own origin.
//
// The origin comes from the collected client data, which the authenticator
// signed over, so a response relayed from another page carries that page's
// origin and cannot be made to carry this one. The library has already checked
// the same value against the relying party's whole origin list; this is the
// narrower check the console needs and the library has no way to know about.
func (s *Service) checkAdminOrigin(origin string) error {
	if len(s.adminOrigins) == 0 {
		// See resolveAdminOrigins: an unanswered question fails closed.
		return fmt.Errorf("%w: the administration interface has no origin of its own "+
			"configured, so no console ceremony can be completed; set webauthn.admin_origins",
			ErrCeremonyFailed)
	}
	if slices.Contains(s.adminOrigins, normaliseOrigin(origin)) {
		return nil
	}
	return fmt.Errorf("%w: the response was collected at %q, which is not an origin the "+
		"administration interface is served from", ErrCeremonyFailed, origin)
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
