// Package risk reports what a completed authentication ceremony looked like,
// as a level, a list of reasons and the score they add up to.
//
// It reports. It never refuses. Every rule below has a legitimate cause as
// well as a suspicious one: a spare security key is dormant because it is a
// spare, a signature counter stalls because most passkeys do not implement
// one, a failure burst precedes a success because the user mistyped. Refusing
// on any of them would lock out people who did nothing wrong, and the
// integrating application is the one that knows what the user is about to do.
// So the service hands over what it saw and the application decides whether to
// ask for more.
//
// The policy is a table of rules, each with a weight, and two thresholds. That
// is deliberately all it is. There is no model, no training data, no
// third-party reputation feed, and so nothing that needs network access and
// nothing that cannot be explained to a user who was asked for a second
// factor. Every signal is derived from something the service already collected
// while completing the ceremony; none of them exists to be collected for this
// purpose.
//
// Assess is a pure function of its arguments. It reads no store, holds no
// clock of its own and performs no I/O. That is what makes the whole policy
// exhaustively testable, and it is what lets anyone reading an audit entry
// recompute the same assessment from the same inputs and get the same answer.
package risk

import (
	"fmt"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
)

// Level is the reported risk level.
//
// Three levels rather than a number, because the number is already there as
// the score. The level is what an application branches on, and a branch with
// more than three arms does not get written.
type Level string

const (
	// LevelLow means nothing in the ceremony stood out. It is not a statement
	// that the subject is who they claim to be, only that this service saw
	// nothing worth reporting.
	LevelLow Level = "low"

	// LevelElevated means at least one signal fired that says the ceremony
	// proved less than a full unphishable factor, or that the authenticator
	// was not quite the one enrolled.
	LevelElevated Level = "elevated"

	// LevelHigh means either one signal that is evidence of an attack rather
	// than of a weaker ceremony, or several weaker signals together.
	LevelHigh Level = "high"
)

// Ceremony names what completed the authentication.
//
// It is needed because several rules apply to one kind of ceremony only:
// asking whether user verification was absent is meaningless for a TOTP code,
// and counting a recovery-code redemption as a phishable factor as well would
// score the same weakness twice.
type Ceremony string

const (
	// CeremonyWebAuthn is a WebAuthn assertion.
	CeremonyWebAuthn Ceremony = "webauthn"

	// CeremonyTOTP is a verified time-based one-time password.
	CeremonyTOTP Ceremony = "totp"

	// CeremonyRecoveryCode is a redeemed single-use recovery code.
	CeremonyRecoveryCode Ceremony = "recovery-code"
)

// Reason names one signal that fired. The set is closed: docs/RISK.md
// documents every member, and Assess never reports anything else.
type Reason string

const (
	// ReasonSignatureCounterStalled is a signature counter that failed to
	// advance across two assertions, which is the signal WebAuthn documents
	// for two copies of one credential private key being in use.
	ReasonSignatureCounterStalled Reason = "signature_counter_stalled"

	// ReasonAuthenticatorBindingChanged is an authenticator whose observed
	// characteristics differ from the ones recorded at registration.
	ReasonAuthenticatorBindingChanged Reason = "authenticator_binding_changed"

	// ReasonUserVerificationAbsent is a WebAuthn assertion where the
	// authenticator proved possession only, with no PIN and no biometric.
	ReasonUserVerificationAbsent Reason = "user_verification_absent"

	// ReasonRecoveryCodeUsed is a ceremony completed by a recovery code, the
	// weakest factor the service offers and the one an attacker reaches for.
	ReasonRecoveryCodeUsed Reason = "recovery_code_used"

	// ReasonCredentialDormant is a credential that has not been used for
	// longer than the configured dormancy window.
	ReasonCredentialDormant Reason = "credential_dormant"

	// ReasonCredentialNew is a credential registered within the configured
	// window, so a freshly enrolled authenticator that authenticates
	// immediately is visible.
	ReasonCredentialNew Reason = "credential_new"

	// ReasonRecentFailuresSubject is at least one failed attempt against this
	// subject inside the current throttle window, before this success.
	ReasonRecentFailuresSubject Reason = "recent_failures_subject"

	// ReasonRecentFailuresNetwork is at least one failed attempt from this
	// source network inside the current throttle window.
	ReasonRecentFailuresNetwork Reason = "recent_failures_network"

	// ReasonTOTPOnly is a TOTP verification for a subject who holds no
	// WebAuthn credential at all, so the only factor available to them is a
	// phishable one.
	ReasonTOTPOnly Reason = "totp_only"
)

// AllReasons lists every declared reason.
//
// It is the authority for completeness: a reason that exists as a constant but
// is missing here would escape both the initialisation check below and the
// tests, so the two are kept adjacent. The order is the order Assess reports
// reasons in, which is fixed so that two identical ceremonies produce
// byte-identical claims and audit entries.
var AllReasons = []Reason{
	ReasonSignatureCounterStalled,
	ReasonAuthenticatorBindingChanged,
	ReasonUserVerificationAbsent,
	ReasonRecoveryCodeUsed,
	ReasonCredentialDormant,
	ReasonCredentialNew,
	ReasonRecentFailuresSubject,
	ReasonRecentFailuresNetwork,
	ReasonTOTPOnly,
}

// The default thresholds and windows.
//
// They are declared here, next to the weights they are compared against,
// because a threshold means nothing without the scale it scores. config.Default
// sets the same values; a test in this package asserts the two stay equal,
// which is the same arrangement as config.SystemTenantID, and for the same
// reason: internal/risk reads the configuration, so the configuration package
// cannot import it back.
const (
	// DefaultElevatedAt is the weight of the lightest single signal that says
	// the ceremony proved less than a full unphishable factor, or that the
	// authenticator was not the one enrolled. Anything at or above it is
	// worth telling the application about.
	DefaultElevatedAt = 20

	// DefaultHighAt is double DefaultElevatedAt: either one signal that is
	// evidence of an attack rather than of a weaker ceremony, or the weakest
	// factor together with the failures that preceded it.
	DefaultHighAt = 40

	// DefaultDormantAfter is ninety days. A security key kept as a spare is
	// routinely unused for a quarter, so a shorter window reports ordinary
	// behaviour as a signal.
	DefaultDormantAfter = 90 * 24 * time.Hour

	// DefaultNewCredentialWithin is one hour. An enrolment followed by a
	// sign-in is the normal shape of setting up an authenticator, so the
	// window only has to cover one sitting.
	DefaultNewCredentialWithin = time.Hour
)

// Input is what a completed ceremony observed.
//
// Every field is something the service already had in hand, or, for the two
// noted in internal/api/risk.go, something one query yields. Nothing here
// exists to be collected for risk reporting.
type Input struct {
	// Ceremony is what completed the authentication.
	Ceremony Ceremony

	// UserVerified reports whether the authenticator proved user identity
	// rather than mere possession. It is read from the authenticator data of
	// this ceremony, so it is false for a possession-only assertion on a
	// credential that was registered with user verification.
	UserVerified bool

	// CloneWarning is the WebAuthn signature counter signal.
	CloneWarning bool

	// BindingChanged reports that the authenticator characteristics differ
	// from those recorded at registration.
	BindingChanged bool

	// WebAuthnCredentials is how many unrevoked WebAuthn credentials the
	// subject is known to hold. Only whether it is zero is read, by totp_only:
	// zero on a TOTP ceremony means the subject has no unphishable factor to
	// fall back on. A caller that already knows one exists, because one just
	// authenticated, may therefore report one without counting.
	WebAuthnCredentials int

	// CredentialCreatedAt is when the credential in play was registered. A
	// zero value means no credential is in play, and the dormancy and
	// newness rules are then skipped rather than firing on the zero instant.
	CredentialCreatedAt time.Time

	// CredentialLastUsedAt is the last recorded use before this ceremony, or
	// nil for a credential that has never been used. A never-used credential
	// is measured from its registration instead, so one enrolled and
	// abandoned a year ago still reads as dormant.
	CredentialLastUsedAt *time.Time

	// RecentFailuresSubject and RecentFailuresNetwork are the throttle
	// counters for this subject and this source network inside the current
	// window. They are the failures the limiter had already recorded when
	// this ceremony succeeded.
	RecentFailuresSubject int
	RecentFailuresNetwork int
}

// Assessment is what Assess decided.
//
// The JSON member names are the wire form of the "risk" claim of an assertion
// and of the "risk" key of the audit entry detail. One type serves both on
// purpose: an operator comparing the two must never have to wonder whether a
// difference in spelling means a difference in meaning.
type Assessment struct {
	Level   Level    `json:"level"`
	Reasons []Reason `json:"reasons"`
	Score   int      `json:"score"`
}

// rule is one row of the policy.
//
// The policy is a table rather than a chain of conditionals so that the whole
// of it is readable in one place, so that adding a signal is adding a row, and
// so that a test can walk it exhaustively instead of guessing which branches
// exist.
type rule struct {
	reason Reason

	// weight is the default contribution to the score. An operator may
	// override it per reason; see config.Risk.Weights.
	weight int

	// meaning is the one-line explanation, kept beside the weight so the two
	// cannot drift. docs/RISK.md is the long form of the same table.
	meaning string

	// applies reports whether the signal fired.
	applies func(in Input, cfg config.Risk, now time.Time) bool
}

// rules is the policy, in reporting order.
var rules = []rule{
	{
		reason: ReasonSignatureCounterStalled,
		weight: 40,
		meaning: "the authenticator's signature counter did not advance, which is the " +
			"documented signal for two copies of one credential private key in use",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			return in.CloneWarning
		},
	},
	{
		reason:  ReasonAuthenticatorBindingChanged,
		weight:  20,
		meaning: "the authenticator's observed characteristics differ from those recorded at registration",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			return in.BindingChanged
		},
	},
	{
		reason:  ReasonUserVerificationAbsent,
		weight:  20,
		meaning: "the WebAuthn ceremony proved possession of the authenticator and not the identity of its holder",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			// Only a WebAuthn ceremony can report user verification. Firing
			// this for a TOTP code or a recovery code would score the same
			// weakness twice, once here and once as totp_only or
			// recovery_code_used.
			return in.Ceremony == CeremonyWebAuthn && !in.UserVerified
		},
	},
	{
		reason:  ReasonRecoveryCodeUsed,
		weight:  25,
		meaning: "the ceremony was completed by a single-use recovery code, the weakest factor the service offers",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			return in.Ceremony == CeremonyRecoveryCode
		},
	},
	{
		reason:  ReasonCredentialDormant,
		weight:  10,
		meaning: "the credential has not been used for longer than the configured dormancy window",
		applies: func(in Input, cfg config.Risk, now time.Time) bool {
			if in.CredentialCreatedAt.IsZero() {
				return false
			}
			// A credential that has never been used is measured from its
			// registration. Treating "never used" as "not dormant" would hide
			// exactly the case that matters: one enrolled long ago and left
			// alone until an attacker found it.
			since := in.CredentialCreatedAt
			if in.CredentialLastUsedAt != nil {
				since = *in.CredentialLastUsedAt
			}
			return now.Sub(since) > dormantAfter(cfg)
		},
	},
	{
		reason: ReasonCredentialNew,
		weight: 10,
		meaning: "the credential was registered within the configured window, so a " +
			"freshly enrolled authenticator is authenticating immediately",
		applies: func(in Input, cfg config.Risk, now time.Time) bool {
			if in.CredentialCreatedAt.IsZero() {
				return false
			}
			return now.Sub(in.CredentialCreatedAt) < newCredentialWithin(cfg)
		},
	},
	{
		reason: ReasonRecentFailuresSubject,
		weight: 10,
		meaning: "at least one attempt against this subject failed inside the current " +
			"throttle window before this one succeeded",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			// One failure is enough to fire, because the throttle window
			// already bounds how long it counts for and the weight is set so
			// that a single mistyped code stays low on its own. A second
			// configurable threshold here would be a knob whose only effect
			// is to duplicate the weight.
			return in.RecentFailuresSubject > 0
		},
	},
	{
		reason:  ReasonRecentFailuresNetwork,
		weight:  5,
		meaning: "at least one attempt from this source network failed inside the current throttle window",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			// The lightest weight in the table. One corporate gateway carries
			// many users, so failures on a network say much less about this
			// subject than failures against the subject do.
			return in.RecentFailuresNetwork > 0
		},
	},
	{
		reason: ReasonTOTPOnly,
		weight: 10,
		meaning: "the subject holds no WebAuthn credential, so the factor that " +
			"authenticated them is phishable and there is no stronger one to fall back on",
		applies: func(in Input, _ config.Risk, _ time.Time) bool {
			return in.Ceremony == CeremonyTOTP && in.WebAuthnCredentials == 0
		},
	},
}

// byReason indexes rules for the lookups below.
var byReason = map[Reason]*rule{}

// init validates the table at package initialisation, in the same spirit as
// internal/rbac.
//
// A reason declared as a constant and left out of the table would never fire,
// and a row whose reason is not in AllReasons would fire under a name nothing
// documents. Either mistake is invisible at runtime, so it fails the build
// instead.
func init() {
	for i := range rules {
		r := &rules[i]
		if r.reason == "" {
			panic("risk: a rule has an empty reason")
		}
		if r.weight <= 0 {
			panic(fmt.Sprintf("risk: rule %q has weight %d, which must be positive", r.reason, r.weight))
		}
		if r.meaning == "" {
			panic(fmt.Sprintf("risk: rule %q has no meaning", r.reason))
		}
		if r.applies == nil {
			panic(fmt.Sprintf("risk: rule %q has no predicate", r.reason))
		}
		if _, dup := byReason[r.reason]; dup {
			panic(fmt.Sprintf("risk: rule %q is declared twice", r.reason))
		}
		byReason[r.reason] = r
	}
	if len(byReason) != len(AllReasons) {
		panic(fmt.Sprintf("risk: %d rules for %d declared reasons", len(byReason), len(AllReasons)))
	}
	for _, reason := range AllReasons {
		if _, ok := byReason[reason]; !ok {
			panic(fmt.Sprintf("risk: reason %q is declared but has no rule", reason))
		}
	}
}

// Valid reports whether r is one of the declared reasons.
func (r Reason) Valid() bool {
	_, ok := byReason[r]
	return ok
}

// String returns the reason as it is written into a claim.
func (r Reason) String() string { return string(r) }

// Meaning returns the one-line explanation of the reason, for the
// administrative interface and for the documentation test. An unknown reason
// returns the empty string.
func (r Reason) Meaning() string {
	if rl, ok := byReason[r]; ok {
		return rl.meaning
	}
	return ""
}

// DefaultWeight returns the weight the reason carries before any configured
// override. An unknown reason returns zero.
func (r Reason) DefaultWeight() int {
	if rl, ok := byReason[r]; ok {
		return rl.weight
	}
	return 0
}

// Weight returns the weight cfg gives the reason.
//
// An override of zero is honoured, because turning one signal off without
// turning the whole feature off is a reasonable thing for an operator to want.
// config.Validate refuses a negative override and an unknown key, so nothing
// silently does nothing here.
func Weight(r Reason, cfg config.Risk) int {
	if w, ok := cfg.Weights[string(r)]; ok {
		return w
	}
	return r.DefaultWeight()
}

// Assess reports the risk of one completed ceremony.
//
// It is pure: the only clock is the now argument, there is no store and no
// I/O. Reasons come back in the fixed order of AllReasons, so two identical
// ceremonies produce identical claims and identical audit entries.
//
// With cfg.Enabled false it returns the low level, no reasons and a zero
// score, so a caller that reports it anyway says nothing rather than
// something wrong. internal/api omits the claim entirely in that case; see
// internal/api/risk.go.
func Assess(in Input, cfg config.Risk, now time.Time) Assessment {
	out := Assessment{Level: LevelLow, Reasons: []Reason{}}
	if !cfg.Enabled {
		return out
	}

	for i := range rules {
		r := &rules[i]
		if !r.applies(in, cfg, now) {
			continue
		}
		out.Reasons = append(out.Reasons, r.reason)
		out.Score += Weight(r.reason, cfg)
	}

	out.Level = LevelFor(out.Score, cfg)
	return out
}

// LevelFor maps a score onto a level.
//
// It is exported because the documentation test and the administrative
// interface both need to state the boundaries, and a second copy of the
// comparison would eventually disagree with this one. The comparisons are
// inclusive at the threshold: a score of exactly high_at is high, which is
// what "high at 40" reads as.
func LevelFor(score int, cfg config.Risk) Level {
	elevatedAt, highAt := thresholds(cfg)
	switch {
	case score >= highAt:
		return LevelHigh
	case score >= elevatedAt:
		return LevelElevated
	default:
		return LevelLow
	}
}

// thresholds resolves the two score boundaries.
//
// A non-positive threshold falls back to the default. config.Validate refuses
// one, so this only covers a caller holding a zero-value configuration, where
// comparing against zero would report every ceremony as high.
func thresholds(cfg config.Risk) (elevatedAt, highAt int) {
	elevatedAt, highAt = cfg.ElevatedAt, cfg.HighAt
	if elevatedAt < 1 {
		elevatedAt = DefaultElevatedAt
	}
	if highAt < 1 {
		highAt = DefaultHighAt
	}
	if highAt <= elevatedAt {
		// Validate refuses this too. Reached only from a hand-built
		// configuration, where collapsing the two levels into one would be
		// worse than ignoring the pair.
		elevatedAt, highAt = DefaultElevatedAt, DefaultHighAt
	}
	return elevatedAt, highAt
}

// dormantAfter resolves the dormancy window, falling back to the default for a
// non-positive value for the reason given on thresholds.
func dormantAfter(cfg config.Risk) time.Duration {
	if cfg.DormantAfter.Duration <= 0 {
		return DefaultDormantAfter
	}
	return cfg.DormantAfter.Duration
}

// newCredentialWithin resolves the newness window, with the same fallback.
func newCredentialWithin(cfg config.Risk) time.Duration {
	if cfg.NewCredentialWithin.Duration <= 0 {
		return DefaultNewCredentialWithin
	}
	return cfg.NewCredentialWithin.Duration
}
