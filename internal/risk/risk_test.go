package risk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
)

// now is the instant every case assesses at. Assess takes it as an argument,
// which is the whole reason this package can be tested exhaustively.
var now = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

// testConfig is the shipped default, which is what a deployment that sets
// nothing gets.
func testConfig() config.Risk { return config.Default().Risk }

// at returns a pointer to an instant, for Input.CredentialLastUsedAt.
func at(t time.Time) *time.Time { return &t }

// inputFor builds the minimal Input that makes exactly one reason fire.
//
// It is the heart of the exhaustive table below: every declared reason must
// have a case here, so a reason added without one fails the test rather than
// going untested.
func inputFor(t *testing.T, reason Reason) Input {
	t.Helper()
	switch reason {
	case ReasonSignatureCounterStalled:
		return Input{Ceremony: CeremonyWebAuthn, UserVerified: true, CloneWarning: true}
	case ReasonAuthenticatorBindingChanged:
		return Input{Ceremony: CeremonyWebAuthn, UserVerified: true, BindingChanged: true}
	case ReasonUserVerificationAbsent:
		return Input{Ceremony: CeremonyWebAuthn, UserVerified: false}
	case ReasonRecoveryCodeUsed:
		return Input{Ceremony: CeremonyRecoveryCode}
	case ReasonCredentialDormant:
		return Input{
			Ceremony:             CeremonyWebAuthn,
			UserVerified:         true,
			CredentialCreatedAt:  now.Add(-3 * 365 * 24 * time.Hour),
			CredentialLastUsedAt: at(now.Add(-100 * 24 * time.Hour)),
		}
	case ReasonCredentialNew:
		return Input{
			Ceremony:            CeremonyWebAuthn,
			UserVerified:        true,
			CredentialCreatedAt: now.Add(-5 * time.Minute),
		}
	case ReasonRecentFailuresSubject:
		return Input{Ceremony: CeremonyWebAuthn, UserVerified: true, RecentFailuresSubject: 1}
	case ReasonRecentFailuresNetwork:
		return Input{Ceremony: CeremonyWebAuthn, UserVerified: true, RecentFailuresNetwork: 1}
	case ReasonTOTPOnly:
		return Input{Ceremony: CeremonyTOTP, WebAuthnCredentials: 0}
	default:
		t.Fatalf("reason %q has no case in inputFor; every declared reason needs one", reason)
		return Input{}
	}
}

// TestEveryReasonFiresAloneAtItsExpectedLevel is the exhaustive table.
//
// Each reason is made to fire on its own, and the expected level is stated
// rather than computed from the weight, so that changing a weight without
// meaning to change the policy fails here.
func TestEveryReasonFiresAloneAtItsExpectedLevel(t *testing.T) {
	expected := map[Reason]Level{
		// The only signal that is evidence of a specific attack rather than
		// of a weaker ceremony, so it is the only one that is high alone.
		ReasonSignatureCounterStalled: LevelHigh,

		// Each says the ceremony proved less than it should have, or was not
		// quite the authenticator that was enrolled.
		ReasonAuthenticatorBindingChanged: LevelElevated,
		ReasonUserVerificationAbsent:      LevelElevated,
		ReasonRecoveryCodeUsed:            LevelElevated,

		// Each has a common innocent explanation, so each contributes to a
		// level without ever creating one.
		ReasonCredentialDormant:     LevelLow,
		ReasonCredentialNew:         LevelLow,
		ReasonRecentFailuresSubject: LevelLow,
		ReasonRecentFailuresNetwork: LevelLow,
		ReasonTOTPOnly:              LevelLow,
	}

	if len(expected) != len(AllReasons) {
		t.Fatalf("the table states %d reasons, want %d", len(expected), len(AllReasons))
	}

	cfg := testConfig()
	for _, reason := range AllReasons {
		want, ok := expected[reason]
		if !ok {
			t.Errorf("reason %q has no expected level", reason)
			continue
		}
		got := Assess(inputFor(t, reason), cfg, now)
		if len(got.Reasons) != 1 || got.Reasons[0] != reason {
			t.Errorf("%s alone produced reasons %v, want exactly [%s]", reason, got.Reasons, reason)
			continue
		}
		if got.Score != reason.DefaultWeight() {
			t.Errorf("%s alone scored %d, want its weight %d", reason, got.Score, reason.DefaultWeight())
		}
		if got.Level != want {
			t.Errorf("%s alone = %s at score %d, want %s", reason, got.Level, got.Score, want)
		}
	}
}

// TestNoSignalIsLowWithNoReasons checks the ordinary case.
func TestNoSignalIsLowWithNoReasons(t *testing.T) {
	got := Assess(Input{Ceremony: CeremonyWebAuthn, UserVerified: true, WebAuthnCredentials: 1},
		testConfig(), now)
	if got.Level != LevelLow || got.Score != 0 || len(got.Reasons) != 0 {
		t.Errorf("a clean ceremony = %+v, want low, score 0, no reasons", got)
	}
	// Non-nil, so the claim carries [] rather than null and a verifier does
	// not have to handle both.
	if got.Reasons == nil {
		t.Error("Reasons is nil; it must marshal as [] rather than null")
	}
}

// TestDisabledReportsLowWithNoReasons checks that a deployment with reporting
// off says nothing rather than something wrong.
func TestDisabledReportsLowWithNoReasons(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false

	// An input where every signal that can co-occur fires.
	got := Assess(maximalInput(), cfg, now)
	if got.Level != LevelLow || got.Score != 0 || len(got.Reasons) != 0 {
		t.Errorf("with reporting off = %+v, want low, score 0, no reasons", got)
	}
}

// maximalInput fires every reason that can fire in one ceremony.
//
// totp_only cannot join, because it needs a TOTP ceremony and the WebAuthn
// signals need a WebAuthn one, and credential_new cannot join credential_dormant
// under any sane pair of windows.
func maximalInput() Input {
	return Input{
		Ceremony:              CeremonyWebAuthn,
		UserVerified:          false,
		CloneWarning:          true,
		BindingChanged:        true,
		WebAuthnCredentials:   1,
		CredentialCreatedAt:   now.Add(-3 * 365 * 24 * time.Hour),
		CredentialLastUsedAt:  at(now.Add(-200 * 24 * time.Hour)),
		RecentFailuresSubject: 4,
		RecentFailuresNetwork: 9,
	}
}

// TestBoundariesAreInclusive pins both thresholds.
//
// A score of exactly elevated_at is elevated and a score of exactly high_at is
// high, which is what "elevated at 20" reads as. One below each is the level
// underneath.
func TestBoundariesAreInclusive(t *testing.T) {
	cfg := testConfig()
	cases := []struct {
		score int
		want  Level
	}{
		{0, LevelLow},
		{cfg.ElevatedAt - 1, LevelLow},
		{cfg.ElevatedAt, LevelElevated},
		{cfg.ElevatedAt + 1, LevelElevated},
		{cfg.HighAt - 1, LevelElevated},
		{cfg.HighAt, LevelHigh},
		{cfg.HighAt + 1, LevelHigh},
	}
	for _, c := range cases {
		if got := LevelFor(c.score, cfg); got != c.want {
			t.Errorf("LevelFor(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

// TestWeightOverridesAreHonoured checks that the configured table wins.
func TestWeightOverridesAreHonoured(t *testing.T) {
	cfg := testConfig()
	cfg.Weights = map[string]int{
		// Raised so that one dormant credential alone reaches high.
		string(ReasonCredentialDormant): 40,
		// Silenced. An operator who does not want a signal sets it to zero;
		// the reason still appears, because it did fire, and contributes
		// nothing to the score.
		string(ReasonRecentFailuresSubject): 0,
	}

	if got := Weight(ReasonCredentialDormant, cfg); got != 40 {
		t.Errorf("overridden weight = %d, want 40", got)
	}
	if got := Weight(ReasonRecentFailuresNetwork, cfg); got != ReasonRecentFailuresNetwork.DefaultWeight() {
		t.Errorf("un-overridden weight = %d, want the default %d",
			got, ReasonRecentFailuresNetwork.DefaultWeight())
	}

	dormant := Assess(inputFor(t, ReasonCredentialDormant), cfg, now)
	if dormant.Level != LevelHigh || dormant.Score != 40 {
		t.Errorf("with the override, a dormant credential = %+v, want high at 40", dormant)
	}

	silenced := Assess(inputFor(t, ReasonRecentFailuresSubject), cfg, now)
	if silenced.Score != 0 || silenced.Level != LevelLow {
		t.Errorf("a zero-weighted reason scored %d at %s, want 0 and low",
			silenced.Score, silenced.Level)
	}
	if !slices.Contains(silenced.Reasons, ReasonRecentFailuresSubject) {
		t.Error("a zero-weighted reason was dropped from the list; it still fired")
	}
}

// TestCombinationsThatReachHigh states the pairings the defaults are chosen
// for, so that retuning a weight cannot quietly change which shapes escalate.
func TestCombinationsThatReachHigh(t *testing.T) {
	cfg := testConfig()

	cases := []struct {
		name string
		in   Input
		want Level
	}{
		{
			// The account-takeover shape: the weakest factor redeemed right
			// after failures against the same account from the same network.
			name: "recovery code after a failure burst",
			in: Input{
				Ceremony:              CeremonyRecoveryCode,
				RecentFailuresSubject: 3,
				RecentFailuresNetwork: 3,
			},
			want: LevelHigh,
		},
		{
			// A possession-only assertion from an authenticator whose
			// characteristics no longer match the enrolled ones.
			name: "possession only and the binding moved",
			in:   Input{Ceremony: CeremonyWebAuthn, BindingChanged: true},
			want: LevelHigh,
		},
		{
			// One mistyped code before a success must not escalate anything.
			name: "one typo then a success",
			in: Input{
				Ceremony:              CeremonyWebAuthn,
				UserVerified:          true,
				RecentFailuresSubject: 1,
				RecentFailuresNetwork: 1,
			},
			want: LevelLow,
		},
		{
			// A subject with nothing but TOTP is a deployment choice as much
			// as a risk, so it stays low on its own even with a failure from
			// the network.
			name: "totp only from a busy network",
			in: Input{
				Ceremony:              CeremonyTOTP,
				RecentFailuresNetwork: 1,
			},
			want: LevelLow,
		},
		{
			name: "totp only after failures against this subject",
			in: Input{
				Ceremony:              CeremonyTOTP,
				RecentFailuresSubject: 2,
			},
			want: LevelElevated,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Assess(c.in, cfg, now); got.Level != c.want {
				t.Errorf("= %s at score %d with %v, want %s", got.Level, got.Score, got.Reasons, c.want)
			}
		})
	}
}

// TestReasonsAreReportedInDeclaredOrder checks the property the claim rests
// on: two identical ceremonies must produce identical claims, byte for byte,
// so a caller may compare them and an audit entry may be recomputed.
func TestReasonsAreReportedInDeclaredOrder(t *testing.T) {
	got := Assess(maximalInput(), testConfig(), now)
	var want []Reason
	for _, reason := range AllReasons {
		if slices.Contains(got.Reasons, reason) {
			want = append(want, reason)
		}
	}
	if !slices.Equal(got.Reasons, want) {
		t.Errorf("reasons = %v, want them in declared order %v", got.Reasons, want)
	}
	if len(got.Reasons) < 5 {
		t.Errorf("the maximal input fired only %d reasons: %v", len(got.Reasons), got.Reasons)
	}
	if got.Level != LevelHigh {
		t.Errorf("the maximal input = %s, want high", got.Level)
	}
}

// TestEveryDeclaredReasonHasAWeightAndAMeaning is the completeness invariant,
// in the same style as internal/rbac.
//
// A reason declared as a constant but absent from the table would never fire,
// and one with no meaning has nothing to put in the documentation. The
// initialiser panics on either, so reaching this test at all is most of the
// proof; it is written out so that the invariant is stated where a reader
// looks for it.
func TestEveryDeclaredReasonHasAWeightAndAMeaning(t *testing.T) {
	seen := map[Reason]int{}
	for _, reason := range AllReasons {
		seen[reason]++
		if seen[reason] > 1 {
			t.Errorf("reason %q appears %d times in AllReasons", reason, seen[reason])
		}
		if reason == "" {
			t.Error("AllReasons contains an empty reason")
		}
		if !reason.Valid() {
			t.Errorf("reason %q reports itself invalid, so it has no rule", reason)
		}
		if reason.DefaultWeight() <= 0 {
			t.Errorf("reason %q has weight %d, which must be positive", reason, reason.DefaultWeight())
		}
		if reason.Meaning() == "" {
			t.Errorf("reason %q has no documented meaning", reason)
		}
		if reason.String() != string(reason) {
			t.Errorf("String() disagrees with the underlying value for %q", reason)
		}
	}
	if len(rules) != len(AllReasons) {
		t.Errorf("%d rules for %d declared reasons", len(rules), len(AllReasons))
	}
	for i := range rules {
		if !slices.Contains(AllReasons, rules[i].reason) {
			t.Errorf("rule %q is not listed in AllReasons", rules[i].reason)
		}
	}
}

// TestUnknownReasonHasNoWeight checks that an undeclared reason cannot creep
// into a claim through the configured weight table.
func TestUnknownReasonHasNoWeight(t *testing.T) {
	unknown := Reason("impossible_travel")
	if unknown.Valid() {
		t.Error("an undeclared reason reports itself valid")
	}
	if got := unknown.DefaultWeight(); got != 0 {
		t.Errorf("an undeclared reason has weight %d, want 0", got)
	}
	if got := unknown.Meaning(); got != "" {
		t.Errorf("an undeclared reason has meaning %q, want none", got)
	}
}

// TestConfigDefaultsMatchThisPackage keeps the two copies of the policy
// constants equal.
//
// internal/config cannot import this package, because this package reads its
// configuration, so the defaults are declared twice. This is the test the
// comment on the constants promises.
func TestConfigDefaultsMatchThisPackage(t *testing.T) {
	cfg := config.Default().Risk
	if !cfg.Enabled {
		t.Error("risk reporting is off by default; it changes nothing about who gets in")
	}
	if cfg.ElevatedAt != DefaultElevatedAt {
		t.Errorf("config elevated_at = %d, want %d", cfg.ElevatedAt, DefaultElevatedAt)
	}
	if cfg.HighAt != DefaultHighAt {
		t.Errorf("config high_at = %d, want %d", cfg.HighAt, DefaultHighAt)
	}
	if cfg.DormantAfter.Duration != DefaultDormantAfter {
		t.Errorf("config dormant_after = %s, want %s", cfg.DormantAfter.Duration, DefaultDormantAfter)
	}
	if cfg.NewCredentialWithin.Duration != DefaultNewCredentialWithin {
		t.Errorf("config new_credential_within = %s, want %s",
			cfg.NewCredentialWithin.Duration, DefaultNewCredentialWithin)
	}
	if len(cfg.Weights) != 0 {
		t.Errorf("the default weight overrides are %v, want none", cfg.Weights)
	}
}

// TestConfigReasonKeysMatchAllReasons keeps the other duplicated list equal.
//
// config.RiskReasons is what Validate checks a [risk.weights] key against. If
// it drifts from AllReasons, either a real reason becomes unconfigurable or a
// name that does nothing becomes configurable.
func TestConfigReasonKeysMatchAllReasons(t *testing.T) {
	want := make([]string, 0, len(AllReasons))
	for _, reason := range AllReasons {
		want = append(want, string(reason))
	}
	if !slices.Equal(config.RiskReasons, want) {
		t.Errorf("config.RiskReasons = %v, want %v", config.RiskReasons, want)
	}
}

// TestZeroValueConfigDoesNotReportEverythingAsHigh checks the fallback.
//
// Validate refuses a threshold below one, so this only happens to a caller
// holding a hand-built configuration. Comparing a score against zero would
// report a ceremony with no signal at all as high, which is the worst possible
// failure mode for a feature whose whole argument is that it is predictable.
func TestZeroValueConfigDoesNotReportEverythingAsHigh(t *testing.T) {
	cfg := config.Risk{Enabled: true}
	clean := Assess(Input{Ceremony: CeremonyWebAuthn, UserVerified: true, WebAuthnCredentials: 1}, cfg, now)
	if clean.Level != LevelLow {
		t.Errorf("a clean ceremony under a zero-value configuration = %s, want low", clean.Level)
	}
	if got := Assess(inputFor(t, ReasonSignatureCounterStalled), cfg, now); got.Level != LevelHigh {
		t.Errorf("a stalled counter under a zero-value configuration = %s, want high", got.Level)
	}
}

// TestNeverUsedCredentialIsMeasuredFromRegistration checks the dormancy
// fallback.
//
// A credential enrolled a year ago and never used is dormant. Reading a nil
// last-use as "not dormant" would hide exactly the case that matters.
func TestNeverUsedCredentialIsMeasuredFromRegistration(t *testing.T) {
	cfg := testConfig()

	old := Assess(Input{
		Ceremony:            CeremonyWebAuthn,
		UserVerified:        true,
		WebAuthnCredentials: 1,
		CredentialCreatedAt: now.Add(-365 * 24 * time.Hour),
	}, cfg, now)
	if !slices.Contains(old.Reasons, ReasonCredentialDormant) {
		t.Errorf("a credential enrolled a year ago and never used is not dormant: %v", old.Reasons)
	}

	// With no credential in play at all, neither of the two credential rules
	// may fire on the zero instant.
	none := Assess(Input{Ceremony: CeremonyRecoveryCode}, cfg, now)
	for _, unwanted := range []Reason{ReasonCredentialDormant, ReasonCredentialNew} {
		if slices.Contains(none.Reasons, unwanted) {
			t.Errorf("%s fired with no credential in play: %v", unwanted, none.Reasons)
		}
	}
}

// TestAssessmentMarshalsAsTheDocumentedClaim pins the wire form, since it is
// both a signed claim and an audit entry field.
func TestAssessmentMarshalsAsTheDocumentedClaim(t *testing.T) {
	raw, err := json.Marshal(Assess(inputFor(t, ReasonRecoveryCodeUsed), testConfig(), now))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"level":"elevated","reasons":["recovery_code_used"],"score":25}`
	if string(raw) != want {
		t.Errorf("marshalled as %s, want %s", raw, want)
	}
}

// TestDocumentedReasonTableIsComplete checks docs/RISK.md against the code.
//
// The documentation is the product here as much as the code is: the feature's
// argument is that the policy can be read and explained, and a reason absent
// from the table cannot be. Every reason must appear with its default weight.
func TestDocumentedReasonTableIsComplete(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "RISK.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("documentation not present: %v", err)
	}
	doc := string(raw)

	for _, reason := range AllReasons {
		if !strings.Contains(doc, "`"+string(reason)+"`") {
			t.Errorf("%s does not document the reason %s", path, reason)
		}
	}
	for _, level := range []Level{LevelLow, LevelElevated, LevelHigh} {
		if !strings.Contains(doc, "`"+string(level)+"`") {
			t.Errorf("%s does not document the level %s", path, level)
		}
	}
	// The weights are the policy. A table that states a different number from
	// the one the code scores is worse than no table.
	for _, reason := range AllReasons {
		row := rowFor(doc, string(reason))
		if row == "" {
			continue
		}
		if !strings.Contains(row, "| "+strconv.Itoa(reason.DefaultWeight())+" |") {
			t.Errorf("%s states the wrong weight for %s; the code scores %d. Row: %s",
				path, reason, reason.DefaultWeight(), row)
		}
	}
}

// rowFor returns the Markdown table row mentioning name, or the empty string.
func rowFor(doc, name string) string {
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| `"+name+"`") {
			return line
		}
	}
	return ""
}
