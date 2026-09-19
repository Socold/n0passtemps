package webauthn_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

// The console's ceremonies, and above all the two directions that must not
// work.
//
// An administrative credential authenticating a subject would let an operator
// sign in as any user; a subject's credential signing into the console would
// make every enrolled user an administrator. The second is the one that ends a
// deployment, so both directions are asserted here rather than left to follow
// from the design.

// adminToken seeds an administrative token. The selector and the verifier are
// stand-ins: nothing in a ceremony reads either, because a passkey replaces the
// pasted secret rather than accompanying it.
func (f *fixture) adminToken(name string, role store.Role, tune ...func(*store.AdminToken)) *store.AdminToken {
	f.t.Helper()
	tok := &store.AdminToken{
		ID:           uuid.NewString(),
		TenantID:     testTenant,
		Name:         name,
		Selector:     strings.ReplaceAll(uuid.NewString(), "-", ""),
		VerifierHash: "not-a-real-hash",
		Role:         role,
		CreatedAt:    f.clock.now(),
	}
	for _, fn := range tune {
		fn(tok)
	}
	if err := f.store.CreateAdminToken(f.ctx, tok); err != nil {
		f.t.Fatalf("seed administrative token: %v", err)
	}
	return tok
}

// adminRegister runs a whole console enrolment ceremony.
func (f *fixture) adminRegister(tok *store.AdminToken, a *virtualAuthenticator) (*store.AdminCredential, error) {
	f.t.Helper()
	begin, err := f.svc.BeginAdminRegistration(f.ctx, tok)
	if err != nil {
		return nil, err
	}
	resp, err := a.create(begin.Options)
	if err != nil {
		f.t.Fatalf("authenticator create: %v", err)
	}
	return f.svc.CompleteAdminRegistration(f.ctx, tok, begin.ChallengeID, resp, "the key on my keyring")
}

func (f *fixture) mustAdminRegister(tok *store.AdminToken, a *virtualAuthenticator) *store.AdminCredential {
	f.t.Helper()
	cred, err := f.adminRegister(tok, a)
	if err != nil {
		f.t.Fatalf("a genuine administrative enrolment was refused: %v", err)
	}
	return cred
}

// adminAssert runs a whole console sign-in ceremony.
func (f *fixture) adminAssert(a *virtualAuthenticator) (*webauthn.AdminAssertionResult, error) {
	f.t.Helper()
	begin, err := f.svc.BeginAdminAssertion(f.ctx, testTenant)
	if err != nil {
		return nil, err
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		f.t.Fatalf("authenticator get: %v", err)
	}
	return f.svc.CompleteAdminAssertion(f.ctx, testTenant, begin.ChallengeID, resp)
}

// testAppOrigin and testConsoleOrigin are the two surfaces of one relying
// party: the origin the integrating application serves its front end from, and
// the one the console is served from. Both are under testRPID, so an
// authenticator will produce a response for either.
const (
	testAppOrigin     = "https://app.login.example.test"
	testConsoleOrigin = "https://console.login.example.test"
)

// twoOriginFixture is a deployment whose relying party serves both surfaces,
// with the console named as its own.
func twoOriginFixture(t *testing.T, tune ...func(*config.WebAuthn)) *fixture {
	t.Helper()
	return newFixture(t, append([]func(*config.WebAuthn){func(c *config.WebAuthn) {
		c.Origins = []string{testAppOrigin, testConsoleOrigin}
		c.AdminOrigins = []string{testConsoleOrigin}
	}}, tune...)...)
}

// TestTheConsoleIsHeldToItsOwnOrigin is the property a passkey is chosen for,
// stated for the surface that needs it most.
//
// The two surfaces share a relying party identifier, so a page served by the
// integrating application can ask an authenticator for an assertion that is
// valid under it, and the library will accept the origin because it is one the
// relying party serves. Nothing about the credential separation helps: the key
// presented is the administrator's own. Only the console's own origin list
// refuses it, and without that refusal any origin trusted to sign a user in
// would be trusted to sign an administrator in.
func TestTheConsoleIsHeldToItsOwnOrigin(t *testing.T) {
	t.Run("an enrolment from the application's origin is refused", func(t *testing.T) {
		f := twoOriginFixture(t)
		tok := f.adminToken("Owner", store.RoleFull)

		_, err := f.adminRegister(tok, f.authenticatorAt(testAppOrigin, modelA))
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Fatalf("enrolment from the application's origin returned %v, want ErrCeremonyFailed: "+
				"the page enrolling the key would decide which key opens the console", err)
		}
		creds, err := f.store.ListAdminCredentials(f.ctx, testTenant, tok.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 0 {
			t.Errorf("the refused enrolment stored %d credential(s)", len(creds))
		}
	})

	t.Run("a sign-in from the application's origin is refused", func(t *testing.T) {
		f := twoOriginFixture(t)
		tok := f.adminToken("Owner", store.RoleFull)

		// The key is enrolled properly, from the console, so the only thing
		// wrong with the sign-in below is where it was collected.
		key := f.authenticatorAt(testConsoleOrigin, modelA)
		f.mustAdminRegister(tok, key)

		relayed := f.authenticatorAt(testAppOrigin, modelA)
		relayed.credentials = key.credentials

		_, err := f.adminAssert(relayed)
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Fatalf("console sign-in from the application's origin returned %v, want "+
				"ErrCeremonyFailed", err)
		}
		if !strings.Contains(err.Error(), testAppOrigin) {
			t.Errorf("refusal reason = %q, want one naming the origin, for the audit entry", err)
		}
	})

	t.Run("the console's own origin still works", func(t *testing.T) {
		// Without this the two cases above would pass against a console that
		// refuses everything.
		f := twoOriginFixture(t)
		tok := f.adminToken("Owner", store.RoleFull)
		key := f.authenticatorAt(testConsoleOrigin, modelA)
		f.mustAdminRegister(tok, key)

		result, err := f.adminAssert(key)
		if err != nil {
			t.Fatalf("a sign-in from the console's own origin was refused: %v", err)
		}
		if result.Token.ID != tok.ID {
			t.Errorf("resolved token = %q, want %q", result.Token.ID, tok.ID)
		}
	})
}

// TestAConsoleWithNoOriginOfItsOwnRefusesEveryCeremony pins the direction the
// resolution fails in.
//
// A deployment serving several origins has to say which one the console is on.
// Until it does, falling back to the relying party's whole list would be the
// failure this exists to prevent, arrived at quietly; refusing is visible, and
// the configuration validator has already said so at startup.
func TestAConsoleWithNoOriginOfItsOwnRefusesEveryCeremony(t *testing.T) {
	f := newFixture(t, func(c *config.WebAuthn) {
		c.Origins = []string{testAppOrigin, testConsoleOrigin}
	})
	tok := f.adminToken("Owner", store.RoleFull)

	_, err := f.adminRegister(tok, f.authenticatorAt(testConsoleOrigin, modelA))
	if !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("enrolment with no console origin configured returned %v, want ErrCeremonyFailed", err)
	}
	if !strings.Contains(err.Error(), "admin_origins") {
		t.Errorf("refusal reason = %q, want the setting an operator has to fill in", err)
	}
}

// TestASingleOriginDeploymentNeedsNoConsoleOriginSetting covers the common case.
// With one origin there is no question to answer, and the console is held to it.
func TestASingleOriginDeploymentNeedsNoConsoleOriginSetting(t *testing.T) {
	f := newFixture(t)
	if got := f.svc.AdminOrigins(); len(got) != 1 || got[0] != testOrigin {
		t.Fatalf("console origins = %v, want the single configured origin %q", got, testOrigin)
	}

	tok := f.adminToken("Owner", store.RoleFull)
	key := f.authenticator(modelA)
	f.mustAdminRegister(tok, key)
	if _, err := f.adminAssert(key); err != nil {
		t.Fatalf("a console sign-in on a single-origin deployment was refused: %v", err)
	}
}

func TestAdminEnrolmentThenSignInResolvesTheTokenAndItsRole(t *testing.T) {
	f := newFixture(t)
	tok := f.adminToken("Support desk", store.RoleOperator)
	a := f.authenticator(modelA)

	cred := f.mustAdminRegister(tok, a)
	if cred.AdminTokenID != tok.ID {
		t.Errorf("enrolled credential names token %q, want %q", cred.AdminTokenID, tok.ID)
	}

	result, err := f.adminAssert(a)
	if err != nil {
		t.Fatalf("a genuine console sign-in was refused: %v", err)
	}
	if result.Token.ID != tok.ID {
		t.Errorf("resolved token = %q, want %q", result.Token.ID, tok.ID)
	}
	if result.Credential.ID != cred.ID {
		t.Errorf("resolved credential = %q, want the one that was used, %q",
			result.Credential.ID, cred.ID)
	}
	if !result.Outcome.UserVerified {
		t.Error("user verification is required on this route, so the outcome must report it")
	}
}

// TestAdminRoleComesFromTheTokenAndNotTheCredential enrols one key for each of
// two tokens and checks that the role each sign-in reports is the role of the
// token it resolved.
//
// A credential proves who, never what they may do. If a role could travel on a
// passkey, enrolling one would be a privilege change, and the enrolment route
// is deliberately not gated as one.
func TestAdminRoleComesFromTheTokenAndNotTheCredential(t *testing.T) {
	f := newFixture(t)
	auditor := f.adminToken("Reader", store.RoleAuditor)
	full := f.adminToken("Owner", store.RoleFull)

	auditorKey := f.authenticator(modelA)
	fullKey := f.authenticator(modelB)
	f.mustAdminRegister(auditor, auditorKey)
	f.mustAdminRegister(full, fullKey)

	for _, tc := range []struct {
		name string
		key  *virtualAuthenticator
		want store.Role
	}{
		{"auditor", auditorKey, store.RoleAuditor},
		{"full", fullKey, store.RoleFull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := f.adminAssert(tc.key)
			if err != nil {
				t.Fatalf("sign-in refused: %v", err)
			}
			if result.Token.Role != tc.want {
				t.Errorf("role = %q, want %q: the role must come from the token record",
					result.Token.Role, tc.want)
			}
		})
	}
}

// TestAdminCredentialCannotAuthenticateASubject is the first of the two
// directions.
//
// The administrator's own key is presented at the usernameless subject route,
// which is the closest thing the public surface has to the console's sign-in.
// It must resolve nobody: the credential is not in the subject table, so there
// is nothing for the ceremony to verify against.
func TestAdminCredentialCannotAuthenticateASubject(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	subjectKey := f.authenticator(modelA)
	f.mustRegister(sub, subjectKey)

	tok := f.adminToken("Owner", store.RoleFull)
	adminKey := f.authenticator(modelB)
	f.mustAdminRegister(tok, adminKey)

	if _, _, err := f.discoverableAssert(adminKey); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("usernameless assertion with an administrative passkey returned %v, "+
			"want ErrCeremonyFailed: an operator's key must not sign in as a person", err)
	}

	// The named route never even offers the credential: the allow list is built
	// from the subject's own credentials, so the device holding only the
	// administrative one finds nothing to answer with.
	begin, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatalf("begin named assertion: %v", err)
	}
	if _, err := adminKey.get(begin.Options); err == nil {
		t.Error("the subject's allow list offered the administrative credential")
	}
}

// TestSubjectCredentialCannotSignIntoTheConsole is the second direction, and
// the one that would turn every enrolled user into an administrator.
func TestSubjectCredentialCannotSignIntoTheConsole(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	subjectKey := f.authenticator(modelA)
	f.mustRegister(sub, subjectKey)

	// A token exists, so the failure cannot be "there is nobody to sign in as".
	f.adminToken("Owner", store.RoleFull)

	_, err := f.adminAssert(subjectKey)
	if !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("console sign-in with a subject passkey returned %v, want ErrCeremonyFailed", err)
	}
	if !strings.Contains(err.Error(), "not enrolled for the administration interface") {
		t.Errorf("refusal reason = %q, want the one an operator can act on", err)
	}
}

// TestOneAuthenticatorEnrolledInBothSpacesHoldsTwoCredentials pins the handle
// separation.
//
// The same device is enrolled for a subject and for an administrator. Because
// the two user handles are derived under different domain separators, the
// authenticator treats them as different credentials rather than replacing one
// with the other, and the two identifiers differ. If they were ever equal, one
// row would answer for both surfaces.
func TestOneAuthenticatorEnrolledInBothSpacesHoldsTwoCredentials(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	tok := f.adminToken("Owner", store.RoleFull)

	a := f.authenticator(modelA)
	subjectCred := f.mustRegister(sub, a)
	adminCred := f.mustAdminRegister(tok, a)

	if bytes.Equal(subjectCred.CredentialID, adminCred.CredentialID) {
		t.Fatal("one credential identifier serves both spaces, so a single row answers for both surfaces")
	}

	if _, err := f.store.GetAdminCredentialByID(f.ctx, testTenant, testRPID, subjectCred.CredentialID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the subject's credential is visible to the console lookup: %v", err)
	}
	if _, err := f.store.GetCredentialByID(f.ctx, testTenant, testRPID, adminCred.CredentialID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the administrative credential is visible to the subject lookup: %v", err)
	}
}

// TestConsoleAndSubjectChallengesCannotBeSwapped covers the other half of the
// separation.
//
// A console sign-in ceremony and a subject usernameless ceremony are otherwise
// indistinguishable: neither names an identity and both require user
// verification. Held in one table, a caller could start one and finish it
// through the other's endpoint, choosing which surface's checks and which
// surface's rate limit applied.
func TestConsoleAndSubjectChallengesCannotBeSwapped(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	f.mustRegister(sub, f.authenticator(modelA))
	tok := f.adminToken("Owner", store.RoleFull)
	f.mustAdminRegister(tok, f.authenticator(modelB))

	console, err := f.svc.BeginAdminAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, console.ChallengeID, []byte("{}")); !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("a console challenge completed through the subject route returned %v, want ErrChallengeNotFound", err)
	}

	subjectSide, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CompleteAdminAssertion(f.ctx, testTenant, subjectSide.ChallengeID, []byte("{}")); !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("a subject challenge completed through the console route returned %v, want ErrChallengeNotFound", err)
	}
}

// TestAdminEnrolmentChallengeCannotBeRedirectedToAnotherToken covers the
// enrolment side of the same idea. Grafting a passkey onto a colleague's token
// would be handing yourself their sign-in.
func TestAdminEnrolmentChallengeCannotBeRedirectedToAnotherToken(t *testing.T) {
	f := newFixture(t)
	mine := f.adminToken("Mine", store.RoleOperator)
	theirs := f.adminToken("Theirs", store.RoleFull)
	a := f.authenticator(modelA)

	begin, err := f.svc.BeginAdminRegistration(f.ctx, mine)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.create(begin.Options)
	if err != nil {
		t.Fatalf("authenticator create: %v", err)
	}

	if _, err = f.svc.CompleteAdminRegistration(f.ctx, theirs, begin.ChallengeID, resp, ""); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("completion for another token returned %v, want ErrCeremonyFailed", err)
	}

	creds, err := f.store.ListAdminCredentials(f.ctx, testTenant, theirs.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Errorf("the other token gained %d credentials", len(creds))
	}
}

// TestWithdrawnAdminCredentialSignsInNobody asserts the refusal an operator
// depends on after losing a key.
func TestWithdrawnAdminCredentialSignsInNobody(t *testing.T) {
	f := newFixture(t)
	tok := f.adminToken("Owner", store.RoleFull)
	a := f.authenticator(modelA)
	cred := f.mustAdminRegister(tok, a)

	if _, err := f.adminAssert(a); err != nil {
		t.Fatalf("sign-in before the withdrawal was refused: %v", err)
	}
	if err := f.store.RevokeAdminCredential(f.ctx, testTenant, cred.ID, "left in a taxi", f.clock.now()); err != nil {
		t.Fatalf("withdraw credential: %v", err)
	}

	_, err := f.adminAssert(a)
	if !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("sign-in with a withdrawn passkey returned %v, want ErrCeremonyFailed", err)
	}
	if !strings.Contains(err.Error(), "withdrawn") {
		t.Errorf("refusal reason = %q, want one that names the withdrawal for the audit entry", err)
	}
}

// TestAdminSignInFollowsTheTokenBecomingUnusable covers the case the role
// question turns on: the credential is intact, and the identity behind it is
// not.
func TestAdminSignInFollowsTheTokenBecomingUnusable(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f := newFixture(t)
		tok := f.adminToken("Owner", store.RoleFull)
		a := f.authenticator(modelA)
		f.mustAdminRegister(tok, a)

		if err := f.store.RevokeAdminToken(f.ctx, testTenant, tok.ID, f.clock.now()); err != nil {
			t.Fatalf("revoke token: %v", err)
		}
		_, err := f.adminAssert(a)
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Fatalf("sign-in on a revoked token returned %v, want ErrCeremonyFailed", err)
		}
		if !strings.Contains(err.Error(), "administrative token is expired, withdrawn") {
			t.Errorf("refusal reason = %q, want one that names the token", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newFixture(t)
		expiry := f.clock.now().Add(time.Hour)
		tok := f.adminToken("Owner", store.RoleFull, func(t *store.AdminToken) {
			t.ExpiresAt = &expiry
		})
		a := f.authenticator(modelA)
		f.mustAdminRegister(tok, a)

		f.clock.add(2 * time.Hour)

		_, err := f.adminAssert(a)
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Fatalf("sign-in on an expired token returned %v, want ErrCeremonyFailed", err)
		}
	})
}

// TestAdminEnrolmentRefusesAnUnusableToken stops a session that outlived its
// token from minting a fresh credential.
func TestAdminEnrolmentRefusesAnUnusableToken(t *testing.T) {
	f := newFixture(t)
	tok := f.adminToken("Owner", store.RoleFull)
	if err := f.store.RevokeAdminToken(f.ctx, testTenant, tok.ID, f.clock.now()); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	reloaded, err := f.store.GetAdminTokenByID(f.ctx, testTenant, tok.ID)
	if err != nil {
		t.Fatalf("reload token: %v", err)
	}

	if _, err := f.svc.BeginAdminRegistration(f.ctx, reloaded); !errors.Is(err, webauthn.ErrAdminTokenUnusable) {
		t.Errorf("enrolment on a revoked token returned %v, want ErrAdminTokenUnusable", err)
	}
}

// TestAdminSignInRefusesTheSameAssertionTwice pins the replay guard on the
// console's own credential table, which has its own compare-and-swap.
func TestAdminSignInRefusesTheSameAssertionTwice(t *testing.T) {
	f := newFixture(t)
	tok := f.adminToken("Owner", store.RoleFull)
	a := f.authenticator(modelA)
	f.mustAdminRegister(tok, a)

	begin, err := f.svc.BeginAdminAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatalf("authenticator get: %v", err)
	}
	if _, err := f.svc.CompleteAdminAssertion(f.ctx, testTenant, begin.ChallengeID, resp); err != nil {
		t.Fatalf("first completion refused: %v", err)
	}
	if _, err := f.svc.CompleteAdminAssertion(f.ctx, testTenant, begin.ChallengeID, resp); !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Fatalf("replayed completion returned %v, want ErrChallengeNotFound", err)
	}
}

// TestExpiredConsoleChallengesAreSweptWithTheOthers checks that the second
// challenge table did not arrive without a collector.
func TestExpiredConsoleChallengesAreSweptWithTheOthers(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	f.mustRegister(sub, f.authenticator(modelA))
	tok := f.adminToken("Owner", store.RoleFull)
	f.mustAdminRegister(tok, f.authenticator(modelB))

	if _, err := f.svc.BeginAdminAssertion(f.ctx, testTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant); err != nil {
		t.Fatal(err)
	}

	removed, err := f.store.DeleteExpiredChallenges(f.ctx,
		f.clock.now().Add(f.cfg.ChallengeTTL.Duration+time.Hour))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed < 2 {
		t.Errorf("the sweep removed %d challenges, want at least the 2 just issued: "+
			"the console's table has no collector of its own", removed)
	}
}
