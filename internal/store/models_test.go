package store

import (
	"testing"
	"time"
)

// Eight one-line predicates decide, between them, whether a token
// authenticates, whether a credential still verifies an assertion, whether a
// ticket may be redeemed and whether a subject is locked out. Every caller in
// this repository asks one of them rather than comparing timestamps itself,
// which is the right arrangement and also means none of them had a test: they
// were exercised incidentally, through whatever the caller happened to set up.
//
// What follows is the boundary, which is where a predicate of this shape is
// wrong if it is wrong at all. The instant a credential expires is the
// interesting one: half a second either side is not in dispute, and "expires at
// noon" has to mean the thing stops working at noon rather than a moment after.

var modelsNow = time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// TestRoleValidIsAClosedSet keeps an unknown role out.
//
// The roles come off the wire in an administrative token row, so a value the
// switch does not name has to be refused rather than treated as the least
// privileged one: a role nothing recognises is a row nobody wrote deliberately.
func TestRoleValidIsAClosedSet(t *testing.T) {
	for _, r := range []Role{RoleFull, RoleOperator, RoleAuditor} {
		if !r.Valid() {
			t.Errorf("%q is one of the three roles and does not validate", r)
		}
	}
	for _, r := range []Role{"", "admin", "root", "ADMIN_FULL", "admin_full "} {
		if r.Valid() {
			t.Errorf("%q validates as a role", r)
		}
	}
}

// TestSubjectActiveNeedsBothConditions covers the pairing.
//
// A subject in the retention window of an erasure keeps status active until the
// purge runs, and DeletedAt is what says the erasure was requested. Reading
// either alone would authenticate somebody who has asked to be forgotten.
func TestSubjectActiveNeedsBothConditions(t *testing.T) {
	for name, tc := range map[string]struct {
		subject Subject
		want    bool
	}{
		"active and not deleted": {Subject{Status: SubjectActive}, true},
		"active but deleted": {
			Subject{Status: SubjectActive, DeletedAt: ptr(modelsNow)}, false},
		"locked":           {Subject{Status: SubjectLocked}, false},
		"pending deletion": {Subject{Status: SubjectPendingDeletion}, false},
		"no status at all": {Subject{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.subject.Active(); got != tc.want {
				t.Errorf("Active() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestRevokedReadsTheTimestampAndNothingElse covers both credential families.
//
// Revocation is final on each of them, see ADR 0010, so the predicate is a
// presence check and there is no second condition that could let a withdrawn
// credential come back.
func TestRevokedReadsTheTimestampAndNothingElse(t *testing.T) {
	subject := &Credential{}
	if subject.Revoked() {
		t.Error("a fresh credential reads as revoked")
	}
	subject.RevokedAt = ptr(modelsNow)
	if !subject.Revoked() {
		t.Error("a credential with revoked_at set reads as active")
	}

	admin := &AdminCredential{}
	if admin.Revoked() {
		t.Error("a fresh administrative credential reads as revoked")
	}
	admin.RevokedAt = ptr(modelsNow)
	if !admin.Revoked() {
		t.Error("an administrative credential with revoked_at set reads as active")
	}
}

// TestATicketStopsBeingRedeemableAtItsExpiry is the boundary.
//
// A ticket permits one WebAuthn registration and is delivered over a channel
// this service does not control, so the window has to close when it says it
// closes.
func TestATicketStopsBeingRedeemableAtItsExpiry(t *testing.T) {
	fresh := func() *EnrolmentTicket {
		return &EnrolmentTicket{ExpiresAt: modelsNow.Add(time.Hour)}
	}

	if !fresh().Redeemable(modelsNow) {
		t.Error("a ticket an hour from expiry is not redeemable")
	}
	if !fresh().Redeemable(modelsNow.Add(time.Hour - time.Nanosecond)) {
		t.Error("a ticket is not redeemable a nanosecond before it expires")
	}
	// The instant itself is outside the window: Before is strict, and "expires
	// at" has to mean the ticket has stopped working by then.
	if fresh().Redeemable(modelsNow.Add(time.Hour)) {
		t.Error("a ticket is still redeemable at the instant it expires")
	}
	if fresh().Redeemable(modelsNow.Add(2 * time.Hour)) {
		t.Error("an expired ticket is redeemable")
	}

	consumed := fresh()
	consumed.ConsumedAt = ptr(modelsNow)
	if consumed.Redeemable(modelsNow) {
		t.Error("a consumed ticket is redeemable, so it is not single use")
	}

	revoked := fresh()
	revoked.RevokedAt = ptr(modelsNow)
	if revoked.Redeemable(modelsNow) {
		t.Error("a revoked ticket is redeemable")
	}
}

// TestACredentialWithNoExpiryNeverExpires, and one with an expiry stops at it.
//
// Both token families share the shape, so both are checked: a nil ExpiresAt is
// a credential that was minted without one and must not be read as expired at
// the zero time, which is what a missing nil check produces.
func TestACredentialWithNoExpiryNeverExpires(t *testing.T) {
	expiry := modelsNow.Add(time.Hour)

	for name, usable := range map[string]func(now time.Time, expires, revoked *time.Time) bool{
		"admin token": func(now time.Time, expires, revoked *time.Time) bool {
			return (&AdminToken{Role: RoleOperator, ExpiresAt: expires, RevokedAt: revoked}).Usable(now)
		},
		"api key": func(now time.Time, expires, revoked *time.Time) bool {
			return (&APIKey{ExpiresAt: expires, RevokedAt: revoked}).Usable(now)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !usable(modelsNow, nil, nil) {
				t.Error("a credential with no expiry is not usable")
			}
			if !usable(modelsNow.Add(100*365*24*time.Hour), nil, nil) {
				t.Error("a credential with no expiry stopped working on its own")
			}
			if !usable(modelsNow, &expiry, nil) {
				t.Error("a credential an hour from expiry is not usable")
			}
			if !usable(expiry.Add(-time.Nanosecond), &expiry, nil) {
				t.Error("a credential is not usable a nanosecond before it expires")
			}
			// Not Before, so the instant of expiry is already outside.
			if usable(expiry, &expiry, nil) {
				t.Error("a credential is usable at the instant it expires")
			}
			if usable(expiry.Add(time.Hour), &expiry, nil) {
				t.Error("an expired credential is usable")
			}
			if usable(modelsNow, nil, &modelsNow) {
				t.Error("a revoked credential is usable")
			}
			// Revocation is checked first, so a revoked credential that has not
			// yet expired is still refused.
			if usable(modelsNow, &expiry, &modelsNow) {
				t.Error("a revoked credential with time left is usable")
			}
		})
	}
}

// TestThrottleBlockingEndsWhenItSaysItDoes is the other side of the boundary:
// here the risk is a lockout that outlasts its own deadline.
func TestThrottleBlockingEndsWhenItSaysItDoes(t *testing.T) {
	until := modelsNow.Add(15 * time.Minute)
	blocked := &ThrottleState{BlockedUntil: &until}

	if !blocked.Blocked(modelsNow) {
		t.Error("a subject inside its lockout is not blocked")
	}
	if !blocked.Blocked(until.Add(-time.Nanosecond)) {
		t.Error("a subject is not blocked a nanosecond before the lockout ends")
	}
	if blocked.Blocked(until) {
		t.Error("a subject is still blocked at the instant the lockout ends")
	}
	if blocked.Blocked(until.Add(time.Hour)) {
		t.Error("a lockout outlasted its deadline")
	}
	if (&ThrottleState{}).Blocked(modelsNow) {
		t.Error("a bucket that never blocked anybody reads as blocked")
	}
}

// TestAnAdministrativeTokenNeedsAKnownRole is the one condition the two token
// families do not share, and it is worth its own test because it is the
// difference.
//
// An API key carries scopes and a role is not one of them; an administrative
// token is nothing without a role, so a row whose role column holds a value
// this version does not recognise authenticates nobody. That is the safe
// direction for a schema that may be read by an older binary after a
// downgrade, and for a row written by hand.
func TestAnAdministrativeTokenNeedsAKnownRole(t *testing.T) {
	for _, role := range []Role{RoleFull, RoleOperator, RoleAuditor} {
		if !(&AdminToken{Role: role}).Usable(modelsNow) {
			t.Errorf("a token with role %q is not usable", role)
		}
	}
	for _, role := range []Role{"", "root", "admin", "ADMIN_FULL"} {
		if (&AdminToken{Role: role}).Usable(modelsNow) {
			t.Errorf("a token with role %q authenticates", role)
		}
	}

	// An API key has no role to be wrong about, which is why the shapes differ.
	if !(&APIKey{}).Usable(modelsNow) {
		t.Error("an api key with no expiry and no revocation is not usable")
	}
}
