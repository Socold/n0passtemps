package rbac

import (
	"slices"
	"testing"

	"github.com/Socold/n0passtemps/internal/store"
)

// writePermissions is the complement of readPermissions, derived rather than
// written out, so a new permission joins one list or the other and cannot be
// left out of both.
func writePermissions(t *testing.T) []Permission {
	t.Helper()
	var out []Permission
	for _, p := range AllPermissions {
		if !slices.Contains(readPermissions, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Fatal("no write permissions declared")
	}
	return out
}

func TestAllPermissionsMatchesDeclaredConstants(t *testing.T) {
	seen := map[Permission]int{}
	for _, p := range AllPermissions {
		seen[p]++
		if seen[p] > 1 {
			t.Errorf("permission %q appears %d times in AllPermissions", p, seen[p])
		}
		if p == "" {
			t.Error("AllPermissions contains an empty permission")
		}
	}
}

func TestFullRoleHoldsEveryPermission(t *testing.T) {
	for _, p := range AllPermissions {
		if !Allowed(store.RoleFull, p) {
			t.Errorf("%s does not hold %s; a declared permission nobody can exercise is a dead endpoint",
				store.RoleFull, p)
		}
	}
	if got, want := len(Permissions(store.RoleFull)), len(AllPermissions); got != want {
		t.Errorf("Permissions(%s) returned %d entries, want %d", store.RoleFull, got, want)
	}
}

func TestReadAndWriteSetsPartitionAllPermissions(t *testing.T) {
	for _, p := range readPermissions {
		if !p.Valid() {
			t.Errorf("read permission %q is not declared in AllPermissions", p)
		}
	}
	for _, p := range operatorExtras {
		if !p.Valid() {
			t.Errorf("operator permission %q is not declared in AllPermissions", p)
		}
		if slices.Contains(readPermissions, p) {
			t.Errorf("permission %q is listed as both a read and a write operation", p)
		}
	}
	for _, p := range selfServicePermissions {
		if !p.Valid() {
			t.Errorf("self-service permission %q is not declared in AllPermissions", p)
		}
		// A self-service permission is a write. Listing one as a read would
		// make the claim "everything in readPermissions changes no state"
		// false, and listing one as an operator extra would say the auditor
		// does not hold it.
		if slices.Contains(readPermissions, p) {
			t.Errorf("self-service permission %q is also listed as a read", p)
		}
		if slices.Contains(operatorExtras, p) {
			t.Errorf("self-service permission %q is also listed as an operator extra", p)
		}
	}
}

// TestRoleMatrix states the expected answer for every role and every
// permission. The table is exhaustive by construction: the subtest fails if a
// permission has no entry.
func TestRoleMatrix(t *testing.T) {
	// expected lists, for each role, the permissions that role holds.
	expected := map[store.Role][]Permission{
		store.RoleAuditor: {
			PermSubjectList,
			PermSubjectRead,
			PermCredentialList,
			PermAuditRead,
			PermAuditVerify,
			PermAlertRead,
			PermApprovalRead,
			PermHealthReadFull,
			// Listing the credentials that authenticate callers is read only
			// and metadata only: neither listing can disclose a token,
			// because only a selector and a digest are stored. Withholding it
			// from the role whose job is to review the deployment would make
			// the audit trail harder to interpret without protecting
			// anything.
			PermAPIKeyList,
			PermAdminTokenList,
			// The one write an auditor holds. It replaces the caller's own
			// token and touches nothing else; see
			// TestAuditorHoldsNoWriteBeyondSelfService.
			PermAdminTokenRotateSelf,
		},
		store.RoleOperator: {
			PermSubjectList,
			PermSubjectRead,
			PermCredentialList,
			PermAuditRead,
			PermAuditVerify,
			PermAlertRead,
			PermApprovalRead,
			PermHealthReadFull,
			PermAPIKeyList,
			PermAdminTokenList,
			PermAdminTokenRotateSelf,
			PermSubjectLock,
			PermSubjectUnlock,
			PermCredentialRevoke,
			PermRecoveryReissue,
			PermThrottleReset,
			PermAlertAcknowledge,
		},
		store.RoleFull: AllPermissions,
	}

	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator, store.RoleFull} {
		held := expected[role]
		for _, p := range AllPermissions {
			wantAllowed := slices.Contains(held, p)
			if got := Allowed(role, p); got != wantAllowed {
				t.Errorf("Allowed(%s, %s) = %v, want %v", role, p, got, wantAllowed)
			}
		}
		if got, want := len(Permissions(role)), len(held); got != want {
			t.Errorf("Permissions(%s) returned %d entries, want %d", role, got, want)
		}
	}
}

func TestOperatorIsRefusedTheReservedOperations(t *testing.T) {
	reserved := []Permission{
		PermCredentialRevokeBulk,
		PermApprovalDecide,
		PermAPIKeyCreate,
		PermAPIKeyRevoke,
		PermAPIKeyRotate,
		PermAdminTokenCreate,
		PermAdminTokenRevoke,
		PermKEKRotate,
	}
	for _, p := range reserved {
		if Allowed(store.RoleOperator, p) {
			t.Errorf("%s holds %s, which must be reserved to %s", store.RoleOperator, p, store.RoleFull)
		}
	}
}

// TestAuditorHoldsNoWriteBeyondSelfService states the precise rule for the
// auditor: no write permission other than self-service credential hygiene.
//
// The rule used to be "no write permission at all". Rotating one's own token
// is a write, so that sentence is no longer true, and the test says what is
// true instead of being loosened: the exception is one named permission, it is
// pinned below, and every other write is still refused.
func TestAuditorHoldsNoWriteBeyondSelfService(t *testing.T) {
	for _, p := range writePermissions(t) {
		if slices.Contains(selfServicePermissions, p) {
			if !Allowed(store.RoleAuditor, p) {
				t.Errorf("%s does not hold the self-service permission %s; an auditor whose "+
					"token may have leaked must be able to replace it without asking anyone",
					store.RoleAuditor, p)
			}
			continue
		}
		if Allowed(store.RoleAuditor, p) {
			t.Errorf("%s holds the write permission %s; the role exists to be unable to "+
				"change anything but its own credential", store.RoleAuditor, p)
		}
	}
	// Stated separately because it is the one an implementation is most
	// tempted to grant: acknowledging an alert looks harmless and is not.
	if Allowed(store.RoleAuditor, PermAlertAcknowledge) {
		t.Errorf("%s may acknowledge alerts", store.RoleAuditor)
	}
}

// TestSelfServiceIsExactlyOwnTokenRotation pins the exception.
//
// The self-service list is what an auditor may write, so growing it grows the
// auditor. Anyone adding a second entry has to change this test, which is the
// point: the decision is made in review rather than by appending to a slice.
func TestSelfServiceIsExactlyOwnTokenRotation(t *testing.T) {
	want := []Permission{PermAdminTokenRotateSelf}
	if !slices.Equal(selfServicePermissions, want) {
		t.Fatalf("selfServicePermissions = %v, want %v", selfServicePermissions, want)
	}
	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator, store.RoleFull} {
		if !Allowed(role, PermAdminTokenRotateSelf) {
			t.Errorf("%s may not rotate its own token", role)
		}
	}
	// Rotating an application's key is not self-service: it hands the caller a
	// working credential for the public surface.
	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator} {
		if Allowed(role, PermAPIKeyRotate) {
			t.Errorf("%s holds %s, which must be reserved to %s", role, PermAPIKeyRotate, store.RoleFull)
		}
	}
	// Self-rotation changes no authority, so holding it for a second
	// administrator would protect nothing.
	if RequiresApproval(PermAdminTokenRotateSelf) {
		t.Errorf("%s is a dual-approval candidate", PermAdminTokenRotateSelf)
	}
}

func TestUnknownRoleIsRefusedEverything(t *testing.T) {
	for _, role := range []store.Role{"", "admin", "root", "admin_super", store.Role("ADMIN_FULL")} {
		if got := Permissions(role); got != nil {
			t.Errorf("Permissions(%q) = %v, want nil", role, got)
		}
		for _, p := range AllPermissions {
			if Allowed(role, p) {
				t.Errorf("Allowed(%q, %s) = true, want false", role, p)
			}
			if d := Authorise(role, p, true); d.Allowed {
				t.Errorf("Authorise(%q, %s, true) allowed the request", role, p)
			}
			if d := Authorise(role, p, false); d.Allowed {
				t.Errorf("Authorise(%q, %s, false) allowed the request; a role this build "+
					"cannot interpret must be refused even in lite mode", role, p)
			}
		}
	}
}

func TestPermissionsReturnsSortedCopy(t *testing.T) {
	got := Permissions(store.RoleOperator)
	if !slices.IsSorted(got) {
		t.Errorf("Permissions(%s) = %v, want sorted", store.RoleOperator, got)
	}

	// Mutating the result must not affect the next call.
	got[0] = "tampered"
	again := Permissions(store.RoleOperator)
	if slices.Contains(again, "tampered") {
		t.Error("Permissions returned a slice aliasing internal state")
	}
}

func TestAuthoriseWithRBACDisabled(t *testing.T) {
	for _, role := range []store.Role{store.RoleAuditor, store.RoleOperator, store.RoleFull} {
		for _, p := range AllPermissions {
			d := Authorise(role, p, false)
			if !d.Allowed {
				t.Errorf("Authorise(%s, %s, false) = denied, want allowed", role, p)
			}
			if d.Reason == "" {
				t.Errorf("Authorise(%s, %s, false) returned an empty reason", role, p)
			}
		}
	}
}

func TestAuthoriseRefusesUndeclaredPermission(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		d := Authorise(store.RoleFull, Permission("kek.exfiltrate"), enabled)
		if d.Allowed {
			t.Errorf("Authorise with rbacEnabled=%v allowed an undeclared permission", enabled)
		}
		if d.Reason == "" {
			t.Error("denial carried no reason to log")
		}
	}
}

func TestAuthoriseCarriesContextForTheAuditEntry(t *testing.T) {
	d := Authorise(store.RoleOperator, PermKEKRotate, true)
	if d.Allowed {
		t.Fatalf("%s was allowed to rotate the KEK", store.RoleOperator)
	}
	if d.Role != store.RoleOperator || d.Permission != PermKEKRotate {
		t.Errorf("decision = %+v, want the role and permission echoed back", d)
	}
	if d.Reason == "" {
		t.Error("denial carried no reason to log")
	}
}

func TestRequiresApproval(t *testing.T) {
	want := map[Permission]bool{
		PermCredentialRevokeBulk: true,
		PermErasureRequest:       true,
		PermAdminTokenCreate:     true,
		PermKEKRotate:            true,
	}
	for _, p := range AllPermissions {
		if got := RequiresApproval(p); got != want[p] {
			t.Errorf("RequiresApproval(%s) = %v, want %v", p, got, want[p])
		}
	}

	// Every approval candidate must be a permission only admin_full holds:
	// queueing an operation for a second administrator is pointless if the
	// requester's own role could not perform it in the first place.
	for p := range want {
		if !Allowed(store.RoleFull, p) {
			t.Errorf("approval candidate %s is not held by %s", p, store.RoleFull)
		}
		if Allowed(store.RoleOperator, p) {
			t.Errorf("approval candidate %s is held by %s", p, store.RoleOperator)
		}
	}
}

func TestPermissionString(t *testing.T) {
	if got := PermAuditRead.String(); got != "audit.read" {
		t.Errorf("PermAuditRead.String() = %q, want %q", got, "audit.read")
	}
	for _, p := range AllPermissions {
		if p.String() != string(p) {
			t.Errorf("String() disagrees with the underlying value for %q", p)
		}
	}
}
