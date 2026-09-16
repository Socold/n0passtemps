// Package rbac decides what an administrative role is allowed to do.
//
// The three roles follow one principle: authority grows with the damage the
// holder is trusted to cause, and reading is never bundled with writing.
//
//	admin_auditor  reads everything and changes nothing, not even an alert
//	               acknowledgement. An auditor who can quietly clear an alert
//	               can quietly cover a trace, which is the one thing the role
//	               exists to prevent.
//	admin_operator is the day to day user support role. It adds the operations
//	               that recover a locked-out user: unlock, throttle reset,
//	               single credential revocation, recovery code reissue, alert
//	               acknowledgement and locking a subject. It deliberately stops
//	               short of anything that changes who may administer the
//	               service, anything that acts on many records at once, and
//	               anything that touches key material.
//	admin_full     holds every permission.
//
// There is one deliberate exception to "an auditor changes nothing", and it is
// stated here so that it is never mistaken for drift: every role, the auditor
// included, may rotate its own administrative token (admin_token.rotate_self).
// It is a write, but it touches nothing except the caller's own credential. It
// changes no subject, no record and nobody's authority, the successor carries
// the same role, and the rotation is audited. Withholding it would mean an
// auditor whose token may have leaked has to ask a full administrator to revoke
// and re-mint it, and the usual result of that friction is a token that is
// never replaced at all. The split the package enforces is therefore: reading
// is never bundled with writing, other than self-service credential hygiene.
//
// Membership is expressed as an explicit permission set per role rather than as
// a numeric level. A level invites the assumption that a higher role is a
// superset of a lower one, which then makes it impossible to grant an operator
// something an auditor must not have without also reordering the levels.
//
// The mapping is validated at package initialisation: every declared permission
// must be granted to admin_full. Adding a permission and forgetting to place it
// therefore fails loudly rather than leaving an operation nobody can perform.
package rbac

import (
	"fmt"
	"slices"

	"github.com/Socold/n0passtemps/internal/store"
)

// Permission is one administrative operation.
//
// The values are dotted and hierarchical, matching the audit event families, so
// that a denial in the audit log and the permission that caused it read as the
// same vocabulary.
type Permission string

// The administrative permission set.
//
// Read permissions are listed first, then the one self-service write every
// role holds, then the operations an operator may perform, then the operations
// reserved to admin_full. The grouping is a reading aid only; authority comes
// from the role sets below.
const (
	// Read-only permissions.
	PermSubjectList    Permission = "subject.list"
	PermSubjectRead    Permission = "subject.read"
	PermCredentialList Permission = "credential.list"
	PermAuditRead      Permission = "audit.read"
	PermAuditVerify    Permission = "audit.verify"
	PermAlertRead      Permission = "alert.read"
	PermApprovalRead   Permission = "approval.read"
	PermHealthReadFull Permission = "health.read_detailed"

	// Listing the credentials that authenticate callers of the service. Read
	// only, and metadata only: neither listing can disclose a token, because
	// only a selector and a digest of the verifier are ever stored.
	//
	// These are separate permissions rather than a reuse of subject.list,
	// which is what the routes were guarded by at first. Sharing a permission
	// between unrelated resources means a later decision to withhold one of
	// them has nowhere to express itself.
	PermAPIKeyList     Permission = "api_key.list"
	PermAdminTokenList Permission = "admin_token.list"

	// Self-service credential hygiene, held by every role.
	//
	// The permission covers the caller's own token and nothing else. There is
	// deliberately no permission, and no route, for rotating another
	// administrator's token: the response to a rotation carries the successor
	// credential, so rotating someone else's token would hand the caller that
	// person's next credential, which is impersonation. Replacing another
	// administrator's token is a revocation followed by a mint, and the mint is
	// a dual-approval candidate.
	PermAdminTokenRotateSelf Permission = "admin_token.rotate_self"

	// User support permissions.
	PermSubjectLock      Permission = "subject.lock"
	PermSubjectUnlock    Permission = "subject.unlock"
	PermCredentialRevoke Permission = "credential.revoke"
	PermRecoveryReissue  Permission = "recovery.reissue"
	PermThrottleReset    Permission = "throttle.reset"
	PermAlertAcknowledge Permission = "alert.acknowledge"

	// Permissions reserved to admin_full.
	PermCredentialRevokeBulk Permission = "credential.revoke_bulk"
	PermApprovalDecide       Permission = "approval.decide"
	PermErasureRequest       Permission = "erasure.request"
	PermErasureCancel        Permission = "erasure.cancel"
	PermAPIKeyCreate         Permission = "api_key.create"
	PermAPIKeyRevoke         Permission = "api_key.revoke"
	PermAPIKeyRotate         Permission = "api_key.rotate"
	PermAdminTokenCreate     Permission = "admin_token.create"
	PermAdminTokenRevoke     Permission = "admin_token.revoke"
	PermKEKRotate            Permission = "kek.rotate"
)

// AllPermissions lists every declared permission.
//
// It is the authority for completeness checks. A permission that exists as a
// constant but is missing here would escape both the initialisation check and
// the tests, so the two are kept adjacent.
var AllPermissions = []Permission{
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

	PermCredentialRevokeBulk,
	PermApprovalDecide,
	PermErasureRequest,
	PermErasureCancel,
	PermAPIKeyCreate,
	PermAPIKeyRevoke,
	PermAPIKeyRotate,
	PermAdminTokenCreate,
	PermAdminTokenRevoke,
	PermKEKRotate,
}

// String returns the permission as it appears in configuration and audit
// entries.
func (p Permission) String() string { return string(p) }

// Valid reports whether p is a declared permission.
//
// An undeclared permission is a programming error, and authorisation treats it
// as a denial rather than guessing, so a mistyped permission cannot open an
// endpoint.
func (p Permission) Valid() bool {
	_, ok := declared[p]
	return ok
}

// readPermissions are the operations that change no state. audit.verify belongs
// here because verification recomputes hashes and writes nothing.
var readPermissions = []Permission{
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
}

// selfServicePermissions are the write operations every role may perform,
// because each one touches nothing but the caller's own credential.
//
// This is the only write an auditor holds. The list is kept separate from
// readPermissions rather than appended to it, so that the claim "everything in
// readPermissions changes no state" stays true, and so that a second entry
// here is a visible decision that a test has to be changed to admit.
var selfServicePermissions = []Permission{
	PermAdminTokenRotateSelf,
}

// operatorExtras are the write operations an operator may perform. Each one
// affects a single subject and is recoverable by re-enrolment, which is the line
// the role is drawn on.
var operatorExtras = []Permission{
	PermSubjectLock,
	PermSubjectUnlock,
	PermCredentialRevoke,
	PermRecoveryReissue,
	PermThrottleReset,
	PermAlertAcknowledge,
}

// rolePermissions is the mapping consulted by every decision.
//
// It is built once at initialisation and never mutated afterwards, so it is safe
// to read concurrently without a lock.
var rolePermissions = map[store.Role]map[Permission]struct{}{}

// declared indexes AllPermissions for validity checks.
var declared = map[Permission]struct{}{}

func init() {
	for _, p := range AllPermissions {
		declared[p] = struct{}{}
	}

	auditor := set(readPermissions...)
	operator := set(readPermissions...)
	for _, p := range selfServicePermissions {
		auditor[p] = struct{}{}
		operator[p] = struct{}{}
	}
	for _, p := range operatorExtras {
		operator[p] = struct{}{}
	}
	full := set(AllPermissions...)

	rolePermissions[store.RoleAuditor] = auditor
	rolePermissions[store.RoleOperator] = operator
	rolePermissions[store.RoleFull] = full

	// Completeness invariant. A permission nobody can exercise is a dead
	// endpoint, and one granted to a role by accident is a privilege
	// escalation; both are caught here, at start, rather than in production.
	for _, p := range AllPermissions {
		if _, ok := full[p]; !ok {
			panic(fmt.Sprintf("rbac: permission %q is declared but not granted to %s", p, store.RoleFull))
		}
	}
	for role, perms := range rolePermissions {
		for p := range perms {
			if _, ok := declared[p]; !ok {
				panic(fmt.Sprintf("rbac: role %s holds undeclared permission %q", role, p))
			}
		}
	}
}

func set(perms ...Permission) map[Permission]struct{} {
	out := make(map[Permission]struct{}, len(perms))
	for _, p := range perms {
		out[p] = struct{}{}
	}
	return out
}

// Allowed reports whether role holds p.
//
// An unknown role holds nothing. Authorisation fails closed so that a token
// carrying a role this build does not recognise, for instance after a
// downgrade, cannot act at all.
func Allowed(role store.Role, p Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	_, ok = perms[p]
	return ok
}

// Permissions returns the permissions held by role, sorted.
//
// The result is a fresh slice: handing out the internal set would let a caller
// grant itself a permission by writing to the map it was shown.
func Permissions(role store.Role) []Permission {
	perms, ok := rolePermissions[role]
	if !ok {
		return nil
	}
	out := make([]Permission, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// approvalCandidates are the permissions whose effect is wide enough, or hard
// enough to undo, to be worth a second administrator.
//
// They are candidates rather than requirements: whether the dual-approval queue
// actually intercepts an operation is decided by
// config.Features.DualApprovalOperations. That setting names operations and this
// package names permissions, so the administrative layer maps between the two
// vocabularies; the default list there covers exactly these four.
var approvalCandidates = set(
	PermCredentialRevokeBulk,
	PermErasureRequest,
	PermAdminTokenCreate,
	PermKEKRotate,
)

// RequiresApproval reports whether p is a candidate for the dual-approval
// queue.
func RequiresApproval(p Permission) bool {
	_, ok := approvalCandidates[p]
	return ok
}

// Decision is the outcome of an authorisation check.
//
// Reason explains the outcome for the audit entry and the log line. It is not
// safe to return to the caller verbatim: it names the role and the permission,
// which tells an attacker holding a valid token exactly which capability it is
// missing and therefore which token is worth stealing next. The HTTP layer
// answers a denial with a bare status and correlates through RequestID.
type Decision struct {
	Allowed    bool
	Role       store.Role
	Permission Permission
	Reason     string
}

// Authorise decides whether role may exercise p.
//
// rbacEnabled mirrors config.Features.AdminRBAC. With it off, every valid role
// carries full authority, because that is what the lite deployment means: one
// administrator, no separation of duty, and no pretence of one. An unknown role
// is still refused, since the value comes from a persisted token rather than
// from the operator, and an unrecognised one means the token is not
// interpretable rather than unrestricted.
func Authorise(role store.Role, p Permission, rbacEnabled bool) Decision {
	d := Decision{Role: role, Permission: p}

	if !role.Valid() {
		d.Reason = fmt.Sprintf("role %q is not a known administrative role", role)
		return d
	}
	if !p.Valid() {
		d.Reason = fmt.Sprintf("permission %q is not declared", p)
		return d
	}
	if !rbacEnabled {
		d.Allowed = true
		d.Reason = "role-based access control is disabled, every valid role has full authority"
		return d
	}
	if !Allowed(role, p) {
		d.Reason = fmt.Sprintf("role %s does not hold %s", role, p)
		return d
	}

	d.Allowed = true
	d.Reason = fmt.Sprintf("role %s holds %s", role, p)
	return d
}
