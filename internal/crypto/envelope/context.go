package envelope

import (
	"encoding/binary"
	"fmt"
)

// Kind names the family of secret a sealed record holds.
//
// The set is closed. An unknown kind is refused rather than encoded, because a
// caller inventing a kind would be inventing a namespace nothing else checks,
// and the whole value of the kind is that two columns never share one.
type Kind string

// The kinds of secret this service seals. They match the sealed record families
// a key rotation walks, and the text is part of the authenticated data, so
// renaming one makes every existing record of that kind unreadable.
const (
	// KindSubjectRef is subjects.ref_sealed, the readable copy of the
	// identifier an integrating application uses for its own user.
	KindSubjectRef Kind = "subject_ref"

	// KindTOTPSecret is totp_secrets.secret_sealed, a TOTP seed.
	KindTOTPSecret Kind = "totp_secret"
)

// bindingDomain separates the additional authenticated data of an envelope from
// every other byte string this service authenticates or hashes.
const bindingDomain = "n0passtemps/envelope-binding/v1"

// maxBindingField bounds one field of a context.
//
// Identifiers here are UUIDs and a configured tenant name, so nothing
// legitimate comes near it. The limit exists so that the authenticated data
// stays a bounded quantity whatever a caller passes, and so that a field long
// enough to overflow the length prefix is a refusal rather than a silent
// truncation.
const maxBindingField = 4096

// Context binds a sealed record to the place it is stored.
//
// It never travels with the ciphertext. The caller rebuilds it from the row it
// has in hand, which is the point: an attacker who can write to the database
// but does not hold the key encryption key can still copy a ciphertext from one
// row to another, and the cipher then rejects it because the row it was sealed
// for is not the row it was read from. Without this, a valid ciphertext opened
// in any row, any column and any tenant, so a TOTP seed whose value the
// attacker knew could be pasted over a victim's, and a subject reference could
// be moved across a tenant boundary and read back through the reveal route.
//
// Every field is mandatory for the kinds that use it, and Validate refuses a
// context that is incomplete. A caller that has nothing to bind must not be
// able to seal anything at all.
type Context struct {
	// Kind is the family of secret, which keeps a ciphertext from one column
	// from being opened as if it came from another.
	Kind Kind

	// TenantID is the tenant owning the row. It is what stops a record from
	// being moved across the boundary that separates two customers.
	TenantID string

	// RowID is the primary key of the row holding the sealed value.
	RowID string

	// SubjectID is the subject the record belongs to, for kinds whose row is
	// not the subject itself. KindTOTPSecret requires it: a TOTP row can be
	// replaced outright, so binding only the row identifier would still let an
	// attacker insert their own seed under a new row identifier for someone
	// else. KindSubjectRef must leave it empty, because RowID is already the
	// subject identifier there and a second copy of it could only ever drift.
	SubjectID string
}

// SubjectRef returns the binding context of subjects.ref_sealed.
func SubjectRef(tenantID, subjectID string) Context {
	return Context{Kind: KindSubjectRef, TenantID: tenantID, RowID: subjectID}
}

// TOTPSecret returns the binding context of totp_secrets.secret_sealed.
func TOTPSecret(tenantID, subjectID, secretID string) Context {
	return Context{Kind: KindTOTPSecret, TenantID: tenantID, RowID: secretID, SubjectID: subjectID}
}

// Validate reports why a context cannot be used, if it cannot.
//
// It is called on every seal and on every open, including when the record turns
// out to be in the legacy format that will not use the context. A caller
// holding an incomplete context must not discover that it works by happening to
// read an old row.
func (c Context) Validate() error {
	switch c.Kind {
	case KindSubjectRef:
		if c.SubjectID != "" {
			return fmt.Errorf("%w: %s carries the subject in the row identifier, so SubjectID must be empty",
				ErrContextInvalid, c.Kind)
		}
	case KindTOTPSecret:
		if c.SubjectID == "" {
			return fmt.Errorf("%w: %s must name the subject the secret authenticates", ErrContextInvalid, c.Kind)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrContextInvalid, string(c.Kind))
	}

	if c.TenantID == "" {
		return fmt.Errorf("%w: %s must name a tenant", ErrContextInvalid, c.Kind)
	}
	if c.RowID == "" {
		return fmt.Errorf("%w: %s must name the row holding the record", ErrContextInvalid, c.Kind)
	}

	for _, f := range c.fields() {
		if len(f.value) > maxBindingField {
			return fmt.Errorf("%w: %s is %d bytes, the limit is %d",
				ErrContextInvalid, f.name, len(f.value), maxBindingField)
		}
	}
	return nil
}

// bindingField is one named component of the serialised context. The name is
// carried so that a refusal says which field is at fault.
type bindingField struct {
	name  string
	value string
}

// fields lists the components in the fixed order they are serialised in.
// Reordering them makes every existing record unreadable, so the order lives in
// one place rather than being repeated at each use.
func (c Context) fields() []bindingField {
	return []bindingField{
		{"kind", string(c.Kind)},
		{"tenant id", c.TenantID},
		{"row id", c.RowID},
		{"subject id", c.SubjectID},
	}
}

// bytes renders the context as the trailing half of a record's additional
// authenticated data.
//
// Each field is length-prefixed rather than joined by a separator. A separator
// would have to be a byte that cannot occur in a tenant name or an identifier,
// and there is no such byte that stays impossible for the life of the service;
// with lengths in front, a tenant "a" holding row "bc" and a tenant "ab"
// holding row "c" encode differently, so no two distinct contexts can ever
// produce the same authenticated data.
func (c Context) bytes() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	fields := c.fields()
	size := len(bindingDomain) + 1
	for _, f := range fields {
		size += 4 + len(f.value)
	}

	out := make([]byte, 0, size)
	out = append(out, bindingDomain...)
	out = append(out, 0)
	var length [4]byte
	for _, f := range fields {
		n := len(f.value)
		if n < 0 || n > maxBindingField {
			// Unreachable: Validate has already refused an oversized field.
			// The check is repeated here because the line below narrows the
			// length, and a narrowing that depends on a check made in another
			// function is a narrowing nobody will re-examine when that other
			// function changes.
			return nil, fmt.Errorf("%w: %s is %d bytes", ErrContextInvalid, f.name, n)
		}
		binary.BigEndian.PutUint32(length[:], uint32(n))
		out = append(out, length[:]...)
		out = append(out, f.value...)
	}
	return out, nil
}
