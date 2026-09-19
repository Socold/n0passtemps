// Package audit records security-relevant events in a tamper-evident log.
//
// Each entry commits to a hash of the entry before it, so the log forms a
// chain. Altering, removing or inserting an entry breaks verification for every
// entry after it.
//
// This detects tampering; it does not prevent it. In an on-premise deployment
// the operator owns the database file and can rewrite the whole chain
// consistently if they choose to. Preventing that needs a witness outside the
// operator's control, which is what shipping entries to an append-only external
// sink is for. Within a single database, detection is the strongest property
// available, and it is enough to make undetected selective deletion
// impractical.
//
// # Erasure and the chain
//
// An audit log and a right to erasure pull in opposite directions. The log must
// not change, and Article 17 says some of its contents must go.
//
// Hashing the personal fields directly would mean erasing them breaks
// verification for the rest of the log. Leaving them out of the hash entirely
// would mean the subject reference on an entry could be altered without
// detection, and the subject reference is precisely the field an attacker would
// want to alter. Committing to a bare digest of them would not help either: a
// source address has only thirty-two bits of entropy and would be recovered
// from its digest by exhaustive search in seconds.
//
// So the personal fields are committed through a salted digest. Each entry
// carries a random salt, and the chain covers the digest of the salt together
// with the personal fields, not the fields themselves. Erasing an entry means
// clearing those fields and destroying the salt, keeping the digest. The chain
// still verifies, the fields are gone, and without the salt the digest cannot
// be reversed even for a low-entropy value.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// HashSize is the length of a chain hash in bytes.
const HashSize = sha256.Size

// SaltSize is the length of the per-entry salt protecting the personal fields.
const SaltSize = 16

// Domain separators are mixed into every digest, so a value computed here can
// never be mistaken for, or substituted by, one computed elsewhere in this
// system.
const (
	chainDomain = "n0passtemps/audit-chain/v1"
	piiDomain   = "n0passtemps/audit-pii/v1"
)

// Genesis is the PrevHash of the first entry in the log.
//
// It is derived from the domain separator rather than being a block of zero
// bytes, so an attacker cannot truncate the log to nothing and present the
// result as a valid empty chain whose head happens to be all zeroes.
func Genesis() []byte {
	sum := sha256.Sum256([]byte(chainDomain + "/genesis"))
	return sum[:]
}

// NewSalt draws a fresh per-entry salt.
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltSize)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("audit: generate salt: %w", err)
	}
	return s, nil
}

// PIIDigest commits to the personal fields of an entry under its salt.
//
// Once the salt is destroyed the digest reveals nothing about the fields, which
// is what allows an entry to be erased without breaking the chain.
func PIIDigest(e *store.AuditEntry) []byte {
	h := sha256.New()
	writeField(h, []byte(piiDomain))
	writeField(h, e.PIISalt)
	writeField(h, []byte(e.SubjectID))
	writeField(h, []byte(e.SourceIP))
	writeField(h, e.Detail)
	return h.Sum(nil)
}

// ComputeHash returns the chain hash of an entry, given the hash of its
// predecessor.
//
// Every field is written length-prefixed. Without the prefixes two different
// entries could serialise to the same byte string: an entry with event type
// "credential.revoke" and an empty actor would be indistinguishable from one
// with event type "credential" and actor ".revoke". That ambiguity would let an
// attacker construct a substitute entry with a matching hash, which is exactly
// what the chain exists to rule out.
//
// The timestamp is written as a Unix nanosecond count rather than a formatted
// string, so a change in how timestamps are rendered cannot invalidate an
// existing chain.
//
// The personal fields enter through PIIDigest rather than directly. See the
// package comment.
func ComputeHash(e *store.AuditEntry, prevHash []byte) []byte {
	h := sha256.New()
	writeField(h, []byte(chainDomain))
	writeField(h, prevHash)

	// The two numeric fields are reinterpreted as their two's-complement bit
	// patterns. That mapping is injective, which is the only property the
	// chain asks of them: both are committed to the digest and neither is
	// ever read back or compared, so a negative sequence number or a
	// pre-epoch instant still hashes to something no other entry hashes to.
	// Rejecting either here would invalidate every chain already written
	// without detecting anything.
	// #nosec G115 -- injective bit reinterpretation of a value that is hashed, never read back
	writeUint64(h, uint64(e.Seq))
	writeField(h, []byte(e.TenantID))
	// #nosec G115 -- injective bit reinterpretation of a value that is hashed, never read back
	writeUint64(h, uint64(e.OccurredAt.UTC().UnixNano()))
	writeField(h, []byte(e.EventType))
	writeField(h, []byte(e.ActorType))
	writeField(h, []byte(e.ActorID))
	writeField(h, []byte(e.ResourceType))
	writeField(h, []byte(e.ResourceID))
	writeField(h, []byte(e.Outcome))
	writeField(h, []byte(e.RequestID))
	writeField(h, e.PIIDigest)

	return h.Sum(nil)
}

// Prepare fills in the salt, the personal-field digest and the chain hashes of
// an entry about to be appended.
//
// It is called by the store implementation inside the same transaction that
// reads the chain head, because computing the hashes outside that transaction
// would let two concurrent appends chain onto the same predecessor.
func Prepare(e *store.AuditEntry, seq int64, prevHash []byte) error {
	// The timestamp is truncated to microseconds before it is hashed.
	//
	// ComputeHash commits to a nanosecond count, and PostgreSQL's TIMESTAMPTZ
	// stores microseconds. Without this, an entry written with nanosecond
	// precision would hash a value the column cannot hold, and the entry would
	// fail verification the moment it was read back. Truncating here rather
	// than in one backend means the hashed value does not depend on which
	// engine stores it, and the constraint is stated once.
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)

	if e.PIISalt == nil {
		salt, err := NewSalt()
		if err != nil {
			return err
		}
		e.PIISalt = salt
	}
	e.Seq = seq
	e.PrevHash = prevHash
	e.PIIDigest = PIIDigest(e)
	e.EntryHash = ComputeHash(e, prevHash)
	return nil
}

// VerifyEntry recomputes an entry's hash and reports whether it matches what
// was stored and chains onto prevHash.
//
// An entry that still holds its salt is checked fully, including that its
// personal fields reproduce the stored digest. An erased entry has no salt, so
// its digest is taken as given and only the chain link is checked. That is the
// intended limitation: erasure trades the ability to re-derive one entry's
// personal fields for the ability to erase them at all.
func VerifyEntry(e *store.AuditEntry, prevHash []byte) bool {
	if len(e.EntryHash) != HashSize || len(e.PrevHash) != HashSize || len(e.PIIDigest) != HashSize {
		return false
	}
	if !equal(e.PrevHash, prevHash) {
		return false
	}
	if len(e.PIISalt) == SaltSize && !equal(PIIDigest(e), e.PIIDigest) {
		return false
	}
	return equal(ComputeHash(e, prevHash), e.EntryHash)
}

// VerifySequence walks a contiguous run of entries and returns the sequence
// number of the first that does not verify, or zero if all of them do.
//
// prevHash is the hash the run is expected to chain onto: Genesis() when
// starting from the beginning of the log, or the stored EntryHash of the entry
// immediately before entries[0].
func VerifySequence(entries []*store.AuditEntry, prevHash []byte) (brokenAt int64) {
	cur := prevHash
	for _, e := range entries {
		if !VerifyEntry(e, cur) {
			return e.Seq
		}
		cur = e.EntryHash
	}
	return 0
}

// Erase clears the personal fields of an entry and destroys its salt, leaving
// the chain verifiable.
//
// The caller is responsible for persisting the result. The audit table refuses
// ordinary updates, so the store performs this through the one statement
// permitted to touch an existing row.
func Erase(e *store.AuditEntry) {
	e.SubjectID = ""
	e.SourceIP = ""
	e.Detail = nil
	e.PIISalt = nil
}

// Erased reports whether an entry has had its personal fields removed.
func Erased(e *store.AuditEntry) bool { return len(e.PIISalt) == 0 }

// writeField writes an 8-byte big-endian length followed by the bytes.
func writeField(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func writeUint64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = h.Write(b[:])
}

// equal is a plain comparison. Chain hashes are not secrets and an attacker
// learns nothing from how long this takes, so a constant-time comparison would
// add cost without adding a property.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
