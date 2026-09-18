// Package subject resolves the identifier an integrating application uses for
// its own user into a record in this service.
//
// The application's reference is treated as personal data. The documentation
// asks for an opaque identifier, and applications supply email addresses
// regardless, so the reference is never stored in clear:
//
//	ref_hmac    a deterministic HMAC-SHA256 under a server-held pepper, which
//	            is the only value used for lookups, so an exact match stays a
//	            single indexed probe
//	ref_sealed  the envelope-encrypted original, decrypted only to answer a
//	            subject access request or to render the admin interface
//
// An attacker holding the database alone can neither read nor enumerate the
// references. One holding the database and the pepper can confirm a guess, but
// still cannot enumerate. The pepper is deliberately a different secret from
// the key encryption key, so that the key able to decrypt secrets is not also
// the key able to confirm whether a given person has an account.
package subject

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
	"github.com/Socold/n0passtemps/internal/store"
)

// MinPepperBytes is the shortest pepper accepted.
//
// The pepper is an HMAC key, so 32 bytes matches the output length of the hash
// and there is no benefit in going longer. Anything materially shorter reduces
// the work an attacker who has the database needs to do to confirm a guess.
const MinPepperBytes = 32

// Errors reported by this package.
var (
	ErrRefEmpty      = errors.New("subject: reference is empty")
	ErrRefTooLong    = errors.New("subject: reference is too long")
	ErrRefMalformed  = errors.New("subject: reference contains control characters")
	ErrPepperMissing = errors.New("subject: pepper is not set")
	ErrPepperShort   = errors.New("subject: pepper is too short")
)

// Service resolves references to subjects.
type Service struct {
	store  store.Store
	sealer *envelope.Sealer
	cfg    config.Subject
	pepper []byte
	now    func() time.Time
}

// New builds a Service, reading the pepper from the environment variable named
// in the configuration.
//
// The variable is unset once read, so the pepper does not remain visible to
// child processes or through /proc/self/environ.
func New(cfg config.Subject, st store.Store, sealer *envelope.Sealer, clock func() time.Time) (*Service, error) {
	if clock == nil {
		clock = time.Now
	}

	raw, ok := os.LookupEnv(cfg.PepperEnv)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: set %s", ErrPepperMissing, cfg.PepperEnv)
	}
	defer func() { _ = os.Unsetenv(cfg.PepperEnv) }()

	pepper, err := decodePepper(raw)
	if err != nil {
		return nil, err
	}
	if len(pepper) < MinPepperBytes {
		zeroize.Bytes(pepper)
		return nil, fmt.Errorf("%w: %s holds %d bytes, at least %d are required",
			ErrPepperShort, cfg.PepperEnv, len(pepper), MinPepperBytes)
	}

	return &Service{store: st, sealer: sealer, cfg: cfg, pepper: pepper, now: clock}, nil
}

// Close zeroizes the pepper.
func (s *Service) Close() {
	zeroize.Bytes(s.pepper)
	s.pepper = nil
}

// RefHMAC derives the lookup key for a reference under a pepper.
//
// The domain separator means this value cannot be confused with, or substituted
// for, any other digest in the service.
//
// It is a function rather than only a method so that a tool verifying a backup
// can recompute a stored lookup value without building a Service. The
// construction exists once: a second copy of it elsewhere would drift, and a
// drifted domain separator makes every existing subject unfindable.
func RefHMAC(pepper []byte, ref string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte("n0passtemps/subject-ref/v1"))
	mac.Write([]byte{0})
	mac.Write([]byte(ref))
	return mac.Sum(nil)
}

// RefHMAC derives the lookup key for a reference under this Service's pepper.
func (s *Service) RefHMAC(ref string) []byte {
	return RefHMAC(s.pepper, ref)
}

// ValidateRef checks a reference before it is used.
//
// Control characters are refused because the reference reaches log lines, the
// admin interface and audit detail. A reference containing a newline could
// otherwise forge an extra log entry, and one carrying a terminal escape
// sequence could rewrite what an operator reading the log sees.
func (s *Service) ValidateRef(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return ErrRefEmpty
	}
	if len(ref) > s.cfg.MaxRefLength {
		return fmt.Errorf("%w: %d bytes, the limit is %d",
			ErrRefTooLong, len(ref), s.cfg.MaxRefLength)
	}
	// Validity is checked on the bytes. Ranging over the string substitutes
	// U+FFFD for an invalid sequence, which cannot be told apart from a
	// reference that legitimately contains that rune.
	if !utf8.ValidString(ref) {
		return fmt.Errorf("%w: invalid UTF-8", ErrRefMalformed)
	}
	for _, r := range ref {
		if unicode.IsControl(r) {
			return ErrRefMalformed
		}
	}
	return nil
}

// Resolve returns the subject for a reference, creating it if it does not
// exist.
//
// Creation is idempotent, so an integrating application may call this on every
// login rather than tracking whether it has registered the user here before.
func (s *Service) Resolve(ctx context.Context, tenantID, ref, displayName string) (*store.Subject, error) {
	if err := s.ValidateRef(ref); err != nil {
		return nil, err
	}

	refHMAC := s.RefHMAC(ref)

	// The common path is an existing subject, so try the read first and avoid
	// sealing the reference again on every login.
	existing, err := s.store.GetSubjectByRef(ctx, tenantID, refHMAC)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("subject: look up reference: %w", err)
	}

	now := s.now().UTC()
	sub := &store.Subject{
		ID:          uuid.NewString(),
		TenantID:    tenantID,
		RefHMAC:     refHMAC,
		DisplayName: strings.TrimSpace(displayName),
		Status:      store.SubjectActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if s.cfg.SealReference {
		sub.RefSealed, err = s.sealer.Seal([]byte(ref))
		if err != nil {
			return nil, fmt.Errorf("subject: seal reference: %w", err)
		}
	}

	created, err := s.store.UpsertSubject(ctx, sub)
	if err != nil {
		return nil, fmt.Errorf("subject: create: %w", err)
	}
	return created, nil
}

// Lookup returns the subject for a reference without creating one.
func (s *Service) Lookup(ctx context.Context, tenantID, ref string) (*store.Subject, error) {
	if err := s.ValidateRef(ref); err != nil {
		return nil, err
	}
	return s.store.GetSubjectByRef(ctx, tenantID, s.RefHMAC(ref))
}

// RevealRef decrypts the stored reference.
//
// This is the operation that turns a row back into something identifying a
// person, so it exists for exactly two purposes: answering a subject access
// request under GDPR Article 15, and showing an operator which user a record
// belongs to. Callers are expected to record an audit entry when they use it.
func (s *Service) RevealRef(sub *store.Subject) (string, error) {
	if len(sub.RefSealed) == 0 {
		return "", fmt.Errorf("subject: %s has no sealed reference, seal_reference was off when it was created", sub.ID)
	}
	plain, err := s.sealer.Unseal(sub.RefSealed)
	if err != nil {
		return "", fmt.Errorf("subject: unseal reference: %w", err)
	}
	defer zeroize.Bytes(plain)
	return string(plain), nil
}

// Matches reports whether a subject corresponds to a reference, in constant
// time with respect to the stored value.
func (s *Service) Matches(sub *store.Subject, ref string) bool {
	return hmac.Equal(sub.RefHMAC, s.RefHMAC(ref))
}
