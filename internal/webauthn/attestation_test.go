package webauthn

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/store"
)

// The stored attestation type has to survive a round trip into the library's
// vocabulary, because with a metadata BLOB loaded every assertion is checked
// against it.
//
// ValidateLogin calls protocol.ValidateMetadata with the AttestationType and
// AttestationFormat of the credential record it was handed, which is what
// toLibCredential builds. The entries in a BLOB name their attestation types as
// "basic_full" and "basic_surrogate"; the column names them "basic" and "self",
// because that is what its CHECK constraint permits. These tests are against the
// library function itself rather than through a ceremony, because a ceremony
// needs a signed BLOB and what is being pinned is the comparison that function
// makes.

// mdsEntry is one authenticator model as a metadata BLOB describes it, with the
// attestation types it is certified for.
func mdsEntry(t *testing.T, aaguid uuid.UUID, types ...metadata.AuthenticatorAttestationType) metadata.Provider {
	t.Helper()
	entry := &metadata.Entry{
		AaGUID: aaguid,
		MetadataStatement: metadata.Statement{
			AttestationTypes: types,
		},
	}
	provider, err := memory.New(
		memory.WithMetadata(map[uuid.UUID]*metadata.Entry{aaguid: entry}),
		memory.WithValidateEntry(true),
		memory.WithValidateEntryPermitZeroAAGUID(false),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
	)
	if err != nil {
		t.Fatalf("build metadata provider: %v", err)
	}
	return provider
}

// validateStored puts a stored credential through the check ValidateLogin makes
// on every assertion.
func validateStored(t *testing.T, provider metadata.Provider, aaguid uuid.UUID,
	stored store.AttestationType) error {
	t.Helper()
	lib := toLibCredential(&store.Credential{
		CredentialID:    []byte("credential"),
		AAGUID:          aaguid[:],
		AttestationType: stored,
	})
	err := protocol.ValidateMetadata(context.Background(), provider, aaguid,
		lib.AttestationType, lib.AttestationFormat, nil)
	if err == nil {
		return nil
	}
	return err
}

func TestACredentialEnrolledUnderAMetadataBlobCanStillSignIn(t *testing.T) {
	aaguid := uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")

	for _, tc := range []struct {
		name     string
		stored   store.AttestationType
		entry    []metadata.AuthenticatorAttestationType
		reported string
	}{
		{
			// The case that locked keys out. A packed attestation with a
			// certificate chain is reported by the library as "basic_full" and
			// stored as "basic"; handing "basic" back matches nothing in an
			// entry that says "basic_full", so the credential registered and
			// then never signed in again.
			name:     "a key that attested with a certificate chain",
			stored:   store.AttestationBasic,
			entry:    []metadata.AuthenticatorAttestationType{metadata.BasicFull},
			reported: "basic_full",
		},
		{
			name:     "a key that attested with its own credential key",
			stored:   store.AttestationSelf,
			entry:    []metadata.AuthenticatorAttestationType{metadata.BasicSurrogate},
			reported: "basic_surrogate",
		},
		{
			name:     "a key attested through a privacy CA",
			stored:   store.AttestationAttCA,
			entry:    []metadata.AuthenticatorAttestationType{metadata.AttCA},
			reported: "attca",
		},
		{
			name:     "a key attested through an anonymization CA",
			stored:   store.AttestationAnonCA,
			entry:    []metadata.AuthenticatorAttestationType{metadata.AnonCA},
			reported: "anonca",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := libAttestation(tc.stored); got != tc.reported {
				t.Errorf("stored %q reads back as %q, want %q: it is compared against the "+
					"attestationTypes of the metadata entry, which use this spelling",
					tc.stored, got, tc.reported)
			}
			if err := validateStored(t, mdsEntry(t, aaguid, tc.entry...), aaguid, tc.stored); err != nil {
				t.Fatalf("an assertion by a credential enrolled with attestation %q was refused "+
					"against the entry that certified it: %v", tc.stored, err)
			}
		})
	}
}

// TestAnAttestationTypeTheModelIsNotCertifiedForIsStillRefused keeps the round
// trip from becoming a way of skipping the check.
//
// Without this, mapping every stored value onto something the entry happens to
// accept would pass the test above and check nothing.
func TestAnAttestationTypeTheModelIsNotCertifiedForIsStillRefused(t *testing.T) {
	aaguid := uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")
	provider := mdsEntry(t, aaguid, metadata.BasicSurrogate)

	if err := validateStored(t, provider, aaguid, store.AttestationBasic); err == nil {
		t.Fatal("a credential recorded as having attested with a certificate chain was accepted " +
			"against a model certified only for self attestation")
	}
}

// TestACredentialEnrolledWithoutAttestationIsNotLockedOutByALaterBlob covers the
// deployment that turns metadata verification on after people have enrolled.
//
// An attestation of none carries no proof, and the AAGUID beside it is a claim
// rather than an identification, so there is nothing about it for a metadata
// entry to confirm or contradict. Looking it up anyway means refusing every
// credential whose model is not in the BLOB, which is every credential enrolled
// while attestation_preference was "none".
func TestACredentialEnrolledWithoutAttestationIsNotLockedOutByALaterBlob(t *testing.T) {
	known := uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")
	unknown := uuid.MustParse("ee882879-721c-4913-9775-3dfcce97072a")
	provider := mdsEntry(t, known, metadata.BasicFull)

	if _, format := libAttestation(store.AttestationNone); format != "none" {
		t.Fatalf("a credential stored as unattested reads back with format %q, want \"none\"", format)
	}
	if err := validateStored(t, provider, unknown, store.AttestationNone); err != nil {
		t.Fatalf("a credential enrolled without attestation was refused once a blob was "+
			"loaded: %v", err)
	}
}

// TestAnAttestedModelWithNoMetadataEntryIsRefused is the neighbouring case, and
// it is deliberately left refusing.
//
// Turning require_attestation on for a population that already holds keys will
// lock out every one whose model the BLOB does not describe. That is the setting
// doing what it says, so it is documented rather than worked around: the answer
// is to enrol a second factor before turning it on, not to accept a model the
// operator asked to have verified.
func TestAnAttestedModelWithNoMetadataEntryIsRefused(t *testing.T) {
	known := uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")
	unknown := uuid.MustParse("ee882879-721c-4913-9775-3dfcce97072a")
	provider := mdsEntry(t, known, metadata.BasicFull)

	if err := validateStored(t, provider, unknown, store.AttestationBasic); err == nil {
		t.Fatal("an attested credential whose model has no metadata entry was accepted")
	}
}

// TestTheStoredVocabularyIsUnchanged is what makes the round trip safe without a
// migration.
//
// Nothing about what is written changed, so a row an earlier build wrote and a
// row written today hold the same value, and libAttestation reads both. The pair
// has to stay an inverse for that to remain true.
func TestTheStoredVocabularyIsUnchanged(t *testing.T) {
	for _, stored := range []store.AttestationType{
		store.AttestationBasic,
		store.AttestationSelf,
		store.AttestationAttCA,
		store.AttestationAnonCA,
		store.AttestationNone,
	} {
		reported, _ := libAttestation(stored)
		if got := normaliseAttestation(reported); got != stored {
			t.Errorf("stored %q reads back as %q, which is stored again as %q: a row written "+
				"today would not read the same as one written before", stored, reported, got)
		}
	}
}
