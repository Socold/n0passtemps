package webauthn_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator data flag bits, from WebAuthn Level 2 section 6.1.
const (
	flagUserPresent  byte = 0x01
	flagUserVerified byte = 0x04
	flagAttestedData byte = 0x40
)

// errCredentialExcluded is what a real authenticator reports, through the
// browser's InvalidStateError, when one of its credentials appears in the
// exclude list of a creation request.
var errCredentialExcluded = errors.New("authenticator: a credential on this device is in the exclude list")

// errNoMatchingCredential is the authenticator finding nothing in the allow
// list that it holds for the requested relying party.
var errNoMatchingCredential = errors.New("authenticator: no credential on this device matches the allow list")

// virtualCredential is one key pair held by the authenticator.
type virtualCredential struct {
	id         []byte
	key        *ecdsa.PrivateKey
	rpID       string
	userHandle []byte
}

// virtualAuthenticator plays the part of the browser and the security key
// together, because the service under test sees only their joint output.
//
// It exists so that the ceremony code can be exercised with genuine
// signatures over genuine authenticator data. A test that fed the service
// canned fixtures would prove the fixtures parse; it would not prove that a
// wrong origin, a stale counter or a forged signature is refused, because
// each of those needs a response that is valid in every respect but one.
//
// The signature counter is global to the device rather than per credential.
// The specification permits either, and a global counter is what several
// widely deployed hardware keys implement.
type virtualAuthenticator struct {
	aaguid      [16]byte
	origin      string
	transports  []string
	credentials map[string]*virtualCredential
	counter     uint32

	// userPresent and userVerified drive the UP and UV flag bits.
	userPresent  bool
	userVerified bool

	// freezeCounter stops the counter advancing, which is how both a
	// counter-less authenticator (frozen at zero) and a cloned one (frozen at
	// whatever the clone last saw) look from the relying party's side.
	freezeCounter bool

	// forcedCounter, when set, is reported by the next operation verbatim and
	// becomes the device counter.
	forcedCounter *uint32

	// rpIDHashOverride replaces SHA-256(rpId) in the authenticator data. A
	// response carrying it is what a phishing relying party would obtain from
	// a genuine key: valid in every respect, but scoped to the wrong party.
	rpIDHashOverride []byte

	// tamperSignature makes get sign over a different message. The result is
	// a well-formed DER signature from the right key that does not verify,
	// so a refusal is attributable to the cryptographic check and not to a
	// parsing failure.
	tamperSignature bool

	// nextCredentialID makes the next create reuse this identifier in place
	// of a random one. A hostile client can submit any identifier it likes,
	// including one it observed belonging to somebody else.
	nextCredentialID []byte

	// forgePackedAttestation makes create produce a packed attestation
	// statement (section 8.2) signed by a certificate this device made up,
	// instead of the empty "none" statement. The library reports such a
	// statement as attestation type "basic_full", because the format-specific
	// verifier only checks that the statement is internally consistent; that
	// the certificate chains to nothing is a question only a trust anchor can
	// ask. It is what software pretending to be a hardware key produces.
	forgePackedAttestation bool

	// last is the credential most recently created, so a test can compare
	// what the service stored against what the device actually holds.
	last *virtualCredential
}

// newVirtualAuthenticator returns a device that reports user presence and user
// verification, the way a key with a PIN or a biometric sensor does.
func newVirtualAuthenticator(origin string, aaguid [16]byte) *virtualAuthenticator {
	return &virtualAuthenticator{
		aaguid:       aaguid,
		origin:       origin,
		transports:   []string{"usb"},
		credentials:  make(map[string]*virtualCredential),
		userPresent:  true,
		userVerified: true,
	}
}

// forceCounter arranges for the next operation to report exactly v.
func (a *virtualAuthenticator) forceCounter(v uint32) { a.forcedCounter = &v }

// creationOptions is the subset of PublicKeyCredentialCreationOptions a
// browser and an authenticator act on.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []credentialDescriptor `json:"excludeCredentials"`
	} `json:"publicKey"`
}

// requestOptions is the subset of PublicKeyCredentialRequestOptions a browser
// and an authenticator act on.
type requestOptions struct {
	PublicKey struct {
		Challenge        string                 `json:"challenge"`
		RPID             string                 `json:"rpId"`
		AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	} `json:"publicKey"`
}

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// readOptions round-trips the service's options through JSON, which is the only
// form in which a browser ever sees them. Reading the Go struct directly would
// hide an encoding mistake, such as a challenge serialised in the wrong
// alphabet, that a real client would trip over.
func readOptions(options, into any) error {
	raw, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("authenticator: marshal options: %w", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("authenticator: read options: %w", err)
	}
	return nil
}

// create performs navigator.credentials.create and returns the
// PublicKeyCredential JSON the browser would POST.
func (a *virtualAuthenticator) create(options any) ([]byte, error) {
	var opts creationOptions
	if err := readOptions(options, &opts); err != nil {
		return nil, err
	}
	pk := opts.PublicKey
	if pk.Challenge == "" || pk.RP.ID == "" || pk.User.ID == "" {
		return nil, errors.New("authenticator: creation options lack a challenge, rp.id or user.id")
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(pk.User.ID)
	if err != nil {
		return nil, fmt.Errorf("authenticator: user.id is not base64url: %w", err)
	}

	for _, d := range pk.ExcludeCredentials {
		var id []byte
		id, err = base64.RawURLEncoding.DecodeString(d.ID)
		if err != nil {
			return nil, fmt.Errorf("authenticator: excluded id is not base64url: %w", err)
		}
		if held, ok := a.credentials[string(id)]; ok && held.rpID == pk.RP.ID {
			return nil, errCredentialExcluded
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authenticator: generate key: %w", err)
	}
	credID := a.nextCredentialID
	a.nextCredentialID = nil
	if credID == nil {
		credID = make([]byte, 32)
		if _, err = rand.Read(credID); err != nil {
			return nil, fmt.Errorf("authenticator: generate credential id: %w", err)
		}
	}

	coseKey, err := encodeCOSEKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	// Attested credential data, section 6.5.1:
	// aaguid(16) || credentialIdLength(2, big endian) || credentialId || COSE_Key.
	var attested bytes.Buffer
	attested.Write(a.aaguid[:])
	_ = binary.Write(&attested, binary.BigEndian, uint16(len(credID)))
	attested.Write(credID)
	attested.Write(coseKey)

	// Creation reports the device counter without advancing it: section 6.3.2
	// has a global counter reported at its current value, and only
	// authenticatorGetAssertion moves it.
	authData := a.authenticatorData(pk.RP.ID, flagAttestedData, a.currentCounter(), attested.Bytes())

	// The client data comes first because a packed statement signs over it.
	clientData, err := a.clientDataJSON("webauthn.create", pk.Challenge)
	if err != nil {
		return nil, err
	}

	statement := map[string]any{
		// Attestation format "none", section 8.7: an empty statement, which is
		// what a browser substitutes when the relying party asked for no
		// attestation.
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	if a.forgePackedAttestation {
		if statement, err = a.packedStatement(authData, clientData); err != nil {
			return nil, err
		}
	}
	attObj, err := ctap2Encode(statement)
	if err != nil {
		return nil, err
	}

	cred := &virtualCredential{id: credID, key: key, rpID: pk.RP.ID, userHandle: userHandle}
	a.credentials[string(credID)] = cred
	a.last = cred

	return json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credID),
		"rawId": base64.RawURLEncoding.EncodeToString(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
			"transports":        a.transports,
		},
	})
}

// get performs navigator.credentials.get and returns the assertion JSON the
// browser would POST.
func (a *virtualAuthenticator) get(options any) ([]byte, error) {
	var opts requestOptions
	if err := readOptions(options, &opts); err != nil {
		return nil, err
	}
	pk := opts.PublicKey
	if pk.Challenge == "" || pk.RPID == "" {
		return nil, errors.New("authenticator: request options lack a challenge or rpId")
	}

	var cred *virtualCredential
	if len(pk.AllowCredentials) == 0 {
		// An empty allow list is a discoverable request: the relying party has
		// named nobody, so the device itself chooses from the credentials it
		// holds for this relying party. A real authenticator prompts the user;
		// this one takes the lowest identifier so the choice is deterministic
		// and a test can assert which subject came back.
		var chosen string
		for id, held := range a.credentials {
			if held.rpID != pk.RPID {
				continue
			}
			if chosen == "" || id < chosen {
				chosen, cred = id, held
			}
		}
	} else {
		for _, d := range pk.AllowCredentials {
			id, err := base64.RawURLEncoding.DecodeString(d.ID)
			if err != nil {
				return nil, fmt.Errorf("authenticator: allowed id is not base64url: %w", err)
			}
			// A credential is scoped to the relying party it was created for,
			// and the device will not use it for another one.
			if held, ok := a.credentials[string(id)]; ok && held.rpID == pk.RPID {
				cred = held
				break
			}
		}
	}
	if cred == nil {
		return nil, errNoMatchingCredential
	}

	clientData, err := a.clientDataJSON("webauthn.get", pk.Challenge)
	if err != nil {
		return nil, err
	}
	clientDataHash := sha256.Sum256(clientData)

	// Section 6.3.3 step 10 advances the counter before the authenticator data
	// is built, so the value signed is the new one.
	authData := a.authenticatorData(pk.RPID, 0, a.advanceCounter(), nil)

	// The signature covers authenticatorData || SHA-256(clientDataJSON),
	// section 6.3.3 step 11, as an ASN.1 DER ECDSA signature (section 6.5.5).
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	if a.tamperSignature {
		signed[len(signed)-1] ^= 0x01
	}
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("authenticator: sign: %w", err)
	}

	return json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(cred.id),
		"rawId": base64.RawURLEncoding.EncodeToString(cred.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(cred.userHandle),
		},
	})
}

// oidFIDOGenCeAAGUID is id-fido-gen-ce-aaguid, the certificate extension
// section 8.2.1 uses to name the authenticator model an attestation
// certificate speaks for.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// packedStatement builds a packed attestation statement signed by a
// certificate this device generated for itself.
//
// Everything section 8.2.1 requires of the certificate is present, including
// the extension naming the AAGUID, and the signature over
// authenticatorData || SHA-256(clientDataJSON) verifies against it. What is
// absent is any reason to believe the certificate: it is self-signed and chains
// to nothing. A relying party with no trust anchors cannot tell the difference,
// which is the whole point of the test that uses this.
func (a *virtualAuthenticator) packedStatement(authData, clientData []byte) (map[string]any, error) {
	attestationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authenticator: generate attestation key: %w", err)
	}

	aaguidExtension, err := asn1.Marshal(a.aaguid[:])
	if err != nil {
		return nil, fmt.Errorf("authenticator: encode aaguid extension: %w", err)
	}

	// Section 8.2.1 requires four subject attributes, and they are written
	// here as the object identifiers the certificate actually carries: a
	// country, the vendor's legal name, the literal string "Authenticator
	// Attestation" as the organisational unit, and a common name of the
	// vendor's choosing.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "SE"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Plausible Security AB"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Authenticator Attestation"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Plausible Security Attestation"},
		}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{{
			Id:       oidFIDOGenCeAAGUID,
			Critical: false,
			Value:    aaguidExtension,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template,
		&attestationKey.PublicKey, attestationKey)
	if err != nil {
		return nil, fmt.Errorf("authenticator: create attestation certificate: %w", err)
	}

	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, attestationKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("authenticator: sign attestation: %w", err)
	}

	return map[string]any{
		"fmt": "packed",
		"attStmt": map[string]any{
			// -7 is ES256, RFC 9053 table 5.
			"alg": -7,
			"sig": signature,
			"x5c": []any{der},
		},
		"authData": authData,
	}, nil
}

// clientDataJSON is the browser's contribution (section 5.8.1). The origin is
// the one the page was really served from, which is why a test overrides it on
// the authenticator and not in the options: the relying party never gets to
// tell the browser where it is.
func (a *virtualAuthenticator) clientDataJSON(ceremony, challenge string) ([]byte, error) {
	return json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{ceremony, challenge, a.origin, false})
}

// authenticatorData lays out section 6.1:
// rpIdHash(32) || flags(1) || signCount(4, big endian) || attestedCredentialData.
func (a *virtualAuthenticator) authenticatorData(rpID string, extraFlags byte, signCount uint32, attested []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	hash := rpIDHash[:]
	if a.rpIDHashOverride != nil {
		hash = a.rpIDHashOverride
	}

	flags := extraFlags
	if a.userPresent {
		flags |= flagUserPresent
	}
	if a.userVerified {
		flags |= flagUserVerified
	}

	out := make([]byte, 0, 37+len(attested))
	out = append(out, hash...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, signCount)
	return append(out, attested...)
}

// currentCounter reports the counter without moving it.
func (a *virtualAuthenticator) currentCounter() uint32 {
	if a.forcedCounter != nil {
		a.counter = *a.forcedCounter
		a.forcedCounter = nil
	}
	return a.counter
}

// advanceCounter moves the counter as an assertion does and reports the result.
func (a *virtualAuthenticator) advanceCounter() uint32 {
	if a.forcedCounter != nil {
		return a.currentCounter()
	}
	if !a.freezeCounter {
		a.counter++
	}
	return a.counter
}

// encodeCOSEKey renders an ES256 public key as the COSE_Key of RFC 9052
// section 7: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
func encodeCOSEKey(pub *ecdsa.PublicKey) ([]byte, error) {
	x, y, err := coordinates(pub)
	if err != nil {
		return nil, err
	}
	return ctap2Encode(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
}

// coordinates returns the fixed-width affine coordinates of a P-256 key.
func coordinates(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	// The uncompressed point is 0x04 || X(32) || Y(32), which yields the
	// coordinates already left-padded to the width COSE demands.
	point, err := pub.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("authenticator: encode public key: %w", err)
	}
	if len(point) != 65 || point[0] != 0x04 {
		return nil, nil, errors.New("authenticator: public key is not an uncompressed P-256 point")
	}
	return point[1:33], point[33:65], nil
}

// ctap2Encode uses the CTAP2 canonical CBOR form. Authenticators are required
// to emit it, and a relying party is entitled to reject anything else.
func ctap2Encode(v any) ([]byte, error) {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("authenticator: cbor mode: %w", err)
	}
	out, err := mode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("authenticator: cbor encode: %w", err)
	}
	return out, nil
}
