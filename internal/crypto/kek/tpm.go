package kek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// A keyring sealed to a TPM.
//
// # What this is for, and what it is not for
//
// Attacker 5 of docs/THREAT-MODEL.md starts with a copy of the database and a
// copy of the keyring, and the model says of that position: "Nothing in the
// above" is mitigated. It is the likeliest way to arrive there too, because one
// backup archive or one snapshot commonly contains both.
// [ADR 0009](../../../docs/adr/0009-refuse-a-kek-inside-the-data-directory.md)
// keeps the two apart on disk; it cannot keep them apart in a tar file.
//
// Sealing closes exactly that. The keyring on disk becomes ciphertext, and the
// key that opens it exists only inside one TPM, which is soldered to one
// machine and will not surrender it. A copied volume, a stolen backup or a
// cloned virtual disk is then so much noise.
//
// It closes nothing else, and the distinction matters enough to put at the top
// of the file. A live compromise of this host, running as the service account,
// can ask the same TPM to unseal, exactly as the service does. After unsealing,
// the keyring is in this process's memory as it always was. This is protection
// at rest and not protection in use. Protection in use would mean the KEK never
// leaving the device, which for AES key wrapping means a different TPM object
// type and a round trip per sealed record, and is not what this is.
//
// # No PCR policy, deliberately
//
// The sealed object is bound to the TPM's owner hierarchy and nothing else. It
// could also be bound to platform configuration registers, so that it unseals
// only under the boot state it was sealed under. That sounds strictly better
// and is not: every firmware update, kernel update and bootloader change moves
// those registers, so the service stops starting on a Tuesday for a reason
// nobody connects to the update. What operators do then is unseal with a
// recovery copy and turn PCR binding off, which leaves them where they started
// having spent an outage to get there.
//
// The attacker this defends against holds a copy of the disk and not the
// machine. PCR binding does nothing about that attacker, since they have no
// TPM to present to. It defends against booting the same machine into a
// different operating system, which is a real attack and a different one, and
// one worth its own record if it is ever taken on.
//
// # The recovery hazard, which is the reason this is not the default
//
// A TPM cannot be backed up. If the board dies, the sealed keyring dies with
// it, and every TOTP secret and sealed subject reference in the database is
// unreadable for ever. Sealing therefore does not replace the offline copy of
// the plaintext keyring, it adds a layer in front of it, and an operator who
// deletes the plaintext copy because the sealed one exists has built a way to
// lose their own data. The wizard says so at every seal, and refuses to seal a
// keyring it has not just been able to read back.

// TPMFormat identifies the sealed file layout and travels inside it.
const TPMFormat = "n0passtemps.kek.tpm.v1"

// tpmFileKeySize is the length of the key that encrypts the keyring. It is
// sealed by the TPM; the TPM never sees the keyring itself.
//
// The indirection exists because a TPM sealed object holds at most 128 bytes of
// sensitive data on most parts, which a keyring with several versions exceeds.
// It is the same envelope construction as internal/crypto/envelope and for the
// same reason: seal something small, encrypt the rest with it.
const tpmFileKeySize = 32

// DefaultTPMDevice is the resource-managed device node. The resource manager is
// what allows more than one process to use the TPM without colliding over its
// three transient object slots, so it is preferred over /dev/tpm0.
const DefaultTPMDevice = "/dev/tpmrm0"

// Errors this file reports.
var (
	// ErrNotSealed says the file is a plaintext keyring. It is separate from a
	// parse failure because the fix is different: seal it, rather than repair
	// it.
	ErrNotSealed = errors.New("kek: file is not a TPM-sealed keyring")

	// ErrUnsealFailed is returned when the TPM refuses to unseal. The commonest
	// cause by far is the file having been moved to another machine, which is
	// the mechanism working rather than failing.
	ErrUnsealFailed = errors.New("kek: the TPM did not unseal the keyring")
)

// sealedFile is the on-disk layout of a sealed keyring.
//
// Everything in it is public. The sealed object's private area is encrypted to
// the TPM's storage root key and is useless anywhere else, and the ciphertext
// is AES-256-GCM under a key that exists only inside the TPM. The file is still
// written mode 0600, because a file an attacker cannot read is one they cannot
// try offline attacks against either, and because an operator who sees mode
// 0644 on something called a keyring has no way to know which kind it is.
type sealedFile struct {
	// Format is checked before anything else is attempted, so a plaintext
	// keyring pointed at the TPM provider is reported as such.
	Format string `json:"format"`

	// Parent names the primary key template the sealed object was created
	// under. It is recorded rather than assumed so that a file sealed by one
	// version is still openable if another template is ever added.
	Parent string `json:"parent"`

	// SealedPublic and SealedPrivate are the two halves of the TPM object, as
	// TPM2_Create returned them.
	SealedPublic  string `json:"sealed_public"`
	SealedPrivate string `json:"sealed_private"`

	// Nonce and Ciphertext are the AES-256-GCM envelope around the keyring
	// JSON, under the key the TPM holds.
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// parentECCP256 is the only supported primary key template: the TCG reference
// ECC P-256 storage root key.
//
// It is derived from the owner hierarchy seed, which means TPM2_CreatePrimary
// reproduces the same key on the same TPM across reboots without anything being
// stored. Clearing the owner hierarchy changes the seed and makes every sealed
// file on that machine unopenable, which is the documented way to decommission
// one and a documented way to lose a keyring.
const parentECCP256 = "ecc-p256"

// TPMProvider reads a keyring that was sealed to this machine's TPM.
type TPMProvider struct {
	*keyring
	path   string
	device string
}

// Path returns the absolute path of the sealed keyring, for diagnostics.
func (p *TPMProvider) Path() string { return p.path }

// Device returns the TPM device the keyring was unsealed through.
func (p *TPMProvider) Device() string { return p.device }

// LoadTPMProvider opens the TPM, unseals the keyring at path and parses it.
//
// dataDirs is checked exactly as the file provider checks it. A sealed keyring
// beside its own ciphertext is less dangerous than a plaintext one, since the
// pair is still useless without the TPM, but it is the same mistake and the
// same volume: a deployment that puts it there will put the next one there too.
func LoadTPMProvider(path, device string, dataDirs ...string) (*TPMProvider, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("kek: resolve %q: %w", path, err)
	}
	if err = checkNotInDataDir(abs, dataDirs); err != nil {
		return nil, err
	}
	if device == "" {
		device = DefaultTPMDevice
	}

	// #nosec G304 -- the path comes from kek.path in the operator's configuration or the KEK_PATH variable,
	// and the contents are authenticated by the TPM and by AES-GCM before anything is derived from them
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("kek: read %q: %w", abs, err)
	}

	t, err := OpenTPM(device)
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()

	plain, err := unsealKeyring(t, raw)
	if err != nil {
		return nil, err
	}
	defer zeroize.Bytes(plain)

	ring, err := parseKeyring(plain)
	if err != nil {
		return nil, err
	}
	return &TPMProvider{keyring: ring, path: abs, device: device}, nil
}

// SealKeyring encrypts a plaintext keyring to the TPM and returns the file to
// write. It is the wizard's half of the pair, exported so that sealing and
// unsealing cannot drift apart in two packages.
//
// plain is not retained and not zeroized here: it belongs to the caller, who
// also holds the copy being backed up.
func SealKeyring(t transport.TPM, plain []byte) ([]byte, error) {
	// Refused rather than sealed, because sealing an unparseable keyring
	// produces a file that fails at the next start of the service instead of
	// here, with the plaintext possibly already deleted.
	ring, err := parseKeyring(plain)
	if err != nil {
		return nil, fmt.Errorf("kek: refusing to seal a keyring that does not parse: %w", err)
	}
	_ = ring.Close()

	fileKey := make([]byte, tpmFileKeySize)
	if _, err = io.ReadFull(rand.Reader, fileKey); err != nil {
		return nil, fmt.Errorf("kek: generate the file key: %w", err)
	}
	defer zeroize.Bytes(fileKey)

	primary, err := createParent(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, primary.ObjectHandle)

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: fileKey}),
			},
		},
		InPublic: tpm2.New2B(sealedObjectTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("kek: the TPM refused to seal the file key: %w", err)
	}

	nonce, ciphertext, err := sealEnvelope(fileKey, plain)
	if err != nil {
		return nil, err
	}

	doc := sealedFile{
		Format:        TPMFormat,
		Parent:        parentECCP256,
		SealedPublic:  base64.StdEncoding.EncodeToString(tpm2.Marshal(created.OutPublic)),
		SealedPrivate: base64.StdEncoding.EncodeToString(tpm2.Marshal(created.OutPrivate)),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("kek: encode the sealed keyring: %w", err)
	}
	return append(body, '\n'), nil
}

// UnsealKeyring reverses SealKeyring and returns the plaintext keyring.
//
// It is exported for the wizard, which unseals immediately after sealing and
// compares, so that a file it has just written is known to open before an
// operator is told the sealing worked.
func UnsealKeyring(t transport.TPM, sealed []byte) ([]byte, error) {
	return unsealKeyring(t, sealed)
}

func unsealKeyring(t transport.TPM, raw []byte) ([]byte, error) {
	var doc sealedFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotSealed, err)
	}
	if doc.Format != TPMFormat {
		if doc.Format == "" {
			return nil, fmt.Errorf("%w: it has no format member, so it is probably a plaintext "+
				"keyring; seal it with: n0passtemps-wizard kek seal", ErrNotSealed)
		}
		return nil, fmt.Errorf("%w: format is %q, this build reads %q", ErrNotSealed, doc.Format, TPMFormat)
	}
	if doc.Parent != parentECCP256 {
		return nil, fmt.Errorf("%w: it was sealed under the %q primary key and this build "+
			"creates only %q", ErrNotSealed, doc.Parent, parentECCP256)
	}

	pubRaw, err := base64.StdEncoding.DecodeString(doc.SealedPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed_public is not base64: %v", ErrNotSealed, err)
	}
	privRaw, err := base64.StdEncoding.DecodeString(doc.SealedPrivate)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed_private is not base64: %v", ErrNotSealed, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(doc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce is not base64: %v", ErrNotSealed, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(doc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext is not base64: %v", ErrNotSealed, err)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed_public is not a TPM2B_PUBLIC: %v", ErrNotSealed, err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed_private is not a TPM2B_PRIVATE: %v", ErrNotSealed, err)
	}

	primary, err := createParent(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, primary.ObjectHandle)

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *priv,
		InPublic:  *pub,
	}.Execute(t)
	if err != nil {
		// This is where a file carried to another machine fails, and it is the
		// only failure mode worth naming, because it is the one that means the
		// mechanism is working.
		return nil, fmt.Errorf("%w: the sealed object does not belong to this TPM, or the "+
			"owner hierarchy has been cleared since it was sealed: %v", ErrUnsealFailed, err)
	}
	defer flush(t, loaded.ObjectHandle)

	unsealed, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsealFailed, err)
	}

	fileKey := unsealed.OutData.Buffer
	defer zeroize.Bytes(fileKey)
	if len(fileKey) != tpmFileKeySize {
		return nil, fmt.Errorf("%w: the sealed object holds %d bytes, want %d",
			ErrUnsealFailed, len(fileKey), tpmFileKeySize)
	}

	return openEnvelope(fileKey, nonce, ciphertext)
}

// sealedObjectTemplate is the public area of the sealed data object.
//
// FixedTPM and FixedParent are what make the object non-duplicable: the TPM
// will not export it under another parent or to another device, which is the
// property the whole file rests on. NoDA keeps a failed unseal out of the
// dictionary attack counter, because the object has no authorisation value to
// guess and a lockout would only ever be self-inflicted.
func sealedObjectTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
	}
}

// createParent derives the storage root key the sealed object lives under.
//
// Nothing is stored: the TPM re-derives the same key from the owner hierarchy
// seed every time, so this is reproducible across reboots and cannot be lost
// short of clearing the hierarchy.
func createParent(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("kek: derive the TPM storage root key: %w", err)
	}
	return primary, nil
}

// flush releases a transient object slot. A TPM has very few, and leaking them
// makes the next start fail with an out-of-memory error from the device rather
// than from Go, which is a confusing place to begin diagnosing.
func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

func sealEnvelope(fileKey, plain []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(fileKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("kek: generate a nonce: %w", err)
	}
	// The format string is authenticated, so a file cannot be replayed into a
	// future layout that means something else by the same bytes.
	return nonce, gcm.Seal(nil, nonce, plain, []byte(TPMFormat)), nil
}

func openEnvelope(fileKey, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(fileKey)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrNotSealed, len(nonce), gcm.NonceSize())
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(TPMFormat))
	if err != nil {
		// The TPM unsealed, so the key is right and the file has been edited.
		return nil, fmt.Errorf("%w: the file key is correct and the ciphertext does not "+
			"authenticate, so the file has been altered", ErrUnsealFailed)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kek: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kek: gcm: %w", err)
	}
	return gcm, nil
}
