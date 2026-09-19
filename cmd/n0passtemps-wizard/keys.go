package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
)

// keyringFile is the on-disk keyring layout, matching internal/crypto/kek.
type keyringFile struct {
	Current uint32            `json:"current"`
	Keys    map[string]string `json:"keys"`
}

// runKEK manages the key encryption keyring.
func runKEK(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected a subcommand: init, rotate, seal or inspect")
	}
	switch args[0] {
	case "init":
		return kekInit(args[1:])
	case "rotate":
		return kekRotate(args[1:])
	case "seal":
		return kekSeal(args[1:])
	case "inspect":
		return kekInspect(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q, expected init, rotate, seal or inspect", args[0])
	}
}

// kekSeal encrypts a plaintext keyring to this machine's TPM.
//
// What it buys is the one line docs/THREAT-MODEL.md marks as not mitigated for
// attacker 5, who holds a copy of the database and a copy of the keyring: after
// sealing, that pair is useless without this TPM, and the likeliest way to hold
// both, one backup archive, stops working. It buys nothing against a live
// compromise of this host, which can ask the same TPM to unseal exactly as the
// service does.
//
// The command is deliberately noisy about the other half. A TPM cannot be
// backed up, so the sealed file dies with the board, and an operator who reads
// "sealed" as "safe" and deletes the plaintext has built a way to lose every
// TOTP secret in the database. It therefore unseals what it has just written
// and compares, before it says anything reassuring.
func kekSeal(args []string) error {
	fs := flag.NewFlagSet("kek seal", flag.ExitOnError)
	in := fs.String("in", "/etc/n0passtemps/kek/keyring.json", "plaintext keyring to seal")
	out := fs.String("out", "/etc/n0passtemps/kek/keyring.sealed.json", "path to write the sealed keyring to")
	device := fs.String("device", kek.DefaultTPMDevice, "TPM 2.0 device node")
	force := fs.Bool("force", false, "overwrite an existing sealed keyring")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// #nosec G304 -- the path is the one the operator asked the wizard to seal
	plain, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read %s: %w", *in, err)
	}
	defer zeroize.Bytes(plain)

	t, err := kek.OpenTPM(*device)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()

	sealed, err := kek.SealKeyring(t, plain)
	if err != nil {
		return err
	}

	// Read back before writing anything, so a TPM that seals but will not
	// unseal is found here rather than at the next start of the service.
	readBack, err := kek.UnsealKeyring(t, sealed)
	if err != nil {
		return fmt.Errorf("the sealed keyring did not unseal again, so it has not been written: %w", err)
	}
	defer zeroize.Bytes(readBack)
	if !bytes.Equal(readBack, plain) {
		return fmt.Errorf("the sealed keyring unsealed to different bytes, so it has not been written")
	}

	// Mode 0600 although the contents are ciphertext: an operator who sees a
	// file called a keyring has no way to tell which kind it is from the name,
	// and a file nobody can read is a file nobody can attack offline.
	if err := writeFile(*out, sealed, 0o600, *force); err != nil {
		return err
	}

	fmt.Printf("Sealed keyring written to %s (mode 0600).\n", *out)
	fmt.Printf("Unsealed and compared against %s before writing.\n\n", *in)
	fmt.Printf("Point the service at it:\n\n  [kek]\n  provider = \"tpm\"\n  path = %q\n", *out)
	if *device != kek.DefaultTPMDevice {
		fmt.Printf("  tpm_device = %q\n", *device)
	}
	fmt.Print("\nKEEP THE PLAINTEXT KEYRING. Back it up offline, now, if you have not.\n\n" +
		"A TPM cannot be backed up. This file opens on this machine and on no other,\n" +
		"so a dead board, a cleared owner hierarchy or a motherboard replacement makes\n" +
		"it unreadable for ever, and with it every TOTP secret and every sealed subject\n" +
		"reference in the database. Sealing adds a layer in front of the offline copy.\n" +
		"It does not replace it.\n\n" +
		"What this does buy: a copied volume, a stolen backup or a cloned disk now\n" +
		"carries ciphertext. What it does not buy: anything against an attacker running\n" +
		"as the service account on this host, who can ask the TPM to unseal exactly as\n" +
		"the service does.\n")
	return nil
}

// kekInit writes a new keyring with one key version.
func kekInit(args []string) error {
	fs := flag.NewFlagSet("kek init", flag.ExitOnError)
	out := fs.String("out", "/etc/n0passtemps/kek/keyring.json", "path to write the keyring to")
	force := fs.Bool("force", false, "overwrite an existing keyring, destroying every secret sealed under it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key := make([]byte, kek.KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	defer zeroize.Bytes(key)

	doc := keyringFile{
		Current: 1,
		Keys:    map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode keyring: %w", err)
	}
	defer zeroize.Bytes(body)

	// Mode 0600. The provider refuses a keyring readable by group or other,
	// so writing it any other way would produce a file the service will not
	// load.
	if err := writeFile(*out, append(body, '\n'), 0o600, *force); err != nil {
		return err
	}

	fmt.Printf("Keyring written to %s (mode 0600, key version 1).\n\n", *out)
	fmt.Print("Back this file up now, somewhere separate from the database.\n\n" +
		"Two things follow from losing it. The TOTP secrets and the encrypted copies\n" +
		"of your application's user references become unreadable. WebAuthn credentials\n" +
		"and recovery codes are unaffected, because public keys are stored in clear and\n" +
		"recovery codes are hashed rather than encrypted.\n\n" +
		"Do not place it inside the data directory. A key stored beside the ciphertext\n" +
		"it protects gives no confidentiality if the volume is copied, and the service\n" +
		"refuses to start in that arrangement.\n")
	return nil
}

// kekRotate adds a new key version and makes it current.
//
// Existing records keep working: each sealed record names the version it was
// sealed under, and the old key stays in the file so those records can still be
// read. Records move to the new key as they are rewritten, or in bulk through
// the rewrap operation.
//
// The old key is retained rather than removed, because removing it makes every
// record still sealed under it unreadable. Pruning a version is a separate,
// deliberate step once nothing references it.
func kekRotate(args []string) error {
	fs := flag.NewFlagSet("kek rotate", flag.ExitOnError)
	path := fs.String("file", "/etc/n0passtemps/kek/keyring.json", "keyring to rotate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The mode is checked before the keys are read, as the service checks it
	// before it starts and as assertion.LoadPrivateKeyPEM checks it for the
	// signing key. Rotating writes the file back at 0600, so without this the
	// tool would quietly repair the mode of a keyring whose every key had
	// already been readable by any local account, and say nothing of the
	// exposure. Inspecting warns instead of refusing: reading a file is not
	// what makes the state worse.
	info, err := os.Lstat(*path)
	if err != nil {
		return fmt.Errorf("read %s: %w", *path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is mode %#o, readable beyond its owner: every key in it has been "+
			"exposed to any local account, so rotating now would hide that rather than answer it. "+
			"Treat the current keys as compromised, chmod 600 %s, then rotate",
			*path, info.Mode().Perm(), *path)
	}

	raw, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read %s: %w", *path, err)
	}
	defer zeroize.Bytes(raw)

	var doc keyringFile
	if err = json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", *path, err)
	}
	if len(doc.Keys) == 0 {
		return fmt.Errorf("%s contains no keys", *path)
	}

	next := doc.Current
	for v := range doc.Keys {
		var n uint64
		n, err = strconv.ParseUint(v, 10, 32)
		if err != nil {
			return fmt.Errorf("key version %q is not a number", v)
		}
		if n > uint64(next) {
			next = uint32(n)
		}
	}
	next++

	key := make([]byte, kek.KeySize)
	if _, err = rand.Read(key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	defer zeroize.Bytes(key)

	doc.Keys[strconv.FormatUint(uint64(next), 10)] = base64.StdEncoding.EncodeToString(key)
	doc.Current = next

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode keyring: %w", err)
	}
	defer zeroize.Bytes(body)

	if err := writeFile(*path, append(body, '\n'), 0o600, true); err != nil {
		return err
	}

	fmt.Printf("Key version %d added and made current. %d versions retained.\n\n",
		next, len(doc.Keys))
	fmt.Print("Back up the updated file before restarting the service.\n\n" +
		"Existing records stay readable: each names the version it was sealed under,\n" +
		"and the earlier keys remain in the file. Do not remove an old version until\n" +
		"nothing is sealed under it any more.\n")
	return nil
}

// kekInspect reports what a keyring contains, without disclosing key material.
func kekInspect(args []string) error {
	fs := flag.NewFlagSet("kek inspect", flag.ExitOnError)
	path := fs.String("file", "/etc/n0passtemps/kek/keyring.json", "keyring to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}

	info, err := os.Stat(*path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", *path, err)
	}

	raw, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read %s: %w", *path, err)
	}
	defer zeroize.Bytes(raw)

	var doc keyringFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", *path, err)
	}

	versions := make([]int, 0, len(doc.Keys))
	for v := range doc.Keys {
		n, _ := strconv.Atoi(v)
		versions = append(versions, n)
	}
	sort.Ints(versions)

	fmt.Printf("Keyring:   %s\n", *path)
	fmt.Printf("Mode:      %#o\n", info.Mode().Perm())
	fmt.Printf("Current:   %d\n", doc.Current)
	fmt.Printf("Retained:  %v\n", versions)

	if info.Mode().Perm()&0o077 != 0 {
		fmt.Printf("\nThis file is readable beyond its owner. The service will refuse to\n"+
			"start until it is mode 0600. Fix it with: chmod 600 %s\n", *path)
	}
	return nil
}

// runAssertionKey manages the Ed25519 key that signs assertions.
func runAssertionKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected a subcommand: init, rotate or inspect")
	}
	switch args[0] {
	case "init":
		return assertionKeyInit(args[1:])
	case "rotate":
		return assertionKeyRotate(args[1:])
	case "inspect":
		return assertionKeyInspect(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q, expected init, rotate or inspect", args[0])
	}
}

// assertionKeyInit writes a new signing key.
//
// Ed25519 rather than RSA or ECDSA: there are no parameter or padding choices
// to get wrong, the keys and signatures are small, and verification is fast
// enough that an integrating application can check every assertion without
// caching.
func assertionKeyInit(args []string) error {
	fs := flag.NewFlagSet("assertion-key init", flag.ExitOnError)
	out := fs.String("out", "/etc/n0passtemps/kek/assertion-key.pem", "path to write the private key to")
	pubOut := fs.String("pub-out", "", "also write the public key here, for a verifier that pins it")
	force := fs.Bool("force", false, "overwrite an existing key, invalidating every assertion already issued")
	if err := fs.Parse(args); err != nil {
		return err
	}

	priv, pub, err := assertion.GenerateKeyPEM()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	defer zeroize.Bytes(priv)

	if err := writeFile(*out, priv, 0o600, *force); err != nil {
		return err
	}
	fmt.Printf("Signing key written to %s (mode 0600).\n", *out)

	if *pubOut != "" {
		if err := writeFile(*pubOut, pub, 0o644, *force); err != nil {
			return err
		}
		fmt.Printf("Public key written to %s.\n", *pubOut)
	}

	fmt.Print("\nThe service publishes the matching public key at\n" +
		"/v1/.well-known/jwks.json, so an integrating application normally fetches it\n" +
		"from there rather than holding a copy.\n\n" +
		"To replace this key later, use 'assertion-key rotate' rather than running\n" +
		"init again with -force. Overwriting the file refuses every assertion already\n" +
		"issued and every assertion a verifier checks against its cached copy of the\n" +
		"key set; rotate keeps the outgoing key published for a stated window so that\n" +
		"neither happens.\n")
	return nil
}

// assertionKeyRotate replaces the signing key and leaves the outgoing public
// key where the service can go on publishing it.
//
// Running init with -force is the alternative, and it is the one that causes an
// outage: the outgoing key disappears from the key set at the same instant it
// stops signing, so every token still inside its lifetime is refused, as is
// every token reaching a verifier whose cached copy of the document is older
// than the restart. Neither failure is visible here. Both are visible to the
// application, as logins that refuse for no stated reason.
//
// So this writes three files rather than one, and prints the configuration line
// that closes the gap. The old private key is kept too: a rotation performed in
// a panic is a rotation that may have to be undone, and a key that has been
// deleted cannot be put back.
func assertionKeyRotate(args []string) error {
	fs := flag.NewFlagSet("assertion-key rotate", flag.ExitOnError)
	path := fs.String("file", "/etc/n0passtemps/kek/assertion-key.pem", "signing key to replace")
	keep := fs.String("keep-prefix", "",
		"where to move the outgoing key, without an extension (default: the key path plus a timestamp)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Loaded rather than merely read, so a file that is not a usable signing
	// key is refused before anything is written. Rotating away from a key the
	// service could not have been running with means the operator is about to
	// discover two faults at once.
	outgoing, err := assertion.LoadPrivateKeyPEM(*path)
	if err != nil {
		return fmt.Errorf("outgoing key: %w", err)
	}
	outgoingIssuer, err := assertion.NewIssuer(outgoing, "rotate", time.Minute, 0)
	if err != nil {
		return fmt.Errorf("outgoing key: %w", err)
	}
	outgoingKid := outgoingIssuer.KeyID()

	prefix := *keep
	if prefix == "" {
		prefix = strings.TrimSuffix(*path, filepath.Ext(*path)) +
			"." + time.Now().UTC().Format("20060102T150405Z")
	}
	prevPub := prefix + ".pub.pem"
	prevPriv := prefix + ".pem"

	// The outgoing pair is written from the key that was just loaded rather
	// than copied from disk, so the retired public key is provably the half of
	// the key that was signing a moment ago and not whatever else the path
	// happened to hold.
	outgoingPrivPEM, outgoingPubPEM, err := assertion.EncodeKeyPEM(outgoing)
	if err != nil {
		return fmt.Errorf("encode the outgoing key: %w", err)
	}
	defer zeroize.Bytes(outgoingPrivPEM)

	if err = writeFile(prevPub, outgoingPubPEM, 0o644, false); err != nil {
		return err
	}
	if err = writeFile(prevPriv, outgoingPrivPEM, 0o600, false); err != nil {
		return err
	}

	priv, _, err := assertion.GenerateKeyPEM()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	defer zeroize.Bytes(priv)

	// Only now is the live key replaced. Everything above can fail without the
	// deployment having changed.
	if err = writeFile(*path, priv, 0o600, true); err != nil {
		return err
	}

	incoming, err := assertion.LoadPrivateKeyPEM(*path)
	if err != nil {
		return fmt.Errorf("re-read the new key: %w", err)
	}
	incomingIssuer, err := assertion.NewIssuer(incoming, "rotate", time.Minute, 0)
	if err != nil {
		return fmt.Errorf("new key: %w", err)
	}

	fmt.Printf("New signing key written to %s (mode 0600).\n", *path)
	fmt.Printf("  kid now:      %s\n", incomingIssuer.KeyID())
	fmt.Printf("  kid outgoing: %s\n", outgoingKid)
	fmt.Printf("\nOutgoing key kept at:\n  %s  (public, publish this)\n  %s  (private, mode 0600)\n",
		prevPub, prevPriv)
	fmt.Printf("\nAdd this to [assertion] before restarting, or the tokens issued in the\n"+
		"last minute and every verifier holding a cached key set will be refused:\n\n"+
		"  retired_public_key_paths = [%q]\n\n", prevPub)
	fmt.Print("Remove that line, and delete the outgoing private key, once no token signed\n" +
		"by it can still be accepted: assertion.ttl plus assertion.allowed_clock_skew\n" +
		"plus the five minutes the JWKS response stays cacheable. An hour covers it.\n" +
		"Until you do, the outgoing key still verifies whatever its private half signs,\n" +
		"which is the thing a rotation exists to stop. Every start warns while the line\n" +
		"is there.\n")
	return nil
}

// assertionKeyInspect reports the key identifier a verifier will see.
func assertionKeyInspect(args []string) error {
	fs := flag.NewFlagSet("assertion-key inspect", flag.ExitOnError)
	path := fs.String("file", "/etc/n0passtemps/kek/assertion-key.pem", "key to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}

	priv, err := assertion.LoadPrivateKeyPEM(*path)
	if err != nil {
		return err
	}

	issuer, err := assertion.NewIssuer(priv, "inspect", 60_000_000_000, 0)
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	jwks, err := issuer.JWKS()
	if err != nil {
		return fmt.Errorf("build jwks: %w", err)
	}

	fmt.Printf("Key:   %s\n", *path)
	fmt.Printf("Kid:   %s\n", issuer.KeyID())
	fmt.Printf("JWKS:  %s\n", jwks)
	return nil
}

// runPepper generates the subject reference pepper.
//
// It is a separate secret from the keyring on purpose: the key able to decrypt
// stored secrets should not also be the key able to confirm whether a given
// person has an account.
func runPepper(args []string) error {
	fs := flag.NewFlagSet("pepper", flag.ExitOnError)
	length := fs.Int("bytes", 32, "length of the pepper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *length < 32 {
		return fmt.Errorf("the pepper must be at least 32 bytes; it is an HMAC key and "+
			"32 matches the hash output length, got %d", *length)
	}

	buf := make([]byte, *length)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate pepper: %w", err)
	}
	defer zeroize.Bytes(buf)

	fmt.Printf("N0PASSTEMPS_SUBJECT_PEPPER=%s\n", base64.StdEncoding.EncodeToString(buf))
	fmt.Fprint(os.Stderr, "\nPut this in your environment or your secret manager, never in config.toml.\n"+
		"Back it up with the same care as the keyring: losing it makes every existing\n"+
		"subject unfindable, because it is what derives the lookup key from your\n"+
		"application's user reference.\n")
	return nil
}
