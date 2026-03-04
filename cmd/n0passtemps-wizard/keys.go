package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"

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
		return fmt.Errorf("expected a subcommand: init, rotate or inspect")
	}
	switch args[0] {
	case "init":
		return kekInit(args[1:])
	case "rotate":
		return kekRotate(args[1:])
	case "inspect":
		return kekInspect(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q, expected init, rotate or inspect", args[0])
	}
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

	raw, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read %s: %w", *path, err)
	}
	defer zeroize.Bytes(raw)

	var doc keyringFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", *path, err)
	}
	if len(doc.Keys) == 0 {
		return fmt.Errorf("%s contains no keys", *path)
	}

	next := doc.Current
	for v := range doc.Keys {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return fmt.Errorf("key version %q is not a number", v)
		}
		if uint32(n) > next {
			next = uint32(n)
		}
	}
	next++

	key := make([]byte, kek.KeySize)
	if _, err := rand.Read(key); err != nil {
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
		return fmt.Errorf("expected a subcommand: init or inspect")
	}
	switch args[0] {
	case "init":
		return assertionKeyInit(args[1:])
	case "inspect":
		return assertionKeyInspect(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q, expected init or inspect", args[0])
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
		"Replacing this key invalidates every assertion already issued. Since an\n" +
		"assertion lives for sixty seconds, that is a brief disruption rather than a\n" +
		"migration, but it is not nothing: a rotation during a login burst refuses\n" +
		"those logins and the users retry.\n")
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
	bytes := fs.Int("bytes", 32, "length of the pepper")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bytes < 32 {
		return fmt.Errorf("the pepper must be at least 32 bytes; it is an HMAC key and "+
			"32 matches the hash output length, got %d", *bytes)
	}

	buf := make([]byte, *bytes)
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
