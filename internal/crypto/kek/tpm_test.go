package kek

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// These tests need a TPM 2.0. They are skipped rather than failed when there is
// none, which is the same arrangement the PostgreSQL suite uses: a test that
// cannot run says so, and a test that silently passes without exercising
// anything is worse than one that is not there.
//
// Two ways to give them one.
//
//	N0PASSTEMPS_TEST_TPM_TCP=127.0.0.1:2321,127.0.0.1:2322
//
// is a software TPM, which is what CI uses and what a developer without access
// to the device node uses:
//
//	swtpm socket --tpm2 --tpmstate dir=$(mktemp -d) \
//	  --server type=tcp,port=2321,bindaddr=127.0.0.1 \
//	  --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
//	  --flags not-need-init,startup-clear --daemon
//
//	N0PASSTEMPS_TEST_TPM_DEVICE=/dev/tpmrm0
//
// is the real device, which needs the running user to be in the 'tss' group.
// It is worth doing at least once before trusting a deployment to it, because a
// simulator agrees with the specification and hardware only mostly does.
const (
	envTPMTCP    = "N0PASSTEMPS_TEST_TPM_TCP"
	envTPMDevice = "N0PASSTEMPS_TEST_TPM_DEVICE"
)

// testKeyring is a plaintext keyring with two versions, so that the test covers
// a payload past the 128 bytes a TPM sealed object can hold by itself. That
// limit is the reason the file key exists at all.
const testKeyring = `{
  "current": 2,
  "keys": {
    "1": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "2": "IB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE="
  }
}`

// openTestTPM connects to whichever TPM the environment offers.
func openTestTPM(t *testing.T) (transport.TPM, bool) {
	t.Helper()

	if addrs := os.Getenv(envTPMTCP); addrs != "" {
		cmd, plat, ok := bytes.Cut([]byte(addrs), []byte(","))
		if !ok {
			t.Fatalf("%s must be command,platform, for example 127.0.0.1:2321,127.0.0.1:2322", envTPMTCP)
		}
		conn, err := tcp.Open(tcp.Config{CommandAddress: string(cmd), PlatformAddress: string(plat)})
		if err != nil {
			t.Fatalf("connect to the simulator at %s: %v", addrs, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn, true
	}

	device := os.Getenv(envTPMDevice)
	if device == "" {
		t.Skipf("no TPM: set %s or %s", envTPMTCP, envTPMDevice)
		return nil, false
	}
	conn, err := linuxtpm.Open(device)
	if err != nil {
		t.Fatalf("open %s: %v", device, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, true
}

// TestSealedKeyringRoundTrip is the property the file exists for: what goes in
// comes back, and what comes back parses as the keyring it was.
func TestSealedKeyringRoundTrip(t *testing.T) {
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}

	sealed, err := SealKeyring(tpm, []byte(testKeyring))
	if err != nil {
		t.Fatalf("SealKeyring: %v", err)
	}

	// The keyring must not be recoverable from the file by reading it.
	if bytes.Contains(sealed, []byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")) {
		t.Fatal("the sealed file contains a key from the plaintext keyring")
	}
	var doc sealedFile
	if err = json.Unmarshal(sealed, &doc); err != nil {
		t.Fatalf("the sealed file is not JSON: %v", err)
	}
	if doc.Format != TPMFormat {
		t.Errorf("format = %q, want %q", doc.Format, TPMFormat)
	}

	plain, err := UnsealKeyring(tpm, sealed)
	if err != nil {
		t.Fatalf("UnsealKeyring: %v", err)
	}
	if !bytes.Equal(plain, []byte(testKeyring)) {
		t.Fatalf("round trip changed the keyring:\n%s\n%s", testKeyring, plain)
	}

	ring, err := parseKeyring(plain)
	if err != nil {
		t.Fatalf("the unsealed keyring does not parse: %v", err)
	}
	defer func() { _ = ring.Close() }()
	v, key, err := ring.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v != 2 {
		t.Errorf("current version = %d, want 2", v)
	}
	if len(key) != KeySize {
		t.Errorf("current key is %d bytes, want %d", len(key), KeySize)
	}
}

// TestSealingIsNotDeterministic guards the envelope. Two seals of the same
// keyring must differ, or the nonce is being reused and GCM's guarantees are
// gone.
func TestSealingIsNotDeterministic(t *testing.T) {
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}
	first, err := SealKeyring(tpm, []byte(testKeyring))
	if err != nil {
		t.Fatalf("SealKeyring: %v", err)
	}
	second, err := SealKeyring(tpm, []byte(testKeyring))
	if err != nil {
		t.Fatalf("SealKeyring: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of the same keyring produced identical files")
	}
}

// TestAnAlteredSealedFileIsRefused covers the half of the file the TPM does not
// authenticate by itself.
func TestAnAlteredSealedFileIsRefused(t *testing.T) {
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}
	sealed, err := SealKeyring(tpm, []byte(testKeyring))
	if err != nil {
		t.Fatalf("SealKeyring: %v", err)
	}

	var doc sealedFile
	if err = json.Unmarshal(sealed, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// One character of the base64 ciphertext, which is one or two bits of it.
	ct := []byte(doc.Ciphertext)
	if ct[0] == 'A' {
		ct[0] = 'B'
	} else {
		ct[0] = 'A'
	}
	doc.Ciphertext = string(ct)
	altered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := UnsealKeyring(tpm, altered); err == nil {
		t.Fatal("an altered sealed file was accepted")
	}
}

// TestAPlaintextKeyringIsReportedAsSuch keeps the commonest configuration
// mistake, pointing the TPM provider at the file that was there before, from
// being reported as a corrupt file.
func TestAPlaintextKeyringIsReportedAsSuch(t *testing.T) {
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}
	_, err := UnsealKeyring(tpm, []byte(testKeyring))
	if err == nil {
		t.Fatal("a plaintext keyring was accepted as sealed")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("kek seal")) {
		t.Errorf("the error does not say how to fix it: %s", got)
	}
}

// TestAnUnparseableKeyringIsNotSealed stops the failure that would be
// discovered after the plaintext had been deleted.
func TestAnUnparseableKeyringIsNotSealed(t *testing.T) {
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}
	if _, err := SealKeyring(tpm, []byte(`{"current": 1, "keys": {}}`)); err == nil {
		t.Fatal("a keyring with no keys was sealed")
	}
	if _, err := SealKeyring(tpm, []byte("not json")); err == nil {
		t.Fatal("a file that is not a keyring was sealed")
	}
}

// TestClearingTheOwnerHierarchyLosesTheKeyring is the mechanism working, and it
// is also the operational hazard, so it is pinned rather than described.
//
// It runs only against a simulator. Clearing the owner hierarchy of a real TPM
// invalidates every other sealed object on that machine, including ones this
// project did not create, and a test suite has no business doing that to
// somebody's laptop.
func TestClearingTheOwnerHierarchyLosesTheKeyring(t *testing.T) {
	if os.Getenv(envTPMTCP) == "" {
		t.Skipf("only against a simulator; set %s", envTPMTCP)
	}
	tpm, ok := openTestTPM(t)
	if !ok {
		return
	}

	sealed, err := SealKeyring(tpm, []byte(testKeyring))
	if err != nil {
		t.Fatalf("SealKeyring: %v", err)
	}
	if _, err := UnsealKeyring(tpm, sealed); err != nil {
		t.Fatalf("UnsealKeyring before the clear: %v", err)
	}

	if _, err := (tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHLockout,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}).Execute(tpm); err != nil {
		t.Fatalf("clear the owner hierarchy: %v", err)
	}

	if _, err := UnsealKeyring(tpm, sealed); err == nil {
		t.Fatal("the keyring still unsealed after the owner hierarchy was cleared; " +
			"the sealed object is not bound to the hierarchy seed, so a copied file " +
			"would open on a machine it was not sealed on")
	}
}
