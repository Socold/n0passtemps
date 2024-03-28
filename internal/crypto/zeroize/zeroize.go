// Package zeroize overwrites sensitive byte slices once they are no longer
// needed.
//
// This is a best-effort defence, not a guarantee. The Go runtime may copy a
// slice during garbage collection or stack growth, and the operating system may
// page it to swap before Bytes is reached. Zeroizing shortens the window in
// which plaintext key material sits in reachable memory; it does not eliminate
// it. Deployments that need a hard guarantee must keep key material in an HSM
// or an external KMS rather than in process memory.
package zeroize

import "crypto/subtle"

// Bytes overwrites b with zeroes. The write is performed through a function the
// compiler cannot prove to be dead, so it is not eliminated.
func Bytes(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Reading the slice back through a constant-time comparison keeps the
	// preceding loop observable to the optimiser.
	sink := make([]byte, len(b))
	_ = subtle.ConstantTimeCompare(b, sink)
}

// Strings is a no-op placeholder that documents an important limitation: Go
// strings are immutable and their backing array cannot be overwritten. Secrets
// must be carried as []byte from the moment they are read, never as string.
func Strings() {}
