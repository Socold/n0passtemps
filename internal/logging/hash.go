package logging

import "crypto/sha256"

// fingerprintHash is separated so the domain separator is stated once.
//
// The separator means a fingerprint computed for a log line can never collide
// with, or be substituted for, a digest computed elsewhere in the service, in
// particular the HMAC used to look a subject up.
func fingerprintHash(v string) [sha256.Size]byte {
	return sha256.Sum256([]byte("n0passtemps/log-fingerprint/v1" + v))
}
