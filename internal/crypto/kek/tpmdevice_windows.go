//go:build windows

package kek

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

// OpenTPM reports that this platform has no device to open.
//
// The TPM provider seals the keyring against a device node, which is a Linux
// notion; Windows exposes its TPM through TBS instead, and nothing here speaks
// it. The binary still builds and every other provider still works, so an
// operator on Windows who asks for this one is told why rather than handed a
// binary that would not link.
func OpenTPM(string) (transport.TPMCloser, error) {
	return nil, errors.New("kek: the tpm provider needs a TPM device node, which this platform does not have; " +
		"use kek.provider = \"file\" or \"env\"")
}
