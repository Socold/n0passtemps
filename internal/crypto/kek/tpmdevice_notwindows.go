//go:build !windows

package kek

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// OpenTPM opens the TPM device node.
//
// It exists so that the one import of a platform-specific transport lives in
// one file with one build constraint. go-tpm's linuxtpm package is built for
// every platform except Windows, and importing it from tpm.go made the whole
// module, the wizard included, fail to build for Windows: a release matrix that
// builds a windows/amd64 binary stopped at the import rather than at the one
// provider that cannot work there.
//
// The caller closes what it is given.
func OpenTPM(device string) (transport.TPMCloser, error) {
	if device == "" {
		device = DefaultTPMDevice
	}
	t, err := linuxtpm.Open(device)
	if err != nil {
		return nil, fmt.Errorf("kek: open %s: %w\n"+
			"the account needs read and write on the TPM device, which on most "+
			"distributions means membership of the 'tss' group", device, err)
	}
	return t, nil
}
