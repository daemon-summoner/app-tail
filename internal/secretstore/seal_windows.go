// SPDX-License-Identifier: MIT

package secretstore

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sealEntropy is mixed into every seal, so a blob this package wrote is not unsealed by an
// unrelated program of the same account calling DPAPI with no entropy. It is not a secret.
var sealEntropy = []byte("app-tail secrets.json")

// seal encrypts plain with DPAPI to the current account: only a process running as this
// user on this machine can unseal it. UI is forbidden because the agent runs with no one
// at a prompt, and a dialog nothing answers is a write that never returns.
func seal(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("nothing to seal")
	}
	in := blob(plain)
	entropy := blob(sealEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return takeBlob(&out)
}

// unseal reverses seal. A blob sealed by another account, on another machine, or altered
// since it was written fails here rather than decoding to something else.
func unseal(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("the file is empty")
	}
	in := blob(sealed)
	entropy := blob(sealEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return takeBlob(&out)
}

func blob(data []byte) windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

// takeBlob copies what DPAPI allocated into Go memory and frees the original, which
// LocalFree owns.
func takeBlob(out *windows.DataBlob) ([]byte, error) {
	data := make([]byte, out.Size)
	copy(data, unsafe.Slice(out.Data, out.Size))
	if _, err := windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))); err != nil {
		return nil, fmt.Errorf("LocalFree: %w", err)
	}
	return data, nil
}
