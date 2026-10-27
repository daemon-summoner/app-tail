// SPDX-License-Identifier: MIT

//go:build !windows

package secretstore

// seal and unseal pass the contents through unchanged. The file's 0600 mode is the
// protection here: macOS and Linux have no per-account sealing an unsigned, headless
// process can rely on, and the Docker image has no keyring at all.
func seal(plain []byte) ([]byte, error) { return plain, nil }

func unseal(sealed []byte) ([]byte, error) { return sealed, nil }
