// SPDX-License-Identifier: MIT

package hostnet

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// OpenSSL reads a configuration file and loads provider modules from folders compiled into
// it, and a Homebrew build compiles in folders the installing account owns. A configuration
// file there can name a module for the root openvpn to load, so openvpn has to be started
// pointing OpenSSL at nothing a normal account can write.
func TestTheRootOpenVPNReadsNoOpenSSLConfigurationAnAccountCanWrite(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	local.state = testRootState(t)
	local.openvpnManagementDir = managementDir(t)
	dir := t.TempDir()
	program := filepath.Join(dir, "openvpn")
	envFile := filepath.Join(dir, "env")
	script := fmt.Sprintf("#!/bin/sh\n/usr/bin/env > %q.tmp\n: > \"$4\"\n/bin/mv %q.tmp %q\n", envFile, envFile, envFile)
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatalf("write the program standing in for openvpn: %v", err)
	}
	local.openvpnBinary = func() (string, error) { return program, nil }

	if err := local.StartOpenVPN(t.Context(), workingRun(t)); err != nil {
		t.Fatalf("start a connection on the stand-in openvpn: %v", err)
	}
	awaitFile(t, envFile)
	raw, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read the environment the stand-in was started with: %v", err)
	}
	env := strings.Split(strings.TrimSpace(string(raw)), "\n")

	for _, want := range []string{"OPENSSL_CONF=/dev/null", "OPENSSL_MODULES=/var/empty", "OPENSSL_ENGINES=/var/empty"} {
		if !slices.Contains(env, want) {
			t.Errorf("openvpn was started without %s, so OpenSSL reads its compiled-in folders; environment: %q", want, env)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == "HOME" || name == "PATH" || name == "DYLD_INSERT_LIBRARIES" {
			t.Errorf("openvpn inherited %s from the helper's environment", kv)
		}
	}
}
