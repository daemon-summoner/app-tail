// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"testing"
)

// The whole point: after the capture, nothing that builds a tailnet node can find a
// credential in the environment, while everything this app resolves still can. Without
// it, one variable in the environment enrolls every connection that deliberately carries
// no key of its own -- a device joining a tailnet nobody asked it to join.
func TestCapturingTheEnvironmentTakesTheTailnetLibrarysOwnVariablesOutOfIt(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "tskey-auth-from-the-environment")
	t.Setenv("TS_CONTROL_URL", "https://headscale.example.com")
	t.Setenv(EnvUIAddr, "127.0.0.1:9999")

	getenv, err := CaptureEnv()
	if err != nil {
		t.Fatalf("CaptureEnv: %v", err)
	}

	for _, key := range tailnetLibraryEnv {
		if got := os.Getenv(key); got != "" {
			t.Errorf("%s is still in the environment as %q, so a connection with no "+
				"credentials of its own would enroll with it", key, got)
		}
	}

	if got := getenv(EnvTSAuthKey); got != "tskey-auth-from-the-environment" {
		t.Errorf("the captured environment reports %s as %q; the value the user set has "+
			"to keep working where this app honors it", EnvTSAuthKey, got)
	}
	if got := getenv("TS_CONTROL_URL"); got != "https://headscale.example.com" {
		t.Errorf("the captured environment reports TS_CONTROL_URL as %q", got)
	}
	if got := getenv(EnvUIAddr); got != "127.0.0.1:9999" {
		t.Errorf("the captured environment reports %s as %q; it is not one of the "+
			"variables that were removed", EnvUIAddr, got)
	}
	if got := getenv("APPTAIL_NOTHING_SETS_THIS"); got != "" {
		t.Errorf("an unset variable reads as %q, want empty", got)
	}
}

// A captured environment is a snapshot on purpose: the settings write path re-runs the
// whole precedence chain, and a pinned value that vanished mid-run would report itself as
// editable and then be overwritten from the stored document on the next resolve.
func TestTheCapturedEnvironmentDoesNotChangeUnderneathTheProcess(t *testing.T) {
	t.Setenv(EnvHostname, "pinned-by-the-environment")

	getenv, err := CaptureEnv()
	if err != nil {
		t.Fatalf("CaptureEnv: %v", err)
	}
	t.Setenv(EnvHostname, "changed-after-the-capture")

	if got := getenv(EnvHostname); got != "pinned-by-the-environment" {
		t.Errorf("the captured environment reports %s as %q, want the value it held when "+
			"the process read it", EnvHostname, got)
	}
}

// The pinned-value machinery names these variables, and the capture removes them from the
// environment. A name in one list and not the other is how a variable stops being honored
// with nothing reporting it.
func TestEveryRemovedVariableIsOneThisAppReadsItself(t *testing.T) {
	honored := make(map[string]bool, len(tailnetEnvVars))
	for _, key := range tailnetEnvVars {
		honored[key] = true
	}
	// TS_AUTH_KEY and TS_CONTROL_URL are the library's own spellings of settings this app
	// takes under its own names, so they are removed without being resolved from.
	readElsewhere := map[string]bool{"TS_AUTH_KEY": true, "TS_CONTROL_URL": true}
	for _, key := range tailnetLibraryEnv {
		if !honored[key] && !readElsewhere[key] {
			t.Errorf("%s is taken out of the environment but nothing reads it back, so "+
				"setting it now does nothing at all", key)
		}
	}
}
