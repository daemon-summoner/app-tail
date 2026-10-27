// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"os"
	"strings"
)

// tailnetLibraryEnv are the variables the tailnet library reads on its own, behind this
// app, whenever the corresponding field on a node it builds is left empty.
//
// That fallback was written for a process that runs one node. This one runs a node per
// connection, and an empty field is a legal answer: a connection with no auth key is one
// that logs in interactively. Left in place, a single variable in the environment would
// silently enroll every such connection into whichever tailnet the key belongs to -- and
// on Tailscale, enrolling is not a read-only mistake.
//
// TS_AUTHKEY and TS_CLIENT_SECRET are honored by this app under their native names, so
// removing them from the environment is not the same as ignoring them: they are captured
// first and layered onto the primary connection by the resolver, exactly as before.
var tailnetLibraryEnv = []string{
	"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CONTROL_URL", "TS_CLIENT_SECRET",
}

// CaptureEnv reads the process environment once and hands back a Getenv over that
// snapshot, having removed the variables the tailnet library would otherwise consult
// itself. Every later lookup answers from the snapshot, so a value the user set is still
// honored everywhere this app honors it -- and nothing but this app decides what a
// connection enrolls with.
//
// Call it once, before anything builds a node. A failure to remove one is returned rather
// than logged: proceeding would leave the fallback armed while the process believes it is
// not, which is the one state this exists to prevent.
func CaptureEnv() (Getenv, error) {
	snapshot := make(map[string]string, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		snapshot[key] = value
	}
	for _, key := range tailnetLibraryEnv {
		if _, held := snapshot[key]; !held {
			continue
		}
		if err := os.Unsetenv(key); err != nil {
			return nil, fmt.Errorf("take %s out of the environment so it cannot enroll a "+
				"connection that has no credentials of its own: %w", key, err)
		}
	}
	return func(key string) string { return snapshot[key] }, nil
}
