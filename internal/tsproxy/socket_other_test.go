// SPDX-License-Identifier: MIT

//go:build !unix

package tsproxy

// Starting an instance on a platform that has no socket beside the port. listenLocal opens
// nothing here, and what the caller does with that answer is the whole question: the split
// listener and the status line both take what it hands back.

import (
	"net/http"
	"testing"

	"tailscale.com/net/socks5"

	"github.com/sellitus/app-tail/internal/config"
)

// A state directory is configured, so the socket path is computed and only the absence of a
// listener stops it being used. Reporting that path would put a socket in the status, in the
// dashboard and in every connection snippet that nothing on this machine can connect to, and
// the two serving goroutines behind it would be started over a listener that is not there.
func TestAPlatformWithNoInstanceSocketReportsNoneRatherThanItsPath(t *testing.T) {
	set := NewSet(Options{
		Network:  newFakeNetwork(t),
		Logger:   quietLogger(),
		StateDir: t.TempDir(),
	})
	t.Cleanup(set.Close)
	inst := newInstance(set, config.ProxyInstance{
		ID:      config.DefaultProxyID,
		Slug:    config.DefaultProxySlug,
		Name:    "Default",
		Enabled: true,
	})

	ln, path, err := inst.startLocal(&http.Server{}, &socks5.Server{})

	if err != nil {
		t.Fatalf("starting an instance where the platform has no socket: %v", err)
	}
	if ln != nil {
		ln.Close()
		t.Error("a listener came back from a platform that opens none")
	}
	if path != "" {
		t.Errorf("the instance reports its socket at %q, but no socket was opened there", path)
	}
}
