// SPDX-License-Identifier: MIT

package app

import (
	"testing"

	"golang.org/x/net/proxy"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// proxyReachingThisMachine seeds the proxy with the grant for everything that leaves through
// this machine's own network, which is the configuration the guard has to hold under: no
// rule is what keeps the proxy off app-tail's own listeners here.
func proxyReachingThisMachine(c *config.Config) {
	proxyOn(c)
	for i := range c.Proxies {
		if c.Proxies[i].ID == config.DefaultProxyID {
			c.Proxies[i].Rules = []access.Rule{{ID: "ar_this_machine", Action: access.Allow, Tunnel: access.ThisMachine}}
		}
	}
}

// The dashboard treats a connection from this machine as the user sitting at it. A program
// that was only handed the proxy's address would otherwise borrow that standing by asking
// the proxy to connect to the dashboard for it.
func TestAProxyCannotBeUsedToReachTheAgentsOwnListeners(t *testing.T) {
	h := newHarness(t, proxyReachingThisMachine)
	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	dialer, err := proxy.SOCKS5("tcp", view.Listening, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build a SOCKS5 client: %v", err)
	}
	for what, own := range map[string]string{
		"dashboard": h.agent.UIAddr().String(),
		"proxy":     view.Listening,
	} {
		conn, err := dialer.Dial("tcp", own)
		if err == nil {
			conn.Close()
			t.Errorf("the proxy connected a program to app-tail's own %s at %s", what, own)
		}
	}
	if got := proxyView(h).Counters.Refused; got != 2 {
		t.Errorf("the proxy counted %d refusals, want one for each of its own listeners", got)
	}
}

// Every other service on this machine is what a rule about this machine is for.
func TestAProxyStillReachesAnOrdinaryServiceOnThisMachine(t *testing.T) {
	h := newHarness(t, proxyReachingThisMachine)
	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	conn := dialThroughProxy(t, view.Listening, echoPeer(t))
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q through the proxy, want the service's echo", buf)
	}
}
