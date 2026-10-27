// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/sigscan"
)

func validForward() Forward {
	return Forward{
		ID:         "f_aaaaaa",
		Name:       "SSH to build box",
		Direction:  ToLocal,
		Protocol:   TCP,
		BindAddr:   "127.0.0.1",
		ListenPort: 2222,
		Target:     "buildbox:22",
		Enabled:    true,
	}
}

func TestValidateForwardRejectsBadFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Forward)
		wantField string
	}{
		{"unknown direction", func(f *Forward) { f.Direction = "sideways" }, "direction"},
		{"empty direction", func(f *Forward) { f.Direction = "" }, "direction"},
		{"unknown protocol", func(f *Forward) { f.Protocol = "sctp" }, "protocol"},
		{"port zero", func(f *Forward) { f.ListenPort = 0 }, "listenPort"},
		{"port negative", func(f *Forward) { f.ListenPort = -1 }, "listenPort"},
		{"port too high", func(f *Forward) { f.ListenPort = 65536 }, "listenPort"},
		{"bind addr is a hostname", func(f *Forward) { f.BindAddr = "localhost" }, "bindAddr"},
		{"bind addr garbage", func(f *Forward) { f.BindAddr = "999.1.1.1" }, "bindAddr"},
		{"target missing port", func(f *Forward) { f.Target = "buildbox" }, "target"},
		{"target empty", func(f *Forward) { f.Target = "" }, "target"},
		{"target port zero", func(f *Forward) { f.Target = "buildbox:0" }, "target"},
		{"target port too high", func(f *Forward) { f.Target = "buildbox:70000" }, "target"},
		{"target port not a number", func(f *Forward) { f.Target = "buildbox:ssh" }, "target"},
		{"target host empty", func(f *Forward) { f.Target = ":22" }, "target"},
		{"negative udp timeout", func(f *Forward) { f.UDPTimeoutSec = -5 }, "udpTimeoutSec"},
		{"lan bind nobody chose to expose", func(f *Forward) { f.BindAddr = "0.0.0.0" }, "bindAddr"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := validForward()
			tc.mutate(&f)
			err := ValidateForward(f)
			if err == nil {
				t.Fatalf("ValidateForward accepted invalid forward %+v", f)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error is %T (%v), want *ValidationError", err, err)
			}
			if ve.Field != tc.wantField {
				t.Errorf("field = %q, want %q (err: %v)", ve.Field, tc.wantField, err)
			}
		})
	}
}

func TestValidateForwardAcceptsValidVariants(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Forward)
	}{
		{"plain to_local tcp", func(*Forward) {}},
		{"udp", func(f *Forward) { f.Protocol = UDP }},
		{"both", func(f *Forward) { f.Protocol = Both }},
		{"ipv6 bind", func(f *Forward) { f.BindAddr = "::1" }},
		{"lan bind the user chose to expose", func(f *Forward) { f.BindAddr = "0.0.0.0"; f.ExposeToNetwork = true }},
		{"magicdns target", func(f *Forward) { f.Target = "dns-server.tail1234.ts.net:53" }},
		{"ipv6 target", func(f *Forward) { f.Target = "[fd7a:115c:a1e0::1]:22" }},
		{"to_tailnet ignores bind addr", func(f *Forward) { f.Direction = ToTailnet; f.BindAddr = "not-an-ip" }},
		{"max port", func(f *Forward) { f.ListenPort = 65535 }},
		{"disabled", func(f *Forward) { f.Enabled = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := validForward()
			tc.mutate(&f)
			if err := ValidateForward(f); err != nil {
				t.Fatalf("ValidateForward rejected valid forward %+v: %v", f, err)
			}
		})
	}
}

func TestValidateForwardInDetectsConflicts(t *testing.T) {
	existing := validForward()
	existing.ID = "f_existing"
	existing.Name = "Existing SSH"

	t.Run("same proto bind and port conflicts", func(t *testing.T) {
		next := validForward()
		next.ID = "f_new"
		next.Target = "otherbox:22"
		err := ValidateForwardIn(next, []Forward{existing})
		var ce *ConflictError
		if !errors.As(err, &ce) {
			t.Fatalf("error is %T (%v), want *ConflictError", err, err)
		}
		if ce.OtherID != "f_existing" {
			t.Errorf("OtherID = %q, want f_existing", ce.OtherID)
		}
		// The message must name the other forward so the user can find it.
		if !strings.Contains(ce.Error(), "Existing SSH") {
			t.Errorf("conflict message %q does not name the conflicting forward", ce.Error())
		}
	})

	t.Run("different protocol does not conflict", func(t *testing.T) {
		next := validForward()
		next.ID = "f_new"
		next.Protocol = UDP
		if err := ValidateForwardIn(next, []Forward{existing}); err != nil {
			t.Fatalf("udp on the same port as tcp should be allowed, got %v", err)
		}
	})

	t.Run("both conflicts with a tcp-only forward on the same port", func(t *testing.T) {
		// existing is tcp. A "both" forward shares the tcp stack, so it must be refused
		// even though its udp half is free.
		next := validForward()
		next.ID = "f_new"
		next.Protocol = Both
		var ce *ConflictError
		if err := ValidateForwardIn(next, []Forward{existing}); !errors.As(err, &ce) {
			t.Fatalf("both must conflict with a tcp forward on the same port, got %v", err)
		}
	})

	t.Run("both conflicts with a udp-only forward on the same port", func(t *testing.T) {
		udpOnly := validForward()
		udpOnly.ID = "f_udp"
		udpOnly.Protocol = UDP
		next := validForward()
		next.ID = "f_new"
		next.Protocol = Both
		var ce *ConflictError
		if err := ValidateForwardIn(next, []Forward{udpOnly}); !errors.As(err, &ce) {
			t.Fatalf("both must conflict with a udp forward on the same port, got %v", err)
		}
	})

	t.Run("both conflicts with another both on the same port", func(t *testing.T) {
		first := validForward()
		first.ID = "f_first"
		first.Protocol = Both
		next := validForward()
		next.ID = "f_new"
		next.Protocol = Both
		var ce *ConflictError
		if err := ValidateForwardIn(next, []Forward{first}); !errors.As(err, &ce) {
			t.Fatalf("two both forwards on the same port must conflict, got %v", err)
		}
	})

	t.Run("both does not conflict on a different port", func(t *testing.T) {
		next := validForward()
		next.ID = "f_new"
		next.Protocol = Both
		next.ListenPort = existing.ListenPort + 1
		if err := ValidateForwardIn(next, []Forward{existing}); err != nil {
			t.Fatalf("both on a free port should be allowed, got %v", err)
		}
	})

	t.Run("different bind addr does not conflict", func(t *testing.T) {
		next := validForward()
		next.ID = "f_new"
		next.BindAddr = "127.0.0.2"
		if err := ValidateForwardIn(next, []Forward{existing}); err != nil {
			t.Fatalf("different bind address should be allowed, got %v", err)
		}
	})

	t.Run("updating the same id is not a self-conflict", func(t *testing.T) {
		next := existing
		next.Target = "newtarget:22"
		if err := ValidateForwardIn(next, []Forward{existing}); err != nil {
			t.Fatalf("updating a forward in place should be allowed, got %v", err)
		}
	})

	t.Run("disabled forwards do not reserve a port", func(t *testing.T) {
		disabled := existing
		disabled.Enabled = false
		next := validForward()
		next.ID = "f_new"
		if err := ValidateForwardIn(next, []Forward{disabled}); err != nil {
			t.Fatalf("a disabled forward should not hold its port, got %v", err)
		}
	})

	t.Run("a new disabled forward never conflicts", func(t *testing.T) {
		next := validForward()
		next.ID = "f_new"
		next.Enabled = false
		if err := ValidateForwardIn(next, []Forward{existing}); err != nil {
			t.Fatalf("disabled forward should not conflict, got %v", err)
		}
	})

	t.Run("to_tailnet shares one namespace regardless of bind addr", func(t *testing.T) {
		a := validForward()
		a.ID = "f_a"
		a.Direction = ToTailnet
		a.BindAddr = "127.0.0.1"
		b := validForward()
		b.ID = "f_b"
		b.Direction = ToTailnet
		b.BindAddr = "10.0.0.5"
		var ce *ConflictError
		if err := ValidateForwardIn(b, []Forward{a}); !errors.As(err, &ce) {
			t.Fatalf("two to_tailnet forwards on the same port must conflict, got %v", err)
		}
	})

	t.Run("to_local and to_tailnet on the same port do not conflict", func(t *testing.T) {
		remote := validForward()
		remote.ID = "f_remote"
		remote.Direction = ToTailnet
		if err := ValidateForwardIn(remote, []Forward{existing}); err != nil {
			t.Fatalf("directions bind different stacks and should not conflict, got %v", err)
		}
	})
}

func TestEndpointRendersTheProtocol(t *testing.T) {
	f := validForward()
	f.ListenPort = 8080
	f.BindAddr = "127.0.0.1"

	f.Protocol = TCP
	if got, want := Endpoint(f), "TCP 127.0.0.1:8080"; got != want {
		t.Errorf("tcp endpoint = %q, want %q", got, want)
	}
	f.Protocol = Both
	if got, want := Endpoint(f), "TCP+UDP 127.0.0.1:8080"; got != want {
		t.Errorf("both endpoint = %q, want %q", got, want)
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("a both forward reserves both stacks", func(t *testing.T) {
		both := validForward()
		both.ID = "f_both"
		both.Protocol = Both
		// A tcp-only forward on the same port must collide with the both forward's tcp key.
		tcpDup := validForward()
		tcpDup.ID = "f_tcp"
		tcpDup.Protocol = TCP
		cfg := &Config{Settings: Defaults().Settings, Forwards: []Forward{both, tcpDup}}
		var ce *ConflictError
		if err := cfg.Validate(); !errors.As(err, &ce) {
			t.Fatalf("a both forward must reserve its tcp port, got %T %v", err, err)
		}
	})

	t.Run("duplicate ids rejected", func(t *testing.T) {
		a := validForward()
		b := validForward()
		b.ListenPort = 2223
		cfg := &Config{Settings: Defaults().Settings, Forwards: []Forward{a, b}}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate id") {
			t.Fatalf("want duplicate id error, got %v", err)
		}
	})

	t.Run("missing id rejected", func(t *testing.T) {
		f := validForward()
		f.ID = ""
		cfg := &Config{Settings: Defaults().Settings, Forwards: []Forward{f}}
		if err := cfg.Validate(); err == nil {
			t.Fatal("a forward without an id must be rejected")
		}
	})

	t.Run("conflicting endpoints rejected", func(t *testing.T) {
		a := validForward()
		a.ID = "f_a"
		a.Name = "First"
		b := validForward()
		b.ID = "f_b"
		cfg := &Config{Settings: Defaults().Settings, Forwards: []Forward{a, b}}
		var ce *ConflictError
		if err := cfg.Validate(); !errors.As(err, &ce) {
			t.Fatalf("want *ConflictError, got %T %v", err, err)
		} else if ce.OtherID != "f_a" {
			t.Errorf("OtherID = %q, want f_a", ce.OtherID)
		}
	})

	t.Run("valid document accepted", func(t *testing.T) {
		a := validForward()
		a.ID = "f_a"
		b := validForward()
		b.ID = "f_b"
		b.ListenPort = 2223
		cfg := &Config{Settings: Defaults().Settings, Forwards: []Forward{a, b}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid document rejected: %v", err)
		}
	})
}

func TestSettingsValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Settings)
		wantErr bool
	}{
		{"defaults are valid", func(*Settings) {}, false},
		{"loopback ui addr ok", func(s *Settings) { s.UIListen = "127.0.0.1:8377" }, false},
		{"ipv6 loopback ui addr ok", func(s *Settings) { s.UIListen = "[::1]:8377" }, false},
		{"wildcard ui addr rejected", func(s *Settings) { s.UIListen = "0.0.0.0:8377" }, true},
		{"lan ui addr rejected", func(s *Settings) { s.UIListen = "192.168.1.5:8377" }, true},
		{"tailnet ui addr rejected", func(s *Settings) { s.UIListen = "100.64.0.1:8377" }, true},
		{"ui addr without port rejected", func(s *Settings) { s.UIListen = "127.0.0.1" }, true},
		{"ui addr with hostname rejected", func(s *Settings) { s.UIListen = "localhost:8377" }, true},
		{"ui addr with an out-of-range port rejected", func(s *Settings) { s.UIListen = "127.0.0.1:99999" }, true},
		{"negative udp timeout rejected", func(s *Settings) { s.UDPSessionTimeoutSec = -1 }, true},
		{"oversized udp buffer rejected", func(s *Settings) { s.UDPBufferBytes = 70000 }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := Defaults().Settings
			tc.mutate(&s)
			err := s.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate accepted invalid settings %+v", s)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate rejected valid settings %+v: %v", s, err)
			}
		})
	}
}

// The tailnet's own rules now belong to the connection that describes it, and they are
// checked on the whole document because the credential and the tags it requires can only
// be judged together.
func TestTailnetConnectionValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TailscaleTunnel)
		wantErr bool
	}{
		{"defaults are valid", func(*TailscaleTunnel) {}, false},
		{"untagged tag rejected", func(ts *TailscaleTunnel) { ts.Tags = []string{"app-tail"} }, true},
		{"oauth secret without tags rejected", func(ts *TailscaleTunnel) {
			ts.OAuthClientSecret = "tskey-client-x"
			ts.Tags = nil
		}, true},
		{"oauth secret file without tags rejected", func(ts *TailscaleTunnel) {
			ts.OAuthClientSecretFile = "/run/secrets/oauth"
			ts.Tags = nil
		}, true},
		{"oauth secret with tags ok", func(ts *TailscaleTunnel) { ts.OAuthClientSecret = "tskey-client-x" }, false},
		{"auth key without tags ok", func(ts *TailscaleTunnel) {
			ts.AuthKey = "tskey-auth-x"
			ts.Tags = nil
		}, false},
		{"control url must be http", func(ts *TailscaleTunnel) { ts.ControlURL = "headscale.example.com" }, true},
		{"https control url ok", func(ts *TailscaleTunnel) { ts.ControlURL = "https://headscale.example.com" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			ts, err := cfg.PrimaryTailscale()
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(ts)
			err = cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate accepted an invalid connection %+v", *ts)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate rejected a valid connection %+v: %v", *ts, err)
			}
		})
	}
}

// A tailnet block on a connection of another protocol is a set of values nothing reads,
// which is how a credential someone stored goes nowhere with no error anywhere.
func TestATailnetBlockOnAnotherProtocolIsRefused(t *testing.T) {
	cfg := Defaults()
	peer := NewTunnel("tn_a1b2c3", "office", "Office", TunnelWireGuard)
	peer.Tailscale = &TailscaleTunnel{AuthKey: "tskey-auth-x"}
	cfg.Tunnels = append(cfg.Tunnels, peer)

	err := cfg.Validate()

	if err == nil {
		t.Fatal("a WireGuard connection carrying tailnet settings was accepted")
	}
	if !strings.Contains(err.Error(), "office") {
		t.Errorf("error = %v, want the connection named", err)
	}
}

// Every kind of connection carries the block for its own type and no other. A block of
// another type is settings nothing reads, and its credentials are ones the move into
// secrets.json never looks for, so they would stay in config.json for good.
func TestABlockOfAnotherTypeIsRefusedOnEveryKindOfConnection(t *testing.T) {
	blocks := map[TunnelType]func(*Tunnel){
		TunnelTailscale: func(into *Tunnel) { into.Tailscale = &TailscaleTunnel{} },
		TunnelWireGuard: func(into *Tunnel) {
			stray := wireGuardFixture()
			into.WireGuard = &stray
		},
		TunnelOpenVPN: func(into *Tunnel) { into.OpenVPN = &OpenVPNTunnel{Remote: "vpn.example.com:1194"} },
	}
	base := Defaults()
	if err := storeEverySecret(base); err != nil {
		t.Fatal(err)
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("the fixture is not valid to begin with: %v", err)
	}

	for i, held := range base.Tunnels {
		for block, add := range blocks {
			if block == held.Type {
				continue
			}
			cfg := base.Clone()
			add(&cfg.Tunnels[i])

			err := cfg.Validate()

			if err == nil {
				t.Errorf("a %s connection carrying a %s block was accepted", held.Type, block)
				continue
			}
			if !strings.Contains(err.Error(), held.Handle()) || !strings.Contains(err.Error(), "tunnels."+string(block)) {
				t.Errorf("error = %v, want the connection %q and its %s block named", err, held.Handle(), block)
			}
		}
	}
}

// Internet traffic pointed at a connection that is not in the document would leave every
// request that no connection carries dialling a connection that does not exist. That fails
// as a timeout against whatever was being reached, with nothing naming the setting that
// caused it, so it is refused at the point it is written.
func TestInternetTrafficCannotBeSentThroughAConnectionThatIsNotThere(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.EgressMode = EgressTunnel
	cfg.Settings.EgressTunnelID = "tn_removed"

	err := cfg.Validate()

	if err == nil {
		t.Fatal("internet traffic was pointed at a connection that does not exist")
	}
	if !strings.Contains(err.Error(), "tn_removed") {
		t.Errorf("error = %v, want the connection named", err)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "egress.tunnelId" {
		t.Errorf("error = %T %v, want it to name egress.tunnelId", err, err)
	}
}

// Choosing a connection and sending traffic through it are two separate acts. A remembered
// choice while the traffic goes out directly carries nothing, so removing the connection
// it names must not make the document unloadable.
func TestARememberedEgressConnectionIsNotCheckedWhileTrafficGoesOutDirectly(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.EgressMode = EgressDirect
	cfg.Settings.EgressTunnelID = "tn_removed"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a remembered choice that carries nothing was refused: %v", err)
	}
}

// The check has to pass a connection that is actually there, or it is a check that refuses
// everything and the setting could never be used.
func TestInternetTrafficGoesThroughAConnectionThatExists(t *testing.T) {
	cfg := Defaults()
	peer := NewTunnel("tn_a1b2c3", "office", "Office", TunnelWireGuard)
	cfg.Tunnels = append(cfg.Tunnels, peer)
	cfg.Settings.EgressMode = EgressTunnel
	cfg.Settings.EgressTunnelID = peer.ID

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a connection in the document was refused: %v", err)
	}
}

// loopbackOnly is registered as a field's validate rule, which the registry runs after
// the kind's own syntax check. Only KindAddrPort uses it today, so the malformed input
// it refuses here cannot reach it through that one field -- but the rule is what would
// be attached to a plain-string address setting, and a rule that assumed its input was
// already well-formed would then admit anything.
func TestLoopbackOnlyRefusesAnythingItCannotProveIsLoopback(t *testing.T) {
	tests := []struct {
		name string
		addr string
		ok   bool
	}{
		{"unset means the default applies", "", true},
		{"ipv4 loopback", "127.0.0.1:8377", true},
		{"ipv6 loopback", "[::1]:8377", true},
		{"any interface", "0.0.0.0:8377", false},
		{"a routable address", "192.168.1.5:8377", false},
		{"not an address at all", "not-an-address", false},
		{"a name rather than a literal", "localhost:8377", false},
		{"a port outside the range", "127.0.0.1:70000", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := loopbackOnly(tc.addr)
			if tc.ok && err != nil {
				t.Fatalf("loopbackOnly(%q) = %v, want it accepted", tc.addr, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("loopbackOnly(%q) accepted an address the dashboard must never bind", tc.addr)
			}
		})
	}
}

// The rule guards a port this process picks for itself, so zero has to stay acceptable:
// it is how a document says "use the default" rather than a request to bind port zero.
func TestAPortBelowTheUnprivilegedRangeIsRefused(t *testing.T) {
	tests := []struct {
		name string
		port int
		ok   bool
	}{
		{"unset means the default applies", 0, true},
		{"a privileged port", 80, false},
		{"the last privileged port", 1023, false},
		{"the first unprivileged port", 1024, true},
		{"an ordinary high port", 14000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := unprivilegedPort(tc.port)
			if tc.ok && err != nil {
				t.Fatalf("unprivilegedPort(%d) = %v, want it accepted", tc.port, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("unprivilegedPort(%d) accepted a port this process cannot bind", tc.port)
			}
		})
	}
}

// The floor is refused at write time rather than clamped, because a user typing five
// seconds has misunderstood what the setting costs and silently storing sixty would
// leave them believing otherwise. Zero still means the default.
func TestARotationIntervalUnderTheFloorIsRefusedAtWriteTime(t *testing.T) {
	tests := []struct {
		name string
		secs int
		ok   bool
	}{
		{"unset means the default applies", 0, true},
		{"a few seconds", 5, false},
		{"one below the floor", MinExitNodeRotateIntervalSec - 1, false},
		{"the floor itself", MinExitNodeRotateIntervalSec, true},
		{"the default", DefaultExitNodeRotateIntervalSec, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rotateIntervalSec(tc.secs)
			if tc.ok && err != nil {
				t.Fatalf("rotateIntervalSec(%d) = %v, want it accepted", tc.secs, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("rotateIntervalSec(%d) accepted an interval that is an outage", tc.secs)
			}
			if !tc.ok && !strings.Contains(err.Error(), "drops the") {
				t.Errorf("refusal is %q, want it to say what the cost of rotating is", err)
			}
		})
	}
}

// A blocklist is rebuilt daily at best, and a refresh interval under the floor is this
// machine asking somebody else's server for the same file over and over.
func TestABlocklistRefreshIntervalUnderTheFloorIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		hours int
		ok    bool
	}{
		{"unset means the default applies", 0, true},
		{"the floor itself", MinDNSBlockRefreshHours, true},
		{"the default", DefaultDNSBlockRefreshHours, true},
		{"an interval below the floor", MinDNSBlockRefreshHours - 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := blockRefreshHours(tc.hours)

			if tc.ok && err != nil {
				t.Fatalf("blockRefreshHours(%d) = %v, want it accepted", tc.hours, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("blockRefreshHours(%d) accepted an interval that hammers the server holding the list", tc.hours)
				}
				if !strings.Contains(err.Error(), fmt.Sprint(MinDNSBlockRefreshHours)) {
					t.Errorf("refusal is %q, want it to say what the floor is", err)
				}
			}
		})
	}
}

// Which lists are on is a list of ids, and a repeat would be counted where lists are
// counted and credit a blocked name to whichever copy sorted first.
func TestASwitchedOnListNamedTwiceOrNamedByNothingIsRefused(t *testing.T) {
	tests := []struct {
		name string
		ids  []string
		says string
	}{
		{"nothing switched on", nil, ""},
		{"two different lists", []string{"hagezi-pro", "stevenblack"}, ""},
		{"an id of nothing at all", []string{"hagezi-pro", "  "}, "no id"},
		{"the same list twice", []string{"hagezi-pro", "hagezi-pro"}, "twice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := blocklistIDs(tc.ids)

			if tc.says == "" {
				if err != nil {
					t.Fatalf("blocklistIDs(%v) = %v, want it accepted", tc.ids, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("blocklistIDs(%v) was accepted", tc.ids)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal is %q, want it to say %q", err, tc.says)
			}
		})
	}
}

// One list holds domains, single addresses and whole networks, so the form is read from
// the text rather than declared. What must not happen is a near-miss being taken for the
// form it is nearest to: "10.0.0.0/33" written as a network has to be refused as one
// rather than accepted as a domain nothing will ever match.
func TestAnEntryThatIsNeitherANameNorAnAddressIsRefused(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		says    string
	}{
		{"nothing entered", nil, ""},
		{"a domain", []string{"bad.example"}, ""},
		{"a network", []string{"10.0.0.0/8"}, ""},
		{"a single address", []string{"198.51.100.9"}, ""},
		{"an address with room around it", []string{"  198.51.100.9  "}, ""},
		{"an entry of nothing at all", []string{"bad.example", "   "}, "neither"},
		{"a network with an impossible size", []string{"10.0.0.0/33"}, "looks like a network"},
		{"a path rather than a name", []string{"http://example.com/path"}, "looks like a network"},
		{"a name nothing could resolve", []string{"not a domain"}, "cannot appear in a name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := namesOrPrefixes(tc.entries)

			if tc.says == "" {
				if err != nil {
					t.Fatalf("namesOrPrefixes(%v) = %v, want it accepted", tc.entries, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("namesOrPrefixes(%v) was accepted", tc.entries)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal is %q, want it to say %q", err, tc.says)
			}
		})
	}
}

// A signature is refused where it is written rather than where it is matched: the matcher is
// built inside the agent, and an entry that only fails there is a control the user believes is
// switched on and is not.
func TestAWrittenSignatureIsRefusedWhereItIsTyped(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		says    string
	}{
		{"nothing entered", nil, ""},
		{"a named pattern", []string{`a token = "hunter2-9f3a1c"`}, ""},
		{"rows left empty between entries", []string{"", `a token = "hunter2-9f3a1c"`, "  "}, ""},
		{"escapes for the bytes that are not text", []string{`a marker = "MARK\x00\xff"`}, ""},
		{"nothing but a name", []string{"a token"}, "not a signature"},
		{"bytes that are not quoted", []string{`a token = hunter2`}, "not a quoted string"},
		{"too few bytes to mean anything", []string{`a token = "ab"`}, "or more are needed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := signaturePatterns(tc.entries)

			if tc.says == "" {
				if err != nil {
					t.Fatalf("signaturePatterns(%v) = %v, want it accepted", tc.entries, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("signaturePatterns(%v) was accepted", tc.entries)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal is %q, want it to say %q", err, tc.says)
			}
		})
	}
}

// More patterns than one matcher holds has to be refused here too, because the entries are
// counted after the empty rows are dropped and the matcher counts them the same way.
func TestMorePatternsThanTheMatcherHoldsIsRefusedWhereTheyAreTyped(t *testing.T) {
	entries := make([]string, 0, sigscan.MaxPatterns+1)
	for i := 0; i <= sigscan.MaxPatterns; i++ {
		entries = append(entries, fmt.Sprintf("pattern %d = %q", i, fmt.Sprintf("mark-%06d", i)))
	}

	if err := signaturePatterns(entries[:sigscan.MaxPatterns]); err != nil {
		t.Fatalf("%d patterns were refused: %v", sigscan.MaxPatterns, err)
	}
	err := signaturePatterns(entries)
	if err == nil {
		t.Fatalf("%d patterns were accepted, where %d is the most", len(entries), sigscan.MaxPatterns)
	}
	if !strings.Contains(err.Error(), "matched at once") {
		t.Errorf("refusal is %q, want it to say how many are matched at once", err)
	}
}

// The interface mode installs a privileged helper and creates an interface, and the
// operating system asks for administrator credentials before either happens. Storing the
// mode is therefore a request rather than the change itself, and validation has no
// precondition of its own to enforce beyond the module switch that reveals the setting.
func TestTheInterfaceModeIsStoredOnItsOwn(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		mode    NetworkMode
	}{
		{name: "the mode this app installs as", mode: NetworkUserspace},
		{name: "the module on, still contained", enabled: true, mode: NetworkUserspace},
		{name: "the interface mode", enabled: true, mode: NetworkTUN},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			settings := Defaults().Settings
			settings.InterfaceEnabled = tc.enabled
			settings.InterfaceMode = tc.mode

			if err := settings.Validate(); err != nil {
				t.Fatalf("enabled=%t mode=%q was refused: %v", tc.enabled, tc.mode, err)
			}
		})
	}
}

// The interface name reaches the operating system, which on Linux truncates anything over
// 15 characters and on every platform rejects punctuation. Both failures would otherwise
// land during startup, after the working userspace node has been torn down to make way for
// an interface that cannot be created.
func TestAnInterfaceNameTheSystemWouldRejectIsRefusedBeforeItIsStored(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"unset lets the platform choose", "", ""},
		{"an ordinary name", "app-tail", ""},
		{"underscores and digits", "app_tail0", ""},
		{"the longest the shortest platform takes", strings.Repeat("a", interfaceNameMax), ""},
		{"one character too long", strings.Repeat("a", interfaceNameMax+1), "at most"},
		{"a space", "app tail", "letters, digits"},
		{"a path separator", "app/tail", "letters, digits"},
		{"a null byte", "app\x00tail", "letters, digits"},
		{"a character outside ASCII", "app-täil", "letters, digits"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkInterfaceName(tc.value)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkInterfaceName(%q) = %v, want it accepted", tc.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkInterfaceName(%q) accepted a name the system would not", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal is %q, want it to explain %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "interface.name") {
				t.Errorf("refusal is %q, want it to name the setting", err)
			}
		})
	}
}

// The name check has to be reached from Validate rather than only from the helper that
// performs it: a check nothing calls refuses nothing, and the name would reach the OS
// unexamined at the one moment it cannot be taken back.
func TestAnInterfaceNameIsCheckedOnTheWayIntoTheStoredSettings(t *testing.T) {
	settings := Defaults().Settings
	settings.InterfaceEnabled = true
	settings.InterfaceMode = NetworkTUN
	settings.InterfaceName = "app/tail"

	err := settings.Validate()
	if err == nil {
		t.Fatal("a name carrying a path separator was stored")
	}
	if !strings.Contains(err.Error(), "interface.name") {
		t.Errorf("refusal is %q, want it to name the setting that was refused", err)
	}
}

// The list is what a person typed into a form, so the blank left by a trailing comma and
// a port named twice are both ordinary rather than mistakes. Anything that is not a port
// is a mistake, and the refusal quotes it back so the offending entry is identifiable.
func TestAPortListDropsBlanksAndRepeatsButRefusesNonPorts(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []int
	}{
		{name: "nothing at all", in: nil, want: []int{}},
		{name: "one port", in: []string{"22"}, want: []int{22}},
		{name: "surrounding space is not part of the number", in: []string{" 22 "}, want: []int{22}},
		{name: "a trailing comma leaves a blank", in: []string{"22", "", "  "}, want: []int{22}},
		{name: "a repeat is kept once, in the order first written", in: []string{"80", "22", "80"}, want: []int{80, 22}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePortList(tc.in)
			if err != nil {
				t.Fatalf("ParsePortList(%q) = %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePortList(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePortList(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}

	for _, bad := range []string{"0", "65536", "-1", "http", "22/tcp"} {
		if _, err := ParsePortList([]string{bad}); err == nil {
			t.Errorf("ParsePortList(%q) was accepted as a port list", bad)
		} else if !strings.Contains(err.Error(), bad) {
			t.Errorf("refusal for %q is %q, want it to quote the entry back", bad, err)
		}
	}
}

// Every rule about what this device may offer to carry is a route that would break
// something rather than a matter of taste, so each is refused at the write with the
// reason on screen. A route accepted here reaches the admin console, where an approval
// makes peers send real traffic at it.
func TestARouteThisDeviceMustNotOfferToCarryIsRefused(t *testing.T) {
	tests := []struct {
		name    string
		routes  string
		wantErr string
	}{
		{"a private network", "10.0.0.0/24", ""},
		{"several of them", "10.0.0.0/24, 192.168.4.0/22, 172.16.0.0/16", ""},
		{"one IPv6 network", "2001:db8:1::/64", ""},
		{"a single host", "192.168.1.7/32", ""},
		{"host bits set", "10.0.0.1/24", "non-address bits set; expected 10.0.0.0/24"},
		{"everything, v4", "0.0.0.0/0", AdvertiseExitNodeLabel},
		{"everything, v6", "::/0", AdvertiseExitNodeLabel},
		{"the tailnet's own range", "100.64.0.0/10", "tailnet's own addresses"},
		{"a slice of the tailnet's range", "100.100.0.0/16", "tailnet's own addresses"},
		{"the tailnet's IPv6 range", "fd7a:115c:a1e0::/48", "tailnet's own addresses"},
		{"this machine's loopback", "127.0.0.0/8", "loopback"},
		{"link-local", "169.254.0.0/16", "link-local"},
		{"IPv6 link-local", "fe80::/10", "link-local"},
		{"multicast", "224.0.0.0/4", "multicast"},
		{"a network hanging off the unspecified address", "0.0.0.0/8", "not a network this device can carry"},
		{"its IPv6 form", "::/64", "not a network this device can carry"},
		{"two entries covering the same addresses", "10.0.0.0/8, 10.1.2.0/24", "cover the same addresses"},
		{"the same network twice", "10.0.0.0/24, 10.0.0.0/24", "cover the same addresses"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := tailnetRedirect.field("routes-advertise")
			if !ok {
				t.Fatal("the advertised-routes setting is not reachable by its CLI name")
			}
			got, err := f.ParseCLIValue(tc.routes)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("%q was refused: %v", tc.routes, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%q was accepted as a network this device can carry, and reads back as %v",
					tc.routes, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("refusing %q reads %q, want it to say %q", tc.routes, err, tc.wantErr)
			}
		})
	}
}

// A route list arrives as text from a person, so the space after a comma and the blank a
// trailing one leaves are ordinary. Anything that is not a network is a mistake, and
// dropping it silently would advertise less than the user asked for with nothing saying so.
func TestARouteListIsReadFromWhatAPersonWouldType(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "nothing at all", in: "", want: nil},
		{name: "one network", in: "10.0.0.0/24", want: []string{"10.0.0.0/24"}},
		{name: "comma separated", in: "10.0.0.0/24,192.168.1.0/24", want: []string{"10.0.0.0/24", "192.168.1.0/24"}},
		{name: "with the spaces a person types", in: " 10.0.0.0/24 , 192.168.1.0/24 ", want: []string{"10.0.0.0/24", "192.168.1.0/24"}},
		{name: "space separated", in: "10.0.0.0/24 192.168.1.0/24", want: []string{"10.0.0.0/24", "192.168.1.0/24"}},
		{name: "a trailing comma leaves a blank", in: "10.0.0.0/24,", want: []string{"10.0.0.0/24"}},
	}
	f, ok := tailnetRedirect.field("routes-advertise")
	if !ok {
		t.Fatal("the advertised-routes setting is not reachable by its CLI name")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := f.ParseCLIValue(tc.in)
			if err != nil {
				t.Fatalf("ParseCLIValue(%q) = %v", tc.in, err)
			}
			var got []string
			for _, p := range v.([]netip.Prefix) {
				got = append(got, p.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ParseCLIValue(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	for _, bad := range []string{"10.0.0.0", "10.0.0.0/33", "not-a-network", "10.0.0.0/24;192.168.1.0/24"} {
		if _, err := f.ParseCLIValue(bad); err == nil {
			t.Errorf("ParseCLIValue(%q) was accepted as a list of networks", bad)
		} else if !strings.Contains(err.Error(), "CIDR") {
			t.Errorf("refusing %q reads %q, want it to say what the form is", bad, err)
		}
	}
}

// The advertised set is the module's answer, not the stored list: a module switched off
// must advertise nothing, and two lists holding the same networks in a different order
// are the same advertisement rather than a change to push at the tailnet.
func TestTheAdvertisedNetworksAreTheModulesAnswerInAStableOrder(t *testing.T) {
	stored := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}

	held := tailnetWith(TailnetPrefs{RoutesAdvertise: stored})

	off := Settings{}
	if got := off.TailnetPrefsOf(held).AdvertisedSubnets(); got != nil {
		t.Errorf("a switched-off routing module still advertises %v", got)
	}

	on := Settings{RoutesEnabled: true}
	want := []string{"10.0.0.0/24", "192.168.1.0/24"}
	var got []string
	for _, p := range on.TailnetPrefsOf(held).AdvertisedSubnets() {
		got = append(got, p.String())
	}
	if !slices.Equal(got, want) {
		t.Errorf("advertised networks = %v, want %v in a stable order", got, want)
	}
	if stored[0].String() != "192.168.1.0/24" {
		t.Error("sorting the advertised networks reordered the stored setting itself")
	}

	// An empty list that is not nil is what removing the last network in the form leaves
	// behind. It has to read as nothing at all, because that is what a comparison against
	// the node's own preferences is made against.
	empty := tailnetWith(TailnetPrefs{RoutesAdvertise: []netip.Prefix{}})
	if got := on.TailnetPrefsOf(empty).AdvertisedSubnets(); got != nil {
		t.Errorf("advertising an emptied list reads as %#v, want nothing at all", got)
	}
}

// Carrying traffic is the module's answer for the same reason advertising is: the stored
// bool outlives the module being switched off, and a router still carrying connections
// for a module the user turned off is the failure this guards.
func TestWhetherThisDeviceCarriesTheTrafficIsTheModulesAnswer(t *testing.T) {
	tests := []struct {
		name  string
		app   Settings
		serve bool
		want  bool
	}{
		{name: "module off, serving stored on", serve: true},
		{name: "module on, serving off", app: Settings{RoutesEnabled: true}},
		{name: "both on", app: Settings{RoutesEnabled: true}, serve: true, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.app.TailnetPrefsOf(tailnetWith(TailnetPrefs{RoutesServe: tc.serve}))
			if got.RoutesServe != tc.want {
				t.Errorf("RoutesServe = %v, want %v", got.RoutesServe, tc.want)
			}
		})
	}
}

// A blank entry is what a trailing comma or an empty box in a list control leaves behind,
// and it names no network to drop. Anything that is not blank and not a network is a typo
// the user must see, because silently skipping it advertises less than they asked for.
func TestABlankEntryInARouteListIsSkippedButATypoIsNot(t *testing.T) {
	got, err := ParsePrefixList([]string{"10.0.0.0/24", "", "   ", " 192.168.1.0/24 "})
	if err != nil {
		t.Fatalf("a list carrying blank entries was refused: %v", err)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.String())
	}
	if want := []string{"10.0.0.0/24", "192.168.1.0/24"}; !slices.Equal(names, want) {
		t.Errorf("read %v from a list with blanks in it, want %v", names, want)
	}

	if _, err := ParsePrefixList([]string{"10.0.0.0/24", "not-a-network"}); err == nil {
		t.Error("a typo in a route list was skipped like a blank instead of being reported")
	} else if !strings.Contains(err.Error(), "not-a-network") {
		t.Errorf("refusing a typo reads %q, want it to name the entry", err)
	}
}

// The two lookups answer the same registry from the two names a field carries. A front
// end holding a key from a schema it was handed has only that key to find out how the
// setting is written, so a miss there means the write is refused as unknown.
func TestAFieldIsReachableByBothTheNamesItCarries(t *testing.T) {
	f, ok := FieldByJSONKey("exitNode.enabled")
	if !ok {
		t.Fatal("exitNode.enabled is not reachable by the key the wire uses")
	}
	if f.CLIName == "" {
		t.Fatal("the field found by JSON key carries no CLI name")
	}
	byCLI, ok := FieldByCLIName(f.CLIName)
	if !ok {
		t.Fatalf("%s is not reachable by its own CLI name %q", f.JSONKey, f.CLIName)
	}
	if byCLI.JSONKey != f.JSONKey {
		t.Errorf("the two names reach different fields: %q and %q", f.JSONKey, byCLI.JSONKey)
	}
	if _, ok := FieldByJSONKey("nothing.declares.this"); ok {
		t.Error("a key no field declares was reported as a known setting")
	}
}

// A forward bound to anything but loopback answers every machine that can reach this one,
// with no authentication in front of it. That has to be something the user asked for in
// so many words, not a side effect of typing an address.
func TestANetworkFacingForwardBindIsRefusedUnlessItIsExposedOnPurpose(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "192.168.1.20", "fe80::1"} {
		f := validForward()
		f.BindAddr = bind
		err := ValidateForward(f)
		if err == nil {
			t.Errorf("bind %s was accepted without exposeToNetwork", bind)
			continue
		}
		if !strings.Contains(err.Error(), "exposeToNetwork") {
			t.Errorf("bind %s: error = %v, want it to name the setting that allows it", bind, err)
		}
		f.ExposeToNetwork = true
		if err := ValidateForward(f); err != nil {
			t.Errorf("bind %s with exposeToNetwork was refused: %v", bind, err)
		}
	}
	for _, bind := range []string{"127.0.0.1", "127.0.0.2", "::1", ""} {
		f := validForward()
		f.BindAddr = bind
		if err := ValidateForward(f); err != nil {
			t.Errorf("loopback bind %q was refused: %v", bind, err)
		}
	}
	// A to_tailnet forward binds the node's own tailnet address whatever bindAddr says,
	// so the flag has nothing to guard there.
	f := validForward()
	f.Direction = ToTailnet
	f.BindAddr = "0.0.0.0"
	if err := ValidateForward(f); err != nil {
		t.Errorf("to_tailnet forward refused over a bindAddr it never uses: %v", err)
	}
}
