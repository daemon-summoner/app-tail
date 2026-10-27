// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"
)

// recordingHost stands in for the privileged side. Substituting it is not mocking this
// app's own code: the real one is a separate process holding root, reached over a socket,
// and Host is the wire between them. What is exercised here is everything on this side of
// that wire -- which is the side that runs unprivileged, and therefore the side a test can
// reach at all.
type recordingHost struct {
	upCalls        int
	routeCalls     []*router.Config
	hostRouteCalls []Routes
	dnsCalls       []dns.OSConfig
	baseCalls      int
	splitCalls     int
	scopeCalls     int
	unscopeCalls   int

	split    bool
	splitErr error
	upErr    error
	routeErr error
	dnsErr   error
	base     dns.OSConfig
	baseErr  error
	scopeErr error

	// deadlines records whether each call arrived with a deadline, which is what stops a
	// wedged helper from wedging the engine's reconfiguration lock with it.
	deadlines []bool
}

var _ Host = (*recordingHost)(nil)

func (h *recordingHost) note(ctx context.Context) {
	_, ok := ctx.Deadline()
	h.deadlines = append(h.deadlines, ok)
}

func (h *recordingHost) Capabilities(ctx context.Context) (Capabilities, error) {
	h.note(ctx)
	return Capabilities{Version: Version}, nil
}

func (h *recordingHost) OpenTUN(ctx context.Context, _ string) (tun.Device, string, error) {
	h.note(ctx)
	return nil, "", errors.New("this host opens no interface")
}

func (h *recordingHost) RouterUp(ctx context.Context) error {
	h.note(ctx)
	h.upCalls++
	return h.upErr
}

func (h *recordingHost) SetRoutes(ctx context.Context, cfg *router.Config) error {
	h.note(ctx)
	h.routeCalls = append(h.routeCalls, cfg)
	return h.routeErr
}

func (h *recordingHost) SetHostRoutes(ctx context.Context, r Routes) error {
	h.note(ctx)
	h.hostRouteCalls = append(h.hostRouteCalls, r)
	return h.routeErr
}

func (h *recordingHost) ScopeHostDefault(ctx context.Context) error {
	h.note(ctx)
	h.scopeCalls++
	return h.scopeErr
}

func (h *recordingHost) UnscopeHostDefault(ctx context.Context) error {
	h.note(ctx)
	h.unscopeCalls++
	return h.scopeErr
}

func (h *recordingHost) SetDNS(ctx context.Context, cfg dns.OSConfig) error {
	h.note(ctx)
	h.dnsCalls = append(h.dnsCalls, cfg)
	return h.dnsErr
}

func (h *recordingHost) BaseDNS(ctx context.Context) (dns.OSConfig, error) {
	h.note(ctx)
	h.baseCalls++
	return h.base, h.baseErr
}

func (h *recordingHost) SplitDNS(ctx context.Context) (bool, error) {
	h.note(ctx)
	h.splitCalls++
	return h.split, h.splitErr
}

func (h *recordingHost) Close() error { return nil }

// The engine reconfigures the machine through router.Router and dns.OSConfigurator and
// nothing else, so every call on those two has to arrive at the privileged side. A method
// that quietly did nothing would leave the node reporting Running with no routes on the
// machine, which is the exact failure the whole interface mode exists to avoid.
func TestEveryEngineCallReachesThePrivilegedSide(t *testing.T) {
	host := &recordingHost{split: true}
	rtr, osCfg, err := Engine(context.Background(), host)
	if err != nil {
		t.Fatalf("Engine: %v", err)
	}

	if err := rtr.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if host.upCalls != 1 {
		t.Errorf("Up reached the privileged side %d times, want 1", host.upCalls)
	}

	cfg := &router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	if err := rtr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(host.routeCalls) != 1 || host.routeCalls[0] != cfg {
		t.Errorf("Set delivered %v, want the caller's own config %v", host.routeCalls, cfg)
	}

	want := dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("100.100.100.100")}}
	if err := osCfg.SetDNS(want); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if len(host.dnsCalls) != 1 || !host.dnsCalls[0].Equal(want) {
		t.Errorf("SetDNS delivered %v, want %v", host.dnsCalls, want)
	}

	if _, err := osCfg.GetBaseConfig(); err != nil {
		t.Fatalf("GetBaseConfig: %v", err)
	}
	if host.baseCalls != 1 {
		t.Errorf("GetBaseConfig reached the privileged side %d times, want 1", host.baseCalls)
	}
}

// A nil config is how the engine says "remove everything" on the way down. Turning it into
// an empty config instead would leave the addresses and routes on the machine, which is
// the leftover state the doctor exists to report.
func TestRemovingEveryRouteTravelsAsNil(t *testing.T) {
	host := &recordingHost{}
	rtr, _, err := Engine(context.Background(), host)
	if err != nil {
		t.Fatalf("Engine: %v", err)
	}
	if err := rtr.Set(nil); err != nil {
		t.Fatalf("Set(nil): %v", err)
	}
	if len(host.routeCalls) != 1 {
		t.Fatalf("Set(nil) made %d calls, want 1", len(host.routeCalls))
	}
	if host.routeCalls[0] != nil {
		t.Errorf("Set(nil) delivered %v, want nil so the privileged side removes everything", host.routeCalls[0])
	}
}

// The engine holds the lock the whole node depends on while it reconfigures, and the peer
// is another process that can be stopped or wedged. Every call therefore carries a
// deadline; one that did not would turn a stopped helper into a node that never reports
// anything again.
func TestEveryPrivilegedCallCarriesADeadline(t *testing.T) {
	host := &recordingHost{}
	rtr, osCfg, err := Engine(context.Background(), host)
	if err != nil {
		t.Fatalf("Engine: %v", err)
	}
	// The construction-time SplitDNS read is the caller's context, not one of these.
	host.deadlines = nil

	if err := rtr.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := rtr.Set(nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := osCfg.SetDNS(dns.OSConfig{}); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if _, err := osCfg.GetBaseConfig(); err != nil {
		t.Fatalf("GetBaseConfig: %v", err)
	}

	if len(host.deadlines) != 4 {
		t.Fatalf("recorded %d calls, want 4", len(host.deadlines))
	}
	for i, ok := range host.deadlines {
		if !ok {
			t.Errorf("call %d reached the privileged side with no deadline, so a wedged helper would wedge the engine with it", i)
		}
	}
}

// The split-DNS answer is a fixed property of the configurator on the other side, read
// once so the engine is not making a round trip from inside its reconfiguration lock.
func TestTheSplitDNSAnswerIsReadOnceAndRemembered(t *testing.T) {
	for _, want := range []bool{true, false} {
		host := &recordingHost{split: want}
		_, osCfg, err := Engine(context.Background(), host)
		if err != nil {
			t.Fatalf("Engine: %v", err)
		}
		if got := osCfg.SupportsSplitDNS(); got != want {
			t.Errorf("SupportsSplitDNS() = %v, want the privileged side's answer %v", got, want)
		}
		// Asked again, because the engine asks on every reconfiguration.
		osCfg.SupportsSplitDNS()
		osCfg.SupportsSplitDNS()
		if host.splitCalls != 1 {
			t.Errorf("the privileged side was asked %d times, want once at construction", host.splitCalls)
		}
	}
}

// A privileged side that cannot answer what it supports is one the engine must not be
// built on: a wrong split-DNS answer silently drops the split, and the machine resolves
// tailnet names while every other domain quietly stops working.
func TestEngineRefusesAPrivilegedSideThatCannotAnswer(t *testing.T) {
	host := &recordingHost{splitErr: errors.New("the socket went away")}
	rtr, osCfg, err := Engine(context.Background(), host)
	if err == nil {
		t.Fatal("Engine accepted a privileged side that could not say what it supports")
	}
	if rtr != nil || osCfg != nil {
		t.Error("Engine returned interfaces alongside its failure, which a caller could use")
	}
	if !strings.Contains(err.Error(), "the socket went away") {
		t.Errorf("Engine said %q, which loses the reason it was given", err)
	}
}

// A failure from the privileged side is the engine's failure. Swallowing one would leave
// the node believing it had installed routes it does not have.
func TestAPrivilegedFailureReachesTheEngine(t *testing.T) {
	boom := errors.New("the routing table refused this")
	host := &recordingHost{upErr: boom, routeErr: boom, dnsErr: boom, baseErr: boom}
	rtr, osCfg, err := Engine(context.Background(), host)
	if err != nil {
		t.Fatalf("Engine: %v", err)
	}

	if err := rtr.Up(); !errors.Is(err, boom) {
		t.Errorf("Up() = %v, want the privileged side's own failure", err)
	}
	if err := rtr.Set(nil); !errors.Is(err, boom) {
		t.Errorf("Set() = %v, want the privileged side's own failure", err)
	}
	if err := osCfg.SetDNS(dns.OSConfig{}); !errors.Is(err, boom) {
		t.Errorf("SetDNS() = %v, want the privileged side's own failure", err)
	}
	if _, err := osCfg.GetBaseConfig(); !errors.Is(err, boom) {
		t.Errorf("GetBaseConfig() = %v, want the privileged side's own failure", err)
	}
}

// Both proxies' Close must do nothing. The privileged side owns the teardown and runs it
// when this process's connection drops -- which is the only path that runs when the agent
// is killed. A second teardown from here would race the one that always happens, and the
// engine calls Close on its way down every time.
func TestNeitherProxyTearsDownFromThisSide(t *testing.T) {
	host := &recordingHost{}
	rtr, osCfg, err := Engine(context.Background(), host)
	if err != nil {
		t.Fatalf("Engine: %v", err)
	}
	if err := rtr.Close(); err != nil {
		t.Fatalf("router Close: %v", err)
	}
	if err := osCfg.Close(); err != nil {
		t.Fatalf("dns Close: %v", err)
	}
	if len(host.routeCalls) != 0 || len(host.dnsCalls) != 0 {
		t.Errorf("closing the proxies sent %d route and %d resolver calls, want none: the privileged side tears itself down",
			len(host.routeCalls), len(host.dnsCalls))
	}
}
