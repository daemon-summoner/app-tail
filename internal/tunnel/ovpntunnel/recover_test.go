// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// miscopiedFixture is a connection configured the way a provider's file is most often copied
// wrong: the key filed under tls-crypt when the server signs a tls-auth control channel, no
// digest, and a port that carries a name server rather than an OpenVPN server.
func miscopiedFixture() config.OpenVPNTunnel {
	held := heldFixture()
	held.Remote = "vpn.example.com:53"
	held.TLSCrypt = "-----BEGIN OpenVPN Static key V1-----\ndeadbeef\n-----END OpenVPN Static key V1-----\n"
	return held
}

// answering builds a fake openvpn that reads the three subscriptions, hands the connection the
// text decide returns for the settings it was started with, and then holds the socket open the
// way openvpn does.
func answering(runner *fakeOpenVPN, decide func(run hostnet.OpenVPNRun) string) func(*testing.T, net.Conn) {
	return func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		for range 3 {
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
		}
		runs := runner.runs()
		if _, err := io.WriteString(conn, decide(runs[len(runs)-1])); err != nil {
			return
		}
		_, _ = io.ReadAll(conn)
	}
}

const connectedLine = ">STATE:1699999999,CONNECTED,SUCCESS,10.8.0.6,203.0.113.9,1194,192.168.1.20,54321,\n"

// The failure this whole mechanism exists for. A port that carries a name server answers
// openvpn with something openvpn reads as another client, and no key and no digest changes
// that -- so the connection moves to the next address rather than working through the keys it
// could have tried at a dead one, comes up there, and says so.
func TestAnAddressThatIsNotAnOpenVPNServerIsAbandonedForTheNextOne(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(run hostnet.OpenVPNRun) string {
		if run.Remote == "vpn.example.com:53" {
			return ">LOG:1699999999,N,TLS Error: client->client or server->server connection " +
				"attempted from [AF_INET]203.0.113.9:53\n"
		}
		return connectedLine
	})

	held := miscopiedFixture()
	live := newTunnel(t, held, CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateConnected)

	runs := runner.runs()
	if runs[0].Remote != "vpn.example.com:53" {
		t.Errorf("the first attempt dialled %q, want the address as it is stored", runs[0].Remote)
	}
	// Every attempt at the dead address shares its endpoint, so the second attempt has to be at
	// a different one rather than the same address with the key read another way.
	if len(runs) != 2 {
		t.Fatalf("the connection made %d attempts, want the stored one and the next address", len(runs))
	}
	if runs[1].Remote == "vpn.example.com:53" {
		t.Errorf("the second attempt dialled %q again, and no key makes a name server answer OpenVPN", runs[1].Remote)
	}

	limits := strings.Join(status.Limits, "\n")
	if !strings.Contains(limits, "did not reach") || !strings.Contains(limits, runs[1].Remote) {
		t.Errorf("the connection does not report the change that reached the server:\n%s", limits)
	}
	if !strings.Contains(limits, "Nothing stored here was changed") {
		t.Errorf("the connection does not say the stored settings were left alone:\n%s", limits)
	}
}

// Nothing the search does is written back. The settings a connection holds after it recovers
// are the ones that were entered, wrong port and all -- the change is reported so a person can
// make it, and never made for them.
func TestRecoveringChangesNothingThatIsStored(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(run hostnet.OpenVPNRun) string {
		if run.TLSCrypt != "" {
			return ">LOG:1699999999,N,TLS Error: TLS key negotiation failed to occur within 60 seconds\n"
		}
		return connectedLine
	})

	held := miscopiedFixture()
	held.Remote = "vpn.example.com:1194"
	live := newTunnel(t, held, CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateConnected)

	run := runner.runs()[len(runner.runs())-1]
	if run.TLSAuth != held.TLSCrypt || run.KeyDirection != config.OpenVPNKeyDirectionClient {
		t.Errorf("the attempt that connected reads the key as %+v, want it read as a tls-auth key", run)
	}
	if live.held.TLSCrypt != held.TLSCrypt || live.held.TLSAuth != "" || live.held.KeyDirection != "" {
		t.Errorf("the stored settings were rewritten: %+v", live.held)
	}
	if !strings.Contains(strings.Join(status.Limits, "\n"), "tls-auth") {
		t.Errorf("the connection does not report which change reached the server:\n%s", status.Limits)
	}
}

// What a search puts on screen is the search, not the failures inside it. A reason the next
// attempt is about to answer, shown on its own, reads as a connection that has failed -- and
// somebody watching acts on that seconds before it corrects itself.
func TestASearchInProgressReportsWhatItIsTryingRatherThanTheFailure(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(run hostnet.OpenVPNRun) string {
		if run.Remote == "vpn.example.com:53" {
			return ">LOG:1699999999,N,TLS Error: client->client or server->server connection attempted\n"
		}
		// Silence, which is what a server that is not there gives: the attempt is left to its
		// own window rather than moved on at once, so the text it reports stays put.
		return ""
	})

	live := newTunnel(t, miscopiedFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	// Every state the connection went through on the way, not only the one it settled on: a
	// reason that flashes past for a moment is exactly what a dashboard would draw.
	status, seen := waitForDetail(t, live, "trying ")
	if status.State != tunnel.StateConnecting {
		t.Errorf("a connection in the middle of a search reports %q, want it still trying", status.State)
	}
	for _, detail := range seen {
		if strings.Contains(detail, "client->client") {
			t.Errorf("the connection reported %q, want what it is trying rather than the failure it moved past", detail)
		}
	}
	if !strings.Contains(status.Detail, " of ") {
		t.Errorf("the connection reports %q, want how far through the search it is", status.Detail)
	}
}

// A server that was reached and said no ends the search there. Trying other ports for a refused
// account would leave the account still refused and bury the reason under addressing advice.
func TestAServerThatRefusesTheAccountIsNotSearchedPast(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">STATE:1699999999,AUTH,,,,,,\n" +
			">LOG:1699999999,N,AUTH_FAILED\n"
	})

	live := newTunnel(t, miscopiedFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	waitForDetail(t, live, "AUTH_FAILED")
	if runs := runner.runs(); len(runs) != 1 {
		t.Errorf("the connection made %d attempts against a server that answered, want the one", len(runs))
	}
}

// When no way of reaching the server works, the connection says so with the reason and how many
// ways were tried, rather than reporting "connecting" for as long as anybody watches it.
func TestAServerNoAttemptReachesIsReportedAsFailed(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">LOG:1699999999,N,TLS Error: client->client or server->server connection attempted\n"
	})

	live := newTunnel(t, miscopiedFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateFailed)
	if !strings.Contains(status.Detail, "client->client") {
		t.Errorf("the connection failed with %q, want the reason openvpn gave", status.Detail)
	}
	if !strings.Contains(status.Detail, "none of them answered") {
		t.Errorf("the connection failed with %q, want what it tried", status.Detail)
	}
	// One address condemned per failure: the three addresses, not the twelve attempts.
	if runs := runner.runs(); len(runs) != 3 {
		t.Errorf("the connection made %d attempts, want one per address", len(runs))
	}
}

// A connection with nothing to vary is left retrying rather than restarted or failed: openvpn
// goes on trying, and a server that is merely down comes back on its own.
func TestAConnectionWithNothingToTryKeepsRetryingWithTheReason(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">LOG:1699999999,N,Connection refused (errno=61)\n"
	})

	held := heldFixture()
	held.Remote = "vpn.example.com"
	held.Routes = []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")}
	live := newTunnel(t, held, CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	waitForDetail(t, live, "Connection refused")
	if got := live.Status().State; got != tunnel.StateConnecting {
		t.Errorf("the connection reports %q, want it still trying", got)
	}
	if runs := runner.runs(); len(runs) != 1 {
		t.Errorf("the connection made %d attempts, want the one there was to make", len(runs))
	}
}

// waitForDetail blocks until the connection reports a detail containing want, and returns every
// detail it reported on the way there.
func waitForDetail(t *testing.T, live *Tunnel, want string) (tunnel.Status, []string) {
	t.Helper()
	deadline := time.After(stateDeadline)
	var seen []string
	for {
		got := live.Status()
		if len(seen) == 0 || seen[len(seen)-1] != got.Detail {
			seen = append(seen, got.Detail)
		}
		if strings.Contains(got.Detail, want) {
			return got, seen
		}
		select {
		case <-live.Events():
		case <-deadline:
			t.Fatalf("the connection reported %q, want a detail containing %q", live.Status().Detail, want)
		}
	}
}

// Switching which connection carries this machine's internet traffic restarts both of them, so
// a connection that had to search for its server would search again on every switch. What
// reached the server is remembered for the life of the process and tried first.
func TestWhatReachedTheServerIsTriedFirstTheNextTimeTheConnectionStarts(t *testing.T) {
	remembered := NewReached()
	answer := func(runner *fakeOpenVPN) func(*testing.T, net.Conn) {
		return answering(runner, func(run hostnet.OpenVPNRun) string {
			if run.Remote == "vpn.example.com:53" {
				return ">LOG:1699999999,N,TLS Error: client->client or server->server connection attempted\n"
			}
			return connectedLine
		})
	}

	first := &fakeOpenVPN{dir: socketDir(t)}
	first.speak = answer(first)
	live := New(Options{
		ID: "tn_test01", Held: miscopiedFixture(), Logger: slog.New(slog.DiscardHandler),
		Runner: first, Reached: remembered,
	}).(*Tunnel)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	waitForState(t, live, tunnel.StateConnected)
	worked := first.runs()[len(first.runs())-1]
	if err := live.Close(); err != nil {
		t.Fatalf("close the connection: %v", err)
	}

	second := &fakeOpenVPN{dir: socketDir(t)}
	second.speak = answer(second)
	again := New(Options{
		ID: "tn_test01", Held: miscopiedFixture(), Logger: slog.New(slog.DiscardHandler),
		Runner: second, Reached: remembered,
	}).(*Tunnel)
	if err := again.Start(context.Background()); err != nil {
		t.Fatalf("start the connection again: %v", err)
	}
	t.Cleanup(func() {
		if err := again.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})
	waitForState(t, again, tunnel.StateConnected)

	runs := second.runs()
	if len(runs) != 1 {
		t.Fatalf("the connection made %d attempts the second time, want the one that worked before", len(runs))
	}
	if runs[0].Remote != worked.Remote || runs[0].Proto != worked.Proto || runs[0].TLSAuth != worked.TLSAuth {
		t.Errorf("the connection started with %+v, want what reached the server last time: %+v", runs[0], worked)
	}
	// Remembering is not storing: the settings are still exactly what was entered.
	if again.held.Remote != "vpn.example.com:53" || again.held.TLSCrypt == "" {
		t.Errorf("the stored settings were rewritten: %+v", again.held)
	}
}

// A remembered change that no longer names any attempt -- the settings were edited since --
// leaves the connection starting from its settings rather than from something derived out of
// what they used to say.
func TestAMemoryThatNoLongerFitsTheSettingsIsIgnored(t *testing.T) {
	attempts := attemptsFor(Run{Remote: "vpn.example.com:1194", Proto: config.OpenVPNProtoUDP, TLSCrypt: "key"}, false)
	if got := preferring(attempts, "its server reached on the moon"); !got[0].stored() {
		t.Errorf("the first attempt is %q, want the settings as they are stored", got[0].what)
	}
	if got := preferring(attempts, ""); len(got) != len(attempts) || !got[0].stored() {
		t.Error("remembering nothing changed the order the attempts are tried in")
	}
}

// The attempts at one address have to stay together whatever is remembered: an address that
// answers with something other than OpenVPN condemns all of them at once, and that decision
// walks the list forwards.
func TestRememberingAnAttemptKeepsTheAttemptsAtOneAddressTogether(t *testing.T) {
	attempts := attemptsFor(Run{Remote: "vpn.example.com:53", Proto: config.OpenVPNProtoUDP, TLSCrypt: "key"}, false)
	var want string
	for _, a := range attempts {
		if a.endpoint == 1 && a.what != "" {
			want = a.what
			break
		}
	}
	if want == "" {
		t.Fatal("no attempt at a second address, so this proves nothing")
	}

	got := preferring(attempts, want)
	if got[0].what != want {
		t.Errorf("the first attempt is %q, want the one that worked", got[0].what)
	}
	if len(got) != len(attempts) {
		t.Errorf("the order has %d attempts, want the same %d", len(got), len(attempts))
	}
	seen := map[int]bool{}
	last := -1
	for _, a := range got {
		if a.endpoint == last {
			continue
		}
		if seen[a.endpoint] {
			t.Fatalf("the attempts at address %d are split apart by another address's", a.endpoint)
		}
		seen[a.endpoint], last = true, a.endpoint
	}
}
