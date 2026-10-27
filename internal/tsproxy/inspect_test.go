// SPDX-License-Identifier: MIT

package tsproxy

// The inspector's seat in the proxy: the one path that knows both the name a program asked
// for and the address that name resolved to.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// fakeInspector refuses the flows a test names and records every flow it was asked about.
type fakeInspector struct {
	refuse map[string]string
	seen   []inspect.Flow
	// watch answers what reads a tunnel's opening bytes, nil in the tests that only exercise
	// the refusal before anything is dialled.
	watch func(inspect.Flow) netpipe.Stream
	// open answers the pair a tunnel is carried between, nil in every test that does not
	// exercise opening one.
	open func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error)
}

func (f *fakeInspector) Open(_ context.Context, flow inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	if f.open == nil {
		return client, upstream, nil
	}
	return f.open(flow, client, upstream)
}

func (f *fakeInspector) Watch(flow inspect.Flow) netpipe.Stream {
	if f.watch == nil {
		return nil
	}
	return f.watch(flow)
}

func (f *fakeInspector) Refuse(flow inspect.Flow) (string, bool) {
	f.seen = append(f.seen, flow)
	if reason, ok := f.refuse[flow.Name]; ok {
		return reason, true
	}
	if reason, ok := f.refuse[flow.Addr.String()]; ok {
		return reason, true
	}
	return "", false
}

func TestARefusedDestinationIsNeverDialled(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)
	box.set.SetInspector(&fakeInspector{refuse: map[string]string{"peer": "peer is named by your own entries"}})

	_, err := p.dial(context.Background(), "tcp", "peer:22")

	if !errors.Is(err, ErrRefused) {
		t.Fatalf("dial = %v, want it refused as an inspected destination", err)
	}
	if !strings.Contains(err.Error(), "your own entries") {
		t.Errorf("dial error = %v, want it to carry the reason the inspector gave", err)
	}
	if len(tn.dialledAddresses()) != 0 {
		t.Error("a refused destination was dialed anyway, so nothing was prevented")
	}
}

// A plain HTTP fetch is the one refused path where nothing has been written yet, so the
// client can be told what happened instead of having its connection cut. A reset here would
// read to the user as the site being down.
func TestARefusedPlainRequestIsAnsweredRatherThanCut(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:80")
	p, box := startProxy(t, tn)
	box.set.SetInspector(&fakeInspector{refuse: map[string]string{"peer": "peer is named by your own entries"}})

	rec := httptest.NewRecorder()
	p.serveForward(rec, httptest.NewRequest(http.MethodGet, "http://peer/index.html", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for a destination the rules refuse", rec.Code, http.StatusForbidden)
	}
	// The reason is in a header as well as the body, because a browser shows its own error
	// page for a proxy failure and never displays the body at all.
	if got := rec.Header().Get(ConnectErrorHeader); !strings.Contains(got, "your own entries") {
		t.Errorf("%s = %q, want it to carry the reason the inspector gave", ConnectErrorHeader, got)
	}
	if !strings.Contains(rec.Body.String(), "your own entries") {
		t.Errorf("body = %q, want it to name the rule that refused the request", rec.Body)
	}
	if len(tn.dialledAddresses()) != 0 {
		t.Error("a refused destination was dialled anyway, so nothing was prevented")
	}
}

// The name is the whole reason this hook sits here rather than only on the interface, and
// the address is what a rule written as a network matches on. A hook handing over one of
// the two would make half the rules dead on the one path that could have applied them.
func TestTheProxyOffersBothTheNameAskedForAndTheAddressItResolvedTo(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)
	seen := &fakeInspector{}
	box.set.SetInspector(seen)

	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(seen.seen) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one connection that was made", len(seen.seen))
	}
	flow := seen.seen[0]
	if flow.Name != "peer" {
		t.Errorf("flow name = %q, want the name the program asked for", flow.Name)
	}
	if !flow.Addr.IsValid() {
		t.Error("flow carries no address, so a rule written as a network could never match here")
	}
	if flow.Protocol != "tcp" || flow.Where == "" {
		t.Errorf("flow = %+v, want it to say what was carried and where", flow)
	}
	// The port is not matched on by any rule. It is here because a run of connections to
	// many ports of one address is a port scan, and a flow that dropped it would leave
	// every connection through the proxy looking like one port.
	if flow.Port != 22 {
		t.Errorf("flow port = %d, want the port the connection was bound for", flow.Port)
	}
}

// A program that dialled an address gave no name, and writing the address into the name
// half would offer it to the entries written as domains -- where it can only fail to match,
// leaving an entry that names a network looking as though it does not cover an address in it.
func TestADestinationDialledAsAnAddressCarriesNoName(t *testing.T) {
	tn := newFakeNetwork(t)
	addr := tn.routeLiteral(t)
	p, box := startProxy(t, tn)
	seen := &fakeInspector{}
	box.set.SetInspector(seen)

	conn, err := p.dial(context.Background(), "tcp", addr.String())
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	conn.Close()

	if len(seen.seen) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one connection that was made", len(seen.seen))
	}
	flow := seen.seen[0]
	if flow.Name != "" {
		t.Errorf("flow name = %q, want none: nothing asked for a name here", flow.Name)
	}
	if flow.Addr != addr.Addr() {
		t.Errorf("flow address = %s, want the address that was dialled", flow.Addr)
	}
}

// A dial address is host:port everywhere the proxy builds one, and an address that is not
// carries no name rather than reaching the rules as one: a name half holding "peer" with no
// port would match an entry naming that host, on a dial nobody could have made.
func TestADialAddressWithNoPortCarriesNoName(t *testing.T) {
	for _, address := range []string{"peer", "", "[::1"} {
		if got := nameAsked(address); got != "" {
			t.Errorf("nameAsked(%q) = %q, want no name from an address that is not host:port",
				address, got)
		}
	}
}

// The port a flow carries is the one the program asked for, not the one the destination
// resolved to. Anything a port cannot be read out of carries none: a zero in the ledger is
// "the path did not decide one", and inventing a number would put a port in it that nothing
// asked for.
func TestTheProxyReadsThePortTheProgramAskedForOrNoneAtAll(t *testing.T) {
	for address, want := range map[string]uint16{
		"peer:22":      22,
		"10.0.0.1:443": 443,
		"[::1]:8080":   8080,
		"peer":         0,
		"peer:ssh":     0,
		"peer:99999":   0,
		"peer:-1":      0,
		"":             0,
		"[::1":         0,
	} {
		if got := portAsked(address); got != want {
			t.Errorf("portAsked(%q) = %d, want %d", address, got, want)
		}
	}
}

// Nothing set is the module switched off, and it has to compile to carrying everything:
// the set holds the inspector for every instance, so reading an absent one as a refusal
// would take every proxy down with the switch.
func TestAProxyWithNoInspectorCarriesEverything(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)
	box.set.SetInspector(&fakeInspector{refuse: map[string]string{"peer": "stopped"}})
	box.set.SetInspector(nil)

	conn, err := p.dial(context.Background(), "tcp", "peer:22")

	if err != nil {
		t.Fatalf("dial with inspection off: %v", err)
	}
	conn.Close()
	if got := tn.dialledAddresses(); len(got) != 1 {
		t.Errorf("the backend was dialed %d times, want the one connection", len(got))
	}
	if _, err := netip.ParseAddrPort(tn.dialledAddresses()[0]); err != nil {
		t.Errorf("dialed %q, want the address the classifier resolved: %v", tn.dialledAddresses()[0], err)
	}
}

// preludeStream stands in for the window on the tunnel path, stopping the tunnel on a chosen
// word and keeping what it was offered.
type preludeStream struct {
	stopOn string
	up     [][]byte
	shut   int
}

func (s *preludeStream) Up(b []byte) bool {
	s.up = append(s.up, append([]byte(nil), b...))
	return s.stopOn != "" && strings.Contains(string(b), s.stopOn)
}

func (s *preludeStream) Down([]byte) bool { return false }
func (s *preludeStream) Close()           { s.shut++ }

// The blind spot this closes: a client that pipelines its opening bytes behind the CONNECT
// line puts them in the server's reader rather than in the socket, so they never pass through
// the copy loop. Without this hook they are the one client whose handshake nothing reads.
func TestBytesPipelinedBehindTheConnectLineAreRead(t *testing.T) {
	peer := &scriptedConn{}
	p := tunnelProxy(t, peer)
	stream := &preludeStream{}
	p.set.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})

	client := &scriptedConn{}
	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           client,
		buffered:         "the client hello for pipelined.example",
	}, connectTo("peer:443"))

	if len(stream.up) == 0 {
		t.Fatal("the pipelined bytes were never offered to the inspector")
	}
	if got := string(stream.up[0]); got != "the client hello for pipelined.example" {
		t.Errorf("the inspector was offered %q, want the bytes the client pipelined", got)
	}
	// And they still reach the peer, because reading them is not a reason to lose them: a
	// handshake missing its hello hangs until something times out.
	if got := peer.written.String(); got != "the client hello for pipelined.example" {
		t.Errorf("the peer received %q, want the bytes the client pipelined", got)
	}
}

// The same bytes, stopped. They are offered before the write, so a tunnel stopped on its
// pipelined hello is a tunnel whose hello the peer never receives.
func TestPipelinedBytesTheInspectorStopsNeverReachThePeer(t *testing.T) {
	peer := &scriptedConn{}
	p := tunnelProxy(t, peer)
	stream := &preludeStream{stopOn: "bad.example"}
	p.set.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})

	client := &scriptedConn{}
	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           client,
		buffered:         "the client hello for bad.example",
	}, connectTo("peer:443"))

	if got := peer.written.String(); got != "" {
		t.Errorf("the peer received %q of a stopped tunnel, want nothing", got)
	}
	if !peer.closed() || !client.closed() {
		t.Error("a stopped tunnel left one of its two connections open")
	}
	if stream.shut != 1 {
		t.Errorf("the inspector was closed %d times, want once", stream.shut)
	}
}

// The pipelined bytes that cannot be moved. Neither end is left holding a tunnel that will
// never carry anything, and neither is offered bytes the peer has not got.
func TestPipelinedBytesThatCannotBeMovedCloseBothEnds(t *testing.T) {
	peer := &scriptedConn{writeErr: errors.New("the peer went away")}
	p := tunnelProxy(t, peer)
	stream := &preludeStream{}
	p.set.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})

	client := &scriptedConn{}
	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           client,
		buffered:         "the client hello for peer.example",
	}, connectTo("peer:443"))

	if got := peer.written.String(); got != "" {
		t.Errorf("the peer received %q, want nothing", got)
	}
	if !client.closed() || !peer.closed() {
		t.Error("a tunnel that could not carry its pipelined bytes left one of its ends open")
	}
	if stream.shut != 1 {
		t.Errorf("the inspector was closed %d times, want once", stream.shut)
	}
}

// A tunnel the inspector was going to open and could not is stopped rather than carried
// unread. Carrying it would be the failure that matters: the reason an opening fails is
// usually that the far end could not be verified, and carrying it anyway would hand the
// client a connection app-tail has already decided it cannot vouch for.
func TestATunnelThatCouldNotBeOpenedIsStoppedRatherThanCarried(t *testing.T) {
	peer := &scriptedConn{}
	p := tunnelProxy(t, peer)
	stream := &preludeStream{}
	p.set.SetInspector(&fakeInspector{
		watch: func(inspect.Flow) netpipe.Stream { return stream },
		open: func(_ inspect.Flow, _, _ net.Conn) (net.Conn, net.Conn, error) {
			return nil, nil, errors.New("the real server's certificate did not verify")
		},
	})

	client := &scriptedConn{}
	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           client,
		buffered:         "the client hello for peer.example",
	}, connectTo("peer:443"))

	if got := peer.written.String(); got != "" {
		t.Errorf("the peer received %q of a tunnel that was never opened, want nothing", got)
	}
	if !client.closed() || !peer.closed() {
		t.Error("a tunnel that could not be opened left one of its two connections open")
	}
	if stream.shut != 1 {
		t.Errorf("the inspector was closed %d times, want once", stream.shut)
	}
}

// The bytes a client pipelined are put back in front of the connection, so whatever decides
// whether to open the tunnel reads them like any other opening bytes. Without that they are
// the one hello an interception could never see, and the handshake it started would hang.
func TestPipelinedBytesAreReadableByWhateverOpensTheTunnel(t *testing.T) {
	peer := &scriptedConn{}
	p := tunnelProxy(t, peer)
	opening := make(chan string, 1)
	p.set.SetInspector(&fakeInspector{
		open: func(_ inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
			buf := make([]byte, 64)
			n, err := client.Read(buf)
			if err != nil {
				return client, upstream, err
			}
			opening <- string(buf[:n])
			return client, upstream, nil
		},
	})

	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           &scriptedConn{},
		buffered:         "the client hello for pipelined.example",
	}, connectTo("peer:443"))

	select {
	case got := <-opening:
		if got != "the client hello for pipelined.example" {
			t.Errorf("what opened the tunnel read %q, want the bytes the client pipelined", got)
		}
	default:
		t.Fatal("what opened the tunnel never saw the bytes the client pipelined")
	}
}

// The tunnel names what the client asked for, which is the whole reason the proxy is the
// best-placed seam: the name is in the request line, before anything is resolved.
func TestATunnelSaysWhichNameItWasOpenedFor(t *testing.T) {
	p := tunnelProxy(t, &scriptedConn{})
	var seen []inspect.Flow
	p.set.SetInspector(&fakeInspector{watch: func(f inspect.Flow) netpipe.Stream {
		seen = append(seen, f)
		return nil
	}})

	p.serveConnect(&hijackWriter{
		ResponseRecorder: httptest.NewRecorder(),
		client:           &scriptedConn{},
	}, connectTo("peer:443"))

	if len(seen) != 1 {
		t.Fatalf("the inspector was asked about %d tunnels, want the one that was opened", len(seen))
	}
	if seen[0].Name != "peer" || seen[0].Port != 443 {
		t.Errorf("the tunnel reads as %+v, want the name and port the client asked for", seen[0])
	}
	if seen[0].Protocol != "tcp" || seen[0].Where == "" {
		t.Errorf("the tunnel reads as %+v, want it to say what was carried and where", seen[0])
	}
}
