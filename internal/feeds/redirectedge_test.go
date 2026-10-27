package feeds

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A redirect is the feed server naming the next address, so the origin rules hold on it
// too: a hop to an address Fetchable refuses ends the download instead of being fetched
// from whatever the pinned dialer reaches.
func TestARedirectToAnAddressThatIsNotFetchableIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "http://127.0.0.1:9/next", http.StatusFound)
			return
		}
		io.WriteString(w, testListBody)
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	client := PinnedClient([]netip.Addr{ap.Addr()}, ap.Port(), time.Minute)
	defer client.CloseIdleConnections()

	_, err := Fetch(context.Background(), client, srv.URL+"/hop", State{}, testMaxBytes)

	if err == nil {
		t.Fatal("Fetch = nil, want the redirect to a refused address rejected")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("err = %v, want it to name the address the download was turned away at", err)
	}
}

// The transport already refuses an unsupported scheme, but the refusal must come from the
// redirect policy as well so the error says the redirect was refused, not that the
// transport stumbled on it.
func TestARedirectToASchemeThatIsNotHTTPIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "gopher://lists.example/pro", http.StatusFound)
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	client := PinnedClient([]netip.Addr{ap.Addr()}, ap.Port(), time.Minute)
	defer client.CloseIdleConnections()

	_, err := Fetch(context.Background(), client, srv.URL, State{}, testMaxBytes)

	if err == nil || !strings.Contains(err.Error(), "not http or https") {
		t.Fatalf("Fetch = %v, want the non-http scheme refused by the redirect policy", err)
	}
}

// A redirect to another hostname is allowed -- CDNs serve feeds this way -- because every
// hop still connects to an address already checked with Fetchable, whatever host the
// request carries.
func TestARedirectToAnotherHostOnAPinnedAddressIsFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "http://lists.example/next", http.StatusFound)
			return
		}
		if r.Host != "lists.example" {
			t.Errorf("second request host = %q, want the redirect target's host", r.Host)
		}
		io.WriteString(w, testListBody)
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	client := PinnedClient([]netip.Addr{ap.Addr()}, ap.Port(), time.Minute)
	defer client.CloseIdleConnections()

	got, err := Fetch(context.Background(), client, srv.URL+"/hop", State{}, testMaxBytes)

	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.Body) != testListBody {
		t.Errorf("body = %q, want the file the pinned address served after the hop", got.Body)
	}
}

// A list fetched over https was asked for over an encrypted connection, so a server
// redirecting it to plain http is asking for it to be fetched where anyone on the path
// can read or replace it. That hop is refused, wherever in the chain the https was.
func TestARedirectFromHTTPSToHTTPIsRefused(t *testing.T) {
	client := PinnedClient([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, 443, time.Minute)
	defer client.CloseIdleConnections()
	request := func(raw string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	err := client.CheckRedirect(request("http://lists.example/pro"), []*http.Request{request("https://lists.example/pro")})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("https -> http: err = %v, want the downgrade refused", err)
	}
	err = client.CheckRedirect(request("http://cdn.example/pro"),
		[]*http.Request{request("https://lists.example/pro"), request("https://mirror.example/pro")})
	if err == nil {
		t.Error("https -> https -> http: the downgrade after two encrypted hops was followed")
	}

	if err := client.CheckRedirect(request("https://cdn.example/pro"), []*http.Request{request("http://lists.example/pro")}); err != nil {
		t.Errorf("http -> https: err = %v, want the upgrade followed", err)
	}
	if err := client.CheckRedirect(request("http://cdn.example/pro"), []*http.Request{request("http://lists.example/pro")}); err != nil {
		t.Errorf("http -> http: err = %v, want a list that was never encrypted followed as before", err)
	}
}

// Setting a redirect policy replaces the standard library's own limit on hops, so the
// policy has to carry one: a server redirecting forever would otherwise hold the download
// open until the whole timeout ran out.
func TestARedirectChainHasAnEnd(t *testing.T) {
	client := PinnedClient([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, 443, time.Minute)
	defer client.CloseIdleConnections()
	via := make([]*http.Request, 10)
	for i := range via {
		req, err := http.NewRequest(http.MethodGet, "https://lists.example/hop", nil)
		if err != nil {
			t.Fatal(err)
		}
		via[i] = req
	}
	next, err := http.NewRequest(http.MethodGet, "https://lists.example/hop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(next, via); err == nil {
		t.Error("an eleventh redirect was followed")
	}
}
