// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// openvpn says why a connection is not coming up on its log rather than in the state it
// reports, so the lines carrying a reason are picked out and the rest are left alone. Without
// this a server that never answers and an account the server refused both read as a
// connection that is still connecting, with nothing on screen saying which.
func TestTheReasonAConnectionIsNotComingUpIsPickedOffTheLog(t *testing.T) {
	for _, text := range []string{
		"TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)",
		"AUTH: Received control message: AUTH_FAILED",
		"VERIFY X509NAME ERROR: CN=vpn.example.com, must be CN=other.example.com",
		"Connection reset, restarting [0]",
		"RESOLVE: Cannot resolve host address: vpn.example.com",
	} {
		notice, ok := noticeFrom(text)
		if !ok || notice != text {
			t.Errorf("noticeFrom(%q) = %q/%v, want the line carried through as it stands", text, notice, ok)
		}
	}
	for _, text := range []string{
		"OpenVPN 2.6.8 aarch64-apple-darwin [SSL (OpenSSL)]",
		"UDPv4 link remote: [AF_INET]203.0.113.9:1194",
		"Initialization Sequence Completed",
		"   ",
	} {
		if notice, ok := noticeFrom(text); ok {
			t.Errorf("noticeFrom(%q) = %q, want an ordinary line to carry no reason", text, notice)
		}
	}

	// The cut lands inside a multi-byte character, and a broken one would travel from here to
	// a dashboard.
	notice, ok := noticeFrom("TLS Error: " + strings.Repeat("é", maxNoticeLen))
	if !ok {
		t.Fatal("a long line carried no reason at all")
	}
	if len(notice) > maxNoticeLen+len("...") {
		t.Errorf("the reason is %d bytes, over the %d-byte bound", len(notice), maxNoticeLen)
	}
	if !utf8.ValidString(notice) {
		t.Errorf("the reason %q is not valid text", notice)
	}
}

// The notification carries up to nine fields and openvpn leaves most of them empty in most
// states, so what matters is that the ones that are there are read from the right positions
// and the ones that are not leave nothing behind.
func TestAStateNotificationIsReadFromOpenVPNsOwnFieldOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want report
	}{
		{
			name: "a connection that has everything",
			line: ">STATE:1699999999,CONNECTED,SUCCESS,10.8.0.6,203.0.113.9,1194,192.168.1.20,54321,fd00::6",
			want: report{
				Name:   "CONNECTED",
				Detail: "SUCCESS",
				TunV4:  netip.MustParseAddr("10.8.0.6"),
				Server: netip.MustParseAddr("203.0.113.9"),
				TunV6:  netip.MustParseAddr("fd00::6"),
			},
		},
		{
			name: "an early state carries a name and nothing else",
			line: ">STATE:1699999999,RESOLVE,,,",
			want: report{Name: "RESOLVE"},
		},
		{
			name: "the reason a connection dropped is the description",
			line: ">STATE:1699999999,RECONNECTING,tls-error,,",
			want: report{Name: "RECONNECTING", Detail: "tls-error"},
		},
		{
			name: "an IPv4-only connection holds no IPv6 address",
			line: ">STATE:1699999999,CONNECTED,SUCCESS,10.8.0.6,203.0.113.9,1194,192.168.1.20,54321,",
			want: report{
				Name:   "CONNECTED",
				Detail: "SUCCESS",
				TunV4:  netip.MustParseAddr("10.8.0.6"),
				Server: netip.MustParseAddr("203.0.113.9"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseState(tc.line)
			if !ok {
				t.Fatalf("parseState(%q) reported no notification", tc.line)
			}
			if got != tc.want {
				t.Errorf("parseState(%q) =\n\t%+v\nwant\n\t%+v", tc.line, got, tc.want)
			}
		})
	}

	for _, line := range []string{
		"",
		">BYTECOUNT:1,2",
		">STATE:1699999999",
		">STATE:1699999999,",
		"SUCCESS: hold release succeeded",
	} {
		if _, ok := parseState(line); ok {
			t.Errorf("parseState(%q) reported a notification, want none", line)
		}
	}
}

func TestTheByteCountersAreReadAsCumulativeTotals(t *testing.T) {
	in, out, ok := parseBytecount(">BYTECOUNT:1024,2048")
	if !ok {
		t.Fatal("parseBytecount reported no counters")
	}
	if in != 1024 || out != 2048 {
		t.Errorf("parseBytecount = %d, %d; want 1024, 2048", in, out)
	}
	// Both halves are checked, not just the first: a counter read as zero because the second
	// number was unreadable would show a connection sending and never receiving.
	for _, line := range []string{
		"", ">BYTECOUNT:", ">BYTECOUNT:1024", ">BYTECOUNT:a,b", ">BYTECOUNT:1024,b", ">STATE:1,CONNECTED",
	} {
		if _, _, ok := parseBytecount(line); ok {
			t.Errorf("parseBytecount(%q) reported counters, want none", line)
		}
	}
}

// A log line puts a time and a set of flags in front of the text, and the text itself
// routinely contains commas -- a pushed reply is nothing but commas -- so splitting on every
// separator would cut the message in half.
func TestALogMessageKeepsTheCommasInsideIt(t *testing.T) {
	text, ok := parseLog(">LOG:1699999999,I,PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.0 255.255.0.0'")
	if !ok {
		t.Fatal("parseLog reported no message")
	}
	const want = "PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.0 255.255.0.0'"
	if text != want {
		t.Errorf("parseLog = %q, want %q", text, want)
	}
	for _, line := range []string{"", ">LOG:1699999999", ">LOG:1699999999,I", ">STATE:1,CONNECTED"} {
		if _, ok := parseLog(line); ok {
			t.Errorf("parseLog(%q) reported a message, want none", line)
		}
	}
}

// What the server offered is read so it can be reported. The options this connection would
// never act on anyway are left out, because a list that includes them buries the two or three
// that explain why a destination does not work.
func TestTheOptionsAServerOfferedAreReadSoTheyCanBeReported(t *testing.T) {
	text := "PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.0 255.255.0.0," +
		"dhcp-option DNS 10.8.0.1,redirect-gateway def1,ping 10,ping-restart 60," +
		"route-ipv6 fd00::/48,ifconfig 10.8.0.6 255.255.255.0',flags=0x0"
	got, ok := parsePushReply(text)
	if !ok {
		t.Fatal("parsePushReply reported no options")
	}
	want := []string{
		"route 10.8.0.0 255.255.0.0",
		"dhcp-option DNS 10.8.0.1",
		"redirect-gateway def1",
		"route-ipv6 fd00::/48",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("parsePushReply =\n\t%q\nwant\n\t%q", got, want)
	}

	// A log line that is not a pushed reply, and one whose reply carried nothing worth
	// reporting, are both "nothing to report" rather than an empty list somebody has to
	// render.
	if _, ok := parsePushReply("Initialization Sequence Completed"); ok {
		t.Error("an ordinary log line was read as a pushed reply")
	}
	if _, ok := parsePushReply("PUSH: Received control message: 'PUSH_REPLY,ping 10,ping-restart 60'"); ok {
		t.Error("a reply carrying only options this connection ignores was reported, want none")
	}
	// Servers write a trailing separator, and a reply split on it ends in an empty option.
	// Reading that as an option would report a blank line among what the server offered.
	got, ok = parsePushReply("PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.0 255.255.0.0,,'")
	if !ok {
		t.Fatal("a reply written with a trailing separator was read as carrying nothing")
	}
	if len(got) != 1 || got[0] != "route 10.8.0.0 255.255.0.0" {
		t.Errorf("parsePushReply = %q, want the one route and nothing beside it", got)
	}
}

// Every prompt openvpn can send is answered from what is stored, and a prompt with no stored
// answer is an error rather than silence: openvpn waits forever for an answer it was told to
// ask for here, so a connection that stayed quiet would sit in AUTH with nothing saying why.
func TestEveryCredentialPromptIsEitherAnsweredOrRefusedOutLoud(t *testing.T) {
	full := credentials{Username: "alice", Password: "s3cret", KeyPassphrase: "keypass"}
	for _, tc := range []struct {
		name   string
		creds  credentials
		prompt string
		want   []string
	}{
		{
			name:   "an account is answered with both lines",
			creds:  full,
			prompt: "Need 'Auth' username/password",
			want:   []string{`username "Auth" "alice"`, `password "Auth" "s3cret"`},
		},
		{
			name:   "a username on its own",
			creds:  full,
			prompt: "Need 'Auth' username",
			want:   []string{`username "Auth" "alice"`},
		},
		{
			name:   "an encrypted private key is answered with its passphrase, not the account password",
			creds:  full,
			prompt: "Need 'Private Key' password",
			want:   []string{`password "Private Key" "keypass"`},
		},
		{
			name:   "a password prompt that is not the key uses the account password",
			creds:  full,
			prompt: "Need 'Auth' password",
			want:   []string{`password "Auth" "s3cret"`},
		},
		{
			name:   "a value carrying the characters that would end its own quoting",
			creds:  credentials{Username: `a"b`, Password: `c\d`},
			prompt: "Need 'Auth' username/password",
			want:   []string{`username "Auth" "a\"b"`, `password "Auth" "c\\d"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.creds.replies(tc.prompt)
			if err != nil {
				t.Fatalf("replies(%q) failed: %v", tc.prompt, err)
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("replies(%q) =\n\t%q\nwant\n\t%q", tc.prompt, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		creds  credentials
		prompt string
	}{
		{"the server refused what was sent", full, "Verification Failed: 'Auth'"},
		{"an account the connection has none for", credentials{}, "Need 'Auth' username/password"},
		{"only half an account", credentials{Username: "alice"}, "Need 'Auth' username/password"},
		{"an encrypted key with no passphrase", credentials{Password: "s3cret"}, "Need 'Private Key' password"},
		{"a username nothing is stored for", credentials{Password: "s3cret"}, "Need 'Auth' username"},
		{"a password nothing is stored for", credentials{}, "Need 'Auth' password"},
		{"a prompt shape this app does not know", full, "Need 'Auth' token-insertion"},
		{"a line that is not a prompt at all", full, "something else entirely"},
		{"a prompt with no second half", full, "Need 'Auth'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.creds.replies(tc.prompt); err == nil {
				t.Errorf("replies(%q) answered %q, want a refusal", tc.prompt, got)
			}
		})
	}
}

// A password with a space in it would be read as two arguments unquoted, and the failure that
// produces is a login refused for a reason nobody can see.
func TestEveryValueSentOverTheSocketIsQuoted(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", `"plain"`},
		{"with space", `"with space"`},
		{`with"quote`, `"with\"quote"`},
		{`with\slash`, `"with\\slash"`},
		{"", `""`},
	} {
		if got := quoteManagement(tc.in); got != tc.want {
			t.Errorf("quoteManagement(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// Commands are sent from the reader's own goroutine and from a caller stopping the
// connection, so one can arrive after openvpn has gone. Answering it is what keeps that
// caller from waiting on a socket nothing is on any more.
func TestACommandSentToAConnectionThatIsGoneIsAnswered(t *testing.T) {
	err := (&link{}).send("hold release")
	if err == nil {
		t.Fatal("a command sent with nothing on the socket was accepted, so its caller would wait")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("send failed with %q, want it to say the connection is not reachable", err)
	}
}

// openvpn opens its management socket a few milliseconds after it starts, so the first dial
// usually finds nothing there yet. Giving up on that would fail every start; the dial goes on
// trying until the socket answers.
func TestTheManagementSocketIsDialledUntilItOpens(t *testing.T) {
	path := filepath.Join(socketDir(t), "late.sock")
	listening := make(chan net.Listener, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		ln, err := net.Listen("unix", path)
		if err != nil {
			listening <- nil
			return
		}
		listening <- ln
		if conn, err := ln.Accept(); err == nil {
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialManagement(ctx, path)
	ln := <-listening
	if ln == nil {
		t.Fatal("the socket standing in for openvpn's could not be opened")
	}
	defer ln.Close()
	if err != nil {
		t.Fatalf("a socket that opened 200ms after the dial began was not reached: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close the management connection: %v", err)
	}
}

// And a socket that never opens is an error inside a bound, naming the socket. A dial that
// waited for ever would hold the start of a connection whose program died at once.
func TestAManagementSocketThatNeverOpensIsAnErrorWithinItsBound(t *testing.T) {
	path := filepath.Join(socketDir(t), "never.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	conn, err := dialManagement(ctx, path)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a socket nothing ever listened on was reached")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("giving up took %v", took)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the failure does not name the socket it was waiting for: %v", err)
	}
	if managementDialTimeout <= 0 || managementDialTimeout > time.Minute {
		t.Errorf("the dial waits %v on its own, want a bound of seconds", managementDialTimeout)
	}
}
