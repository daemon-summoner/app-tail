// SPDX-License-Identifier: MIT

package inspect

// The plaintext half of the same question the hello answers, and the same standard: a head
// built to be wrong must be refused rather than half-read.

import (
	"strings"
	"testing"
)

// The ordinary request, and the two things read out of it.
func TestARequestSaysWhichHostItIsFor(t *testing.T) {
	cases := []struct {
		name   string
		win    string
		method string
		host   string
	}{
		{
			name:   "a plain request",
			win:    "GET /index.html HTTP/1.1\r\nHost: plain.example\r\nAccept: */*\r\n\r\n",
			method: "GET",
			host:   "plain.example",
		},
		{
			name:   "a host carrying a port",
			win:    "POST /submit HTTP/1.1\r\nHost: ported.example:8443\r\n\r\n",
			method: "POST",
			host:   "ported.example",
		},
		{
			name:   "a header name in another case",
			win:    "GET / HTTP/1.1\r\nHOST:  spaced.example  \r\n\r\n",
			method: "GET",
			host:   "spaced.example",
		},
		{
			name:   "an address in brackets",
			win:    "GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n",
			method: "GET",
			host:   "[2001:db8::1]",
		},
		{
			// Clients send these, and a parser that insisted on the pair would read the whole
			// request as one unfinished line.
			name:   "lines ended with a newline alone",
			win:    "GET / HTTP/1.0\nHost: bare.example\n\n",
			method: "GET",
			host:   "bare.example",
		},
		{
			name:   "a request with no host at all",
			win:    "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
			method: "GET",
			host:   "",
		},
		{
			// The first Host is the one that counts: a second one is request smuggling, and
			// answering with it would be answering with the attacker's copy.
			name:   "two host headers",
			win:    "GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n",
			method: "GET",
			host:   "first.example",
		},
		{
			name:   "a target that is a whole URL",
			win:    "GET http://proxied.example/path HTTP/1.1\r\nHost: proxied.example\r\n\r\n",
			method: "GET",
			host:   "proxied.example",
		},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			head, state := ParseHTTPHead([]byte(held.win))
			if state != Parsed {
				t.Fatalf("the head read as %v, want Parsed", state)
			}
			if got := head.Method(); got != held.method {
				t.Errorf("the method is %q, want %q", got, held.method)
			}
			if got := head.Host(); got != held.host {
				t.Errorf("the host is %q, want %q", got, held.host)
			}
		})
	}
}

// What is not HTTP must be said to be not HTTP, and quickly: a connection carrying something
// else entirely gets one comparison of its first word, not a wait for a line that never ends.
func TestSomethingThatIsNotARequestIsNotReadAsOne(t *testing.T) {
	cases := []struct {
		name string
		win  string
	}{
		{"a request line with no space", "GET/index.htmlHTTP/1.1\r\nHost: nospace.example\r\n\r\n"},
		{"a word that is not a method", "FETCH / HTTP/1.1\r\nHost: fetch.example\r\n\r\n"},
		{"a method with no version", "GET well soon\r\nHost: prose.example\r\n\r\n"},
		{"a version nobody speaks", "GET / HTTP/9.9\r\nHost: future.example\r\n\r\n"},
		{"an SSH banner", "SSH-2.0-OpenSSH_9.6\r\n"},
		{"a mail banner", "220 mail.example ESMTP\r\n"},
		{"a method that is only spaces", "   \r\nHost: blank.example\r\n\r\n"},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			head, state := ParseHTTPHead([]byte(held.win))
			if state != NotThis {
				t.Fatalf("bytes that are not a request read as %v with the host %q, want NotThis",
					state, head.Host())
			}
		})
	}
}

// A head still arriving is unfinished, not empty: answering early on a head whose Host header
// has not arrived is answering with no name for a connection that has one.
func TestAnUnfinishedRequestIsUnfinishedRatherThanEmpty(t *testing.T) {
	win := "GET /index.html HTTP/1.1\r\nHost: partial.example\r\nAccept: */*\r\n\r\n"
	for at := 1; at < len(win); at++ {
		head, state := ParseHTTPHead([]byte(win[:at]))
		if state == Parsed {
			t.Fatalf("%d bytes of a %d-byte head read as finished, with the host %q",
				at, len(win), head.Host())
		}
		if state == NotThis {
			t.Fatalf("%d bytes of a real request read as not HTTP at all", at)
		}
	}
}

// Split at every offset, through the stream that a copy loop actually drives, the answer has
// to be the one name the request named.
func TestARequestSplitAnywhereReadsTheSameHost(t *testing.T) {
	win := []byte("GET / HTTP/1.1\r\nHost: split.example\r\nUser-Agent: something\r\n\r\n")
	for at := 1; at < len(win); at++ {
		var found Handshake
		stream := NewStream(StreamOptions{}, func(h Handshake) bool {
			found = h
			return false
		})
		stream.Up(win[:at])
		stream.Up(win[at:])
		if found.Protocol != ProtocolHTTP {
			t.Fatalf("split at %d read the connection as %q, want %q", at, found.Protocol, ProtocolHTTP)
		}
		if found.Name != "split.example" {
			t.Fatalf("split at %d read the host as %q, want %q", at, found.Name, "split.example")
		}
	}
}

// The head an attacker sends. None of these may hand back a name, and none may take longer
// than the window is wide.
func TestAMalformedRequestIsNeverReadAsAHost(t *testing.T) {
	var many strings.Builder
	many.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 10000; i++ {
		many.WriteString("X-Filler: 1\r\n")
	}
	many.WriteString("Host: buried.example\r\n\r\n")

	cases := []struct {
		name string
		win  string
		host string
	}{
		{
			// The Host is past the window, so the answer is no name rather than a name read
			// from bytes that were never kept.
			name: "ten thousand headers before the host",
			win:  many.String(),
			host: "",
		},
		{
			name: "a host carrying a carriage return",
			win:  "GET / HTTP/1.1\r\nHost: bad\rname.example\r\n\r\n",
			host: "",
		},
		{
			name: "a host carrying a null byte",
			win:  "GET / HTTP/1.1\r\nHost: bad\x00name.example\r\n\r\n",
			host: "",
		},
		{
			name: "a host of nothing but spaces",
			win:  "GET / HTTP/1.1\r\nHost:      \r\n\r\n",
			host: "",
		},
		{
			name: "a host longer than any name",
			win:  "GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", maxName+1) + ".example\r\n\r\n",
			host: "",
		},
		{
			name: "an address in brackets that never closes",
			win:  "GET / HTTP/1.1\r\nHost: [2001:db8::1\r\n\r\n",
			host: "",
		},
		{
			name: "a header with no colon at all",
			win:  "GET / HTTP/1.1\r\nHostnocolon\r\nHost: real.example\r\n\r\n",
			host: "real.example",
		},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			win := []byte(held.win)
			if len(win) > windowSize {
				win = win[:windowSize]
			}
			head, _ := ParseHTTPHead(win)
			if got := head.Host(); got != held.host {
				t.Errorf("the host is %q, want %q", got, held.host)
			}
		})
	}
}

// The window edge is where a length check that is off by one shows up, and the Host header is
// the thing that has to survive landing on it.
func TestAHostStraddlingTheWindowEdgeIsNeverHalfAName(t *testing.T) {
	const host = "edge.example"
	head := "GET / HTTP/1.1\r\n"
	tail := "Host: " + host + "\r\n\r\n"

	// One case per byte of the Host line, so the line begins at every offset either side of
	// the window edge.
	for over := 0; over < len(tail); over++ {
		filler := windowSize - len(head) - len(tail) + over
		if filler < 0 {
			continue
		}
		var win strings.Builder
		win.WriteString(head)
		for win.Len() < len(head)+filler {
			left := len(head) + filler - win.Len()
			if left < 14 {
				win.WriteString("X-P: " + strings.Repeat("p", left-8) + "\r\n")
				break
			}
			win.WriteString("X-Filler: " + strings.Repeat("f", min(left, 200)-12) + "\r\n")
		}
		win.WriteString(tail)

		clipped := []byte(win.String())
		if len(clipped) > windowSize {
			clipped = clipped[:windowSize]
		}
		parsed, _ := ParseHTTPHead(clipped)
		if got := parsed.Host(); got != "" && got != host {
			t.Fatalf("a host landing on the window edge read as %q, want %q or nothing", got, host)
		}
	}
}
