// SPDX-License-Identifier: MIT

package inspect

// What real clients send, and what an adversary sends.
//
// The captures are the honest half: three different TLS stacks, each asked for the same name,
// each recorded off a socket rather than written by hand. The rest of this file is the other
// half -- hellos built to break the parser, every one of which must produce a wrong answer
// never, and a panic never.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

// captures are the recorded hellos, and what the client that sent each one was asked for. The
// name and the protocol are what the capture was made with, so they are evidence rather than
// a note of what the parser said the first time it read them.
var captures = []struct {
	name string
	file string
	sni  string
	alpn string
}{
	{name: "curl", file: "clienthello-curl.hex", sni: "example.test", alpn: "h2"},
	{name: "go", file: "clienthello-go.hex", sni: "example.test", alpn: "h2"},
	{name: "openssl", file: "clienthello-openssl.hex", sni: "example.test", alpn: "h2"},
}

// capture reads one recorded hello.
func capture(t *testing.T, file string) []byte {
	t.Helper()
	win, err := readCapture(file)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return win
}

// readCapture is the same read without a test to fail, for the fuzz seeds.
func readCapture(file string) ([]byte, error) {
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		return nil, fmt.Errorf("reading the capture: %w", err)
	}
	win, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decoding the capture: %w", err)
	}
	return win, nil
}

// The whole point of the parser: a connection dialled at an address still says which name it
// is for, and this reads it out of what three different TLS stacks actually send.
func TestARealHelloSaysWhichNameItIsFor(t *testing.T) {
	for _, held := range captures {
		t.Run(held.name, func(t *testing.T) {
			hello, state := ParseClientHello(capture(t, held.file))
			if state != Parsed {
				t.Fatalf("a complete hello read as %v, want Parsed", state)
			}
			if got := hello.SNI(); got != held.sni {
				t.Errorf("the name is %q, want %q", got, held.sni)
			}
			if got := hello.ALPN(); got != held.alpn {
				t.Errorf("the first protocol offered is %q, want %q", got, held.alpn)
			}
			// Every one of these clients speaks TLS 1.3, and each says so in the extension
			// rather than in the version at the front of the hello.
			if got := hello.Version(); got != 0x0304 {
				t.Errorf("the version offered is %#04x, want 0x0304", got)
			}
			if hello.ECH {
				t.Error("a hello with no encrypted client hello was read as carrying one")
			}
		})
	}
}

// A hello arrives in whatever pieces the network hands over, and the name has to read the same
// out of every one of them. This is the split test as a loop rather than three hand-picked
// offsets: the interesting break is always the one nobody thought of.
func TestAHelloSplitAnywhereReadsTheSame(t *testing.T) {
	for _, held := range captures {
		t.Run(held.name, func(t *testing.T) {
			win := capture(t, held.file)
			for at := 1; at < len(win); at++ {
				var found Handshake
				stream := NewStream(StreamOptions{Fingerprint: true}, func(h Handshake) bool {
					found = h
					return false
				})
				stream.Up(win[:at])
				stream.Up(win[at:])
				if found.Name != held.sni {
					t.Fatalf("split at %d read the name as %q, want %q", at, found.Name, held.sni)
				}
				if found.ALPN != held.alpn {
					t.Fatalf("split at %d read the protocol as %q, want %q", at, found.ALPN, held.alpn)
				}
				if found.Protocol != ProtocolTLS {
					t.Fatalf("split at %d read the connection as %q, want %q", at, found.Protocol, ProtocolTLS)
				}
			}
		})
	}
}

// Every prefix of a real hello is an unfinished hello. None of them may read as a finished one:
// a parser that answers early answers with whatever it has, and what it has is half a name.
func TestEveryPrefixOfAHelloIsUnfinishedRatherThanWrong(t *testing.T) {
	for _, held := range captures {
		t.Run(held.name, func(t *testing.T) {
			win := capture(t, held.file)
			for at := 1; at < len(win); at++ {
				hello, state := ParseClientHello(win[:at])
				if state == Parsed {
					t.Fatalf("%d bytes of a %d-byte hello read as finished, with the name %q",
						at, len(win), hello.SNI())
				}
			}
		})
	}
}

// helloWriter builds a hello a byte at a time, which is what the corpus below is made of.
type helloWriter struct{ b []byte }

func (w *helloWriter) u8(v int)         { w.b = append(w.b, byte(v)) }
func (w *helloWriter) u16(v int)        { w.b = binary.BigEndian.AppendUint16(w.b, uint16(v)) }
func (w *helloWriter) raw(more ...byte) { w.b = append(w.b, more...) }
func (w *helloWriter) fill(n int, v byte) {
	for i := 0; i < n; i++ {
		w.b = append(w.b, v)
	}
}

// extension is one extension block, ready to be pasted into a hello.
func extension(kind int, body []byte) []byte {
	var w helloWriter
	w.u16(kind)
	w.u16(len(body))
	w.raw(body...)
	return w.b
}

// serverName is a server_name extension body naming one host.
func serverName(name string) []byte {
	var w helloWriter
	w.u16(len(name) + 3)
	w.u8(0)
	w.u16(len(name))
	w.raw([]byte(name)...)
	return w.b
}

// buildHello wraps a hello body in the handshake and record headers a client sends it in,
// splitting it across records of at most recordSize bytes when one is given.
func buildHello(extensions []byte, recordSize int) []byte {
	var body helloWriter
	body.u16(0x0303)
	body.fill(32, 0x11) // random
	body.u8(0)          // no session id
	body.u16(2)         // one cipher
	body.u16(0x1301)
	body.u8(1) // one compression method
	body.u8(0)
	body.u16(len(extensions))
	body.raw(extensions...)

	var handshake helloWriter
	handshake.u8(1) // client_hello
	handshake.u8(len(body.b) >> 16)
	handshake.u16(len(body.b) & 0xffff)
	handshake.raw(body.b...)

	if recordSize <= 0 {
		recordSize = len(handshake.b)
	}
	var out helloWriter
	for at := 0; at < len(handshake.b); at += recordSize {
		end := min(at+recordSize, len(handshake.b))
		out.raw(0x16, 0x03, 0x01)
		out.u16(end - at)
		out.raw(handshake.b[at:end]...)
	}
	return out.b
}

// A hello whose name is split across two TLS records is the ordinary case for a hello carrying
// a post-quantum key share, and the record headers in the middle of it are not part of any
// length the hello itself declares.
func TestANameSplitAcrossRecordsIsStillOneName(t *testing.T) {
	win := buildHello(extension(0, serverName("split.example")), 40)
	hello, state := ParseClientHello(win)
	if state != Parsed {
		t.Fatalf("a hello across records read as %v, want Parsed", state)
	}
	if got := hello.SNI(); got != "split.example" {
		t.Errorf("the name is %q, want %q", got, "split.example")
	}
}

// The corpus: hellos built to be wrong. Each one must be refused or read as unfinished, and
// none of them may panic or hand back a name.
func TestAMalformedHelloIsNeverReadAsAName(t *testing.T) {
	var huge helloWriter
	huge.u16(0xffff) // a name list claiming 64 KB
	huge.u8(0)
	huge.u16(0xfffc)
	huge.raw([]byte("short.example")...)

	var manyNames helloWriter
	for i := 0; i < 300; i++ {
		manyNames.b = append(manyNames.b, serverName("name.example")...)
	}

	cases := []struct {
		name string
		win  []byte
	}{
		{"a name list claiming sixty-four kilobytes", buildHello(extension(0, huge.b), 0)},
		{"a name of no length at all", buildHello(extension(0, serverName("")), 0)},
		{"a name carrying a newline", buildHello(extension(0, serverName("bad\r\nname.example")), 0)},
		{"a name carrying a null byte", buildHello(extension(0, serverName("bad\x00name.example")), 0)},
		{"a name of spaces", buildHello(extension(0, serverName("   ")), 0)},
		{"an extension length past the end", append(buildHello(extension(0, serverName("x.example")), 0)[:9], 0xff, 0xff)},
		{"nothing but record headers", []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
		{"four kilobytes of the first two bytes of a hello", []byte(strings.Repeat("\x16\x03", 2048))},
		{"a hello that is only a handshake header", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0xff, 0xff}},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			hello, state := ParseClientHello(held.win)
			if state == Parsed && hello.SNI() != "" {
				t.Fatalf("a hello built to be wrong handed back the name %q", hello.SNI())
			}
		})
	}

	// Three hundred names in one extension is bounded by the keep-the-first rule rather than
	// by a buffer, so it parses -- and answers with the first name, not the last.
	hello, state := ParseClientHello(buildHello(extension(0, manyNames.b), 0))
	if state != Parsed || hello.SNI() != "name.example" {
		t.Fatalf("a hello naming three hundred hosts read as %v with the name %q", state, hello.SNI())
	}
}

// Four kilobytes is the window, so a hello either side of it is where a length check that is
// off by one shows up.
func TestAHelloAtTheWindowEdgeIsReadOrRefusedButNeverWrong(t *testing.T) {
	for _, size := range []int{windowSize - 1, windowSize, windowSize + 1} {
		// A padding extension takes the hello to whatever size is wanted; the name sits in
		// front of it, so the ones that fit are read and the ones that do not are unfinished.
		grown := append([]byte(nil), extension(0, serverName("edge.example"))...)
		short := len(buildHello(grown, 0))
		if size > short {
			grown = append(grown, extension(21, make([]byte, size-short-4))...)
		}
		win := buildHello(grown, 0)

		var found Handshake
		stream := NewStream(StreamOptions{}, func(h Handshake) bool {
			found = h
			return false
		})
		for at := 0; at < len(win); at += 512 {
			stream.Up(win[at:min(at+512, len(win))])
		}
		stream.Close()

		if found.Protocol != ProtocolTLS {
			t.Errorf("a %d-byte hello read as %q, want %q", len(win), found.Protocol, ProtocolTLS)
		}
		if len(win) <= windowSize && found.Name != "edge.example" {
			t.Errorf("a %d-byte hello inside the window read the name as %q", len(win), found.Name)
		}
	}
}
