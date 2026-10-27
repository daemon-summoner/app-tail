// SPDX-License-Identifier: MIT

package inspect

// Every parser here reads bytes an attacker chooses, from a local process as readily as from
// the network. The corpus tests say what the parsers must answer; these say what they must
// never do whatever they are handed: panic, or read past what they were given.
//
// The seeds run as ordinary tests under test.sh, so the cheap half of this is in every run and
// the expensive half is one command away:
//
//	go test -fuzz=FuzzClientHello -fuzztime=5m ./internal/inspect

import (
	"testing"
)

// seedCorpus is what every target starts from: real captures, the hellos built to be wrong,
// and the shapes that are not TLS at all.
func seedCorpus(f *testing.F) {
	for _, held := range captures {
		raw, err := readCapture(held.file)
		if err != nil {
			f.Fatalf("reading the capture: %v", err)
		}
		f.Add(raw)
	}
	f.Add(buildHello(extension(0, serverName("seed.example")), 0))
	f.Add(buildHello(extension(0, serverName("split.example")), 40))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: seed.example\r\n\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	f.Add(dnsQuery("seed.example"))
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
	f.Add([]byte{})
}

// The hello parser, which reads the most structure off the least trustworthy bytes.
func FuzzClientHello(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, win []byte) {
		if len(win) > windowSize {
			win = win[:windowSize]
		}
		hello, state := ParseClientHello(win)
		if state != Parsed {
			return
		}
		// A finished parse answers about the bytes it was given and nothing else: a name or a
		// protocol longer than the window is a read past the end that happened to land inside
		// this process.
		if name := hello.SNI(); len(name) > len(win) {
			t.Fatalf("a %d-byte window produced a %d-byte name", len(win), len(name))
		}
		if alpn := hello.ALPN(); len(alpn) > len(win) {
			t.Fatalf("a %d-byte window produced a %d-byte protocol", len(win), len(alpn))
		}
		if !printableName([]byte(hello.SNI())) && hello.SNI() != "" {
			t.Fatalf("a name carrying something unprintable was handed back: %q", hello.SNI())
		}
	})
}

// The head parser, whose bytes come from the same place and whose Host lands in the same
// fields.
func FuzzHTTPHead(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, win []byte) {
		if len(win) > windowSize {
			win = win[:windowSize]
		}
		head, state := ParseHTTPHead(win)
		if state != Parsed {
			return
		}
		if host := head.Host(); len(host) > len(win) {
			t.Fatalf("a %d-byte window produced a %d-byte host", len(win), len(host))
		}
		if host := head.Host(); host != "" && !printableName([]byte(host)) {
			t.Fatalf("a host carrying something unprintable was handed back: %q", host)
		}
		if method := head.Method(); method != "" && !knownMethod([]byte(method)) {
			t.Fatalf("a method nothing recognises was handed back: %q", method)
		}
	})
}

// The message parser, which is the one that could be made to walk in a circle if it ever
// followed a compression pointer.
func FuzzDNSMessage(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		name, ok := DNSQuestion(msg)
		if !ok {
			return
		}
		if len(name) > maxDNSName {
			t.Fatalf("a name of %d bytes was handed back, past the protocol's own ceiling", len(name))
		}
		if len(name) > len(msg) {
			t.Fatalf("a %d-byte message produced a %d-byte name", len(msg), len(name))
		}
		if !printableName([]byte(name)) {
			t.Fatalf("a name carrying something unprintable was handed back: %q", name)
		}
	})
}

// The fingerprint, which is derived rather than read, so what it must never do is produce a
// value that is not a fingerprint at all.
func FuzzJA4(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, win []byte) {
		if len(win) > windowSize {
			win = win[:windowSize]
		}
		hello, state := ParseClientHello(win)
		if state != Parsed {
			return
		}
		for _, transport := range []byte{TransportTCP, TransportQUIC} {
			fingerprint := hello.JA4(transport)
			if fingerprint == "" {
				continue
			}
			if len(fingerprint) != 36 {
				t.Fatalf("a fingerprint of %d characters was produced: %q", len(fingerprint), fingerprint)
			}
			if !printableName([]byte(fingerprint)) {
				t.Fatalf("a fingerprint carrying something unprintable was produced: %q", fingerprint)
			}
		}
	})
}

// The whole window path, which is where the parsers are actually reached from and the one
// place a panic would reach a data path.
func FuzzStream(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, win []byte) {
		var counted counting
		stream := NewStream(StreamOptions{Fingerprint: true}, counted.report)
		for at := 0; at < len(win); at += 7 {
			stream.Up(win[at:min(at+7, len(win))])
		}
		stream.Close()
		if len(counted.seen) > 1 {
			t.Fatalf("one connection was reported %d times", len(counted.seen))
		}
	})
}

// The same path with the patterns on, which holds the window longer and reads it a second
// time. The two reports are separate signals and neither may be made twice.
func FuzzStreamAgainstSignatures(f *testing.F) {
	seedCorpus(f)
	set, err := CompileSignatures("the fuzzer's entries", []string{
		`a token = "hunter2-9f3a1c"`,
		`a marker = "MARK\x00\xff"`,
		`a header = "Authorization: "`,
	})
	if err != nil {
		f.Fatalf("compile the signatures: %v", err)
	}

	f.Fuzz(func(t *testing.T, win []byte) {
		var counted counting
		var matched matching
		stream := NewStream(StreamOptions{
			Fingerprint: true,
			Signatures:  set,
			Matched:     matched.report,
		}, counted.report)
		for at := 0; at < len(win); at += 7 {
			stream.Up(win[at:min(at+7, len(win))])
		}
		stream.Close()

		if len(counted.seen) > 1 {
			t.Fatalf("one connection was reported %d times", len(counted.seen))
		}
		if len(matched.seen) > 1 {
			t.Fatalf("one connection matched a pattern %d times", len(matched.seen))
		}
		for _, found := range matched.seen {
			if found.Signal != SignalPayload {
				t.Fatalf("a pattern was reported under the signal %q", found.Signal)
			}
			if found.Value == "" {
				t.Fatal("a pattern was reported under no name at all")
			}
		}
	})
}

// The datagram path, which reads each message whole rather than accumulating one.
func FuzzDatagramsAgainstSignatures(f *testing.F) {
	seedCorpus(f)
	set, err := CompileSignatures("the fuzzer's entries", []string{`a token = "hunter2-9f3a1c"`})
	if err != nil {
		f.Fatalf("compile the signatures: %v", err)
	}

	f.Fuzz(func(t *testing.T, win []byte) {
		var counted counting
		var matched matching
		flow := NewDatagrams(DatagramOptions{
			Report:     counted.report,
			Signatures: set,
			Matched:    matched.report,
		})
		for at := 0; at < len(win); at += 64 {
			flow.Up(win[at:min(at+64, len(win))])
		}
		flow.Close()

		for _, found := range matched.seen {
			if found.Signal != SignalPayload || found.Value == "" {
				t.Fatalf("a pattern was reported as %q under the name %q", found.Signal, found.Value)
			}
		}
	})
}
