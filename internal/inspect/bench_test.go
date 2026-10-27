// SPDX-License-Identifier: MIT

package inspect

// The cost of reading, measured where it is paid. The package doc states a budget; this is
// what checks it, and the two allocation claims are asserted as tests rather than left as
// numbers somebody has to read off a benchmark and compare by eye.

import "testing"

func BenchmarkClientHelloParse(b *testing.B) {
	win := benchCapture(b, "clienthello-go.hex")
	b.ReportAllocs()
	b.SetBytes(int64(len(win)))
	for b.Loop() {
		hello, state := ParseClientHello(win)
		if state != Parsed || hello.SNI() == "" {
			b.Fatalf("the capture read as %v", state)
		}
	}
}

func BenchmarkJA4(b *testing.B) {
	hello, state := ParseClientHello(benchCapture(b, "clienthello-go.hex"))
	if state != Parsed {
		b.Fatalf("the capture read as %v", state)
	}
	b.ReportAllocs()
	for b.Loop() {
		if hello.JA4(TransportTCP) == "" {
			b.Fatal("the capture produced no fingerprint")
		}
	}
}

func BenchmarkHTTPHeadParse(b *testing.B) {
	win := []byte("GET /index.html HTTP/1.1\r\nHost: bench.example\r\n" +
		"User-Agent: something/1.0\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(win)))
	for b.Loop() {
		head, state := ParseHTTPHead(win)
		if state != Parsed || head.Host() == "" {
			b.Fatalf("the head read as %v", state)
		}
	}
}

func BenchmarkDNSQuestion(b *testing.B) {
	msg := dnsQuery("bench.example.test")
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := DNSQuestion(msg); !ok {
			b.Fatal("the query was not read as a question")
		}
	}
}

// BenchmarkFlowOpen is what one connection costs: a stream, a window, the copy in, and the
// parse that reaches the verdict. This is the per-flow figure the budget is stated in.
func BenchmarkFlowOpen(b *testing.B) {
	win := benchCapture(b, "clienthello-curl.hex")
	report := func(Handshake) bool { return false }
	b.ReportAllocs()
	for b.Loop() {
		stream := NewStream(StreamOptions{Fingerprint: true}, report)
		stream.Up(win)
		stream.Close()
	}
}

// BenchmarkSteadyState is what every chunk after the verdict costs, which is the figure that
// multiplies by the size of a transfer rather than by the number of connections.
func BenchmarkSteadyState(b *testing.B) {
	stream := NewStream(StreamOptions{}, func(Handshake) bool { return false })
	stream.Up([]byte("SSH-2.0-OpenSSH_9.6\r\n"))

	chunk := make([]byte, 32*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(chunk)))
	for b.Loop() {
		if stream.Up(chunk) {
			b.Fatal("a chunk after the verdict asked for the connection to be stopped")
		}
	}
}

// The budget says the hello parse allocates nothing, and the reason it can is that every
// field lands in fixed room inside the returned struct. A parser that started allocating
// would be sizing something by what the network sent, which is the whole class of bug the
// fixed room exists to make impossible -- so this is a correctness claim, not a speed one.
func TestReadingAHelloAllocatesNothing(t *testing.T) {
	for _, held := range captures {
		t.Run(held.name, func(t *testing.T) {
			win := capture(t, held.file)
			allocs := testing.AllocsPerRun(100, func() {
				hello, state := ParseClientHello(win)
				if state != Parsed {
					t.Fatalf("the capture read as %v", state)
				}
				// The name is read out of the struct but not turned into a string: SNI()
				// allocates by definition, and it is called once per connection rather than
				// once per parse.
				if hello.sniLen == 0 {
					t.Fatal("the capture read as finished with no name in it")
				}
			})
			if allocs != 0 {
				t.Errorf("reading a hello allocated %.0f times, want none", allocs)
			}
		})
	}
}

// The same claim for the steady state, which is the other half of the budget: once a verdict
// is in, a chunk costs one field comparison and nothing else.
func TestAChunkAfterTheVerdictAllocatesNothing(t *testing.T) {
	stream := NewStream(StreamOptions{}, func(Handshake) bool { return false })
	stream.Up([]byte("SSH-2.0-OpenSSH_9.6\r\n"))

	chunk := make([]byte, 32*1024)
	allocs := testing.AllocsPerRun(100, func() {
		stream.Up(chunk)
	})
	if allocs != 0 {
		t.Errorf("a chunk after the verdict allocated %.0f times, want none", allocs)
	}
}

// A window filled by a client dripping bytes is the adversarial shape, and what bounds it is
// the count of reads rather than the count of bytes. One connection's worth of work here must
// stay within a small multiple of one honest parse.
func TestDrippingBytesCostsABoundedNumberOfReads(t *testing.T) {
	win := capture(t, "clienthello-go.hex")
	reports := 0
	stream := NewStream(StreamOptions{}, func(Handshake) bool {
		reports++
		return false
	})
	for at := 0; at < len(win) && !stream.done; at++ {
		stream.Up(win[at : at+1])
	}
	if reports != 1 {
		t.Fatalf("a dripped hello was reported %d times, want once", reports)
	}
	if stream.tries != 0 {
		t.Errorf("the stream is still counting %d reads after its verdict", stream.tries)
	}
}

func benchCapture(b *testing.B, file string) []byte {
	b.Helper()
	win, err := readCapture(file)
	if err != nil {
		b.Fatalf("%v", err)
	}
	return win
}
