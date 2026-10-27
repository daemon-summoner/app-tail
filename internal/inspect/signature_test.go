// SPDX-License-Identifier: MIT

package inspect

// What the byte patterns do once they are compiled, and how they reach a connection through
// the window everything else here reads.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/sigscan"
)

// matching is a signature report that records what it was told and how often.
type matching struct {
	seen  []Finding
	where []string
	stops bool
}

func (m *matching) report(found Finding, protocol string) bool {
	m.seen = append(m.seen, found)
	m.where = append(m.where, protocol)
	return m.stops
}

// signatures compiles a set from written entries, failing the test on a fixture that will not
// parse.
func signatures(t *testing.T, entries ...string) *Signatures {
	t.Helper()
	set, err := CompileSignatures(manualSourceForTest, entries)
	if err != nil {
		t.Fatalf("compile the signatures: %v", err)
	}
	if set == nil {
		t.Fatal("compiling real entries built nothing")
	}
	return set
}

// manualSourceForTest is what a finding names, standing in for whatever the runner calls the
// entries somebody typed.
const manualSourceForTest = "your own entries"

func TestAMatchNamesTheSignatureAndTheSetItCameFrom(t *testing.T) {
	set := signatures(t, `a token that must not leave = "hunter2-9f3a1c"`)

	found, ok := set.Match([]byte("POST /upload HTTP/1.1\r\n\r\nhunter2-9f3a1c"))
	if !ok {
		t.Fatal("nothing matched")
	}
	if found.Signal != SignalPayload {
		t.Errorf("the finding carried the signal %q, want %q", found.Signal, SignalPayload)
	}
	if found.Value != "a token that must not leave" {
		t.Errorf("the finding named %q", found.Value)
	}
	if found.Source != manualSourceForTest {
		t.Errorf("the finding came from %q, want %q", found.Source, manualSourceForTest)
	}
	want := "the connection carries a token that must not leave, which is named by your own entries"
	if found.Reason() != want {
		t.Errorf("the reason read %q, want %q", found.Reason(), want)
	}
}

// The bytes are the pattern, and the pattern is often the secret being watched for. A finding
// that carried them would copy that secret into every log line, event and card it reaches.
func TestAMatchNeverCarriesTheBytesThatMatched(t *testing.T) {
	const secret = "hunter2-9f3a1c"
	set := signatures(t, `a token that must not leave = "`+secret+`"`)

	found, ok := set.Match([]byte("....." + secret + "....."))
	if !ok {
		t.Fatal("nothing matched")
	}
	for _, text := range []string{found.Value, found.Source, found.Reason()} {
		if strings.Contains(text, secret) {
			t.Fatalf("a finding carried the pattern's own bytes: %q", text)
		}
	}
}

func TestEntriesThatHoldNothingAreSkippedRatherThanRefused(t *testing.T) {
	// A settings list edited in a text box round-trips through empty rows, so refusing one
	// would make the field impossible to edit.
	set, err := CompileSignatures(manualSourceForTest,
		[]string{"", "   ", `a token = "hunter2-9f3a1c"`, "\t\r\n"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if set.Count() != 1 {
		t.Fatalf("the set holds %d patterns, want 1", set.Count())
	}
}

func TestNothingWrittenCompilesToNoSetAtAll(t *testing.T) {
	set, err := CompileSignatures(manualSourceForTest, []string{"", "   "})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if set != nil {
		t.Fatal("nothing written built a matcher, so a caller cannot tell it from one that is " +
			"switched off")
	}
	if _, ok := set.Match([]byte("anything")); ok {
		t.Error("a set that was never built matched something")
	}
	if set.Count() != 0 {
		t.Errorf("a set that was never built counted %d", set.Count())
	}
}

// An entry that will not parse is refused rather than dropped: a signature is a control the
// user asked for by name, and one silently skipped is a control that stopped applying with
// nothing saying so.
func TestAnEntryThatWillNotParseTakesTheWholeCompileDownWithIt(t *testing.T) {
	set, err := CompileSignatures(manualSourceForTest,
		[]string{`a good one = "hunter2-9f3a1c"`, `a bad one`})
	if err == nil {
		t.Fatal("an entry that is not a signature was accepted")
	}
	if set != nil {
		t.Fatal("a failed compile handed back a matcher")
	}
}

// The parser accepts each line on its own, so the ceiling on how many of them one matcher
// holds can only be reached by the compile.
func TestMorePatternsThanOneMatcherHoldsIsRefusedByTheCompile(t *testing.T) {
	entries := make([]string, 0, sigscan.MaxPatterns+1)
	for i := 0; i <= sigscan.MaxPatterns; i++ {
		entries = append(entries, fmt.Sprintf("pattern %d = %q", i, fmt.Sprintf("mark-%06d", i)))
	}

	set, err := CompileSignatures(manualSourceForTest, entries)
	if err == nil {
		t.Fatalf("%d patterns were accepted, where %d is the most",
			len(entries), sigscan.MaxPatterns)
	}
	if set != nil {
		t.Fatal("a failed compile handed back a matcher")
	}
}

func TestAPatternInTheOpeningBytesIsFoundThroughTheWindow(t *testing.T) {
	var matched matching
	stream := NewStream(StreamOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	}, nil)

	// A plain request whose head parses at once: with signatures on, the window is held past
	// that and the body is read too.
	stream.Up([]byte("POST /upload HTTP/1.1\r\nHost: files.example\r\n\r\n"))
	if len(matched.seen) != 0 {
		t.Fatal("a signature was reported before the window could grow no further")
	}
	stream.Up([]byte("secret=hunter2-9f3a1c&more=1"))
	stream.Up([]byte(strings.Repeat("x", windowSize)))

	if len(matched.seen) != 1 {
		t.Fatalf("the pattern was reported %d times, want once", len(matched.seen))
	}
	if matched.seen[0].Value != "a token" {
		t.Errorf("the report named %q", matched.seen[0].Value)
	}
	// What the connection turned out to be goes with the match: a token leaving over a plain
	// web request and one leaving over something unrecognised are different findings.
	if matched.where[0] != ProtocolHTTP {
		t.Errorf("the report said the connection was %q, want %q", matched.where[0], ProtocolHTTP)
	}
	if stream.win != nil {
		t.Error("the window is still held after the scan")
	}
}

// The window is held past the naming only while there are signatures to read it against. With
// them off it goes back the moment the connection is named, which is the whole defence against
// a client opening thousands of connections and sending one byte down each.
func TestWithoutSignaturesTheWindowStillGoesBackAtTheNaming(t *testing.T) {
	var counted counting
	stream := NewStream(StreamOptions{}, counted.report)
	stream.Up([]byte("GET / HTTP/1.1\r\nHost: files.example\r\n\r\n"))
	if stream.win != nil {
		t.Fatal("the window is held after the naming with no signatures to read it against")
	}

	var matched matching
	held := NewStream(StreamOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	}, counted.report)
	held.Up([]byte("GET / HTTP/1.1\r\nHost: files.example\r\n\r\n"))
	if held.win == nil {
		t.Fatal("the window was let go at the naming, so nothing is left to read the patterns " +
			"against")
	}
}

// Both signals reach a connection that carries both, and each is reported once.
func TestAConnectionIsNamedAndThenReadForPatterns(t *testing.T) {
	var counted counting
	var matched matching
	stream := NewStream(StreamOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	}, counted.report)

	stream.Up([]byte("GET /?q=hunter2-9f3a1c HTTP/1.1\r\nHost: files.example\r\n\r\n"))
	stream.Up([]byte(strings.Repeat("x", windowSize)))

	if len(counted.seen) != 1 {
		t.Fatalf("the connection was named %d times, want once", len(counted.seen))
	}
	if counted.seen[0].Name != "files.example" {
		t.Errorf("the connection was named %q", counted.seen[0].Name)
	}
	if len(matched.seen) != 1 {
		t.Fatalf("the pattern was reported %d times, want once", len(matched.seen))
	}
	// And nothing after the scan is read at all.
	if stream.Up([]byte("hunter2-9f3a1c")) {
		t.Error("a chunk after the scan asked for the connection to be stopped")
	}
	if len(matched.seen) != 1 {
		t.Errorf("the pattern was reported again after the scan")
	}
}

// A stop decided on the name ends the connection there, so the patterns are never read: the
// connection the scan would have described is already over.
func TestAConnectionStoppedOnItsNameIsNeverReadForPatterns(t *testing.T) {
	counted := counting{stops: true}
	var matched matching
	stream := NewStream(StreamOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	}, counted.report)

	if !stream.Up([]byte("GET /?q=hunter2-9f3a1c HTTP/1.1\r\nHost: stopped.example\r\n\r\n")) {
		t.Fatal("a report asking for a stop was not carried back")
	}
	if len(matched.seen) != 0 {
		t.Error("the patterns were read after the connection had already been stopped")
	}
	if stream.win != nil {
		t.Error("the window is still held after the stop")
	}
}

func TestWhatTheSignatureReportSaysIsWhatTheStreamAnswers(t *testing.T) {
	matched := matching{stops: true}
	stream := NewStream(StreamOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	}, nil)

	stream.Up([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	if !stream.Up([]byte(strings.Repeat("hunter2-9f3a1c", 300))) {
		t.Fatal("a signature report asking for a stop was not carried back")
	}
}

// A pattern split across two chunks is still one pattern, because the window is read whole
// rather than a chunk at a time.
func TestAPatternSplitAcrossChunksIsStillFound(t *testing.T) {
	const secret = "hunter2-9f3a1c"
	for cut := 1; cut < len(secret); cut++ {
		var matched matching
		stream := NewStream(StreamOptions{
			Signatures: signatures(t, `a token = "`+secret+`"`),
			Matched:    matched.report,
		}, nil)

		stream.Up([]byte("\xa5\xa5" + secret[:cut]))
		stream.Up([]byte(secret[cut:] + "\xa5\xa5"))
		stream.Up([]byte(strings.Repeat("\xa5", windowSize)))

		if len(matched.seen) != 1 {
			t.Fatalf("a pattern split after %d bytes was reported %d times, want once",
				cut, len(matched.seen))
		}
	}
}

// Signatures with nothing to report them to would be a window held open to answer nobody.
func TestSignaturesWithNowhereToReportReadNothing(t *testing.T) {
	if NewStream(StreamOptions{Signatures: signatures(t, `a token = "abcdefgh"`)}, nil) != nil {
		t.Fatal("a stream with signatures and no report was handed back rather than nothing")
	}
	var matched matching
	if NewStream(StreamOptions{Matched: matched.report}, nil) != nil {
		t.Fatal("a stream with a report and no signatures was handed back rather than nothing")
	}
}

// The datagram paths read the same patterns, because a token leaving over UDP left just the
// same. The budget is the stream's window, spent across as many datagrams as it takes.
func TestDatagramsAreReadAgainstThePatternsUpToTheSameBudget(t *testing.T) {
	var matched matching
	flow := NewDatagrams(DatagramOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	})

	flow.Up([]byte("nothing interesting"))
	if len(matched.seen) != 0 {
		t.Fatal("a datagram carrying nothing was reported")
	}
	flow.Up([]byte("carrying hunter2-9f3a1c along"))
	if len(matched.seen) != 1 {
		t.Fatalf("the pattern was reported %d times, want once", len(matched.seen))
	}

	// Past the budget nothing further is read, so the flow costs a bounded amount however long
	// it runs.
	spent := NewDatagrams(DatagramOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	})
	spent.Up([]byte(strings.Repeat("x", windowSize)))
	before := len(matched.seen)
	spent.Up([]byte("carrying hunter2-9f3a1c along"))
	if len(matched.seen) != before {
		t.Error("a datagram past the flow's budget was still read against the patterns")
	}
}

// A flow is named first and read second, so a match carries what the flow turned out to be.
func TestADatagramMatchSaysWhatTheFlowWasSpeaking(t *testing.T) {
	var counted counting
	var matched matching
	flow := NewDatagrams(DatagramOptions{
		Report:     counted.report,
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	})

	flow.Up(append(dnsQuery("files.example"), []byte("hunter2-9f3a1c")...))
	if len(counted.seen) != 1 || counted.seen[0].Protocol != ProtocolDNS {
		t.Fatalf("the flow was named %v, want one report of %q", counted.seen, ProtocolDNS)
	}
	if len(matched.seen) != 1 {
		t.Fatalf("the pattern was reported %d times, want once", len(matched.seen))
	}
	if matched.where[0] != ProtocolDNS {
		t.Errorf("the report said the flow was %q, want %q", matched.where[0], ProtocolDNS)
	}
}

// A flow whose patterns are the only reason it is read still works out what it is, because a
// match has to say what the flow was speaking. There is nowhere to report the naming itself, so
// it is worked out and kept rather than announced.
func TestAFlowReadOnlyForPatternsIsStillNamedForTheMatch(t *testing.T) {
	var matched matching
	flow := NewDatagrams(DatagramOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	})

	flow.Up(append(dnsQuery("files.example"), []byte("hunter2-9f3a1c")...))

	if len(matched.seen) != 1 {
		t.Fatalf("the pattern was reported %d times, want once", len(matched.seen))
	}
	if matched.where[0] != ProtocolDNS {
		t.Errorf("the report said the flow was %q, want %q", matched.where[0], ProtocolDNS)
	}
}

func TestWhatADatagramSignatureReportSaysIsWhatTheFlowAnswers(t *testing.T) {
	matched := matching{stops: true}
	flow := NewDatagrams(DatagramOptions{
		Signatures: signatures(t, `a token = "hunter2-9f3a1c"`),
		Matched:    matched.report,
	})
	if !flow.Up([]byte("carrying hunter2-9f3a1c along")) {
		t.Fatal("a signature report asking for a stop was not carried back")
	}
}
