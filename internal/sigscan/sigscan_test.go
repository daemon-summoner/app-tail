// SPDX-License-Identifier: MIT

package sigscan

import (
	"fmt"
	"strings"
	"testing"
)

// compile builds a set from written entries, failing the test on anything that will not parse:
// every test here is about what the matcher does, so a typo in a fixture must read as a broken
// fixture rather than as a matcher that found nothing.
func compile(t *testing.T, entries ...string) *Set {
	t.Helper()
	written := make([]Signature, 0, len(entries))
	for _, entry := range entries {
		sig, err := Parse(entry)
		if err != nil {
			t.Fatalf("parse %q: %v", entry, err)
		}
		written = append(written, sig)
	}
	set, err := Compile(written)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return set
}

func TestAPatternIsFoundWhereverItStartsInTheBuffer(t *testing.T) {
	set := compile(t, `a token = "hunter2-9f3a1c"`)

	for _, buf := range []string{
		"hunter2-9f3a1c",
		"GET /?q=hunter2-9f3a1c HTTP/1.1\r\n",
		strings.Repeat("x", 4000) + "hunter2-9f3a1c",
	} {
		name, ok := set.Match([]byte(buf))
		if !ok {
			t.Fatalf("the pattern was not found in %d bytes ending %q", len(buf), tail(buf))
		}
		if name != "a token" {
			t.Fatalf("the match named %q, want %q", name, "a token")
		}
	}
}

func TestABufferThatDoesNotCarryThePatternIsNoMatch(t *testing.T) {
	set := compile(t, `a token = "hunter2-9f3a1c"`)

	// Every prefix of the pattern, so a matcher that reported on a partial walk fails here.
	for cut := 1; cut < len("hunter2-9f3a1c"); cut++ {
		if _, ok := set.Match([]byte("hunter2-9f3a1c"[:cut])); ok {
			t.Fatalf("the first %d bytes of the pattern matched on their own", cut)
		}
	}
	if _, ok := set.Match([]byte("hunter2-9f3a1d")); ok {
		t.Fatal("a pattern differing in its last byte matched")
	}
	if _, ok := set.Match(nil); ok {
		t.Fatal("an empty buffer matched")
	}
}

func TestAPartialMatchThatBreaksOffDoesNotStopALaterRealOne(t *testing.T) {
	// The walk gets three bytes into the pattern, meets a byte the node cannot take, and has
	// to fall back to somewhere the pattern can still start. Without the fallback links the
	// second start is missed entirely.
	set := compile(t, `repeated = "abcd"`)

	name, ok := set.Match([]byte("abcabcd"))
	if !ok {
		t.Fatal("a pattern starting after a broken-off attempt was not found")
	}
	if name != "repeated" {
		t.Fatalf("the match named %q, want %q", name, "repeated")
	}
}

func TestAPatternEndingInsideAnotherIsStillReported(t *testing.T) {
	// "bcde" ends part-way along the walk of "abcdefg", at a node that is not itself an end.
	// Only the suffix links reach it, so a matcher without them reports nothing here.
	set := compile(t, `the long one = "abcdefg"`, `the short one = "bcde"`)

	name, ok := set.Match([]byte("xxabcde"))
	if !ok {
		t.Fatal("a pattern ending inside a longer one's walk was not found")
	}
	if name != "the short one" {
		t.Fatalf("the match named %q, want %q", name, "the short one")
	}
}

func TestWhereTwoPatternsEndTogetherTheLongerIsReported(t *testing.T) {
	set := compile(t, `the long one = "xabcd"`, `the short one = "abcd"`)

	name, ok := set.Match([]byte("zxabcd"))
	if !ok {
		t.Fatal("nothing matched")
	}
	if name != "the long one" {
		t.Fatalf("the match named %q, want %q", name, "the long one")
	}
}

func TestTheEarliestPatternToEndIsTheOneReported(t *testing.T) {
	set := compile(t, `later = "zzzz"`, `earlier = "aaaa"`)

	name, ok := set.Match([]byte("--aaaa--zzzz--"))
	if !ok {
		t.Fatal("nothing matched")
	}
	if name != "earlier" {
		t.Fatalf("the match named %q, want %q -- the report follows the buffer, not the list",
			name, "earlier")
	}
}

func TestEveryOneOfManyPatternsIsFoundInTheOneWalk(t *testing.T) {
	entries := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		entries = append(entries, fmt.Sprintf("pattern %d = %q", i, fmt.Sprintf("mark-%04d", i)))
	}
	set := compile(t, entries...)

	if set.Count() != 200 {
		t.Fatalf("the set holds %d patterns, want 200", set.Count())
	}
	for i := 0; i < 200; i++ {
		name, ok := set.Match([]byte("noise " + fmt.Sprintf("mark-%04d", i) + " noise"))
		if !ok {
			t.Fatalf("pattern %d was not found", i)
		}
		if want := fmt.Sprintf("pattern %d", i); name != want {
			t.Fatalf("the match named %q, want %q", name, want)
		}
	}
}

func TestBytesThatAreNotTextAreMatchedAsBytes(t *testing.T) {
	set := compile(t, `a marker = "MARK\x00\xff\r\n"`)

	if _, ok := set.Match([]byte("....MARK\x00\xff\r\n....")); !ok {
		t.Fatal("a pattern written with escapes did not match the bytes it names")
	}
	// The escape must be one byte rather than the four characters that wrote it.
	if _, ok := set.Match([]byte(`MARK\x00\xff\r\n`)); ok {
		t.Fatal("the text of the escapes matched, so the pattern was never unescaped")
	}
}

func TestMatchingIsExactAboutCase(t *testing.T) {
	set := compile(t, `a token = "SecretValue"`)

	if _, ok := set.Match([]byte("xx secretvalue xx")); ok {
		t.Fatal("a pattern matched text differing only in case")
	}
	if _, ok := set.Match([]byte("xx SecretValue xx")); !ok {
		t.Fatal("a pattern did not match the exact text it names")
	}
}

func TestTwoEntriesWithTheSameBytesAreOnePatternUnderTheFirstName(t *testing.T) {
	set := compile(t, `written first = "abcdefgh"`, `written second = "abcdefgh"`)

	if set.Count() != 1 {
		t.Fatalf("the set holds %d patterns, want 1", set.Count())
	}
	name, ok := set.Match([]byte("--abcdefgh--"))
	if !ok {
		t.Fatal("nothing matched")
	}
	if name != "written first" {
		t.Fatalf("the match named %q, want %q", name, "written first")
	}
}

func TestASetWithNothingInItIsNoSetRatherThanAnEmptyOne(t *testing.T) {
	set, err := Compile(nil)
	if err != nil {
		t.Fatalf("compile nothing: %v", err)
	}
	if set != nil {
		t.Fatal("compiling nothing built a matcher, so a caller cannot tell it from one that " +
			"is switched off")
	}
	// A nil set answers rather than panicking, which is what makes that the caller's one check.
	if _, ok := set.Match([]byte("anything at all")); ok {
		t.Fatal("a set that holds nothing matched something")
	}
	if set.Count() != 0 {
		t.Fatalf("a set that holds nothing counted %d", set.Count())
	}
}

func TestMorePatternsThanOneSetHoldsIsRefused(t *testing.T) {
	written := make([]Signature, 0, MaxPatterns+1)
	for i := 0; i <= MaxPatterns; i++ {
		written = append(written, Signature{
			Name:    fmt.Sprintf("pattern %d", i),
			Pattern: []byte(fmt.Sprintf("mark-%06d", i)),
		})
	}
	_, err := Compile(written)
	if err == nil {
		t.Fatalf("%d patterns were accepted, where %d is the most", len(written), MaxPatterns)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d signatures is more than the %d", MaxPatterns+1, MaxPatterns)) {
		t.Fatalf("the refusal was %q, which does not say how many is the most", err)
	}
	// One fewer is the most, and it builds.
	set, err := Compile(written[:MaxPatterns])
	if err != nil || set.Count() != MaxPatterns {
		t.Fatalf("Compile of exactly %d patterns = %d, %v", MaxPatterns, set.Count(), err)
	}
}

func TestAPatternOutsideTheAcceptedLengthsIsRefusedByTheCompilerToo(t *testing.T) {
	// Parse refuses these where they are written; the compiler refuses them again, so a
	// signature reaching it another way cannot build a matcher that reports on every buffer.
	for _, sig := range []Signature{
		{Name: "too short", Pattern: []byte("ab")},
		{Name: "too long", Pattern: make([]byte, MaxBytes+1)},
	} {
		_, err := Compile([]Signature{sig})
		if err == nil {
			t.Fatalf("a %d-byte pattern was accepted", len(sig.Pattern))
		}
		if !strings.Contains(err.Error(), sig.Name) || !strings.Contains(err.Error(), "outside the") {
			t.Fatalf("the refusal was %q, which does not name the signature and the accepted lengths", err)
		}
	}
	// The bounds themselves are inside.
	for _, sig := range []Signature{
		{Name: "shortest", Pattern: make([]byte, MinBytes)},
		{Name: "longest", Pattern: make([]byte, MaxBytes)},
	} {
		if _, err := Compile([]Signature{sig}); err != nil {
			t.Fatalf("a %d-byte pattern was refused: %v", len(sig.Pattern), err)
		}
	}
}

func TestWhatIsWrittenIsReadBackAsANamedAndBytes(t *testing.T) {
	sig, err := Parse(`  a token that must not leave  =  "hunter2-9f3a1c"  `)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sig.Name != "a token that must not leave" {
		t.Fatalf("the name read back as %q", sig.Name)
	}
	if string(sig.Pattern) != "hunter2-9f3a1c" {
		t.Fatalf("the bytes read back as %q", sig.Pattern)
	}
}

func TestQuotingIsWhatKeepsASpaceAtTheEndOfAPattern(t *testing.T) {
	sig, err := Parse(`a header = "Authorization: "`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(sig.Pattern) != "Authorization: " {
		t.Fatalf("the bytes read back as %q, so the trailing space did not survive", sig.Pattern)
	}
}

func TestAnEntryTheMatcherCouldNotBuildFromSaysWhatIsWrongWithIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		says  string
	}{
		{"no equals sign", `just some words`, "not a signature"},
		{"nothing named", `= "abcdefgh"`, "nothing before the equals sign"},
		{"a name too long", strings.Repeat("n", maxName+1) + ` = "abcdefgh"`, "longer than"},
		{"a name that is not text", "a\tname = \"abcdefgh\"", "not plain text"},
		{"bytes that are not quoted", `a name = abcdefgh`, "not a quoted string"},
		{"bytes that are quoted wrong", `a name = "abcdefgh`, "not a quoted string"},
		{"an escape that is not one", `a name = "ab\qcd"`, "not a quoted string"},
		{"too few bytes", `a name = "abc"`, "or more are needed"},
		{"too many bytes", `a name = "` + strings.Repeat("x", MaxBytes+1) + `"`, "is the most"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.entry)
			if err == nil {
				t.Fatalf("%q was accepted", tc.entry)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("the refusal was %q, which does not say %q", err, tc.says)
			}
		})
	}
}

// tail is the end of a buffer, for a failure message that must not print four kilobytes.
func tail(buf string) string {
	if len(buf) <= 24 {
		return buf
	}
	return "…" + buf[len(buf)-24:]
}

// The first equals sign is where the name ends, so the bytes may hold as many as they like
// and a name may hold none: a name with one in it reads as bytes that were never quoted, and
// the refusal says so rather than reporting a match under half a name.
func TestTheFirstEqualsSignEndsTheNameAndTheBytesMayHoldMore(t *testing.T) {
	sig, err := Parse(`a query = "a=b&c=d"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sig.Name != "a query" || string(sig.Pattern) != "a=b&c=d" {
		t.Fatalf("read back as %q = %q", sig.Name, sig.Pattern)
	}

	_, err = Parse(`x=y = "abcdefgh"`)
	if err == nil || !strings.Contains(err.Error(), "not a quoted string") {
		t.Fatalf("a name holding an equals sign was read as %v, want the bytes refused as unquoted", err)
	}
}

// Every byte the quoting can write is read back as that byte: a NUL, a carriage return and a
// byte above ASCII arrive in the pattern as themselves, and a name at its full length is kept.
func TestBytesThatAreNotTextAreReadBackAsThemselves(t *testing.T) {
	sig, err := Parse(strings.Repeat("n", maxName) + ` = "MARK\x00\r\n\xff"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []byte{'M', 'A', 'R', 'K', 0, '\r', '\n', 0xff}; string(sig.Pattern) != string(want) {
		t.Fatalf("the bytes read back as %v, want %v", sig.Pattern, want)
	}
	if len(sig.Name) != maxName {
		t.Fatalf("a name of exactly %d characters was read back as %d", maxName, len(sig.Name))
	}

	// And the bounds on the bytes are inclusive where they are written.
	if _, err := Parse(`shortest = "` + strings.Repeat("a", MinBytes) + `"`); err != nil {
		t.Fatalf("a pattern of exactly %d bytes was refused: %v", MinBytes, err)
	}
	if _, err := Parse(`longest = "` + strings.Repeat("a", MaxBytes) + `"`); err != nil {
		t.Fatalf("a pattern of exactly %d bytes was refused: %v", MaxBytes, err)
	}
}

// The report follows the buffer: a general pattern that ends inside a more specific one ends
// first, and it is the one reported even though the specific one was written first and is
// longer. The longer-wins rule only applies where two end on the same byte.
func TestAPatternThatEndsFirstBeatsALongerOneThatEndsLater(t *testing.T) {
	set := compile(t, `specific = "xabcdy"`, `general = "abcd"`)

	name, ok := set.Match([]byte("--xabcdy--"))
	if !ok {
		t.Fatal("nothing matched")
	}
	if name != "general" {
		t.Fatalf("the match named %q, want %q -- it ends a byte earlier", name, "general")
	}
}

// The ceiling of what one set holds: as many patterns as MaxPatterns allows, each as long as
// MaxBytes allows. The arena is sized from the total of the patterns -- 512 x 256 nodes at
// the top -- so this is where a sizing mistake or an index wider than the arena shows: it
// compiles, and a window is walked over it, without a panic.
func TestTheCeilingOfPatternsAtTheCeilingOfLengthCompilesAndWalks(t *testing.T) {
	written := make([]Signature, 0, MaxPatterns)
	for i := 0; i < MaxPatterns; i++ {
		pattern := make([]byte, MaxBytes)
		pattern[0] = byte(i)
		pattern[1] = byte(i >> 8)
		for j := 2; j < len(pattern); j++ {
			pattern[j] = byte(i) ^ byte(j)*17
		}
		written = append(written, Signature{Name: fmt.Sprintf("ceiling %d", i), Pattern: pattern})
	}
	set, err := Compile(written)
	if err != nil {
		t.Fatalf("Compile at the ceiling: %v", err)
	}
	if set.Count() != MaxPatterns {
		t.Fatalf("Count = %d, want %d", set.Count(), MaxPatterns)
	}

	// A window of the size the one caller reads, none of it matching, and the last pattern
	// appended so the hit path is walked at the ceiling too.
	window := make([]byte, 4096)
	for i := range window {
		window[i] = byte(i*31 + 7)
	}
	if _, ok := set.Match(window); ok {
		t.Fatal("nothing of this window is in the set")
	}
	if _, ok := set.Match(append(window, written[MaxPatterns/2].Pattern...)); !ok {
		t.Fatal("the window carries a pattern of the set")
	}
}
