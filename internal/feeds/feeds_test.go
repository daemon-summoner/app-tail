// SPDX-License-Identifier: MIT

package feeds

// Downloading a file, keeping it, and the two hazards that come with it: a download that
// resolves through app-tail itself, and an address a download must never be made from.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

const testListBody = "0.0.0.0 doubleclick.net\n0.0.0.0 ads.example.com\n"

// testMaxBytes is the cap these tests fetch against. It is small so the over-the-cap test
// does not have to serve sixty megabytes to prove one comparison.
const testMaxBytes = 64 << 10

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// lookups counts what the machine-wide resolver was asked for over the whole package.
var lookups atomic.Int32

// TestMain puts a resolver that answers nothing in place of the machine's, once, before any
// test runs. Every server here is dialled at a literal address, so nothing in this package
// needs a name resolved and a lookup is always a fault worth counting.
//
// It is installed here rather than inside the one test that counts, because the standard
// library reads this while a connection is being dialled: a test that swapped it while another
// test's dial was still in flight would be writing what that dial is reading, whatever either
// test is about.
func TestMain(m *testing.M) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, io.EOF
		},
	}
	os.Exit(m.Run())
}

// listServer answers one URL, recording what it was asked with so the conditional request
// can be checked. serve decides the response.
type listServer struct {
	*httptest.Server
	mu    sync.Mutex
	etags []string
}

// asked returns the If-None-Match header of every request so far.
func (s *listServer) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.etags)
}

func serveList(t *testing.T, serve http.HandlerFunc) *listServer {
	t.Helper()
	s := &listServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.etags = append(s.etags, r.Header.Get("If-None-Match"))
		s.mu.Unlock()
		serve(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestDownloadingAFileReportsWhatCameBackAndWhatToSendNextTime(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		io.WriteString(w, testListBody)
	})

	got, err := Fetch(context.Background(), srv.Client(), srv.URL, State{}, testMaxBytes)

	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.Body) != testListBody {
		t.Errorf("body = %q, want the file as served", got.Body)
	}
	if got.NotModified {
		t.Error("a 200 was read as the cached copy still being current")
	}
	if got.ETag != `"v1"` || got.LastModified != "Wed, 21 Oct 2026 07:28:00 GMT" {
		t.Errorf("tags = %q / %q, want what the server said so the next request can be conditional",
			got.ETag, got.LastModified)
	}
}

// The whole point of keeping the tags: Hagezi Ultimate is tens of megabytes, and a file
// that has not changed has to cost one round trip rather than another download.
func TestAnUnchangedFileCostsOneRequestAndKeepsTheCopyOnDisk(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, testListBody)
	})

	got, err := Fetch(context.Background(), srv.Client(), srv.URL, State{ETag: `"v1"`}, testMaxBytes)

	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !got.NotModified {
		t.Fatal("a 304 was not read as the cached copy still being current")
	}
	if len(got.Body) != 0 {
		t.Errorf("body = %q, want nothing: a 304 carries no file", got.Body)
	}
}

// The conditional request has to carry what the server tagged the copy with, or every
// refresh is a full download of a file that has not changed.
func TestTheRequestCarriesTheTagsTheServerGaveLastTime(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, testListBody)
	})

	if _, err := Fetch(context.Background(), srv.Client(), srv.URL,
		State{ETag: `"v7"`, LastModified: "Wed, 21 Oct 2026 07:28:00 GMT"}, testMaxBytes); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if asked := srv.asked(); len(asked) != 1 || asked[0] != `"v7"` {
		t.Errorf("the request carried %v as its tag, want the one the previous copy was given", asked)
	}
}

func TestAFileTheServerWillNotServeIsAFailureThatNamesTheStatus(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})

	_, err := Fetch(context.Background(), srv.Client(), srv.URL, State{}, testMaxBytes)

	if err == nil {
		t.Fatal("a 404 was accepted as a file")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %q, which does not say what the server answered", err)
	}
}

// A body read to the cap and stored would be a file missing its last half, which applies
// less than the user asked for and looks exactly like one that is up to date.
func TestABodyLargerThanTheCapIsRefusedRatherThanTruncated(t *testing.T) {
	chunk := strings.Repeat("0.0.0.0 ads.example.com\n", 1024)
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		for written := 0; written <= testMaxBytes; written += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	})

	_, err := Fetch(context.Background(), srv.Client(), srv.URL, State{}, testMaxBytes)

	if err == nil {
		t.Fatal("a body past the cap was accepted")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %q, which does not say the file was too big", err)
	}
}

// A body exactly at the cap is a whole file, so it has to be accepted: the limit reader
// takes one byte past the cap precisely so the two cases can be told apart.
func TestABodyExactlyAtTheCapIsAccepted(t *testing.T) {
	body := strings.Repeat("a", testMaxBytes)
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	})

	got, err := Fetch(context.Background(), srv.Client(), srv.URL, State{}, testMaxBytes)

	if err != nil {
		t.Fatalf("a body exactly at the cap was refused: %v", err)
	}
	if len(got.Body) != testMaxBytes {
		t.Errorf("body is %d bytes, want the whole %d", len(got.Body), testMaxBytes)
	}
}

// The hazard the pinned dialer exists for: with the machine-wide resolver on, this process
// is what the system resolver answers with, so a download that resolves its own hostname
// waits on the answer it is producing.
func TestTheDialerNeverAsksTheSystemResolver(t *testing.T) {
	before := lookups.Load()

	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, testListBody)
	})
	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	client := PinnedClient([]netip.Addr{addr.Addr()}, addr.Port(), time.Minute)
	defer client.CloseIdleConnections()

	// The URL names a host that resolves nowhere. Only the pinned address makes this
	// reachable, so an answer at all is the proof.
	got, err := Fetch(context.Background(), client, "http://lists.invalid/pro.txt", State{}, testMaxBytes)

	if err != nil {
		t.Fatalf("Fetch through the pinned dialer: %v", err)
	}
	if string(got.Body) != testListBody {
		t.Errorf("body = %q, want the file the pinned address served", got.Body)
	}
	if n := lookups.Load() - before; n != 0 {
		t.Errorf("the system resolver was asked %d times; while app-tail is that resolver, that is a deadlock", n)
	}
}

// A pinned client with nowhere to dial has to say so rather than fall back to resolving the
// hostname, which is the fallback that would reintroduce the deadlock.
func TestAFileWhoseHostResolvedToNothingFailsRatherThanFallingBack(t *testing.T) {
	client := PinnedClient(nil, 443, time.Minute)
	defer client.CloseIdleConnections()

	_, err := Fetch(context.Background(), client, "http://lists.invalid/pro.txt", State{}, testMaxBytes)

	if err == nil {
		t.Fatal("a client with no address to dial reached something")
	}
	if !strings.Contains(err.Error(), "resolved to no address") {
		t.Errorf("error = %q, which does not say the hostname produced nothing", err)
	}
}

// Every address the name resolved to is tried by the dialer in turn, so one reachable
// address behind an unreachable one still has to serve the file.
func TestTheDialerTriesEveryPinnedAddress(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, testListBody)
	})
	live := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	// 192.0.2.0/24 is the range reserved for documentation, so nothing answers on it.
	client := PinnedClient([]netip.Addr{netip.MustParseAddr("192.0.2.1"), live.Addr()}, live.Port(), time.Minute)
	defer client.CloseIdleConnections()

	got, err := Fetch(context.Background(), client, "http://lists.invalid/pro.txt", State{}, testMaxBytes)

	if err != nil {
		t.Fatalf("Fetch with a dead address first: %v", err)
	}
	if string(got.Body) != testListBody {
		t.Errorf("body = %q, want the file the second address served", got.Body)
	}
}

// The fetch is where this process dials somewhere a caller named, deliberately without the
// system proxy and without app-tail's own resolver, so nothing else is placed to refuse it.
// What it must not become is a way to ask this machine's own services or a tailnet host a
// question and read the answer back out of the byte count the view reports.
func TestAFileIsNotFetchedFromAnAddressThatIsNotOnTheInternet(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		says string
	}{
		{"this machine", "127.0.0.1", "loopback"},
		{"this machine over v6", "::1", "loopback"},
		{"the cloud metadata address", "169.254.169.254", "link-local"},
		{"a link-local v6 address", "fe80::1", "link-local"},
		{"a home network", "192.168.1.1", "private network"},
		{"a corporate network", "10.0.0.5", "private network"},
		{"the third private range", "172.16.9.9", "private network"},
		{"a tailnet address", "100.101.102.103", "tailnet"},
		{"nowhere at all", "0.0.0.0", "no host"},
		{"multicast", "224.0.0.1", "multicast"},
		{"interface-local multicast", "ff01::1", "multicast"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)

			err := Fetchable(addr)

			if err == nil {
				t.Fatalf("Fetchable(%s) = nil; a file would be downloaded from it", tc.addr)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Fetchable(%s) said %q, which does not name why", tc.addr, err)
			}
		})
	}
}

// A zero address is not an address at all, and the guard has to say that rather than let it
// through to a dialer that would report something unrelated.
func TestAnAddressThatIsNotOneIsRefused(t *testing.T) {
	err := Fetchable(netip.Addr{})

	if err == nil {
		t.Fatal("the zero address was accepted")
	}
	if !strings.Contains(err.Error(), "not an address") {
		t.Errorf("error = %q, which does not say what is wrong with it", err)
	}
}

// A private address written in the v4-in-v6 form is the same machine as the v4 one, and a
// guard that unmapped only some of its cases would be a guard with a way past it.
func TestAPrivateAddressInTheSixFormIsRefused(t *testing.T) {
	if err := Fetchable(netip.MustParseAddr("::ffff:10.0.0.5")); err == nil {
		t.Fatal("::ffff:10.0.0.5 was accepted; that is 10.0.0.5 written another way")
	}
}

// The refusal has to leave the ordinary case alone, or nothing downloads at all.
func TestAFileIsStillFetchedFromAnOrdinaryInternetAddress(t *testing.T) {
	for _, raw := range []string{"93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"} {
		if err := Fetchable(netip.MustParseAddr(raw)); err != nil {
			t.Errorf("Fetchable(%s) = %v; that is where files actually live", raw, err)
		}
	}
}

// The index describes files that can be downloaded again, so a corrupt one must not stop
// the agent starting -- and must not be read as "every copy is current" either.
func TestAnUnreadableIndexStartsOverRatherThanRefusingToStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, IndexName), []byte("{not json"), config.FileMode); err != nil {
		t.Fatalf("write a corrupt index: %v", err)
	}

	c := NewCache(quietLogger(), dir, time.Now)

	if st := c.StateOf("test"); !st.FetchedAt.IsZero() {
		t.Errorf("the corrupt index was read as knowledge about a file: %+v", st)
	}
	if !c.Due("test", c.StateOf("test"), time.Hour) {
		t.Error("a file the corrupt index said nothing about was not due")
	}
}

// What one round learned has to survive a restart, or every start re-downloads everything.
func TestWhatIsKnownAboutACopySurvivesReopeningTheDirectory(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	first := NewCache(quietLogger(), dir, func() time.Time { return at })
	if err := first.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	first.SetState("test", State{ETag: `"v1"`, FetchedAt: at, Bytes: 42, Rules: 2})

	again := NewCache(quietLogger(), dir, func() time.Time { return at })

	st := again.StateOf("test")
	if st.ETag != `"v1"` || st.Rules != 2 || !st.FetchedAt.Equal(at) {
		t.Errorf("what was read back is %+v, want what the first round recorded", st)
	}
}

// The copy on disk is what keeps applying when the network is gone, so it has to be exactly
// what was downloaded and it has to survive the index being rewritten around it.
func TestACopyIsStoredAndReadBackUnchanged(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if err := c.Store("test", []byte(testListBody)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	c.SetState("test", State{FetchedAt: time.Now(), Bytes: len(testListBody)})

	got, err := c.Read("test")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != testListBody {
		t.Errorf("read back %q, want what was stored", got)
	}
}

// An id is a slug the catalog controls, but the function is what makes that a property of
// the code rather than of every caller: a path separator in one must not reach outside the
// directory.
func TestAnIdCannotNameAFileOutsideTheDirectory(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)

	path := c.Path("../../etc/passwd")

	if got := filepath.Dir(path); got != dir {
		t.Errorf("the copy would live in %s, want %s", got, dir)
	}
}

// Deleting an entry has to take its download with it, or the disk keeps a copy of a file
// nothing points at any more.
func TestForgettingAnEntryRemovesItsDownloadedCopy(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := c.Store("test", []byte(testListBody)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	c.SetState("test", State{FetchedAt: time.Now()})

	if err := c.Forget("test"); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	if _, err := os.Stat(c.Path("test")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the downloaded copy is still there: %v", err)
	}
	if st := c.StateOf("test"); st != (State{}) {
		t.Errorf("what was known about the entry survived it: %+v", st)
	}
}

// Forgetting something the index never held is not a failure: the reconcile calls this for
// every entry the user removed, and one that was never downloaded is the ordinary case.
func TestForgettingSomethingNeverDownloadedIsNotAFailure(t *testing.T) {
	c := NewCache(quietLogger(), t.TempDir(), time.Now)

	if err := c.Forget("never-seen"); err != nil {
		t.Errorf("Forget on an unknown entry = %v, want nothing to have gone wrong", err)
	}
}

// The three ways a copy is due, and the one way it is not. Each is a real state: never
// fetched, fetched long enough ago, and fetched but no longer on disk.
func TestWhenACopyIsDue(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	c := NewCache(quietLogger(), dir, func() time.Time { return now })
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := c.Store("test", []byte(testListBody)); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if !c.Due("test", State{}, time.Hour) {
		t.Error("a copy that was never fetched is not due")
	}
	if !c.Due("test", State{FetchedAt: now.Add(-2 * time.Hour)}, time.Hour) {
		t.Error("a copy older than the interval is not due")
	}
	if c.Due("test", State{FetchedAt: now.Add(-time.Minute)}, time.Hour) {
		t.Error("a copy fetched a minute ago is due, which is a download every round")
	}
	if !c.Due("gone", State{FetchedAt: now.Add(-time.Minute)}, time.Hour) {
		t.Error("a copy the index remembers but the disk does not have is not due")
	}
}

// A write that lands leaves no temporary file behind, and one that replaces an existing copy
// leaves the previous one only if the rename never happened.
func TestWritingAFileLeavesNothingBehindIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")

	if err := WriteFile(path, []byte("first")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := WriteFile(path, []byte("second")); err != nil {
		t.Fatalf("WriteFile again: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "list.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want only the file itself", names)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the file: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("the file holds %q, want the second write", got)
	}
}

// A directory that cannot be created is a failure the caller has to see: a refresh that
// silently downloaded into nowhere would report success and block nothing.
func TestADirectoryThatCannotBeMadeIsAFailure(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("in the way"), config.FileMode); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	c := NewCache(quietLogger(), filepath.Join(blocked, "feeds"), time.Now)

	if err := c.Prepare(); err == nil {
		t.Fatal("a directory that cannot exist was prepared without complaint")
	}
}

// The view asks for the whole index at once and reads it while rounds keep recording into it,
// so what it gets has to be a copy rather than the map the cache keeps writing to.
func TestTheWholeIndexIsHandedOutAsACopy(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	at := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	c.SetState("one", State{ETag: `"v1"`, FetchedAt: at, Rules: 2})
	c.SetState("two", State{ETag: `"v2"`, FetchedAt: at, Rules: 7})

	snap := c.Snapshot()

	if len(snap) != 2 || snap["one"].Rules != 2 || snap["two"].Rules != 7 {
		t.Fatalf("the index reads as %+v, want both entries as they were recorded", snap)
	}
	delete(snap, "one")
	snap["two"] = State{}
	if st := c.StateOf("one"); st.Rules != 2 {
		t.Errorf("dropping an entry from the copy dropped it from the cache: %+v", st)
	}
	if st := c.StateOf("two"); st.Rules != 7 {
		t.Errorf("overwriting an entry in the copy overwrote it in the cache: %+v", st)
	}
	if got := c.Dir(); got != dir {
		t.Errorf("Dir() = %s, want %s", got, dir)
	}
}

// An index holding a JSON null decodes to no map at all. Read as one it would panic the first
// time a round recorded anything, so it has to come back as an empty index instead.
func TestAnIndexHoldingNothingIsAnEmptyIndexRatherThanNoIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, IndexName), []byte("null\n"), config.FileMode); err != nil {
		t.Fatalf("write the index: %v", err)
	}

	c := NewCache(quietLogger(), dir, time.Now)
	c.SetState("test", State{Rules: 3})

	if st := c.StateOf("test"); st.Rules != 3 {
		t.Errorf("recording against an index holding nothing produced %+v", st)
	}
}

// The copies are what enforce; the index only says whether they are current. An index that
// cannot be written must therefore leave the round intact -- the cost is re-downloading on the
// next start, not losing what this round learned.
func TestWhatARoundLearnedSurvivesAnIndexThatCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// A directory where the index file goes: the rename that replaces it cannot land.
	if err := os.Mkdir(filepath.Join(dir, IndexName), config.DirMode); err != nil {
		t.Fatalf("put a directory where the index goes: %v", err)
	}

	c.SetState("test", State{ETag: `"v1"`, Rules: 9})

	if st := c.StateOf("test"); st.Rules != 9 {
		t.Errorf("what the round learned is %+v, want it kept in memory regardless of the index", st)
	}
}

// Forgetting an entry whose copy will not go away has to report it: the caller removed the
// feed from the catalog, and a file still on disk under an id nothing points at is the state
// somebody has to be told about.
func TestForgettingAnEntryWhoseCopyCannotBeRemovedSaysSo(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(quietLogger(), dir, time.Now)
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	c.SetState("test", State{FetchedAt: time.Now()})
	// A directory that is not empty cannot be removed, which is what the copy's path is now.
	if err := os.Mkdir(c.Path("test"), config.DirMode); err != nil {
		t.Fatalf("put a directory where the copy goes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(c.Path("test"), "held"), []byte("x"), config.FileMode); err != nil {
		t.Fatalf("fill the directory: %v", err)
	}

	err := c.Forget("test")

	if err == nil {
		t.Fatal("Forget reported success while the copy is still on disk")
	}
	if !strings.Contains(err.Error(), "remove the downloaded copy of test") {
		t.Errorf("error = %q, which does not name what could not be removed", err)
	}
}

// A file cannot be written where its directory cannot exist, and the caller has to see that
// rather than a later read failing for a reason that names nothing.
func TestAFileIsNotWrittenWhereItsDirectoryCannotExist(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("in the way"), config.FileMode); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}

	err := WriteFile(filepath.Join(blocked, "feeds", "list.txt"), []byte(testListBody))

	if err == nil {
		t.Fatal("a file was written under a path that is a file")
	}
	if !strings.Contains(err.Error(), "create ") {
		t.Errorf("error = %q, which does not name the directory that could not be made", err)
	}
}

// A directory nothing may write into is where a temporary file cannot be created, and the
// write has to stop there rather than report a copy that is not on disk.
func TestAFileIsNotWrittenIntoADirectoryNothingMayWriteTo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(dir, config.DirMode); err != nil {
		t.Fatalf("make the directory to close: %v", err)
	}
	fileowntest.CloseDirectory(t, dir)

	err := WriteFile(filepath.Join(dir, "list.txt"), []byte(testListBody))

	if err == nil {
		t.Fatal("a file was written into a directory nothing may write to")
	}
	if !strings.Contains(err.Error(), "temporary file") {
		t.Errorf("error = %q, which does not say what could not be created", err)
	}
}

// The rename is the step that makes the write visible. One that cannot land is a failure, and
// it must not leave the temporary file behind: the directory is scanned for stray copies.
func TestAWriteThatCannotBeRenamedIntoPlaceLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "list.txt")
	if err := os.Mkdir(target, config.DirMode); err != nil {
		t.Fatalf("put a directory where the file goes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "held"), []byte("x"), config.FileMode); err != nil {
		t.Fatalf("fill the directory: %v", err)
	}

	err := WriteFile(target, []byte(testListBody))

	if err == nil {
		t.Fatal("a file was written over a directory that is not empty")
	}
	if !strings.Contains(err.Error(), "replace ") {
		t.Errorf("error = %q, which does not name the step that failed", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read the directory: %v", readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".feed-") {
			t.Errorf("the failed write left %s behind", e.Name())
		}
	}
}

// An address that is not one is refused before a request is built, so the failure names the
// address rather than arriving as a transport error with no context.
func TestAnAddressNoRequestCanBeBuiltFromIsRefused(t *testing.T) {
	client := PinnedClient([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, 443, time.Minute)
	defer client.CloseIdleConnections()

	_, err := Fetch(context.Background(), client, "http://lists.example/\x7f", State{}, testMaxBytes)

	if err == nil {
		t.Fatal("a request was built from an address that is not one")
	}
	if !strings.Contains(err.Error(), "ask ") {
		t.Errorf("error = %q, which does not name the address that could not be asked for", err)
	}
}

// A body that stops part way through is not a short list, it is a failure: accepted, it would
// replace a complete copy with half of one and quietly stop blocking the rest.
func TestABodyThatStopsPartWayThroughIsAFailureRatherThanAShortFile(t *testing.T) {
	srv := serveList(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		io.WriteString(w, testListBody)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	client := PinnedClient([]netip.Addr{addr.Addr()}, addr.Port(), time.Minute)
	defer client.CloseIdleConnections()

	_, err := Fetch(context.Background(), client, srv.URL, State{}, testMaxBytes)

	if err == nil {
		t.Fatal("half a body was accepted as the whole file")
	}
	if !strings.Contains(err.Error(), "read ") {
		t.Errorf("error = %q, which does not say the body could not be read", err)
	}
}

// Every address that failed reaches the caller, not just the last one: a download that could
// not be made is diagnosed from what each address did.
func TestADownloadWithNoReachableAddressReportsWhatEachOneDid(t *testing.T) {
	// 192.0.2.0/24 is the range reserved for documentation, so nothing answers on it. The
	// port is one nothing listens on either, so the dial is refused rather than timing out.
	client := PinnedClient([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	}, 9, 2*time.Second)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Fetch(ctx, client, "http://lists.invalid/pro.txt", State{}, testMaxBytes)

	if err == nil {
		t.Fatal("a download was made from a range nothing answers on")
	}
	if strings.Contains(err.Error(), "resolved to no address") {
		t.Errorf("error = %q, want what the dials did rather than the no-address case", err)
	}
}
