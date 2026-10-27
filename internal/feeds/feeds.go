// SPDX-License-Identifier: MIT

// Package feeds downloads and caches files somebody else maintains, on a schedule, for
// whatever consumes them.
//
// It is the transport half of both the domain blocklists and the traffic-inspection
// address feeds: a conditional GET, a copy on disk, an index describing every copy, and
// the guard on where a download may come from. What a body means is the consumer's --
// this package never parses one, so the two consumers cannot end up with two different
// answers to "is this copy current" or two different opinions on where a file may be
// fetched from.
//
// The properties worth naming, because each was a decision rather than an accident:
//
//   - The fetch is conditional. A file that has not been rebuilt costs one round trip and
//     a 304 rather than the whole download, which is what makes an hourly refresh of a
//     forty-megabyte list affordable.
//   - The copy on disk keeps working when the network does not. A download that fails is
//     recorded against its entry and carried into the view; the previous copy stays.
//   - The caller decides whether a body is acceptable before Store is called, so a body
//     that does not parse never replaces one that did. A captive portal's sign-in page is
//     the one that happens.
//   - Where a file may be fetched from is checked after the name resolves, not only when
//     the URL is entered. See Fetchable.
package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

const (
	// IndexName holds what each cached copy is: when it arrived, what the server tagged it
	// with, how much it yielded and what went wrong last time.
	IndexName = "index.json"

	// UserAgent is what a download identifies itself as. Several of the servers these files
	// come from rate-limit by it, so it names the app rather than being blank.
	UserAgent = "app-tail"
)

// State is what one cached copy is, as the index holds it.
type State struct {
	// ETag and LastModified are what the server tagged the cached copy with, sent back on
	// the next request so an unchanged file costs one 304 rather than forty megabytes.
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	// FetchedAt is when the copy on disk was last confirmed current, which a 304 moves
	// forward as much as a download does.
	FetchedAt time.Time `json:"fetchedAt,omitempty"`
	// StoredAt is when the copy on disk was last replaced, which a 304 does not move. It is
	// what a consumer keys a rebuild on: FetchedAt moves every time a copy is confirmed
	// current, and rebuilding a matcher then means parsing a file byte-for-byte identical to
	// the one already in force.
	StoredAt time.Time `json:"storedAt,omitempty"`
	Bytes    int       `json:"bytes,omitempty"`
	Rules    int       `json:"rules,omitempty"`
	Skipped  int       `json:"skipped,omitempty"`
	// Error is what went wrong the last time this entry was fetched or read, and is carried
	// rather than logged because the cached copy keeps applying either way: a file that
	// stopped updating looks exactly like one that is up to date.
	Error string `json:"lastError,omitempty"`
}

// Fetched is one download's outcome.
type Fetched struct {
	Body []byte
	// NotModified is the server saying the cached copy is still current.
	NotModified  bool
	ETag         string
	LastModified string
}

// Cache is one directory of downloaded copies plus the index describing them.
//
// The index is written on every change rather than at shutdown: the process holding it is
// a VPN agent that is expected to be killed, and an index written only on a clean exit is
// an index that is usually a lie.
type Cache struct {
	logger *slog.Logger
	dir    string
	now    func() time.Time

	mu sync.Mutex
	// state is the index, keyed by entry id.
	state map[string]State
}

// NewCache reads the index in dir. A missing or unreadable index is an empty one: it
// describes files that are re-downloadable, so refusing to start over it would trade a
// working feature for a broken one.
func NewCache(logger *slog.Logger, dir string, now func() time.Time) *Cache {
	c := &Cache{logger: logger, dir: dir, now: now, state: map[string]State{}}
	state, err := readIndex(filepath.Join(dir, IndexName))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		logger.Warn("what is known about the downloaded files could not be read; they will be downloaded again",
			"dir", dir, "error", err)
	default:
		c.state = state
	}
	return c
}

// Dir is where the copies live.
func (c *Cache) Dir() string { return c.dir }

// Prepare creates the directory the copies live in.
func (c *Cache) Prepare() error {
	if err := os.MkdirAll(c.dir, config.DirMode); err != nil {
		return fmt.Errorf("create the directory the downloaded files live in: %w", err)
	}
	return nil
}

// Path is where one entry's downloaded copy lives. The id is a slug the catalog controls,
// so it cannot escape the directory; Base is what makes that a property of this function
// rather than of every caller.
func (c *Cache) Path(id string) string {
	return filepath.Join(c.dir, filepath.Base(id)+".txt")
}

// StateOf returns what is known about one entry.
func (c *Cache) StateOf(id string) State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state[id]
}

// Snapshot returns a copy of the whole index.
func (c *Cache) Snapshot() map[string]State {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]State, len(c.state))
	for id, st := range c.state {
		out[id] = st
	}
	return out
}

// SetState records what is known about one entry and writes the index.
func (c *Cache) SetState(id string, st State) {
	c.mu.Lock()
	c.state[id] = st
	index := c.copyLocked()
	c.mu.Unlock()

	if err := writeIndex(c.dir, index); err != nil {
		// The files themselves are on disk and still apply; what is lost is the knowledge
		// that they are current, so the next start downloads them again.
		c.logger.Warn("recording what is known about the downloaded files failed",
			"dir", c.dir, "error", err)
	}
}

// Forget drops what is known about an entry and deletes its cached copy, for one the user
// removed from the catalog.
func (c *Cache) Forget(id string) error {
	c.mu.Lock()
	_, held := c.state[id]
	delete(c.state, id)
	index := c.copyLocked()
	c.mu.Unlock()
	if !held {
		return nil
	}
	var errs []error
	if err := os.Remove(c.Path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove the downloaded copy of %s: %w", id, err))
	}
	errs = append(errs, writeIndex(c.dir, index))
	return errors.Join(errs...)
}

// copyLocked returns the index as a fresh map. The caller holds the mutex.
func (c *Cache) copyLocked() map[string]State {
	index := make(map[string]State, len(c.state))
	for k, v := range c.state {
		index[k] = v
	}
	return index
}

// Due reports an entry that has never been downloaded, or whose copy is older than the
// refresh interval.
func (c *Cache) Due(id string, st State, every time.Duration) bool {
	if st.FetchedAt.IsZero() {
		return true
	}
	if _, err := os.Stat(c.Path(id)); err != nil {
		// The index remembers a copy that is not there: a half-cleaned state directory, or
		// a file somebody removed. Downloading it again is the only way back.
		return true
	}
	return c.now().Sub(st.FetchedAt) >= every
}

// Read returns one entry's downloaded copy.
func (c *Cache) Read(id string) ([]byte, error) { return os.ReadFile(c.Path(id)) }

// Store replaces one entry's downloaded copy.
func (c *Cache) Store(id string, body []byte) error { return WriteFile(c.Path(id), body) }

// readIndex reads what is known about the cached copies.
func readIndex(path string) (map[string]State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var index map[string]State
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if index == nil {
		index = map[string]State{}
	}
	return index, nil
}

// writeIndex replaces the index through a temp file, so a crash mid-write leaves the
// previous one rather than half of this one.
func writeIndex(dir string, index map[string]State) error {
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode what is known about the downloaded files: %w", err)
	}
	return WriteFile(filepath.Join(dir, IndexName), append(data, '\n'))
}

// WriteFile puts data at path through a temp file in the same directory, renamed over the
// target. Nothing is left behind on failure.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, config.DirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".feed-*")
	if err != nil {
		return fmt.Errorf("create a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	discard := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(name))
	}
	if err := tmp.Chmod(config.FileMode); err != nil {
		return discard(fmt.Errorf("set the permissions on %s: %w", name, err))
	}
	if _, err := tmp.Write(data); err != nil {
		return discard(fmt.Errorf("write %s: %w", name, err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("flush %s: %w", name, err))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("close %s: %w", name, err), os.Remove(name))
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(fmt.Errorf("replace %s: %w", path, err), os.Remove(name))
	}
	return nil
}

// Fetch performs one conditional GET through a client the caller pinned to an address.
// A body larger than maxBytes is refused rather than truncated.
func Fetch(ctx context.Context, client *http.Client, rawURL string, prev State, maxBytes int) (Fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Fetched{}, fmt.Errorf("ask %s for a file: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/plain, */*")
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Fetched{}, fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return Fetched{NotModified: true}, nil
	case http.StatusOK:
	default:
		return Fetched{}, fmt.Errorf("%s answered %s", rawURL, resp.Status)
	}

	// One byte past the cap, so a body that is exactly at it is accepted and one over it is
	// refused rather than silently truncated into a file missing its last half.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return Fetched{}, fmt.Errorf("read %s: %w", rawURL, err)
	}
	if len(body) > maxBytes {
		return Fetched{}, fmt.Errorf("%s is larger than the %d MB this list may be", rawURL, maxBytes>>20)
	}
	return Fetched{
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// maxRedirects is how many hops a download follows, the standard library's own default.
const maxRedirects = 10

// PinnedClient dials every connection to one of addrs, whatever hostname the request
// carries.
//
// Without this the transport would look the hostname up through the system resolver,
// which -- while the machine-wide resolver is on -- is this process, and the answer it is
// waiting for is this download. That is not a slow path, it is a deadlock, and a hostname
// that is itself on a list would be the second way to lose. The proxy is off for the same
// reason: app-tail installs one on this machine, and a download that went through it would
// come back here.
func PinnedClient(addrs []netip.Addr, port uint16, timeout time.Duration) *http.Client {
	pinned := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		pinned = append(pinned, netip.AddrPortFrom(addr, port).String())
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			d.Timeout = 10 * time.Second
			var failures []error
			for _, addr := range pinned {
				conn, err := d.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				failures = append(failures, err)
			}
			if len(failures) == 0 {
				return nil, errors.New("the hostname resolved to no address")
			}
			return nil, errors.Join(failures...)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A redirect is the server choosing the next URL, so it is checked here rather
		// than trusted: a hop to a scheme that is not http or https, or to a literal
		// address Fetchable refuses, ends the download. A hop to another hostname is
		// held by the dialer above -- every hop connects to an address already checked
		// with Fetchable, whatever host the request carries -- so it is allowed.
		//
		// A hop to plain http after any https one is refused: the list was asked for
		// encrypted, and following the server off it would let anyone on the path replace
		// what is downloaded. Setting this policy also drops the standard library's own
		// limit on hops, so it carries the same one.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirected to %s, which is not http or https", req.URL.Scheme)
			}
			if req.URL.Scheme == "http" {
				for _, hop := range via {
					if hop.URL.Scheme == "https" {
						return fmt.Errorf("redirected from https to plain http at %s, which would let anyone on the way replace the download",
							req.URL.Redacted())
					}
				}
			}
			if host, err := netip.ParseAddr(req.URL.Hostname()); err == nil {
				if err := Fetchable(host); err != nil {
					return fmt.Errorf("redirected to %s, which is not somewhere a list is fetched from: %w", host, err)
				}
			}
			return nil
		},
	}
}

// Fetchable refuses an address a file may not be downloaded from.
//
// The fetch is the one place this process opens a connection to somewhere a caller named, and
// it deliberately dials without the system proxy and without app-tail's own resolver, so
// nothing else is positioned to say no. What it must not become is a way to ask this machine's
// own services, the metadata address, or a host on the tailnet a question and read the answer
// back out of the byte count and the error text.
//
// Every address the name resolved to is checked rather than only the first, because the dialer
// tries each in turn: one refusable address among several is still an address that gets dialled.
func Fetchable(addr netip.Addr) error {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return errors.New("it is not an address")
	case addr.IsLoopback():
		return errors.New("loopback is this machine talking to itself")
	case addr.IsMulticast():
		// Before the link-local test: the link-local multicast ranges answer to both, and
		// multicast is the more accurate reason.
		return errors.New("multicast is not a host serving a file")
	case addr.IsLinkLocalUnicast():
		return errors.New("a link-local address names a different machine on every network")
	case addr.IsUnspecified():
		return errors.New("it names no host")
	case addr.IsPrivate():
		return errors.New("it is on a private network rather than the internet")
	}
	// The tailnet ranges come from the library through tsnode rather than being written out
	// here, so an upstream change cannot leave a stale constant deciding what this refuses.
	for _, p := range tsnode.TailnetRanges() {
		if p.Contains(addr) {
			return errors.New("it is a tailnet address")
		}
	}
	return nil
}
