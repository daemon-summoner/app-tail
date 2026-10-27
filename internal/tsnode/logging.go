// SPDX-License-Identifier: MIT

package tsnode

// What the tailscale stack logs stays on this machine. tsnet otherwise uploads its log to
// Tailscale's log service, and that log carries the login URL -- a credential until someone
// opens it, since whoever opens it first signs their own account in as this device. This
// file switches the upload off, deletes what an earlier run left queued for it, and keeps
// the login URL out of the lines this app writes to its own log.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/envknob"
	"tailscale.com/logtail"
)

// loginURLWithheld stands in for a login URL in every log line.
const loginURLWithheld = "[login URL withheld — open the dashboard]"

// loginURLPattern matches the login URLs Tailscale's and Headscale's control servers hand
// out: /a/<code> and /register/<key>.
var loginURLPattern = regexp.MustCompile(`https?://\S+/(a|register)/\S+`)

// logBufferPattern names the files tsnet queues its log upload in: tailscaled.log1.txt
// and tailscaled.log2.txt. tailscaled.log.conf beside them is the node's log identity,
// which the pattern leaves alone.
const logBufferPattern = "tailscaled.log*.txt"

var logUploadOff sync.Once

// disableLogUpload switches tsnet's log upload off for the whole process.
//
// logtail.Disable drops every line a running logger is handed instead of queueing it, and
// TS_NO_LOGS_NO_SUPPORT is the setting the rest of the tailscale stack reads for the same
// decision. Both are process-wide and cannot be switched back, so once is enough.
func disableLogUpload() {
	logUploadOff.Do(func() {
		logtail.Disable()
		envknob.SetNoLogsNoSupport()
	})
}

// removeLogBuffers deletes the upload queue an earlier run left in a node's state
// directory. logtail.Disable stops new lines being queued, but the logger still sends
// what it finds already on disk when it starts. Only regular files matching
// logBufferPattern directly inside dir are touched.
func removeLogBuffers(dir string) error {
	if dir == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, logBufferPattern))
	if err != nil {
		return fmt.Errorf("list leftover log buffers in %s: %w", dir, err)
	}
	for _, path := range matches {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect leftover log buffer %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("delete leftover log buffer %s: %w", path, err)
		}
	}
	return nil
}

// loginURLRedactor keeps login URLs out of log lines. Its zero value is ready to use.
type loginURLRedactor struct {
	// current is the last login URL the backend handed over. A control server may put its
	// login page at any path, so the exact URL is withheld as well as anything matching
	// loginURLPattern.
	current atomic.Pointer[string]
}

// remember records the login URL the backend is offering now. An empty URL is ignored:
// the last one stays withheld after login completes, since a line carrying it can still
// arrive late.
func (r *loginURLRedactor) remember(url string) {
	if url != "" {
		r.current.Store(&url)
	}
}

// redact replaces every login URL in line with loginURLWithheld.
func (r *loginURLRedactor) redact(line string) string {
	if current := r.current.Load(); current != nil {
		line = strings.ReplaceAll(line, *current, loginURLWithheld)
	}
	return loginURLPattern.ReplaceAllLiteralString(line, loginURLWithheld)
}

// wrap returns logf with every line it writes redacted first.
func (r *loginURLRedactor) wrap(logf func(string, ...any)) func(string, ...any) {
	return func(format string, args ...any) {
		logf("%s", r.redact(fmt.Sprintf(format, args...)))
	}
}
