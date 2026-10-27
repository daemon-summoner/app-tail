// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

const indexFile = "index.html"

// Types the Go mime table lacks. A font served as application/octet-stream is
// refused by browsers under the dashboard's strict CSP.
var uiContentTypes = map[string]string{
	".woff2": "font/woff2",
}

// uiContentType resolves the Content-Type for an embedded asset, the bundle's own
// table first and the system mime table after it. Empty when neither knows the
// extension, so the caller leaves the header unset.
func uiContentType(name string) string {
	ext := path.Ext(name)
	if ctype, ok := uiContentTypes[ext]; ok {
		return ctype
	}
	return mime.TypeByExtension(ext)
}

// handleUI serves the embedded dashboard. Unknown paths fall back to index.html so
// client-side routes survive a reload, but anything under /api keeps its 404 --
// silently answering a mistyped API path with HTML would turn a client bug into a
// baffling parse error.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.writeJSON(w, http.StatusNotFound, errorBody{Error: "no such API endpoint"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeJSON(w, http.StatusMethodNotAllowed,
			errorBody{Error: "the dashboard only serves GET and HEAD"})
		return
	}
	if s.ui == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, errorBody{
			Error: "no dashboard was built into this binary; use the CLI or rebuild with the UI",
		})
		return
	}

	name := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if name == "." || name == "/" || name == "" {
		name = indexFile
	}
	if !fs.ValidPath(name) {
		s.writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid path"})
		return
	}

	if name != indexFile {
		if s.serveUIFile(w, r, name, false) {
			return
		}
		// A missing asset is a build problem, not a client route; only
		// extension-less paths are plausible SPA routes.
		if path.Ext(name) != "" {
			s.writeJSON(w, http.StatusNotFound, errorBody{Error: "not found"})
			return
		}
	}
	if s.serveUIFile(w, r, indexFile, true) {
		return
	}
	s.writeJSON(w, http.StatusServiceUnavailable, errorBody{
		Error: "the embedded dashboard is missing its index.html",
	})
}

// serveUIFile writes one embedded file, reporting whether it existed. isFallback
// suppresses caching for the SPA shell, which must always be revalidated.
func (s *Server) serveUIFile(w http.ResponseWriter, r *http.Request, name string, isFallback bool) bool {
	f, err := s.ui.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Error("reading embedded dashboard asset failed", "name", name, "error", err)
		}
		return false
	}
	defer func() {
		if err := f.Close(); err != nil {
			s.logger.Error("closing embedded dashboard asset failed", "name", name, "error", err)
		}
	}()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	seeker, ok := f.(io.ReadSeeker)
	if !ok {
		s.logger.Error("embedded dashboard asset is not seekable", "name", name)
		return false
	}

	if ctype := uiContentType(name); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if isFallback || name == indexFile {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		// Vite emits content-hashed asset names, so a hit can never go stale.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	// The embedded FS has no meaningful mtime; a zero time disables If-Modified-Since
	// handling rather than asserting a false date.
	http.ServeContent(w, r, name, time.Time{}, seeker)
	return true
}
