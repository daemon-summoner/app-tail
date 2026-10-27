package ui

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

// The dashboard is the app's whole interface, so a build that embeds nothing must
// fail here rather than at a user's blank page.
func TestEmbeddedDashboardHasItsShell(t *testing.T) {
	dashboard, err := FS()
	if err != nil {
		t.Fatalf("FS: %v", err)
	}

	index, err := fs.ReadFile(dashboard, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !strings.Contains(string(index), `id="root"`) {
		t.Fatalf("index.html has no React root element:\n%s", index)
	}
}

// Vite emits content-hashed assets and references them from index.html. If the
// hashed files were not embedded, the shell would load and then fail in the
// browser with no server-side error at all.
func TestEmbeddedDashboardCarriesTheAssetsItsShellReferences(t *testing.T) {
	dashboard, err := FS()
	if err != nil {
		t.Fatalf("FS: %v", err)
	}
	index, err := fs.ReadFile(dashboard, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}

	refs := referencedAssets(string(index))
	if len(refs) == 0 {
		t.Fatal("index.html references no bundled assets, which means the build produced nothing")
	}

	var sawScript, sawStyle bool
	for _, ref := range refs {
		if _, err := fs.Stat(dashboard, ref); err != nil {
			t.Errorf("index.html references %q, which is not embedded: %v", ref, err)
			continue
		}
		switch path.Ext(ref) {
		case ".js":
			sawScript = true
		case ".css":
			sawStyle = true
		}
	}
	if !sawScript {
		t.Error("no JavaScript bundle is referenced; the dashboard would render nothing")
	}
	if !sawStyle {
		t.Error("no stylesheet is referenced; the dashboard would render unstyled")
	}
}

// referencedAssets pulls the relative src/href targets out of the built shell.
func referencedAssets(html string) []string {
	var refs []string
	for _, attr := range []string{`src="`, `href="`} {
		rest := html
		for {
			i := strings.Index(rest, attr)
			if i < 0 {
				break
			}
			rest = rest[i+len(attr):]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				break
			}
			value := rest[:end]
			rest = rest[end:]

			// Only local build output matters here; absolute URLs are not embedded.
			if strings.HasPrefix(value, "http") || strings.HasPrefix(value, "//") {
				continue
			}
			refs = append(refs, strings.TrimPrefix(strings.TrimPrefix(value, "./"), "/"))
		}
	}
	return refs
}

// Asset URLs must stay relative: the agent serves the dashboard from a loopback
// origin whose port changes, so an absolute path baked at build time would break.
func TestAssetReferencesAreRelative(t *testing.T) {
	dashboard, err := FS()
	if err != nil {
		t.Fatalf("FS: %v", err)
	}
	index, err := fs.ReadFile(dashboard, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}

	for _, attr := range []string{`src="/`, `href="/`} {
		if strings.Contains(string(index), attr) {
			t.Errorf("index.html contains an absolute reference (%s...); vite base must stay './'", attr)
		}
	}
}
