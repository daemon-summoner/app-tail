// SPDX-License-Identifier: MIT

// Package archtest enforces the repo's import-graph boundaries. It carries no
// production code: the rules are the tests.
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// boundary is one import rule: which packages may reach a given dependency.
type boundary struct {
	// prefix is matched against the head of an import path.
	prefix string
	// allowed lists package directories relative to the repo root, each of which
	// covers itself and everything beneath it.
	allowed []string
	// why is printed on a violation, so the failure explains the design rather than
	// just naming a rule.
	why string
}

// The tailnet is reached through exactly one package. Consumers take stdlib-typed
// values (tsnode.Status, tsnode.Peer) rather than ipn or tailcfg types, which is what
// keeps "how the node is built" -- a userspace tsnet server today, a TUN-backed stack
// later -- a change to one package instead of to every caller. Nothing in the code
// states that rule, so it is stated here.
//
// An import is governed by the longest matching prefix and by that rule alone, so a
// narrower entry carves an exception out of a broader one rather than colliding with it.
var boundaries = []boundary{
	{
		prefix:  "tailscale.com/",
		allowed: []string{"internal/tsnode", "internal/hostnet"},
		why: "the tailnet boundary: other packages must take stdlib-typed values from " +
			"internal/tsnode. internal/hostnet is the second half of that boundary rather " +
			"than an exception to it: the two interfaces it implements, router.Router and " +
			"dns.OSConfigurator, are the engine's own, and restating them in this app's " +
			"types would mean a translation layer that has to be right for the machine's " +
			"routing table to be right",
	},
	{
		prefix:  "github.com/sellitus/app-tail/internal/hostnet",
		allowed: []string{"internal/tsnode", "internal/fabric", "internal/tunnel/ovpntunnel", "internal/cli"},
		why: "the privilege boundary: internal/hostnet is what holds -- or talks to what " +
			"holds -- administrator rights, so the set of packages that can reach it is " +
			"part of the design rather than an accident. There are exactly three privileged " +
			"consumers and they do disjoint jobs. internal/tsnode puts one tailnet on a " +
			"real interface and internal/fabric puts every connected network on one, and " +
			"the helper's own single-interface refusal makes those two mutually exclusive " +
			"rather than two things configuring one machine at once. " +
			"internal/tunnel/ovpntunnel is deliberately not exclusive with either: it asks " +
			"for a program to be run rather than for the interface, and it holds its own " +
			"session gate, because a machine carrying OpenVPN connections and a machine on " +
			"a tailnet are the same machine here. internal/cli installs and inspects the " +
			"helper. A further importer would be a fourth place deciding when this app " +
			"uses its rights",
	},
	{
		prefix:  "github.com/sellitus/app-tail/internal/grants/grantwrite",
		allowed: []string{"internal/cli", "internal/hostnet"},
		why: "the approval boundary: the approvals file is what an administrator said yes " +
			"to, and the privileged helper trusts it because only root writes it. The code " +
			"that writes it belongs to the commands an administrator runs -- `tun grant` and " +
			"the helper's installer -- and to nothing the unprivileged agent runs, which " +
			"reads approvals through internal/grants and never writes them",
	},
	{
		prefix:  "tailscale.com/net/socks5",
		allowed: []string{"internal/tsnode", "internal/tsproxy"},
		why: "the SOCKS5 wire protocol is a leaf: it takes a plain dial function and speaks " +
			"bytes, so it carries none of the backend types the boundary above exists to contain",
	},
	{
		prefix:  "tailscale.com/net/proxymux",
		allowed: []string{"internal/tsnode", "internal/tsproxy"},
		why: "splitting one listener by first byte is a leaf: it takes a net.Listener and " +
			"returns two, and knows nothing about the tailnet",
	},
}

func TestImportBoundariesHold(t *testing.T) {
	root := repoRoot(t)
	uses := scan(t, root)
	// Without this, a broken walk would report a clean repo rather than a broken gate.
	if len(uses) == 0 {
		t.Fatal("scanned no imports at all: the walk is broken, so this gate would pass on any violation")
	}

	matched := make(map[string]bool, len(boundaries))
	for _, use := range uses {
		b, ok := governing(use.path)
		if !ok {
			continue
		}
		matched[b.prefix] = true
		if b.permits(use.dir) {
			continue
		}
		t.Errorf("%s imports %q\n\t%s\n\tallowed only under: %s",
			use.file, use.path, b.why, strings.Join(b.allowed, ", "))
	}

	// A rule that matches nothing guards nothing, and would keep passing after the
	// dependency it was written for was renamed away.
	for _, b := range boundaries {
		if !matched[b.prefix] {
			t.Errorf("no file imports anything under %q; this rule now guards nothing and must be corrected or removed", b.prefix)
		}
	}
}

// governing returns the rule that decides an import: the longest prefix that matches
// it. Applying every matching rule instead would make a narrow allowance unusable, since
// the broad rule it carves out of would reject the same import.
func governing(path string) (boundary, bool) {
	var best boundary
	found := false
	for _, b := range boundaries {
		if !strings.HasPrefix(path, b.prefix) {
			continue
		}
		if !found || len(b.prefix) > len(best.prefix) {
			best, found = b, true
		}
	}
	return best, found
}

// Longest-prefix selection is the whole reason a narrow allowance works. Picking the
// first or the broadest match instead would leave internal/tsproxy's two leaf imports
// judged by the blanket tailscale.com rule -- the gate would fail on a design it is
// supposed to permit, and the fix would be to weaken the boundary itself.
func TestTheNarrowestRuleIsTheOneThatDecidesAnImport(t *testing.T) {
	tests := []struct {
		name, path, prefix string
		governed           bool
	}{
		{"a backend package falls to the blanket rule", "tailscale.com/ipn", "tailscale.com/", true},
		{"so does one nested under an allowed leaf's parent", "tailscale.com/net/tsaddr", "tailscale.com/", true},
		{"a leaf is governed by its own rule", "tailscale.com/net/socks5", "tailscale.com/net/socks5", true},
		{"and so is the other one", "tailscale.com/net/proxymux", "tailscale.com/net/proxymux", true},
		{"an unrelated dependency is governed by nothing", "golang.org/x/sys/windows", "", false},
		{"and neither is the stdlib", "net/http", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, ok := governing(tt.path)
			if ok != tt.governed {
				t.Fatalf("governing(%q) matched = %v, want %v", tt.path, ok, tt.governed)
			}
			if ok && b.prefix != tt.prefix {
				t.Errorf("governing(%q) chose the %q rule, want %q", tt.path, b.prefix, tt.prefix)
			}
		})
	}
}

// Every rule's allowed set names package directories that exist. A typo there silently
// widens the rule to nothing and narrows it to everything at once: the named directory
// never matches, so every real importer is reported, and the fix looks like relaxing the
// boundary rather than correcting a path.
func TestEveryAllowedDirectoryExists(t *testing.T) {
	root := repoRoot(t)
	for _, b := range boundaries {
		if len(b.allowed) == 0 {
			t.Errorf("the %q rule allows no directory at all, which forbids the import outright; say so in why or remove the rule", b.prefix)
		}
		for _, dir := range b.allowed {
			info, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir)))
			if err != nil {
				t.Errorf("the %q rule allows %q, which is not in the repo: %v", b.prefix, dir, err)
				continue
			}
			if !info.IsDir() {
				t.Errorf("the %q rule allows %q, which is a file rather than a package directory", b.prefix, dir)
			}
		}
	}
}

func (b boundary) permits(dir string) bool {
	for _, allowed := range b.allowed {
		if dir == allowed || strings.HasPrefix(dir, allowed+"/") {
			return true
		}
	}
	return false
}

// importUse is one import statement, located well enough to name in a failure.
type importUse struct {
	file string // repo-relative path, for the message
	dir  string // repo-relative package directory, for the rule
	path string // the imported package
}

// scan parses every Go file in the repo for its imports. Only direct imports matter:
// the boundary package is expected to import what it wraps, so a transitive reach
// through it is exactly what the design intends.
func scan(t *testing.T, root string) []importUse {
	t.Helper()
	var uses []importUse
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: unquote import %s: %w", rel, spec.Path.Value, err)
			}
			uses = append(uses, importUse{file: rel, dir: pathpkg.Dir(rel), path: imported})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning the repo: %v", err)
	}
	return uses
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", "testdata":
		return true
	}
	return false
}

// repoRoot resolves the module root from this package's own location, failing loudly
// rather than silently scanning the wrong tree if the package is ever moved.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected the module root at %s, but it holds no go.mod: %v", root, err)
	}
	return root
}
