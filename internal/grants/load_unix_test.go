// SPDX-License-Identifier: MIT

//go:build unix

package grants

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// someoneElse is an account id that is neither root nor whoever runs the suite. No account by
// that number has to exist.
const someoneElse = 4242

// testTrust treats root and the account running the suite as trusted, so files the suite
// makes count as root's would in production, and reports any path in owners as belonging to
// that account instead -- for the walk and for the opened file alike.
func testTrust(owners map[string]uint32) trust {
	me := uint32(os.Getuid())
	rewrite := func(name string, info fs.FileInfo) fs.FileInfo {
		uid, ok := owners[name]
		if !ok {
			return info
		}
		stat := *info.Sys().(*syscall.Stat_t)
		stat.Uid = uid
		return ownedBy{FileInfo: info, stat: &stat}
	}
	return trust{
		trusted: func(uid uint32) bool { return uid == 0 || uid == me },
		lstat: func(name string) (fs.FileInfo, error) {
			info, err := os.Lstat(name)
			if err != nil {
				return nil, err
			}
			return rewrite(name, info), nil
		},
		readlink: os.Readlink,
		fstat: func(f *os.File) (fs.FileInfo, error) {
			info, err := f.Stat()
			if err != nil {
				return nil, err
			}
			return rewrite(f.Name(), info), nil
		},
	}
}

type ownedBy struct {
	fs.FileInfo
	stat *syscall.Stat_t
}

func (o ownedBy) Sys() any { return o.stat }

// grantsFile writes approvals into a fresh directory with an exact mode and returns the path
// the kernel resolves it to, which is the name the walk records each component by.
func grantsFile(t *testing.T, body string, mode fs.FileMode) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve the test's directory: %v", err)
	}
	path := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set the mode of %s: %v", path, err)
	}
	return path
}

func TestNoApprovalsFileMeansNothingIsApproved(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := testTrust(nil).load(filepath.Join(dir, "missing", "grants.json"))
	if err != nil {
		t.Fatalf("a missing file is an error: %v", err)
	}
	if doc.FullTunnel || doc.SystemDNS || len(doc.Routes) != 0 || doc.Version != Version {
		t.Fatalf("a missing file approved %+v", doc)
	}
}

func TestAnApprovalsFileOnlyRootCanWriteIsRead(t *testing.T) {
	path := grantsFile(t, `{"version":1,"fullTunnel":true}`, 0o644)
	doc, err := testTrust(nil).load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !doc.FullTunnel {
		t.Fatalf("read %+v", doc)
	}
}

func TestAMalformedApprovalsFileIsAnErrorRatherThanNoApprovals(t *testing.T) {
	path := grantsFile(t, `{"version":1,"fullTunnel":tru`, 0o644)
	if _, err := testTrust(nil).load(path); err == nil {
		t.Fatal("a malformed file loaded")
	}
}

func TestAnApprovalsFileOtherAccountsCanWriteIsRefused(t *testing.T) {
	for _, mode := range []fs.FileMode{0o664, 0o646} {
		path := grantsFile(t, `{"version":1,"fullTunnel":true}`, mode)
		_, err := testTrust(nil).load(path)
		if err == nil || !strings.Contains(err.Error(), "other than root") {
			t.Errorf("mode %#o: got %v, want a refusal", mode, err)
		}
	}
}

func TestAnApprovalsFileAnotherAccountOwnsIsRefused(t *testing.T) {
	path := grantsFile(t, `{"version":1,"fullTunnel":true}`, 0o644)
	_, err := testTrust(map[string]uint32{path: someoneElse}).load(path)
	if err == nil || !strings.Contains(err.Error(), "rather than to root") {
		t.Fatalf("got %v, want a refusal naming the owner", err)
	}
}

func TestAnApprovalsFileInAFolderAnotherAccountOwnsIsRefused(t *testing.T) {
	path := grantsFile(t, `{"version":1,"fullTunnel":true}`, 0o644)
	_, err := testTrust(map[string]uint32{filepath.Dir(path): someoneElse}).load(path)
	if err == nil || !strings.Contains(err.Error(), "reached through") {
		t.Fatalf("got %v, want a refusal naming the folder", err)
	}
}

func TestAnApprovalsFileInAFolderOtherAccountsCanWriteIsRefused(t *testing.T) {
	path := grantsFile(t, `{"version":1,"fullTunnel":true}`, 0o644)
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := testTrust(nil).load(path); err == nil {
		t.Fatal("a file in a folder everyone can write loaded")
	}
}

func TestTheProductionPolicyRefusesAFileThatIsNotRoots(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, every file the suite makes is root's")
	}
	path := grantsFile(t, `{"version":1,"fullTunnel":true}`, 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("the production policy loaded a file the suite's own account owns")
	}
}
